"""
DARPAN Honeytoken Beacon System
Real-time monitor for honeytoken file access events in Cowrie JSON logs.
Generates CRITICAL alerts and optionally POSTs to a webhook.
"""
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

log = logging.getLogger("darpan.honeytoken_beacon")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BEACON] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/darpan_beacon.log", mode="a"),
    ],
)

COWRIE_LOG = Path(os.getenv("COWRIE_LOG_PATH", "/opt/darpan/logs/cowrie/cowrie.json"))
ALERT_FILE = Path("/opt/darpan/intel/alerts/honeytoken_alerts.json")
WEBHOOK_URL = os.getenv("HONEYTOKEN_WEBHOOK_URL", "")

# Files whose access constitutes a honeytoken trigger
HONEYTOKEN_FILES = frozenset({
    "/opt/app/config.yml",
    "/opt/app/config.yaml",
    "/etc/app/secrets.env",
})

# High-sensitivity paths to also monitor
SENSITIVE_PATHS = {
    "/home/": {
        "patterns": [".ssh/authorized_keys", ".ssh/id_rsa", ".ssh/id_ed25519"],
        "alert_level": "HIGH",
        "reason": "SSH_KEY_ACCESS",
    },
    "/etc/shadow": {
        "patterns": ["/etc/shadow"],
        "alert_level": "CRITICAL",
        "reason": "SHADOW_FILE_ACCESS",
    },
    "/etc/sudoers": {
        "patterns": ["/etc/sudoers"],
        "alert_level": "HIGH",
        "reason": "SUDOERS_ACCESS",
    },
}

# Session state: track recent commands before a trigger
_session_history: dict[str, list[str]] = {}
MAX_SESSION_HISTORY = 30


def _is_honeytoken_access(event: dict) -> tuple[bool, str, str]:
    """Returns (is_trigger, alert_level, reason)."""
    cmd = event.get("input") or event.get("command") or ""

    # Check honeytoken files
    for ht_file in HONEYTOKEN_FILES:
        if ht_file in cmd:
            return True, "CRITICAL", "HONEYTOKEN_ACCESSED"

    # Check sensitive paths
    for _, spec in SENSITIVE_PATHS.items():
        for pattern in spec["patterns"]:
            if pattern in cmd:
                return True, spec["alert_level"], spec["reason"]

    return False, "", ""


def _build_alert(
    event: dict,
    alert_level: str,
    reason: str,
    session_id: str,
    commands_before: list[str],
) -> dict:
    return {
        "alert_level": alert_level,
        "reason": reason,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "session_id": session_id,
        "src_ip": event.get("src_ip", "unknown"),
        "src_port": event.get("src_port"),
        "dst_port": event.get("dst_port"),
        "username": event.get("username", ""),
        "trigger_command": event.get("input") or event.get("command", ""),
        "commands_before_access": commands_before[-10:],
        "cowrie_eventid": event.get("eventid", ""),
        "sensor": "darpan-reflector-01",
    }


def _write_alert(alert: dict) -> None:
    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")
    log.critical(
        f"HONEYTOKEN ALERT [{alert['alert_level']}] "
        f"src={alert['src_ip']} session={alert['session_id']} "
        f"reason={alert['reason']} cmd={alert['trigger_command'][:60]}"
    )


def _post_webhook(alert: dict) -> None:
    if not WEBHOOK_URL:
        return
    payload = {
        "text": (
            f"🚨 *DARPAN HONEYTOKEN ALERT* — `{alert['alert_level']}`\n"
            f"*Reason:* `{alert['reason']}`\n"
            f"*Source IP:* `{alert['src_ip']}`\n"
            f"*Session:* `{alert['session_id']}`\n"
            f"*Trigger:* `{alert['trigger_command'][:80]}`\n"
            f"*Time:* {alert['timestamp']}"
        )
    }
    try:
        resp = requests.post(WEBHOOK_URL, json=payload, timeout=10)
        if resp.ok:
            log.info(f"Webhook delivered: {resp.status_code}")
        else:
            log.warning(f"Webhook failed: {resp.status_code} {resp.text[:100]}")
    except requests.RequestException as e:
        log.error(f"Webhook error: {e}")


def _process_event(event: dict) -> None:
    eid = event.get("eventid", "")
    sid = event.get("session", "unknown")

    # Track command history per session
    if eid == "cowrie.command.input":
        cmd = event.get("input") or event.get("command") or ""
        history = _session_history.setdefault(sid, [])
        history.append(cmd)
        if len(history) > MAX_SESSION_HISTORY:
            history.pop(0)

        triggered, level, reason = _is_honeytoken_access(event)
        if triggered:
            alert = _build_alert(
                event, level, reason, sid,
                _session_history.get(sid, [])[:-1],
            )
            _write_alert(alert)
            _post_webhook(alert)

    elif eid == "cowrie.session.closed":
        _session_history.pop(sid, None)


class LogTailer:
    """Efficient tail-F implementation using inode tracking for log rotation."""

    def __init__(self, path: Path, poll_interval: float = 0.5):
        self.path = path
        self.poll_interval = poll_interval
        self._pos = 0
        self._inode = 0

    def _open_and_seek(self):
        if not self.path.exists():
            return None
        try:
            f = open(self.path, encoding="utf-8", errors="replace")
            st = self.path.stat()
            if st.st_ino != self._inode:
                # File rotated — start from beginning
                self._inode = st.st_ino
                self._pos = 0
            f.seek(self._pos)
            return f
        except OSError:
            return None

    def tail(self):
        log.info(f"Watching: {self.path}")
        while True:
            f = self._open_and_seek()
            if f is None:
                log.warning(f"Log file not found: {self.path} — retrying in 10s")
                time.sleep(10)
                continue

            try:
                while True:
                    line = f.readline()
                    if not line:
                        self._pos = f.tell()
                        time.sleep(self.poll_interval)
                        # Check for rotation
                        try:
                            if self.path.stat().st_ino != self._inode:
                                break
                        except OSError:
                            break
                        continue
                    line = line.strip()
                    if line:
                        try:
                            event = json.loads(line)
                            _process_event(event)
                        except json.JSONDecodeError:
                            pass
            finally:
                self._pos = f.tell()
                f.close()


def main() -> None:
    log.info("DARPAN Honeytoken Beacon starting...")
    log.info(f"Monitoring: {COWRIE_LOG}")
    log.info(f"Honeytokens: {list(HONEYTOKEN_FILES)}")
    log.info(f"Webhook: {'configured' if WEBHOOK_URL else 'not configured'}")
    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    tailer = LogTailer(COWRIE_LOG)
    tailer.tail()


if __name__ == "__main__":
    main()
