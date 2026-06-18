"""
DARPAN ML Feature Engineering
Extracts temporal, command-sequence, payload, and network features from Cowrie sessions.
"""
import json
import math
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer

RECON_CMDS = frozenset({
    "ls", "dir", "cat", "type", "pwd", "whoami", "id", "uname", "hostname",
    "ifconfig", "ip", "netstat", "ss", "arp", "route", "ps", "top", "htop",
    "w", "who", "last", "df", "du", "free", "uptime", "dmesg", "lscpu",
    "lsblk", "env", "printenv", "set", "mount", "find", "locate", "which",
    "whereis", "file", "stat", "lsof", "strings",
})

LATERAL_CMDS = frozenset({
    "ssh", "scp", "sftp", "rsync", "rsh", "rlogin", "telnet",
    "nc", "ncat", "netcat", "socat",
    "wget", "curl", "fetch", "axel", "aria2c",
    "python", "python3", "perl", "ruby", "php", "node",
    "bash", "sh", "dash", "zsh",
})

PERSISTENCE_CMDS = frozenset({
    "crontab", "at", "atd", "systemctl", "service", "update-rc.d",
    "chkconfig", "launchctl", "schtasks",
    "chmod", "chattr", "setuid", "install",
    "echo", "tee",
})

BASE64_PATTERN = re.compile(
    r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"https?://\S+|ftp://\S+")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _extract_cmd_name(cmd: str) -> str:
    parts = cmd.strip().split()
    return parts[0] if parts else ""


class SessionFeatureExtractor:
    def __init__(self, ngram_range: tuple[int, int] = (1, 3), max_features: int = 200):
        self.ngram_range = ngram_range
        self.max_features = max_features
        self._vectorizer: CountVectorizer | None = None

    def extract_from_file(self, log_path: str | Path) -> pd.DataFrame:
        sessions: dict[str, list[dict]] = {}
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sid = ev.get("session", "unknown")
                sessions.setdefault(sid, []).append(ev)
        return self._sessions_to_df(sessions)

    def extract_from_events(self, events: list[dict]) -> pd.DataFrame:
        sessions: dict[str, list[dict]] = {}
        for ev in events:
            sid = ev.get("session", "unknown")
            sessions.setdefault(sid, []).append(ev)
        return self._sessions_to_df(sessions)

    def _sessions_to_df(self, sessions: dict[str, list[dict]]) -> pd.DataFrame:
        rows = []
        for sid, evs in sessions.items():
            row = self._extract_session_features(sid, evs)
            rows.append(row)
        if not rows:
            return pd.DataFrame()
        df = pd.DataFrame(rows)

        # Command n-gram features (fit on first call, transform thereafter)
        cmd_texts = df["command_text"].fillna("").tolist()
        if self._vectorizer is None:
            self._vectorizer = CountVectorizer(
                analyzer="word",
                tokenizer=lambda x: x.split(),
                ngram_range=self.ngram_range,
                max_features=self.max_features,
                binary=True,
            )
            ngram_matrix = self._vectorizer.fit_transform(cmd_texts)
        else:
            ngram_matrix = self._vectorizer.transform(cmd_texts)

        ngram_df = pd.DataFrame(
            ngram_matrix.toarray(),
            columns=[f"ngram_{c}" for c in self._vectorizer.get_feature_names_out()],
            index=df.index,
        )
        return pd.concat([df.drop(columns=["command_text"]), ngram_df], axis=1)

    def _extract_session_features(self, sid: str, events: list[dict]) -> dict[str, Any]:
        events_sorted = sorted(
            events,
            key=lambda e: e.get("timestamp", e.get("@timestamp", ""))
        )

        commands: list[str] = []
        cmd_timestamps: list[float] = []
        first_auth_ts: float | None = None
        first_cmd_ts: float | None = None
        auth_success = False
        src_ip = ""
        src_country = ""
        dst_port = 22
        credential_type = "unknown"
        session_start: float | None = None
        session_end: float | None = None

        for ev in events_sorted:
            eid = ev.get("eventid", "")
            ts_str = ev.get("timestamp") or ev.get("@timestamp") or ""
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
            except Exception:
                ts = 0.0

            if eid == "cowrie.session.connect":
                session_start = ts
                src_ip = ev.get("src_ip", "")
                dst_port = int(ev.get("dst_port", 22))
                src_country = ev.get("geoip", {}).get("src_country", "") or \
                              ev.get("src_country", "")

            elif eid in ("cowrie.login.success", "cowrie.login.failed"):
                if first_auth_ts is None:
                    first_auth_ts = ts
                if eid == "cowrie.login.success":
                    auth_success = True
                    credential_type = ev.get("credential_type", "unknown")

            elif eid == "cowrie.command.input":
                cmd = ev.get("input", ev.get("command", "")).strip()
                if cmd:
                    commands.append(cmd)
                    cmd_timestamps.append(ts)
                    if first_cmd_ts is None:
                        first_cmd_ts = ts

            elif eid == "cowrie.session.closed":
                session_end = ts

        # ── Temporal features ──────────────────────────────────────────────
        if session_start and session_end:
            session_duration = max(0.0, session_end - session_start)
        elif session_start and cmd_timestamps:
            session_duration = max(cmd_timestamps) - session_start
        else:
            session_duration = 0.0

        if len(cmd_timestamps) >= 2:
            iats = [cmd_timestamps[i] - cmd_timestamps[i - 1]
                    for i in range(1, len(cmd_timestamps))]
            iat_mean = float(np.mean(iats))
            iat_std = float(np.std(iats))
            iat_min = float(np.min(iats))
            iat_max = float(np.max(iats))
        else:
            iat_mean = iat_std = iat_min = iat_max = 0.0

        cpm = (len(commands) / session_duration * 60) if session_duration > 0 else 0.0
        time_to_first_cmd = (
            (first_cmd_ts - first_auth_ts) if first_cmd_ts and first_auth_ts else -1.0
        )

        # ── Command sequence features ──────────────────────────────────────
        cmd_count = len(commands)
        cmd_names = [_extract_cmd_name(c) for c in commands]
        unique_ratio = len(set(cmd_names)) / max(cmd_count, 1)

        recon_score = sum(1 for c in cmd_names if c in RECON_CMDS)
        lateral_score = sum(1 for c in cmd_names if c in LATERAL_CMDS)
        persistence_score = sum(1 for c in cmd_names if c in PERSISTENCE_CMDS)
        syntax_error_rate = sum(1 for c in commands
                                if "not found" in c or "command not found" in c
                                ) / max(cmd_count, 1)

        # ── Payload features ───────────────────────────────────────────────
        all_cmd_text = " ".join(commands)
        payload_entropy = _shannon_entropy(all_cmd_text)
        avg_cmd_len = float(np.mean([len(c) for c in commands])) if commands else 0.0
        base64_flag = int(bool(BASE64_PATTERN.search(all_cmd_text)))
        ip_flag = int(bool(IP_PATTERN.search(all_cmd_text)))
        url_flag = int(bool(URL_PATTERN.search(all_cmd_text)))

        return {
            "session_id": sid,
            "src_ip": src_ip,
            "src_country": src_country,
            "dst_port": dst_port,
            "auth_success": int(auth_success),
            "credential_type": credential_type,
            # Temporal
            "session_duration": session_duration,
            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "iat_min": iat_min,
            "iat_max": iat_max,
            "commands_per_minute": cpm,
            "time_to_first_command": time_to_first_cmd,
            # Command sequence
            "command_count": cmd_count,
            "unique_command_ratio": unique_ratio,
            "syntax_error_rate": syntax_error_rate,
            "recon_command_score": recon_score,
            "lateral_movement_score": lateral_score,
            "persistence_command_score": persistence_score,
            # Payload
            "payload_entropy": payload_entropy,
            "avg_command_length": avg_cmd_len,
            "base64_usage_flag": base64_flag,
            "contains_ip_address_flag": ip_flag,
            "contains_url_flag": url_flag,
            # For n-gram vectorization (dropped after)
            "command_text": " ".join(cmd_names),
        }

    def save_features(self, df: pd.DataFrame, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        df.to_parquet(str(path), index=False)

    def load_features(self, path: str | Path) -> pd.DataFrame:
        return pd.read_parquet(str(path))


NUMERIC_FEATURE_COLS = [
    "session_duration", "iat_mean", "iat_std", "iat_min", "iat_max",
    "commands_per_minute", "time_to_first_command",
    "command_count", "unique_command_ratio", "syntax_error_rate",
    "recon_command_score", "lateral_movement_score", "persistence_command_score",
    "payload_entropy", "avg_command_length",
    "base64_usage_flag", "contains_ip_address_flag", "contains_url_flag",
    "auth_success", "dst_port",
]
