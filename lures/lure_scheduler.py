"""
DARPAN Lure Refresh Scheduler
Regenerates the polymorphic honeyfs every 6 hours to defeat fingerprinting.
Run as: python3 lure_scheduler.py  (or via systemd/cron)
"""
import difflib
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

log = logging.getLogger("darpan.lure_scheduler")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [LURE-SCHEDULER] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/darpan_lures.log", mode="a"),
    ],
)

DARPAN_ROOT = Path("/opt/darpan")
HONEYFS_DIR = DARPAN_ROOT / "reflector" / "honeyfs"
USERDB_PATH = DARPAN_ROOT / "reflector" / "userdb.txt"
HONEYFS_GEN = DARPAN_ROOT / "reflector" / "generate_honeyfs.py"
CONTAINER_NAME = "darpan_cowrie-reflector-01"
LOG_FILE = Path("/var/log/darpan_lures.log")
STATE_FILE = DARPAN_ROOT / "lures" / ".lure_state.json"

HONEYTOKEN_POOL = [
    ("prod_maint", "xK9#mPqR2vL8nW"),
    ("db_rotate",  "zT7@jHsF4xN1cQ"),
    ("sec_audit",  "pY5$vBkM8wR3dE"),
    ("infra_ops",  "hL2#nCxP6tV9bZ"),
    ("backup_key", "wQ4@rDgJ7kS0mX"),
]

CANARY_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789@#$!"


def _random_canary_password(length: int = 16) -> str:
    import random
    return "".join(random.choices(CANARY_CHARS, k=length))


def _file_fingerprint(path: Path) -> str:
    if not path.exists():
        return ""
    h = hashlib.sha256()
    for f in sorted(path.rglob("*")):
        if f.is_file():
            h.update(f.name.encode())
            h.update(f.read_bytes())
    return h.hexdigest()


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"cycles": 0, "last_run": None, "active_honeytokens": []}


def _save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, default=str))


def _snapshot_fs_hashes(honeyfs: Path) -> dict[str, str]:
    hashes = {}
    for f in sorted(honeyfs.rglob("*")):
        if f.is_file():
            rel = str(f.relative_to(honeyfs))
            hashes[rel] = hashlib.md5(f.read_bytes()).hexdigest()
    return hashes


def regenerate_honeyfs(output_dir: Path) -> dict:
    log.info(f"Regenerating honeyfs → {output_dir}")
    before_fingerprint = _file_fingerprint(output_dir)
    before_hashes = _snapshot_fs_hashes(output_dir) if output_dir.exists() else {}

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp) / "honeyfs"
        result = subprocess.run(
            [sys.executable, str(HONEYFS_GEN), "--output", str(tmp_path)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            log.error(f"generate_honeyfs.py failed:\n{result.stderr}")
            return {"success": False, "error": result.stderr}

        # Replace honeyfs atomically
        if output_dir.exists():
            backup = output_dir.parent / (output_dir.name + ".prev")
            if backup.exists():
                shutil.rmtree(backup)
            shutil.copytree(str(output_dir), str(backup))

        if output_dir.exists():
            shutil.rmtree(str(output_dir))
        shutil.copytree(str(tmp_path), str(output_dir))

    after_hashes = _snapshot_fs_hashes(output_dir)
    after_fingerprint = _file_fingerprint(output_dir)

    added = set(after_hashes) - set(before_hashes)
    removed = set(before_hashes) - set(after_hashes)
    changed = {
        k for k in set(before_hashes) & set(after_hashes)
        if before_hashes[k] != after_hashes[k]
    }

    diff_summary = {
        "files_added": sorted(added),
        "files_removed": sorted(removed),
        "files_changed": sorted(changed),
        "total_files": len(after_hashes),
        "fingerprint_before": before_fingerprint[:16],
        "fingerprint_after": after_fingerprint[:16],
    }
    log.info(f"Honeyfs diff: +{len(added)} -{len(removed)} ~{len(changed)} files")
    return {"success": True, "diff": diff_summary, "stdout": result.stdout}


def rotate_honeytokens(userdb_path: Path, state: dict, new_count: int = 3) -> list[tuple[str, str]]:
    log.info(f"Rotating honeytokens in {userdb_path}")
    content = userdb_path.read_text(encoding="utf-8") if userdb_path.exists() else ""

    existing_tokens = state.get("active_honeytokens", [])
    new_tokens: list[tuple[str, str]] = []
    import random
    import string
    for i in range(new_count):
        username = f"ht_{random.randint(1000, 9999)}"
        password = _random_canary_password(18)
        new_tokens.append((username, password))

    # Keep all existing honeytokens + add new ones
    all_tokens = existing_tokens + [{"user": u, "pass": p} for u, p in new_tokens]
    state["active_honeytokens"] = all_tokens

    # Append new tokens to userdb.txt
    additions = "\n".join(
        f"# HONEYTOKEN cycle-{state.get('cycles', 0)}\n"
        f"{u}:{9000+i}:!{p}"
        for i, (u, p) in enumerate(new_tokens)
    )
    if additions:
        with open(userdb_path, "a", encoding="utf-8") as f:
            f.write(f"\n{additions}\n")

    log.info(f"Added {len(new_tokens)} new honeytokens: {[u for u, _ in new_tokens]}")
    return new_tokens


def reload_cowrie(container_name: str) -> bool:
    log.info(f"Reloading Cowrie container: {container_name}")
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "pgrep", "-f", "cowrie"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            log.warning("Cowrie process not found — may not be running")
            return False

        # SIGHUP causes Cowrie to reload config (graceful)
        subprocess.run(
            ["docker", "exec", container_name, "pkill", "-HUP", "-f", "cowrie"],
            capture_output=True, timeout=10,
        )
        log.info("Sent SIGHUP to Cowrie for config reload")
        return True
    except subprocess.TimeoutExpired:
        log.error("Docker exec timed out")
        return False
    except FileNotFoundError:
        log.error("Docker command not found")
        return False


def run_cycle() -> None:
    state = _load_state()
    cycle = state.get("cycles", 0) + 1
    state["cycles"] = cycle
    state["last_run"] = datetime.utcnow().isoformat() + "Z"
    log.info(f"===== Lure Refresh Cycle {cycle} =====")

    # 1. Regenerate honeyfs
    regen_result = regenerate_honeyfs(HONEYFS_DIR)

    # 2. Rotate honeytokens
    new_tokens = []
    if USERDB_PATH.exists():
        new_tokens = rotate_honeytokens(USERDB_PATH, state, new_count=3)

    # 3. Signal Cowrie to reload
    cowrie_reloaded = reload_cowrie(CONTAINER_NAME)

    # 4. Log event
    event = {
        "cycle": cycle,
        "timestamp": state["last_run"],
        "honeyfs_regenerated": regen_result.get("success", False),
        "honeyfs_diff": regen_result.get("diff", {}),
        "new_honeytokens": [u for u, _ in new_tokens],
        "cowrie_reloaded": cowrie_reloaded,
    }
    log.info(f"Cycle {cycle} complete: {json.dumps(event)}")

    _save_state(state)


if __name__ == "__main__":
    run_cycle()
