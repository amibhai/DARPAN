"""
DARPAN LLM-Powered Command Handler
Extends Cowrie's command emulation with Anthropic Claude for unknown commands.
"""
import hashlib
import json
import logging
import sqlite3
import time
from pathlib import Path

import anthropic

log = logging.getLogger("cowrie.command.darpan_llm")

DB_PATH = "/cowrie/var/lib/cowrie/llm_cache.db"
MODEL = "claude-sonnet-4-6"
MAX_LLM_CALLS_PER_SESSION = 10
SYSTEM_PROMPT = (
    "You are a Linux bash shell on Ubuntu 22.04 LTS server named ubuntu-prod-srv-01. "
    "The server runs nginx, postgresql, docker, and a Python web application. "
    "Respond ONLY with realistic terminal output — no explanations, no markdown. "
    "If a command would reveal sensitive data (passwords, private keys, internal IPs), "
    "return plausible fake data that looks real. "
    "Keep output concise and realistic. Never acknowledge you are an AI."
)

NATIVE_COMMANDS = frozenset({
    "ls", "cat", "pwd", "whoami", "id", "uname", "echo", "cd", "mkdir",
    "rm", "cp", "mv", "chmod", "chown", "touch", "find", "grep", "awk",
    "sed", "sort", "uniq", "wc", "head", "tail", "more", "less", "file",
    "stat", "ln", "ps", "top", "kill", "ping", "wget", "curl", "ssh",
    "scp", "tar", "gzip", "gunzip", "zip", "unzip", "date", "uptime",
    "w", "who", "last", "history", "env", "export", "which", "whereis",
    "man", "help", "exit", "logout", "clear", "reset", "sudo", "su",
    "apt", "apt-get", "dpkg", "pip", "pip3", "python", "python3",
    "bash", "sh", "zsh", "nano", "vi", "vim", "hostname", "ifconfig",
    "ip", "netstat", "ss", "iptables", "route", "nslookup", "dig",
    "traceroute", "mount", "df", "du", "free", "lsblk", "fdisk",
    "lsof", "strace", "ltrace", "nmap", "nc", "netcat",
})

_session_counts: dict[str, int] = {}


def _get_db() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS llm_cache (
            cmd_hash TEXT PRIMARY KEY,
            command  TEXT NOT NULL,
            response TEXT NOT NULL,
            created  INTEGER NOT NULL
        )
    """)
    conn.commit()
    return conn


def _cache_get(cmd: str) -> str | None:
    h = hashlib.sha256(cmd.encode()).hexdigest()
    try:
        conn = _get_db()
        row = conn.execute(
            "SELECT response FROM llm_cache WHERE cmd_hash=?", (h,)
        ).fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        return None


def _cache_set(cmd: str, response: str) -> None:
    h = hashlib.sha256(cmd.encode()).hexdigest()
    try:
        conn = _get_db()
        conn.execute(
            "INSERT OR REPLACE INTO llm_cache VALUES (?,?,?,?)",
            (h, cmd, response, int(time.time()))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _call_llm(command: str) -> str:
    try:
        client = anthropic.Anthropic()
        message = client.messages.create(
            model=MODEL,
            max_tokens=512,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": f"Command: {command}"}
            ]
        )
        return message.content[0].text.strip()
    except anthropic.APIConnectionError:
        log.warning("DARPAN LLM: API connection failed, using fallback")
        return f"bash: {command.split()[0]}: command not found"
    except anthropic.RateLimitError:
        log.warning("DARPAN LLM: Rate limited, using fallback")
        return f"bash: {command.split()[0]}: command not found"
    except Exception as e:
        log.error(f"DARPAN LLM: Unexpected error: {e}")
        return f"bash: {command.split()[0]}: command not found"


def handle_unknown_command(
    command: str,
    session_id: str,
    cowrie_log_fn=None,
) -> str:
    """
    Main entry point called by Cowrie for commands it doesn't natively handle.
    Returns the terminal output string to present to the attacker.
    """
    cmd_name = command.split()[0] if command.strip() else ""

    if cmd_name in NATIVE_COMMANDS:
        return None

    session_count = _session_counts.get(session_id, 0)
    if session_count >= MAX_LLM_CALLS_PER_SESSION:
        log.info(f"DARPAN LLM: Session {session_id} exceeded rate limit")
        return f"bash: {cmd_name}: command not found"

    cached = _cache_get(command)
    if cached:
        log.info(f"DARPAN LLM: Cache hit for command: {command[:60]}")
        _log_event(command, cached, session_id, cowrie_log_fn, from_cache=True)
        return cached

    log.info(f"DARPAN LLM: Calling API for command: {command[:60]}")
    response = _call_llm(command)

    _cache_set(command, response)
    _session_counts[session_id] = session_count + 1
    _log_event(command, response, session_id, cowrie_log_fn, from_cache=False)

    return response


def _log_event(
    command: str,
    response: str,
    session_id: str,
    log_fn,
    from_cache: bool,
) -> None:
    entry = {
        "eventid": "darpan.llm.command",
        "LLM_GENERATED": True,
        "from_cache": from_cache,
        "session": session_id,
        "command": command,
        "response_preview": response[:200],
        "model": MODEL,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    log.info(f"DARPAN_LLM_EVENT: {json.dumps(entry)}")
    if log_fn:
        try:
            log_fn(entry)
        except Exception:
            pass
