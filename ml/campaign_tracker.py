"""
DARPAN Campaign Tracker
DBSCAN clustering to group attacker sessions into coordinated campaigns.
Maps TTPs to MITRE ATT&CK framework.
"""
import json
import logging
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

log = logging.getLogger("darpan.campaign_tracker")

CAMPAIGN_DIR = Path("/opt/darpan/intel/campaigns")

# MITRE ATT&CK command-to-TTP mapping
COMMAND_TTP_MAP: dict[str, dict] = {
    # Ingress Tool Transfer
    "wget":    {"tactic": "Command and Control", "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer", "confidence": "HIGH"},
    "curl":    {"tactic": "Command and Control", "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer", "confidence": "HIGH"},
    "tftp":    {"tactic": "Command and Control", "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer", "confidence": "HIGH"},
    "axel":    {"tactic": "Command and Control", "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer", "confidence": "MEDIUM"},
    # Scheduled Task / Job
    "crontab": {"tactic": "Persistence", "technique_id": "T1053.003",
                "technique_name": "Scheduled Task/Job: Cron", "confidence": "HIGH"},
    "at":      {"tactic": "Persistence", "technique_id": "T1053.001",
                "technique_name": "Scheduled Task/Job: At", "confidence": "HIGH"},
    # Credential Dumping
    "passwd":  {"tactic": "Credential Access", "technique_id": "T1003.008",
                "technique_name": "OS Credential Dumping: /etc/passwd", "confidence": "HIGH"},
    "shadow":  {"tactic": "Credential Access", "technique_id": "T1003.008",
                "technique_name": "OS Credential Dumping: /etc/shadow", "confidence": "HIGH"},
    "mimikatz":{"tactic": "Credential Access", "technique_id": "T1003.001",
                "technique_name": "OS Credential Dumping: LSASS", "confidence": "HIGH"},
    # SSH Lateral Movement
    "ssh":     {"tactic": "Lateral Movement", "technique_id": "T1021.004",
                "technique_name": "Remote Services: SSH", "confidence": "MEDIUM"},
    "scp":     {"tactic": "Lateral Movement", "technique_id": "T1021.004",
                "technique_name": "Remote Services: SSH", "confidence": "MEDIUM"},
    "sftp":    {"tactic": "Lateral Movement", "technique_id": "T1021.004",
                "technique_name": "Remote Services: SSH", "confidence": "MEDIUM"},
    # System Information Discovery
    "uname":   {"tactic": "Discovery", "technique_id": "T1082",
                "technique_name": "System Information Discovery", "confidence": "MEDIUM"},
    "whoami":  {"tactic": "Discovery", "technique_id": "T1033",
                "technique_name": "System Owner/User Discovery", "confidence": "HIGH"},
    "id":      {"tactic": "Discovery", "technique_id": "T1033",
                "technique_name": "System Owner/User Discovery", "confidence": "HIGH"},
    "hostname":{"tactic": "Discovery", "technique_id": "T1082",
                "technique_name": "System Information Discovery", "confidence": "MEDIUM"},
    # Deobfuscate/Decode
    "base64":  {"tactic": "Defense Evasion", "technique_id": "T1140",
                "technique_name": "Deobfuscate/Decode Files or Information", "confidence": "HIGH"},
    "openssl": {"tactic": "Defense Evasion", "technique_id": "T1140",
                "technique_name": "Deobfuscate/Decode Files or Information", "confidence": "MEDIUM"},
    # Command and Scripting Interpreter
    "python":  {"tactic": "Execution", "technique_id": "T1059.006",
                "technique_name": "Command and Scripting Interpreter: Python", "confidence": "HIGH"},
    "python3": {"tactic": "Execution", "technique_id": "T1059.006",
                "technique_name": "Command and Scripting Interpreter: Python", "confidence": "HIGH"},
    "perl":    {"tactic": "Execution", "technique_id": "T1059.006",
                "technique_name": "Command and Scripting Interpreter: Perl", "confidence": "HIGH"},
    "bash":    {"tactic": "Execution", "technique_id": "T1059.004",
                "technique_name": "Command and Scripting Interpreter: Unix Shell", "confidence": "MEDIUM"},
    "sh":      {"tactic": "Execution", "technique_id": "T1059.004",
                "technique_name": "Command and Scripting Interpreter: Unix Shell", "confidence": "MEDIUM"},
    # Network Service Discovery
    "nmap":    {"tactic": "Discovery", "technique_id": "T1046",
                "technique_name": "Network Service Discovery", "confidence": "HIGH"},
    "masscan": {"tactic": "Discovery", "technique_id": "T1046",
                "technique_name": "Network Service Discovery", "confidence": "HIGH"},
    "nc":      {"tactic": "Lateral Movement", "technique_id": "T1049",
                "technique_name": "System Network Connections Discovery", "confidence": "MEDIUM"},
    # Indicator Removal
    "shred":   {"tactic": "Defense Evasion", "technique_id": "T1070.004",
                "technique_name": "Indicator Removal: File Deletion", "confidence": "HIGH"},
    "history": {"tactic": "Defense Evasion", "technique_id": "T1070.003",
                "technique_name": "Indicator Removal: Clear Command History", "confidence": "HIGH"},
    # Privilege Escalation
    "sudo":    {"tactic": "Privilege Escalation", "technique_id": "T1548.003",
                "technique_name": "Abuse Elevation Control Mechanism: Sudo", "confidence": "MEDIUM"},
    "chmod":   {"tactic": "Privilege Escalation", "technique_id": "T1222",
                "technique_name": "File and Directory Permissions Modification", "confidence": "MEDIUM"},
    # Collection
    "tar":     {"tactic": "Collection", "technique_id": "T1560.001",
                "technique_name": "Archive Collected Data: Archive via Utility", "confidence": "MEDIUM"},
    "zip":     {"tactic": "Collection", "technique_id": "T1560.001",
                "technique_name": "Archive Collected Data: Archive via Utility", "confidence": "MEDIUM"},
    "mysqldump":{"tactic": "Collection", "technique_id": "T1005",
                "technique_name": "Data from Local System", "confidence": "HIGH"},
    # Account Discovery
    "cat /etc/passwd": {
        "tactic": "Discovery", "technique_id": "T1087.001",
        "technique_name": "Account Discovery: Local Account", "confidence": "HIGH",
    },
}

CLUSTER_FEATURES = [
    "iat_mean", "commands_per_minute", "command_count",
    "recon_command_score", "lateral_movement_score", "persistence_command_score",
    "payload_entropy", "base64_usage_flag", "auth_success",
]


class CampaignTracker:
    def __init__(
        self,
        eps: float = 0.5,
        min_samples: int = 3,
        campaign_dir: str | Path = CAMPAIGN_DIR,
    ):
        self.eps = eps
        self.min_samples = min_samples
        self.campaign_dir = Path(campaign_dir)
        self.campaign_dir.mkdir(parents=True, exist_ok=True)
        self._campaigns: dict[str, dict] = {}

    def cluster_sessions(self, df: pd.DataFrame) -> pd.DataFrame:
        feature_cols = [c for c in CLUSTER_FEATURES if c in df.columns]
        if not feature_cols:
            log.error("No clustering features found in dataframe")
            return df

        X = df[feature_cols].fillna(0).replace([np.inf, -np.inf], 0)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Auto-tune eps via elbow on k-distance graph
        eps = self._auto_tune_eps(X_scaled)
        log.info(f"Using eps={eps:.3f}, min_samples={self.min_samples}")

        dbscan = DBSCAN(eps=eps, min_samples=self.min_samples, metric="euclidean", n_jobs=-1)
        labels = dbscan.fit_predict(X_scaled)
        df = df.copy()
        df["cluster_label"] = labels

        n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
        n_noise = (labels == -1).sum()
        log.info(f"Found {n_clusters} clusters, {n_noise} noise points")
        return df

    def _auto_tune_eps(self, X_scaled: np.ndarray) -> float:
        from sklearn.neighbors import NearestNeighbors
        k = min(self.min_samples, len(X_scaled) - 1)
        if k < 1:
            return self.eps
        nbrs = NearestNeighbors(n_neighbors=k).fit(X_scaled)
        distances, _ = nbrs.kneighbors(X_scaled)
        k_dists = np.sort(distances[:, -1])

        # Elbow: find max curvature
        diffs = np.diff(k_dists)
        if len(diffs) > 1:
            elbow_idx = np.argmax(np.diff(diffs)) + 1
            return float(k_dists[elbow_idx])
        return self.eps

    def build_campaigns(self, df: pd.DataFrame) -> list[dict]:
        if "cluster_label" not in df.columns:
            df = self.cluster_sessions(df)

        campaigns = []
        today = datetime.utcnow().strftime("%Y-%m-%d")

        for cluster_id in sorted(df["cluster_label"].unique()):
            if cluster_id == -1:
                continue

            cluster_df = df[df["cluster_label"] == cluster_id]
            campaign_id = f"CAMP-{today}-{cluster_id:04d}"

            # Extract TTPs from commands
            all_commands: list[str] = []
            if "command_text" in cluster_df.columns:
                all_commands = " ".join(cluster_df["command_text"].fillna("")).split()

            ttps = self._map_ttps(all_commands)
            top_commands = [c for c, _ in Counter(all_commands).most_common(10)]

            src_ips = cluster_df["src_ip"].dropna().unique().tolist() \
                if "src_ip" in cluster_df.columns else []
            countries = cluster_df["src_country"].dropna().unique().tolist() \
                if "src_country" in cluster_df.columns else []
            cred_patterns = cluster_df["credential_type"].value_counts().to_dict() \
                if "credential_type" in cluster_df.columns else {}

            campaign = {
                "campaign_id": campaign_id,
                "cluster_id": int(cluster_id),
                "session_count": len(cluster_df),
                "first_seen": self._get_timestamp(cluster_df, "min"),
                "last_seen": self._get_timestamp(cluster_df, "max"),
                "src_ip_list": src_ips,
                "countries": countries,
                "TTPs": ttps,
                "most_common_commands": top_commands,
                "credential_patterns": cred_patterns,
                "avg_session_duration": float(cluster_df["session_duration"].mean())
                    if "session_duration" in cluster_df.columns else 0,
                "generated_at": datetime.utcnow().isoformat() + "Z",
            }
            campaigns.append(campaign)
            self._campaigns[campaign_id] = campaign
            self._save_campaign(campaign)

        log.info(f"Built {len(campaigns)} campaigns")
        return campaigns

    def _get_timestamp(self, df: pd.DataFrame, mode: str) -> str:
        for col in ["@timestamp", "cowrie_timestamp", "timestamp"]:
            if col in df.columns:
                vals = df[col].dropna()
                if not vals.empty:
                    return (vals.min() if mode == "min" else vals.max())
        return datetime.utcnow().isoformat() + "Z"

    def _map_ttps(self, commands: list[str]) -> list[dict]:
        seen: set[str] = set()
        ttps: list[dict] = []
        for cmd in commands:
            cmd_lower = cmd.lower().strip()
            for key, ttp in COMMAND_TTP_MAP.items():
                if key in cmd_lower and ttp["technique_id"] not in seen:
                    seen.add(ttp["technique_id"])
                    ttps.append({
                        **ttp,
                        "evidence_command": cmd[:80],
                    })
        return sorted(ttps, key=lambda x: x["technique_id"])

    def _save_campaign(self, campaign: dict) -> Path:
        path = self.campaign_dir / f"{campaign['campaign_id']}.json"
        path.write_text(json.dumps(campaign, indent=2, default=str), encoding="utf-8")
        return path

    def generate_campaign_timeline(
        self, campaign_id: str, output_dir: str | Path = "/opt/darpan/reports"
    ) -> str:
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            cpath = self.campaign_dir / f"{campaign_id}.json"
            if cpath.exists():
                campaign = json.loads(cpath.read_text())
            else:
                return f"Campaign {campaign_id} not found"

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # ASCII timeline
        ascii_lines = [
            f"Campaign Timeline: {campaign_id}",
            "=" * 60,
            f"  First Seen : {campaign.get('first_seen', 'N/A')}",
            f"  Last Seen  : {campaign.get('last_seen', 'N/A')}",
            f"  Sessions   : {campaign.get('session_count', 0)}",
            f"  Source IPs : {len(campaign.get('src_ip_list', []))}",
            "",
            "TTPs Observed:",
        ]
        for ttp in campaign.get("TTPs", []):
            ascii_lines.append(
                f"  [{ttp['technique_id']}] {ttp['technique_name']} "
                f"({ttp['confidence']}) — {ttp.get('evidence_command', '')[:40]}"
            )

        ascii_timeline = "\n".join(ascii_lines)

        # PNG chart
        ttps = campaign.get("TTPs", [])
        if ttps:
            fig, ax = plt.subplots(figsize=(12, 6))
            tactics = [t.get("tactic", "Unknown") for t in ttps]
            tactic_counts = Counter(tactics)
            colors = plt.cm.tab10(range(len(tactic_counts)))
            bars = ax.bar(
                range(len(tactic_counts)),
                list(tactic_counts.values()),
                color=colors,
            )
            ax.set_xticks(range(len(tactic_counts)))
            ax.set_xticklabels(list(tactic_counts.keys()), rotation=45, ha="right")
            ax.set_ylabel("Technique Count")
            ax.set_title(f"DARPAN — {campaign_id}: MITRE ATT&CK Tactic Distribution")
            plt.tight_layout()
            png_path = output_dir / f"{campaign_id}_timeline.png"
            plt.savefig(str(png_path), dpi=150, bbox_inches="tight")
            plt.close()

        return ascii_timeline
