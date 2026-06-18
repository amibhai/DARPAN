"""
DARPAN Threat Report Generator
Produces structured Markdown and JSON threat intelligence reports
from campaign data, classifier outputs, and SHAP explanations.
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

log = logging.getLogger("darpan.report_generator")

REPORT_DIR = Path("/opt/darpan/reports")
INTEL_DIR = Path("/opt/darpan/intel")


def _confidence_label(confidence: float) -> str:
    if confidence >= 0.80:
        return "HIGH"
    elif confidence >= 0.55:
        return "MEDIUM"
    return "LOW"


def _format_ioc_table(iocs: list[dict]) -> str:
    if not iocs:
        return "*No IOCs identified.*\n"
    lines = ["| Type | Value | Confidence | Notes |",
             "|------|-------|------------|-------|"]
    for ioc in iocs:
        lines.append(
            f"| {ioc.get('type','')} "
            f"| `{ioc.get('value','')}` "
            f"| {ioc.get('confidence','')} "
            f"| {ioc.get('notes','')} |"
        )
    return "\n".join(lines)


def _format_ttp_table(ttps: list[dict]) -> str:
    if not ttps:
        return "*No TTPs mapped.*\n"
    lines = [
        "| ATT&CK ID | Technique | Tactic | Evidence | Confidence |",
        "|-----------|-----------|--------|----------|------------|",
    ]
    for t in ttps:
        lines.append(
            f"| [{t.get('technique_id','')}](https://attack.mitre.org/techniques/{t.get('technique_id','').replace('.','/')}) "
            f"| {t.get('technique_name','')} "
            f"| {t.get('tactic','')} "
            f"| `{t.get('evidence_command','')[:50]}` "
            f"| {t.get('confidence','')} |"
        )
    return "\n".join(lines)


class ThreatReportGenerator:
    def __init__(
        self,
        report_dir: str | Path = REPORT_DIR,
        intel_dir: str | Path = INTEL_DIR,
    ):
        self.report_dir = Path(report_dir)
        self.intel_dir = Path(intel_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        campaign: dict,
        classifier_output: dict | None = None,
        shap_explanation: dict | None = None,
        enriched_ips: list[dict] | None = None,
    ) -> tuple[Path, Path]:
        campaign_id = campaign.get("campaign_id", "UNKNOWN")
        date_str = datetime.utcnow().strftime("%Y-%m-%d")
        filename_base = f"{campaign_id}_{date_str}"

        md_path = self.report_dir / f"{filename_base}.md"
        json_path = self.report_dir / f"{filename_base}.json"

        md_content = self._build_markdown(
            campaign, classifier_output, shap_explanation, enriched_ips
        )
        json_content = self._build_json(
            campaign, classifier_output, shap_explanation, enriched_ips
        )

        md_path.write_text(md_content, encoding="utf-8")
        json_path.write_text(json.dumps(json_content, indent=2, default=str), encoding="utf-8")

        log.info(f"Report saved: {md_path}")
        log.info(f"JSON report: {json_path}")
        return md_path, json_path

    def _build_markdown(
        self,
        campaign: dict,
        clf_out: dict | None,
        shap: dict | None,
        enriched_ips: list[dict] | None,
    ) -> str:
        campaign_id = campaign.get("campaign_id", "UNKNOWN")
        threat_class = (clf_out or {}).get("threat_class", "UNKNOWN")
        confidence = (clf_out or {}).get("confidence", 0.0)
        confidence_label = _confidence_label(confidence)
        ttps = campaign.get("TTPs", [])
        src_ips = campaign.get("src_ip_list", [])
        countries = campaign.get("countries", [])
        session_count = campaign.get("session_count", 0)
        first_seen = campaign.get("first_seen", "N/A")
        last_seen = campaign.get("last_seen", "N/A")
        top_cmds = campaign.get("most_common_commands", [])

        # IOC compilation
        iocs = self._compile_iocs(campaign, enriched_ips)

        # Defensive actions
        defensive_actions = self._get_defensive_actions(threat_class, ttps)

        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        attribution_justification = self._build_attribution_justification(
            threat_class, confidence, ttps, shap
        )

        md = f"""# DARPAN Threat Intelligence Report
## Campaign: `{campaign_id}`

> **Generated:** {now}
> **Classification:** `{threat_class}` | **Confidence:** {confidence:.1%} ({confidence_label})
> **Sensor:** DARPAN Reflector Node reflector-01

---

## 1. Executive Summary

This report documents campaign `{campaign_id}`, comprising **{session_count} intrusion sessions**
observed between {first_seen} and {last_seen}. The DARPAN deception framework
automatically detected, logged, and analyzed these attack sessions via the Cowrie honeypot.

The threat actor exhibits behavioral patterns consistent with **{threat_class}** activity.
{f"Source activity originated from {len(set(countries))} distinct countries, with primary"
 f" origination from {', '.join(countries[:3]) if countries else 'unknown regions'}." }
{len(ttps)} distinct MITRE ATT&CK techniques were observed. Immediate defensive action
is recommended for the indicators listed in Section 6.

---

## 2. Attack Timeline

| Timestamp | Event | Source IP | Detail |
|-----------|-------|-----------|--------|
| {first_seen} | Campaign Start | {src_ips[0] if src_ips else "N/A"} | First session observed |
| {last_seen} | Campaign End (last seen) | {src_ips[-1] if src_ips else "N/A"} | Last session observed |

**Session Statistics:**
- Total Sessions: {session_count}
- Unique Source IPs: {len(set(src_ips))}
- Countries Observed: {', '.join(countries) if countries else 'N/A'}
- Average Session Duration: {campaign.get('avg_session_duration', 0):.1f}s
- Credential Patterns: {json.dumps(campaign.get('credential_patterns', {}), indent=None)}

---

## 3. Threat Actor Profile

| Attribute | Value |
|-----------|-------|
| **Threat Class** | `{threat_class}` |
| **Confidence** | {confidence:.1%} ({confidence_label}) |
| **Sessions** | {session_count} |
| **Source Countries** | {', '.join(countries[:5]) if countries else 'N/A'} |
| **Primary Attack Vector** | SSH brute-force / credential stuffing |
| **Observed Capability** | {'Advanced — custom tooling detected' if threat_class in ('APT_CANDIDATE', 'ADVANCED_HUMAN') else 'Standard — known attack patterns'} |

{f"### Behavioral Indicators{chr(10)}{shap['explanation']}" if shap and 'explanation' in shap else ""}

---

## 4. TTP Analysis (MITRE ATT&CK)

{_format_ttp_table(ttps)}

---

## 5. Infrastructure Analysis

### Source IP Summary

| IP Address | Country | ISP/ASN | Abuse Score | Known Attacker | Open Ports |
|------------|---------|---------|-------------|----------------|------------|
"""
        if enriched_ips:
            for ip_info in enriched_ips[:20]:
                md += (
                    f"| `{ip_info.get('ip','')}` "
                    f"| {ip_info.get('country','')} "
                    f"| {ip_info.get('isp','N/A')} "
                    f"| {ip_info.get('abuse_confidence_score','N/A')} "
                    f"| {'Yes' if ip_info.get('known_attacker') else 'No'} "
                    f"| {', '.join(str(p) for p in ip_info.get('open_ports',[])[:5])} |\n"
                )
        else:
            for ip in src_ips[:10]:
                md += f"| `{ip}` | N/A | N/A | N/A | N/A | N/A |\n"

        md += f"""
---

## 6. Indicators of Compromise (IOCs)

{_format_ioc_table(iocs)}

---

## 7. Attribution Confidence

**Attribution Level:** `{confidence_label}`

{attribution_justification}

---

## 8. Recommended Defensive Actions

"""
        for i, action in enumerate(defensive_actions, 1):
            md += f"{i}. {action}\n"

        md += f"""
---

*Report generated by DARPAN v1.0 — Digital Asset Reflection and Proactive Analysis Network*
*Campaign data source: Cowrie honeypot (reflector-01)*
"""
        return md

    def _build_json(
        self,
        campaign: dict,
        clf_out: dict | None,
        shap: dict | None,
        enriched_ips: list[dict] | None,
    ) -> dict:
        return {
            "schema_version": "1.0",
            "report_type": "DARPAN_THREAT_INTEL",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "campaign": campaign,
            "classification": clf_out,
            "shap_explanation": shap,
            "enriched_ips": enriched_ips,
            "iocs": self._compile_iocs(campaign, enriched_ips),
            "mitre_ttps": campaign.get("TTPs", []),
            "defensive_actions": self._get_defensive_actions(
                (clf_out or {}).get("threat_class", ""),
                campaign.get("TTPs", []),
            ),
        }

    def _compile_iocs(
        self, campaign: dict, enriched_ips: list[dict] | None
    ) -> list[dict]:
        iocs: list[dict] = []
        seen: set[str] = set()

        for ip in campaign.get("src_ip_list", []):
            if ip and ip not in seen:
                seen.add(ip)
                enriched = next(
                    (e for e in (enriched_ips or []) if e.get("ip") == ip), {}
                )
                iocs.append({
                    "type": "ipv4-addr",
                    "value": ip,
                    "confidence": "HIGH" if enriched.get("known_attacker") else "MEDIUM",
                    "notes": f"Attacker source IP — {enriched.get('isp', 'ISP unknown')}",
                })

        for cmd in campaign.get("most_common_commands", [])[:5]:
            iocs.append({
                "type": "command-signature",
                "value": cmd[:80],
                "confidence": "MEDIUM",
                "notes": "Recurring attacker command pattern",
            })

        return iocs

    def _get_defensive_actions(
        self, threat_class: str, ttps: list[dict]
    ) -> list[str]:
        base_actions = [
            "Block source IPs at perimeter firewall using provided IOC list.",
            "Add attacker IP ranges to SIEM watchlist for 30-day monitoring.",
            "Rotate credentials matching patterns observed in this campaign.",
            "Review SSH access logs on production systems for compromise indicators.",
        ]
        tactic_actions: dict[str, str] = {
            "Persistence": "Audit cron jobs and systemd units on all servers for unauthorized entries.",
            "Lateral Movement": "Review SSH access between internal hosts; enforce MFA for privileged access.",
            "Credential Access": "Force password rotation for accounts in /etc/passwd and /etc/shadow.",
            "Command and Control": "Block outbound traffic on non-standard ports; inspect downloads for malware.",
            "Defense Evasion": "Enable comprehensive audit logging (auditd); alert on history clearing.",
            "Collection": "Review archive/compression tool usage; check for data exfiltration on egress.",
            "Execution": "Disable unnecessary interpreters (Python, Perl) on production servers.",
        }
        observed_tactics = {t.get("tactic", "") for t in ttps}
        extra = [v for k, v in tactic_actions.items() if k in observed_tactics]

        if threat_class in ("APT_CANDIDATE", "ADVANCED_HUMAN"):
            extra.append("Engage incident response team — advanced actor detected.")
            extra.append("Conduct full forensic review of systems accessible from attacker IPs.")
        elif threat_class == "WORM_BOT":
            extra.append("Scan internal network for compromised hosts exhibiting same IOC patterns.")

        return base_actions + extra

    def _build_attribution_justification(
        self,
        threat_class: str,
        confidence: float,
        ttps: list[dict],
        shap: dict | None,
    ) -> str:
        level = _confidence_label(confidence)
        tactic_set = {t.get("tactic", "") for t in ttps}
        factors = [
            f"Classifier confidence: {confidence:.1%}",
            f"Distinct MITRE tactics observed: {len(tactic_set)} ({', '.join(sorted(tactic_set)[:3])}...)" if tactic_set else "",
        ]
        if shap and "top_features" in shap:
            top = shap["top_features"][:3]
            for f in top:
                factors.append(f"Feature '{f['feature']}': {f['value']} ({f['direction']} classification)")

        justification = f"Attribution is assessed at **{level}** confidence based on:\n\n"
        for factor in factors:
            if factor:
                justification += f"- {factor}\n"

        caveats = {
            "LOW": "\n> ⚠ Low confidence: insufficient session data or novel behavior pattern. Treat as indicative only.",
            "MEDIUM": "\n> Attribution is probable but not certain. Additional sessions needed for confirmation.",
            "HIGH": "\n> High confidence: consistent behavioral fingerprint across multiple sessions.",
        }
        justification += caveats.get(level, "")
        return justification
