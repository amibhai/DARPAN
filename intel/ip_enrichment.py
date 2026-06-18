"""
DARPAN IP Reputation Enrichment
Queries AbuseIPDB, Shodan InternetDB, and ipapi.co for attacker IP intelligence.
Caches results and outputs STIX 2.1 indicator objects.
"""
import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import requests

log = logging.getLogger("darpan.ip_enrichment")

DB_PATH = Path("/opt/darpan/intel/.ip_cache.db")
IOC_DIR = Path("/opt/darpan/intel")
CACHE_TTL_HOURS = 24
REQUEST_TIMEOUT = 10
RATE_LIMIT_DELAY = 1.0

ABUSEIPDB_KEY = ""  # Set via env: ABUSEIPDB_API_KEY


def _get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip          TEXT PRIMARY KEY,
            data        TEXT NOT NULL,
            fetched_at  INTEGER NOT NULL
        )
    """)
    conn.commit()
    return conn


def _cache_get(ip: str) -> dict | None:
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT data, fetched_at FROM ip_cache WHERE ip=?", (ip,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    fetched_at = datetime.fromtimestamp(row[1])
    if datetime.utcnow() - fetched_at > timedelta(hours=CACHE_TTL_HOURS):
        return None
    return json.loads(row[0])


def _cache_set(ip: str, data: dict) -> None:
    conn = _get_db()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO ip_cache VALUES (?,?,?)",
            (ip, json.dumps(data), int(time.time()))
        )
        conn.commit()
    finally:
        conn.close()


class IPEnricher:
    def __init__(self, abuseipdb_key: str = ""):
        self.abuseipdb_key = abuseipdb_key or ABUSEIPDB_KEY
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "DARPAN-ThreatIntel/1.0"

    def enrich(self, ip: str) -> dict[str, Any]:
        cached = _cache_get(ip)
        if cached:
            log.debug(f"Cache hit: {ip}")
            return cached

        log.info(f"Enriching IP: {ip}")
        result: dict[str, Any] = {
            "ip": ip,
            "fetched_at": datetime.utcnow().isoformat() + "Z",
        }

        # AbuseIPDB
        abuse = self._query_abuseipdb(ip)
        result.update(abuse)

        time.sleep(RATE_LIMIT_DELAY)

        # Shodan InternetDB (free, no key)
        shodan = self._query_shodan_internetdb(ip)
        result.update(shodan)

        time.sleep(RATE_LIMIT_DELAY)

        # ipapi.co geolocation (free tier)
        geo = self._query_ipapi(ip)
        result.update(geo)

        # Derived fields
        result["known_attacker"] = (
            result.get("abuse_confidence_score", 0) > 25
            or result.get("total_reports", 0) > 5
        )

        _cache_set(ip, result)
        return result

    def enrich_batch(self, ips: list[str]) -> list[dict]:
        unique_ips = list(dict.fromkeys(ip for ip in ips if ip))
        results = []
        for ip in unique_ips:
            try:
                results.append(self.enrich(ip))
            except Exception as e:
                log.error(f"Failed to enrich {ip}: {e}")
                results.append({"ip": ip, "error": str(e)})
        return results

    def _query_abuseipdb(self, ip: str) -> dict:
        if not self.abuseipdb_key:
            return {"abuse_confidence_score": None, "total_reports": None, "abuseipdb_error": "no_api_key"}
        try:
            resp = self._session.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 429:
                log.warning("AbuseIPDB rate limit hit")
                return {"abuseipdb_error": "rate_limited"}
            resp.raise_for_status()
            d = resp.json().get("data", {})
            return {
                "abuse_confidence_score": d.get("abuseConfidenceScore"),
                "total_reports": d.get("totalReports"),
                "last_reported_at": d.get("lastReportedAt"),
                "usage_type": d.get("usageType"),
                "isp": d.get("isp"),
                "domain": d.get("domain"),
                "tor_exit_node": d.get("isTor", False),
                "country": d.get("countryCode"),
            }
        except requests.RequestException as e:
            log.warning(f"AbuseIPDB error for {ip}: {e}")
            return {"abuseipdb_error": str(e)}

    def _query_shodan_internetdb(self, ip: str) -> dict:
        try:
            resp = self._session.get(
                f"https://internetdb.shodan.io/{ip}",
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 404:
                return {"open_ports": [], "cpes": [], "hostnames": [], "vulns": []}
            resp.raise_for_status()
            d = resp.json()
            return {
                "open_ports": d.get("ports", []),
                "cpes": d.get("cpes", []),
                "hostnames": d.get("hostnames", []),
                "vulns": d.get("vulns", []),
                "tags": d.get("tags", []),
                "vpn": "vpn" in d.get("tags", []),
                "proxy": "proxy" in d.get("tags", []),
            }
        except requests.RequestException as e:
            log.debug(f"Shodan InternetDB error for {ip}: {e}")
            return {"open_ports": [], "shodan_error": str(e)}

    def _query_ipapi(self, ip: str) -> dict:
        try:
            resp = self._session.get(
                f"https://ipapi.co/{ip}/json/",
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            d = resp.json()
            if d.get("error"):
                return {"geo_error": d.get("reason", "unknown")}
            return {
                "country": d.get("country_name") or d.get("country"),
                "country_code": d.get("country_code"),
                "city": d.get("city"),
                "region": d.get("region"),
                "org": d.get("org"),
                "asn": d.get("asn"),
                "latitude": d.get("latitude"),
                "longitude": d.get("longitude"),
                "timezone": d.get("timezone"),
            }
        except requests.RequestException as e:
            log.debug(f"ipapi error for {ip}: {e}")
            return {"geo_error": str(e)}

    def save_ioc_file(self, enriched_ips: list[dict], date: str | None = None) -> Path:
        date = date or datetime.utcnow().strftime("%Y-%m-%d")
        ioc_path = IOC_DIR / f"ioc_{date}.json"
        IOC_DIR.mkdir(parents=True, exist_ok=True)
        ioc_path.write_text(json.dumps(enriched_ips, indent=2, default=str), encoding="utf-8")
        log.info(f"IOC file saved: {ioc_path}")
        return ioc_path

    def to_stix_indicators(self, enriched_ips: list[dict]) -> list[dict]:
        indicators = []
        for ip_info in enriched_ips:
            ip = ip_info.get("ip", "")
            if not ip or not ip_info.get("known_attacker"):
                continue
            confidence_score = ip_info.get("abuse_confidence_score") or 0
            confidence = (
                "High" if confidence_score >= 75
                else "Medium" if confidence_score >= 25
                else "Low"
            )
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{self._uuid_from_ip(ip)}",
                "created": ip_info.get("fetched_at", datetime.utcnow().isoformat() + "Z"),
                "modified": ip_info.get("fetched_at", datetime.utcnow().isoformat() + "Z"),
                "name": f"Attacker IP: {ip}",
                "description": (
                    f"IP observed attacking DARPAN honeypot. "
                    f"Country: {ip_info.get('country', 'N/A')}. "
                    f"ISP: {ip_info.get('isp', 'N/A')}. "
                    f"AbuseIPDB confidence: {confidence_score}%."
                ),
                "indicator_types": ["malicious-activity", "compromised"],
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": ip_info.get("fetched_at", datetime.utcnow().isoformat() + "Z"),
                "confidence": confidence,
                "labels": ["honeypot-attacker", "darpan"],
                "extensions": {
                    "darpan-enrichment": {
                        "abuse_confidence_score": confidence_score,
                        "open_ports": ip_info.get("open_ports", []),
                        "asn": ip_info.get("asn"),
                        "tor_exit_node": ip_info.get("tor_exit_node", False),
                        "vpn": ip_info.get("vpn", False),
                        "vulns": ip_info.get("vulns", []),
                    }
                },
            }
            indicators.append(indicator)
        return indicators

    @staticmethod
    def _uuid_from_ip(ip: str) -> str:
        import hashlib
        h = hashlib.sha256(ip.encode()).hexdigest()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
