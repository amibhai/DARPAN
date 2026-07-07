#!/usr/bin/env bash
# DARPAN Real-Time Status Dashboard
# Run this script as root to monitor honeypot health and statistics
set -euo pipefail

DARPAN_ROOT="/opt/darpan"
ES_URL="http://127.0.0.1:9200"
TODAY=$(date +%Y.%m.%d)
INDEX="darpan-cowrie-${TODAY}"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'; DIM='\033[2m'

hdr() { echo -e "\n${CYAN}${BOLD}▶ $*${RESET}"; echo -e "${DIM}$(printf '─%.0s' {1..60})${RESET}"; }
ok()  { echo -e "  ${GREEN}●${RESET} $*"; }
warn(){ echo -e "  ${YELLOW}●${RESET} $*"; }
bad() { echo -e "  ${RED}●${RESET} $*"; }

clear
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║          DARPAN STATUS MONITOR — $(date '+%Y-%m-%d %H:%M:%S')          ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ─── CONTAINER HEALTH ─────────────────────────────────────────────────────────
hdr "Container Health"
CONTAINERS=(
    "darpan_cowrie-reflector-01"
    "darpan_elasticsearch"
    "darpan_logstash"
    "darpan_kibana"
    "darpan_filebeat"
)

for ctr in "${CONTAINERS[@]}"; do
    STATUS=$(docker inspect --format='{{.State.Status}}' "$ctr" 2>/dev/null || echo "not_found")
    HEALTH=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}N/A{{end}}' "$ctr" 2>/dev/null || echo "N/A")
    DISPLAY_NAME="${ctr#darpan_}"
    case "$STATUS" in
        running)  ok  "${DISPLAY_NAME}: ${GREEN}running${RESET} (health: $HEALTH)" ;;
        exited)   bad "${DISPLAY_NAME}: ${RED}exited${RESET}" ;;
        not_found)warn "${DISPLAY_NAME}: ${YELLOW}not found${RESET}" ;;
        *)        warn "${DISPLAY_NAME}: ${YELLOW}$STATUS${RESET}" ;;
    esac
done

# ─── ACTIVE HONEYPOT CONNECTIONS ─────────────────────────────────────────────
hdr "Active Honeypot Connections"
SSH_CONNS=$(ss -tn 2>/dev/null | grep -c ":2222 " || echo 0)
TEL_CONNS=$(ss -tn 2>/dev/null | grep -c ":2223 " || echo 0)
echo "  SSH (2222): ${SSH_CONNS} active connections"
echo "  Telnet (2223): ${TEL_CONNS} active connections"
if [[ $((SSH_CONNS + TEL_CONNS)) -gt 0 ]]; then
    echo ""
    echo "  ${BOLD}Current attackers:${RESET}"
    ss -tnp 2>/dev/null | grep -E ":2222|:2223" | awk '{print "    " $5}' | sort -u || true
fi

# ─── TODAY'S ATTACK STATS ─────────────────────────────────────────────────────
hdr "Today's Attack Statistics (${TODAY})"

if curl -sf "$ES_URL/_cluster/health" 2>/dev/null | grep -qE '"status":"(green|yellow)"'; then

    # Total sessions today
    TOTAL=$(curl -sf "$ES_URL/${INDEX}/_count" \
        -H 'Content-Type: application/json' \
        -d '{"query":{"term":{"eventid":"cowrie.session.connect"}}}' \
        2>/dev/null | jq -r '.count // 0')
    echo "  Total sessions today:     ${BOLD}${TOTAL}${RESET}"

    # Unique source IPs
    UNIQUE_IPS=$(curl -sf "$ES_URL/${INDEX}/_search" \
        -H 'Content-Type: application/json' \
        -d '{"size":0,"aggs":{"unique_ips":{"cardinality":{"field":"src_ip"}}}}' \
        2>/dev/null | jq -r '.aggregations.unique_ips.value // 0')
    echo "  Unique source IPs:        ${BOLD}${UNIQUE_IPS}${RESET}"

    # Top 5 countries
    echo ""
    echo "  ${BOLD}Top 5 Attacker Countries:${RESET}"
    curl -sf "$ES_URL/${INDEX}/_search" \
        -H 'Content-Type: application/json' \
        -d '{"size":0,"aggs":{"countries":{"terms":{"field":"geoip.country_name","size":5}}}}' \
        2>/dev/null | \
        jq -r '.aggregations.countries.buckets[]? | "    \(.key // "Unknown"): \(.doc_count) sessions"' || \
        echo "    (no geoip data yet)"

    # Auth successes (attackers that "got in")
    AUTH_OK=$(curl -sf "$ES_URL/${INDEX}/_count" \
        -H 'Content-Type: application/json' \
        -d '{"query":{"term":{"eventid":"cowrie.login.success"}}}' \
        2>/dev/null | jq -r '.count // 0')
    echo ""
    echo "  Auth successes (\"got in\"): ${BOLD}${YELLOW}${AUTH_OK}${RESET}"

    # File downloads by attackers
    DOWNLOADS=$(curl -sf "$ES_URL/${INDEX}/_count" \
        -H 'Content-Type: application/json' \
        -d '{"query":{"term":{"eventid":"cowrie.session.file_download"}}}' \
        2>/dev/null | jq -r '.count // 0')
    echo "  Files downloaded:         ${BOLD}${RED}${DOWNLOADS}${RESET}"

else
    warn "Elasticsearch unavailable — cannot query attack stats"
fi

# ─── ACTIVE CAMPAIGNS ─────────────────────────────────────────────────────────
hdr "Active Campaigns"
CAMP_COUNT=$(find "$DARPAN_ROOT/intel/campaigns" -name "CAMP-*.json" 2>/dev/null | wc -l || echo 0)
echo "  Total campaigns tracked: ${BOLD}${CAMP_COUNT}${RESET}"
if [[ $CAMP_COUNT -gt 0 ]]; then
    echo ""
    echo "  ${BOLD}Recent campaigns:${RESET}"
    find "$DARPAN_ROOT/intel/campaigns" -name "CAMP-*.json" \
        -printf '%T@ %p\n' 2>/dev/null | \
        sort -rn | head -5 | \
        awk '{print $2}' | \
        xargs -I{} bash -c 'echo "    $(basename {}) — first_seen: $(jq -r .first_seen {} 2>/dev/null)"' || true
fi

# ─── HONEYTOKEN ALERTS ────────────────────────────────────────────────────────
hdr "Latest Honeytoken Alert Events"
ALERT_FILE="$DARPAN_ROOT/intel/alerts/honeytoken_alerts.json"
if [[ -f "$ALERT_FILE" ]] && [[ -s "$ALERT_FILE" ]]; then
    echo ""
    tail -5 "$ALERT_FILE" | jq -r \
        '"\(.timestamp // "unknown") | \(.alert_level) | \(.src_ip // "unknown") | \(.reason)"' \
        2>/dev/null | while read -r line; do
        echo -e "  ${RED}⚠${RESET}  $line"
    done
else
    ok "No honeytoken alerts yet"
fi

# ─── DISK USAGE ──────────────────────────────────────────────────────────────
hdr "Storage"
LOG_SIZE=$(du -sh "$DARPAN_ROOT/logs" 2>/dev/null | cut -f1 || echo "N/A")
MALWARE_SIZE=$(du -sh "$DARPAN_ROOT/intel/malware_samples" 2>/dev/null | cut -f1 || echo "N/A")
ES_DATA=$(du -sh /var/lib/docker/volumes/focus_esdata 2>/dev/null | cut -f1 || echo "N/A")
echo "  Cowrie logs:         ${LOG_SIZE}"
echo "  Malware samples:     ${MALWARE_SIZE}"
echo "  Elasticsearch data:  ${ES_DATA}"

# ─── ML MODEL STATUS ─────────────────────────────────────────────────────────
hdr "ML Pipeline"
MODEL_FILE=$(find "$DARPAN_ROOT/ml" -name "*.pkl" -o -name "*.joblib" 2>/dev/null | head -1)
if [[ -n "$MODEL_FILE" ]]; then
    MTIME=$(stat -c '%y' "$MODEL_FILE" 2>/dev/null | cut -d. -f1 || echo "unknown")
    ok "Model: $(basename "$MODEL_FILE") — last trained: $MTIME"
else
    warn "No trained model found — run darpan-ml.service to train"
fi

# ─── SYSTEMD SERVICES ────────────────────────────────────────────────────────
hdr "Systemd Services"
for svc in darpan-beacon darpan-ml darpan-lure; do
    STATUS=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
    case "$STATUS" in
        active)   ok  "$svc: ${GREEN}active${RESET}" ;;
        inactive) warn "$svc: ${YELLOW}inactive${RESET}" ;;
        failed)   bad "$svc: ${RED}failed${RESET}" ;;
        *)        warn "$svc: ${YELLOW}$STATUS${RESET}" ;;
    esac
done

echo ""
echo -e "${DIM}$(date '+%Y-%m-%d %H:%M:%S') — DARPAN Status Monitor${RESET}"
echo ""
