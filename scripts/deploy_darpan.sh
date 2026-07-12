#!/usr/bin/env bash
# DARPAN Master Deployment Orchestrator
# Run as root from /opt/darpan/
set -euo pipefail

DARPAN_ROOT="/opt/darpan"
ENV_FILE="$DARPAN_ROOT/.env"
LOG_FILE="/var/log/darpan_deploy.log"
KIBANA_IMPORT_TIMEOUT=180
ES_STARTUP_TIMEOUT=120

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BOLD='\033[1m'; RESET='\033[0m'

log()     { echo -e "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
ok()      { echo -e "${GREEN}[✓]${RESET} $*" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*" | tee -a "$LOG_FILE"; }
err()     { echo -e "${RED}[✗]${RESET} $*" | tee -a "$LOG_FILE"; }
die()     { err "$*"; exit 1; }
section() { echo -e "\n${CYAN}${BOLD}═══ $* ═══${RESET}\n"; }

[[ $EUID -eq 0 ]] || die "Must run as root"
cd "$DARPAN_ROOT" || die "Cannot cd to $DARPAN_ROOT — run 01_system_prep.sh first"

# ─── 1. PREREQUISITES CHECK ───────────────────────────────────────────────────
section "1. Prerequisites Check"

check_cmd() {
    command -v "$1" &>/dev/null && ok "$1 found: $(command -v "$1")" || die "$1 not found — run 01_system_prep.sh"
}

check_cmd docker
check_cmd docker-compose
check_cmd python3
check_cmd curl
check_cmd jq

docker info &>/dev/null || die "Docker daemon not running"
ok "Docker daemon is running"

# ─── 2. LOAD & VALIDATE .env ──────────────────────────────────────────────────
section "2. Environment Configuration"

[[ -f "$ENV_FILE" ]] || {
    warn ".env not found — copying from env.template"
    [[ -f "$DARPAN_ROOT/env.template" ]] || die "env.template missing"
    cp "$DARPAN_ROOT/env.template" "$ENV_FILE"
    warn "EDIT $ENV_FILE and set ANTHROPIC_API_KEY before re-running!"
    warn "At minimum: ANTHROPIC_API_KEY, DARPAN_HOST_IP"
}

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

REQUIRED_VARS=("ANTHROPIC_API_KEY" "DARPAN_HOST_IP" "ELASTIC_VERSION")
MISSING_VARS=()
for var in "${REQUIRED_VARS[@]}"; do
    [[ -z "${!var:-}" ]] && MISSING_VARS+=("$var") && warn "Missing: $var" || ok "$var is set"
done

if [[ ${#MISSING_VARS[@]} -gt 0 ]]; then
    err "Missing required variables: ${MISSING_VARS[*]}"
    die "Edit $ENV_FILE and fill in required variables, then re-run deploy."
fi

# Auto-detect host IP if not set
if [[ -z "${DARPAN_HOST_IP:-}" ]]; then
    DARPAN_HOST_IP=$(ip route get 1 | awk '{print $7}' | head -1)
    ok "Auto-detected DARPAN_HOST_IP=$DARPAN_HOST_IP"
fi

# ─── 3. SYSTEM PREP (idempotent) ─────────────────────────────────────────────
section "3. System Preparation"

PREP_MARKER="/opt/darpan/.system_prep_done"
if [[ -f "$PREP_MARKER" ]]; then
    ok "System prep already completed (found $PREP_MARKER)"
else
    log "Running 01_system_prep.sh..."
    bash "$DARPAN_ROOT/scripts/01_system_prep.sh" && touch "$PREP_MARKER"
    ok "System prep complete"
fi

# ─── 4. IPTABLES SETUP ───────────────────────────────────────────────────────
section "4. iptables NAT Setup"
# Apply the iptables setup script to configure NAT and containment
bash "$DARPAN_ROOT/scripts/02_iptables_setup.sh"
ok "iptables rules applied"

# ─── 5. GENERATE INITIAL HONEYFS ─────────────────────────────────────────────
section "5. Polymorphic Honeyfs Generation"
log "Generating fake filesystem for Cowrie..."
python3 "$DARPAN_ROOT/reflector/generate_honeyfs.py" \
    --output "$DARPAN_ROOT/reflector/honeyfs" \
    2>&1 | tee -a "$LOG_FILE" | tail -20
ok "Honeyfs generated"

# ─── 6. START FOCUS NODE (ELK) ────────────────────────────────────────────────
section "6. Focus Node — ELK Stack"
log "Starting Elasticsearch, Logstash, Kibana, Filebeat..."
cd "$DARPAN_ROOT/focus"
docker-compose up -d
cd "$DARPAN_ROOT"
ok "Focus node containers started"

# ─── 7. WAIT FOR ELASTICSEARCH ───────────────────────────────────────────────
section "7. Waiting for Elasticsearch Health"
log "Polling Elasticsearch (timeout: ${ES_STARTUP_TIMEOUT}s)..."
ELAPSED=0
until curl -sf http://127.0.0.1:9200/_cluster/health?pretty 2>/dev/null | \
      grep -qE '"status"\s*:\s*"(green|yellow)"'; do
    [[ $ELAPSED -ge $ES_STARTUP_TIMEOUT ]] && \
        die "Elasticsearch did not become healthy in ${ES_STARTUP_TIMEOUT}s"
    log "Waiting for Elasticsearch... (${ELAPSED}s elapsed)"
    sleep 5
    ELAPSED=$((ELAPSED + 5))
done
ES_STATUS=$(curl -sf http://127.0.0.1:9200/_cluster/health | jq -r '.status')
ok "Elasticsearch is healthy: status=$ES_STATUS"

# Create DARPAN index template
log "Creating DARPAN index template..."
curl -sf -X PUT http://127.0.0.1:9200/_index_template/darpan-cowrie \
    -H 'Content-Type: application/json' -d '{
    "index_patterns": ["darpan-cowrie-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.lifecycle.name": "darpan-policy"
        },
        "mappings": {
            "properties": {
                "src_ip":       {"type": "ip"},
                "geoip":        {"properties": {"location": {"type": "geo_point"}}},
                "timestamp":    {"type": "date"},
                "session":      {"type": "keyword"},
                "username":     {"type": "keyword"},
                "password":     {"type": "keyword"},
                "command":      {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "darpan_node":  {"type": "keyword"},
                "campaign_id":  {"type": "keyword"},
                "threat_class": {"type": "keyword"}
            }
        }
    }
}' 2>&1 | tee -a "$LOG_FILE" | tail -1
ok "Index template created"

# ─── 8. START REFLECTOR NODE ─────────────────────────────────────────────────
section "8. Reflector Node — Cowrie Honeypot"
cd "$DARPAN_ROOT/reflector"
docker-compose up -d --build
cd "$DARPAN_ROOT"
ok "Reflector container started"

# Wait for Cowrie ports
log "Verifying Cowrie is listening..."
sleep 5
for port in 2222 2223; do
    if ss -tnlp | grep -q ":$port "; then
        ok "Cowrie listening on port $port"
    else
        warn "Cowrie port $port not yet open — may still be starting"
    fi
done

# ─── 9. IMPORT KIBANA DASHBOARDS ─────────────────────────────────────────────
section "9. Kibana Dashboard Import"
log "Waiting for Kibana to be ready (timeout: ${KIBANA_IMPORT_TIMEOUT}s)..."
ELAPSED=0
until curl -sf http://127.0.0.1:5601/api/status 2>/dev/null | grep -q '"level":"available"'; do
    [[ $ELAPSED -ge $KIBANA_IMPORT_TIMEOUT ]] && {
        warn "Kibana not ready in ${KIBANA_IMPORT_TIMEOUT}s — skipping dashboard import"
        break
    }
    log "Waiting for Kibana... (${ELAPSED}s)"
    sleep 10
    ELAPSED=$((ELAPSED + 10))
done

if curl -sf http://127.0.0.1:5601/api/status 2>/dev/null | grep -q '"level":"available"'; then
    log "Importing DARPAN Kibana dashboards..."
    IMPORT_RESULT=$(curl -sf -X POST \
        "http://127.0.0.1:5601/api/saved_objects/_import?overwrite=true" \
        -H "kbn-xsrf: true" \
        -F "file=@$DARPAN_ROOT/focus/kibana/darpan_dashboards.ndjson" 2>&1)
    echo "$IMPORT_RESULT" | jq -r '.successCount // "unknown"' | \
        xargs -I{} ok "Imported {} Kibana saved objects"
fi

# ─── 10. CRON JOB — LURE SCHEDULER ──────────────────────────────────────────
section "10. Cron Setup — Lure Scheduler"
CRON_JOB="0 */6 * * * darpan python3 $DARPAN_ROOT/lures/lure_scheduler.py >> /var/log/darpan_lures.log 2>&1"
CRON_FILE="/etc/cron.d/darpan-lures"
echo "$CRON_JOB" > "$CRON_FILE"
chmod 644 "$CRON_FILE"
ok "Lure scheduler cron installed at $CRON_FILE (every 6 hours)"

# ─── 11. SYSTEMD SERVICES ────────────────────────────────────────────────────
section "11. Systemd Services"
for svc in darpan-beacon darpan-ml darpan-lure; do
    SVC_SRC="$DARPAN_ROOT/systemd/${svc}.service"
    SVC_DST="/etc/systemd/system/${svc}.service"
    if [[ -f "$SVC_SRC" ]]; then
        cp "$SVC_SRC" "$SVC_DST"
        systemctl daemon-reload
        systemctl enable "$svc" 2>/dev/null || warn "Could not enable $svc"
        ok "Installed systemd service: $svc"
    else
        warn "Service file not found: $SVC_SRC"
    fi
done

# Start beacon immediately
systemctl start darpan-beacon 2>/dev/null && ok "darpan-beacon started" || \
    warn "Could not start darpan-beacon (may need .env configuration)"

# ─── 12. DARPAN STATUS BANNER ────────────────────────────────────────────────
section "12. DARPAN Status"
sleep 3

ES_INDEX_COUNT=$(curl -sf "http://127.0.0.1:9200/_cat/indices?h=index" 2>/dev/null | wc -l || echo "N/A")
KIBANA_URL="http://${DARPAN_HOST_IP}:5601"

echo ""
echo -e "${CYAN}${BOLD}"
cat <<'BANNER'
 ██████╗  █████╗ ██████╗ ██████╗  █████╗ ███╗   ██╗
 ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗  ██║
 ██║  ██║███████║██████╔╝██████╔╝███████║██╔██╗ ██║
 ██║  ██║██╔══██║██╔══██╗██╔═══╝ ██╔══██║██║╚██╗██║
 ██████╔╝██║  ██║██║  ██║██║     ██║  ██║██║ ╚████║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝
 Digital Asset Reflection and Proactive Analysis Network
BANNER
echo -e "${RESET}"

echo -e "${BOLD}Container Status:${RESET}"
docker ps --filter "label=com.darpan=true" --format \
    "  {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || \
docker ps --format "  {{.Names}}\t{{.Status}}" | grep -i "darpan\|cowrie\|elastic\|kibana\|logstash\|filebeat" || true

echo ""
echo -e "${BOLD}Listening Ports:${RESET}"
ss -tnlp 2>/dev/null | grep -E ":(22|23|80|2222|2223|9200|5601|5044) " || true

echo ""
echo -e "${BOLD}Kibana URL:${RESET}    ${CYAN}$KIBANA_URL${RESET}"
echo -e "${BOLD}Elasticsearch:${RESET} ${CYAN}http://${DARPAN_HOST_IP}:9200${RESET}"
echo -e "${BOLD}ES Indices:${RESET}    $ES_INDEX_COUNT"
echo ""
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║  DARPAN ACTIVE — DECEPTION LAYER ONLINE           ║${RESET}"
echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════╝${RESET}"
echo ""
log "====== DARPAN Deployment COMPLETE ======"
