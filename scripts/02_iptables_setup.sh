#!/usr/bin/env bash
# DARPAN Phase 1 — iptables NAT + Containment Rules
# Run as root on Parrot OS
set -euo pipefail

LOG_FILE="/var/log/darpan_setup.log"
DARPAN_NET="172.20.0.0/24"
HONEYPOT_IP="172.20.0.10"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
die() { log "ERROR: $*"; exit 1; }

[[ $EUID -eq 0 ]] || die "Must run as root"

# Auto-detect primary external interface
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
[[ -z "$IFACE" ]] && die "Could not detect primary network interface"
log "Using external interface: $IFACE"

log "====== DARPAN iptables Setup Starting ======"

# ─── FLUSH EXISTING DARPAN RULES ─────────────────────────────────────────────
log "Flushing existing DARPAN iptables rules..."
# Remove rules with DARPAN comment to allow re-runs
iptables -t nat -S PREROUTING 2>/dev/null | grep "DARPAN" | while read -r rule; do
    iptables -t nat -D PREROUTING ${rule#-A PREROUTING } 2>/dev/null || true
done
iptables -S FORWARD 2>/dev/null | grep "DARPAN" | while read -r rule; do
    iptables -D FORWARD ${rule#-A FORWARD } 2>/dev/null || true
done
iptables -S INPUT 2>/dev/null | grep "DARPAN" | while read -r rule; do
    iptables -D INPUT ${rule#-A INPUT } 2>/dev/null || true
done

# ─── 1. MASQUERADE FOR DOCKER DARPAN NETWORK ─────────────────────────────────
log "Enabling NAT masquerade for DARPAN network..."
iptables -t nat -C POSTROUTING -s "$DARPAN_NET" -o "$IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "$DARPAN_NET" -o "$IFACE" -j MASQUERADE

# ─── 2. LOGGING RULES — HONEYPOT-DESTINED PACKETS ────────────────────────────
log "Adding LOG rules for honeypot-destined traffic..."

# Log SSH to honeypot
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 22 \
    -m comment --comment "DARPAN-LOG-SSH" \
    -j LOG --log-prefix "DARPAN-HONEYPOT: " --log-level 4

# Log Telnet to honeypot
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 23 \
    -m comment --comment "DARPAN-LOG-TELNET" \
    -j LOG --log-prefix "DARPAN-HONEYPOT: " --log-level 4

# Log HTTP to honeypot
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 80 \
    -m comment --comment "DARPAN-LOG-HTTP" \
    -j LOG --log-prefix "DARPAN-HONEYPOT: " --log-level 4

# ─── 3. DNAT REDIRECT RULES — INBOUND TO HONEYPOT ────────────────────────────
log "Adding DNAT redirect rules..."

# Port 22 → Cowrie SSH (2222)
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 22 \
    -m comment --comment "DARPAN-REDIR-SSH" \
    -j DNAT --to-destination "$HONEYPOT_IP:2222"

# Port 23 → Cowrie Telnet (2223)
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 23 \
    -m comment --comment "DARPAN-REDIR-TELNET" \
    -j DNAT --to-destination "$HONEYPOT_IP:2223"

# Port 80 → Future HTTP honeypot (8080)
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 80 \
    -m comment --comment "DARPAN-REDIR-HTTP" \
    -j DNAT --to-destination "$HONEYPOT_IP:8080"

# ─── 4. FORWARD RULES — ALLOW DNAT'ED TRAFFIC INTO DOCKER ────────────────────
log "Adding FORWARD rules for honeypot traffic..."

# Allow forwarding to Cowrie honeypot for SSH/Telnet/HTTP
iptables -I FORWARD -d "$HONEYPOT_IP" -p tcp -m multiport --dports 2222,2223,8080 \
    -m comment --comment "DARPAN-FWD-IN" \
    -j ACCEPT

# Allow established return traffic from honeypot
iptables -I FORWARD -s "$HONEYPOT_IP" -m state --state ESTABLISHED,RELATED \
    -m comment --comment "DARPAN-FWD-EST" \
    -j ACCEPT

# ─── 5. CONTAINMENT — BLOCK HONEYPOT OUTBOUND INTERNET ───────────────────────
log "Applying CRITICAL containment rules for honeypot egress..."

# Allow honeypot → Focus node (ELK stack) only
iptables -I FORWARD -s "$HONEYPOT_IP" -d "$DARPAN_NET" \
    -m comment --comment "DARPAN-CONTAIN-ALLOW-FOCUS" \
    -j ACCEPT

# Allow honeypot → DNS (required for fake DNS resolution in Cowrie)
iptables -I FORWARD -s "$HONEYPOT_IP" -p udp --dport 53 \
    -m comment --comment "DARPAN-CONTAIN-ALLOW-DNS" \
    -j ACCEPT

iptables -I FORWARD -s "$HONEYPOT_IP" -p tcp --dport 53 \
    -m comment --comment "DARPAN-CONTAIN-ALLOW-DNS" \
    -j ACCEPT

# BLOCK all other outbound from honeypot IP (CRITICAL containment)
iptables -A FORWARD -s "$HONEYPOT_IP" \
    -m comment --comment "DARPAN-CONTAIN-BLOCK-ALL" \
    -j DROP

# Log blocked outbound attempts
iptables -I FORWARD -s "$HONEYPOT_IP" -o "$IFACE" \
    -m comment --comment "DARPAN-CONTAIN-LOG" \
    -j LOG --log-prefix "DARPAN-CONTAINED: " --log-level 4

# ─── 6. PROTECT HOST SSH ON PORT 2244 ────────────────────────────────────────
log "Protecting host SSH on port 2244..."
iptables -I INPUT -p tcp --dport 2244 \
    -m comment --comment "DARPAN-HOST-SSH" \
    -j ACCEPT

# Rate-limit SSH attempts to host
iptables -I INPUT -p tcp --dport 2244 -m state --state NEW \
    -m recent --set --name DARPAN_SSH
iptables -I INPUT -p tcp --dport 2244 -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 4 --name DARPAN_SSH \
    -m comment --comment "DARPAN-SSH-RATELIMIT" \
    -j DROP

# ─── 7. SAVE RULES ───────────────────────────────────────────────────────────
log "Saving iptables rules with netfilter-persistent..."
netfilter-persistent save
log "Rules saved to /etc/iptables/rules.v4 and rules.v6"

# ─── 8. VERIFICATION TABLE ───────────────────────────────────────────────────
log "====== DARPAN iptables Verification ======"
echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║           DARPAN NAT REDIRECT RULES (PREROUTING)                    ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
printf "║  %-20s → %-20s  %-20s  ║\n" "External Port" "Honeypot Dest" "Protocol"
echo "╠══════════════════════════════════════════════════════════════════════╣"
printf "║  %-20s → %-20s  %-20s  ║\n" "0.0.0.0:22 (SSH)" "${HONEYPOT_IP}:2222" "TCP"
printf "║  %-20s → %-20s  %-20s  ║\n" "0.0.0.0:23 (Telnet)" "${HONEYPOT_IP}:2223" "TCP"
printf "║  %-20s → %-20s  %-20s  ║\n" "0.0.0.0:80 (HTTP)" "${HONEYPOT_IP}:8080" "TCP"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                DARPAN CONTAINMENT RULES                              ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
printf "║  %-35s  %-30s  ║\n" "ALLOW: $HONEYPOT_IP → $DARPAN_NET" "(Focus node communication)"
printf "║  %-35s  %-30s  ║\n" "ALLOW: $HONEYPOT_IP → *:53" "(DNS resolution)"
printf "║  %-35s  %-30s  ║\n" "BLOCK: $HONEYPOT_IP → Internet" "(CRITICAL containment)"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Active DARPAN iptables rules:"
echo "--- NAT PREROUTING ---"
iptables -t nat -L PREROUTING -n --line-numbers | grep -i "DARPAN\|dnat\|DNAT" || echo "(none)"
echo ""
echo "--- FORWARD ---"
iptables -L FORWARD -n --line-numbers | grep -i "DARPAN\|172.20.0" || echo "(none)"
echo ""
log "====== DARPAN iptables Setup COMPLETE ======"
