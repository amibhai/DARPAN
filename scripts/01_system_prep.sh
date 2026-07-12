#!/usr/bin/env bash
# DARPAN Phase 1 — System Preparation
# Run as root on Parrot OS (Debian-based)
set -euo pipefail

DARPAN_ROOT="/opt/darpan"
DARPAN_USER="darpan"
LOG_FILE="/var/log/darpan_setup.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
die() { log "ERROR: $*"; exit 1; }

[[ $EUID -eq 0 ]] || die "Must run as root"

log "====== DARPAN System Preparation Starting ======"

# ─── 1. SYSTEM UPDATE & CORE PACKAGES ───────────────────────────────────────
log "Updating apt and installing core packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    docker.io \
    docker-compose \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    net-tools \
    iptables-persistent \
    netfilter-persistent \
    jq \
    fail2ban \
    auditd \
    audispd-plugins \
    ca-certificates \
    gnupg \
    lsb-release \
    htop \
    tmux \
    unzip \
    nmap \
    tcpdump \
    libssl-dev \
    libffi-dev \
    build-essential \
    python3-dev

log "Core packages installed."

# ─── 2. DOCKER ───────────────────────────────────────────────────────────────
log "Enabling and starting Docker..."
systemctl enable docker
systemctl start docker
docker --version | tee -a "$LOG_FILE"

# ─── 3. DARPAN SYSTEM USER ───────────────────────────────────────────────────
log "Creating system user '${DARPAN_USER}'..."
if id "$DARPAN_USER" &>/dev/null; then
    log "User '${DARPAN_USER}' already exists, skipping creation."
else
    useradd --system \
            --no-create-home \
            --shell /usr/sbin/nologin \
            --comment "DARPAN Honeypot Operator" \
            "$DARPAN_USER"
    log "User '${DARPAN_USER}' created."
fi

# Add darpan user to docker group
usermod -aG docker "$DARPAN_USER"
log "Added '${DARPAN_USER}' to docker group."

# ─── 4. KERNEL PARAMETERS (Elasticsearch requirement) ────────────────────────
log "Configuring sysctl for Elasticsearch..."
SYSCTL_CONF="/etc/sysctl.d/99-darpan.conf"
cat > "$SYSCTL_CONF" <<EOF
# DARPAN — Elasticsearch requires high vm.max_map_count
vm.max_map_count=262144
# Reduce swap use
vm.swappiness=10
# Increase max file descriptors
fs.file-max=655360
EOF
sysctl --system -q
log "vm.max_map_count=$(sysctl -n vm.max_map_count)"

# ─── 5. SSH HARDENING — Free Port 22 for Honeypot NAT ────────────────────────
log "Hardening SSH: disabling password auth, moving to port 2244..."
SSH_CFG="/etc/ssh/sshd_config"
SSH_BACKUP="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"
cp "$SSH_CFG" "$SSH_BACKUP"
log "Backed up sshd_config to $SSH_BACKUP"

# Apply hardened settings
sed -i 's/^#*Port .*/Port 2244/' "$SSH_CFG"
sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' "$SSH_CFG"
sed -i 's/^#*ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' "$SSH_CFG"
sed -i 's/^#*PermitRootLogin .*/PermitRootLogin prohibit-password/' "$SSH_CFG"
sed -i 's/^#*UsePAM .*/UsePAM yes/' "$SSH_CFG"

# Ensure settings are present if not already
grep -q "^Port 2244" "$SSH_CFG" || echo "Port 2244" >> "$SSH_CFG"
grep -q "^PasswordAuthentication no" "$SSH_CFG" || echo "PasswordAuthentication no" >> "$SSH_CFG"
grep -q "^MaxAuthTries" "$SSH_CFG" || echo "MaxAuthTries 3" >> "$SSH_CFG"
grep -q "^LoginGraceTime" "$SSH_CFG" || echo "LoginGraceTime 30" >> "$SSH_CFG"
grep -q "^ClientAliveInterval" "$SSH_CFG" || echo "ClientAliveInterval 300" >> "$SSH_CFG"
grep -q "^ClientAliveCountMax" "$SSH_CFG" || echo "ClientAliveCountMax 2" >> "$SSH_CFG"
grep -q "^X11Forwarding" "$SSH_CFG" || echo "X11Forwarding no" >> "$SSH_CFG"
grep -q "^AllowTcpForwarding" "$SSH_CFG" || echo "AllowTcpForwarding no" >> "$SSH_CFG"

# Validate config before restarting
sshd -t && systemctl restart sshd
log "SSH moved to port 2244, password auth disabled."
log "CRITICAL: Ensure you have key-based access on port 2244 before logging out!"

# Update fail2ban to watch new SSH port
cat > /etc/fail2ban/jail.d/darpan-sshd.conf <<EOF
[sshd]
enabled = true
port    = 2244
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 3600
EOF

# ─── 6. FAIL2BAN & AUDITD ────────────────────────────────────────────────────
log "Starting fail2ban and auditd..."
systemctl enable fail2ban auditd
systemctl restart fail2ban auditd

# Audit rules for DARPAN monitoring
cat >> /etc/audit/rules.d/darpan.rules <<EOF
# DARPAN audit rules
-w /opt/darpan/ -p rwxa -k darpan_access
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k identity_changes
-w /etc/sudoers -p wa -k sudoers_changes
-a always,exit -F arch=b64 -S execve -k command_execution
EOF
augenrules --load 2>/dev/null || log "augenrules not available, skipping rule load"

# ─── 7. PYTHON DEPENDENCIES ──────────────────────────────────────────────────
log "Installing Python packages globally..."
pip3 install --upgrade pip --quiet
pip3 install --quiet \
    paramiko \
    twisted \
    cryptography \
    pyOpenSSL \
    bcrypt \
    requests \
    zope.interface \
    service_identity \
    pyasn1 \
    attrs \
    Automat \
    constantly \
    incremental \
    scikit-learn \
    shap \
    faker \
    elasticsearch \
    python-dotenv \
    pandas \
    numpy \
    matplotlib \
    seaborn \
    anthropic \
    abuseipdb \
    stix2 \
    mitreattack-python \
    scipy \
    joblib \
    watchdog \
    schedule

log "Python packages installed."

# ─── 8. DIRECTORY STRUCTURE ──────────────────────────────────────────────────
log "Creating DARPAN directory structure..."
dirs=(
    "$DARPAN_ROOT/reflector"
    "$DARPAN_ROOT/focus/logstash/pipeline"
    "$DARPAN_ROOT/focus/filebeat"
    "$DARPAN_ROOT/focus/kibana"
    "$DARPAN_ROOT/ml"
    "$DARPAN_ROOT/lures"
    "$DARPAN_ROOT/scripts"
    "$DARPAN_ROOT/certs"
    "$DARPAN_ROOT/logs/cowrie"
    "$DARPAN_ROOT/intel/campaigns"
    "$DARPAN_ROOT/intel/alerts"
    "$DARPAN_ROOT/intel/malware_samples"
    "$DARPAN_ROOT/reports"
)

for d in "${dirs[@]}"; do
    mkdir -p "$d"
done

# Set ownership
chown -R "$DARPAN_USER:$DARPAN_USER" "$DARPAN_ROOT"
chmod -R 750 "$DARPAN_ROOT"
chmod 770 "$DARPAN_ROOT/logs/cowrie"
chmod 770 "$DARPAN_ROOT/intel"
chmod 770 "$DARPAN_ROOT/intel/campaigns"
chmod 770 "$DARPAN_ROOT/intel/alerts"
chmod 770 "$DARPAN_ROOT/intel/malware_samples"
chmod 770 "$DARPAN_ROOT/reports"

# Allow docker group to write logs
chgrp docker "$DARPAN_ROOT/logs/cowrie"
chgrp docker "$DARPAN_ROOT/intel/malware_samples"

log "Directory structure created under $DARPAN_ROOT"

# ─── 9. SELF-SIGNED TLS CERTS ────────────────────────────────────────────────
log "Generating self-signed TLS certificate for internal use..."
openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout "$DARPAN_ROOT/certs/darpan.key" \
    -out "$DARPAN_ROOT/certs/darpan.crt" \
    -subj "/C=US/ST=DARPAN/L=DECEPTION/O=DARPAN/CN=darpan.internal" \
    2>/dev/null
chmod 600 "$DARPAN_ROOT/certs/darpan.key"
chmod 644 "$DARPAN_ROOT/certs/darpan.crt"
log "TLS certificates generated."

# ─── 10. FIREWALL HARDENING ──────────────────────────────────────────────────
log "Applying basic host firewall rules (UFW or iptables)..."
# Apply rules to ensure honeypot isolation
# Ensure iptables-persistent is configured to load on boot
systemctl enable netfilter-persistent 2>/dev/null || true

# ─── SUMMARY ─────────────────────────────────────────────────────────────────
log "====== DARPAN System Preparation COMPLETE ======"
log "Summary:"
log "  - Docker: $(docker --version 2>/dev/null | head -1)"
log "  - Python3: $(python3 --version 2>/dev/null)"
log "  - SSH port: 2244 (password auth disabled)"
log "  - vm.max_map_count: $(sysctl -n vm.max_map_count)"
log "  - DARPAN user: $DARPAN_USER (no login shell)"
log "  - DARPAN root: $DARPAN_ROOT"
log ""
log "  NEXT STEP: Run 02_iptables_setup.sh"
log "  CRITICAL: Verify SSH key access on port 2244 BEFORE closing current session!"
