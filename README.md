# ⚠️ [IN DEVELOPMENT] — This project is actively under construction. APIs, schemas, and component interfaces are subject to change without notice.

---

<div align="center">

```
██████╗  █████╗ ██████╗ ██████╗  █████╗ ███╗   ██╗
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗  ██║
██║  ██║███████║██████╔╝██████╔╝███████║██╔██╗ ██║
██║  ██║██╔══██║██╔══██╗██╔═══╝ ██╔══██║██║╚██╗██║
██████╔╝██║  ██║██║  ██║██║     ██║  ██║██║ ╚████║
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝
```

**Digital Asset Reflection and Proactive Analysis Network**

*Inverting the asymmetric advantage of cyber adversaries through adaptive deception.*

![Status](https://img.shields.io/badge/Status-IN%20DEVELOPMENT-orange?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Parrot%20OS-blueviolet?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker)
![License](https://img.shields.io/badge/License-Research%20Use%20Only-red?style=for-the-badge)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Core Architecture](#core-architecture)
- [Feature Highlights](#feature-highlights)
- [MITRE ATT\&CK Coverage](#mitre-attck-coverage)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Deployment](#deployment)
- [Development Roadmap](#development-roadmap)
- [Technical Stack](#technical-stack)
- [Security & Ethics Notice](#security--ethics-notice)
- [Research Context](#research-context)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)

---

## Overview

**DARPAN** (Digital Asset Reflection and Proactive Analysis Network) is a next-generation, hybrid-adaptive, and context-aware cyber deception framework designed for threat actor profiling, APT campaign tracking, and proactive intelligence collection. It transitions cybersecurity defense from passive perimeters to active, high-fidelity deception environments that collect adversarial intelligence at every stage of an attack lifecycle.

DARPAN is built for deployment across **IT, Cloud, and OT** environments and is intended for use by security researchers, threat intelligence teams, and SOC analysts who require research-grade attribution-level data.

> DARPAN does not block attacks — it **studies** them, **profiles** the adversary, and **generates actionable intelligence** that feeds back into defensive operations.

### Core Philosophy

Traditional defense is reactive. Perimeters fail. DARPAN operates on a different doctrine:

| Traditional Defense | DARPAN Doctrine |
|---|---|
| Block known bad | Attract, engage, and profile |
| Alert on IOCs | Generate IOCs from live adversary behavior |
| Static signatures | Dynamic, polymorphic attack surfaces |
| Post-incident forensics | Real-time TTPs mapped to MITRE ATT&CK |
| Defender has no information | Adversary has no genuine target |

---

## Core Architecture

DARPAN is organized around two logical node types that work in concert:

```
                        ┌─────────────────────────────────────────────────┐
  INTERNET              │                  DARPAN HOST                    │
  Adversary ──────────► │                                                 │
                        │  ┌──────────────────────────────────────────┐  │
  Port 22  ──NAT──────► │  │         REFLECTOR NODE (Cowrie)          │  │
  Port 23  ──NAT──────► │  │                                          │  │
                        │  │  • SSH/Telnet Emulation (port 2222/2223) │  │
                        │  │  • Polymorphic Filesystem (Faker)        │  │
                        │  │  • LLM-Powered Command Responses         │  │
                        │  │  • Honeytoken Beacon System              │  │
                        │  │  • Credential Lure Engine                │  │
                        │  └──────────────┬───────────────────────────┘  │
                        │                 │ cowrie.json logs              │
                        │                 ▼                               │
                        │  ┌──────────────────────────────────────────┐  │
                        │  │           FOCUS NODE (ELK + ML)          │  │
                        │  │                                          │  │
                        │  │  Filebeat → Logstash → Elasticsearch     │  │
                        │  │                              │           │  │
                        │  │                          Kibana          │  │
                        │  │                              │           │  │
                        │  │                     ML Pipeline          │  │
                        │  │          (Random Forest + DBSCAN)        │  │
                        │  │                     │                    │  │
                        │  │             SHAP Explainability          │  │
                        │  │                     │                    │  │
                        │  │          Threat Report Generator         │  │
                        │  │       (MITRE ATT&CK + STIX 2.1)         │  │
                        │  └──────────────────────────────────────────┘  │
                        └─────────────────────────────────────────────────┘
```

### Reflector Node

The deception surface. A hardened, containerized **Cowrie** honeypot running as a medium-interaction SSH/Telnet emulator. It presents adversaries with a realistic Ubuntu 22.04 LTS environment complete with:

- A **polymorphic filesystem** that regenerates every 6 hours using Python's `Faker` library, defeating automated fingerprinting tools that cache filesystem state.
- An **LLM-powered command handler** (Claude API backend) that generates contextually accurate terminal responses for commands Cowrie does not natively emulate.
- **Honeytokens** — planted fake credential files, SSH keys, and configuration files that trigger high-priority alerts the moment they are accessed.
- A curated `userdb.txt` with 30+ realistic credential pairs (IoT defaults, corporate-pattern credentials) — all configured to grant access, maximizing session depth and behavioral data collection.

### Focus Node

The intelligence brain. A containerized **ELK stack** (Elasticsearch, Logstash, Kibana, Filebeat) that ingests, enriches, and stores all Cowrie telemetry. On top of the ELK foundation sits:

- A **feature engineering pipeline** that extracts temporal, command-sequence, and payload features from raw session logs.
- A **Random Forest classifier** that categorizes attacker sessions into: `SCRIPT_KIDDIE`, `AUTOMATED_SCANNER`, `ADVANCED_HUMAN`, `APT_CANDIDATE`, `WORM_BOT`.
- **DBSCAN clustering** for grouping related sessions into **named campaigns** with tracked infrastructure, TTPs, and timelines.
- **SHAP (SHapley Additive exPlanations)** integration that translates every ML decision into human-readable justifications for SOC analysts.
- An automated **threat report generator** producing structured Markdown and JSON reports, including ATT&CK Navigator layer exports.

---

## Feature Highlights

### Deception Engineering
- Medium-interaction Cowrie honeypots in hardened Docker containers
- Dynamic lure surfaces — honeyfs regenerates with new fake users, histories, cron jobs, and config files on every cycle
- LLM-backed shell emulation for commands outside Cowrie's native library
- Honeytoken beacon system with real-time alerting on credential/file access events
- SSH version string spoofing and realistic kernel/OS fingerprint emulation
- Full TTY session recording for forensic playback

### Data Pipeline & Telemetry
- Structured JSON log ingestion via Filebeat → Logstash → Elasticsearch
- GeoIP enrichment on every attacker IP (country, city, coordinates)
- Logstash pipeline with automated credential classification (default/honeytoken/brute-force tagging)
- 4 pre-built Kibana dashboards: Attack Overview, Credential Analysis, Command Intelligence, Session Profiling
- Log retention management and automated index lifecycle policies

### Machine Learning & AI
- Feature extraction across three dimensions: Temporal, Command Sequence, and Payload/Network
- Inter-arrival time (IAT) analysis to distinguish human vs. automated behavior
- Command n-gram modeling (bigrams, trigrams) for behavioral fingerprinting
- Payload entropy scoring to detect obfuscation and encoding patterns
- Random Forest classifier with 200 estimators, hyperparameter-optimized, and balanced class weighting
- DBSCAN campaign clustering with automatic parameter tuning
- SHAP explainability with visual summary plots and per-session analyst narratives

### Threat Intelligence
- MITRE ATT&CK mapping for 50+ command patterns across all major tactics
- ATT&CK Navigator JSON layer export (importable at attack.mitre.org)
- OSINT IP enrichment via AbuseIPDB and Shodan InternetDB
- STIX 2.1 formatted IOC output for SIEM/SOAR ingestion
- Attribution confidence scoring (LOW / MEDIUM / HIGH) with justification
- Research-grade threat reports: attack timeline, infrastructure analysis, TTP tables

---

## MITRE ATT&CK Coverage

DARPAN maps observed adversary behavior to the following ATT&CK tactics and techniques:

| Tactic | Technique ID | Technique | Trigger Pattern |
|---|---|---|---|
| Reconnaissance | T1592 | Gather Victim Host Info | `uname -a`, `cat /etc/os-release` |
| Execution | T1059.004 | Unix Shell | Any command input |
| Persistence | T1053.003 | Cron | `crontab -e`, edits to `/etc/cron*` |
| Persistence | T1098 | Account Manipulation | `useradd`, `passwd`, `usermod` |
| Privilege Escalation | T1548.001 | Setuid/Setgid | `chmod +s`, `chmod u+s` |
| Defense Evasion | T1140 | Deobfuscate/Decode | Base64 encoded command strings |
| Defense Evasion | T1070.003 | Clear Command History | `history -c`, `unset HISTFILE` |
| Credential Access | T1003.008 | /etc/passwd & /etc/shadow | `cat /etc/passwd`, `cat /etc/shadow` |
| Discovery | T1082 | System Information Discovery | `uname`, `whoami`, `id`, `hostname` |
| Discovery | T1083 | File & Directory Discovery | `ls`, `find`, `locate` |
| Discovery | T1016 | System Network Config Discovery | `ifconfig`, `ip addr`, `netstat` |
| Lateral Movement | T1021.004 | SSH | `ssh` commands to internal IPs |
| Collection | T1005 | Data from Local System | Sensitive file reads, `tar`, `zip` |
| C2 | T1105 | Ingress Tool Transfer | `wget`, `curl` to external IPs |
| Exfiltration | T1048 | Exfiltration Over Alt Protocol | `scp`, `nc` with data piping |

---

## Project Structure

```
/opt/darpan/
│
├── reflector/                  # REFLECTOR NODE — Deception Surface
│   ├── Dockerfile              # Hardened Cowrie container image
│   ├── docker-compose.yml      # Reflector deployment config
│   ├── cowrie.cfg              # Cowrie honeypot configuration
│   ├── userdb.txt              # Credential honeytokens & lure pairs
│   ├── generate_honeyfs.py     # Polymorphic filesystem generator (Faker)
│   ├── custom_commands.py      # LLM-powered command handler (Claude API)
│   └── honeyfs/                # Generated fake filesystem (auto-populated)
│       ├── etc/
│       ├── home/
│       ├── var/log/
│       ├── root/
│       └── opt/app/
│
├── focus/                      # FOCUS NODE — Intelligence Brain
│   ├── docker-compose.yml      # ELK stack deployment config
│   ├── logstash/
│   │   └── pipeline/
│   │       └── cowrie.conf     # Logstash ingest pipeline
│   ├── filebeat/
│   │   └── filebeat.yml        # Filebeat shipper config
│   └── kibana/
│       └── darpan_dashboards.ndjson  # Importable Kibana dashboards
│
├── ml/                         # MACHINE LEARNING PIPELINE
│   ├── feature_engineering.py  # Session feature extractor
│   ├── classifier.py           # Random Forest + SHAP classifier
│   ├── campaign_tracker.py     # DBSCAN campaign clustering
│   └── report_generator.py     # Automated threat report generator
│
├── lures/                      # LURE ENGINEERING
│   ├── lure_scheduler.py       # Polymorphic refresh daemon (6h cycle)
│   └── honeytoken_beacon.py    # Real-time honeytoken alert system
│
├── intel/                      # THREAT INTELLIGENCE OUTPUTS
│   ├── ip_enrichment.py        # AbuseIPDB + Shodan OSINT enricher
│   ├── mitre_mapper.py         # ATT&CK TTP mapper + Navigator export
│   ├── campaigns/              # Per-campaign JSON intelligence files
│   ├── alerts/                 # Honeytoken and high-priority alerts
│   ├── malware_samples/        # Attacker-uploaded file captures
│   └── ioc_*.json              # STIX 2.1 IOC exports (per date)
│
├── scripts/                    # ORCHESTRATION & AUTOMATION
│   ├── 01_system_prep.sh       # OS hardening & dependency installer
│   ├── 02_iptables_setup.sh    # NAT rules & containment firewall
│   ├── deploy_darpan.sh        # Master one-command deployment script
│   └── darpan_status.sh        # Live terminal status dashboard
│
├── reports/                    # GENERATED THREAT REPORTS
│   └── CAMP-*_*.md             # Campaign-specific Markdown reports
│
├── certs/                      # TLS certificates (internal)
├── logs/                       # Raw aggregated log storage
│   └── cowrie/                 # Cowrie JSON + TTY logs
│
└── env.template                # Environment variable template
```

---

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| OS | Parrot OS / Debian 11+ | Parrot OS Security Edition |
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 50 GB | 200 GB (log retention) |
| Network | Public-facing NIC | Dedicated honeypot NIC |

### Software Dependencies

All dependencies are installed automatically by `01_system_prep.sh`. For reference:

- Docker + Docker Compose
- Python 3.11+
- `scikit-learn`, `shap`, `faker`, `elasticsearch-py`, `pandas`, `numpy`
- `matplotlib`, `seaborn`, `requests`, `python-dotenv`
- `iptables-persistent`, `fail2ban`, `auditd`
- ELK Stack 8.11.0 (via Docker images)

### API Keys Required

| Service | Purpose | Free Tier |
|---|---|---|
| Anthropic API | LLM-powered command emulation | Yes (rate limited) |
| AbuseIPDB | IP reputation enrichment | Yes (1000 checks/day) |
| Shodan InternetDB | Open port + banner data on attacker IPs | Yes (no key required) |

---

## Deployment

### 1. Clone and configure

```bash
git clone https://github.com/your-org/darpan.git /opt/darpan
cd /opt/darpan
cp env.template .env
nano .env   # Fill in ANTHROPIC_API_KEY and DARPAN_HOST_IP
```

### 2. System preparation

```bash
# Run as root — hardens OS, installs deps, moves host SSH to port 2244
sudo bash /opt/darpan/scripts/01_system_prep.sh
```

> **Important:** After this script completes, your host SSH will be on **port 2244**. Reconnect with `ssh -p 2244 user@host` before proceeding.

### 3. Configure iptables NAT

```bash
# Redirects port 22 → 2222, port 23 → 2223, and enforces container containment
sudo bash /opt/darpan/scripts/02_iptables_setup.sh
```

### 4. Deploy the full stack

```bash
# Generates honeyfs, starts ELK + Cowrie, imports dashboards, registers services
sudo bash /opt/darpan/scripts/deploy_darpan.sh
```

### 5. Verify deployment

```bash
bash /opt/darpan/scripts/darpan_status.sh
```

Expected output:
```
╔══════════════════════════════════════════════════╗
║      DARPAN STATUS — DECEPTION LAYER ONLINE      ║
╚══════════════════════════════════════════════════╝
[✓] cowrie-reflector-01     RUNNING  (172.20.0.10)
[✓] elasticsearch           RUNNING  (172.20.0.20)
[✓] logstash                RUNNING  (172.20.0.21)
[✓] kibana                  RUNNING  (172.20.0.22)
[✓] filebeat                RUNNING  (172.20.0.23)
[✓] Port 2222 (SSH)         LISTENING
[✓] Port 2223 (Telnet)      LISTENING
Kibana UI:  http://127.0.0.1:5601
```

### 6. Access Kibana

```bash
ssh -L 5601:127.0.0.1:5601 -p 2244 user@your-host
# Then open: http://localhost:5601 in your browser
```

---

## Development Roadmap

DARPAN is built across four phases:

### Phase 1 — Foundation: Core Engineering ✅ (In Progress)
- [x] Cowrie Reflector Node (Docker, custom config, credential lures)
- [x] Polymorphic filesystem generator
- [x] LLM-powered command handler
- [x] ELK Stack Focus Node (Filebeat → Logstash → Elasticsearch → Kibana)
- [x] iptables NAT + containment rules
- [x] Master deployment orchestration scripts
- [ ] Full integration testing on Parrot OS host
- [ ] Performance tuning under sustained attack load

### Phase 2 — Personality: Lure Engineering 🔄 (Planned)
- [ ] HTTP honeypot (port 80/443) — fake admin panels, login portals
- [ ] RDP honeypot for Windows credential lure
- [ ] OT/SCADA protocol emulation (Modbus, DNP3) for ICS environments
- [ ] Decoy cloud storage buckets (S3-compatible fake endpoints)
- [ ] Email honeytoken (planted fake credentials in fake .env files)

### Phase 3 — Intelligence: ML & Analytics 🔄 (Planned)
- [ ] Labeled training dataset construction from collected sessions
- [ ] Random Forest classifier training and validation
- [ ] DBSCAN campaign tracking with confidence scoring
- [ ] SHAP explainability dashboard integration in Kibana
- [ ] Automated ML retraining pipeline (triggered on new data volume threshold)
- [ ] Threat report auto-generation and export

### Phase 4 — Expansion: Network Integration 📋 (Future)
- [ ] Multi-node Reflector deployment (distributed honeypot grid)
- [ ] Threat intelligence feed integration (MISP, OpenCTI)
- [ ] SOAR integration for automated playbook triggering
- [ ] Darknet monitoring agent for credential re-use detection
- [ ] API server for SOC/SIEM webhook consumption
- [ ] Cloud deployment modules (AWS, Azure, GCP honeypot instances)

---

## Technical Stack

| Layer | Technology | Version |
|---|---|---|
| Deception Engine | Cowrie (Twisted/Python) | Latest |
| Container Runtime | Docker + Docker Compose | 24+ |
| Log Shipper | Filebeat | 8.11.0 |
| Log Processing | Logstash | 8.11.0 |
| Data Store | Elasticsearch | 8.11.0 |
| Visualization | Kibana | 8.11.0 |
| ML Framework | Scikit-learn | 1.3+ |
| Explainability | SHAP | 0.43+ |
| Dynamic Lures | Python Faker | 19+ |
| LLM Backend | Claude (Anthropic API) | claude-sonnet-4-6 |
| OS Platform | Parrot OS / Debian | Security Edition |
| Host Firewall | iptables + netfilter-persistent | — |
| Network | Docker bridge (172.20.0.0/24) | — |
| IOC Format | STIX 2.1 | — |
| ATT&CK Framework | MITRE ATT&CK | v14 |

---

## Security & Ethics Notice

> **DARPAN is a defensive security research tool. Deploying it responsibly is the operator's obligation.**

### Operational Security Requirements

- **Deploy only on infrastructure you own or have explicit written authorization to use.**
- The Reflector Node must be **network-isolated** — the iptables containment rules in `02_iptables_setup.sh` are not optional. They prevent the honeypot container from being used as a pivot point.
- **Never deploy on a production network** without a dedicated, isolated honeypot VLAN or DMZ segment.
- All attacker-uploaded malware is stored in `/opt/darpan/intel/malware_samples/` — treat this directory with appropriate isolation procedures. Do not execute any captured files.
- Honeytoken credentials planted in the fake filesystem are fictional. Do not reuse them anywhere on real infrastructure.
- Collected attacker data (IPs, session content, commands) may be subject to local data protection regulations. Consult your legal team before long-term retention.

### Responsible Disclosure

DARPAN collects and retains PII-adjacent data (IP addresses, behavioral patterns). All collected data should be handled in accordance with your organization's data governance policy and applicable law.

---

## Research Context

DARPAN is developed in alignment with real-world Cyber Deception Lab requirements, including:

- Design, deployment, and management of low-, medium-, and high-interaction honeypots across IT, Cloud, and OT environments
- Development of custom deception systems for **threat actor profiling** and **campaign tracking**
- Monitoring and analysis of honeypot telemetry: network traffic, system logs, and malware artifacts
- APT attribution using TTP analysis mapped to the **MITRE ATT&CK framework**
- Correlation of honeypot intelligence with threat intelligence feeds, OSINT, malware reports, and darknet sources
- Support for incident response and threat hunting teams with actionable intelligence
- Production of research-grade threat reports including attack timelines, infrastructure analysis, and **attribution confidence levels**
- Continuous research into emerging APT campaigns, zero-day exploitation trends, and deception techniques

---

## Contributing

DARPAN is a research project currently in active development. Contributions, issue reports, and feature proposals are welcome from the security research community.

```
Contribution areas:
  - New Cowrie custom command handlers
  - Additional ML feature engineering methods
  - New MITRE ATT&CK command mappings
  - OT/ICS protocol honeypot modules
  - Threat report templates
  - Kibana dashboard improvements
```

Please open an issue before submitting a pull request for major features.

---

## Disclaimer

DARPAN is intended solely for **authorized security research, threat intelligence collection, and defensive cybersecurity operations**. The authors assume no liability for misuse. Deploying honeypots without proper authorization may violate local laws. All attacker data collected by DARPAN is the responsibility of the deploying organization.

---

<div align="center">

*"The best defense is making the attacker believe they've found something real."*

**DARPAN — Deception as a Discipline**

</div>
