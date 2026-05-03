<div align="center">
  <img src="logo.svg" alt="logalyzer-ng" width="600"/>
</div>

<br>

<div align="center">

![Python](https://img.shields.io/badge/Python-3.x-569cd6?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-4ec9b0?style=flat-square&logo=linux&logoColor=white)
![Root](https://img.shields.io/badge/Requires-root-f44747?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-dcdcaa?style=flat-square)

</div>

<br>

SSH authentication log analyzer for Linux. Parses `/var/log/auth.log` to track login attempts, extract IPs, and perform Whois lookups on unknown addresses. Includes an automated launcher that generates styled HTML reports sent by email.

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| Python 3 | |
| [`ipwhois`](https://pypi.org/project/ipwhois/) | `pip install ipwhois` |
| Root privileges | For reading `/var/log/auth.log` |
| `sendmail` | Configured via `msmtp` or equivalent |

---

## Setup

```bash
bash setup.sh
```

Or manually:

```bash
cp .env.example .env
# Fill in .env with your values
pip install -r requirements.txt
```

### `.env` variables

| Variable          | Description |
|-------------------|-------------|
| `MAIL`            | Recipient email address for HTML reports |
| `MONITORED_USER`  | Username to focus monitoring on |
| `KNOWN_IPS`       | Comma-separated list of trusted IPs |
| `KNOWN_DOMAINS`   | Comma-separated list of trusted domains (resolved to IPs at runtime) |

```env
MAIL=you@example.com
MONITORED_USER=youruser
KNOWN_IPS=1.2.3.4,5.6.7.8
KNOWN_DOMAINS=yourdomain.com,vpn.yourdomain.com
```

---

## Usage

```bash
sudo python3 logalyzer-ng.py [options]
```

### Flags

| Flag          | Description |
|---------------|-------------|
| `-u <user>`   | Filter by user (omit to list all) |
| `-i`          | Show IP addresses |
| `-f`          | Show failure logs |
| `-s`          | Show success logs |
| `-c`          | Show commands (sudo) |
| `-a`          | List all usernames attempted by attackers |
| `-b`          | List brute-force attempts (`Too many authentication failures`) |
| `--sudo-fail` | List failed sudo attempts (`NOT in sudoers`) |
| `--su-fail`   | List failed `su` attempts |
| `--accounts`  | List account creation / modification / deletion events |
| `--full`      | Full raw log dump for specified user |
| `-l <file>`   | Use a custom log file (default: `/var/log/auth.log`) |
| `-v`          | Verbose: show timestamp, log file path, size, last rotation |

> If the user is not found in `auth.log`, the script automatically falls back to `auth.log.1` or `auth.log.2.gz`.

---

### Examples

<details>
<summary><b>Commands run by a user</b> — <code>-u -c</code></summary>

```bash
python3 logalyzer-ng.py -u alice -c
```
```
[+] Commands for user 'alice':
     /sbin/iptables -L -n
```
</details>

<details>
<summary><b>IPs that successfully authenticated</b> — <code>-u -i</code></summary>

```bash
python3 logalyzer-ng.py -u alice -i
```
```
[+] Logged IPs for user 'alice':
     203.0.113.10 (Known IP!)
     198.51.100.5 (Known IP!)
```
</details>

<details>
<summary><b>Failure logs for a user</b> — <code>-u -f</code></summary>

```bash
python3 logalyzer-ng.py -u alice -f
```
```
[+] Failures for user 'alice':
     2026-04-19T23:44:29+02:00 localhost sshd[1234]: Failed password for invalid user alice from 203.0.113.10 port 1667 ssh2
     2026-04-19T23:44:33+02:00 localhost sshd[1234]: Failed password for invalid user alice from 203.0.113.10 port 1667 ssh2
     2026-04-20T00:02:52+02:00 localhost sshd[5678]: Failed password for invalid user alice from 198.51.100.5 port 41826 ssh2
```
</details>

<details>
<summary><b>Failed IPs + Whois on unknown ones</b> — <code>-u -f -i</code></summary>

```bash
python3 logalyzer-ng.py -u alice -f -i
```
```
[+] Failed IPs for user 'alice':
     203.0.113.10 (Known IP!)
     198.51.100.5
[*] Whois on unknown IPs that FAILED for user 'alice'
     198.51.100.5:
     -------------
     COUNTRY: CN
     DESCRIPTION: Shenzhen Example Network Technology Co., Ltd
     ADDRESS: Building A - 10 Example Road, Shenzhen
     CIDR: 198.51.100.0/24
     EMAILS: abuse@example-isp.cn |

     -------------
```
</details>

<details>
<summary><b>Commands run by root</b> — <code>-u root -c</code></summary>

```bash
python3 logalyzer-ng.py -u root -c
```
```
[+] Commands for user 'root':
     /usr/bin/apt update
     /usr/bin/apt upgrade -y
     /usr/sbin/ufw status
     /usr/bin/systemctl restart ssh
     /usr/bin/tail -f /var/log/auth.log
     /usr/bin/journalctl -u ssh --since today
```
</details>

<details>
<summary><b>All usernames tried by attackers</b> — <code>-a</code></summary>

```bash
python3 logalyzer-ng.py -a
```
```
[+] Users attempted by attackers
     admin
     root
     ubuntu
     deploy
     test
     guest
     oracle
     ftpuser
     git
     support
     pam_unix
```
</details>

<details>
<summary><b>Brute-force attempts</b> — <code>-b</code></summary>

```bash
python3 logalyzer-ng.py -b
```
```
[+] Brute-force detected for 'root':
     2026-04-20T03:12:44+02:00 localhost sshd[2301145]: Disconnecting authenticating user root 198.51.100.5 port 52218: Too many authentication failures [preauth]
     2026-04-20T03:14:01+02:00 localhost sshd[2301892]: Disconnecting authenticating user root 198.51.100.5 port 61034: Too many authentication failures [preauth]
```
</details>

<details>
<summary><b>Failed sudo attempt — privilege escalation</b> — <code>--sudo-fail</code></summary>

```bash
python3 logalyzer-ng.py --sudo-fail
```
```
[!] NOT in sudoers — 'bob':
     2026-04-20T11:32:05+02:00 localhost sudo: bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
```
</details>

<details>
<summary><b>Account events</b> — <code>--accounts</code></summary>

```bash
sudo python3 logalyzer-ng.py --accounts
```
```
[+] Account events:
     2026-04-20T14:05:12+02:00 localhost useradd[3120]: new user: name=deploy, UID=1002, GID=1002, home=/home/deploy, shell=/bin/bash
     2026-04-20T14:07:33+02:00 localhost usermod[3198]: change user 'deploy' password
```
</details>

<details>
<summary><b>Verbose log file info</b> — <code>-v</code></summary>

```bash
sudo python3 logalyzer-ng.py -v
```
```
[*] Launched: 2026-04-20 at 15h30m00s
[*] Log file: /var/log/auth.log
[*] Last rotation: 2026-04-14T00:00:01
[*] Log size: 2847.3 KB
```
</details>

---

## Launcher

The launcher runs all report sections automatically, wraps output in a dark-themed HTML email, and sends it via `sendmail`.

```bash
sudo bash logalyzer-ng_launcher.sh
```

**Report sections:**

| Section | Command |
|---------|---------|
| Log file info | `-v` |
| Authenticated IPs | `-i -u $MONITORED_USER` |
| Failed IPs + Whois | `-f -i -u $MONITORED_USER` |
| Failure logs | `-f -u $MONITORED_USER` |
| Root commands | `-u root -c` |
| Attempted attackers | `-a` |
| Brute-force attempts | `-b` |
| Failed sudo attempts | `--sudo-fail` |
| Failed su attempts | `--su-fail` |
| Account events | `--accounts` |

**Color coding in the HTML report:**

| Prefix | Color  | Meaning |
|--------|--------|---------|
| `[+]`  | Green  | Data found / positive result |
| `[-]`  | Red    | Error / nothing found |
| `[!]`  | Yellow | Warning / attention |
| `[*]`  | Blue   | Info / metadata |

---

## Project structure

```
logalyzer-ng/
├── logalyzer-ng.py           # Main CLI
├── logalyzer-ng_launcher.sh  # Automated HTML report + email
├── setup.sh                  # Setup script
├── requirements.txt          # Python dependencies
├── logo.svg                  # Project logo
├── .env                      # Local config (git-ignored)
├── .env.example              # Config template
└── lib/
    ├── ParseLogs.py          # Log parsing engine
    └── WhoisIP.py            # Whois lookup utility
```

---

## Log parsing

`ParseLogs.py` builds a dictionary keyed by username:

```
LOGS = {
  "username": Log(
    logs            = ["raw line", ...],    # all lines
    fail_logs       = ["raw line", ...],    # Failed password / auth failure
    succ_logs       = ["raw line", ...],    # Accepted password
    ips             = ["1.2.3.4", ...],     # IPs seen for this user
    commands        = ["/usr/bin/...", ...] # sudo COMMAND= entries
    bruteforce_logs = ["raw line", ...],    # Too many authentication failures
    sudo_fail_logs  = ["raw line", ...],    # NOT in sudoers
    su_fail_logs    = ["raw line", ...],    # FAILED su for
  ),
  "_system": Log(
    account_events  = ["raw line", ...],    # useradd / usermod / userdel / new user / new group
  ),
  None: Log(...)  # lines where the user could not be parsed
}
```

Supports plain text and gzip-compressed logs — auto-detected via magic bytes, regardless of file extension.
