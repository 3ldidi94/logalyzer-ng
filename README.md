# logalyzer-ng

SSH authentication log analyzer for Linux. Parses `/var/log/auth.log` to track login attempts, extract IPs, and perform Whois lookups on unknown addresses. Includes an automated launcher that generates styled HTML reports sent by email.

---

## Requirements

- Python 3
- [`ipwhois`](https://pypi.org/project/ipwhois/) — `pip install ipwhois`
- Root privileges (for reading `/var/log/auth.log`)
- `sendmail` configured (e.g. via `msmtp`)

---

## Setup

```bash
cp .env.example .env
# Fill in .env with your values
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

| Flag        | Description |
|-------------|-------------|
| `-u <user>` | Filter by user (omit to list all) |
| `-i`        | Show IP addresses |
| `-f`        | Show failure logs |
| `-s`        | Show success logs |
| `-c`        | Show commands (sudo) |
| `--full`    | Full raw log dump for specified user |
| `-l <file>` | Use a custom log file (default: `/var/log/auth.log`) |
| `-v`        | Verbose: show timestamp, log file path, size, last rotation |

### Examples

```bash
# IPs that successfully authenticated as alice
sudo python3 logalyzer-ng.py -u alice -i

# Failed IPs + Whois on unknown ones
sudo python3 logalyzer-ng.py -u alice -f -i

# Commands run by root
sudo python3 logalyzer-ng.py -u root -c

# All usernames tried by attackers
sudo python3 logalyzer-ng.py

# Verbose info about the log file
sudo python3 logalyzer-ng.py -v
```

> If the user is not found in `auth.log`, the script automatically falls back to `auth.log.1`.

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
| Attempted attackers | *(no flags)* |

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
    logs      = ["raw line", ...],    # all lines
    fail_logs = ["raw line", ...],    # Failed password / auth failure
    succ_logs = ["raw line", ...],    # Accepted password
    ips       = ["1.2.3.4", ...],     # IPs seen for this user
    commands  = ["/usr/bin/...", ...]  # sudo COMMAND= entries
  ),
  None: Log(...)  # lines where the user could not be parsed
}
```

Supports plain text and gzip-compressed logs (`.gz`).
