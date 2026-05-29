# Linux Security Audit Tool

A modular Python-based security audit tool for Linux systems.
Designed for system engineers and security professionals who need
a lightweight, scriptable alternative to heavy audit frameworks.

---

## Features

| Check | Description |
|---|---|
| SSH | Audits sshd_config for insecure settings |
| Firewall | Detects ufw / firewalld / iptables status |
| Ports | Identifies open and risky ports via ss or nmap |
| SUID | Detects suspicious SUID binaries |
| Permissions | Audits critical file permissions and ownership |

---

## Requirements

- Python 3.9+
- Linux (tested on Ubuntu 22.04, Debian 11)
- Root or sudo privileges recommended for full scan

No external dependencies — uses only Python standard library.
`nmap` is optional (used as fallback in ports check).

---

## Project Structure

```
linux-security-audit/
│── audit.py               # Main entry point — CLI + orchestration
│── checks/
│   │── __init__.py
│   │── ssh_check.py       # SSH configuration audit
│   │── firewall_check.py  # Firewall status detection
│   │── ports_check.py     # Open ports detection
│   │── suid_check.py      # SUID files detection
│   │── permissions_check.py # Critical file permissions
│── reports/
│   │── reporter.py        # JSON report generation
│── utils/
│   │── scoring.py         # Global score computation
│── output/                # Generated reports saved here
│── README.md
│── requirements.txt
```

---

## Installation

```bash
git clone https://github.com/giova-security-cloud/linux_security_audit.git
cd linux_security_audit
```

No pip install required — pure standard library.

---

## Usage

```bash
# Full audit
sudo python3 audit.py --scan all --output report.json

# Single check
sudo python3 audit.py --scan ssh
sudo python3 audit.py --scan firewall
sudo python3 audit.py --scan ports --output ports.json
sudo python3 audit.py --scan suid
sudo python3 audit.py --scan permissions
```

---

## Example Output

### Terminal

```
[*] Starting security audit...

[*] Running SSH check...
[+] SSH check done
[*] Running firewall check...
[+] Firewall check done
[*] Running ports check...
[+] Ports check done
[*] Running SUID check...
[+] SUID check done
[*] Running permissions check...
[+] Permissions check done

========================================
  Security Score : 65 / 100
========================================

[+] Report saved → output/report.json
```

### JSON Report

```json
{
  "ssh": {
    "PermitRootLogin": "no",
    "PasswordAuthentication": "yes",
    "score_impact": 50
  },
  "firewall": {
    "tool_detected": "ufw",
    "status": "active",
    "rules_count": 4,
    "score_impact": 30
  },
  "ports": {
    "method": "ss",
    "total_open": 5,
    "total_suspicious": 2,
    "risky_ports": [
      {
        "port": 3306,
        "proto": "tcp",
        "risk": true,
        "risk_reason": "MySQL/MariaDB — exposed?"
      }
    ],
    "score_impact": -20
  },
  "suid": {
    "total_suid": 12,
    "total_suspicious": 1,
    "suspicious_files": [
      {
        "path": "/usr/local/bin/custom_tool",
        "owner_uid": 1000,
        "whitelisted": false,
        "suspicious": true
      }
    ],
    "score_impact": -20
  },
  "permissions": {
    "total_checked": 18,
    "total_issues": 2,
    "world_writable": [],
    "world_readable": ["/etc/shadow"],
    "wrong_owner": ["/etc/sudoers"],
    "score_impact": -15
  },
  "score": 65
}
```

---

## Scoring System

The tool computes a global security score out of 100.

| Check | Condition | Impact |
|---|---|---|
| SSH | PermitRootLogin no | +50 |
| SSH | PasswordAuthentication no | +50 |
| Firewall | ufw/firewalld active | +30 |
| Firewall | iptables active | +20 |
| Ports | Per risky port detected | -10 |
| Ports | Maximum penalty | -50 |
| SUID | Per suspicious binary | -20 |
| SUID | Maximum penalty | -60 |
| Permissions | World-writable file | -15 |
| Permissions | Wrong owner | -10 |
| Permissions | Wrong mode | -5 |
| Permissions | World-readable sensitive | -5 |
| Permissions | Maximum penalty | -60 |

Score is always floored at 0.

---

## Roadmap

- [x] Month 1 - Core audit engine
- [x] Month 2 - Extended checks (ports, SUID, permissions, services)
- [ ] Month 3 - Automated hardening suggestions
- [ ] Month 4 - HTML report output
- [ ] Month 5 - CI/CD integration (GitHub Actions)

---

## Author

**Giovanny CLAUDE**
System Engineer | CEHv9 | Stormshield CSNA
[LinkedIn](https://www.linkedin.com/in/giovanny-c-86178a38) * [GitHub](https://github.com/giova-security-cloud/linux_security_audit)

---

## License

MIT License - free to use, modify, and distribute.

