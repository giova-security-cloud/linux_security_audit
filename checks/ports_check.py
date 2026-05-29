# checks/ports_check.py

import subprocess
import re

RISKY_PORTS = {
    21:   "FTP unencrypted file transfer",
    22:   "SSH publicly exposed?",
    23:   "Telnet unencrypted protocol",
    25:   "SMTP open mail relay?",
    53:   "DNS open resolver?",
    80:   "HTTP unencrypted",
    110:  "POP3 unencrypted mail",
    135:  "Windows RPC",
    139:  "NetBIOS",
    443:  "HTTPS check the certificate",
    445:  "SMB critical risk",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL/MariaDB exposed?",
    3389: "RDP critical risk",
    5432: "PostgreSQL exposed?",
    5900: "VNC remote desktop access",
    6379: "Redis often unauthenticated",
    8080: "HTTP alternate port",
    8443: "HTTPS alternate port",
    9200: "Elasticsearch often unauthenticated",
    27017:"MongoDB often unauthenticated",
}

def parse_ss(output: str) -> list[dict]:
    """Parse the output of ss -tuln"""
    ports = []
    for line in output.splitlines():
        # Skip the header line
        if line.startswith("Netid") or line.startswith("State"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto   = parts[0]   # tcp / udp
        state   = parts[1]   # LISTEN / UNCONN
        local   = parts[4]   # 0.0.0.0:22 or [::]:22

        # Extract port number from local address
        match = re.search(r":(\d+)$", local)
        if not match:
            continue
        port = int(match.group(1))

        ports.append({
            "port":     port,
            "proto":    proto.lower(),
            "state":    state.lower(),
            "address":  local,
        })
    return ports


def parse_nmap(output: str) -> list[dict]:
    """Parse the output of nmap -sT -p- or nmap --open"""
    ports = []
    for line in output.splitlines():
        # Line format: "22/tcp   open  ssh"
        match = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(.+)$", line.strip())
        if not match:
            continue
        ports.append({
            "port":    int(match.group(1)),
            "proto":   match.group(2),
            "state":   match.group(3),
            "service": match.group(4).strip(),
        })
    return ports


def flag_risks(ports: list[dict]) -> list[dict]:
    """Add a risk_reason field to sensitive ports"""
    for p in ports:
        p["risk"] = False
        p["risk_reason"] = None
        if p["port"] in RISKY_PORTS:
            p["risk"] = True
            p["risk_reason"] = RISKY_PORTS[p["port"]]
    return ports


def ports_audit() -> dict:
    result = {
        "method":       None,
        "open_ports":   [],
        "risky_ports":  [],
        "total_open":   0,
        "audit_score": 0,
        "error":        None,
    }

    ports = []

    # ── Method 1: ss (always available on modern Linux) ─────────────────────
    try:
        out = subprocess.check_output(
            ["ss", "-tuln"],
            stderr=subprocess.DEVNULL,
            text=True
        )
        ports = parse_ss(out)
        result["method"] = "ss"

    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # ── Method 2: nmap as fallback ───────────────────────────────────────────
    if not ports:
        try:
            out = subprocess.check_output(
                ["nmap", "-sT", "--open", "-p-", "127.0.0.1"],
                stderr=subprocess.DEVNULL,
                text=True
            )
            ports = parse_nmap(out)
            result["method"] = "nmap"

        except (subprocess.CalledProcessError, FileNotFoundError):
            result["error"] = "ss and nmap are both unavailable on this system"
            return result

    # ── Risk analysis ────────────────────────────────────────────────────────
    ports = flag_risks(ports)

    risky = [p for p in ports if p["risk"]]

    result["open_ports"]  = ports
    result["risky_ports"] = risky
    result["total_open"]  = len(ports)

    # Score: -10 per risky port, capped at -50
    penalty = min(len(risky) * 10, 50)
    result["audit_score"] = -penalty
    
    return result





