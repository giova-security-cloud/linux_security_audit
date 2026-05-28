# checks/services_check.py

import subprocess

# Services that should never run on a hardened system
# Format: "service_name": "reason"
RISKY_SERVICES = {
    # Unencrypted remote access
    "telnet":       "Unencrypted remote access — replace with SSH",
    "telnetd":      "Unencrypted remote access — replace with SSH",
    "rsh":          "Unencrypted remote shell — critical risk",
    "rshd":         "Unencrypted remote shell — critical risk",
    "rlogin":       "Unencrypted remote login — critical risk",
    "rexec":        "Unencrypted remote execution — critical risk",

    # Unencrypted file transfer
    "ftp":          "Unencrypted file transfer — replace with SFTP",
    "ftpd":         "Unencrypted file transfer — replace with SFTP",
    "vsftpd":       "FTP daemon — replace with SFTP if possible",
    "proftpd":      "FTP daemon — replace with SFTP if possible",

    # Exposed database services
    "mysqld":       "MySQL exposed — restrict to localhost",
    "mariadbd":     "MariaDB exposed — restrict to localhost",
    "mongod":       "MongoDB exposed — often unauthenticated",
    "redis-server": "Redis exposed — often unauthenticated",
    "postgres":     "PostgreSQL exposed — restrict to localhost",

    # Deprecated or risky protocols
    "finger":       "Exposes user information — should be disabled",
    "talk":         "Deprecated communication service",
    "ntalk":        "Deprecated communication service",
    "chargen":      "Character generator — can be used in DDoS amplification",
    "daytime":      "Deprecated time service",
    "echo":         "Can be used in amplification attacks",
    "discard":      "Deprecated service",

    # Remote desktop
    "x11vnc":       "VNC remote desktop — unencrypted",
    "vncserver":    "VNC remote desktop — unencrypted",
    "xrdp":         "RDP service — high attack surface",

    # Misc
    "avahi-daemon": "mDNS/DNS-SD — exposes network info",
    "cups":         "Printing service — unnecessary on servers",
    "bluetooth":    "Bluetooth — unnecessary on servers",
    "nfs":          "NFS — exposes filesystem if misconfigured",
    "rpcbind":      "RPC portmapper — required by NFS, high risk",
    "snmpd":        "SNMP — exposes system info if misconfigured",
}


def get_active_services() -> list[str]:
    """
    Return a list of all active running services via systemctl.
    Falls back to service --status-all if systemctl is unavailable.
    """
    services = []

    # Method 1: systemctl (systemd — most modern distros)
    try:
        out = subprocess.check_output(
            ["systemctl", "list-units", "--type=service",
             "--state=running", "--no-pager", "--no-legend"],
            stderr=subprocess.DEVNULL,
            text=True
        )
        for line in out.splitlines():
            parts = line.split()
            if parts:
                # Unit name format: "ssh.service"
                service_name = parts[0].replace(".service", "").strip()
                services.append(service_name)
        return services

    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Method 2: service --status-all (SysV init — older distros)
    try:
        out = subprocess.check_output(
            ["service", "--status-all"],
            stderr=subprocess.STDOUT,
            text=True
        )
        for line in out.splitlines():
            # Line format: " [ + ]  ssh"
            if "[ + ]" in line:
                parts = line.strip().split()
                if len(parts) >= 3:
                    services.append(parts[-1])
        return services

    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return services


def flag_risky(active_services: list[str]) -> list[dict]:
    """
    Cross-reference active services against RISKY_SERVICES.
    Returns a list of risky services found running.
    """
    found = []
    for service in active_services:
        # Normalize: remove trailing digits (e.g. "apache2" vs "apache")
        normalized = service.lower().strip()
        if normalized in RISKY_SERVICES:
            found.append({
                "service": service,
                "reason":  RISKY_SERVICES[normalized],
            })
    return found


def services_audit() -> dict:
    result = {
        "active_services":  [],
        "risky_services":   [],
        "total_active":     0,
        "total_risky":      0,
        "audit_score":     0,
        "error":            None,
    }

    active = get_active_services()

    if not active:
        result["error"] = "Could not retrieve active services (systemctl and service both unavailable)"
        return result

    risky = flag_risky(active)

    result["active_services"] = active
    result["risky_services"]  = risky
    result["total_active"]    = len(active)
    result["total_risky"]     = len(risky)

    # Score: -15 per risky service, capped at -60
    penalty = min(len(risky) * 15, 60)
    result["audit_score"] = -penalty

    #Display score
    print("services score : " + str(result["audit_score"]))

    return result
