# utils/recommendations.py

import os
import subprocess
import logging



def get_ssh_recommendations(settings: dict) -> list[dict]:
    if "no" not in settings["PermitRootLogin"]:
        settings["PermitRootLogin"]={
                                     "status":"FAIL",
                                     "expected": "no",
                                     "recommendations": "Set PermitRootLogin to no",
                                     "severity": "HIGH"
                                    }
    else:
         settings["PermitRootLogin"]={
                                      "value":"no",
                                      "status": "PASS",
                                     }
        
    if "no" not in settings["PasswordAuthentication"]:
        settings["PasswordAuthentication"]={
                                            "status":"FAIL",
                                            "expected": "no",
                                            "recommendations": "Set PasswordAuthentication to no",
                                            "severity": "HIGH"
                                           }
    else:
         settings["PasswordAuthentication"]={ 
                                          "value": "no",
                                          "status": "PASS"
                                         }
    if settings["MaxAuthTries"] >= 4:
        settings["MaxAuthTries"]={ 
                                  "status":"FAIL",
                                  "expected": "4",
                                  "recommendation": "Reduce MaxAuthTries to 4 or less to limit brute-force attempts.",
                                  "severity": "MEDIUM"
                                 }
    else:
         settings["MaxAuthTries"]={
                                   "status": "PASS",
                                  }

    if settings["ClientAliveInterval"] >= 300:
         settings["ClientAliveInterval"]={
                                          "status":"FAIL",
                                          "expected": "300",
                                          "recommendation": "Configure ClientAliveInterval to automatically close inactive sessions.",
                                          "severity": "LOW"
                                         }
    else:
         settings["ClientAliveInterval"]={
                                          "status": "PASS",
                                         } 
    return settings


def get_firewall_recommendations(settings: dict) -> list[dict]:
     
    if "ufw" in settings["tool_detected"]:
        
        if "active" not in settings["status"]:
            settings["status"]={
                               "status":"FAIL",
                               "expected":"active",
                               "recommendations":"Enable ufw firewall",
                               "severity":"HIGH"
                               }

        if settings["rules_count"] == 0:
            settings["rules_count"]={
                                     "status":"FAIL",
                                     "recommendations": {
                                                         "default deny": "Set Default Incoming policy to DENY ", 
                                                         "default allow": "Set Default Outgoing policy to ALLOW ",
                                                         "ssh": "Allow SSH port 22 ",
                                                         "Telnet": "Deny Telnet port 23",
                                                         "ftp": "Deny FTP port 21",
                                                         "logging": "Enable firewall logging."
                                                         },
                                     "severity": "HIGH" 
                                     }


    if "firewalld" in settings["tool_detected"]:
       
        if "active" not in settings["status"]:
            settings["status"]={
                               "status":"FAIL",
                               "expected":"active",
                               "recommendations":"Enable firewalld on boot",
                               "severity":"HIGH"
                               }

        if settings["rules_count"] == 0:
            settings["rules_count"]={
                                     "status":"FAIL",
                                     "recommendations": {
                                                         "default": "Set Default Zone to DROP",
                                                         "ssh": "Allow SSH service",
                                                         "Telnet": "Remove Telnet service",
                                                         "ftp": "Remove FTP service",
                                                         "dhcpv6":"Remove unnecessary DHCPv6 client"
                                                         },
                                     "severity": "HIGH"
                                    }

    if "iptables" in settings["tool_detected"]:
        if settings["rules_count"] == 0:
            settings["rules_count"]={
                                     "status":"FAIL",
                                     "recommendations": {
                                                         "default input": "Set Default INPUT policy to DROP",
                                                         "default forward":"Set Default FORWARD policy to DROP",
                                                         "loopback": "Allow loopback interface",
                                                         "established": "Allow established and related connections",
                                                         "ssh": "Allow SSH port 22",
                                                         "telnet": "Deny Telnet port 23",
                                                         "ftp": "Deny FTP port 21"
                                                         },
                                     "severity": "HIGH"
                                    }
    
    return settings


def get_ports_recommendations(settings: dict) -> list[dict]:
    # Recommendations per risky port
    # Format: port -> {recommendation, commands, severity}
    PORT_RECOMMENDATIONS = {
        21: {
            "severity": "HIGH",
            "service":  "FTP",
            "recommendation": (
                               "FTP transmits data and credentials in plaintext. "
                               "Replace with SFTP (SSH File Transfer Protocol) or FTPS. "
                               "If FTP is not needed, disable the service entirely."
                              ),
            "actions": [
                ["systemctl", "stop", "vsftpd"],
                ["systemctl", "disable", "vsftpd"],
            ],
            "ufw_rule":        ["ufw", "deny", "21/tcp"],
            "firewalld_rule":  ["firewall-cmd", "--permanent", "--remove-service=ftp"],
            "iptables_rule":   ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "21", "-j", "DROP"],
        },
        22: {
            "severity":       "medium",
            "service":        "SSH",
            "recommendation": (
                               "SSH is open to ensure it is hardened: "
                               "disable root login, disable password authentication, "
                               "restrict to specific IPs if possible using AllowUsers or firewall rules."
                              ),
            "actions": [],
            "ufw_rule":       ["ufw", "allow", "22/tcp"],
            "firewalld_rule": ["firewall-cmd", "--permanent", "--add-service=ssh"],
            "iptables_rule":  ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"],
        },
        23: {
            "severity":       "critical",
            "service":        "Telnet",
            "recommendation": (
                               "Telnet is a critical risk — all data including passwords "
                               "are sent in plaintext. Disable immediately and replace with SSH."
                              ),
            "actions": [
                ["systemctl", "stop", "telnet"],
                ["systemctl", "disable", "telnet"],
                ["systemctl", "stop", "telnetd"],
                ["systemctl", "disable", "telnetd"],
            ],
            "ufw_rule":       ["ufw", "deny", "23/tcp"],
            "firewalld_rule": ["firewall-cmd", "--permanent", "--remove-service=telnet"],
            "iptables_rule":  ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "23", "-j", "DROP"],
        },
        25: {
            "severity":       "HIGH",
            "service":        "SMTP",
            "recommendation": (
                               "SMTP port is open to verify this server is not an open relay. "
                               "Restrict to authenticated users only and enable TLS. "
                               "If no mail server is needed, disable the service."
                              ),
            "actions": [],
            "ufw_rule":       ["ufw", "deny", "25/tcp"],
            "firewalld_rule": ["firewall-cmd", "--permanent", "--remove-service=smtp"],
            "iptables_rule":  ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "25", "-j", "DROP"],
        },
        53: {
            "severity":       "medium",
            "service":        "DNS",
            "recommendation": (
                               "DNS port is open to ensure this is not an open resolver "
                               "which could be used in DDoS amplification attacks. "
                               "Restrict to authorized clients only."
                              ),
            "actions": [],
            "ufw_rule":       ["ufw", "deny", "53"],
            "firewalld_rule": ["firewall-cmd", "--permanent", "--remove-service=dns"],
            "iptables_rule":  ["iptables", "-A", "INPUT", "-p", "udp", "--dport", "53", "-j", "DROP"],
        },
        445: {
            "severity":       "critical",
            "service":        "SMB",
            "recommendation": (
                               "SMB is a critical attack vector (EternalBlue, WannaCry). "
                               "Block port 445 immediately if this is not a file server. "
                               "If SMB is required, restrict to internal network only."
                              ),
            "actions": [
                ["systemctl", "stop", "smbd"],
                ["systemctl", "disable", "smbd"],
            ],
            "ufw_rule":       ["ufw", "deny", "445/tcp"],
            "firewalld_rule": ["firewall-cmd", "--permanent", "--remove-service=samba"],
            "iptables_rule":  ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "445", "-j", "DROP"],
        },
        3306: {
            "severity":       "HIGH",
            "service":        "MySQL/MariaDB",
            "recommendation": (
                               "MySQL/MariaDB is publicly exposed. "
                               "Bind the service to localhost only by setting "
                               "'bind-address = 127.0.0.1' in /etc/mysql/my.cnf. "
                               "Never expose a database port directly to the internet."
                              ),
            "actions": [],
            "ufw_rule":       ["ufw", "deny", "3306/tcp"],
            "firewalld_rule": ["firewall-cmd", "--permanent", "--remove-service=mysql"],
            "iptables_rule":  ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "3306", "-j", "DROP"],
        },
        3389: {
            "severity":       "critical",
            "service":        "RDP",
            "recommendation": (
                               "RDP is a critical risk — it is one of the most targeted "
                               "services for brute-force and ransomware attacks. "
                               "Block externally, restrict to VPN access only, "
                               "or disable if not needed."
                              ),
            "actions": [
                ["systemctl", "stop", "xrdp"],
                ["systemctl", "disable", "xrdp"],
            ],
            "ufw_rule":       ["ufw", "deny", "3389/tcp"],
            "firewalld_rule": ["firewall-cmd", "--permanent", "--remove-service=rdp"],
            "iptables_rule":  ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "3389", "-j", "DROP"],
        },
        5432: {
            "severity":       "HIGH",
            "service":        "PostgreSQL",
            "recommendation": (
                               "PostgreSQL is publicly exposed. "
                               "Set 'listen_addresses = localhost' in postgresql.conf "
                               "and restrict pg_hba.conf to local connections only."
                              ),
            "actions": [],
            "ufw_rule":       ["ufw", "deny", "5432/tcp"],
            "firewalld_rule": ["firewall-cmd", "--permanent", "--remove-service=postgresql"],
            "iptables_rule":  ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "5432", "-j", "DROP"],
        },
        5900: {
            "severity":       "HIGH",
            "service":        "VNC",
            "recommendation": (
                               "VNC transmits desktop sessions with weak encryption. "
                               "Disable VNC or tunnel it through SSH only. "
                               "Never expose VNC directly to the internet."
                              ),
            "actions": [
                ["systemctl", "stop", "vncserver"],
                ["systemctl", "disable", "vncserver"],
            ],
            "ufw_rule":       ["ufw", "deny", "5900/tcp"],
            "firewalld_rule": ["firewall-cmd", "--permanent", "--remove-port=5900/tcp"],
            "iptables_rule":  ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "5900", "-j", "DROP"],
        },
        6379: {
            "severity":       "critical",
            "service":        "Redis",
            "recommendation": (
                               "Redis is exposed without authentication by default. "
                               "Bind to localhost in redis.conf: 'bind 127.0.0.1'. "
                               "Set a strong password with 'requirepass'. "
                               "Never expose Redis to the internet."
                              ),
            "actions": [],
            "ufw_rule":       ["ufw", "deny", "6379/tcp"],
            "firewalld_rule": ["firewall-cmd", "--permanent", "--remove-port=6379/tcp"],
            "iptables_rule":  ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "6379", "-j", "DROP"],
        },
        9200: {
            "severity":       "critical",
            "service":        "Elasticsearch",
            "recommendation": (
                               "Elasticsearch has no authentication by default. "
                               "Bind to localhost only and enable X-Pack security. "
                               "Many data breaches have involved exposed Elasticsearch instances."
            ),
            "actions": [],
            "ufw_rule":       ["ufw", "deny", "9200/tcp"],
            "firewalld_rule": ["firewall-cmd", "--permanent", "--remove-port=9200/tcp"],
            "iptables_rule":  ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "9200", "-j", "DROP"],
        },
        27017: {
            "severity":       "critical",
            "service":        "MongoDB",
            "recommendation": (
                               "MongoDB has no authentication by default. "
                               "Enable authentication in mongod.conf: 'security.authorization: enabled'. "
                               "Bind to localhost only: 'net.bindIp: 127.0.0.1'."
                              ),
            "actions": [],
            "ufw_rule":       ["ufw", "deny", "27017/tcp"],
            "firewalld_rule": ["firewall-cmd", "--permanent", "--remove-port=27017/tcp"],
            "iptables_rule":  ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "27017", "-j", "DROP"],
        },
    }

    # Severity display order
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    SEVERITY_LABEL = {
        "critical": "[CRITICAL]",
        "high":     "[HIGH]    ",
        "medium":   "[MEDIUM]  ",
        "low":      "[LOW]     ",
    }
    
    rec_l=[]

    if not settings["risky_ports"]:
        print(f"[+] No risky ports detected - nothing to recommend.")
        return

    sorted_ports= sorted(settings["risky_ports"], key=lambda p: SEVERITY_ORDER.get(PORT_RECOMMENDATIONS.get( 
                                                       p["port"], {}) .get("severity", "low"), 3 
                                                  )
                  )

    for port_entry in sorted_ports:
        port= port_entry["port"]
        recs= PORT_RECOMMENDATIONS.get(port)
        label   = SEVERITY_LABEL.get(recs["severity"], "[UNKNOWN] ")
        service = recs["service"]
        if not recs:
            continue

        print(f"\n{label} Port {port} to {service}")
        print(f"  Recommendation: {recs['recommendation']}")
        
        rec_l.append({
                     "target":         port,
                     "service":        service,
                     "severity":       recs["severity"],
                     "address":        port_entry["address"],
                     "proto":          port_entry["proto"],
                     "recommendation": recs['recommendation'],
                     "actions":        recs['actions'],
                     "ufw_rule":       recs.get("ufw_rule"),
                     "firewalld_rule": recs.get("firewalld_rule"),
                     "iptables_rule":  recs.get("iptables_rule")
                    })
                                      
    settings["recommendations"]=rec_l
                                    
    return settings


def get_suid_recommendations(settings: dict) -> list[dict]:
    SUID_DANGEROUS_PATTERNS = {
    "nmap":    "nmap with SUID can spawn a root shell via --interactive (old versions)",
    "vim":     "vim with SUID allows root shell escape via :!sh",
    "vi":      "vi with SUID allows root shell escape via :!sh",
    "find":    "find with SUID allows root shell escape via -exec",
    "python":  "python with SUID allows root shell escape via os.system",
    "python3": "python3 with SUID allows root shell escape via os.system",
    "perl":    "perl with SUID allows root shell escape",
    "awk":     "awk with SUID allows root shell escape via system()",
    "bash":    "bash with SUID is extremely dangerous — instant root shell",
    "sh":      "sh with SUID is extremely dangerous — instant root shell",
    "cp":      "cp with SUID can overwrite /etc/passwd or /etc/shadow",
    "mv":      "mv with SUID can overwrite critical system files",
    "tar":     "tar with SUID allows root shell escape via --checkpoint-action",
    "less":    "less with SUID allows root shell escape via !sh",
    "more":    "more with SUID allows root shell escape",
    }

    SUID_DEFAULT_TEXT = (
    "This SUID binary is not in the known whitelist. Verify it was "
    "installed by a trusted package manager (dpkg -S <path> or rpm -qf <path>). "
    "If SUID is not required, remove it with 'chmod u-s <path>'."
    )

    """
    Args:
        settings: audit["suid"] as the raw output of run_suid_check()
    Returns:
        list of recommendation dicts, sorted by severity
    """
    
    suspicious_files = settings.get("suspicious_files", [])
    recs = []

    for entry in suspicious_files:
        filepath = entry["path"]
        filename = os.path.basename(filepath)

        if filename in SUID_DANGEROUS_PATTERNS:
            severity = "critical"
            text = (
                    f"{SUID_DANGEROUS_PATTERNS[filename]}. "
                    f"Remove SUID immediately: 'chmod u-s {filepath}'."
                   )
        else:
            severity = "high"
            text = SUID_DEFAULT_TEXT

        recs.append({
                     "target":         filepath,
                     "severity":       severity,
                     "recommendation": text,
                     "actions":        [["chmod", "u-s", filepath]],
                     "owner_uid":      entry.get("owner_uid"),
                   })

    settings["recommendations"]=recs

    return settings


def get_permissions_recommendations(settings: dict) -> list[dict]:
    
    return settings


def get_services_recommendations(settings: dict) -> list[dict]:
    
    return settings
