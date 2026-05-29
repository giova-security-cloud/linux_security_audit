# check/firewall_check.py

import subprocess

RISKY_PORTS = {22, 23, 3389, 5900, 21, 25, 110, 3306, 5432}

def firewall_audit():
    display_score=0
    result = {
        "tool_detected": None,
        "status": "inactive",
        "rules_count": 0,
        "audit_score": 0
    }

    for tool in ["ufw", "firewalld", "iptables"]:
        try:
            if tool == "ufw":
                out = subprocess.check_output(["ufw", "status"], stderr=subprocess.DEVNULL, text=True)
                if "active" in out.lower():
                    result["tool_detected"] = "ufw"
                    result["status"] = "active"
                    result["rules_count"] = out.count("ALLOW") + out.count("DENY")
                    result["audit_score"] = 30
                    display_score+= result.get("audit_score")
                    break

            elif tool == "firewalld":
                out = subprocess.check_output(["firewall-cmd", "--state"], stderr=subprocess.DEVNULL, text=True)
                if "running" in out.lower():
                    result["tool_detected"] = "firewalld"
                    result["status"] = "active"
                    result["audit_score"] = 30
                    display_score+= result.get("audit_score")
                    break

            elif tool == "iptables":
                out = subprocess.check_output(["iptables", "-L", "-n"], stderr=subprocess.DEVNULL, text=True)
                lines = [l for l in out.splitlines() if l.startswith("ACCEPT") or l.startswith("DROP")]
                if lines:
                    result["tool_detected"] = "iptables"
                    result["status"] = "active"
                    result["rules_count"] = len(lines)
                    result["audit_score"] = 20
                    display_score+= result.get("audit_score")
                    break

        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    
    return result
