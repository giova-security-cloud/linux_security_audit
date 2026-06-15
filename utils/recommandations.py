import subprocess
import logging



def get_ssh_recommandations(settings: dict) -> list[dict]:
    if "no" not in settings["PermitRootLogin"]:
        settings["PermitRootLogin"]={
                                     "status":"FAIL",
                                     "expected": "no",
                                     "recommandations": "Set PermitRootLogin to no",
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
                                            "recommandations": "Set PasswordAuthentication to no",
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


def get_firewall_recommandations(settings: dict) -> list[dict]:
     
    if "ufw" in settings["tool_detected"]:
        
        if "active" not in settings["status"]:
            settings["status"]={
                               "status":"FAIL",
                               "expected":"active",
                               "recommandations":"Enable ufw firewall",
                               "severity":"HIGH"
                               }

        if settings["rules_count"] == 0:
            settings["rules_count"]={
                                     "status":"FAIL",
                                     "expected": "no",
                                     "recommandations1": "Set Default Incoming policy to DENY",
                                     "recommandations2": "Set Default Outgoing policy to ALLOW",
                                     "recommandations3": "Allow SSH port 22",
                                     "recommandations4": "Deny Telnet port 23",
                                     "recommandations5": "Deny FTP port 21",
                                     "recommandations6": "Enable firewall logging",
                                     "severity": "HIGH"
                                    }


    if "firewalld" in settings["tool_detected"]:
       
        if "active" not in settings["status"]:
            settings["status"]={
                               "status":"FAIL",
                               "expected":"active",
                               "recommandations":"Enable firewalld on boot",
                               "severity":"HIGH"
                               }

        if settings["rules_count"] == 0:
            settings["rules_count"]={
                                     "status":"FAIL",
                                     "recommandations1": "Set Default Zone to DROP",
                                     "recommandations2": "Allow SSH service",
                                     "recommandations3": "Remove Telnet service",
                                     "recommandations4": "Remove FTP service",
                                     "recommandations5": "Remove unnecessary DHCPv6 client",
                                     "severity": "HIGH"
                                    }


    if "iptables" in settings["tool_detected"]:
        if settings["rules_count"] == 0:
            settings["rules_count"]={
                                     "status":"FAIL",
                                     "recommandations1": "Set Default INPUT policy to DROP",
                                     "recommandations2": "Set Default FORWARD policy to DROP",
                                     "recommandations3": "Allow loopback interface",
                                     "recommandations4": "Allow established and related connections",
                                     "recommandations5": "Allow SSH port 22",
                                     "recommandations6": "Deny Telnet port 23",
                                     "recommandations7": "Deny FTP port 21",
                                     "severity": "HIGH"
                                    }
    
    return settings


def get_ports_recommandations(settings: dict) -> list[dict]:
    
    return settings


def get_suid_recommandations(settings: dict) -> list[dict]:
    
    return settings


def get_permissions_recommandations(settings: dict) -> list[dict]:
    
    return settings


def get_services_recommandations(settings: dict) -> list[dict]:
    
    return settings
