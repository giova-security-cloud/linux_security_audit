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
                                                         "default deny ":"Set Default Incoming policy to DENY " 
                                                         "default allow":"Set Default Outgoing policy to ALLOW "
                                                         "ssh": "Allow SSH port 22 "
                                                         "Telnet": "Deny Telnet port 23 "
                                                         "ftp": "Deny FTP port 21 "
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
                                                         "default": "Set Default Zone to DROP"
                                                         "ssh": "Allow SSH service"
                                                         "Telnet": "Remove Telnet service"
                                                         "ftp": "Remove FTP service"
                                                         "dhcpv6":"Remove unnecessary DHCPv6 client"
                                                         },
                                     "severity": "HIGH"
                                    }

    if "iptables" in settings["tool_detected"]:
        if settings["rules_count"] == 0:
            settings["rules_count"]={
                                     "status":"FAIL",
                                     "recommendations": {
                                                         "default input": "Set Default INPUT policy to DROP"
                                                         "default forward":"Set Default FORWARD policy to DROP"
                                                         "loopback": "Allow loopback interface"
                                                         "established": "Allow established and related connections"
                                                         "ssh": "Allow SSH port 22"
                                                         "telnet": "Deny Telnet port 23"
                                                         "ftp": "Deny FTP port 21"
                                                         },
                                     "severity": "HIGH"
                                    }
    
    return settings


def get_ports_recommendations(settings: dict) -> list[dict]:
    
    return settings


def get_suid_recommendations(settings: dict) -> list[dict]:
    
    return settings


def get_permissions_recommendations(settings: dict) -> list[dict]:
    
    return settings


def get_services_recommendations(settings: dict) -> list[dict]:
    
    return settings
