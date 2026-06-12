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
      
    return settings


def get_ports_recommandations(settings: dict) -> list[dict]:
    
    return settings


def get_suid_recommandations(settings: dict) -> list[dict]:
    
    return settings


def get_permissions_recommandations(settings: dict) -> list[dict]:
    
    return settings


def get_services_recommandations(settings: dict) -> list[dict]:
    
    return settings
