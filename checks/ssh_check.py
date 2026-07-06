# check/ssh_check.py
import sys
import os
import struct
import fnmatch
import subprocess
from   utils.logger import logger

def ssh_file_search():
    #Search sshd config file
    try:
            ssh_c="sshd_config"
            ssh_path="find /etc/ -name " + ssh_c + " | tr -d \'\n\'"
            sshconf=subprocess.Popen([ssh_path], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            routput,rerror=sshconf.communicate()
            if rerror:
                logger.error("error while searching configuration ssh file.")
                return rerror
            if os.path.isfile(routput):    
                return routput
    except OSError as e:
        logger.error(f"Error checking file: {e}")

def ssh_audit(search):
    try:
        audit_score=0
        ssh_report={}

        with open(search , 'r') as file:

            for param in file:
            
                if "PermitRootLogin" in param:  
                    words=[ word.lstrip('#') for word in param.strip().split()]
                    if len(words)==2:
                        ssh_report.update({words[0]:words[1]})
                        if "no" in words[1]:
                            audit_score+=50
                if "PasswordAuthentication" in param:  
                    words=[ word.lstrip('#') for word in param.strip().split()]
                    if len(words)==2:
                        ssh_report.update({words[0]:words[1]})
                        if "no" in words[1]:
                            audit_score+= 50        
                if "MaxAuthTries" in param:  
                    words=[ word.lstrip('#') for word in param.strip().split()]
                    if len(words)==2:
                        ssh_report.update({words[0]:int(words[1])})
                if "ClientAliveInterval" in param:  
                    words=[ word.lstrip('#') for word in param.strip().split()]
                    if len(words)==2:
                        ssh_report.update({words[0]:int(words[1])})
        file.close()

        ssh_report["audit_score"]=audit_score
 
        return ssh_report 
    
    except FileNotFoundError:
        return logger.error("Unable to read sshd_config")



