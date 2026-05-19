import sys
import os
import struct
import fnmatch
import subprocess

def ssh_file_search(ssh_c):
    #Search sshd config file
    try:
            ssh_path="find /etc/ -name " + ssh_c + " | tr -d \'\n\'"
            sshconf=subprocess.Popen([ssh_path], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            routput,rerror=sshconf.communicate()
            if rerror:
                print("error while searching configuration ssh file.")
                return rerror
            if os.path.isfile(routput):    
                return routput
    except OSError as e:
        print(f"Error checking file: {e}")

def ssh_audit(search):
    try:
        ssh_report={}
        with open(search , 'r') as file:

            for param in file:
            
                if "PermitRootLogin" in param:  
                    words=[ word.lstrip('#') for word in param.strip().split() ]
                    if len(words)==2:
                        ssh_report.update({words[0]:words[1]})
                if "PasswordAuthentication" in param:  
                    words=[ word.lstrip('#') for word in param.strip().split() ]
                    if len(words)==2:
                        ssh_report.update({words[0]:words[1]})
        
        file.close()
        
        return ssh_report 
    
    except FileNotFoundError:
        return {"error" : "sshd_config file not found"}


