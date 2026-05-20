import sys
import getopt
import socket
import os
import json

def read_report(filename):
    print("[+] Reading the report : " +  filename)
    try: 
        with open(os.path.join("/home/gclaude/linux_security_audit/reports/",filename), "r", encoding="utf-8") as json_f:
            report=json.load(json_f)
            return report

    except OSerror:
        print("Could not open the report file.")
        sys.exit()


def make_score(report):
    score=0  
    #SSH score
    for i,j in list(report["ssh"].items()):
        if "no" in j:
            score+=50
            report["ssh"].update({"ssh_score":"50"})
            print(i + " : +" + str(score))
  
    #Firewall score
    for k,l in report["firewall"].items():
        if "firewall_score" in k:
            print(report["firewall"]["tool_detected"] + " : +" + str(l))
            score+=l 
            break
  
    #Total Score
    print("Total Score = " + str(score))
