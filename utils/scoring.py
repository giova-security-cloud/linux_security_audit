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
    for i,j in report["ssh"].items():
        if "no" in j:
            score=score+50
            print(i + " +50")
   
    print("SCORE = 0")
