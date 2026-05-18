import json
import sys
import subprocess
import os


def make_report(ssh_data):
    if ssh_data:
        r_result={"ssh":ssh_data , "firewall":{} } 
    return r_result


def save_report(filename, r_result):
    try:
        print("[+] Save the report " + filename + " in the reports directory.")
        with open(os.path.join("/home/gclaude/linux_security_audit/reports/",filename), "w", encoding="utf-8") as f:
            json.dump(r_result, f, ensure_ascii=False, indent=4)

    except OSerror:
        print("Could not create the report file.")
        sys.exit()

