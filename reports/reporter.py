import json
import sys
import subprocess
import os

def save_report(filename, r_result):
    try:
        print(f"[+] Save the report {filename} in the reports directory.")
        with open(os.path.join("/home/gclaude/linux_security_audit/reports/", str(filename)), "w", encoding="utf-8") as f:
            json.dump(r_result, f, ensure_ascii=False, indent=4)

    except OSerror:
        print("Could not create the report file.")
        sys.exit()

