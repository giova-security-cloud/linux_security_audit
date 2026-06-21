import json
import sys
import subprocess
import os
from utils.logger import logger

def save_report(filename, r_result):
    try:
        logger.info(f"Save the report {filename} in the reports directory.")
        with open(os.path.join("/home/gclaude/linux_security_audit/reports/", str(filename)), "w", encoding="utf-8") as f:
            json.dump(r_result, f, ensure_ascii=False, indent=4)

    except OSerror:
        logger.error("Could not create the report file.")
        sys.exit()

