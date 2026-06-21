import sys
import getopt
import socket
import os
import json
from utils.logger import logger

def read_report(filename):
    logger.info(f"Reading the report : {filename}")
    try: 
        with open(os.path.join("/home/gclaude/linux_security_audit/reports/", str(filename)), "r", encoding="utf-8") as json_f:
            report=json.load(json_f)
            return report

    except OSerror:
        logger.error("Could not open the report file.")
        sys.exit()


def make_score(report:dict) -> int:
    """
    Compute the global security score based on all check impacts.
    Starts at 100, applies each check's audit_score, floored at 0.
    """
    score=100
    
    for check in report.values():    
        score += check.get("audit_score", 0) 
    return max(0, score)  # max global at 0


