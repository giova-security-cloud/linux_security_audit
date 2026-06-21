# audit.py
import argparse
import logging
import checks.ssh_check as sshp 
import checks.firewall_check as frwlp
import checks.ports_check as prts 
import checks.suid_check as suif
import checks.permissions_check as prmf 
import checks.services_check as srvcs 
import reports.reporter as rprt
import utils.scoring as scor
import utils.recommendations as reco
from   utils.logger import logger

def run_ssh_check():
   #search ssh parameters
   search=str(sshp.ssh_file_search())
   ssh_state=sshp.ssh_audit(search)
   return ssh_state


def run_firewall_check():
   #search firewall parameters
   firewall_state=frwlp.firewall_audit()
   
   return firewall_state

def run_ports_check():
    #search risky ports
    ports_state= prts.ports_audit()
    
    return ports_state

def run_suid_check():
    suid_state=suif.suid_audit()

    return suid_state

def run_permissions_check():
    permissions_state=prmf.permissions_audit()

    return permissions_state

def run_services_check():
    services_state=srvcs.services_audit()

    return services_state

def report(r_name, audit_data):
    rprt.save_report(r_name, audit_data)

def run_hardening_check(audit):
    for key, settings in audit.items():

        recommendations={"ssh":reco.get_ssh_recommendations,
                         "firewall":reco.get_firewall_recommendations,
                         "ports":reco.get_ports_recommendations,
                         "suid":reco.get_suid_recommendations,
                         "permissions":reco.get_permissions_recommendations,
                         "services":reco.get_services_recommendations
                        }

        if key not in recommendations:
            continue
        

        audit[key]=recommendations[key](settings)
    
    return audit 

def scoring(report_f):
    out_report=scor.read_report(report_f)
    score=scor.make_score(out_report)
    logger.info(f"{'='*40}")
    logger.info(f"  Security Score : {str(score)} / 100")
    logger.info(f"{'='*40}\n")


def run_all_check():
    """Run all available security checks and return the audit results"""
    
    audit={"ssh":{},
           "firewall":{},
           "ports":{},
           "suid":{},
           "permissions":{},
           "services":{}
          }

    logger.info("[*] Starting security audit...\n")
    logger.info("[*] Running SSH check...")
    audit["ssh"]=run_ssh_check()
    logger.info("[*] SSH check Done.")
    logger.info("[*] Running Firewall check...")
    audit["firewall"]=run_firewall_check()
    logger.info("[*] Firewall check Done.")
    logger.info("[*] Running Ports check...")
    audit["ports"]=run_ports_check()
    logger.info("[*] Ports check Done.")
    logger.info("[*] Running SUID Files check...")
    audit["suid"]=run_suid_check()
    logger.info("[*] SUID Files check Done.")
    logger.info("[*] Running Permissions Files check...")
    audit["permissions"]=run_permissions_check()
    logger.info("[*] Permission Files check Done.")
    logger.info("[*] Running Services check...")
    audit["services"]=run_services_check()
    logger.info("[*] Services check Done.")
    
    return audit

def run_single_check(check):
    """Run ssh security check and return the audit result"""
    
    logger.info(f"Running {check} check ...")
    
    checks={"ssh": run_ssh_check,
            "firewall": run_firewall_check,
            "ports": run_ports_check,
            "suid": run_suid_check,
            "permissions": run_permissions_check,
            "services": run_services_check
            }

    if check not in checks:
        logger.error(f"[-] The selected check '{check}' is not covered.")
        logger.error(f"[*] Here is the checks list available {", ".join(checks.keys())}.")
        exit(1)
    
    logger.info(f"{check} score : {checks[check]().get("audit_score")}")
    logger.info(f"{check} check Done.")
    return {check:checks[check]()}


def main():
    parser= argparse.ArgumentParser(description = 'Linux Audit Security Tool',
            formatter_class=argparse.RawTextHelpFormatter,
            epilog=(
            "Examples:\n"
            "  python3 audit.py --scan all --output report.json\n"
            "  python3 audit.py --scan ssh --output ssh_report.json\n"
            "  python3 audit.py --scan ports\n"
            "  python3 audit.py --scan firewall --hardening-check\n"))

    parser.add_argument("-s", "--scan",
                        required=True,
                        metavar="CHECK",
                        help=("Check to Run. Options=\n"
                              "all : Run a full audit\n"
                              "ssh : SSH configuration\n"
                              "firewall : Firewall status\n"
                              "ports : Open ports\n"
                              "suid : SUID files\n"
                              "permissions : Risky permissions\n"
                              "services : active services"))

    parser.add_argument("-o", "--output",
                        metavar="FILE",
                        default="report.json",
                        help="Output filename.json to create a report.")
    
    parser.add_argument('--hardening-check',
                        action='store_true',
                        help="Recommendations for remediation.")

    args = parser.parse_args()

    if args.scan=="all" and args.output :
        audit=run_all_check()
    else:
        audit=run_single_check(args.scan)

    if args.hardening_check:
        hardening=run_hardening_check(audit)
        report(args.output, hardening)
    else: 
        report(args.output, audit)
    
    scoring(args.output)

if __name__ == "__main__":
    main()

