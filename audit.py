import argparse
import checks.ssh_check as sshp 
import checks.firewall_check as frwlp
import checks.ports_check as prts 
import checks.suid_check as suif
import checks.permissions_check as prmf 
import checks.services_check as srvcs 
import reports.reporter as rprt
import utils.scoring as scor


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


def scoring(report_f):
    out_report=scor.read_report(report_f)
    score=scor.make_score(out_report)
    print(f"\n{'='*40}")
    print(f"  Security Score : {str(score)} / 100")
    print(f"{'='*40}\n")


def run_all_check():
    """Run all available security checks and return the audit results"""
    
    audit={"ssh":{},
           "firewall":{},
           "ports":{},
           "suid":{},
           "permissions":{},
           "services":{}
            }

    print("[*] Starting security audit...\n")
    print("[*] Running SSH check...")
    print(f"\n{'/'*40}")
    audit["ssh"]=run_ssh_check()
    print(f"\n{'\\'*40}")
    print("[*] SSH check Done.")
    print("[*] Running Firewall check...")
    audit["firewall"]=run_firewall_check()
    print("[*] Firewall check Done.")
    print("[*] Running Ports check...")
    audit["ports"]=run_ports_check()
    print("[*] Ports check Done.")
    print("[*] Running SUID Files check...")
    audit["suid"]=run_suid_check()
    print("[*] SUID Files check Done.")
    print("[*] Running Permissions Files check...")
    audit["permissions"]=run_permissions_check()
    print("[*] Permission Files check Done.")
    print("[*] Running Services check...")
    audit["services"]=run_services_check()
    print("[*] Services check Done.")
    
    return audit

def run_single_check(check):
    """Run ssh security check and return the audit result"""
    
    checks={"ssh": run_ssh_check,
            "firewall": run_firewall_check,
            "ports": run_ports_check,
            "suid": run_suid_check,
            "permissions": run_permissions_check,
            "services": run_services_check
            }

    if check not in checks:
        print(f"[-] The selected check '{check}' is not covered.")
        print(f"[*] Here is the check list available {", ".join(checks.keys())}.")
        exit(1)
    
    return {check:checks[check]()}



def main():
    parser= argparse.ArgumentParser(description = 'Linux Audit Security Tool',
           usage="sudo python3 ./audit.py --scan [all] or [ssh] [firewall] --output report.json")

    parser.add_argument("--scan",
                        help="To scan all ports: [all]. To scan a valid network port number [port].")

    parser.add_argument("--output", 
                                help="Output filename.json to create a report.")
    args = parser.parse_args()

    if args.scan=="all" and args.output :
        audit=run_all_check()
    else:
        audit=run_single_check(args.scan)

    report(args.output, audit)
    scoring(args.output)

if __name__ == "__main__":
    main()

