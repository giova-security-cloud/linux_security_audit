import argparse
import checks.ssh_check as sshp 
import checks.firewall_check as frwlp
import checks.ports_check as prts 
import checks.suid_check as suif
import checks.permissions_check as prmf 
import reports.reporter as rprt
import utils.scoring as scor

def validate_ports(value):
    try:
        if value == 'all':
            
            return value
        
        port= int(value)
        if 1 <= port <= 65535:
            
            return port
        
        raise ValueError
    
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid port: {value}")


def run_ssh_check():
   #search ssh parameters
   ssh_c="sshd_config"
   search=str(sshp.ssh_file_search(ssh_c))
   ssh_state=sshp.ssh_audit(search)
   
   return ssh_state


def run_firewall_check():
   #search firewall parameters
   firewall_state=frwlp.firewall_audit()
   
   return firewall_state


def run_ports_check(ports):
    if "all" in ports:
        #search risky ports
        ports_state= prts.ports_audit()
        
        return ports_state

def run_suid_check():
    suid_state=suif.suid_audit()

    return suid_state

def run_permissions_check():
    permissions_state=prmf.permissions_audit()

    return permissions_state

def report(r_name, audit_data):
    rprt.save_report(r_name, audit_data)


def scoring(report_f):
    out_report=scor.read_report(report_f)
    score=scor.make_score(out_report)
    print(f"\n{'='*40}")
    print(f"  Security Score : {str(score)} / 100")
    print(f"{'='*40}\n")


if __name__ == "__main__":

    parser= argparse.ArgumentParser(description = 'Linux Audit Security Tool',
           usage="python3 ./audit.py --scan [all] or [port] --output report.json")

    parser.add_argument("--scan", type=validate_ports,
                        help="To scan all ports: [all]. To scan a valid network port number [port].")

    parser.add_argument("--output", 
                                help="Output filename.json to create a report.")
    args = parser.parse_args()
   
    audit={"ssh":{},
           "firewall":{},
           "ports":{},
           "suid":{}
            }
    
    
    if args.scan=="all" and args.output :
        audit["ssh"]=run_ssh_check()
        audit["firewall"]=run_firewall_check()
        audit["ports"]=run_ports_check(args.scan)
        audit["suid"]=run_suid_check()
        audit["permissions"]=run_permissions_check()
        report(args.output, audit)
        scoring(args.output)

