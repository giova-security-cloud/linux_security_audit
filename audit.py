import argparse
import checks.ssh_check as sshp 
import checks.firewall_check as frwlp
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

def report(r_name, ssh_audit, firewall_audit):
    r_result=rprt.make_report(ssh_audit, firewall_audit)
    rprt.save_report(r_name, r_result)


def scoring(report_f):
    score=scor.read_report(report_f)
    scor.make_score(score)

if __name__ == "__main__":

    parser= argparse.ArgumentParser(description = 'Linux Audit Security Tool',
           usage="python3 ./audit.py --scan [all] or [port] --output report.json")

    parser.add_argument("--scan", type=validate_ports,
                        help="To scan all ports: [all]. To scan a valid network port number [port].")

    parser.add_argument("--output", 
                                help="Output filename.json to create a report.")
    args = parser.parse_args()
    
    if args.scan=="all" and args.output :
        ssh_audit=run_ssh_check()
        firewall_audit=run_firewall_check()
        report(args.output, ssh_audit, firewall_audit)
        scoring(args.output)

