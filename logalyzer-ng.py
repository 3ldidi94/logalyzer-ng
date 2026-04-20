#!/usr/bin/python3

import datetime
from lib.ParseLogs import ParseLogs
from  lib.WhoisIP import resolver
import os
from optparse import OptionParser
import sys

def load_env(path):
    if not os.path.isfile(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            os.environ.setdefault(key.strip(), value.strip())

# callback for the user flag
def user_call(option, opt_str, value, parser):
    if len(parser.rargs) != 0:
        value = parser.rargs[0]
    else:
        value = None
    setattr(parser.values, option.dest, value)

# entry
if __name__=="__main__":
    load_env(os.path.join(os.path.dirname(__file__), '.env'))
    known_ip = [ip for ip in os.environ.get('KNOWN_IPS', '').split(',') if ip]
    printed_ip = []
    printed_known_ip = []
 
    # parsing options
    parser = OptionParser(epilog=
                    "Combine flags to view user-specific information.  \'-u test -i\' lists IP addresses "
                    "associated with user test")
    parser.add_option("-u", help="Specify user.  Blank lists all users.", action="callback", 
                    callback=user_call, default=None, dest="user")
    parser.add_option("--full", help="Full log dump for specified user", action="store_true", 
                                default=False, dest="fullu") 
    parser.add_option("-l", help="Specify log file.  Default is auth.log", default="/var/log/auth.log", dest="log")
    parser.add_option("-f", help="List failures", action="store_true", default=False, dest="fail")
    parser.add_option("-s", help="List success logs", action="store_true", default=False, dest="success")
    parser.add_option("-c", help="List commands by user", action="store_true", default=False, dest="commands")
    parser.add_option("-i", help="List IP Addresses", action="store_true", default=False, dest="ip")
    parser.add_option("-v", help="Show launch info (timestamp, log file)", action="store_true", default=False, dest="verbose")

    # get arguments
    (options, args) = parser.parse_args()

    if options.verbose:
        print('[*] Launched:', datetime.datetime.now().strftime('%Y-%m-%d at %Hh%Mm%Ss'))
        print(f'[*] Log file: {options.log}')
        if os.path.isfile(options.log):
            stat = os.stat(options.log)
            size_kb = stat.st_size / 1024
            try:
                with open(options.log, 'r') as lf:
                    first_line = lf.readline().strip()
                print(f'[*] Last rotation: {first_line[:19]}')
            except Exception:
                pass
            print(f'[*] Log size: {size_kb:.1f} KB')

    # if they're trying to access /var/log/auth.log without proper privs, exit!
    if os.getuid() != 0 and options.log is None:
        print(f"[-] Please run with SUDO privs! Or at least with a user allowed to read {options.log}")
        sys.exit(1)

    # check if they specified another file
    if options.log is not None:
        log = options.log

    # parse logs
    LOGS = ParseLogs(log)
    if LOGS is None:
        print(f"[-] No logs to parse in the {options.log} logfile!")
        sys.exit(1)

    # validate the user, fallback to rotated log if not found
    if options.user:
        if not options.user in LOGS:
            rotated_log = log + '.1'
            if os.path.isfile(rotated_log):
                print(f"[!] User '{options.user}' not found in {log}, trying {rotated_log}...")
                LOGS = ParseLogs(rotated_log)
                if LOGS is None or options.user not in LOGS:
                    print(f"[-] User '{options.user}' is not present in {log} nor {rotated_log}.")
                    sys.exit(1)
                log = rotated_log
            else:
                print(f"[-] User '{options.user}' is not present in the logs.")
                sys.exit(1)

    # output all commands
    if options.commands and not options.user:
        for user in LOGS:
            for comms in LOGS[user].commands:
                print(f"{user}:\t{comms}")

    # output all failures
    elif options.fail and not options.user:
        for user in LOGS:
            for fail in LOGS[user].fail_logs:
                print(f"{user}:\t{fail}")

    # output all logged IP addresses
    elif options.ip and not options.user:
        for user in LOGS:
            for ip in LOGS[user].ips:
                if ip and user is not None:
                    print(f"{user}:\t{ip}")

    # output user-specific commands
    if options.commands and options.user:
        if not LOGS[options.user].commands:
            print(f"[-] No command found for user '{options.user}'")
        else:
            print(f"[+] Commands for user '{options.user}':")
            for command in LOGS[options.user].commands:
                print(f"\t {command}")

    # output user-specific success logs
    elif options.success and options.user:
        if not LOGS[options.user].succ_logs:
            print(f"[-] No success logs for user '{options.user}'")
        else:
            print(f"[+] Successes logs for user '{options.user}':")
            for log in LOGS[options.user].succ_logs:
                print("\t",log)

    # output user-specific failures with associated ip
    elif options.fail and options.ip and options.user :
        if LOGS[options.user].fail_logs:
            print(f"[+] Failed IPs for user '{options.user}':")
            for log in LOGS[options.user].fail_logs:
                for ip in LOGS[options.user].ips:
                    if ip is None:
                        continue
                    if ip in log and ip in known_ip:
                        printed_known_ip.append(ip)
                    elif ip in log and ip not in known_ip:
                        printed_ip.append(ip)

            for ip in set(printed_known_ip):
                print(f"\t{ip} (Known IP!)")
            for ip in set(printed_ip):
                print(f"\t{ip}")
        else:
            print(f"[-] No failed IP for user '{options.user}'")

        # Whois on bad ip...
        if printed_ip:
            print(f"[*] Whois on unknown IPs that FAILED for user '{options.user}'")
            resolver(list(set(printed_ip)))

    # output user-specific failures
    elif options.fail and options.user:
        for fail in LOGS[options.user].fail_logs:
            if fail:
                print(f"[+] Failures for user '{options.user}'")
                print(f"\t{fail}")
        else:
            print(f"[-] No failure for user '{options.user}'")

    # output user-specific ip addresses
    elif options.ip and options.user:
        if LOGS[options.user].ips:
            print(f"[+] Logged IPs for user '{options.user}':")
            for ip in LOGS[options.user].ips:
                if ip is None:
                    continue
                if ip in known_ip:
                    printed_known_ip.append(ip)
                else:
                    printed_ip.append(ip)

            for ip in set(printed_known_ip):
                print(f"\t{ip} (Known IP!)")
            for ip in set(printed_ip):
                print(f"\t{ip}")
        else:
            print(f"[-] No logged IPs for user '{options.user}'")

        # Whois on unknown IPs...
        if printed_ip:
            print(f"[*] Whois on unknown IPs for user '{options.user}'")
            resolver(list(set(printed_ip)))

    # print out all information regarding specified user
    elif options.user is not None:
        print(f"[*] Logs associated with user '{options.user}'")
        print(f"[*] First log: {LOGS[options.user].first_date()}")
        print(f"[*] Last log: {LOGS[options.user].last_date()}")
        print("[*] Failure Logs")
        for fail in LOGS[options.user].fail_logs:
            print("\t", fail)
        print("[*] Success Logs")
        for succ in LOGS[options.user].succ_logs:
            print("\t", succ)
        print("[*] Associated IPs")
        for ip in LOGS[options.user].ips:
            if ip is not None:
                print("\t", ip)
        print("[*] Commands")
        for comm in LOGS[options.user].commands:
            print("\t", comm)

    # dump the full log for the user if specified
    if options.fullu and options.user:
        print("[*] Full Log")
        for log in LOGS[options.user].logs:
            print(log)

    # if they supplied us with an empty user, dump all of the logged users
    elif options.user is None and not options.verbose:
        if len(LOGS) > 0:
            print ("[+] Users attempted by attackers")
            for user in LOGS:
                if user is not None:
                    print("\t",user)