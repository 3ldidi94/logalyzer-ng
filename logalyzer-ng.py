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
    parser.add_option("-a", help="List all usernames attempted by attackers", action="store_true", default=False, dest="attackers")
    parser.add_option("-b", help="List brute-force attempts", action="store_true", default=False, dest="bruteforce")
    parser.add_option("--sudo-fail", help="List failed sudo attempts (NOT in sudoers)", action="store_true", default=False, dest="sudo_fail")
    parser.add_option("--su-fail", help="List failed su attempts", action="store_true", default=False, dest="su_fail")
    parser.add_option("--accounts", help="List account creation/modification/deletion events", action="store_true", default=False, dest="accounts")

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

    log = options.log

    # check read permissions before parsing
    if not os.access(log, os.R_OK):
        if os.getuid() != 0:
            print(f"[-] Permission denied: cannot read {log} — try running with sudo.")
        else:
            print(f"[-] Cannot read {log}: file not found or permission denied.")
        sys.exit(1)

    # parse logs
    LOGS = ParseLogs(log)
    if LOGS is None:
        print(f"[-] No logs to parse in {log}.")
        sys.exit(1)

    # validate the user, fallback to rotated logs if not found
    if options.user:
        if not options.user in LOGS:
            candidates = [log + '.1', log + '.1.gz', log + '.2.gz']
            rotated_log = next((c for c in candidates if os.path.isfile(c)), None)
            if rotated_log:
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
            if user is None:
                continue
            for comms in LOGS[user].commands:
                print(f"{user}:\t{comms}")

    # output all failures
    elif options.fail and not options.user:
        for user in LOGS:
            if user is None:
                continue
            for fail in LOGS[user].fail_logs:
                print(f"{user}:\t{fail}")

    # output all logged IP addresses (unique, sorted)
    elif options.ip and not options.user:
        all_ips = set()
        for user in LOGS:
            for ip in LOGS[user].ips:
                if ip:
                    all_ips.add(ip)
        if not all_ips:
            print("[-] No IP addresses found in logs")
        else:
            for ip in sorted(all_ips):
                print(ip)

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
        if not LOGS[options.user].fail_logs:
            print(f"[-] No failure for user '{options.user}'")
        else:
            print(f"[+] Failures for user '{options.user}':")
            for fail in LOGS[options.user].fail_logs:
                if fail:
                    print(f"\t{fail}")

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
        if LOGS[options.user].fail_logs:
            print("[*] Failure Logs")
            for fail in LOGS[options.user].fail_logs:
                print("\t", fail)
        if LOGS[options.user].succ_logs:
            print("[*] Success Logs")
            for succ in LOGS[options.user].succ_logs:
                print("\t", succ)
        if LOGS[options.user].ips:
            print("[*] Associated IPs")
            for ip in LOGS[options.user].ips:
                if ip is not None:
                    print("\t", ip)
        if LOGS[options.user].commands:
            print("[*] Commands")
            for comm in LOGS[options.user].commands:
                print("\t", comm)

    # brute-force attempts
    if options.bruteforce:
        found = False
        for user in LOGS:
            if user and LOGS[user].bruteforce_logs:
                found = True
                print(f"[+] Brute-force detected for '{user}':")
                for entry in LOGS[user].bruteforce_logs:
                    print(f"\t{entry}")
        if not found:
            print("[-] No brute-force attempts found")

    # failed sudo attempts
    if options.sudo_fail:
        found = False
        for user in LOGS:
            if user and LOGS[user].sudo_fail_logs:
                found = True
                print(f"[!] NOT in sudoers — '{user}':")
                for entry in LOGS[user].sudo_fail_logs:
                    print(f"\t{entry}")
        if not found:
            print("[-] No failed sudo attempts found")

    # failed su attempts
    if options.su_fail:
        found = False
        for user in LOGS:
            if user and LOGS[user].su_fail_logs:
                found = True
                print(f"[!] Failed su — by '{user}':")
                for entry in LOGS[user].su_fail_logs:
                    print(f"\t{entry}")
        if not found:
            print("[-] No failed su attempts found")

    # account creation / modification / deletion
    if options.accounts:
        if "_system" in LOGS and LOGS["_system"].account_events:
            print("[+] Account events:")
            for entry in LOGS["_system"].account_events:
                print(f"\t{entry}")
        else:
            print("[-] No account events found")

    # dump the full log for the user if specified
    if options.fullu and options.user:
        print("[*] Full Log")
        for log in LOGS[options.user].logs:
            print(log)

    # if they supplied us with an empty user, dump all of the logged users
    elif options.attackers:
        if len(LOGS) > 0:
            print("[+] Users attempted by attackers")
            for user in LOGS:
                if user is not None:
                    print("\t", user)