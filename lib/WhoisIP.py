#!/usr/bin/env python3

import argparse
import os
from ipwhois import IPWhois
from warnings import filterwarnings
from sys import exit
from socket import gethostbyname, gaierror

filterwarnings(action="ignore")

known_ip = [ip for ip in os.environ.get('KNOWN_IPS', '').split(',') if ip]
known_domains = [d for d in os.environ.get('KNOWN_DOMAINS', '').split(',') if d]

def domain_resolver():
    for domain in known_domains:
        try:
            ip = gethostbyname(domain)
        except gaierror:
            print(f"\t[!] DNS resolution failed for domain: {domain}")
            continue

        if not all(int(item) in range(0, 256) for item in ip.split('.')):
            continue

        if ip not in known_ip:
            known_ip.append(ip)

def is_ip(value):
    parts = value.split('.')
    if len(parts) != 4:
        return False
    return all(item.isdigit() and int(item) in range(0, 256) for item in parts)

def resolve_to_ip(value):
    if is_ip(value):
        return value
    try:
        return gethostbyname(value)
    except gaierror:
        print(f"\t[!] DNS resolution failed for: {value}")
        return None

def resolver(ips):
    domain_resolver()
    if isinstance(ips, str):
        ips = list(ips.split(" "))
    if isinstance(ips, list):
        ips = [resolve_to_ip(entry) for entry in ips]
        ips = [ip for ip in ips if ip]
        for ip in ips:
            if ip not in known_ip:
                try:
                    res = IPWhois(ip).lookup_whois()
                except Exception as e:
                    print(f"\t[!] Whois lookup failed for {ip}: {e}")
                    continue

                nets = res.get("nets")
                if not nets:
                    print(f"\t[!] No whois data found for {ip}")
                    continue

                net = nets[0]
                print(f"\t{ip}:")
                print("\t"+"-"*len(ip)+"-")

                if net.get('country'):
                    print("\tCOUNTRY: " + net['country'])
                if net.get('description'):
                    print("\tDESCRIPTION: " + net['description'])
                if net.get('address'):
                    parts = net['address'].split("\n")
                    address_line = parts[0] + (" - " + parts[1] if len(parts) > 1 else "")
                    print("\tADDRESS: " + address_line)
                if net.get('cidr'):
                    print("\tCIDR: " + net['cidr'])

                emails = net.get('emails')
                if emails:
                    print("\tEMAILS:", end=' ')
                    for mail in emails:
                        print(mail + " |", end=' ')
                    print("\n")

                print("\t"+"-"*len(ip)+"-")
                        #print "EMAILS: "+"\n".join(str(mail) for mail in emails)
                #else:
                #    print("\tEMAILS: "+str(res["nets"][0]['emails'])+"\n")
            else:
                print(f"        IP address {ip} already known!")
    else:
        raise TypeError("Provided IPs to resolve are not in list or string format")

if __name__=="__main__":
    argparser = argparse.ArgumentParser(description="This program resolve a list or a single IP address to retreive information about the owner. Default resolve a list of random IPs.")
    argparser.add_argument("-i", "--ip", help="Resolve the specified IP.")
    argparser.add_argument("-f", "--file", help="Resolve all the IPs in the specified file.")
    args = argparser.parse_args()
    
    if args.ip:
        resolver(args.ip)

    if args.file:
        liste = []
        with open(args.file, "r") as file:
            for line in file:
                ip = line.strip()
                if ip:
                    liste.append(ip)
        resolver(liste)

    if not args.ip and not args.file:
        ## RANDOM IP FOR TESTING PURPOSE
        random_ip = ["1.1.1.1","8.8.8.8","9.9.9.9","208.67.222.222","94.140.14.14"]
        resolver(random_ip)
