#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    
    parser.add_option("-t", "--target", dest = "ip", help="Target IP Address or IP Address Range that is to be scanned")

    (options, arguments) = parser.parse_args()

    if not options.ip:
        parser.error("[-] Please specify a target IP Address or a range of IP Address, use --help for more info")

    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered = scapy.srp(arp_request_broadcast, verbose=False, timeout = 1)[0]

    clients_list = []
    for element in answered:
        client_dic = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dic)

        return clients_list


def display_clients(clients_list):
    if clients_list is None:
        print("No devices detected on network")
    else:
        for client in clients_list:
            print("IP Address\t\tMAC Address\n___________________________________________")
            print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_results = scan(options.ip)
display_clients(scan_results)
