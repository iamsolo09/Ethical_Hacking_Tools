#!/usr/bin/env python

import scapy.all as scapy
import optparse

#Will get the arguments from the user 
def get_arguments():
    parser = optparse.OptionParser()
    
    parser.add_option("-t", "--target", dest = "ip", help="Target IP Address or IP Address Range that is to be scanned")

    (options, arguments) = parser.parse_args()

    if not options.ip:
        parser.error("[-] Please specify a target IP Address or a range of IP Address, use --help for more info")

    return options

#Will scan the IP Address
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)#Packet for ARP Request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")#Packet for broadcast
    arp_request_broadcast = broadcast/arp_request#Make a new packet by combining the packets of Broadcast and ARP Request

    #Timeout specified = 1s. This is to avoid waiting for a reponse a very long interval after scanning an IP Address
    answered = scapy.srp(arp_request_broadcast, verbose=False, timeout = 1)[0]

    #Declaring a list to keep a dictionary of the client's information
    clients_list = []
    for element in answered:
        #Each element of answered is a list of couple(packet sent, answer). Since I am only interested in the answer, I wrote element[1]
        client_dic = {"ip": element[1].psrc, "mac": element[1].hwsrc}#psrc is the IP Address of the discovered client and hwsrc is the MAC Address of the discovered client
        clients_list.append(client_dic)#Appending the dictionary client_dic to the list clients_list

        return clients_list


def display_clients(clients_list):
    #if clients_list is null, python wont be able to iterate through clients_list. Hence if it is null, no need to iterate. Rather display a message that no device is found.
    if clients_list is None:
        print("[-] No devices detected on network")
    else:
        for client in clients_list:
            print("IP Address\t\tMAC Address\n___________________________________________")
            print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()#get argument from the user
scan_results = scan(options.ip)#scan the network for the provided IP Address or range of IP Address
display_clients(scan_results)#Display the clients
