#!/usr/bin/env python

import subprocess
import optparse
import re

def get_arguments():

    parser = optparse.OptionParser()

    #This will add new options that we want to take from the user in the command line
    #- & -- will be used as an indicator for the argument
    # "dest" will tell where the value will be stored
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC Address of the Interface") 
    
    #It will tell the child that to parse the arguments in the command line
    #It allows the object to understand what the user has entered and handled
    (options, arguments) = parser.parse_args()

    if not options.interface:
        #code to handle error related to invalid entry of interface name
        parser.error("[-] Please specify an interface, use --help for more info")
    elif not options.new_mac:
        #code to handle error related to invalid entry of MAC Address
        parser.error("[-] Please specify an MAC Address, use --help for more info")
    
    return options

def change_mac(interface, new_mac):
    
    print("[+] Changing MAC Address for " + interface + " to " + new_mac)

    #The reason to call the method in this way to avoid injection in our code
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

def get_current_mac(interface):

    ifconfig_result = subprocess.check_output(["ifconfig", options.interface]).decode("utf-8")
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)

    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("[-] Could not read MAC Adress")


#"arguements" contains the name of the argument like -i, --interface, etc.
#"options" on the other hand contains the value of the arguement
options = get_arguments()

#calling the get_current_mac method to get the current MAC
current_mac = get_current_mac(options.interface)
print("Current MAC: " + str(current_mac))

change_mac(options.interface, options.new_mac)

#calling the get_current_mac method to get the latest MAC(After changing the MAC Address)
#This will be used to check if the new MAC is same as the MAC specified by the user
current_mac = get_current_mac(options.interface)

#checking if the MAC is changed or not
if current_mac == options.new_mac:
    print("[+] MAC Adress was successfully changed to " + current_mac)
else:
    print("[-] MAC Adress did not get changed.")






