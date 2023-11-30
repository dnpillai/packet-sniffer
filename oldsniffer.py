#For a reminder on all Scapy commands use print(sniff.__doc__)

# Importing necessary modules for the program
import logging
from datetime import datetime
import subprocess
import sys

# Suppressing messages with lower seriousness than error messages while running or loading Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

# Checking if Scapy is installed, and importing it if available; exiting if not installed
try:
    from scapy.all import *
except ImportError:
    print("Scapy package for Python is not installed on your system.")
    sys.exit()

# Prompting the user with a message; recommending the use of "sudo scapy" in Linux
print("\n! Run this program as ROOT, or it will not function properly!\n")

# Asking the user for input parameters: interface, number of packets, time interval, and protocol

# Asking the user to enter the network interface for the sniffer
net_iface = input("* Enter the interface on which to run the sniffer (e.g. 'enp0s8'): ")

# Setting the network interface in promiscuous mode
# This allows it to pass all traffic it recieves to it's CPU rather than just what is programmed to recieve.
try:
    subprocess.call(["ifconfig", net_iface, "promisc"], stdout=None, stderr=None, shell=False)
except:
    print("\nFailed to configure interface as promiscuous.\n")
else:
    print("\nInterface %s was set to PROMISC mode.\n" % net_iface)

# Asking the user for the number of packets to sniff (the "count" parameter)
pkt_to_sniff = input("* Enter the number of packets to capture (0 is infinity): ")

# Considering the case when the user enters 0 (infinity)
if int(pkt_to_sniff) != 0:
    print("\nThe program will capture %d packets.\n" % int(pkt_to_sniff))
elif int(pkt_to_sniff) == 0:
    print("\nThe program will capture packets until the timeout expires.\n")

# Asking the user for the time interval to sniff (the "timeout" parameter)
time_to_sniff = input("* Enter the number of seconds to run the capture: ")

# Handling the value entered by the user
if int(time_to_sniff) != 0:
    print("\nThe program will capture packets for %d seconds.\n" % int(time_to_sniff))

# Asking the user for any protocol filter to apply to the sniffing process
# For this example, three protocols are chosen: ARP, BOOTP, ICMP
# You can customize this to add your own desired protocols
proto_sniff = input("* Enter the protocol to filter by (arp|bootp|icmp|0 is all): ")

# Considering the case when the user enters 0 (meaning all protocols)
if (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
    print("\nThe program will capture only %s packets.\n" % proto_sniff.upper())
elif (proto_sniff) == "0":
    print("\nThe program will capture all protocols.\n")

# Asking the user to enter the name and path of the log file to be created
file_name = input("* Please give a name to the log file: ")

# Creating the text file (if it doesn't exist) for packet logging and/or opening it for appending
sniffer_log = open(file_name, "a")

# This function is called for each captured packet
# It extracts parameters from the packet and logs each packet to the log file
def packet_log(packet):
    # Getting the current timestamp
    now = datetime.now()

    # Writing the packet information to the log file, also considering the protocol or 0 for all protocols
    if proto_sniff == "0":
        # Writing the data to the log file
        print("Time: " + str(now) + " Protocol: ALL" + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file=sniffer_log)
    elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
        # Writing the data to the log file
        print("Time: " + str(now) + " Protocol: " + proto_sniff.upper() + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file=sniffer_log)

# Printing an informational message to the screen
print("\n* Starting the capture...")

# Running the sniffing process (with or without a filter)
if proto_sniff == "0":
    sniff(iface=net_iface, count=int(pkt_to_sniff), timeout=int(time_to_sniff), prn=packet_log)

elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
    sniff(iface=net_iface, filter=proto_sniff, count=int(pkt_to_sniff), timeout=int(time_to_sniff), prn=packet_log)

else:
    print("\nNot able identify the protocol.\n")
    sys.exit()

# Printing the closing message
print("\n* Captured packets have been exported to the %s file, please check it to view.\n" % file_name)

# Closing the log file
sniffer_log.close()
