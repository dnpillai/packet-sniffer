import logging
from datetime import datetime
import subprocess
import sys
from scapy.all import *

# Suppressing unnecessary Scapy logging messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

def set_promiscuous_mode(interface):
    try:
        # Setting the network interface in promiscuous mode
        subprocess.call(["ifconfig", interface, "promisc"], stdout=None, stderr=None, shell=False)
        print(f"\nInterface {interface} was set to PROMISC mode.\n")
    except Exception as e:
        # Handling exceptions if setting promiscuous mode fails
        print(f"\nFailed to configure interface as promiscuous. Error: {e}\n")

def capture_packets(interface, count, timeout, protocol, file_name):
    # Opening the log file for packet logging
    sniffer_log = open(file_name, "a")

    def packet_log(packet):
        # Function to log packet information to the file
        now = datetime.now()
        protocol_name = protocol.upper() if protocol != "0" else "ALL"
        print(f"Time: {now} Protocol: {protocol_name} SMAC: {packet[0].src} DMAC: {packet[0].dst}", file=sniffer_log)

    print("\n* Starting the capture...")

    try:
        # Running the sniffing process based on user input
        if protocol == "0":
            sniff(iface=interface, count=int(count), timeout=int(timeout), prn=packet_log)
        elif protocol in ["arp", "bootp", "icmp"]:
            sniff(iface=interface, filter=protocol, count=int(count), timeout=int(timeout), prn=packet_log)
        else:
            # Handling the case when the user enters an invalid protocol
            print("\nCould not identify the protocol.\n")
    except Exception as e:
        # Handling exceptions during packet capture
        print(f"\nAn error occurred during packet capture. Error: {e}\n")
    finally:
        # Closing the log file and providing information to the user
        print(f"\n* Please check the {file_name} file to see the captured packets.\n")
        sniffer_log.close()

if __name__ == "__main__":
    # Main program execution

    print("\n! Make sure to run this program as ROOT !\n")

    # Asking the user for input parameters
    net_iface = input("* Enter the interface on which to run the sniffer (e.g. 'enp0s8'): ")
    set_promiscuous_mode(net_iface)

    # Asking the user for number of packets to capture
    pkt_to_sniff = input("* Enter the number of packets to capture (0 is infinity): ")
    print(f"\nThe program will capture {pkt_to_sniff} packets.\n" if pkt_to_sniff != "0" else "\nThe program will capture packets until the timeout expires.\n")

    # Asking the user for the duration of the packet sniffing
    time_to_sniff = input("* Enter the number of seconds to run the capture: ")
    print(f"\nThe program will capture packets for {time_to_sniff} seconds.\n" if time_to_sniff != "0" else "")

    # Asking the user for protocol based filtering
    proto_sniff = input("* Enter the protocol to filter by (arp|bootp|icmp|0 is all): ")
    print(f"\nThe program will capture only {proto_sniff.upper()} packets.\n" if proto_sniff in ["arp", "bootp", "icmp"] else "\nThe program will capture all protocols.\n" if proto_sniff == "0" else "\nCould not identify the protocol.\n")

    file_name = input("* Please give a name to the log file: ")

    # Initiating the packet capture process
    capture_packets(net_iface, pkt_to_sniff, time_to_sniff, proto_sniff, file_name)
