import argparse
import os
import sys
from scapy.all import *

captured_packets = []
dns_records = {}

def capture_traffic(interface):
    print(f"Capturing DNS traffic on interface {interface}...")
    captured_packets.extend(sniff(iface=interface, filter="port 53", count=0, prn=process_packet))
    print("Finished capturing traffic.")

def process_packet(packet):
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode()
        if query not in dns_records:
            dns_records[query] = []
        dns_records[query].append(packet)
        return f"DNS Query: {query}"

def analyze_traffic():
    for domain, packets in dns_records.items():
        print(f"\nDomain: {domain}")
        for packet in packets:
            if packet.haslayer(DNSRR):
                rdata = packet[DNSRR].rdata
                if packet[DNSRR].type == 1:  #A record
                    print(f"  A record: {rdata}")
                elif packet[DNSRR].type == 5:  #CNAME record
                    print(f"  CNAME record: {rdata.decode()}")

def simulate_scenario(scenario):
    if scenario == "server_failure":
        #simulate server failure scenario
        print("Simulating server failure scenario...")

    elif scenario == "dns_poisoning":
        #simulate DNS poisoning attack scenario
        print("Simulating DNS poisoning attack scenario...")


def generate_report():
    report_file = "Inspector_report.txt"
    with open(report_file, "w") as f:
        f.write("DNS Inspector Report\n\n")
        f.write("Captured DNS Traffic:\n")
        for domain, packets in dns_records.items():
            f.write(f"\nDomain: {domain}\n")
            for packet in packets:
                if packet.haslayer(DNSRR):
                    rdata = packet[DNSRR].rdata
                    if packet[DNSRR].type == 1:  #A record
                        f.write(f"  A record: {rdata}\n")
                    elif packet[DNSRR].type == 5:  #CNAME record
                        f.write(f"  CNAME record: {rdata.decode()}\n")
    print(f"Report generated: {report_file}")

def main():
    parser = argparse.ArgumentParser(description="DNS Inspector")
    parser.add_argument("-i", "--interface", help="Network interface to capture traffic on")
    parser.add_argument("-s", "--simulate", choices=["server_failure", "dns_poisoning"], help="Simulate a specific scenario")
    parser.add_argument("-r", "--report", action="store_true", help="Generate a report")
    args = parser.parse_args()

    if args.interface:
        capture_traffic(args.interface)
        analyze_traffic()

    if args.simulate:
        simulate_scenario(args.simulate)

    if args.report:
        generate_report()

if __name__ == "__main__":
    main()
