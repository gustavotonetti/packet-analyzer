#!/usr/bin/env python3
from scapy.all import sniff, wrpcap, conf
from parser import parse_packet
from logger import log
import argparse
import sys

captured_packets = []

def packet_handler(packet):
    parsed = parse_packet(packet)
    if parsed:
        print(parsed)
        print("-" * 50)
        log(parsed)
    captured_packets.append(packet)

def get_args():
    parser = argparse.ArgumentParser(
        description="🔍 Network Packet Analyzer by sudev404"
    )
    parser.add_argument("-i", "--iface",   default=None,
                        help="Interface to sniff on (e.g. eth0, tun0)")
    parser.add_argument("-c", "--count",   type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter",  default=None,
                        help="BPF filter (e.g. 'tcp', 'udp port 53')")
    parser.add_argument("-o", "--output",  default=None,
                        help="Save capture to .pcap file")
    return parser.parse_args()

def main():
    args = get_args()

    print(f"""
╔══════════════════════════════════════╗
║   🔍 Network Packet Analyzer v1.0   ║
║        github: sudev404             ║
╚══════════════════════════════════════╝
  Interface : {args.iface or 'default'}
  Filter    : {args.filter or 'none'}
  Count     : {args.count or 'unlimited'}
  Output    : {args.output or 'none'}
  Log File  : capture.log
─────────────────────────────────────────
Starting capture... (Ctrl+C to stop)
    """)

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            count=args.count,
            prn=packet_handler,
            store=False
        )
    except KeyboardInterrupt:
        print(f"\n[!] Stopped. Captured {len(captured_packets)} packets.")

    if args.output:
        wrpcap(args.output, captured_packets)
        print(f"[✓] Saved to {args.output}")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("[!] Tip: Run with -h to see options")
    main()