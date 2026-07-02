#!/usr/bin/env python3
from scapy.all import sniff, wrpcap, rdpcap, conf
from parser import parse_packet
from logger import log
from dhcp_monitor import lease_table
import argparse
import sys

captured_packets = []

#ligado pela flag --dhcp-monitor
dhcp_on = False

def packet_handler(packet):
    parsed = parse_packet(packet, dhcp_on)
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
    parser.add_argument("-r", "--read",    default=None,
                        help="Read packets from a .pcap file instead of live capture")
    parser.add_argument("--dhcp-monitor",  action="store_true",
                        help="Track DHCP leases (decode BOOTP/DHCP)")
    return parser.parse_args()

def main():
    global dhcp_on
    args = get_args()

    if args.dhcp_monitor:
        dhcp_on = True

    print(f"""
╔══════════════════════════════════════╗
║   🔍 Network Packet Analyzer v1.0   ║
║        github: sudev404             ║
╚══════════════════════════════════════╝
  Interface : {args.iface or 'default'}
  Filter    : {args.filter or 'none'}
  Count     : {args.count or 'unlimited'}
  Output    : {args.output or 'none'}
  Read PCAP : {args.read or 'none'}
  DHCP Mon. : {'on' if dhcp_on else 'off'}
  Log File  : capture.log
─────────────────────────────────────────
Starting capture... (Ctrl+C to stop)
    """)

    try:
        if args.read:
            #le os pacotes de um arquivo .pcap em vez de capturar ao vivo
            for pkt in rdpcap(args.read):
                packet_handler(pkt)
        else:
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

    #no fim, mostra e salva a tabela de leases
    if dhcp_on:
        table = lease_table()
        print("\n" + table)
        log(table)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("[!] Tip: Run with -h to see options")
    main()
