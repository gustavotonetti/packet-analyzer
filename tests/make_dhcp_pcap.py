#!/usr/bin/env python3
#Gera um pcap de teste com um handshake DHCP completo (DISCOVER, OFFER,
#REQUEST, ACK) mais um RELEASE, pra poder testar o monitor sem precisar de
#trafego DHCP de verdade na rede.

import os
from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP, wrpcap
)

CLIENT_MAC = "08:00:27:ab:cd:ef"
SERVER_MAC = "52:54:00:12:34:56"
SERVER_IP = "192.168.0.1"
OFFERED_IP = "192.168.0.50"
LEASE = 86400  #1 dia
HOSTNAME = "notebook-gustavo"
XID = 0x12345678


def discover():
    return (
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=bytes.fromhex(CLIENT_MAC.replace(":", "")), xid=XID) /
        DHCP(options=[("message-type", "discover"),
                      ("hostname", HOSTNAME),
                      "end"])
    )


def offer():
    return (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
        IP(src=SERVER_IP, dst=OFFERED_IP) /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, yiaddr=OFFERED_IP, siaddr=SERVER_IP,
              chaddr=bytes.fromhex(CLIENT_MAC.replace(":", "")), xid=XID) /
        DHCP(options=[("message-type", "offer"),
                      ("server_id", SERVER_IP),
                      ("lease_time", LEASE),
                      "end"])
    )


def request():
    return (
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=bytes.fromhex(CLIENT_MAC.replace(":", "")), xid=XID) /
        DHCP(options=[("message-type", "request"),
                      ("requested_addr", OFFERED_IP),
                      ("server_id", SERVER_IP),
                      ("hostname", HOSTNAME),
                      "end"])
    )


def ack():
    return (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
        IP(src=SERVER_IP, dst=OFFERED_IP) /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, yiaddr=OFFERED_IP, siaddr=SERVER_IP,
              chaddr=bytes.fromhex(CLIENT_MAC.replace(":", "")), xid=XID) /
        DHCP(options=[("message-type", "ack"),
                      ("server_id", SERVER_IP),
                      ("lease_time", LEASE),
                      "end"])
    )


def release():
    return (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
        IP(src=OFFERED_IP, dst=SERVER_IP) /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, ciaddr=OFFERED_IP,
              chaddr=bytes.fromhex(CLIENT_MAC.replace(":", "")), xid=XID) /
        DHCP(options=[("message-type", "release"),
                      ("server_id", SERVER_IP),
                      "end"])
    )


if __name__ == "__main__":
    pkts = [discover(), offer(), request(), ack(), release()]
    out = os.path.join(os.path.dirname(__file__), "dhcp_sample.pcap")
    wrpcap(out, pkts)
    print(f"[OK] Gerado {out} com {len(pkts)} pacotes DHCP.")
