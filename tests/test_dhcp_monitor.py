#!/usr/bin/env python3
#Testes do monitor DHCP.
#
#Alem de checar valores esperados, cada pacote tambem e conferido contra a
#leitura que o scapy faz da camada DHCP/BOOTP. Como os dois caminhos sao
#independentes (um le os bytes na mao, o outro usa o scapy), se eles batem da
#pra confiar que a interpretacao dos campos esta certa.
#
#Rodar:  py tests/test_dhcp_monitor.py

import os
import sys

#deixa importar os modulos da pasta de cima (raiz do projeto)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import rdpcap, UDP, BOOTP, DHCP
import dhcp_monitor
from dhcp_monitor import parse_bootp, parse_options, parse_dhcp, lease_table, DHCP_TYPES

PCAP = os.path.join(os.path.dirname(__file__), "dhcp_sample.pcap")

#ordem esperada das mensagens no pcap de teste (DORA + RELEASE)
EXPECTED = ["DISCOVER", "OFFER", "REQUEST", "ACK", "RELEASE"]

passed = 0
failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name}  {detail}")


def reset():
    dhcp_monitor.leases.clear()
    dhcp_monitor.total_msgs = 0


def scapy_type(pkt):
    #tipo da mensagem usando a camada DHCP do scapy
    if not pkt.haslayer(DHCP):
        return None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            return DHCP_TYPES.get(opt[1])
    return None


def main():
    pkts = rdpcap(PCAP)

    print("\n== sequencia de mensagens ==")
    types = []
    for pkt in pkts:
        data = bytes(pkt[UDP].payload)
        bootp = parse_bootp(data)
        check("parse_bootp leu o cabecalho", bootp is not None)
        opts = parse_options(data)
        types.append(DHCP_TYPES.get(opts.get("type")))
    check("ordem DORA + RELEASE", types == EXPECTED, f"obtido={types}")

    print("\n== confere campos contra o scapy ==")
    for i, pkt in enumerate(pkts):
        data = bytes(pkt[UDP].payload)
        bootp = parse_bootp(data)
        opts = parse_options(data)
        sc = pkt[BOOTP]

        check(f"pkt{i}: xid igual ao scapy",
              bootp["xid"] == sc.xid,
              f"meu={hex(bootp['xid'])} scapy={hex(sc.xid)}")

        sc_mac = ":".join(f"{b:02x}" for b in bytes(sc.chaddr)[:6])
        check(f"pkt{i}: MAC igual ao scapy",
              bootp["mac"] == sc_mac,
              f"meu={bootp['mac']} scapy={sc_mac}")

        my_type = DHCP_TYPES.get(opts.get("type"))
        check(f"pkt{i}: tipo igual ao scapy ({my_type})",
              my_type == scapy_type(pkt),
              f"meu={my_type} scapy={scapy_type(pkt)}")

    print("\n== valores do OFFER ==")
    data = bytes(pkts[1][UDP].payload)
    bootp = parse_bootp(data)
    opts = parse_options(data)
    check("yiaddr = 192.168.0.50", bootp["yiaddr"] == "192.168.0.50", bootp["yiaddr"])
    check("servidor = 192.168.0.1", opts.get("server") == "192.168.0.1", opts.get("server"))
    check("lease = 86400", opts.get("lease") == 86400, opts.get("lease"))

    print("\n== tabela de leases ==")
    reset()
    for pkt in pkts:
        parse_dhcp(pkt)
    check("1 cliente na tabela", len(dhcp_monitor.leases) == 1, len(dhcp_monitor.leases))
    lease = next(iter(dhcp_monitor.leases.values()))
    check("hostname = notebook-gustavo", lease["hostname"] == "notebook-gustavo", lease["hostname"])
    check("servidor = 192.168.0.1", lease["server"] == "192.168.0.1", lease["server"])
    check("ultima msg = RELEASE", lease["last"] == "RELEASE", lease["last"])
    check("5 mensagens lidas", dhcp_monitor.total_msgs == 5, dhcp_monitor.total_msgs)

    print()
    print("=" * 40)
    print(f"  RESULTADO: {passed} passaram, {failed} falharam")
    print("=" * 40)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
