from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw
from colorama import Fore, Style
from dhcp_monitor import parse_dhcp

def parse_packet(packet, dhcp_on=False):
    output = []

    #--- DHCP ---
    #com o monitor ligado, tenta decodificar o pacote como DHCP
    if dhcp_on:
        dhcp = parse_dhcp(packet)
        if dhcp:
            output.append(dhcp)

    # --- Ethernet Layer ---
    if packet.haslayer(Ether):
        eth = packet[Ether]
        output.append(f"{Fore.CYAN}[ETH]{Style.RESET_ALL} "
                       f"{eth.src} → {eth.dst}")

    # --- IP Layer ---
    if packet.haslayer(IP):
        ip = packet[IP]
        output.append(f"{Fore.YELLOW}[IP]{Style.RESET_ALL}  "
                       f"{ip.src} → {ip.dst}  TTL={ip.ttl}")

        # --- TCP Layer ---
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = tcp.sprintf("%flags%")
            output.append(f"{Fore.GREEN}[TCP]{Style.RESET_ALL} "
                           f"Port {tcp.sport} → {tcp.dport}  Flags={flags}")

        # --- UDP Layer ---
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            output.append(f"{Fore.BLUE}[UDP]{Style.RESET_ALL} "
                           f"Port {udp.sport} → {udp.dport}")

        # --- ICMP Layer ---
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
            icmp_type = types.get(icmp.type, f"Type {icmp.type}")
            output.append(f"{Fore.RED}[ICMP]{Style.RESET_ALL} {icmp_type}")

    # --- Raw Payload (ONLY if readable text) ---
    if packet.haslayer(Raw):
        raw = packet[Raw].load
        try:
            decoded = raw[:100].decode("utf-8", errors="ignore")
            # Only log if it's actually readable text (not mostly binary)
            if len(decoded.strip()) > 5:
                output.append(f"  └─ Payload: {decoded[:50]}...")
        except:
            pass

    return "\n".join(output) if output else None