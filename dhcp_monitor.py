from scapy.all import UDP
from colorama import Fore, Style

#DHCP usa UDP nas portas 67 (servidor) e 68 (cliente)
SERVER_PORT = 67
CLIENT_PORT = 68

#valor fixo que marca onde comecam as opcoes dentro do pacote
DHCP_COOKIE = 0x63825363

#o cabecalho BOOTP tem 236 bytes fixos, depois vem o cookie (4 bytes),
#entao as opcoes comecam no byte 240
OPTIONS_START = 240

#tipos de mensagem (opcao 53)
DHCP_TYPES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}

#tabela de leases, uma entrada por MAC de cliente
leases = {}
total_msgs = 0


def ip_to_str(data):
    #4 bytes viram um IP tipo 192.168.0.1
    return ".".join(str(b) for b in data)


def mac_to_str(data):
    #6 bytes viram um MAC tipo 08:00:27:ab:cd:ef
    return ":".join(f"{b:02x}" for b in data)


def lease_to_str(seconds):
    if seconds is None:
        return "-"
    hours = seconds // 3600
    return f"{seconds}s ({hours}h)"


def parse_bootp(data):
    #le os campos fixos do BOOTP direto dos bytes
    if len(data) < OPTIONS_START:
        return None

    cookie = int.from_bytes(data[236:240], "big")
    if cookie != DHCP_COOKIE:
        return None

    info = {}
    info["op"] = data[0]
    info["htype"] = data[1]
    info["hlen"] = data[2]
    info["xid"] = int.from_bytes(data[4:8], "big")
    info["ciaddr"] = ip_to_str(data[12:16])
    info["yiaddr"] = ip_to_str(data[16:20])
    info["siaddr"] = ip_to_str(data[20:24])
    info["giaddr"] = ip_to_str(data[24:28])
    info["mac"] = mac_to_str(data[28:34])   #chaddr: os 6 primeiros bytes sao o MAC
    return info


def parse_options(data):
    #as opcoes vem no formato: codigo, tamanho, valor
    options = {}
    i = OPTIONS_START
    while i < len(data):
        code = data[i]
        if code == 255:        #fim das opcoes
            break
        if code == 0:          #padding, pula
            i += 1
            continue

        length = data[i + 1]
        value = data[i + 2:i + 2 + length]
        i += 2 + length

        if code == 53:
            options["type"] = value[0]
        elif code == 50:
            options["requested_ip"] = ip_to_str(value)
        elif code == 54:
            options["server"] = ip_to_str(value)
        elif code == 51:
            options["lease"] = int.from_bytes(value, "big")
        elif code == 12:
            options["hostname"] = value.decode("utf-8", errors="ignore")
    return options


def is_dhcp(packet):
    if not packet.haslayer(UDP):
        return False
    udp = packet[UDP]
    return udp.sport in (SERVER_PORT, CLIENT_PORT) and udp.dport in (SERVER_PORT, CLIENT_PORT)


def parse_dhcp(packet):
    #devolve um bloco de texto se for DHCP, senao None
    global total_msgs
    if not is_dhcp(packet):
        return None

    data = bytes(packet[UDP].payload)
    bootp = parse_bootp(data)
    if not bootp:
        return None

    options = parse_options(data)
    total_msgs += 1

    msg_type = DHCP_TYPES.get(options.get("type"), "UNKNOWN")
    update_leases(bootp, options, msg_type)
    return format_dhcp(bootp, options, msg_type)


def update_leases(bootp, options, msg_type):
    mac = bootp["mac"]
    lease = leases.get(mac)
    if lease is None:
        lease = {"mac": mac, "ip": "-", "server": "-",
                 "hostname": "-", "lease": None, "last": "-"}
        leases[mac] = lease

    lease["last"] = msg_type
    if "hostname" in options:
        lease["hostname"] = options["hostname"]
    if "server" in options:
        lease["server"] = options["server"]
    if "lease" in options:
        lease["lease"] = options["lease"]

    #OFFER e ACK trazem o IP concedido no campo yiaddr
    if msg_type in ("OFFER", "ACK") and bootp["yiaddr"] != "0.0.0.0":
        lease["ip"] = bootp["yiaddr"]
    #no REQUEST o cliente costuma pedir o IP na opcao 50
    elif msg_type == "REQUEST" and "requested_ip" in options:
        lease["ip"] = options["requested_ip"]
    elif msg_type == "RELEASE":
        lease["ip"] = "(liberado)"


def format_dhcp(bootp, options, msg_type):
    lines = []
    lines.append(f"{Fore.MAGENTA}[DHCP]{Style.RESET_ALL} {msg_type}  "
                 f"xid={hex(bootp['xid'])}  cliente={bootp['mac']}")
    if bootp["yiaddr"] != "0.0.0.0":
        lines.append(f"        IP concedido : {bootp['yiaddr']}")
    if "requested_ip" in options:
        lines.append(f"        IP pedido    : {options['requested_ip']}")
    if "server" in options:
        lines.append(f"        Servidor     : {options['server']}")
    if "lease" in options:
        lines.append(f"        Lease        : {lease_to_str(options['lease'])}")
    if "hostname" in options:
        lines.append(f"        Hostname     : {options['hostname']}")
    return "\n".join(lines)


def lease_table():
    if not leases:
        return f"{Fore.MAGENTA}[DHCP]{Style.RESET_ALL} Nenhum lease capturado."

    header = (f"{'MAC':<18} {'IP':<16} {'Servidor':<16} "
              f"{'Hostname':<16} {'Ultima msg':<10} {'Lease':<12}")
    rows = []
    rows.append(f"{Fore.MAGENTA}Leases DHCP "
                f"({len(leases)} cliente(s), {total_msgs} mensagens){Style.RESET_ALL}")
    rows.append(header)
    rows.append("-" * len(header))
    for lease in leases.values():
        rows.append(f"{lease['mac']:<18} {lease['ip']:<16} {lease['server']:<16} "
                    f"{lease['hostname']:<16} {lease['last']:<10} "
                    f"{lease_to_str(lease['lease']):<12}")
    return "\n".join(rows)
