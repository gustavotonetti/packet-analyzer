# 🔍 Network Packet Analyzer

A Python-based **interactive packet sniffer** for capturing, parsing, and analyzing network traffic in real-time. Built with Scapy for security research, network troubleshooting, and CTF labs.

**GitHub:** https://github.com/sudev404/packet-analyzer  
**Author:** sudev404 | BCA @ Krupanidhi Degree College, Bangalore

---

## ✨ Features

- 🎯 **Live Packet Capture** — Sniff packets in real-time on any network interface
- 📊 **Protocol Parsing** — Extracts Ethernet, IP, TCP, UDP, ICMP layer information
- 🎨 **Color-Coded Output** — Easy-to-read terminal display with color highlighting
- 💾 **Persistent Logging** — Saves all captures to `capture.log` for review
- 📦 **PCAP Export** — Export captures to `.pcap` format (opens in Wireshark)
- 🔍 **BPF Filtering** — Filter traffic by protocol, port, IP, etc.
- ⚡ **Lightweight** — Minimal dependencies, runs on Windows/Linux/macOS

---

## 🛠️ Installation

### Prerequisites
- **Python 3.7+** (tested on 3.14)
- **Npcap** (Windows) or **libpcap** (Linux/macOS)

### Windows Setup

1. **Install Npcap** (free packet capture library):
   - Download from [npcap.com](https://npcap.com/#download)
   - Run installer, accept defaults

2. **Install Python dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

   Or manually:
   ```powershell
   pip install scapy colorama
   ```

### Linux/macOS Setup

```bash
sudo apt-get install python3-scapy python3-colorama  # Debian/Ubuntu
# or
pip install scapy colorama
```

---

## 🚀 Quick Start

### 1. Test Locally (Loopback)

**Terminal 1 — Start sniffer:**
```powershell
python analyzer.py -i "\Device\NPF_Loopback" -c 10
```

**Terminal 2 — Generate traffic:**
```powershell
ping 127.0.0.1
```

**Output:**
```
[IP]  127.0.0.1 → 127.0.0.1  TTL=128
[ICMP] Echo Request
  └─ Payload: abcdefghijklmnopqrstuvwabcdefghi...
--------------------------------------------------
```

### 2. Capture Real Network Traffic

```powershell
python analyzer.py -i "Ethernet"
```

Open a website, and watch packets flow in real-time!

### 3. Export to Wireshark

```powershell
python analyzer.py -i "Ethernet" -c 100 -o capture.pcap
wireshark capture.pcap
```

---

## 📖 Usage Guide

### Basic Commands

```bash
# Help menu
python analyzer.py -h

# Capture on default interface
python analyzer.py

# Capture on specific interface
python analyzer.py -i "Ethernet"

# Capture 50 packets only
python analyzer.py -i "Ethernet" -c 50

# Filter by protocol (TCP only)
python analyzer.py -i "Ethernet" -f "tcp"

# Capture DNS queries (port 53)
python analyzer.py -i "Ethernet" -f "udp port 53"

# Capture HTTPS traffic (port 443)
python analyzer.py -i "Ethernet" -f "tcp port 443"

# Save to PCAP file
python analyzer.py -i "Ethernet" -o mytraffic.pcap

# Combine multiple filters
python analyzer.py -i "Ethernet" -f "tcp port 80 or tcp port 443" -c 100 -o web.pcap
```

### BPF Filter Examples

| Filter | Purpose |
|--------|---------|
| `tcp` | Capture TCP packets only |
| `udp` | Capture UDP packets only |
| `icmp` | Capture ICMP (ping) packets |
| `tcp port 80` | HTTP traffic |
| `tcp port 443` | HTTPS traffic |
| `udp port 53` | DNS queries |
| `host 192.168.1.100` | Traffic to/from specific IP |
| `net 192.168.1.0/24` | Traffic from subnet |

---

## 📋 Output Format

### Terminal Display

```
[ETH] aa:bb:cc:dd:ee:ff → 11:22:33:44:55:66
[IP]  192.168.1.100 → 8.8.8.8  TTL=64
[TCP] Port 54321 → 443  Flags=A
  └─ Payload: GET / HTTP/1.1...
--------------------------------------------------
```

### Log File (`capture.log`)

```
[2025-01-15 14:23:45]
[IP]  192.168.1.100 → 8.8.8.8  TTL=64
[TCP] Port 54321 → 443  Flags=A
--------------------------------------------------
[2025-01-15 14:23:46]
[IP]  8.8.8.8 → 192.168.1.100  TTL=56
[TCP] Port 443 → 54321  Flags=A
--------------------------------------------------
```

---

## 🏗️ Project Structure

```
packet-analyzer/
├── analyzer.py          # Main sniffer engine
├── parser.py            # Protocol layer parser
├── logger.py            # File logging module
├── requirements.txt     # Python dependencies
├── capture.log          # Generated log file (created at runtime)
└── README.md            # This file
```

### How It Works

1. **`analyzer.py`** — Entry point
   - Listens on network interface using Scapy's `sniff()` function
   - Calls `packet_handler()` for each captured packet
   - Saves to PCAP if `-o` flag is used

2. **`parser.py`** — Packet decoder
   - Extracts Ethernet layer (MAC addresses)
   - Extracts IP layer (source/dest IPs)
   - Extracts TCP/UDP/ICMP layers with port/flag info
   - Handles Raw payload (text only, filters binary)

3. **`logger.py`** — Persistent storage
   - Appends formatted packet data to `capture.log`
   - Includes timestamp for each entry

**Data Flow:**
```
Network Interface
    ↓
analyzer.py (sniff)
    ↓
parser.py (decode)
    ↓
display (terminal) + log (capture.log)
```

---

## 🎓 Use Cases

### 1. **Network Reconnaissance**
```bash
# Monitor all traffic on your interface
python analyzer.py -i "Ethernet"
```
See what services are running, what IPs are communicating.

### 2. **DNS Monitoring**
```bash
# Capture all DNS queries
python analyzer.py -i "Ethernet" -f "udp port 53"
```
Monitor what domains are being queried on your network.

### 3. **HTTP Traffic Analysis**
```bash
# Capture web traffic
python analyzer.py -i "Ethernet" -f "tcp port 80" -o web.pcap
```
Then open `web.pcap` in Wireshark to inspect requests.

### 4. **CTF / TryHackMe Labs**
```bash
# Monitor traffic while exploiting
python analyzer.py -i "Ethernet" -o lab_traffic.pcap
# Then analyze credentials, network activity, etc.
```

### 5. **Security Research**
- Analyze malware network communication
- Detect suspicious patterns
- Forensic packet analysis

---

## 🔧 Find Your Network Interface

### On Windows
```powershell
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

Or use `ipconfig` to see interface names like "Ethernet", "Wi-Fi".

### On Linux/macOS
```bash
ifconfig
# or
ip link show
```

---

## 💡 Tips & Tricks

### 1. Monitor TryHackMe Exploits
```bash
# Start sniffer on your VPN interface
python analyzer.py -i "Ethernet" -o exploit.pcap

# Run your exploit in another terminal
# Then analyze with Wireshark
wireshark exploit.pcap
```

### 2. Detect Port Scans
Monitor for multiple SYN packets to different ports in short time.

### 3. Find Plaintext Credentials
HTTP/FTP/Telnet traffic shows passwords in logs:
```bash
python analyzer.py -i "Ethernet" -f "tcp port 21"  # FTP
python analyzer.py -i "Ethernet" -f "tcp port 23"  # Telnet
```

### 4. DNS Exfiltration Detection
Track unusual DNS query patterns:
```bash
python analyzer.py -i "Ethernet" -f "udp port 53" -o dns.pcap
```

---

## 🚨 Troubleshooting

### "Interface not found" Error
```powershell
# Find your interface
python -c "from scapy.all import get_if_list; print(get_if_list())"

# Use the correct name
python analyzer.py -i "YourInterfaceName"
```

### "Permission denied" on Linux
```bash
# Run with sudo
sudo python analyzer.py -i eth0
```

### No packets captured
- Make sure you're on the correct interface
- Check firewall isn't blocking traffic
- Try `ping` in another terminal to generate traffic

### Binary garbage in logs
This is normal for encrypted traffic (HTTPS, etc.). The parser filters most binary data automatically.

---

## 🔮 Future Enhancements

- [ ] **ARP Spoofing Detection** — Flag duplicate MAC addresses
- [ ] **Port Scan Detection** — Alert on rapid SYN packets
- [ ] **DNS Sniffer Mode** — Extract domain names from queries
- [ ] **GeoIP Lookup** — Map IPs to countries
- [ ] **Web Dashboard** — Real-time visualization with Flask
- [ ] **Regex Filtering** — Custom pattern matching for payloads
- [ ] **Packet Injection** — Send custom crafted packets
- [ ] **Performance Metrics** — Bytes/sec, packet rate, etc.

---

## 📚 Technologies Used

| Technology | Purpose |
|---|---|
| **Python 3.14** | Core language |
| **Scapy 2.7.0** | Packet capture & parsing |
| **Colorama** | Terminal color output |
| **Npcap** | Windows packet capture (libpcap equivalent) |

---

## 📄 Command Reference

```
usage: analyzer.py [-h] [-i IFACE] [-c COUNT] [-f FILTER] [-o OUTPUT]

options:
  -h, --help            show this help message and exit
  -i, --iface IFACE     Interface to sniff on (e.g. eth0, tun0)
  -c, --count COUNT     Number of packets to capture (0 = unlimited)
  -f, --filter FILTER   BPF filter (e.g. 'tcp', 'udp port 53')
  -o, --output OUTPUT   Save capture to .pcap file
```

---

## ⚖️ Disclaimer

**For Educational Purposes Only**

This tool is intended for:
- ✅ Networks you own
- ✅ Networks you have explicit permission to monitor
- ✅ CTF competitions and authorized security testing
- ✅ Learning networking concepts

**Unauthorized packet sniffing may be illegal.** Always obtain written permission before analyzing network traffic you don't own.

---

## 📞 Support & Contributing

Found a bug? Have an enhancement idea?
- Open an issue on GitHub
- Submit a pull request
- Contact: sudev404

---

## 📈 Learning Path

This project teaches:
- Network protocol fundamentals (OSI model)
- Python packet manipulation
- Real-time data processing
- Security research techniques
- GitHub project documentation

**Next Projects:**
1. Intrusion Detection System (IDS)
2. Password Audit Tool
3. Web Vulnerability Scanner
4. Active Directory Exploitation Lab

---

## 📦 Example Workflows

### Workflow 1: Analyze HTTP Headers
```bash
python analyzer.py -i "Ethernet" -f "tcp port 80" -o http.pcap
wireshark http.pcap  # Open in Wireshark for detailed inspection
```

### Workflow 2: Monitor DNS
```bash
python analyzer.py -i "Ethernet" -f "udp port 53" -c 50
# Then check capture.log for domain names
type capture.log
```

### Workflow 3: TryHackMe SMB Enumeration
```bash
python analyzer.py -i "Ethernet" -f "tcp port 445" -o smb.pcap
# Run your exploit
# Analyze SMB traffic in Wireshark
```

---

## 🎖️ Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Jan 2025 | Initial release, core functionality |

---

## 🙏 Acknowledgments

- **Scapy Documentation** — Packet manipulation library
- **TryHackMe** — Hands-on security learning platform
- **Wireshark** — Deep packet inspection tool

---

## 📜 License

MIT License — Free to use and modify for educational purposes.

---

**Happy packet sniffing! 🎉**

For more security projects, follow **@sudev404** on GitHub.
