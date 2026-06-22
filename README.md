# network-packet-sniffer
Performing Network Sniffing using Python
# 🌐 Network Packet Sniffer

A Python-based cybersecurity tool that monitors local network traffic using **Scapy**, displaying real-time packet information including source/destination IPs, protocols, ports, DNS queries, and session statistics.


## 📌 Features

- ✅ **Real-time packet capture** on your local network interface
- ✅ **Protocol detection**: TCP, UDP, ICMP, DNS, ARP and more
- ✅ **Service identification**: HTTP, HTTPS, SSH, DNS, FTP, etc.
- ✅ **DNS query logging**: See exactly which domains your device contacts
- ✅ **IP-to-hostname resolution**: Translates IPs to readable domain names
- ✅ **Session statistics**: Protocol breakdown, top destinations
- ✅ **JSON export**: Save all captured data for later analysis
- ✅ **Demo mode**: Test without root/admin privileges or Scapy installed

---

## 🔧 Installation

### Step 1: Install Python
Make sure Python 3.7+ is installed: https://www.python.org/downloads/

### Step 2: Install Scapy
```bash
pip install scapy
```

> **Windows users**: You may also need to install [Npcap](https://npcap.com/) for packet capture to work.

---

## 🚀 Usage

### Demo Mode (No root/admin needed — just testing)
```bash
python packet_sniffer.py --demo
```

### Real Capture — Linux / macOS
```bash
sudo python3 packet_sniffer.py
```

### Real Capture — Windows (Run CMD as Administrator)
```bash
python packet_sniffer.py
```

### Custom Options
```bash
# Capture only TCP traffic, stop after 50 packets
sudo python3 packet_sniffer.py --filter tcp --max 50

# Use a specific network interface
sudo python3 packet_sniffer.py --interface eth0

# Set a 30-second timeout
sudo python3 packet_sniffer.py --timeout 30

# Capture DNS traffic only
sudo python3 packet_sniffer.py --filter "udp port 53"
```

---

## 📋 Command-Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--demo` | Run in demo/simulation mode | `python packet_sniffer.py --demo` |
| `--filter <bpf>` | BPF packet filter expression | `--filter "tcp port 443"` |
| `--max <n>` | Stop after n packets | `--max 100` |
| `--interface <name>` | Specify network interface | `--interface eth0` |
| `--timeout <secs>` | Stop after n seconds | `--timeout 60` |
| `--no-save` | Don't save JSON report | `--no-save` |

---

## 📊 Sample Output

```
  #0001 | 10:34:21.001 | DNS    | 🔍 DNS Query → google.com
  #0002 | 10:34:21.003 | TCP    | 192.168.1.5:54231 → 142.250.182.14:443 [HTTPS] | 66B
  #0003 | 10:34:21.010 | UDP    | 192.168.1.5:12345 → 8.8.8.8:53 [DNS] | 78B
  #0004 | 10:34:21.025 | ICMP   | 192.168.1.5 → 8.8.8.8 [Echo Request]
```

---

## 📁 Project Structure

```
network-packet-sniffer/
│
├── packet_sniffer.py        # Main sniffer script
├── requirements.txt         # Dependencies (scapy)
└── README.md                # This file
```

---

## 🧠 How It Works

1. **Interface Detection** — Identifies available network interfaces
2. **Packet Capture** — Uses Scapy's `sniff()` to intercept raw network packets
3. **Layer Analysis** — Parses IP, TCP, UDP, DNS, ICMP, and ARP layers
4. **Service Mapping** — Maps port numbers to service names (80→HTTP, 443→HTTPS)
5. **DNS Logging** — Extracts and logs all domain name queries
6. **Statistics** — Tracks protocol distribution and top destinations
7. **JSON Export** — Saves complete session data for later analysis

---

## 🔒 Security & Privacy Note

This tool captures **all unencrypted traffic** on your network. When used responsibly on your own network, it helps you understand what your devices are doing. Remember:
- HTTPS traffic (port 443) content is encrypted — you can see who you're connecting to, but not what you're sending
- HTTP traffic (port 80) is unencrypted — full content may be visible
- DNS queries reveal which websites you're visiting

--

