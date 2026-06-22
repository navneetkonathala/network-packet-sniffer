"""
=============================================================
  Network Packet Sniffer
  Author: [Navneet]
  Description: Monitors network traffic and shows where your
               data is going — source/destination IPs, ports,
               protocols, and DNS queries.
=============================================================

HOW TO RUN (requires admin/root):
  Windows : Run Command Prompt as Administrator, then:
              python packet_sniffer.py
  Linux   : sudo python3 packet_sniffer.py
  macOS   : sudo python3 packet_sniffer.py
"""


import sys          # For command-line arguments and exiting
import os           # For checking admin/root permissions
import time         # For timestamps and timing
import datetime     # For human-readable time formatting
import json         # For saving captured packet data
import signal       # For handling Ctrl+C gracefully
import socket       # For resolving IPs to hostnames
import threading    # For running background tasks
import collections  # For counting and tracking statistics

try:
    # Import specific tools from Scapy that we need
    from scapy.all import (
        sniff,         # The main function to capture packets
        IP,            # Represents the IP layer of a packet
        TCP,           # Represents TCP protocol layer
        UDP,           # Represents UDP protocol layer
        ICMP,          # Represents ICMP (ping) protocol
        DNS,           # Represents DNS (domain name lookup) layer
        DNSQR,         # DNS Query Record
        ARP,           # Address Resolution Protocol
        Ether,         # Ethernet frame layer
        Raw,           # Raw packet payload/data
        conf,          # Scapy configuration
        get_if_list,   # Get list of network interfaces
    )
    SCAPY_AVAILABLE = True
except ImportError:
    # If Scapy isn't installed, set a flag and we'll show demo mode
    SCAPY_AVAILABLE = False


# ─────────────────────────────────────────────────────────────
# You can change these settings to customize the sniffer
# ─────────────────────────────────────────────────────────────
CONFIG = {
    "max_packets": 100,          # Stop after capturing this many packets (0 = unlimited)
    "timeout": 60,               # Stop after this many seconds (0 = run forever)
    "filter": "",                # BPF filter string (e.g., "tcp", "udp port 53", "")
    "interface": None,           # Network interface to sniff on (None = auto-detect)
    "save_to_file": True,        # Save captured data to JSON file
    "output_file": "captured_packets.json",  # Output filename
    "resolve_hostnames": True,   # Try to resolve IP addresses to domain names
    "show_payload": False,       # Show raw packet data (can be verbose)
    "verbose": True,             # Print each packet as it's captured
}

captured_packets = []           # List to store all captured packet info
packet_count = 0                # Counter for total packets captured
start_time = None               # When the session started
stop_sniffing = False           # Flag to stop sniffing (set by Ctrl+C)

# Statistics tracker — counts packets per protocol
stats = collections.Counter()

# DNS cache — stores IP → hostname lookups to avoid repeating them
dns_cache = {}


# ─────────────────────────────────────────────────────────────
# FUNCTION: check_admin_privileges
# PURPOSE: Packet sniffing requires admin/root access. This checks if the user has the right permissions.
# ─────────────────────────────────────────────────────────────
def check_admin_privileges() -> bool:
    """
    Check if the script is running with administrator/root privileges.
    Packet capturing requires elevated permissions on all operating systems.

    Returns:
        bool: True if running as admin/root, False otherwise
    """
    try:
        # On Linux/macOS, root user has UID (User ID) of 0
        return os.getuid() == 0
    except AttributeError:
        # On Windows, os.getuid() doesn't exist
        # We check using ctypes (Windows-specific library)
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False  # Assume not admin if check fails


# ─────────────────────────────────────────────────────────────
# FUNCTION: resolve_hostname
# PURPOSE: Converts an IP address into a readable domain name
#          Example: 142.250.182.14 → google.com
# ─────────────────────────────────────────────────────────────
def resolve_hostname(ip: str) -> str:
    """
    Try to get the domain name (hostname) for an IP address.
    Uses a cache to avoid looking up the same IP multiple times.

    Args:
        ip (str): IP address like "8.8.8.8"

    Returns:
        str: Hostname like "dns.google" or the original IP if lookup fails
    """
    # Return immediately if we already looked this up before
    if ip in dns_cache:
        return dns_cache[ip]

    try:
        # socket.gethostbyaddr() does a reverse DNS lookup
        # It returns (hostname, alias_list, ip_list)
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout, OSError):
        # If lookup fails (network issue, no PTR record, etc.), use the IP itself
        hostname = ip

    # Save result in cache for future use
    dns_cache[ip] = hostname
    return hostname


# ─────────────────────────────────────────────────────────────
# FUNCTION: get_protocol_name
# PURPOSE: Converts a protocol number to a readable name
#          Example: 6 → "TCP", 17 → "UDP", 1 → "ICMP"
# ─────────────────────────────────────────────────────────────
def get_protocol_name(proto_num: int) -> str:
    """
    Convert a numeric protocol ID to its name.

    Args:
        proto_num (int): Protocol number from IP header

    Returns:
        str: Protocol name (TCP, UDP, ICMP, etc.)
    """
    # Dictionary mapping protocol numbers to names
    protocols = {
        1: "ICMP",    # Internet Control Message Protocol (ping)
        2: "IGMP",    # Internet Group Management Protocol
        6: "TCP",     # Transmission Control Protocol (most web traffic)
        17: "UDP",    # User Datagram Protocol (video, DNS, games)
        41: "IPv6",   # IPv6 encapsulation
        47: "GRE",    # Generic Routing Encapsulation (VPN)
        50: "ESP",    # Encapsulating Security Payload (VPN/IPsec)
        51: "AH",     # Authentication Header (VPN/IPsec)
        89: "OSPF",   # Open Shortest Path First (routing protocol)
        132: "SCTP",  # Stream Control Transmission Protocol
    }
    return protocols.get(proto_num, f"PROTO-{proto_num}")


# ─────────────────────────────────────────────────────────────
# FUNCTION: get_service_name
# PURPOSE: Converts a port number to a service name
#          Example: 80 → "HTTP", 443 → "HTTPS", 53 → "DNS"
# ─────────────────────────────────────────────────────────────
def get_service_name(port: int) -> str:
    """
    Convert a port number to a common service/application name.

    Args:
        port (int): TCP or UDP port number

    Returns:
        str: Service name or the port number as a string
    """
    # Common ports and what they're used for
    well_known_ports = {
        20: "FTP-Data",      # File Transfer (data)
        21: "FTP",           # File Transfer Protocol
        22: "SSH",           # Secure Shell (remote access)
        23: "Telnet",        # Old unencrypted remote access
        25: "SMTP",          # Sending emails
        53: "DNS",           # Domain Name System (website name lookup)
        67: "DHCP-Server",   # IP address assignment
        68: "DHCP-Client",   # IP address assignment
        80: "HTTP",          # Unencrypted web traffic
        110: "POP3",         # Receiving emails (older)
        143: "IMAP",         # Receiving emails
        443: "HTTPS",        # Encrypted web traffic (most websites)
        465: "SMTPS",        # Encrypted email sending
        587: "SMTP-TLS",     # Email submission
        993: "IMAPS",        # Encrypted IMAP
        995: "POP3S",        # Encrypted POP3
        1194: "OpenVPN",     # VPN
        1433: "MSSQL",       # Microsoft SQL Server
        3306: "MySQL",       # MySQL database
        3389: "RDP",         # Remote Desktop Protocol
        5432: "PostgreSQL",  # PostgreSQL database
        5900: "VNC",         # Remote desktop (VNC)
        6379: "Redis",       # Redis database
        8080: "HTTP-Alt",    # Alternative HTTP
        8443: "HTTPS-Alt",   # Alternative HTTPS
        27017: "MongoDB",    # MongoDB database
    }
    return well_known_ports.get(port, str(port))


# ─────────────────────────────────────────────────────────────
# FUNCTION: analyze_packet
# PURPOSE: Extracts useful information from each captured packet
# ─────────────────────────────────────────────────────────────
def analyze_packet(packet) -> dict:
    """
    Extract and organize information from a captured network packet.

    A "packet" is a small chunk of data traveling over the network.
    Think of it like a letter: it has a sender (source), a recipient
    (destination), and content (payload).

    Args:
        packet: A Scapy packet object

    Returns:
        dict: Dictionary with all extracted packet information
    """
    # Get current timestamp for this packet
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # Start building our packet info dictionary
    packet_info = {
        "timestamp": timestamp,
        "protocol": "Unknown",
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "src_host": None,
        "dst_host": None,
        "service": None,
        "size": len(packet),  # Packet size in bytes
        "flags": None,        # TCP flags (SYN, ACK, FIN, etc.)
        "dns_query": None,    # DNS query domain (if it's a DNS packet)
        "summary": packet.summary()  # Scapy's built-in one-line summary
    }

    # ── IP Layer Analysis ──────────────────────────────────────
    # The IP layer tells us SOURCE and DESTINATION IP addresses
    if IP in packet:
        ip_layer = packet[IP]
        packet_info["src_ip"] = ip_layer.src    # Who sent this packet
        packet_info["dst_ip"] = ip_layer.dst    # Who receives this packet
        packet_info["protocol"] = get_protocol_name(ip_layer.proto)

        # Optional: Resolve IP addresses to domain names
        # (Can slow down the sniffer if there are many unique IPs)
        if CONFIG["resolve_hostnames"]:
            packet_info["src_host"] = resolve_hostname(ip_layer.src)
            packet_info["dst_host"] = resolve_hostname(ip_layer.dst)

    # ── TCP Layer Analysis ─────────────────────────────────────
    # TCP is used by web browsers, SSH, email, and most applications
    if TCP in packet:
        tcp_layer = packet[TCP]
        packet_info["src_port"] = tcp_layer.sport   # Source port
        packet_info["dst_port"] = tcp_layer.dport   # Destination port
        packet_info["protocol"] = "TCP"

        # Determine the service based on destination port
        packet_info["service"] = get_service_name(tcp_layer.dport)

        # Extract TCP flags (these control the connection state)
        # SYN=connection start, ACK=acknowledgment, FIN=connection end
        flags = tcp_layer.flags
        flag_names = []
        if flags.S: flag_names.append("SYN")   # Synchronize (new connection)
        if flags.A: flag_names.append("ACK")   # Acknowledge
        if flags.F: flag_names.append("FIN")   # Finish (close connection)
        if flags.R: flag_names.append("RST")   # Reset (force close)
        if flags.P: flag_names.append("PSH")   # Push data immediately
        if flags.U: flag_names.append("URG")   # Urgent data
        packet_info["flags"] = "|".join(flag_names)

    # ── UDP Layer Analysis ─────────────────────────────────────
    # UDP is used by DNS lookups, video streaming, online games
    elif UDP in packet:
        udp_layer = packet[UDP]
        packet_info["src_port"] = udp_layer.sport
        packet_info["dst_port"] = udp_layer.dport
        packet_info["protocol"] = "UDP"
        packet_info["service"] = get_service_name(udp_layer.dport)

    # ── DNS Layer Analysis ─────────────────────────────────────
    # DNS packets tell us which domain names your device is looking up
    # This reveals which websites/services you're connecting to
    if DNS in packet and DNSQR in packet:
        try:
            # Extract the domain name being queried
            # decode("utf-8") converts raw bytes to a readable string
            dns_query = packet[DNSQR].qname.decode("utf-8").rstrip(".")
            packet_info["dns_query"] = dns_query
            packet_info["protocol"] = "DNS"
        except Exception:
            pass  # Skip if DNS data can't be decoded

    # ── ICMP Layer Analysis ────────────────────────────────────
    # ICMP is used by "ping" commands to test connectivity
    elif ICMP in packet:
        packet_info["protocol"] = "ICMP"
        icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable",
                      11: "Time Exceeded", 5: "Redirect"}
        packet_info["service"] = icmp_types.get(packet[ICMP].type, "ICMP")

    # ── ARP Layer Analysis ─────────────────────────────────────
    # ARP finds MAC addresses on your local network
    elif ARP in packet:
        packet_info["protocol"] = "ARP"
        packet_info["src_ip"] = packet[ARP].psrc
        packet_info["dst_ip"] = packet[ARP].pdst

    return packet_info


# ─────────────────────────────────────────────────────────────
# FUNCTION: packet_callback
# PURPOSE: Called automatically for EVERY packet that's captured
# ─────────────────────────────────────────────────────────────
def packet_callback(packet) -> None:
    """
    This function is called by Scapy every time a new packet is captured.
    It processes the packet and decides whether to stop sniffing.

    Args:
        packet: The raw Scapy packet object
    """
    global packet_count, captured_packets, stop_sniffing

    # If we've been told to stop, don't process more packets
    if stop_sniffing:
        return

    # Increment our packet counter
    packet_count += 1

    # Extract useful information from the packet
    packet_info = analyze_packet(packet)

    # Update statistics — count by protocol type
    stats[packet_info["protocol"]] += 1

    # Add to our list of captured packets
    captured_packets.append(packet_info)

    # Print the packet info to terminal (if verbose mode is on)
    if CONFIG["verbose"]:
        print_packet(packet_info, packet_count)

    # Check if we've reached the maximum packet count
    if CONFIG["max_packets"] > 0 and packet_count >= CONFIG["max_packets"]:
        print(f"\n[INFO] Reached maximum packet limit ({CONFIG['max_packets']}). Stopping...")
        stop_sniffing = True


# ─────────────────────────────────────────────────────────────
# FUNCTION: print_packet
# PURPOSE: Prints a single packet's info in a readable format
# ─────────────────────────────────────────────────────────────
def print_packet(info: dict, count: int) -> None:
    """
    Print a packet's information to the terminal in a clean format.

    Args:
        info (dict): Packet information dictionary from analyze_packet()
        count (int): Packet number (for display)
    """
    # Build the source and destination strings
    src = info["src_ip"] or "N/A"
    dst = info["dst_ip"] or "N/A"

    # Add port info if available (e.g., "192.168.1.1:443")
    if info["src_port"]:
        src += f":{info['src_port']}"
    if info["dst_port"]:
        dst += f":{info['dst_port']}"

    # Add hostname if we resolved it and it's different from the IP
    if info["dst_host"] and info["dst_host"] != info["dst_ip"]:
        dst += f" ({info['dst_host']})"

    # Build service label
    service = f"[{info['service']}]" if info["service"] else ""

    # Print DNS queries with special formatting (they're especially informative)
    if info["dns_query"]:
        print(f"  #{count:04d} | {info['timestamp']} | 🔍 DNS Query → {info['dns_query']}")
    else:
        # Print regular packet
        proto_display = f"{info['protocol']:<6}"  # Left-align protocol, 6 chars wide
        print(f"  #{count:04d} | {info['timestamp']} | {proto_display} | {src} → {dst} {service} | {info['size']}B")


# ─────────────────────────────────────────────────────────────
# FUNCTION: print_session_stats
# PURPOSE: Shows a summary of all captured traffic when done
# ─────────────────────────────────────────────────────────────
def print_session_stats() -> None:
    """
    Print a summary of the entire sniffing session when it ends.
    Shows total packets, protocols used, top destinations, etc.
    """
    duration = time.time() - start_time if start_time else 0

    print("\n" + "="*65)
    print("              📊 SESSION STATISTICS SUMMARY")
    print("="*65)
    print(f"  Duration       : {duration:.1f} seconds")
    print(f"  Total Packets  : {packet_count}")

    if duration > 0:
        print(f"  Packets/second : {packet_count / duration:.1f}")

    # Show breakdown by protocol
    if stats:
        print(f"\n  PROTOCOL BREAKDOWN:")
        print("  " + "-"*40)
        # Sort by count (most common first)
        for proto, count in stats.most_common():
            bar = "█" * min(count, 30)  # Visual bar chart (max 30 chars)
            percentage = (count / packet_count * 100) if packet_count > 0 else 0
            print(f"  {proto:<10} : {count:4d} packets ({percentage:.1f}%) {bar}")

    # Show DNS queries made (which websites were visited)
    dns_queries = [p["dns_query"] for p in captured_packets if p.get("dns_query")]
    if dns_queries:
        print(f"\n  🔍 DNS QUERIES (Domains Visited):")
        print("  " + "-"*40)
        # Count unique domains and show top ones
        domain_counts = collections.Counter(dns_queries)
        for domain, count in domain_counts.most_common(15):  # Show top 15
            print(f"  {count:3d}x  {domain}")

    # Show top destination IPs
    dst_ips = [p["dst_ip"] for p in captured_packets if p.get("dst_ip")]
    if dst_ips:
        print(f"\n  🎯 TOP DESTINATION IPs:")
        print("  " + "-"*40)
        ip_counts = collections.Counter(dst_ips)
        for ip, count in ip_counts.most_common(10):  # Show top 10
            # Try to show hostname if we have it
            hostname = dns_cache.get(ip, ip)
            display = f"{ip}" if hostname == ip else f"{ip} ({hostname})"
            print(f"  {count:3d}x  {display}")

    print("="*65 + "\n")


# ─────────────────────────────────────────────────────────────
# FUNCTION: save_capture_report
# PURPOSE: Saves all captured packet data to a JSON file
# ─────────────────────────────────────────────────────────────
def save_capture_report() -> None:
    """
    Save the complete capture session data to a JSON file.
    JSON files can be opened in any text editor or analyzed with other tools.
    """
    duration = time.time() - start_time if start_time else 0

    # Build the complete report
    report = {
        "session_info": {
            "start_time": datetime.datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S") if start_time else "N/A",
            "duration_seconds": round(duration, 2),
            "total_packets": packet_count,
            "interface": CONFIG["interface"] or "auto"
        },
        "statistics": dict(stats),
        "dns_queries": list(set(p["dns_query"] for p in captured_packets if p.get("dns_query"))),
        "packets": captured_packets  # All captured packet data
    }

    # Save to file
    output_path = CONFIG["output_file"]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[INFO] Capture saved to: {output_path}")


# ─────────────────────────────────────────────────────────────
# FUNCTION: handle_sigint
# PURPOSE: Handles Ctrl+C (keyboard interrupt) gracefully
# ─────────────────────────────────────────────────────────────
def handle_sigint(signum, frame) -> None:
    """
    Handle the Ctrl+C keyboard interrupt signal.
    Instead of crashing, we gracefully stop and show statistics.
    """
    global stop_sniffing
    print("\n\n[INFO] Ctrl+C detected. Stopping packet capture...")
    stop_sniffing = True


# ─────────────────────────────────────────────────────────────
# FUNCTION: run_demo_mode
# PURPOSE: Simulates packet sniffing when Scapy isn't available or when you're testing without root/admin privileges
# ─────────────────────────────────────────────────────────────
def run_demo_mode() -> None:
    """
    Demo mode: Simulates what real packet output looks like.
    Useful for testing on systems where Scapy isn't installed
    or where you don't have admin/root privileges yet.
    """
    print("\n" + "="*65)
    print("  🎭 DEMO MODE — Simulated Network Traffic")
    print("  (Real mode requires: sudo + pip install scapy)")
    print("="*65 + "\n")

    # Simulated packet data (what real traffic might look like)
    demo_packets = [
        {"ts": "10:34:21.001", "proto": "DNS",   "detail": "🔍 DNS Query → google.com"},
        {"ts": "10:34:21.003", "proto": "TCP",   "detail": "192.168.1.5:54231 → 142.250.182.14:443 [HTTPS] | 66B"},
        {"ts": "10:34:21.010", "proto": "DNS",   "detail": "🔍 DNS Query → cloudflare.com"},
        {"ts": "10:34:21.012", "proto": "TCP",   "detail": "192.168.1.5:54232 → 104.16.133.229:443 [HTTPS] | 1420B"},
        {"ts": "10:34:21.015", "proto": "DNS",   "detail": "🔍 DNS Query → api.github.com"},
        {"ts": "10:34:21.020", "proto": "TCP",   "detail": "192.168.1.5:54233 → 140.82.121.6:443 [HTTPS] | 512B"},
        {"ts": "10:34:21.025", "proto": "UDP",   "detail": "192.168.1.5:12345 → 8.8.8.8:53 [DNS] | 78B"},
        {"ts": "10:34:21.026", "proto": "DNS",   "detail": "🔍 DNS Query → reddit.com"},
        {"ts": "10:34:21.030", "proto": "TCP",   "detail": "192.168.1.5:54234 → 151.101.129.140:443 [HTTPS] | 2880B"},
        {"ts": "10:34:21.035", "proto": "ICMP",  "detail": "192.168.1.5 → 8.8.8.8 [Echo Request]"},
        {"ts": "10:34:21.040", "proto": "ICMP",  "detail": "8.8.8.8 → 192.168.1.5 [Echo Reply]"},
        {"ts": "10:34:21.045", "proto": "DNS",   "detail": "🔍 DNS Query → youtube.com"},
        {"ts": "10:34:21.050", "proto": "TCP",   "detail": "192.168.1.5:54235 → 208.65.153.238:443 [HTTPS] | 1480B"},
        {"ts": "10:34:21.055", "proto": "ARP",   "detail": "192.168.1.5 → 192.168.1.1 [ARP Request]"},
        {"ts": "10:34:21.056", "proto": "ARP",   "detail": "192.168.1.1 → 192.168.1.5 [ARP Reply]"},
    ]

    print("  Simulating packet capture (press Ctrl+C to stop)...\n")
    print(f"  {'#':<6} {'Time':<15} {'Proto':<7} Detail")
    print("  " + "-"*60)

    try:
        for i, pkt in enumerate(demo_packets, 1):
            print(f"  #{i:04d} | {pkt['ts']} | {pkt['proto']:<6} | {pkt['detail']}")
            time.sleep(0.3)  # Simulate packets arriving over time
    except KeyboardInterrupt:
        print("\n[Demo stopped]")

    print("\n" + "="*65)
    print("  📊 DEMO SESSION SUMMARY")
    print("  Total Simulated Packets: 15")
    print("  DNS Queries: google.com, cloudflare.com, github.com,")
    print("               reddit.com, youtube.com")
    print("  Top Protocol: HTTPS (443) — Encrypted web traffic")
    print("="*65)
    print("\n✅ This is demo mode. For real packet capture:")
    print("   1. Install Scapy: pip install scapy")
    print("   2. Run as administrator/root")
    print("   3. Run: sudo python3 packet_sniffer.py\n")


# ─────────────────────────────────────────────────────────────
# FUNCTION: start_sniffer
# PURPOSE: Sets up and starts the actual packet capture
# ─────────────────────────────────────────────────────────────
def start_sniffer() -> None:
    """
    Initialize and start the packet sniffer using Scapy.
    Requires Scapy to be installed and admin/root privileges.
    """
    global start_time

    # Register the Ctrl+C handler so we can stop gracefully
    signal.signal(signal.SIGINT, handle_sigint)

    # List available network interfaces
    try:
        interfaces = get_if_list()
        print(f"[INFO] Available interfaces: {', '.join(interfaces)}")
    except Exception:
        print("[INFO] Could not list interfaces.")

    # Choose which interface to sniff on
    interface = CONFIG["interface"]  # None = let Scapy decide

    print(f"\n[INFO] Starting packet capture...")
    print(f"[INFO] Interface  : {interface or 'auto-detect'}")
    print(f"[INFO] Max packets: {CONFIG['max_packets'] or 'unlimited'}")
    print(f"[INFO] Timeout    : {CONFIG['timeout'] or 'none'} seconds")
    print(f"[INFO] Filter     : '{CONFIG['filter'] or 'none'}'")
    print("\n  Press Ctrl+C to stop capture.\n")
    print(f"  {'#':<6} {'Time':<15} {'Proto':<7} Connection Details")
    print("  " + "-"*65)

    start_time = time.time()  # Record when we started sniffing
    conf.verb = 0

    # ── THE MAIN SNIFF CALL ────────────────────────────────────
    # This is the core of the sniffer. It captures packets and
    # calls packet_callback() for each one.
    #
    # Parameters:
    #   prn       = function to call for each packet
    #   filter    = BPF filter (like "tcp" or "port 80")
    #   iface     = which network interface to sniff
    #   count     = stop after this many packets (0 = forever)
    #   timeout   = stop after this many seconds (0 = forever)
    #   stop_filter = a function that returns True to stop early
    # ─────────────────────────────────────────────────────────

    try:
        sniff(
            prn=packet_callback,                  # Call this for each packet
            filter=CONFIG["filter"],              # BPF filter (empty = all traffic)
            iface=interface,                      # Which network interface
            count=CONFIG["max_packets"],          # Max packets (0 = no limit)
            timeout=CONFIG["timeout"] or None,    # Timeout in seconds
            stop_filter=lambda p: stop_sniffing,  # Stop when flag is set
            store=False                           # Don't store in Scapy's memory (save RAM)
        )
    except PermissionError:
        print("\n[ERROR] Permission denied! Run with sudo (Linux/macOS) or as Administrator (Windows).")
        sys.exit(1)
    except OSError as e:
        print(f"\n[ERROR] Network interface error: {e}")
        sys.exit(1)

    # Sniffing has stopped — show summary and save report
    print_session_stats()

    if CONFIG["save_to_file"] and captured_packets:
        save_capture_report()


if __name__ == "__main__":
    print("   🌐 Network Packet Sniffer")

    # Check if user wants demo mode (no root needed)
    if "--demo" in sys.argv:
        run_demo_mode()
        sys.exit(0)

    # Check if Scapy is installed
    if not SCAPY_AVAILABLE:
        print("[WARNING] Scapy is not installed. Running in DEMO mode.")
        print("          Install Scapy with: pip install scapy")
        print("          Then run with root/admin privileges.\n")
        run_demo_mode()
        sys.exit(0)

    # Check for admin/root privileges
    if not check_admin_privileges():
        print("[WARNING] This script requires administrator/root privileges.")
        print("          Running in DEMO mode instead.\n")
        print("          To run the real sniffer:")
        print("          Linux/macOS: sudo python3 packet_sniffer.py")
        print("          Windows: Run Command Prompt as Administrator\n")
        run_demo_mode()
        sys.exit(0)

    # Parse command-line arguments for custom settings
    # Example: python packet_sniffer.py --filter tcp --max 50
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--filter" and i + 1 < len(sys.argv):
            CONFIG["filter"] = sys.argv[i + 1]
        elif arg == "--max" and i + 1 < len(sys.argv):
            CONFIG["max_packets"] = int(sys.argv[i + 1])
        elif arg == "--interface" and i + 1 < len(sys.argv):
            CONFIG["interface"] = sys.argv[i + 1]
        elif arg == "--timeout" and i + 1 < len(sys.argv):
            CONFIG["timeout"] = int(sys.argv[i + 1])
        elif arg == "--no-save":
            CONFIG["save_to_file"] = False

    # Start the sniffer
    start_sniffer()
