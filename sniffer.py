#!/usr/bin/env python3
"""
The Pocket SOC - DNS Traffic Sniffer
Host-Based DNS Traffic Analyzer for Windows
"""

import sys
import signal
import csv
import os
from datetime import datetime

try:
    from scapy.all import sniff, IP, UDP, DNS
    from scapy.error import Scapy_Exception
except ImportError as e:
    print(f"[!] Error: Scapy is not installed. Please install it using: pip install scapy")
    sys.exit(1)

# Global flag for graceful shutdown
running = True


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global running
    print("\n[!] Shutting down DNS sniffer...")
    running = False
    sys.exit(0)


def init_csv():
    """
    Initialize CSV file if it doesn't exist.
    Creates traffic_log.csv with headers if the file is missing.
    """
    csv_filename = "traffic_log.csv"
    if not os.path.exists(csv_filename):
        with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Timestamp", "Source IP", "Domain"])


def log_packet(source_ip, domain_name):
    """
    Log packet information to CSV file.
    
    Args:
        source_ip: Source IP address
        domain_name: Domain name that was requested
    """
    csv_filename = "traffic_log.csv"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(csv_filename, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([timestamp, source_ip, domain_name])
    except Exception as e:
        # Silent fail for CSV logging errors to not interrupt packet capture
        pass


def parse_dns_packet(packet):
    """
    Parse DNS packet to extract source IP and queried domain name.
    
    Args:
        packet: Scapy packet object
        
    Returns:
        tuple: (source_ip, domain_name) or (None, None) if parsing fails
    """
    try:
        # Check if packet has IP layer
        if not packet.haslayer(IP):
            return None, None
        
        # Get source IP
        source_ip = packet[IP].src
        
        # Check if packet has DNS layer and is a query (not response)
        if not packet.haslayer(DNS):
            return None, None
        
        dns_layer = packet[DNS]
        
        # Only process DNS queries (QR flag = 0), not responses
        if dns_layer.qr != 0:
            return None, None
        
        # Check if there's a DNS question section
        if dns_layer.qd is None:
            return None, None
        
        # Extract the queried domain name
        domain_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
        
        return source_ip, domain_name
    
    except Exception as e:
        # Silent fail for non-DNS packets or parsing errors
        return None, None


def dns_packet_handler(packet):
    """
    Handler function called for each captured packet.
    
    Args:
        packet: Scapy packet object
    """
    global running
    if not running:
        return
    
    source_ip, domain_name = parse_dns_packet(packet)
    
    if source_ip and domain_name:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [+] {source_ip} requested {domain_name}")
        log_packet(source_ip, domain_name)


def main():
    """Main function to start DNS packet sniffing"""
    global running
    
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("=" * 60)
    print("The Pocket SOC - DNS Traffic Sniffer")
    print("=" * 60)
    print("[*] Starting DNS traffic monitor on UDP port 53...")
    print("[*] Press Ctrl+C to stop\n")
    
    # Initialize CSV file before starting sniffer
    init_csv()
    
    try:
        # Sniff DNS traffic on UDP port 53
        # filter: UDP port 53 (DNS)
        # prn: callback function for each packet
        # stop_filter: stop when running flag is False
        # store=False: don't store packets in memory (better performance)
        sniff(
            filter="udp port 53",
            prn=dns_packet_handler,
            stop_filter=lambda x: not running,
            store=False
        )
    
    except PermissionError:
        print("[!] Error: Permission denied. Please run as Administrator.")
        print("[!] On Windows, you need administrator privileges to capture packets.")
        sys.exit(1)
    
    except OSError as e:
        if "WinError 10013" in str(e) or "10013" in str(e):
            print("[!] Error: Permission denied. Please run as Administrator.")
            print("[!] On Windows, you need administrator privileges to capture packets.")
        elif "No such device" in str(e) or "couldn't find interface" in str(e).lower():
            print("[!] Error: No network interface found.")
            print("[!] Please ensure you have a network adapter enabled.")
            print("[!] You may need to install Npcap: https://nmap.org/npcap/")
        else:
            print(f"[!] Error: {e}")
        sys.exit(1)
    
    except Scapy_Exception as e:
        print(f"[!] Scapy Error: {e}")
        print("[!] Please ensure Npcap is installed: https://nmap.org/npcap/")
        print("[!] Scapy requires Npcap or WinPcap on Windows.")
        sys.exit(1)
    
    except KeyboardInterrupt:
        signal_handler(None, None)
    
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        print("[!] Please check your network interface and permissions.")
        sys.exit(1)


if __name__ == "__main__":
    # Check if running on Windows
    if sys.platform != "win32":
        print("[!] Warning: This script is optimized for Windows.")
        print("[!] It may work on other platforms, but behavior may differ.\n")
    
    main()