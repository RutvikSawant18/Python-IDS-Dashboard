#!/usr/bin/env python3
"""
The Pocket SOC - DNS Traffic Sniffer
Host-Based DNS Traffic Analyzer for Windows
"""

import sys
import signal
import csv
import os
import requests
import math
from collections import Counter
from datetime import datetime

try:
    from scapy.all import sniff, IP, UDP, DNS
    from scapy.error import Scapy_Exception
except ImportError as e:
    print(f"[!] Error: Scapy is not installed. Please install it using: pip install scapy")
    sys.exit(1)

# Global flag for graceful shutdown
running = True

# Global threat intelligence variables
KNOWN_MALICIOUS_DOMAINS = set()
THREAT_FEED_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global running
    print("\n[!] Shutting down DNS sniffer...")
    running = False
    sys.exit(0)


def load_threat_intelligence():
    """
    Download and parse threat intelligence feed at startup.
    Populates the global KNOWN_MALICIOUS_DOMAINS set.
    """
    global KNOWN_MALICIOUS_DOMAINS
    print("[*] Loading threat intelligence feed...")
    try:
        response = requests.get(THREAT_FEED_URL, timeout=10)
        response.raise_for_status()
        
        # Parse the hosts file format
        # Format: IP address followed by domain names (space or tab separated)
        for line in response.text.splitlines():
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Split by whitespace and skip the IP address (first element)
            parts = line.split()
            if len(parts) > 1:
                # Add all domains after the IP address
                for domain in parts[1:]:
                    # Clean up domain (remove trailing dots, convert to lowercase)
                    domain = domain.rstrip('.').lower()
                    if domain:
                        KNOWN_MALICIOUS_DOMAINS.add(domain)
        
        print(f"[+] Loaded {len(KNOWN_MALICIOUS_DOMAINS)} malicious domains from threat feed")
    except Exception as e:
        print(f"[!] Warning: Failed to load threat intelligence feed: {e}")
        print("[!] Continuing without threat intelligence...")


def calculate_entropy(string):
    """
    Calculate Shannon entropy of a string.
    
    Args:
        string: Input string to calculate entropy for
        s
    Returns:
        float: Shannon entropy score
    """
    if not string:
        return 0.0
    
    # Count character frequencies
    char_counts = Counter(string.lower())
    length = len(string)
    
    # Calculate Shannon entropy
    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def init_csv():
    """
    Initialize CSV file if it doesn't exist.
    Creates traffic_log.csv with headers if the file is missing.
    """
    csv_filename = "traffic_log.csv"
    if not os.path.exists(csv_filename):
        with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Timestamp", "Source IP", "Domain", "Status", "Risk Score"])


def log_packet(source_ip, domain_name, status="", risk_score=""):
    """
    Log packet information to CSV file.
    
    Args:
        source_ip: Source IP address
        domain_name: Domain name that was requested
        status: Threat status of the domain
        risk_score: Risk score for the domain
    """
    csv_filename = "traffic_log.csv"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(csv_filename, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([timestamp, source_ip, domain_name, status, risk_score])
    except Exception as e:
        # Silent fail for CSV logging errors to not interrupt packet capture
        pass


def analyze_domain(domain):
    """
    Analyze a domain for threats using threat intelligence and entropy.
    
    Args:
        domain: Domain name to analyze
        
    Returns:
        tuple: (status, risk_score) where status is a string and risk_score is a float
    """
    global KNOWN_MALICIOUS_DOMAINS
    
    # Normalize domain for comparison
    domain_lower = domain.lower().rstrip('.')
    
    # Check if domain is in known malicious domains
    if domain_lower in KNOWN_MALICIOUS_DOMAINS:
        return ("MALICIOUS", 10.0)
    
    # Calculate entropy
    entropy = calculate_entropy(domain)
    
    # Determine status and risk score based on entropy
    if entropy > 4.0:
        return ("HIGH: DGA", entropy)
    elif entropy > 3.5:
        return ("SUSPICIOUS", entropy)
    else:
        return ("CLEAN", entropy)


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
        # Analyze domain for threats
        status, risk_score = analyze_domain(domain_name)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [+] {source_ip} requested {domain_name} [{status}] (Risk: {risk_score:.2f})")
        log_packet(source_ip, domain_name, status, risk_score)


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
    
    # Load threat intelligence before starting sniffer
    load_threat_intelligence()
    
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