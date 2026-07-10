"""
Basic Network Sniffer
CodeAlpha Cyber Security Internship
"""

import argparse
import datetime
import os
import sys
from collections import defaultdict
import logging

# Suppress Scapy warning about IPv6 routing
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, wrpcap
except ImportError:
    print("Error: Scapy is not installed. Please run 'pip install -r requirements.txt'")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
except ImportError:
    print("Error: Colorama is not installed. Please run 'pip install -r requirements.txt'")
    sys.exit(1)

# Initialize Colorama for cross-platform color support
init(autoreset=True)

class NetworkSniffer:
    """A basic network packet sniffer."""
    
    def __init__(self, interface: str = None, packet_count: int = 0):
        self.interface = interface
        self.packet_count = packet_count
        self.captured_packets = []
        self.protocol_counts = defaultdict(int)
        self.start_time = None
        self.log_file = "logs/sniffer_log.txt"
        self.pcap_file = "captures/network_capture.pcap"
        
        # Ensure output directories exist
        os.makedirs("logs", exist_ok=True)
        os.makedirs("captures", exist_ok=True)
        
    def log_packet(self, log_msg: str) -> None:
        """Append a log message to the log file."""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_msg + "\n")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to write to log file: {e}{Style.RESET_ALL}")

    def process_packet(self, packet) -> None:
        """Process each captured packet, extract information, and log it."""
        self.captured_packets.append(packet)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        size = len(packet)
        
        protocol = "UNKNOWN"
        src_ip = "N/A"
        dst_ip = "N/A"
        src_port = "N/A"
        dst_port = "N/A"
        payload_preview = ""
        
        if packet.haslayer(ARP):
            protocol = "ARP"
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
        elif packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if packet.haslayer(TCP):
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            else:
                protocol = "IPv4"
                
        self.protocol_counts[protocol] += 1
        
        # Extract a short payload preview if available
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            try:
                # Attempt to decode as ASCII, ignoring errors
                payload_str = raw_data.decode("ascii", errors="ignore").replace("\n", "").replace("\r", "")
                # Keep only printable characters
                payload_str = "".join(c for c in payload_str if 32 <= ord(c) <= 126)
                payload_preview = payload_str[:40] + "..." if len(payload_str) > 40 else payload_str
            except Exception:
                pass
                
        # Determine output color based on protocol
        color = Fore.WHITE
        if protocol == "TCP":
            color = Fore.GREEN
        elif protocol == "UDP":
            color = Fore.BLUE
        elif protocol == "ICMP":
            color = Fore.YELLOW
        elif protocol == "ARP":
            color = Fore.MAGENTA
            
        # Format strings for console and log
        ports_str = f"{src_port} -> {dst_port}" if src_port != "N/A" else "N/A"
        base_msg = f"{protocol:4} | {src_ip} -> {dst_ip} | Ports: {ports_str} | Size: {size} bytes"
        
        output_msg = f"[{timestamp}] {color}{base_msg}{Style.RESET_ALL}"
        log_msg = f"[{timestamp}] {base_msg}"
        
        if payload_preview:
            output_msg += f" | Payload: {payload_preview}"
            log_msg += f" | Payload: {payload_preview}"
            
        print(output_msg)
        self.log_packet(log_msg)

    def start(self) -> None:
        """Start capturing packets."""
        self.start_time = datetime.datetime.now()
        
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}CodeAlpha Basic Network Sniffer{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"[*] Started at: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Interface: {self.interface if self.interface else 'Default (All)'}")
        print(f"[*] Logs path: {self.log_file}")
        print(f"[*] PCAP path: {self.pcap_file}")
        print(f"[*] Press Ctrl+C to stop sniffing.")
        print(f"{Fore.CYAN}{'-'*60}{Style.RESET_ALL}")
        
        # Clear log file at start
        open(self.log_file, "w").close()
        
        try:
            # Prepare sniff arguments
            kwargs = {"prn": self.process_packet, "store": False}
            if self.interface:
                kwargs["iface"] = self.interface
            if self.packet_count > 0:
                kwargs["count"] = self.packet_count
                
            # Begin sniffing (blocking call)
            sniff(**kwargs)
            
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Sniffing stopped by user (Ctrl+C).{Style.RESET_ALL}")
        except PermissionError:
            print(f"\n{Fore.RED}[!] Error: Permission denied.{Style.RESET_ALL}")
            print(f"{Fore.RED}[!] Packet sniffing requires administrative/root privileges.{Style.RESET_ALL}")
            print(f"{Fore.RED}[!] Please run the script as Administrator or with sudo.{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] An unexpected error occurred: {e}{Style.RESET_ALL}")
            if "winpcap is not installed" in str(e).lower():
                print(f"\n{Fore.YELLOW}[*] Windows Dependency Missing:{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}    Scapy requires 'Npcap' to capture packets on Windows.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}    1. Download Npcap from: https://npcap.com/{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}    2. Install it and check the box 'Install Npcap in WinPcap API-compatible Mode'{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}    3. Restart your terminal and run the script again.{Style.RESET_ALL}")
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop the sniffer, show summary, and save pcap."""
        if not self.start_time:
            return
            
        end_time = datetime.datetime.now()
        duration = end_time - self.start_time
        
        print("\n" + "=" * 60)
        print(f"{Fore.GREEN}Sniffing Summary{Style.RESET_ALL}")
        print("=" * 60)
        print(f"Total Capture Duration : {duration}")
        print(f"Total Packets Captured : {sum(self.protocol_counts.values())}")
        print("-" * 60)
        print("Protocol Breakdown:")
        for protocol, count in sorted(self.protocol_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {protocol:6}: {count} packets")
        print("=" * 60)
        
        if self.captured_packets:
            print(f"{Fore.CYAN}[*] Saving captured packets to {self.pcap_file}...{Style.RESET_ALL}")
            try:
                wrpcap(self.pcap_file, self.captured_packets)
                print(f"{Fore.GREEN}[+] Packets successfully saved to {self.pcap_file}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Failed to save PCAP file: {e}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description="CodeAlpha Basic Network Sniffer")
    parser.add_argument("-i", "--interface", type=str, default=None, 
                        help="Network interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=0, 
                        help="Number of packets to capture (default is 0 for infinite)")
    
    args = parser.parse_args()
    
    sniffer = NetworkSniffer(interface=args.interface, packet_count=args.count)
    sniffer.start()

if __name__ == "__main__":
    main()
