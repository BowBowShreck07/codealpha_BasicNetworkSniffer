#!/usr/bin/env python3
"""
Task 1: Basic Network Sniffer
CodeAlpha Cybersecurity Internship
Author: Aswin
Description: Captures and analyzes network packets using Scapy
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw
from datetime import datetime
import argparse
import sys
import os

# ── Colours for terminal output ──────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

packet_count = 0

def print_banner():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════╗
║        CodeAlpha — Network Sniffer           ║
║         Task 1 | Cybersecurity Intern        ║
╚══════════════════════════════════════════════╝
{RESET}""")

def get_protocol_name(proto_num: int) -> str:
    protocols = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 89: "OSPF"}
    return protocols.get(proto_num, f"PROTO-{proto_num}")

def analyse_packet(packet):
    global packet_count
    packet_count += 1
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # ── Layer 3: IP ───────────────────────────────────────────────────────────
    if packet.haslayer(IP):
        ip   = packet[IP]
        src  = ip.src
        dst  = ip.dst
        proto = get_protocol_name(ip.proto)
        ttl  = ip.ttl
        size = len(packet)

        # ── TCP ───────────────────────────────────────────────────────────────
        if packet.haslayer(TCP):
            tcp   = packet[TCP]
            sport = tcp.sport
            dport = tcp.dport
            flags = tcp.flags

            flag_str = ""
            if flags & 0x02: flag_str += "SYN "
            if flags & 0x10: flag_str += "ACK "
            if flags & 0x01: flag_str += "FIN "
            if flags & 0x04: flag_str += "RST "
            if flags & 0x08: flag_str += "PSH "
            flag_str = flag_str.strip() or "NONE"

            # Colour by well-known port
            colour = GREEN
            label  = "TCP"
            if dport in (80, 8080) or sport in (80, 8080):
                colour, label = YELLOW, "HTTP"
            elif dport in (443, 8443) or sport in (443, 8443):
                colour, label = GREEN,  "HTTPS"
            elif dport == 22 or sport == 22:
                colour, label = CYAN,   "SSH"
            elif dport == 21 or sport == 21:
                colour, label = BLUE,   "FTP"
            elif dport == 25 or sport == 25:
                colour, label = RED,    "SMTP"
            elif dport == 3306 or sport == 3306:
                colour, label = RED,    "MySQL"

            print(f"{colour}[{timestamp}] [{label}] {src}:{sport} → {dst}:{dport} | "
                  f"Flags: {flag_str} | TTL: {ttl} | Size: {size}B{RESET}")

            # Show raw payload (first 80 chars) for HTTP
            if label == "HTTP" and packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors="replace")[:80]
                print(f"  {YELLOW}Payload: {payload}{RESET}")

        # ── UDP ───────────────────────────────────────────────────────────────
        elif packet.haslayer(UDP):
            udp   = packet[UDP]
            sport = udp.sport
            dport = udp.dport

            colour, label = BLUE, "UDP"
            if dport == 53 or sport == 53:
                colour, label = CYAN, "DNS"
            elif dport == 67 or dport == 68:
                colour, label = YELLOW, "DHCP"

            print(f"{colour}[{timestamp}] [{label}] {src}:{sport} → {dst}:{dport} | "
                  f"TTL: {ttl} | Size: {size}B{RESET}")

            # Show DNS query name
            if label == "DNS" and packet.haslayer(DNSQR):
                qname = packet[DNSQR].qname.decode(errors="replace")
                print(f"  {CYAN}Query: {qname}{RESET}")

        # ── ICMP ──────────────────────────────────────────────────────────────
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            icmp_types = {0: "Echo Reply", 3: "Dest Unreachable",
                          8: "Echo Request", 11: "Time Exceeded"}
            icmp_label = icmp_types.get(icmp.type, f"Type-{icmp.type}")
            print(f"{RED}[{timestamp}] [ICMP] {src} → {dst} | "
                  f"{icmp_label} | TTL: {ttl} | Size: {size}B{RESET}")

        # ── Other IP protocols ────────────────────────────────────────────────
        else:
            print(f"[{timestamp}] [{proto}] {src} → {dst} | "
                  f"TTL: {ttl} | Size: {size}B")

    # ── Layer 2: ARP ──────────────────────────────────────────────────────────
    elif packet.haslayer(ARP):
        arp = packet[ARP]
        op  = "REQUEST" if arp.op == 1 else "REPLY"
        print(f"{YELLOW}[{timestamp}] [ARP-{op}] {arp.psrc} ({arp.hwsrc}) "
              f"→ {arp.pdst} ({arp.hwdst}){RESET}")

    # Print packet separator every 20 packets
    if packet_count % 20 == 0:
        print(f"\n{BOLD}{'─'*60}  [{packet_count} packets captured]{RESET}\n")


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="CodeAlpha Network Sniffer")
    parser.add_argument("-i", "--iface",   default=None,  help="Network interface (e.g. eth0, wlan0)")
    parser.add_argument("-c", "--count",   type=int, default=0, help="Number of packets to capture (0=unlimited)")
    parser.add_argument("-f", "--filter",  default="",    help="BPF filter string (e.g. 'tcp port 80')")
    parser.add_argument("-v", "--verbose", action="store_true",  help="Show all packet layers")
    args = parser.parse_args()

    iface_msg = args.iface if args.iface else "all interfaces"
    count_msg = str(args.count) if args.count else "unlimited"

    print(f"{BOLD}Interface : {iface_msg}")
    print(f"Capture   : {count_msg} packets")
    print(f"Filter    : '{args.filter}' " if args.filter else "Filter    : none")
    print(f"{RESET}")
    print(f"Listening… (Ctrl+C to stop)\n{'─'*60}\n")

    try:
        sniff(
            iface=args.iface,
            prn=analyse_packet,
            count=args.count,
            filter=args.filter,
            store=False,
        )
    except KeyboardInterrupt:
        print(f"\n\n{BOLD}{GREEN}Capture stopped.{RESET}")
        print(f"{BOLD}Total packets captured: {packet_count}{RESET}\n")
    except PermissionError:
        print(f"\n{RED}[ERROR] Root/administrator privileges required.{RESET}")
        print("Run with: sudo python3 task1_network_sniffer.py")
        sys.exit(1)


if __name__ == "__main__":
    if os.name != "nt" and os.geteuid() != 0:
        print(f"{YELLOW}[WARNING] Not running as root — packet capture may fail.{RESET}\n")
    main()