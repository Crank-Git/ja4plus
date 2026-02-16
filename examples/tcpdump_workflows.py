#!/usr/bin/env python3
"""
JA4+ tcpdump Integration Workflows

Demonstrates multiple ways to integrate tcpdump with ja4plus fingerprinting:
  - capture: Run tcpdump to save a PCAP, then analyze it
  - pipe:    Stream packets from tcpdump in real-time
  - filters: Print useful BPF filter strings for each fingerprint type
  - analyze: Analyze an existing PCAP file

Usage:
    python examples/tcpdump_workflows.py capture --interface en0 --duration 30 --output capture.pcap
    python examples/tcpdump_workflows.py pipe --interface en0 --filter "tcp port 443"
    python examples/tcpdump_workflows.py filters
    python examples/tcpdump_workflows.py analyze capture.pcap
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
from collections import Counter

from scapy.all import IP, IPv6, TCP, UDP, PcapReader, rdpcap

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter


# BPF filter recipes for each fingerprint type
FILTER_RECIPES = {
    "JA4": {
        "filter": "tcp port 443",
        "description": "TLS Client Hello (outbound HTTPS)",
    },
    "JA4S": {
        "filter": "tcp port 443",
        "description": "TLS Server Hello (inbound HTTPS responses)",
    },
    "JA4H": {
        "filter": "tcp port 80 or tcp port 8080",
        "description": "HTTP requests (plaintext)",
    },
    "JA4T": {
        "filter": "tcp[tcpflags] & (tcp-syn) != 0",
        "description": "TCP SYN packets (client TCP fingerprint)",
    },
    "JA4TS": {
        "filter": "tcp[tcpflags] & (tcp-syn) != 0",
        "description": "TCP SYN-ACK packets (server TCP fingerprint)",
    },
    "JA4SSH": {
        "filter": "tcp port 22",
        "description": "SSH traffic",
    },
    "JA4L": {
        "filter": "tcp[tcpflags] & (tcp-syn) != 0",
        "description": "TCP handshake packets (latency measurement)",
    },
    "JA4X": {
        "filter": "tcp port 443",
        "description": "TLS certificate exchange (X.509 fingerprint)",
    },
}


def build_fingerprinters():
    """Initialize all fingerprinters."""
    return {
        "JA4": JA4Fingerprinter(),
        "JA4S": JA4SFingerprinter(),
        "JA4H": JA4HFingerprinter(),
        "JA4L": JA4LFingerprinter(),
        "JA4X": JA4XFingerprinter(),
        "JA4SSH": JA4SSHFingerprinter(),
        "JA4T": JA4TFingerprinter(),
        "JA4TS": JA4TSFingerprinter(),
    }


def extract_packet_info(packet):
    """Extract src/dst IP and port from a packet."""
    info = {}
    if packet.haslayer(IP):
        info["src_ip"] = packet[IP].src
        info["dst_ip"] = packet[IP].dst
    elif packet.haslayer(IPv6):
        info["src_ip"] = packet[IPv6].src
        info["dst_ip"] = packet[IPv6].dst
    if packet.haslayer(TCP):
        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport
    elif packet.haslayer(UDP):
        info["src_port"] = packet[UDP].sport
        info["dst_port"] = packet[UDP].dport
    return info


def fingerprint_packet(packet, fingerprinters):
    """Run all fingerprinters on a single packet. Returns list of (name, fingerprint)."""
    results = []
    for name, fp in fingerprinters.items():
        try:
            result = fp.process_packet(packet)
            if result:
                results.append((name, result))
        except Exception as e:
            sys.stderr.write(f"Error in {name}: {e}\n")
    return results


def print_summary(fingerprinters):
    """Print fingerprint summary grouped by type."""
    print("\n===== Fingerprint Summary =====")
    total = 0
    for name, fp in fingerprinters.items():
        fingerprints = fp.get_fingerprints()
        if not fingerprints:
            continue
        count = len(fingerprints)
        total += count
        print(f"\n{name} ({count} fingerprints):")
        fp_counter = Counter(f["fingerprint"] for f in fingerprints)
        for value, n in fp_counter.most_common(10):
            print(f"  {value}: {n} occurrences")
        if len(fp_counter) > 10:
            print(f"  ... and {len(fp_counter) - 10} more unique values")
    if total == 0:
        print("\nNo fingerprints found.")
    else:
        print(f"\nTotal fingerprints: {total}")


# ---------------------------------------------------------------------------
# Mode A: capture — run tcpdump, save PCAP, then analyze
# ---------------------------------------------------------------------------

def cmd_capture(args):
    """Run tcpdump to capture packets to a PCAP file, then analyze."""
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        sys.exit("Error: tcpdump not found in PATH. Install it or use 'analyze' mode with an existing PCAP.")

    output = args.output or "capture.pcap"
    cmd = [tcpdump, "-i", args.interface, "-w", output]
    if args.filter:
        cmd.extend(args.filter.split())
    if args.count:
        cmd.extend(["-c", str(args.count)])

    print(f"Starting tcpdump on interface {args.interface} ...")
    print(f"Writing to: {output}")
    if args.duration:
        print(f"Duration: {args.duration}s")
    print("Press Ctrl+C to stop early.\n")

    proc = subprocess.Popen(cmd, stderr=subprocess.PIPE)
    try:
        proc.wait(timeout=args.duration if args.duration else None)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=5)
        print(f"\nCapture duration ({args.duration}s) reached.")
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait(timeout=5)
        print("\nCapture interrupted by user.")

    stderr_out = proc.stderr.read().decode(errors="replace").strip()
    if stderr_out:
        print(f"tcpdump: {stderr_out}")

    if not os.path.exists(output) or os.path.getsize(output) == 0:
        sys.exit("No packets captured.")

    # Analyze the captured file
    print(f"\nAnalyzing {output} ...")
    _analyze_pcap(output)


# ---------------------------------------------------------------------------
# Mode B: pipe — stream packets from tcpdump in real-time
# ---------------------------------------------------------------------------

def cmd_pipe(args):
    """Stream packets from tcpdump stdout and fingerprint in real-time."""
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        sys.exit("Error: tcpdump not found in PATH. Install it or use 'analyze' mode with an existing PCAP.")

    cmd = [tcpdump, "-U", "-w", "-", "-i", args.interface]
    if args.filter:
        cmd.extend(args.filter.split())

    print(f"Piping from tcpdump on interface {args.interface} ...")
    print("Press Ctrl+C to stop.\n")

    fingerprinters = build_fingerprinters()
    packet_count = 0
    stop = False

    def _sighandler(signum, frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _sighandler)
    signal.signal(signal.SIGTERM, _sighandler)

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        reader = PcapReader(proc.stdout)
        for packet in reader:
            if stop:
                break
            packet_count += 1
            results = fingerprint_packet(packet, fingerprinters)
            if results:
                info = extract_packet_info(packet)
                flow = ""
                if "src_ip" in info:
                    flow = f"{info.get('src_ip')}:{info.get('src_port', '?')} -> {info.get('dst_ip')}:{info.get('dst_port', '?')}"
                for name, fp_val in results:
                    print(f"[{name}] {flow}  {fp_val}")
    except EOFError:
        pass
    except Exception as e:
        sys.stderr.write(f"Error reading pcap stream: {e}\n")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    print(f"\nProcessed {packet_count} packets.")
    print_summary(fingerprinters)


# ---------------------------------------------------------------------------
# Mode C: filters — print BPF filter recipes
# ---------------------------------------------------------------------------

def cmd_filters(args):
    """Print useful BPF filter strings for each fingerprint type."""
    print("BPF Filter Recipes for JA4+ Fingerprinting")
    print("=" * 55)
    for name, info in FILTER_RECIPES.items():
        print(f"\n  {name}")
        print(f"    Filter:      {info['filter']}")
        print(f"    Description: {info['description']}")
    print("\nCombined filter for all TLS fingerprints (JA4, JA4S, JA4X):")
    print("  tcp port 443")
    print("\nCombined filter for TCP + TLS fingerprints:")
    print("  tcp")
    print("\nExample tcpdump commands:")
    print('  tcpdump -i en0 -w tls.pcap "tcp port 443"')
    print('  tcpdump -i eth0 -w ssh.pcap "tcp port 22"')
    print('  tcpdump -i any -w syn.pcap "tcp[tcpflags] & (tcp-syn) != 0"')


# ---------------------------------------------------------------------------
# Mode D: analyze — load and fingerprint an existing PCAP
# ---------------------------------------------------------------------------

def cmd_analyze(args):
    """Analyze an existing PCAP file."""
    if not os.path.exists(args.pcap):
        sys.exit(f"Error: file not found: {args.pcap}")
    _analyze_pcap(args.pcap)


def _analyze_pcap(path):
    """Shared helper to load a PCAP and run all fingerprinters."""
    fingerprinters = build_fingerprinters()
    try:
        packets = rdpcap(path)
    except Exception as e:
        sys.exit(f"Error reading PCAP: {e}")

    print(f"Loaded {len(packets)} packets from {path}")

    for packet in packets:
        fingerprint_packet(packet, fingerprinters)

    print_summary(fingerprinters)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="JA4+ tcpdump Integration Workflows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s capture -i en0 --duration 30 -o capture.pcap\n"
            "  %(prog)s pipe -i en0 -f 'tcp port 443'\n"
            "  %(prog)s filters\n"
            "  %(prog)s analyze capture.pcap\n"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # capture
    p_cap = subparsers.add_parser("capture", help="Run tcpdump, save PCAP, then analyze")
    p_cap.add_argument("--interface", "-i", default="any", help="Network interface (default: any)")
    p_cap.add_argument("--duration", "-d", type=int, default=None, help="Capture duration in seconds")
    p_cap.add_argument("--count", "-c", type=int, default=None, help="Max packets to capture")
    p_cap.add_argument("--output", "-o", default="capture.pcap", help="Output PCAP path (default: capture.pcap)")
    p_cap.add_argument("--filter", "-f", default=None, help="BPF filter expression")

    # pipe
    p_pipe = subparsers.add_parser("pipe", help="Real-time pipe from tcpdump")
    p_pipe.add_argument("--interface", "-i", default="any", help="Network interface (default: any)")
    p_pipe.add_argument("--filter", "-f", default=None, help="BPF filter expression")

    # filters
    subparsers.add_parser("filters", help="Print BPF filter recipes for each fingerprint type")

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Analyze an existing PCAP file")
    p_analyze.add_argument("pcap", help="Path to PCAP file")

    args = parser.parse_args()

    commands = {
        "capture": cmd_capture,
        "pipe": cmd_pipe,
        "filters": cmd_filters,
        "analyze": cmd_analyze,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
