#!/usr/bin/env python3
"""
DEPRECATED: Use the `ja4plus` CLI command instead.
This module is kept for backward compatibility and will be removed in v0.4.0.
Run `ja4plus --help` for usage.
"""
import warnings
warnings.warn(
    "collector.py is deprecated. Use the 'ja4plus' CLI command instead.",
    DeprecationWarning,
    stacklevel=2,
)

import argparse
import json
import sys
import time
import signal
from scapy.all import sniff

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter

# Global variables for signal handling
packet_count = 0
max_packets = 0
start_time = 0
timeout_seconds = 0

def signal_handler(signum, frame):
    """Handle termination signals gracefully"""
    sys.stderr.write("Received signal, shutting down gracefully...\n")
    sys.exit(0)

def main():
    """Main collector function"""
    global packet_count, max_packets, start_time, timeout_seconds

    parser = argparse.ArgumentParser(description="JA4+ Network Fingerprinting Collector")
    parser.add_argument("--interface", "-i", default="any", help="Network interface to capture on")
    parser.add_argument("--filter", "-f", default="tcp or udp", help="BPF filter expression")
    parser.add_argument("--fingerprinters", default="ja4,ja4s,ja4h,ja4t,ja4ts,ja4x,ja4ssh",
                       help="Comma-separated list of fingerprinters to enable")
    parser.add_argument("--max-packets", type=int, default=0,
                       help="Maximum packets to process (0 = unlimited)")
    parser.add_argument("--timeout", type=float, default=0,
                       help="Timeout in seconds (0 = no timeout)")
    parser.add_argument("--output", choices=["json", "text"], default="json",
                       help="Output format")

    args = parser.parse_args()

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Initialize global variables
    max_packets = args.max_packets
    timeout_seconds = args.timeout
    start_time = time.time()

    # Initialize enabled fingerprinters
    available_fingerprinters = {
        "ja4": JA4Fingerprinter(),
        "ja4s": JA4SFingerprinter(),
        "ja4h": JA4HFingerprinter(),
        "ja4t": JA4TFingerprinter(),
        "ja4ts": JA4TSFingerprinter(),
        "ja4x": JA4XFingerprinter(),
        "ja4ssh": JA4SSHFingerprinter()
    }

    enabled_fps = args.fingerprinters.split(",")
    fingerprinters = {}
    for name in enabled_fps:
        name = name.strip()
        if name in available_fingerprinters:
            fingerprinters[name] = available_fingerprinters[name]
        else:
            sys.stderr.write(f"Warning: Unknown fingerprinter '{name}'\n")

    if not fingerprinters:
        sys.stderr.write("Error: No valid fingerprinters enabled\n")
        sys.exit(1)

    def process_packet(packet):
        """Process packet with enabled fingerprinters and output results"""
        global packet_count

        # Check packet limit
        if max_packets > 0 and packet_count >= max_packets:
            return

        # Check timeout
        if timeout_seconds > 0 and (time.time() - start_time) >= timeout_seconds:
            return

        packet_count += 1

        results = {
            "@timestamp": int(time.time() * 1000),  # Elasticsearch expects milliseconds
            "ja4plus": {}
        }

        # Apply each enabled fingerprinter
        for name, fp in fingerprinters.items():
            try:
                fingerprint = fp.process_packet(packet)
                if fingerprint:
                    results["ja4plus"][name] = fingerprint
            except Exception as e:
                sys.stderr.write(f"Error in {name} fingerprinter: {e}\n")

        # Only output if we have fingerprints
        if results["ja4plus"]:
            # Add network metadata - properly extract IP addresses
            try:
                from scapy.all import IP, IPv6

                # Look for IP layer (IPv4 or IPv6)
                if packet.haslayer(IP):
                    ip_layer = packet[IP]
                    results["source"] = {"ip": ip_layer.src}
                    results["destination"] = {"ip": ip_layer.dst}
                elif packet.haslayer(IPv6):
                    ip_layer = packet[IPv6]
                    results["source"] = {"ip": ip_layer.src}
                    results["destination"] = {"ip": ip_layer.dst}
                elif hasattr(packet, "src") and hasattr(packet, "dst"):
                    # Fallback to packet-level src/dst (might be MAC addresses)
                    # Only use if they look like IP addresses
                    src_str = str(packet.src)
                    dst_str = str(packet.dst)
                    if ":" not in src_str or len(src_str.split(":")) <= 4:  # Not a MAC address
                        results["source"] = {"ip": src_str}
                        results["destination"] = {"ip": dst_str}

                # Add port information if available
                from scapy.all import TCP, UDP
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    if "source" in results:
                        results["source"]["port"] = tcp_layer.sport
                    if "destination" in results:
                        results["destination"]["port"] = tcp_layer.dport
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    if "source" in results:
                        results["source"]["port"] = udp_layer.sport
                    if "destination" in results:
                        results["destination"]["port"] = udp_layer.dport

            except Exception as e:
                sys.stderr.write(f"Error extracting network metadata: {e}\n")

            # Add collection metadata
            results["ja4plus"]["interface"] = args.interface
            results["ja4plus"]["filter"] = args.filter
            results["ja4plus"]["collection_timestamp"] = int(time.time() * 1000)

            # Output based on format
            if args.output == "json":
                print(json.dumps(results))
            else:
                print(f"Packet {packet_count}: {results}")

            sys.stdout.flush()

        # Stop if we've reached the packet limit
        if max_packets > 0 and packet_count >= max_packets:
            sys.stderr.write(f"Reached packet limit of {max_packets}, stopping...\n")
            sys.exit(0)

        # Stop if we've reached the timeout
        if timeout_seconds > 0 and (time.time() - start_time) >= timeout_seconds:
            sys.stderr.write(f"Reached timeout of {timeout_seconds} seconds, stopping...\n")
            sys.exit(0)

    try:
        sys.stderr.write(f"Starting JA4+ collection on interface '{args.interface}' with filter '{args.filter}'\n")
        sys.stderr.write(f"Enabled fingerprinters: {', '.join(fingerprinters.keys())}\n")

        # Start sniffing
        sniff(prn=process_packet,
              filter=args.filter,
              iface=args.interface if args.interface != "any" else None,
              store=0)

    except KeyboardInterrupt:
        sys.stderr.write("Interrupted by user\n")
    except Exception as e:
        sys.stderr.write(f"Error during packet capture: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()