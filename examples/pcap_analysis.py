#!/usr/bin/env python3
"""
JA4+ PCAP Analysis Example

Analyzes a PCAP file with all JA4+ fingerprinters and displays results.

Usage:
    python examples/pcap_analysis.py capture.pcap
"""

import sys
from collections import Counter
from scapy.all import rdpcap
from ja4plus import (
    JA4Fingerprinter,
    JA4SFingerprinter,
    JA4HFingerprinter,
    JA4LFingerprinter,
    JA4XFingerprinter,
    JA4SSHFingerprinter,
    JA4TFingerprinter,
    JA4TSFingerprinter,
)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    fingerprinters = {
        "JA4": JA4Fingerprinter(),
        "JA4S": JA4SFingerprinter(),
        "JA4H": JA4HFingerprinter(),
        "JA4L": JA4LFingerprinter(),
        "JA4X": JA4XFingerprinter(),
        "JA4SSH": JA4SSHFingerprinter(),
        "JA4T": JA4TFingerprinter(),
        "JA4TS": JA4TSFingerprinter(),
    }

    print(f"Loading: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading PCAP: {e}")
        sys.exit(1)

    print(f"Processing {len(packets)} packets...\n")

    for packet in packets:
        for name, fp in fingerprinters.items():
            fp.process_packet(packet)

    for name, fp in fingerprinters.items():
        results = fp.get_fingerprints()
        if results:
            print(f"{name} ({len(results)} fingerprints):")
            counts = Counter(r["fingerprint"] for r in results)
            for fingerprint, count in counts.most_common(10):
                print(f"  {fingerprint}  ({count}x)")
            print()


if __name__ == "__main__":
    main()
