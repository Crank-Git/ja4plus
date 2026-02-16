#!/usr/bin/env python3
"""
JA4+ Threat Detection Example

This script demonstrates how to use JA4+ fingerprints for threat detection.
"""

import sys
from scapy.all import rdpcap
from collections import Counter
from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

# Known malicious fingerprints (examples)
SUSPICIOUS_JA4 = [
    "t13d1516h2_8daaf6152771_e5627efa2ab1",  # Known malware C2
    "t12d1516h1_8daaf6152771_e5627efa2ab1",  # Botnet client
]

SUSPICIOUS_JA4S = [
    "t120200_1301_ed86a758ad98",  # Suspicious server
]

def analyze_pcap(pcap_file):
    """Analyze a PCAP file for suspicious fingerprints."""
    print(f"Analyzing {pcap_file} for suspicious traffic...")
    
    # Initialize fingerprinters
    ja4_fp = JA4Fingerprinter()
    ja4s_fp = JA4SFingerprinter()
    
    # Read the PCAP
    packets = rdpcap(pcap_file)
    
    # Counters for stats
    total_packets = len(packets)
    tls_packets = 0
    suspicious_found = 0
    
    # Process packets
    for i, packet in enumerate(packets):
        # Show progress for large PCAPs
        if i % 1000 == 0 and i > 0:
            print(f"Processed {i}/{total_packets} packets...")
        
        # Check client TLS (JA4)
        ja4 = ja4_fp.process_packet(packet)
        if ja4:
            tls_packets += 1
            if ja4 in SUSPICIOUS_JA4:
                suspicious_found += 1
                print(f"[!] Suspicious JA4: {ja4}")
                print(f"    Source: {packet.src}:{packet.sport if hasattr(packet, 'sport') else '?'}")
                print(f"    Destination: {packet.dst}:{packet.dport if hasattr(packet, 'dport') else '?'}")
        
        # Check server TLS (JA4S)
        ja4s = ja4s_fp.process_packet(packet)
        if ja4s:
            if ja4s in SUSPICIOUS_JA4S:
                suspicious_found += 1
                print(f"[!] Suspicious JA4S: {ja4s}")
                print(f"    Source: {packet.src}:{packet.sport if hasattr(packet, 'sport') else '?'}")
                print(f"    Destination: {packet.dst}:{packet.dport if hasattr(packet, 'dport') else '?'}")
    
    # Print summary
    print("\n--- Analysis Summary ---")
    print(f"Total packets: {total_packets}")
    print(f"TLS connections: {len(ja4_fp.get_fingerprints())}")
    print(f"Suspicious connections: {suspicious_found}")
    
    # Return results
    return {
        'total_packets': total_packets,
        'tls_connections': len(ja4_fp.get_fingerprints()),
        'suspicious': suspicious_found
    }

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    
    analyze_pcap(sys.argv[1])

if __name__ == "__main__":
    main() 