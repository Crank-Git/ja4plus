#!/usr/bin/env python3
"""
JA4+ Live Traffic Fingerprinting Example

This script demonstrates how to use JA4+ for live traffic analysis.
"""

from scapy.all import sniff
from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter
import argparse
import sys

def main():
    """Run the live traffic fingerprinting example."""
    parser = argparse.ArgumentParser(description="JA4+ Live Traffic Fingerprinting")
    parser.add_argument("--interface", "-i", help="Network interface to capture on")
    parser.add_argument("--filter", "-f", default="tcp or udp", 
                      help="BPF filter (default: 'tcp or udp')")
    parser.add_argument("--count", "-c", type=int, default=0,
                      help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--verbose", "-v", action="store_true",
                      help="Show verbose output for each packet")
    args = parser.parse_args()
    
    # Initialize fingerprinters
    fingerprinters = {
        'JA4': JA4Fingerprinter(),
        'JA4S': JA4SFingerprinter(),
        'JA4H': JA4HFingerprinter(),
        'JA4L': JA4LFingerprinter(),
        'JA4X': JA4XFingerprinter(),
        'JA4SSH': JA4SSHFingerprinter(),
        'JA4T': JA4TFingerprinter(),
        'JA4TS': JA4TSFingerprinter()
    }
    
    # Initialize global fingerprints list
    global fingerprints
    fingerprints = []
    
    # Process packets
    print(f"Starting packet capture on {args.interface or 'default interface'}.")
    print(f"Filter: {args.filter}")
    print("Press Ctrl+C to stop.")
    
    try:
        # Sniff packets
        sniff(prn=lambda pkt: process_packet(pkt, fingerprinters, args.verbose), 
              filter=args.filter, 
              store=0,
              iface=args.interface,
              count=args.count)
    except KeyboardInterrupt:
        print("\nStopping capture...")
    except Exception as e:
        print(f"\nError during capture: {e}")
    
    # Display results
    display_results(fingerprinters)

def process_packet(packet, fingerprinters, verbose=False):
    """Process a packet with all fingerprinters"""
    global fingerprints
    results = []
    
    for name, fingerprinter in fingerprinters.items():
        result = fingerprinter.process_packet(packet)
        if result:
            if verbose:
                if name in ['JA4T', 'JA4TS'] and hasattr(packet, 'haslayer') and packet.haslayer('TCP'):
                    flags = packet['TCP'].flags
                    window = packet['TCP'].window
                    print(f"{name}: {result} (TCP Flags: {flags}, Window: {window})")
                else:
                    print(f"{name}: {result}")
            results.append((name, result))
            fingerprints.append((name, result))
    
    # Only print if we found something and verbose is enabled
    if results and verbose:
        src = packet.src if hasattr(packet, 'src') else "?"
        dst = packet.dst if hasattr(packet, 'dst') else "?"
        print(f"{src} → {dst}: {results}")
    
    return results

def display_results(fingerprinters):
    """Display all collected fingerprints"""
    print("\n===== Results =====")
    for name, fingerprinter in fingerprinters.items():
        fingerprints = fingerprinter.get_fingerprints()
        if fingerprints:
            print(f"\n{name} Fingerprints ({len(fingerprints)}):")
            
            # Group fingerprints by value for more compact display
            fp_values = {}
            for fp in fingerprints:
                value = fp['fingerprint']
                if value in fp_values:
                    fp_values[value] += 1
                else:
                    fp_values[value] = 1
            
            # Display unique fingerprints with counts
            for i, (value, count) in enumerate(sorted(fp_values.items(), 
                                              key=lambda x: x[1], reverse=True)):
                if i < 10:  # Show top 10
                    if name in ['JA4T', 'JA4TS']:
                        example_packet = next(fp for fp in fingerprints 
                                           if fp['fingerprint'] == value)['packet']
                        if hasattr(example_packet, 'haslayer') and example_packet.haslayer('TCP'):
                            flags = example_packet['TCP'].flags
                            window = example_packet['TCP'].window
                            print(f"  {i+1}. {value} ({count} occurrences) - TCP Flags: {flags}, Window: {window}")
                            continue
                    print(f"  {i+1}. {value} ({count} occurrences)")
                
            if len(fp_values) > 10:
                print(f"  ... and {len(fp_values) - 10} more unique patterns")

if __name__ == "__main__":
    main() 