#!/usr/bin/env python3
"""
JA4+ CLI - Command-line interface for network fingerprinting.

Subcommands:
  analyze <pcap_file>  Fingerprint packets in a PCAP file
  live <interface>     Live capture from a network interface
  cert <cert_file>     Fingerprint an X.509 certificate (DER or PEM)
"""

import argparse
import csv
import json
import os
import sys

from ja4plus import __version__
from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter

VALID_TYPES = ["ja4", "ja4s", "ja4h", "ja4l", "ja4t", "ja4ts", "ja4x", "ja4ssh"]

ALL_FINGERPRINTERS = {
    "ja4": JA4Fingerprinter,
    "ja4s": JA4SFingerprinter,
    "ja4h": JA4HFingerprinter,
    "ja4l": JA4LFingerprinter,
    "ja4t": JA4TFingerprinter,
    "ja4ts": JA4TSFingerprinter,
    "ja4x": JA4XFingerprinter,
    "ja4ssh": JA4SSHFingerprinter,
}


def _parse_types(types_str):
    """Parse and validate --types argument. Returns list of type names."""
    types = [t.strip().lower() for t in types_str.split(",") if t.strip()]
    invalid = [t for t in types if t not in VALID_TYPES]
    if invalid:
        print(
            f"Error: invalid fingerprint type(s): {', '.join(invalid)}. "
            f"Valid types: {', '.join(VALID_TYPES)}",
            file=sys.stderr,
        )
        sys.exit(1)
    return types


def _build_fingerprinters(types):
    """Instantiate fingerprinters for the given type names."""
    return {name: ALL_FINGERPRINTERS[name]() for name in types}


def _get_packet_source(packet):
    """Return a source string like src_ip:src_port -> dst_ip:dst_port."""
    try:
        from scapy.all import IP, IPv6, TCP, UDP

        src_ip = dst_ip = ""
        src_port = dst_port = None

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif packet.haslayer(IPv6):
            from scapy.all import IPv6 as IPv6Layer
            src_ip = packet[IPv6Layer].src
            dst_ip = packet[IPv6Layer].dst

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        if src_port is not None:
            return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        elif src_ip:
            return f"{src_ip} -> {dst_ip}"
    except Exception:
        pass
    return "unknown"


def _output_results(results, fmt, writer=None):
    """
    Output a list of (source, type, fingerprint) tuples in the requested format.
    writer is only used for csv format (a csv.writer instance).
    """
    for source, fp_type, fingerprint in results:
        if fmt == "json":
            print(json.dumps({"source": source, "type": fp_type, "fingerprint": fingerprint}))
        elif fmt == "csv":
            writer.writerow([source, fp_type, fingerprint])
        else:  # table
            print(f"{source:<50}  {fp_type:<10}  {fingerprint}")


def cmd_analyze(args):
    """Handle the 'analyze' subcommand."""
    pcap_file = args.pcap_file
    if not os.path.exists(pcap_file):
        print(f"Error: file not found: {pcap_file}", file=sys.stderr)
        sys.exit(1)

    types = _parse_types(args.types) if args.types else list(ALL_FINGERPRINTERS.keys())
    fingerprinters = _build_fingerprinters(types)

    # Set up output
    csv_writer = None
    if args.format == "table":
        print(f"{'Source':<50}  {'Type':<10}  Fingerprint")
        print("-" * 90)
    elif args.format == "csv":
        csv_writer = csv.writer(sys.stdout)
        csv_writer.writerow(["source", "type", "fingerprint"])

    try:
        from scapy.utils import PcapReader
    except ImportError:
        print("Error: scapy is required. Install with: pip install scapy", file=sys.stderr)
        sys.exit(1)

    try:
        with PcapReader(pcap_file) as reader:
            for packet in reader:
                source = _get_packet_source(packet)
                row_batch = []
                for fp_type, fp in fingerprinters.items():
                    try:
                        result = fp.process_packet(packet)
                        if result:
                            row_batch.append((source, fp_type, result))
                    except Exception:
                        pass
                if row_batch:
                    _output_results(row_batch, args.format, csv_writer)
    except FileNotFoundError:
        print(f"Error: file not found: {pcap_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        err = str(e)
        if "not a pcap" in err.lower() or "magic" in err.lower() or "truncated" in err.lower():
            print(f"Error: invalid or corrupt PCAP file: {pcap_file}", file=sys.stderr)
        else:
            print(f"Error reading PCAP file: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_live(args):
    """Handle the 'live' subcommand."""
    if os.geteuid() != 0:
        print(
            "Error: live capture requires root privileges.\n"
            f"Try: sudo ja4plus live {args.interface}",
            file=sys.stderr,
        )
        sys.exit(1)

    types = _parse_types(args.types) if args.types else list(ALL_FINGERPRINTERS.keys())
    fingerprinters = _build_fingerprinters(types)

    csv_writer = None
    if args.format == "table":
        print(f"{'Source':<50}  {'Type':<10}  Fingerprint")
        print("-" * 90)
    elif args.format == "csv":
        csv_writer = csv.writer(sys.stdout)
        csv_writer.writerow(["source", "type", "fingerprint"])

    print(f"Starting live capture on '{args.interface}'... (Ctrl-C to stop)", file=sys.stderr)

    def process_packet(packet):
        source = _get_packet_source(packet)
        row_batch = []
        for fp_type, fp in fingerprinters.items():
            try:
                result = fp.process_packet(packet)
                if result:
                    row_batch.append((source, fp_type, result))
            except Exception:
                pass
        if row_batch:
            _output_results(row_batch, args.format, csv_writer)
            sys.stdout.flush()

    try:
        from scapy.all import sniff
        sniff(
            prn=process_packet,
            iface=args.interface if args.interface != "any" else None,
            store=0,
        )
    except KeyboardInterrupt:
        print("\nCapture stopped.", file=sys.stderr)
    except Exception as e:
        print(f"Error during capture: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_cert(args):
    """Handle the 'cert' subcommand."""
    cert_file = args.cert_file
    if not os.path.exists(cert_file):
        print(f"Error: file not found: {cert_file}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(cert_file, "rb") as f:
            cert_bytes = f.read()
    except OSError as e:
        print(f"Error reading certificate file: {e}", file=sys.stderr)
        sys.exit(1)

    # Handle PEM format: decode to DER
    if cert_bytes.lstrip().startswith(b"-----BEGIN"):
        try:
            from cryptography import x509 as cx509
            from cryptography.hazmat.backends import default_backend

            cert = cx509.load_pem_x509_certificate(cert_bytes, default_backend())
            cert_bytes = cert.public_bytes(
                __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER
            )
        except Exception as e:
            print(f"Error parsing PEM certificate: {e}", file=sys.stderr)
            sys.exit(1)

    fp = JA4XFingerprinter()
    fingerprint = fp.fingerprint_certificate(cert_bytes)

    if fingerprint is None:
        print("Error: could not generate JA4X fingerprint from certificate", file=sys.stderr)
        sys.exit(1)

    source = os.path.basename(cert_file)
    results = [(source, "ja4x", fingerprint)]

    csv_writer = None
    if args.format == "table":
        print(f"{'Source':<50}  {'Type':<10}  Fingerprint")
        print("-" * 90)
    elif args.format == "csv":
        csv_writer = csv.writer(sys.stdout)
        csv_writer.writerow(["source", "type", "fingerprint"])

    _output_results(results, args.format, csv_writer)


def main():
    parser = argparse.ArgumentParser(
        prog="ja4plus",
        description="JA4+ Network Fingerprinting Tool",
    )
    parser.add_argument(
        "--version", action="version", version=f"ja4plus {__version__}"
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--types",
        default=None,
        metavar="TYPES",
        help=f"Comma-separated fingerprint types to include. Valid: {', '.join(VALID_TYPES)}",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    # analyze subcommand
    analyze_parser = subparsers.add_parser(
        "analyze", help="Fingerprint packets in a PCAP file"
    )
    analyze_parser.add_argument("pcap_file", help="Path to the PCAP file")

    # live subcommand
    live_parser = subparsers.add_parser(
        "live", help="Live capture from a network interface"
    )
    live_parser.add_argument("interface", help="Network interface (e.g. eth0, any)")

    # cert subcommand
    cert_parser = subparsers.add_parser(
        "cert", help="Fingerprint an X.509 certificate"
    )
    cert_parser.add_argument("cert_file", help="Path to certificate file (DER or PEM)")

    args = parser.parse_args()

    if args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "live":
        cmd_live(args)
    elif args.command == "cert":
        cmd_cert(args)


if __name__ == "__main__":
    main()
