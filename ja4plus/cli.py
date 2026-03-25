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
    except (AttributeError, IndexError, TypeError):
        pass
    return "unknown"


def _output_results(results, fmt, writer=None, ja4db_client=None):
    """
    Output a list of (source, type, fingerprint) tuples in the requested format.
    writer is only used for csv format (a csv.writer instance).
    ja4db_client is optional JA4DBClient for fingerprint identification.
    """
    for source, fp_type, fingerprint in results:
        identified = ""
        if ja4db_client:
            match = ja4db_client.lookup(fingerprint)
            if match:
                identified = match.get("application", "")

        if fmt == "json":
            obj = {"source": source, "type": fp_type, "fingerprint": fingerprint}
            if ja4db_client:
                obj["identified_as"] = identified or None
            print(json.dumps(obj))
        elif fmt == "csv":
            row = [source, fp_type, fingerprint]
            if ja4db_client:
                row.append(identified)
            writer.writerow(row)
        else:  # table
            if identified:
                print(f"{source:<50}  {fp_type:<10}  {fingerprint}  ({identified})")
            else:
                print(f"{source:<50}  {fp_type:<10}  {fingerprint}")


def _init_lookup(args):
    """Initialize ja4db client if --lookup is set."""
    if not getattr(args, "lookup", False):
        return None
    try:
        from ja4plus.ja4db import JA4DBClient
        return JA4DBClient()
    except Exception as e:
        print(f"Warning: could not initialize ja4db lookup: {e}", file=sys.stderr)
        return None


def cmd_analyze(args):
    """Handle the 'analyze' subcommand."""
    pcap_file = args.pcap_file
    if not os.path.exists(pcap_file):
        print(f"Error: file not found: {pcap_file}", file=sys.stderr)
        sys.exit(1)

    types = _parse_types(args.types) if args.types else list(ALL_FINGERPRINTERS.keys())
    fingerprinters = _build_fingerprinters(types)
    ja4db_client = _init_lookup(args)

    # Set up output
    csv_writer = None
    if args.format == "table":
        header = f"{'Source':<50}  {'Type':<10}  Fingerprint"
        if ja4db_client:
            header += "  Identified As"
        print(header)
        print("-" * (110 if ja4db_client else 90))
    elif args.format == "csv":
        csv_writer = csv.writer(sys.stdout)
        row = ["source", "type", "fingerprint"]
        if ja4db_client:
            row.append("identified_as")
        csv_writer.writerow(row)

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
                    _output_results(row_batch, args.format, csv_writer, ja4db_client)
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
    ja4db_client = _init_lookup(args)

    csv_writer = None
    if args.format == "table":
        header = f"{'Source':<50}  {'Type':<10}  Fingerprint"
        if ja4db_client:
            header += "  Identified As"
        print(header)
        print("-" * (110 if ja4db_client else 90))
    elif args.format == "csv":
        csv_writer = csv.writer(sys.stdout)
        row = ["source", "type", "fingerprint"]
        if ja4db_client:
            row.append("identified_as")
        csv_writer.writerow(row)

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
            _output_results(row_batch, args.format, csv_writer, ja4db_client)
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
            from cryptography.hazmat.primitives.serialization import Encoding
            cert_bytes = cert.public_bytes(Encoding.DER)
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
    ja4db_client = _init_lookup(args)

    csv_writer = None
    if args.format == "table":
        header = f"{'Source':<50}  {'Type':<10}  Fingerprint"
        if ja4db_client:
            header += "  Identified As"
        print(header)
        print("-" * (110 if ja4db_client else 90))
    elif args.format == "csv":
        csv_writer = csv.writer(sys.stdout)
        row = ["source", "type", "fingerprint"]
        if ja4db_client:
            row.append("identified_as")
        csv_writer.writerow(row)

    _output_results(results, args.format, csv_writer, ja4db_client)


def cmd_db(args):
    """Handle the 'db' subcommand."""
    import csv as csv_mod
    from ja4plus.ja4db import _BUNDLED_CSV, _MAPPING_URL, _load_bundled_db

    if args.db_command == "info":
        db = _load_bundled_db()
        print(f"Database: {_BUNDLED_CSV}")
        print(f"Entries:  {len(db)}")
        if os.path.exists(_BUNDLED_CSV):
            import time
            mtime = os.path.getmtime(_BUNDLED_CSV)
            print(f"Updated:  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))}")
        print(f"Source:   {_MAPPING_URL}")
        return

    # db update
    print(f"Downloading latest fingerprint database from FoxIO...")
    try:
        import urllib.request
        data = urllib.request.urlopen(_MAPPING_URL, timeout=15).read().decode("utf-8")
    except Exception as e:
        print(f"Error: could not download database: {e}", file=sys.stderr)
        sys.exit(1)

    # Validate it's a real CSV with expected headers
    lines = data.strip().split("\n")
    if len(lines) < 2 or "Application" not in lines[0]:
        print("Error: downloaded file does not look like a valid ja4plus-mapping.csv", file=sys.stderr)
        sys.exit(1)

    # Count entries
    reader = csv_mod.DictReader(lines)
    entry_count = sum(1 for row in reader if any(row.get(f, "").strip() for f in ("ja4", "ja4s", "ja4h", "ja4x", "ja4t")))

    # Write to bundled location
    os.makedirs(os.path.dirname(_BUNDLED_CSV), exist_ok=True)
    with open(_BUNDLED_CSV, "w", encoding="utf-8") as f:
        f.write(data)

    print(f"Updated: {entry_count} fingerprint entries written to {_BUNDLED_CSV}")


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
    parser.add_argument(
        "--lookup",
        action="store_true",
        default=False,
        help="Identify fingerprints using ja4db (bundled database + optional remote lookup)",
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

    # db subcommand
    db_parser = subparsers.add_parser(
        "db", help="Manage the fingerprint identification database"
    )
    db_sub = db_parser.add_subparsers(dest="db_command", metavar="ACTION")
    db_sub.required = True
    db_update_parser = db_sub.add_parser("update", help="Download latest fingerprint database from FoxIO")
    db_update_parser.add_argument("--force", action="store_true", help="Update even if already up to date")
    db_sub.add_parser("info", help="Show database location and entry count")

    args = parser.parse_args()

    if args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "live":
        cmd_live(args)
    elif args.command == "cert":
        cmd_cert(args)
    elif args.command == "db":
        cmd_db(args)


if __name__ == "__main__":
    main()
