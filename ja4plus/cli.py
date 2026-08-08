#!/usr/bin/env python3
"""
JA4+ CLI - Command-line interface for network fingerprinting.

Subcommands:
  analyze <pcap_file>  Fingerprint packets in a PCAP file
  live <interface>     Live capture from a network interface
  cert <cert_file>     Fingerprint an X.509 certificate (DER or PEM)
"""

# Python 3.9 is the floor, and it evaluates no annotation written as `str | None`
# without this import.
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ja4plus import __version__
from ja4plus.output import OutputWriter, build_writer
from ja4plus.types import FingerprintResult
from ja4plus.fingerprinters.base import BaseFingerprinter
from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter
from ja4plus.fingerprinters.ja4d import JA4DFingerprinter
from ja4plus.fingerprinters.ja4d6 import JA4D6Fingerprinter

if TYPE_CHECKING:
    # Each command imports scapy and the lookup client where it needs them, so an
    # import at the top would load both for a caller that reads `--version` alone.
    from scapy.packet import Packet

    from ja4plus.ja4db import JA4DBClient

VALID_TYPES = [
    "ja4",
    "ja4s",
    "ja4h",
    "ja4l",
    "ja4t",
    "ja4ts",
    "ja4x",
    "ja4ssh",
    "ja4d",
    "ja4d6",
]

ALL_FINGERPRINTERS: dict[str, type[BaseFingerprinter]] = {
    "ja4": JA4Fingerprinter,
    "ja4s": JA4SFingerprinter,
    "ja4h": JA4HFingerprinter,
    "ja4l": JA4LFingerprinter,
    "ja4t": JA4TFingerprinter,
    "ja4ts": JA4TSFingerprinter,
    "ja4x": JA4XFingerprinter,
    "ja4ssh": JA4SSHFingerprinter,
    "ja4d": JA4DFingerprinter,
    "ja4d6": JA4D6Fingerprinter,
}


def _parse_types(types_str: str) -> list[str]:
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


def _build_fingerprinters(types: list[str]) -> dict[str, BaseFingerprinter]:
    """Instantiate fingerprinters for the given type names."""
    return {name: ALL_FINGERPRINTERS[name]() for name in types}


def _packet_endpoints(packet: Packet) -> tuple[str, int, str, int]:
    """Return the source address, the source port, the destination address and the port.

    FR-structured-output-1 asks every output format to carry the four values as separate
    fields, so the command reads them apart rather than as one string.

    Every packet is hostile input, so a layer this call cannot read produces the empty
    address and the port zero.

    Args:
        packet: The packet to read.

    Returns:
        A tuple of the source address, the source port, the destination address and the
        destination port. The address is empty and the port is zero where the packet
        carries no value.
    """
    src_ip = dst_ip = ""
    src_port = dst_port = 0
    try:
        from scapy.all import IP, IPv6, TCP, UDP

        if packet.haslayer(IP):
            src_ip = str(packet[IP].src)
            dst_ip = str(packet[IP].dst)
        elif packet.haslayer(IPv6):
            src_ip = str(packet[IPv6].src)
            dst_ip = str(packet[IPv6].dst)

        if packet.haslayer(TCP):
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
    except (AttributeError, IndexError, TypeError, ValueError):
        pass
    return src_ip, src_port, dst_ip, dst_port


def _packet_timestamp(packet: Packet) -> datetime | None:
    """Return the time the capture recorded for the packet, or None when it has none.

    `scapy` holds the time as a decimal count of seconds from the epoch, and it names no
    zone. The count is UTC, so the call builds a UTC time.

    Args:
        packet: The packet to read.

    Returns:
        The packet time as a UTC `datetime`, or None when the packet carries no readable
        time.
    """
    seconds = getattr(packet, "time", None)
    if seconds is None:
        return None
    try:
        return datetime.fromtimestamp(float(seconds), tz=timezone.utc)
    except (OSError, OverflowError, TypeError, ValueError):
        return None


def _endpoints_from_connection(connection: str) -> tuple[str, int, str, int]:
    """Return the four endpoint values that a connection key names.

    A window that no packet closes carries the connection key and no packet, so the
    command reads the endpoints back from the key. The key form is
    `<address>:<port>-<address>:<port>`. An IPv6 address holds a colon and no hyphen, so
    the first hyphen separates the two endpoints and the last colon of each half
    separates the port.

    Args:
        connection: The connection key the fingerprinter reported.

    Returns:
        A tuple of the source address, the source port, the destination address and the
        destination port. A key this call cannot read produces empty addresses and the
        port zero.
    """
    first, separator, second = connection.partition("-")
    if not separator:
        return "", 0, "", 0
    src_ip, src_port = _split_endpoint(first)
    dst_ip, dst_port = _split_endpoint(second)
    return src_ip, src_port, dst_ip, dst_port


def _split_endpoint(endpoint: str) -> tuple[str, int]:
    """Return the address and the port that one half of a connection key names.

    Args:
        endpoint: One half of a connection key, such as `172.16.225.48:57377`.

    Returns:
        The address and the port. A half that carries no numeric port returns the whole
        half as the address and the port zero.
    """
    address, separator, port = endpoint.rpartition(":")
    if not separator or not port.isdigit():
        return endpoint, 0
    return address, int(port)


def _close_open_windows(fingerprinters: dict[str, BaseFingerprinter]) -> list[FingerprintResult]:
    """Return one result for every window the fingerprinters hold open.

    Run this function when the packet source ends without an error. JA4SSH is the only
    method that holds a window, and #214 decided that it emits the window a connection
    holds open.

    A read error ends the command with a message and the status 1, and the command
    writes no trailing window then. A partial window that follows an error describes a
    connection the command failed to read.

    Args:
        fingerprinters: The map of method name to fingerprinter that the command built.

    Returns:
        A list of `FingerprintResult`, in the order the fingerprinters emitted them. The
        endpoints read the connection key of the window, because no packet produces
        them. The timestamp is None for the same reason.
    """
    results: list[FingerprintResult] = []
    for fp_type, fp in fingerprinters.items():
        for entry in fp.close_open_windows():
            src_ip, src_port, dst_ip, dst_port = _endpoints_from_connection(
                entry.get("connection", "")
            )
            results.append(
                FingerprintResult(
                    type=fp_type,
                    fingerprint=entry["fingerprint"],
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                )
            )
    return results


def _fingerprint_one_packet(
    packet: Packet, fingerprinters: dict[str, BaseFingerprinter]
) -> list[FingerprintResult]:
    """Return one result for every method that reads a fingerprint from the packet.

    The command reads the endpoints and the time once, because every method that reads
    the same packet reports the same four endpoint values and the same time.

    Args:
        packet: The packet to read.
        fingerprinters: The map of method name to fingerprinter that the command built.

    Returns:
        A list of `FingerprintResult`, in the order the fingerprinters ran. The list is
        empty when the packet produces no fingerprint.
    """
    results: list[FingerprintResult] = []
    src_ip, src_port, dst_ip, dst_port = _packet_endpoints(packet)
    timestamp = _packet_timestamp(packet)
    for fp_type, fp in fingerprinters.items():
        try:
            fingerprint = fp.process_packet(packet)
        except Exception:
            # #51 replaces this silent pass with a diagnostic on standard error.
            continue
        if not fingerprint:
            continue
        results.append(
            FingerprintResult(
                type=fp_type,
                fingerprint=fingerprint,
                raw=getattr(fp, "last_raw", None),
                raw_original_order=getattr(fp, "last_raw_original_order", None),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                timestamp=timestamp,
            )
        )
    return results


def _write_results(
    results: list[FingerprintResult],
    writer: OutputWriter,
    ja4db_client: JA4DBClient | None = None,
) -> None:
    """Write every result to the writer, with the identification the lookup returned.

    Args:
        results: The results to write, in the order the fingerprinters emitted them.
        writer: The writer the `--format` option selected.
        ja4db_client: The lookup client, or None when the user passed no `--lookup`.
    """
    for result in results:
        identified: str | None = None
        if ja4db_client:
            match = ja4db_client.lookup(result.fingerprint)
            if match:
                identified = match.get("application") or None
        writer.write(result, identified)


def _init_lookup(args: argparse.Namespace) -> JA4DBClient | None:
    """Initialize ja4db client if --lookup is set."""
    if not getattr(args, "lookup", False):
        return None
    try:
        from ja4plus.ja4db import JA4DBClient

        return JA4DBClient()
    except Exception as e:
        print(f"Warning: could not initialize ja4db lookup: {e}", file=sys.stderr)
        return None


def cmd_analyze(args: argparse.Namespace) -> None:
    """Handle the 'analyze' subcommand."""
    pcap_file = args.pcap_file
    if not os.path.exists(pcap_file):
        print(f"Error: file not found: {pcap_file}", file=sys.stderr)
        sys.exit(1)

    types = _parse_types(args.types) if args.types else list(ALL_FINGERPRINTERS.keys())
    fingerprinters = _build_fingerprinters(types)
    ja4db_client = _init_lookup(args)

    # FR-structured-output-4 asks for the same columns whatever flags the user passed, so
    # the header reads no flag.
    writer = build_writer(args.format, sys.stdout)
    writer.write_header()

    try:
        from scapy.utils import PcapReader
    except ImportError:
        print("Error: scapy is required. Install with: pip install scapy", file=sys.stderr)
        sys.exit(1)

    try:
        with PcapReader(pcap_file) as reader:
            for packet in reader:
                batch = _fingerprint_one_packet(packet, fingerprinters)
                if batch:
                    _write_results(batch, writer, ja4db_client)
            # The capture ends here, and a connection that never closes still holds a
            # window open. #214 decided that JA4SSH emits that window.
            trailing = _close_open_windows(fingerprinters)
            if trailing:
                _write_results(trailing, writer, ja4db_client)
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


def cmd_live(args: argparse.Namespace) -> None:
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

    # FR-structured-output-4 asks for the same columns whatever flags the user passed, so
    # the header reads no flag.
    writer = build_writer(args.format, sys.stdout)
    writer.write_header()

    print(f"Starting live capture on '{args.interface}'... (Ctrl-C to stop)", file=sys.stderr)

    def process_packet(packet: Packet) -> None:
        batch = _fingerprint_one_packet(packet, fingerprinters)
        if batch:
            _write_results(batch, writer, ja4db_client)
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

    # The capture ends here, and a connection that never closes still holds a window
    # open. #214 decided that JA4SSH emits that window.
    trailing = _close_open_windows(fingerprinters)
    if trailing:
        _write_results(trailing, writer, ja4db_client)
        sys.stdout.flush()


def cmd_cert(args: argparse.Namespace) -> None:
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

    # A certificate file carries no address, no port and no packet time, so the record
    # holds the empty address, the port zero and no time. FR-structured-output-5 asks
    # for a column that is empty rather than absent.
    results = [FingerprintResult(type="ja4x", fingerprint=fingerprint)]
    ja4db_client = _init_lookup(args)

    writer = build_writer(args.format, sys.stdout)
    writer.write_header()
    _write_results(results, writer, ja4db_client)


def cmd_db(args: argparse.Namespace) -> None:
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
    print("Downloading latest fingerprint database from FoxIO...")
    try:
        import urllib.request

        data = urllib.request.urlopen(_MAPPING_URL, timeout=15).read().decode("utf-8")
    except Exception as e:
        print(f"Error: could not download database: {e}", file=sys.stderr)
        sys.exit(1)

    # Validate it's a real CSV with expected headers
    lines = data.strip().split("\n")
    if len(lines) < 2 or "Application" not in lines[0]:
        print(
            "Error: downloaded file does not look like a valid ja4plus-mapping.csv", file=sys.stderr
        )
        sys.exit(1)

    # Count entries
    reader = csv_mod.DictReader(lines)
    entry_count = sum(
        1
        for row in reader
        if any(row.get(f, "").strip() for f in ("ja4", "ja4s", "ja4h", "ja4x", "ja4t"))
    )

    # Write to bundled location
    os.makedirs(os.path.dirname(_BUNDLED_CSV), exist_ok=True)
    with open(_BUNDLED_CSV, "w", encoding="utf-8") as f:
        f.write(data)

    print(f"Updated: {entry_count} fingerprint entries written to {_BUNDLED_CSV}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ja4plus",
        description="JA4+ Network Fingerprinting Tool",
    )
    parser.add_argument("--version", action="version", version=f"ja4plus {__version__}")
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
    analyze_parser = subparsers.add_parser("analyze", help="Fingerprint packets in a PCAP file")
    analyze_parser.add_argument("pcap_file", help="Path to the PCAP file")

    # live subcommand
    live_parser = subparsers.add_parser("live", help="Live capture from a network interface")
    live_parser.add_argument("interface", help="Network interface (e.g. eth0, any)")

    # cert subcommand
    cert_parser = subparsers.add_parser("cert", help="Fingerprint an X.509 certificate")
    cert_parser.add_argument("cert_file", help="Path to certificate file (DER or PEM)")

    # db subcommand
    db_parser = subparsers.add_parser("db", help="Manage the fingerprint identification database")
    db_sub = db_parser.add_subparsers(dest="db_command", metavar="ACTION")
    db_sub.required = True
    db_update_parser = db_sub.add_parser(
        "update", help="Download latest fingerprint database from FoxIO"
    )
    db_update_parser.add_argument(
        "--force", action="store_true", help="Update even if already up to date"
    )
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
