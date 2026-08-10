#!/usr/bin/env python3
"""
JA4+ CLI - Command-line interface for network fingerprinting.

Subcommands:
  analyze <pcap_file>  Fingerprint packets in a PCAP file
  watch <interface>    Read packets from a network interface
  live <interface>     An alias of watch
  cert <cert_file>     Fingerprint an X.509 certificate (DER or PEM)
"""

# Python 3.9 is the floor, and it evaluates no annotation written as `str | None`
# without this import.
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import math
import os
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Iterator, TextIO

from ja4plus import __version__
from ja4plus.output import OutputWriter, build_writer
from ja4plus.processor import Processor
from ja4plus.types import FingerprintResult
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter
from ja4plus.watch import (
    CAPTURE_FAILURES,
    DEFAULT_CONNECTION_TIMEOUT,
    DEFAULT_MAX_CONNECTIONS,
    CaptureDropCount,
    Monitor,
    MonitorStats,
    available_interfaces,
    describe_capture_failure,
    read_interface,
    report_statistics,
    stop_on_signal,
    unsupported_platform_message,
    write_statistics,
)

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

# The environment variable that permits the remote lookup. It serves an operator who
# runs a command line another program builds. `features/07-db-enrichment.md` line 50
# states the name, and FR-db-enrichment-5 states the value 1.
_REMOTE_LOOKUP_ENV = "JA4PLUS_DB_LOOKUP"

# The disclosure notice FR-db-enrichment-6 asks for. A fingerprint describes traffic the
# operator observed, so the notice names the third party that reads it and the two ways
# to stop the request. It is one output line, and `_init_lookup` writes it once for
# each run.
_REMOTE_LOOKUP_NOTICE = (
    "Notice: the remote lookup is on. Each fingerprint the bundled mapping file holds "
    "no entry for goes to the lookup service at https://ja4db.com. To stop it, pass no "
    "--lookup-remote option and unset JA4PLUS_DB_LOOKUP."
)


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


def _reporting_order(types: list[str]) -> dict[str, int]:
    """Return the position each method holds in the output, keyed by the method name.

    The processor runs the ten methods in one fixed order, and FR-typed-api-3 states
    that the order is part of the library interface. The command reports the order the
    user asked for instead, so `--types ja4t,ja4` writes the JA4T value first.

    A name the user wrote twice keeps its first position, because version 0.6.0 built a
    dict of fingerprinters and a repeated key kept the position of its first write.
    `--types ja4t,ja4,ja4t` therefore writes the JA4T value first.

    Args:
        types: The method names the user asked for, in the order the user wrote them.

    Returns:
        A dict that maps the method name to its position.
    """
    order: dict[str, int] = {}
    for position, name in enumerate(types):
        order.setdefault(name, position)
    return order


def _select(results: list[FingerprintResult], order: dict[str, int]) -> list[FingerprintResult]:
    """Return the results of the methods the user asked for, in the order the user wrote.

    The processor runs every method whatever `--types` names, so it evicts the
    connections of a method the user filtered out and it reports that method's errors.
    The command therefore selects from the results rather than from the methods.

    Args:
        results: The results one call to the processor produced.
        order: The map `_reporting_order` built.

    Returns:
        A list of `FingerprintResult`. The list is empty when no result names a method
        the user asked for.
    """
    selected = [result for result in results if result.type in order]
    selected.sort(key=lambda result: order[result.type])
    return selected


def _report_errors(errors: list[tuple[str, Exception]]) -> None:
    """Write one line to standard error for every method that raised.

    FR-structured-output-12 asks the command to report a fingerprinter error rather than
    to swallow it. The command writes each error and keeps none. An exception that the
    command kept would hold the error chain of every packet it read, and nothing that
    survives across packets grows without a limit.

    Args:
        errors: The pairs of method name and exception that the processor returned.
    """
    for method, error in errors:
        print(f"Warning: {method} could not read a packet: {error}", file=sys.stderr)


@contextlib.contextmanager
def _result_stream(args: argparse.Namespace) -> Iterator[TextIO]:
    """Yield the stream that carries the results, and close it at the end.

    FR-structured-output-9 gives standard output to the results alone, and
    FR-structured-output-10 lets `--output` send them to a file instead. The behaviour
    rules refuse to overwrite a file that exists, because a run that names the wrong file
    destroys the earlier run.

    The `csv` module ends a row with `\\r\\n`, so the call opens the file with no newline
    translation. A file opened without that argument holds `\\r\\r\\n` on Windows.

    Args:
        args: The parsed command line. It carries `output` and `force`.

    Yields:
        Standard output when the user named no file, and the open file otherwise.

    Raises:
        SystemExit: The file exists and the user passed no `--force`, or the file cannot
            be opened. Both exit with the status 1.
    """
    path: str | None = getattr(args, "output", None)
    if path is None:
        yield sys.stdout
        return
    refusal = f"Error: the output file exists: {path}. Pass --force to overwrite it."
    force = getattr(args, "force", False)
    if os.path.exists(path) and not force:
        print(refusal, file=sys.stderr)
        sys.exit(1)
    try:
        # The mode `x` fails when the file exists, so a file that arrives between the
        # test above and this call is refused too. The mode `w` would overwrite it.
        handle = open(path, "w" if force else "x", encoding="utf-8", newline="")
    except FileExistsError:
        print(refusal, file=sys.stderr)
        sys.exit(1)
    except OSError as error:
        print(f"Error: could not open the output file: {error}", file=sys.stderr)
        sys.exit(1)
    try:
        yield handle
    finally:
        handle.close()


def _exit_on_broken_pipe() -> None:
    """End the run without a traceback after the reader of standard output goes away.

    A command such as `head -1` closes the pipe early. Every later write then raises
    `BrokenPipeError`. The interpreter flushes standard output at exit, and that flush
    raises the error a second time. The call therefore points the file descriptor of
    standard output at the null device first.
    https://docs.python.org/3/library/signal.html#note-on-sigpipe gives this recipe. The
    recipe exits with the status 1. Retrieved 2026-08-08.

    Raises:
        SystemExit: Always, with the status 1.
    """
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError):
        # An in-memory stream that a caller put in place of standard output holds no file
        # descriptor. The interpreter flushes no pipe for such a stream at exit.
        pass
    sys.exit(1)


def _report_no_result(args: argparse.Namespace, count: int) -> None:
    """Write one line to standard error when the table format produced no result.

    The edge-case table of `docs/specs/features/05-structured-output.md` gives this
    message to the table format alone. The `json` format writes nothing for this case and
    the `csv` format writes its header, because a parser reads both.

    Args:
        args: The parsed command line. It carries `format`.
        count: The count of results the run wrote.
    """
    if count == 0 and args.format == "table":
        print("No fingerprint was produced.", file=sys.stderr)


def _close_open_windows(processor: Processor, order: dict[str, int]) -> list[FingerprintResult]:
    """Return one result for every window the processor holds open.

    Run this function when the packet source ends without an error. JA4SSH is the only
    method that holds a window, and #214 decided that it emits the window a connection
    holds open.

    A read error ends the command with a message and the status 1, and the command
    writes no trailing window then. A partial window that follows an error describes a
    connection the command failed to read.

    Args:
        processor: The processor the command built.
        order: The map `_reporting_order` built.

    Returns:
        A list of `FingerprintResult`, in the order the user wrote. The endpoints read
        the connection key of the window, because no packet produces them. The timestamp
        is None for the same reason.
    """
    entries: list[dict[str, Any]] = [
        entry for entry in processor.close_open_windows() if entry["type"] in order
    ]
    entries.sort(key=lambda entry: order[str(entry["type"])])
    results: list[FingerprintResult] = []
    for entry in entries:
        src_ip, src_port, dst_ip, dst_port = _endpoints_from_connection(
            entry.get("connection") or ""
        )
        results.append(
            FingerprintResult(
                type=str(entry["type"]),
                fingerprint=str(entry["fingerprint"]),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
            )
        )
    return results


def _fingerprint_one_packet(
    packet: Packet, processor: Processor, order: dict[str, int]
) -> list[FingerprintResult]:
    """Return one result for every method the user asked for that reads the packet.

    The call writes one line to standard error for every method that raises, and the run
    continues. Version 0.6.0 caught the error and continued without a word.

    The processor sets no timestamp, because it reads no packet timestamp. The command
    adds the time, because the output schema of
    `docs/specs/features/05-structured-output.md` holds a `timestamp` field.

    Args:
        packet: The packet to read.
        processor: The processor the command built.
        order: The map `_reporting_order` built.

    Returns:
        A list of `FingerprintResult`. The list is empty when the packet produces no
        fingerprint of a method the user asked for.
    """
    results, errors = processor.process_packet_with_method_errors(packet)
    _report_errors(errors)
    timestamp = _packet_timestamp(packet)
    return [dataclasses.replace(result, timestamp=timestamp) for result in _select(results, order)]


def _write_results(
    results: list[FingerprintResult],
    writer: OutputWriter,
    ja4db_client: JA4DBClient | None = None,
) -> None:
    """Write every result to the writer, with the identification the lookup returned.

    Args:
        results: The results to write, in the order the fingerprinters emitted them.
        writer: The writer the `--format` option selected.
        ja4db_client: The lookup client, or None when the user passed neither `--lookup`
            nor `--lookup-remote`.
    """
    for result in results:
        identified: str | None = None
        if ja4db_client:
            match = ja4db_client.lookup(result.fingerprint)
            if match:
                identified = match.application or None
        writer.write(result, identified)


def _remote_lookup_permitted(args: argparse.Namespace) -> bool:
    """Report whether the operator permits the remote lookup.

    The option and the environment variable each permit the disclosure, and neither one
    refuses it. FR-db-enrichment-4 states the option and FR-db-enrichment-5 states the
    variable, and both read as a permission. `JA4PLUS_DB_LOOKUP=0` therefore cancels no
    option, and an operator who wants the local lookup passes `--lookup`.

    Args:
        args: The parsed command line.

    Returns:
        True when the operator asks for the remote lookup.
    """
    if getattr(args, "lookup_remote", False):
        return True
    # FR-db-enrichment-5 names the value 1 and names no other value, so `true` and `yes`
    # permit nothing. A privacy gate reads one spelling, because a gate that guesses at a
    # value opens on a value the operator did not intend.
    return os.environ.get(_REMOTE_LOOKUP_ENV) == "1"


def _init_lookup(args: argparse.Namespace) -> JA4DBClient | None:
    """Return the lookup client the options ask for, or None for a run without a lookup.

    The command writes the disclosure notice here, so one run writes it once whatever
    count of fingerprints it looks up. FR-db-enrichment-6 asks for that, and each command
    calls this function once.

    Args:
        args: The parsed command line.

    Returns:
        The client, or None when the operator asks for no lookup.

    Raises:
        SystemExit: The operator asks for the remote lookup and `requests` is absent.
    """
    allow_remote = _remote_lookup_permitted(args)
    # The variable permits the disclosure and asks for no lookup. A run that names no
    # option therefore looks nothing up, and it discloses nothing.
    if not getattr(args, "lookup", False) and not getattr(args, "lookup_remote", False):
        return None

    if allow_remote:
        try:
            import requests  # noqa: F401 - the import measures the package, not a name
        except ImportError:
            print(
                "Error: the remote lookup needs the requests package. "
                "Install it with: pip install ja4plus[lookup]",
                file=sys.stderr,
            )
            sys.exit(1)

    try:
        from ja4plus.ja4db import JA4DBClient

        client = JA4DBClient(allow_remote=allow_remote)
    # The wide catch is the design, and #319 read the site and narrowed nothing. The
    # lookup enriches a result the command already produced, so a client this command
    # cannot build costs the operator a warning and no fingerprint.
    except Exception as e:
        print(f"Warning: could not initialize ja4db lookup: {e}", file=sys.stderr)
        return None

    # The notice follows the client, so a run that builds no client claims no
    # disclosure.
    if allow_remote:
        print(_REMOTE_LOOKUP_NOTICE, file=sys.stderr)
    return client


def cmd_analyze(args: argparse.Namespace) -> None:
    """Handle the 'analyze' subcommand."""
    pcap_file = args.pcap_file
    if not os.path.exists(pcap_file):
        print(f"Error: file not found: {pcap_file}", file=sys.stderr)
        sys.exit(1)

    types = _parse_types(args.types) if args.types else list(VALID_TYPES)
    order = _reporting_order(types)
    # FR-structured-output-11 asks for one processor. The processor runs every method,
    # so the command gets the connection eviction of Epic 3 and the errors of Epic 4.
    processor = Processor()
    ja4db_client = _init_lookup(args)

    try:
        from scapy.utils import PcapReader
    except ImportError:
        print("Error: scapy is required. Install with: pip install scapy", file=sys.stderr)
        sys.exit(1)

    with _result_stream(args) as stream:
        # FR-structured-output-4 asks for the same columns whatever flags the user
        # passed, so the header reads no flag.
        writer = build_writer(args.format, stream)
        writer.write_header()
        count = 0
        try:
            with PcapReader(pcap_file) as reader:
                for packet in reader:
                    batch = _fingerprint_one_packet(packet, processor, order)
                    if batch:
                        _write_results(batch, writer, ja4db_client)
                        count += len(batch)
                # The capture ends here, and a connection that never closes still holds a
                # window open. #214 decided that JA4SSH emits that window.
                trailing = _close_open_windows(processor, order)
                if trailing:
                    _write_results(trailing, writer, ja4db_client)
                    count += len(trailing)
        except FileNotFoundError:
            print(f"Error: file not found: {pcap_file}", file=sys.stderr)
            sys.exit(1)
        except BrokenPipeError:
            # The reader of standard output went away. `main` ends the run quietly, and
            # the catch below would report it as a read error of the capture file.
            raise
        # The wide catch is the design, and #319 read the site and narrowed nothing. The
        # capture reader is `scapy`, which publishes no exception list for a corrupt
        # file. A traceback tells the operator less about a bad capture than this
        # message, so the command reports the failure and exits.
        except Exception as e:
            err = str(e)
            if "not a pcap" in err.lower() or "magic" in err.lower() or "truncated" in err.lower():
                print(f"Error: invalid or corrupt PCAP file: {pcap_file}", file=sys.stderr)
            else:
                print(f"Error reading PCAP file: {e}", file=sys.stderr)
            sys.exit(1)
    _report_no_result(args, count)


def cmd_watch(args: argparse.Namespace) -> None:
    """Handle the `watch` subcommand, and the `live` alias of it.

    The command owns the connection table. It records the connection of every packet it
    reads, and it evicts a connection on the entry count or on the entry age.
    `ja4plus/watch.py` holds the table and the loop. Version 0.6.0 called
    `Processor.cleanup_connection` never, so its monitor grew until the host stopped it.

    The command reads no user identity. It attempts the capture and reads the failure,
    because a Linux host grants `CAP_NET_RAW` without granting the user identity zero.
    Version 0.6.0 read `os.geteuid() != 0` and refused that operator.

    Args:
        args: The parsed command line. It carries `interface`, `max_connections`,
            `connection_timeout` and `bpf`, plus the five output options.
    """
    # `os.geteuid` is absent on Windows, so a check that read it raised `AttributeError`
    # there. FR-live-capture-13 names Linux and macOS, and Windows is out of scope.
    refusal = unsupported_platform_message(sys.platform, args.command)
    if refusal is not None:
        print(refusal, file=sys.stderr)
        sys.exit(1)

    types = _parse_types(args.types) if args.types else list(VALID_TYPES)
    order = _reporting_order(types)
    # FR-structured-output-11 asks for one processor. A monitor runs without an end, so
    # the connection eviction of Epic 3 matters most here.
    processor = Processor()
    ja4db_client = _init_lookup(args)

    with _result_stream(args) as stream:
        # FR-structured-output-4 asks for the same columns whatever flags the user
        # passed, so the header reads no flag.
        writer = build_writer(args.format, stream)
        writer.write_header()

        print(f"Starting live capture on '{args.interface}'... (Ctrl-C to stop)", file=sys.stderr)

        def report(packet: Packet) -> None:
            batch = _fingerprint_one_packet(packet, processor, order)
            if batch:
                _write_results(batch, writer, ja4db_client)
                stream.flush()
                # FR-live-capture-8 asks for the fingerprint count. The monitor counts
                # the packet and the report counts what the packet produced.
                monitor.stats.count_fingerprints(len(batch))

        # FR-live-capture-8 asks for the drop count. The capture attaches
        # the socket it opens to this object, so the `dropped` field reports the
        # `BIOCGSTATS` reading of that socket. #423 owns the reading.
        drop_count = CaptureDropCount()

        monitor = Monitor(
            processor,
            report,
            max_connections=args.max_connections,
            connection_timeout=args.connection_timeout,
            stats=MonitorStats(dropped_source=drop_count),
        )

        try:
            # FR-live-capture-5 and FR-live-capture-6 ask for a clean exit on a signal.
            # The handler sets a flag and the capture reads the flag after each packet
            # and after each poll interval, so the loop finishes the line it writes. A
            # handler that called `sys.exit` would end the run at the point the signal
            # arrived, and that point holds half a line whenever the signal arrives
            # during a write.
            with stop_on_signal() as stop:
                # FR-live-capture-9 asks for the schedule, and FR-live-capture-10 puts
                # the line on standard error. The thread ends when the capture returns,
                # so a monitor that reads a termination signal starts no line after it.
                with report_statistics(monitor.stats, args.stats_interval, sys.stderr):
                    # #320 asks the monitor to stop on an interface that carries no
                    # traffic. `stop_filter` reads a packet, and `stop_requested` reads
                    # the flag after each poll interval, so a quiet interface stops the
                    # monitor too.
                    read_interface(
                        args.interface,
                        monitor.handle_packet,
                        stop.stop_after,
                        capture_filter=args.bpf,
                        stop_requested=stop.requested,
                        drop_count=drop_count,
                    )
            if stop.requested():
                print("\nCapture stopped.", file=sys.stderr)
        except KeyboardInterrupt:
            print("\nCapture stopped.", file=sys.stderr)
        except BrokenPipeError:
            # The reader of standard output went away. `main` ends the run quietly, and
            # the catch below would report it as a capture error. `BrokenPipeError`
            # inherits `OSError`, so this clause must precede the capture clause.
            raise
        except CAPTURE_FAILURES as error:
            # FR-live-capture-12 asks for a clear error. The command attempts the
            # capture and reads the failure, so a host that grants the privilege through
            # a capability is not refused on its user identity.
            print(
                describe_capture_failure(
                    error,
                    interface=args.interface,
                    command=args.command,
                    capture_filter=args.bpf,
                    interfaces=available_interfaces(),
                ),
                file=sys.stderr,
            )
            sys.exit(1)
        # The wide catch is the design, and #319 read the site and narrowed nothing. The
        # capture layer raises one of `CAPTURE_FAILURES`, which the clause above names,
        # so this clause reads a failure of the report path. No case reaches it, because
        # this host grants no capture socket, and the reading rests on the code alone.
        except Exception as e:
            print(f"Error during capture: {e}", file=sys.stderr)
            sys.exit(1)

        # The capture ends here, and a connection that never closes still holds a window
        # open. #214 decided that JA4SSH emits that window.
        trailing = _close_open_windows(processor, order)
        if trailing:
            _write_results(trailing, writer, ja4db_client)
            # The exit summary reports every fingerprint the command wrote, and the
            # trailing window is a fingerprint the command wrote.
            monitor.stats.count_fingerprints(len(trailing))

        # FR-live-capture-7 asks for a flush before the exit. The stream holds a buffer,
        # and the operator reads the file of a monitor that runs for weeks. A flush that
        # the interpreter runs at shutdown reaches no reader of a running monitor, and it
        # reaches no file after a host kills the process.
        stream.flush()

        # FR-live-capture-8 asks for statistics on exit. The line follows the flush, so
        # the counts it reports describe output the operator can already read.
        write_statistics(monitor.stats, sys.stderr)


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
        # The wide catch is the design, and #319 read the site and narrowed nothing. The
        # command reports the failure to the operator and exits, where the library form
        # of the same read returns nothing. `compute_ja4x_from_pem` of `ja4plus/__init__`
        # holds that form, and #319 narrowed it.
        except Exception as e:
            print(f"Error parsing PEM certificate: {e}", file=sys.stderr)
            sys.exit(1)

    fp = JA4XFingerprinter()
    fingerprint = fp.fingerprint_certificate(cert_bytes)

    if fingerprint is None:
        print("Error: could not generate JA4X fingerprint from certificate", file=sys.stderr)
        sys.exit(1)

    # A certificate file carries no address, no port and no packet time, so the output
    # line holds the empty address, the port zero and no time. FR-structured-output-5 asks
    # for a column that is empty rather than absent.
    results = [FingerprintResult(type="ja4x", fingerprint=fingerprint)]
    ja4db_client = _init_lookup(args)

    with _result_stream(args) as stream:
        writer = build_writer(args.format, stream)
        writer.write_header()
        _write_results(results, writer, ja4db_client)


def cmd_db(args: argparse.Namespace) -> None:
    """Handle the 'db' subcommand."""
    import csv as csv_mod
    from ja4plus.ja4db import _MAPPING_URL, cache_dir_path, cache_file_path, load_mapping_file

    if args.db_command == "info":
        db, source, path = load_mapping_file()
        # `Source` names the file the client reads, and `Mapping` names the file FoxIO
        # publishes. An earlier form wrote the FoxIO address on the `Source` line, and
        # `features/07-db-enrichment.md` gives that word one other meaning.
        print(f"Source:   {source}")
        print(f"Path:     {path}")
        print(f"Entries:  {len(db)}")
        if os.path.exists(path):
            import time

            mtime = os.path.getmtime(path)
            print(f"Updated:  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))}")
        print(f"Mapping:  {_MAPPING_URL}")
        if source != "cache":
            # The `Screens & states` table of `features/07-db-enrichment.md` names three
            # states, and a cache file that the client read no entry from is the third.
            # A hint that names no cache file would contradict the file on disk.
            cache_file = cache_file_path()
            if os.path.exists(cache_file):
                print(f"\nThe cache file at {cache_file} holds no entry.")
                print("Run `ja4plus db update` to write it again.")
            else:
                # `runDBInfo` of `cmd/ja4plus/main.go:389` prints the same hint.
                print(f"\nNo cache file at {cache_file}")
                print("Run `ja4plus db update` to download the latest from FoxIO.")
        return

    # db update
    # FR-structured-output-9 keeps standard output for results. This line reports
    # progress, so a person reads it and a pipe does not.
    print("Downloading latest fingerprint database from FoxIO...", file=sys.stderr)
    try:
        import urllib.request

        data = urllib.request.urlopen(_MAPPING_URL, timeout=15).read().decode("utf-8")
    # The wide catch is the design, and #319 read the site and narrowed nothing.
    # `urlopen` raises `URLError`, `HTTPError`, `OSError`, `ValueError` and
    # `UnicodeDecodeError` for the cases here, and a proxy or a TLS failure of the host
    # adds more. The command reports the failure to the operator and exits.
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

    # FR-db-enrichment-12 keeps the write outside the installed package. A package
    # directory may be read-only, several users may share it, and the next `pip install`
    # replaces it.
    cache_dir = cache_dir_path()
    cache_file = cache_file_path()
    try:
        os.makedirs(cache_dir, exist_ok=True)
    except OSError as e:
        print(f"Error: could not create the cache directory {cache_dir}: {e}", file=sys.stderr)
        sys.exit(1)

    # A reader of the cache file sees the file the last run wrote, or the whole new file,
    # and never a part of one. `runDBUpdate` of `cmd/ja4plus/main.go:352` renames the same
    # way.
    partial = cache_file + ".tmp"
    try:
        with open(partial, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(partial, cache_file)
    except OSError as e:
        if os.path.exists(partial):
            os.remove(partial)
        print(f"Error: could not write {cache_file}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Updated: {entry_count} fingerprint entries written to {cache_file}")


def _max_connections(value: str) -> int:
    """Return the maximum connection count the user stated.

    A table that holds fewer than one connection tracks nothing, and `BoundedStateTable`
    raises `ValueError` for it. The command reports the refusal instead of a traceback.

    Args:
        value: The text the user wrote after `--max-connections`.

    Returns:
        The count as an integer.

    Raises:
        argparse.ArgumentTypeError: The text is no integer, or it is below one.
    """
    try:
        count = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"--max-connections needs a whole number, and it is {value}"
        )
    if count < 1:
        raise argparse.ArgumentTypeError(f"--max-connections must be 1 or more, and it is {count}")
    return count


def _connection_timeout(value: str) -> float:
    """Return the maximum connection age the user stated, in seconds.

    Args:
        value: The text the user wrote after `--connection-timeout`.

    Returns:
        The age as a count of seconds.

    Raises:
        argparse.ArgumentTypeError: The text is no number, or it is below zero. A
            negative age evicts every connection on the first pass.
    """
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"--connection-timeout needs a number, and it is {value}")
    if seconds < 0:
        raise argparse.ArgumentTypeError(
            f"--connection-timeout must be 0 or more, and it is {seconds}"
        )
    return seconds


def _stats_interval(value: str) -> float:
    """Return the statistics interval the user stated, in seconds.

    Args:
        value: The text the user wrote after `--stats-interval`.

    Returns:
        The interval as a count of seconds.

    Raises:
        argparse.ArgumentTypeError: The text is no number, or it is 0 or less, or it is
            no finite number. An interval of zero writes a statistics line without an
            end. `Event.wait` returns at once for `nan`, which writes a line without an
            end, and it raises `OverflowError` for `inf`, which ends the statistics
            thread and leaves the monitor running.
    """
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"--stats-interval needs a number, and it is {value}")
    if not math.isfinite(seconds):
        raise argparse.ArgumentTypeError(
            f"--stats-interval needs a finite number, and it is {value}"
        )
    if seconds <= 0:
        raise argparse.ArgumentTypeError(
            f"--stats-interval must be more than 0, and it is {seconds}"
        )
    return seconds


def _add_output_options(parser: argparse.ArgumentParser, *, defaults: bool) -> None:
    """Add the five options that every result-producing subcommand accepts.

    The main parser carries these options, and each result-producing subparser carries
    them again. The acceptance criteria of #52 write them after the subcommand name, as
    in `ja4plus analyze capture.pcap --output out.json --force`, and version 0.6.0
    accepted them before it.

    A subparser default overwrites the value the main parser already parsed, so a
    subparser sets `argparse.SUPPRESS` and writes nothing when the user names no option.

    Args:
        parser: The parser to add the options to.
        defaults: True for the main parser, which holds the real default of each option.
            False for a subparser, which holds `argparse.SUPPRESS` instead.
    """

    def default(value: Any) -> Any:
        return value if defaults else argparse.SUPPRESS

    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default=default("table"),
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--types",
        default=default(None),
        metavar="TYPES",
        help=f"Comma-separated fingerprint types to include. Valid: {', '.join(VALID_TYPES)}",
    )
    parser.add_argument(
        "--lookup",
        action="store_true",
        default=default(False),
        # #57 made the remote lookup opt-in at the client, so this option reads the
        # bundled mapping file and reaches no network.
        help="Identify fingerprints from the bundled database. It makes no network request",
    )
    parser.add_argument(
        "--lookup-remote",
        action="store_true",
        default=default(False),
        # The option asks for the lookup and for the disclosure, so an operator who
        # passes it needs no `--lookup` as well.
        help=(
            "Identify fingerprints, and send each one the bundled database holds no "
            "entry for to https://ja4db.com"
        ),
    )
    parser.add_argument(
        "--output",
        default=default(None),
        metavar="FILE",
        help="Write the results to FILE instead of standard output",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        default=default(False),
        help="Overwrite the file that --output names when it exists",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ja4plus",
        description="JA4+ Network Fingerprinting Tool",
    )
    parser.add_argument("--version", action="version", version=f"ja4plus {__version__}")
    _add_output_options(parser, defaults=True)

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    # analyze subcommand
    analyze_parser = subparsers.add_parser("analyze", help="Fingerprint packets in a PCAP file")
    analyze_parser.add_argument("pcap_file", help="Path to the PCAP file")
    _add_output_options(analyze_parser, defaults=False)

    # watch subcommand, and the live alias FR-live-capture-14 keeps. One parser serves
    # both names, so the two accept the same options and behave the same way.
    watch_parser = subparsers.add_parser(
        "watch", aliases=["live"], help="Read packets from a network interface"
    )
    watch_parser.add_argument("interface", help="Network interface (e.g. eth0, any)")
    watch_parser.add_argument(
        "--max-connections",
        type=_max_connections,
        default=DEFAULT_MAX_CONNECTIONS,
        metavar="COUNT",
        help=(
            "Maximum number of tracked connections "
            f"(default: {DEFAULT_MAX_CONNECTIONS}). When the table is full, the "
            "monitor evicts the least recently used connection."
        ),
    )
    watch_parser.add_argument(
        "--connection-timeout",
        type=_connection_timeout,
        default=DEFAULT_CONNECTION_TIMEOUT,
        metavar="SECONDS",
        help=(
            "Maximum age of a connection that sends no packet, in seconds "
            f"(default: {int(DEFAULT_CONNECTION_TIMEOUT)})"
        ),
    )
    watch_parser.add_argument(
        "--stats-interval",
        type=_stats_interval,
        default=None,
        metavar="SECONDS",
        help=(
            "Write a statistics line to standard error every SECONDS seconds "
            "(default: no schedule). The monitor writes one statistics line on exit "
            "whether or not this option is given."
        ),
    )
    watch_parser.add_argument(
        "--bpf",
        default=None,
        metavar="FILTER",
        help=(
            "Capture filter, in Berkeley Packet Filter syntax "
            "(for example 'tcp port 443'). The capture layer drops every packet the "
            "filter rejects, so the monitor never reads it."
        ),
    )
    _add_output_options(watch_parser, defaults=False)

    # cert subcommand
    cert_parser = subparsers.add_parser("cert", help="Fingerprint an X.509 certificate")
    cert_parser.add_argument("cert_file", help="Path to certificate file (DER or PEM)")
    _add_output_options(cert_parser, defaults=False)

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

    try:
        if args.command == "analyze":
            cmd_analyze(args)
        elif args.command in ("watch", "live"):
            cmd_watch(args)
        elif args.command == "cert":
            cmd_cert(args)
        elif args.command == "db":
            cmd_db(args)
        # The flush belongs inside the guard, so a pipe that closed early raises here
        # rather than during the flush the interpreter runs at exit.
        sys.stdout.flush()
    except BrokenPipeError:
        _exit_on_broken_pipe()


if __name__ == "__main__":
    main()
