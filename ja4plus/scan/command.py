"""Run the `ja4plus scan` subcommand.

`ja4plus/cli.py` holds the options of the subcommand and loads `run` through the
`ja4plus.commands` entry point, so the command-line program imports no module of this
package. `docs/specs/features/12-active-scan.md` states the command.

The command reads every target and opens the socket before it writes the firewall rules.
A target it cannot read or a privilege the host refuses therefore stops the scan before
the first SYN.
"""

from __future__ import annotations

import argparse
import itertools
import random
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from typing import NoReturn, Protocol, TextIO

from ja4plus.output import build_writer
from ja4plus.scan.link import LinkNetwork, privilege_refused
from ja4plus.scan.scanner import Scanner, ScanResult, TargetError, firewall_rules, parse_targets
from ja4plus.types import FingerprintResult
from ja4plus.watch import CAPTURE_FAILURES, unsupported_platform_message

__all__ = ["METHOD_TYPE", "run", "scan_command"]

# FR-active-scan-17 names this `type` value.
METHOD_TYPE = "ja4tscan"

ResultStream = Callable[[argparse.Namespace], AbstractContextManager[TextIO]]


class Network(Protocol):
    """The send function, the receive function and the close call of one scan."""

    def send(self, target: str, src_port: int, sequence: int) -> str | None: ...

    def receive(self, timeout: float) -> tuple[float, bytes] | None: ...

    def close(self) -> None: ...


OpenNetwork = Callable[[int, str, Callable[[str], None]], Network]


def to_fingerprint_result(result: ScanResult) -> FingerprintResult:
    """Return the structured output record of one scan result.

    `docs/specs/features/12-active-scan.md` names the target as the source, because the
    target sent the responses the value reads.

    Args:
        result: The value of one target.
    """
    return FingerprintResult(
        type=METHOD_TYPE,
        fingerprint=result.value,
        src_ip=result.src_ip,
        src_port=result.src_port,
        dst_ip=result.dst_ip,
        dst_port=result.dst_port,
        timestamp=datetime.fromtimestamp(result.seconds, tz=timezone.utc),
    )


def _fail(message: str) -> NoReturn:
    """Write one error message to standard error and exit with the status 1."""
    print(message, file=sys.stderr)
    sys.exit(1)


def _warn(line: str) -> None:
    """Write one warning line to standard error."""
    print(line, file=sys.stderr)


def scan_command(
    args: argparse.Namespace,
    *,
    result_stream: ResultStream,
    platform: str,
    open_network: OpenNetwork,
    clock: Callable[[], float],
    rng: random.Random | None = None,
) -> None:
    """Scan the targets that the command line names, and write one result for each.

    Args:
        args: The parsed command line. It carries `target`, `port`, `rate`,
            `retransmit`, `format`, `output` and `force`.
        result_stream: The context manager of `ja4plus/cli.py` that opens the result
            stream and refuses a file that exists.
        platform: The value of `sys.platform` on this host.
        open_network: The function that opens the network. It takes the port, the first
            target and the warning function.
        clock: The function that returns the time the wait reads, in seconds.
        rng: The source of the source port and the sequence number.

    Raises:
        SystemExit: The call exits with the status 1 before the first SYN in four cases.

            - The platform is Windows.
            - A target is unreadable.
            - The target list is empty.
            - The host refused the socket.

            The call also exits with the status 1 when a socket call fails during the
            scan. The results written before the failure stay in the result stream.
    """
    refusal = unsupported_platform_message(platform, args.command)
    if refusal is not None:
        _fail(refusal)
    try:
        targets: Iterator[str] = iter(parse_targets(args.target))
    except TargetError as error:
        _fail(f"Error: {error}. The scan sent nothing.")
    first = next(targets, None)
    if first is None:
        _fail(f"Error: the target {args.target!r} names no address. The scan sent nothing.")
    try:
        network = open_network(args.port, first, _warn)
    except CAPTURE_FAILURES as error:
        if privilege_refused(error):
            _fail(
                "Error: ja4plus scan has no privilege to open a raw socket.\n"
                "Linux grants the privilege through the CAP_NET_RAW capability.\n"
                "macOS grants the privilege through write access to the /dev/bpf* devices.\n"
                f"Try: sudo ja4plus scan {args.target}\n"
                f"The socket layer reported: {error}"
            )
        _fail(f"Error: ja4plus scan could not open a raw socket: {error}")
    try:
        retransmit = args.retransmit == "yes"
        # FR-active-scan-8 writes the rules before the first SYN. The mode without
        # retransmissions reads the first response alone, so a kernel RST changes no
        # value there and the mode writes no rule.
        if retransmit:
            print(firewall_rules(platform), file=sys.stderr)
        with result_stream(args) as stream:
            writer = build_writer(args.format, stream)
            writer.write_header()
            scanner = Scanner(
                port=args.port,
                rate=args.rate,
                retransmit=retransmit,
                send=network.send,
                receive=network.receive,
                clock=clock,
                on_result=lambda result: writer.write(to_fingerprint_result(result)),
                on_warning=_warn,
                rng=rng,
            )
            try:
                scanner.run(itertools.chain([first], targets))
            except KeyboardInterrupt:
                # The operator stopped the wait, so each target writes what it sent.
                scanner.flush()
                raise
            except BrokenPipeError:
                # `BrokenPipeError` inherits `OSError`, and `ja4plus/cli.py` owns the exit
                # of a reader that closed the result stream.
                raise
            except OSError as error:
                # A downed interface or a full send buffer fails a socket call. The exit
                # closes the result stream, so every result written so far stays in it.
                _fail(f"Error: the scan stopped: {error}")
    finally:
        network.close()


def run(args: argparse.Namespace, result_stream: ResultStream) -> None:
    """Run the scan on the network of this host.

    `pyproject.toml` names this function under the `ja4plus.commands` entry point.

    Args:
        args: The parsed command line.
        result_stream: The context manager of `ja4plus/cli.py` that opens the result
            stream.
    """
    scan_command(
        args,
        result_stream=result_stream,
        platform=sys.platform,
        open_network=LinkNetwork,
        clock=time.time,
    )
