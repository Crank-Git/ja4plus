"""Processor aggregator: runs every JA4+ fingerprinter on each packet.

Mirrors the API of ja4plus-go's ja4plus.Processor:

    p = Processor()
    results = p.process_packet(pkt)            # list of FingerprintResult
    results, errors = p.process_packet_with_errors(pkt)
    p.cleanup_connection(src_ip, src_port, dst_ip, dst_port, "tcp")
    key = p.get_shard_key(pkt)                 # stable connection key
    p.reset()                                  # clear all state

`ja4plus/types.py` states the fields of a `FingerprintResult`.
"""

# Python 3.9 is the floor, and it evaluates no annotation written as `list[str]`
# without this import.
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

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
from ja4plus.types import FingerprintResult
from ja4plus.utils.state_table import TableStats

if TYPE_CHECKING:
    # The module reads scapy inside the two functions that need it, so an import at the
    # top would load scapy for a caller that only builds a `Processor`.
    from scapy.packet import Packet

logger = logging.getLogger(__name__)

# `Processor.stats` returns `dict[str, ProcessorStats]`, so a caller who annotates the
# report names the class. Both names are therefore public, and #47 states the reading.
# `ja4plus/__init__.py` exports `Processor` alone, so `ProcessorStats` is public at
# `ja4plus.processor.ProcessorStats`, which is the path `docs/api_reference.md` documents.
__all__ = ["Processor", "ProcessorStats"]


class ProcessorStats:
    """The counts one method reports.

    FR-concurrency-safety-11 and FR-concurrency-safety-12 ask the processor to report
    the entry count of each state table and the count of entries it evicted. One method
    holds up to four state tables, so this object holds the count of each table and the
    sum across them.

    Epic 4 makes this a typed dataclass. #41 ships a plain object.

    Args:
        method: The method name, such as `ja4h`.
        packets: The count of packets the processor gave this method. The count rises
            for a packet the method reads and for a packet it ignores, and
            `Processor.reset` returns it to zero.
        tables: A dict that maps the state table name to its `TableStats`.

    Attributes:
        entries: The sum of the entry counts of the tables.
        evictions: The sum of the eviction counts of the tables.
        returned_connections: The sum of the counts of connections that returned after
            an eviction. A returned connection produces a fingerprint that may be
            incomplete, because its new entry holds none of the packets that came
            before the eviction.
    """

    __slots__ = ("method", "packets", "tables", "entries", "evictions", "returned_connections")

    def __init__(self, method: str, packets: int, tables: dict[str, TableStats]) -> None:
        self.method = method
        self.packets = packets
        self.tables = tables
        self.entries = sum(table.entries for table in tables.values())
        self.evictions = sum(table.evictions for table in tables.values())
        self.returned_connections = sum(table.returned_connections for table in tables.values())

    def __repr__(self) -> str:
        return (
            f"ProcessorStats(method={self.method!r}, packets={self.packets}, "
            f"entries={self.entries}, evictions={self.evictions}, "
            f"returned_connections={self.returned_connections}, "
            f"tables={sorted(self.tables)})"
        )


class Processor:
    """Aggregator that runs every JA4+ fingerprinter on each packet."""

    # The order here drives the iteration order of process_packet()
    _SPEC: list[tuple[str, type[BaseFingerprinter]]] = [
        ("ja4", JA4Fingerprinter),
        ("ja4s", JA4SFingerprinter),
        ("ja4h", JA4HFingerprinter),
        ("ja4t", JA4TFingerprinter),
        ("ja4ts", JA4TSFingerprinter),
        ("ja4l", JA4LFingerprinter),
        ("ja4x", JA4XFingerprinter),
        ("ja4ssh", JA4SSHFingerprinter),
        ("ja4d", JA4DFingerprinter),
        ("ja4d6", JA4D6Fingerprinter),
    ]

    def __init__(self, thread_safe: bool = True) -> None:
        """Build one processor and the ten fingerprinters it drives.

        Args:
            thread_safe: True makes every fingerprinter guard its own state with a
                reentrant lock, and several threads may then call `process_packet` on
                one processor. False makes every fingerprinter acquire no lock, and the
                caller then promises that one thread at a time calls this processor. A
                caller that breaks the promise gets undefined results.
        """
        self.thread_safe = bool(thread_safe)
        # One fingerprinter holds one lock, so ten threads work at once on ten methods.
        # A single lock over the processor would serialize all ten.
        self.fingerprinters: dict[str, BaseFingerprinter] = {
            name: cls(thread_safe=thread_safe) for name, cls in self._SPEC
        }
        # `stats` reports this count, and no fingerprinter holds it. A method that reads
        # no packet still receives every packet, and the count records that.
        self._packet_counts = {name: 0 for name, _ in self._SPEC}

    def __getattr__(self, name: str) -> Any:
        # Convenience: processor.ja4 returns the underlying fingerprinter.
        # __getattr__ is only invoked when normal attribute lookup fails,
        # so this doesn't shadow process_packet/reset/etc.
        if "fingerprinters" in self.__dict__ and name in self.__dict__["fingerprinters"]:
            return self.__dict__["fingerprinters"][name]
        raise AttributeError(name)

    def process_packet(self, packet: Packet) -> list[FingerprintResult]:
        """Run every fingerprinter on one packet, and return the results.

        The results follow the fixed method order of `_SPEC`. The order is part of the
        interface, and FR-typed-api-3 states it.

        A fingerprinter that raises produces no result, and the processor logs the error
        at DEBUG. One method that raises poisons no other method. A caller who needs the
        errors calls `process_packet_with_errors` instead. FR-typed-api-4 states that.

        Args:
            packet: The packet to read.

        Returns:
            A list of `FingerprintResult`. The list is empty when the packet produces no
            fingerprint.
        """
        results, _ = self.process_packet_with_errors(packet)
        return results

    def process_packet_with_errors(
        self, packet: Packet
    ) -> tuple[list[FingerprintResult], list[Exception]]:
        """Run every fingerprinter on one packet, and return the results and the errors.

        The port returns both from one call, and parity rule 2 keeps the pair. Python
        has no multiple-return form that reads well as a default, so `process_packet`
        returns the results alone and this method returns both.

        Every returned exception carries no traceback. A traceback holds the frame of
        every call it passed, and those frames hold the packet. `CLAUDE.md` states that
        no code holds a reference to a packet object after `process_packet` returns. The
        type, the message and the error chain stay.

        Args:
            packet: The packet to read.

        Returns:
            A tuple of two lists. The first holds one `FingerprintResult` for each
            method that produced a fingerprint, in the fixed method order. The second
            holds one exception for each method that raised, in the same order.
        """
        results: list[FingerprintResult] = []
        errors: list[Exception] = []
        src_ip, dst_ip, src_port, dst_port = _packet_endpoints(packet)

        for fp_type, fp in self.fingerprinters.items():
            # `last_raw` describes the value the call below produces, so that call and
            # the read of `last_raw` form one operation. A second thread that runs
            # between the two pairs the raw form of its own packet with this
            # fingerprint.
            with fp.lock:
                # The read, the addition and the write are three steps, so a second
                # thread that runs between them loses a packet from the count.
                self._packet_counts[fp_type] += 1
                try:
                    fingerprint = fp.process_packet(packet)
                except Exception as e:
                    logger.debug(f"{fp_type} processing failed: {e}")
                    errors.append(_drop_traceback(e))
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
                    )
                )
        return results, errors

    def close_open_windows(self) -> list[dict[str, Any]]:
        """Emit every window the fingerprinters hold open, and return the results.

        Run this method when the packet source ends. JA4SSH is the only method that
        holds a window, and #214 decided that it emits the window a connection holds
        open at the end of a capture.

        Returns:
            A list of result dicts. Each dict holds the method name, the fingerprint
            and the connection key of the window. It holds no packet endpoint, because
            no packet produces the value.
        """
        results: list[dict[str, Any]] = []
        for fp_type, fp in self.fingerprinters.items():
            try:
                entries = fp.close_open_windows()
            except Exception as e:
                logger.debug(f"{fp_type} close_open_windows failed: {e}")
                continue
            for entry in entries:
                results.append(
                    {
                        "type": fp_type,
                        "fingerprint": entry["fingerprint"],
                        "connection": entry.get("connection"),
                    }
                )
        return results

    def stats(self) -> dict[str, ProcessorStats]:
        """Return the counts each method reports, keyed by the method name.

        The report holds one entry for each of the ten methods. Each entry states the
        packet count of that method and the counts of every state table it holds.
        FR-concurrency-safety-11 and FR-concurrency-safety-12 state the requirement.

        The call holds the lock of one fingerprinter across the read of that
        fingerprinter, because the counts of one method describe one instant. A read
        that acquires nothing catches a table between the store of a new entry and the
        count of it, and the report then breaks the invariant
        `inserts == entries + evictions + removals`. The call acquires one lock at a
        time, so it stops no other method and it holds two locks never.

        The report describes ten instants and not one. A caller that needs one instant
        across the ten methods stops the packet source first.

        Returns:
            A dict that maps the method name to a `ProcessorStats`.
        """
        report: dict[str, ProcessorStats] = {}
        for fp_type, fp in self.fingerprinters.items():
            with fp.lock:
                tables = {name: table.stats() for name, table in fp.state_tables().items()}
                packets = self._packet_counts[fp_type]
            report[fp_type] = ProcessorStats(fp_type, packets, tables)
        return report

    def reset(self) -> None:
        """Reset every underlying fingerprinter, and return every packet count to zero.

        A reset drops the state tables, and a count that survives the drop describes
        entries no table holds. The packet counts therefore start again.
        """
        for fp_type, fp in self.fingerprinters.items():
            with fp.lock:
                fp.reset()
                self._packet_counts[fp_type] = 0

    def cleanup_connection(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str
    ) -> None:
        """Drop per-connection state across all fingerprinters.

        Each fingerprinter normalizes the 5-tuple to its own internal key
        format. Call this when a connection is evicted from your tracker
        to prevent state leaks in long-running monitors.
        """
        for fp in self.fingerprinters.values():
            try:
                fp.cleanup_connection(src_ip, src_port, dst_ip, dst_port, proto)
            except Exception as e:
                logger.debug(f"cleanup_connection error in {fp.__class__.__name__}: {e}")

    def get_shard_key(self, packet: Packet) -> str:
        """Return a stable per-connection key for sharding processors.

        Sorts the 5-tuple so both directions of the same connection map
        to the same shard. Returns "" if the packet is not TCP/UDP/IP.
        """
        from scapy.all import TCP, UDP, IP, IPv6

        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip_layer is None:
            return ""
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)

        if packet.haslayer(TCP):
            proto = "tcp"
            sport = int(packet[TCP].sport)
            dport = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            proto = "udp"
            sport = int(packet[UDP].sport)
            dport = int(packet[UDP].dport)
        else:
            return ""

        if (src_ip > dst_ip) or (src_ip == dst_ip and sport > dport):
            src_ip, dst_ip = dst_ip, src_ip
            sport, dport = dport, sport

        return f"{proto}:{src_ip}:{sport}->{dst_ip}:{dport}"


def _drop_traceback(error: Exception) -> Exception:
    """Return the error with no traceback on it or on any error it followed.

    `CLAUDE.md` states that no code holds a reference to a packet object after
    `process_packet` returns. A traceback holds the frame of every call it passed, and
    those frames hold the packet as a local. A caller that keeps the error of every
    packet would therefore hold every packet it read.

    The call walks `__cause__` and `__context__`, because a fingerprinter that raises
    inside an `except` block chains a second error whose traceback holds its own frames.
    The type, the message and the chain stay, so the caller reads what failed.

    The traceback is the one path this call clears. An error that carries the packet in
    `args`, or on an attribute of its own, still holds it. No fingerprinter of this
    project builds such an error, and a new fingerprinter must not.

    Args:
        error: The error one fingerprinter raised.

    Returns:
        The same error object.
    """
    # The list holds a reference to every error it cleared, so the walk compares
    # identities and no freed object returns the identity of a later one.
    cleared: list[BaseException] = []
    pending: list[BaseException | None] = [error]
    while pending:
        current = pending.pop()
        # A chain can hold a cycle, so the walk records what it already cleared.
        if current is None or any(current is done for done in cleared):
            continue
        cleared.append(current)
        current.__traceback__ = None
        pending.append(current.__cause__)
        pending.append(current.__context__)
    return error


def _packet_endpoints(packet: Packet) -> tuple[str, str, int, int]:
    """Best-effort extraction of (src_ip, dst_ip, src_port, dst_port)."""
    from scapy.all import TCP, UDP, IP, IPv6

    src_ip = dst_ip = ""
    src_port = dst_port = 0

    ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
    if ip_layer is not None:
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)

    if packet.haslayer(TCP):
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    return src_ip, dst_ip, src_port, dst_port
