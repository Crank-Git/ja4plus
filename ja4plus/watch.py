"""The monitor loop and the connection table of `ja4plus watch`.

`docs/specs/features/06-live-capture.md` states the requirements. A monitor runs for
weeks, so the connection table it owns holds a maximum entry count and a maximum age.
`CLAUDE.md` states the rule: nothing that survives across packets grows without a limit.

Version 0.6.0 called `Processor.cleanup_connection` never. Its live capture therefore
held the state of every connection it ever read, and a monitor on a busy interface grew
until the host stopped it.

The table this module owns is a `BoundedStateTable`, the form Epic 14 shipped. Its
eviction hook calls `Processor.cleanup_connection`, so one eviction drops the entry of
this table and the per-connection state of all ten methods together. An eviction that
dropped the entry alone would leave the leak behind a bound.

Eviction runs on packet arrival. This module starts no thread.
"""

# Python 3.9 is the floor, and it evaluates no annotation written as `str | None`
# without this import.
from __future__ import annotations

import contextlib
import logging
import signal
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator, Optional

from scapy.all import TCP, UDP

from ja4plus.processor import Processor
from ja4plus.utils.packet_utils import packet_endpoints, packet_seconds
from ja4plus.utils.state_table import DEFAULT_EVICTION_INTERVAL, BoundedStateTable
from ja4plus.utils.tunnels import innermost_layer

if TYPE_CHECKING:
    from types import FrameType

    from scapy.packet import Packet

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_CONNECTION_TIMEOUT",
    "DEFAULT_MAX_CONNECTIONS",
    "Monitor",
    "StopRequest",
    "connection_key",
    "read_interface",
    "stop_on_signal",
]

# The two signals that stop a monitor. FR-live-capture-5 and FR-live-capture-6 name one
# each.
_TERMINATION_SIGNALS = (signal.SIGINT, signal.SIGTERM)

# The maximum count of connections the monitor tracks. `--max-connections` changes it.
# `features/06-live-capture.md` states the value.
DEFAULT_MAX_CONNECTIONS = 10000

# The maximum age of one connection, in seconds. `--connection-timeout` changes it.
# `features/06-live-capture.md` states the value. It sits below the age bound of the
# state tables the ten methods hold, so the monitor sheds an idle connection before
# those tables do.
DEFAULT_CONNECTION_TIMEOUT = 300.0

# The two scapy layer classes that carry a port. `innermost_layer` reads the deepest
# one, because a tunnel carries a second port layer inside the first one.
_PORT_LAYERS = (TCP, UDP)


def connection_key(packet: Packet) -> tuple[str, str, int, str, int] | None:
    """Return the key of the connection the packet belongs to, or None.

    The two directions of one connection produce one key, so the table holds one entry
    for one connection. The call therefore sorts the two endpoints.

    The address pair names the outer address layer and the port pair names the innermost
    port layer, because the ten methods read the same two layers. A key that read other
    layers would name a connection whose state `Processor.cleanup_connection` never
    drops.

    Args:
        packet: The packet to read.

    Returns:
        A tuple of the protocol name and the two endpoints, or None when the packet
        carries no address layer or no port layer.
    """
    port_layer = innermost_layer(packet, _PORT_LAYERS)
    if port_layer is None:
        return None
    endpoints = packet_endpoints(packet)
    if any(endpoints[field] is None for field in ("src", "dst", "srcport", "dstport")):
        return None

    proto = "tcp" if isinstance(port_layer, TCP) else "udp"
    src_ip = str(endpoints["src"])
    dst_ip = str(endpoints["dst"])
    src_port = int(endpoints["srcport"])
    dst_port = int(endpoints["dstport"])
    if (src_ip > dst_ip) or (src_ip == dst_ip and src_port > dst_port):
        src_ip, dst_ip = dst_ip, src_ip
        src_port, dst_port = dst_port, src_port
    return (proto, src_ip, src_port, dst_ip, dst_port)


class Monitor:
    """The monitor loop of `ja4plus watch`, without the packet source.

    The loop reads one packet at a time. It records the connection the packet names,
    evicts what either bound removes, and then reports the packet. The order matters: an
    eviction pass that ran after the report would drop the state of the packet that just
    arrived.

    The class holds no packet after `handle_packet` returns. The table stores the
    connection key, which holds two addresses, two ports and a protocol name.

    Args:
        processor: The processor that fingerprints the traffic. The monitor calls its
            `cleanup_connection` for every connection it evicts.
        report: A callable the monitor calls with each packet, after it records the
            connection. The command-line program passes the call that fingerprints the
            packet and writes the results.
        max_connections: The maximum count of tracked connections.
        connection_timeout: The maximum age of one connection, in seconds. The age reads
            the capture time of the packets, because a capture replays faster than real
            time.
        eviction_interval: The count of packets between two age eviction passes. A pass
            reads every entry, so a pass on each packet costs the entry count on each
            packet.

    Raises:
        ValueError: `max_connections` is below one, or `eviction_interval` is below one.
    """

    def __init__(
        self,
        processor: Processor,
        report: Callable[[Packet], None],
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        connection_timeout: float = DEFAULT_CONNECTION_TIMEOUT,
        eviction_interval: int = DEFAULT_EVICTION_INTERVAL,
    ) -> None:
        self._processor = processor
        self._report = report
        self._connections = BoundedStateTable(
            max_connections=max_connections,
            max_connection_age=connection_timeout,
            eviction_interval=eviction_interval,
            on_eviction=self._drop_connection,
        )

    @property
    def evictions(self) -> int:
        """The count of connections the monitor evicted, on either bound."""
        return self._connections.evictions

    def tracked_connections(self) -> list[tuple[str, str, int, str, int]]:
        """Return the key of every connection the table holds.

        The pass holds no entry against either bound, so a caller reads the table
        without changing what the table evicts next.

        Warning: the monitor acquires no lock. Call this method from the thread that
        calls `handle_packet`. A second thread that reads the table while the capture
        thread writes it reads a list the writer changed under it.

        Returns:
            A list of connection keys, least recently seen first.
        """
        keys: list[tuple[str, str, int, str, int]] = self._connections.keys()
        return keys

    def handle_packet(self, packet: Packet) -> None:
        """Read one packet: record its connection, evict, and report the packet.

        A packet that names no connection still reaches the report, because a method
        that reads no port still reads the packet.

        Args:
            packet: The packet the capture produced.
        """
        # The announcement carries the capture time, so the age bound measures capture
        # time and not wall-clock time.
        self._connections.on_packet(packet_seconds(packet))
        key = connection_key(packet)
        if key is not None:
            # The write refreshes the entry of a connection that keeps sending, and it
            # evicts the least recently used entry when the table is full.
            self._connections[key] = None
        self._report(packet)

    def _drop_connection(self, key: Any) -> None:
        """Drop the per-connection state of all ten methods for one evicted connection.

        Args:
            key: The connection key the table evicted.
        """
        proto, src_ip, src_port, dst_ip, dst_port = key
        self._processor.cleanup_connection(src_ip, src_port, dst_ip, dst_port, proto)
        logger.debug("the monitor evicts the connection %r", key)


class StopRequest:
    """The flag that a termination signal sets and that the capture loop reads.

    The handler sets the flag and returns. It calls `sys.exit` never, because a signal
    arrives at any point, including the point where the output holds half a line. An exit
    there truncates that line. Version 0.6.0 called `sys.exit` inside the handler of
    `ja4plus/collector.py`, and Epic 4 removed that module.

    `scapy` reads the flag through the `stop_filter` argument of `sniff`. It applies that
    filter to each packet after it reports the packet, so the loop finishes the packet it
    holds and the command flushes the output after the loop returns.

    Verified against: https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html
    (scapy 2.6 and later, retrieved 2026-08-08).

    Warning: `scapy` applies the filter on packet arrival alone. An interface that carries
    no traffic therefore holds the loop until the next packet arrives. #320 records that
    gap.
    """

    def __init__(self) -> None:
        self._requested = False

    def requested(self) -> bool:
        """Return True after a termination signal arrived."""
        return self._requested

    def request(self, signal_number: int = 0, frame: Optional[FrameType] = None) -> None:
        """Set the flag, and return.

        `signal.signal` calls this method with the signal number and the frame. The
        method reads neither, because it does the least work a handler can do.

        Args:
            signal_number: The number of the signal that arrived.
            frame: The stack frame the signal interrupted.
        """
        self._requested = True

    def stop_after(self, packet: Packet) -> bool:
        """Return True when the capture stops after this packet.

        Args:
            packet: The packet the capture just reported. The answer reads no packet,
                because a signal and not a packet stops a monitor.

        Returns:
            True after a termination signal arrived, and False before it.
        """
        return self._requested


@contextlib.contextmanager
def stop_on_signal(
    signal_numbers: Iterable[int] = _TERMINATION_SIGNALS,
) -> Iterator[StopRequest]:
    """Yield the stop request, with a handler installed for each signal number.

    The call restores the handler it replaced, whether the body returns or raises. A
    library caller that runs a monitor twice therefore leaves no handler behind.

    Args:
        signal_numbers: The signal numbers to handle. The default is `SIGINT` and
            `SIGTERM`, which FR-live-capture-5 and FR-live-capture-6 name.

    Yields:
        The stop request that each handler sets.

    Raises:
        ValueError: The caller runs outside the main thread. `signal.signal` raises it.
    """
    stop = StopRequest()
    replaced: list[tuple[int, Any]] = []
    try:
        for number in signal_numbers:
            replaced.append((number, signal.signal(number, stop.request)))
        yield stop
    finally:
        for number, handler in replaced:
            signal.signal(number, handler)


def read_interface(
    interface: str,
    handle_packet: Callable[[Packet], None],
    stop_filter: Optional[Callable[[Packet], bool]] = None,
) -> None:
    """Read packets from one interface, and call the handler with each one.

    The call returns when the capture stops. `store=0` is required: without it `scapy`
    keeps every packet it read, and the monitor then grows whatever the connection table
    bounds.

    Verified against: https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html
    (scapy 2.6 and later, retrieved 2026-08-08).

    Args:
        interface: The interface name. The name `any` reads every interface.
        handle_packet: The callable that reads one packet.
        stop_filter: The callable that ends the capture when it returns True for a
            packet, or None to read until the process ends. `StopRequest.stop_after` is
            the callable the command passes.
    """
    from scapy.all import sniff

    sniff(
        prn=handle_packet,
        iface=interface if interface != "any" else None,
        store=0,
        stop_filter=stop_filter,
    )
