"""The monitor loop and the connection table of `ja4plus watch`.

`docs/specs/features/06-live-capture.md` states the requirements. A monitor runs for
weeks, so the connection table it owns holds a maximum entry count and a maximum age.
`CLAUDE.md` states the rule: nothing that survives across packets grows without a limit.

Version 0.6.0 called `Processor.cleanup_connection` never. Its live capture therefore
held the state of every connection it ever read, and a monitor on a busy interface grew
until the host stopped it.

The table this module owns is a `BoundedStateTable`, the form Epic 14 shipped. Its
eviction hook calls `Processor.cleanup_connection`, so one eviction drops the entry of
this table and the per-connection state of all ten fingerprinters together. An eviction that
dropped the entry alone would leave the leak behind a bound.

Eviction runs on packet arrival. The statistics thread is the only thread this module
starts, and `report_statistics` starts it only when the operator states an interval.
"""

# Python 3.9 is the floor, and it evaluates no annotation written as `str | None`
# without this import.
from __future__ import annotations

import contextlib
import errno
import logging
import math
import signal
import threading
import time
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator, Optional, TextIO

from scapy.all import TCP, UDP
from scapy.error import Scapy_Exception

from ja4plus.processor import Processor
from ja4plus.utils.packet_utils import packet_endpoints, packet_seconds
from ja4plus.utils.state_table import DEFAULT_EVICTION_INTERVAL, BoundedStateTable
from ja4plus.utils.tunnels import innermost_layer

if TYPE_CHECKING:
    from types import FrameType

    from scapy.packet import Packet

logger = logging.getLogger(__name__)

__all__ = [
    "CAPTURE_FAILURES",
    "DEFAULT_CONNECTION_TIMEOUT",
    "DEFAULT_MAX_CONNECTIONS",
    "DEFAULT_POLL_INTERVAL",
    "STATISTICS_THREAD_NAME",
    "Monitor",
    "MonitorStats",
    "StatisticsReporter",
    "StatisticsSnapshot",
    "StopRequest",
    "available_interfaces",
    "connection_key",
    "describe_capture_failure",
    "format_statistics",
    "open_capture_socket",
    "read_interface",
    "report_statistics",
    "stop_on_signal",
    "unsupported_platform_message",
    "write_statistics",
]

# The two signals that stop a monitor. FR-live-capture-5 and FR-live-capture-6 name one
# each.
_TERMINATION_SIGNALS = (signal.SIGINT, signal.SIGTERM)

# The maximum count of connections the monitor tracks. `--max-connections` changes it.
# `features/06-live-capture.md` states the value.
DEFAULT_MAX_CONNECTIONS = 10000

# The maximum age of one connection, in seconds. `--connection-timeout` changes it.
# `features/06-live-capture.md` states the value. It sits below the age bound of the
# state tables the ten fingerprinters hold, so the monitor sheds an idle connection before
# those tables do.
DEFAULT_CONNECTION_TIMEOUT = 300.0

# The count of seconds one `sniff` call reads before it returns to the monitor loop. The
# loop reads the stop request there, so an operator waits at most this long after the
# signal. #320 states a bound of one second, and this value holds a margin below it.
# A smaller value costs one control pipe and one `select` call for each interval.
DEFAULT_POLL_INTERVAL = 0.25

# The two scapy layer classes that carry a port. `innermost_layer` reads the deepest
# one, because a tunnel carries a second port layer inside the first one.
_PORT_LAYERS = (TCP, UDP)

# The name of the statistics thread. An operator reads it in a stack dump, and a test
# reads it from `threading.enumerate`.
STATISTICS_THREAD_NAME = "ja4plus-statistics"

# The first field of the statistics line. `features/06-live-capture.md` publishes it.
_STATISTICS_PREFIX = "[ja4plus]"

# The count of seconds `StatisticsReporter.stop` waits for its thread. The thread
# writes one line and then reads the stop event, so a wait this long names a stream
# that blocks rather than a thread that ignores the stop.
_STATISTICS_JOIN_TIMEOUT = 5.0


def connection_key(packet: Packet) -> tuple[str, str, int, str, int] | None:
    """Return the key of the connection the packet belongs to, or None.

    The two directions of one connection produce one key, so the table holds one entry
    for one connection. The call therefore sorts the two endpoints.

    The address pair names the outer address layer and the port pair names the innermost
    port layer, because the ten fingerprinters read the same two layers. A key that read other
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


class StatisticsSnapshot:
    """The counts one statistics line reports.

    `MonitorStats.snapshot` builds one of these under its lock, so the six values
    describe one instant.

    Args:
        packets: The count of packets the monitor read.
        fingerprints: The count of fingerprints the monitor reported.
        connections: The count of connections the connection table holds.
        evicted: The count of connections the connection table evicted, on either
            bound.
        dropped: The count of packets the capture layer dropped, or None where the
            capture layer reports no count.
        uptime: The count of seconds since the monitor started.
    """

    __slots__ = ("packets", "fingerprints", "connections", "evicted", "dropped", "uptime")

    def __init__(
        self,
        packets: int,
        fingerprints: int,
        connections: int,
        evicted: int,
        dropped: Optional[int],
        uptime: float,
    ) -> None:
        self.packets = packets
        self.fingerprints = fingerprints
        self.connections = connections
        self.evicted = evicted
        self.dropped = dropped
        self.uptime = uptime

    def __repr__(self) -> str:
        return (
            f"StatisticsSnapshot(packets={self.packets}, "
            f"fingerprints={self.fingerprints}, connections={self.connections}, "
            f"evicted={self.evicted}, dropped={self.dropped}, uptime={self.uptime})"
        )


def format_statistics(snapshot: StatisticsSnapshot) -> str:
    """Return the statistics line of one snapshot.

    `features/06-live-capture.md` publishes the line and its six fields. The uptime
    holds whole seconds, because a monitor runs for weeks and a fraction of a second
    tells the operator nothing.

    Args:
        snapshot: The counts to report.

    Returns:
        One line, without a line feed.
    """
    dropped = "null" if snapshot.dropped is None else str(snapshot.dropped)
    return (
        f"{_STATISTICS_PREFIX} packets={snapshot.packets} "
        f"fingerprints={snapshot.fingerprints} connections={snapshot.connections} "
        f"evicted={snapshot.evicted} dropped={dropped} "
        f"uptime={int(snapshot.uptime)}s"
    )


class MonitorStats:
    """The counts of one monitor, and the lock that guards them.

    The capture thread writes these counts and the statistics thread reads them. Every
    write and every read holds one lock, so a reader reads the counts of one instant.
    A reader that acquired nothing would read a count another thread was writing.

    The capture thread publishes the two table counts through `record_packet`, so the
    statistics thread reads this object and never the connection table. The table is a
    dictionary that the capture thread writes on each packet, and a second reader of it
    reads entries the writer is moving.

    The `dropped` field reports a measurement, and `null` where none exists. `scapy`
    2.7.0 gives the monitor no drop count through `sniff`, so `ja4plus watch` passes no
    source and the field reads `null`. Two readings support that.

    1. On macOS the capture socket reports a drop count, and `sniff` hides the socket.
       `_L2bpfSocket.get_stats` reads the `BIOCGSTATS` ioctl and returns the received
       count and the drop count. `AsyncSniffer._run` holds the socket it opens in a
       local name, so a caller reaches that socket through the `opened_socket` argument
       alone. #56 owns the socket the command opens.
    2. On Linux `scapy` reads no drop count at all. It defines `PACKET_STATISTICS = 6`
       and calls `getsockopt` with that option nowhere.

    Verified against `scapy` 2.7.0, at `scapy/arch/bpf/supersocket.py:297`,
    `scapy/arch/linux/__init__.py:95` and `scapy/sendrecv.py:1205`, read on
    2026-08-08. Reading 1 ran on macOS 25.6.0. Reading 2 is a reading of the `scapy`
    source, and no Linux host ran it.

    Args:
        clock: The callable that returns the current time in seconds. The default is
            `time.monotonic`, because a host that steps its wall clock would report a
            negative uptime.
        dropped_source: The callable that returns the count of packets the capture
            layer dropped, or None where no capture layer reports one.
    """

    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        dropped_source: Optional[Callable[[], Optional[int]]] = None,
    ) -> None:
        self._lock = threading.Lock()
        self._clock = clock
        self._dropped_source = dropped_source
        self._started = clock()
        self._packets = 0
        self._fingerprints = 0
        self._connections = 0
        self._evicted = 0

    def count_fingerprints(self, count: int) -> None:
        """Add the fingerprints of one packet to the fingerprint count.

        Args:
            count: The count of fingerprints the monitor reported for one packet.
        """
        with self._lock:
            self._fingerprints += count

    def record_packet(self, connections: int, evicted: int) -> None:
        """Count one packet, and publish the two counts of the connection table.

        The capture thread calls this method after it reads the table, so the
        statistics thread reads the published counts and never the table itself.

        Args:
            connections: The count of entries the connection table holds now.
            evicted: The count of connections the connection table evicted.
        """
        with self._lock:
            self._packets += 1
            self._connections = connections
            self._evicted = evicted

    def snapshot(self) -> StatisticsSnapshot:
        """Return the counts of one instant.

        The call reads the drop count outside the lock, because that call reaches the
        capture layer and a slow answer would hold the capture thread.

        Returns:
            The counts, with the drop count and the uptime.
        """
        dropped = self._dropped_source() if self._dropped_source is not None else None
        with self._lock:
            return StatisticsSnapshot(
                packets=self._packets,
                fingerprints=self._fingerprints,
                connections=self._connections,
                evicted=self._evicted,
                dropped=dropped,
                uptime=self._clock() - self._started,
            )


def write_statistics(stats: MonitorStats, stream: TextIO) -> None:
    """Write one statistics line, and flush the stream.

    A monitor runs for weeks, and the operator reads the line as the monitor writes it.
    A flush that the interpreter runs at shutdown reaches no such reader.

    Args:
        stats: The counts to report.
        stream: The stream to write to. The command passes standard error, which
            FR-live-capture-10 states.
    """
    stream.write(format_statistics(stats.snapshot()) + "\n")
    stream.flush()


class StatisticsReporter:
    """The thread that writes a statistics line on a schedule.

    FR-live-capture-9 asks for the schedule. The thread waits on an event rather than
    on a sleep, so `stop` ends it inside a millisecond. A thread that slept the whole
    interval would hold the exit of the monitor for that interval, and #54 shipped a
    stop that returns as soon as the capture returns.

    The thread reads `MonitorStats` and nothing else, so it acquires one lock and it
    reads no state table.

    Args:
        stats: The counts to report.
        interval: The count of seconds between two lines.
        stream: The stream to write to.
        wait: The call that waits one interval and reports whether the stop arrived. It
            receives the interval and returns True for a stop, which matches
            `threading.Event.wait`. The default waits on the stop event, and no caller
            inside this package passes another. A test passes its own call, so it
            states the schedule rather than measures how promptly the host schedules a
            thread. #369 added the parameter.
    """

    def __init__(
        self,
        stats: MonitorStats,
        interval: float,
        stream: TextIO,
        wait: Optional[Callable[[float], bool]] = None,
    ) -> None:
        self._stats = stats
        self._interval = interval
        self._stream = stream
        self._stop = threading.Event()
        self._wait = self._stop.wait if wait is None else wait
        self._thread = threading.Thread(target=self._run, name=STATISTICS_THREAD_NAME, daemon=True)

    def start(self) -> None:
        """Start the thread."""
        self._thread.start()

    def stop(self) -> None:
        """End the thread, and wait for the line it is writing.

        A second call returns, so a caller that stops the reporter twice raises
        nothing.
        """
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=_STATISTICS_JOIN_TIMEOUT)

    def is_alive(self) -> bool:
        """Return True while the thread runs."""
        return self._thread.is_alive()

    def _run(self) -> None:
        """Write one line for each interval that passes, until the stop arrives.

        The wait comes first, so a monitor that starts writes no line before the
        operator's first interval passes.
        """
        while not self._wait(self._interval):
            write_statistics(self._stats, self._stream)


@contextlib.contextmanager
def report_statistics(
    stats: MonitorStats,
    interval: Optional[float],
    stream: TextIO,
    wait: Optional[Callable[[float], bool]] = None,
) -> Iterator[Optional[StatisticsReporter]]:
    """Yield the statistics reporter, and stop it when the body returns.

    The statistics thread is the only thread the monitor starts, and this call starts
    it only when the operator states an interval.

    Args:
        stats: The counts to report.
        interval: The count of seconds between two lines, or None for no thread.
        stream: The stream to write to.
        wait: The call that waits one interval and reports whether the stop arrived, or
            None for the wait on the stop event. `StatisticsReporter` states the form.
            `ja4plus/cli.py` passes None and a test passes its own call. A case that
            reaches the reporter through `cmd_watch` therefore states the schedule rather
            than samples it. #371 added the parameter.

    Yields:
        The reporter, or None where the operator stated no interval.
    """
    if interval is None:
        yield None
        return
    reporter = StatisticsReporter(stats, interval, stream, wait=wait)
    reporter.start()
    try:
        yield reporter
    finally:
        reporter.stop()


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
        stats: The counts the statistics line reports, or None to build them here. The
            monitor counts every packet it reads, whether or not the operator asked for
            a statistics line, because the exit summary of FR-live-capture-8 reports
            the same counts.

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
        stats: Optional[MonitorStats] = None,
    ) -> None:
        self._processor = processor
        self._report = report
        self.stats = stats if stats is not None else MonitorStats()
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
        # The capture thread is the only thread that reads the connection table, so it
        # publishes the two table counts here. The publication precedes the report,
        # because the report counts the fingerprints of this packet.
        self.stats.record_packet(len(self._connections), self._connections.evictions)
        self._report(packet)

    def _drop_connection(self, key: Any) -> None:
        """Drop the per-connection state of all ten fingerprinters for one evicted connection.

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

    `scapy` applies the filter on packet arrival alone, so an interface that carries no
    traffic reaches that filter never. `read_interface` therefore reads `requested`
    after each poll interval, and #320 shipped that loop.

    Verified against: https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html
    (scapy 2.6 and later, retrieved 2026-08-08).
    """

    def __init__(self) -> None:
        self._requested = False

    def requested(self) -> bool:
        """Return True after a termination signal arrived."""
        return self._requested

    def request(self, signal_number: int, frame: Optional[FrameType]) -> None:
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


# The exception classes the capture layer raises when it refuses to read an interface.
# `scapy` 2.7.0 raises one of the three for every failure this module classifies:
# `Scapy_Exception` for a refused `/dev/bpf` device and for a refused filter, `OSError`
# for the Linux socket calls, and `ValueError` from `resolve_iface` for an interface the
# host does not hold.
#
# Warning: `BrokenPipeError` inherits `OSError`, so a caller catches it before it
# catches this tuple. `ja4plus/cli.py` holds that order.
CAPTURE_FAILURES: tuple[type[BaseException], ...] = (Scapy_Exception, OSError, ValueError)

# The platform names of Windows. `sys.platform` reports `win32` on every Windows build,
# whatever the word size. `features/06-live-capture.md` puts Windows out of scope.
_WINDOWS_PLATFORMS = ("win32", "cygwin")

# The error numbers that name a refused privilege. Linux returns `EPERM` from the
# `AF_PACKET` socket call, and macOS returns `EACCES` from the `/dev/bpf` open.
_PRIVILEGE_ERRNOS = frozenset({errno.EPERM, errno.EACCES})

# The error numbers that name an interface the host does not hold. Linux returns
# `ENODEV` from the bind call.
_ABSENT_DEVICE_ERRNOS = frozenset({errno.ENODEV, errno.ENXIO})

# The text `scapy` 2.7.0 writes for a refused `/dev/bpf` device, at
# `scapy/arch/bpf/core.py:59`. It raises a `Scapy_Exception` there and no `OSError`, so
# the error number of that failure reaches no reader.
_PRIVILEGE_TEXT = "permission denied"

# The text `scapy` 2.7.0 writes for an interface the host does not hold, at
# `scapy/interfaces.py:434`.
_ABSENT_INTERFACE_TEXT = "not found"

# The word every filter failure of `scapy` 2.7.0 carries. `scapy/arch/common.py:129`
# writes `Failed to compile filter expression`. Both socket classes wrap that failure:
# `scapy/arch/bpf/supersocket.py:218` and `scapy/arch/linux/__init__.py:232` each write
# `Cannot set filter:`.
_FILTER_TEXT = "filter"


def unsupported_platform_message(platform: str, command: str) -> Optional[str]:
    """Return the reason the platform runs no monitor, or None when it runs one.

    The call reads the platform name alone. Every platform other than Windows attempts
    the capture, because a failed attempt reports what the host refuses and a platform
    name does not.

    Args:
        platform: The value of `sys.platform` on this host.
        command: The subcommand name the operator ran, `watch` or `live`.

    Returns:
        The message the operator reads, or None where the platform runs a monitor.
    """
    if platform.startswith(_WINDOWS_PLATFORMS):
        return (
            f"Error: ja4plus {command} runs on Linux and on macOS. This host runs Windows.\n"
            "Read a capture file with ja4plus analyze instead."
        )
    return None


def available_interfaces() -> list[str]:
    """Return the name of every interface the host holds, in sorted order.

    The call reads the interface list of the host and it opens no interface, so an
    operator without the capture privilege still reads the list.

    Returns:
        The interface names, or an empty list where the capture layer reports none.
    """
    from scapy.all import get_if_list

    try:
        names: list[str] = list(get_if_list())
    except CAPTURE_FAILURES:
        # This call runs while the command reports another failure. A second failure
        # here would replace that report with a stack trace.
        logger.debug("the capture layer reported no interface list", exc_info=True)
        return []
    return sorted(names)


def describe_capture_failure(
    error: BaseException,
    *,
    interface: str,
    command: str,
    capture_filter: Optional[str],
    interfaces: list[str],
) -> str:
    """Return the message the operator reads for one capture failure.

    The call reads the failure the capture layer reported. It opens nothing and it calls
    no capture function, so the call classifies the failure of any capture layer that
    raises one of `CAPTURE_FAILURES`.

    The privilege reading comes first. A host that refuses the privilege refuses it
    before it reads the interface name or the filter, so a later reading would report
    the wrong cause.

    Verified against `scapy` 2.7.0, at `scapy/arch/bpf/core.py:59`,
    `scapy/interfaces.py:434`, `scapy/arch/common.py:129` and
    `scapy/arch/linux/__init__.py:232`, read on 2026-08-08.

    Args:
        error: The failure the capture layer reported.
        interface: The interface name the operator stated.
        command: The subcommand name the operator ran, `watch` or `live`.
        capture_filter: The `--bpf` expression the operator stated, or None.
        interfaces: The interface names the host holds.

    Returns:
        The message, as one string without a trailing line feed.
    """
    text = str(error).lower()
    number = error.errno if isinstance(error, OSError) else None

    if number in _PRIVILEGE_ERRNOS or _PRIVILEGE_TEXT in text:
        return (
            f"Error: ja4plus has no privilege to read the interface {interface!r}.\n"
            "Linux grants the privilege through the CAP_NET_RAW capability.\n"
            "macOS grants the privilege through read access to the /dev/bpf* devices.\n"
            f"Try: sudo ja4plus {command} {interface}\n"
            f"The capture layer reported: {error}"
        )

    if number in _ABSENT_DEVICE_ERRNOS or (
        isinstance(error, ValueError) and _ABSENT_INTERFACE_TEXT in text
    ):
        held = (
            f"The host holds these interfaces: {', '.join(interfaces)}"
            if interfaces
            else "The host reports no interface."
        )
        return (
            f"Error: the host holds no interface named {interface!r}.\n"
            f"{held}\n"
            f"The capture layer reported: {error}"
        )

    if capture_filter is not None and _FILTER_TEXT in text:
        return (
            f"Error: the capture layer refused the capture filter {capture_filter!r}.\n"
            f"The capture layer reported: {error}"
        )

    return f"Error during capture on the interface {interface!r}: {error}"


def open_capture_socket(interface: str, capture_filter: Optional[str] = None) -> Any:
    """Return an open capture socket for one interface.

    The call resolves the interface and opens the listening socket of that interface, in
    the order `AsyncSniffer._run` holds. `libpcap` compiles the capture filter here,
    because the socket attaches the filter as it opens.

    The name `any` reads the default interface of the capture layer. `AsyncSniffer._run`
    reads `iface or conf.iface`, so a `sniff` call that stated no interface read the same
    one.

    Verified against `scapy` 2.7.0, at `scapy/sendrecv.py:1268` and
    `scapy/arch/bpf/supersocket.py:215`, read on 2026-08-08.

    Args:
        interface: The interface name. The name `any` reads the default interface of the
            capture layer.
        capture_filter: The Berkeley Packet Filter expression the socket attaches, or
            None to read every packet.

    Returns:
        The open capture socket. The caller closes it.

    Raises:
        Scapy_Exception: The host refuses the `/dev/bpf` device, or `libpcap` refuses
            the capture filter.
        OSError: The host refuses the capture socket.
        ValueError: The host holds no interface of that name.
    """
    from scapy.config import conf
    from scapy.data import ETH_P_ALL
    from scapy.interfaces import resolve_iface

    name = interface if interface != "any" else conf.iface
    socket_class = resolve_iface(name).l2listen()
    return socket_class(type=ETH_P_ALL, iface=name, filter=capture_filter)


def read_interface(
    interface: str,
    handle_packet: Callable[[Packet], None],
    stop_filter: Optional[Callable[[Packet], bool]] = None,
    capture_filter: Optional[str] = None,
    stop_requested: Optional[Callable[[], bool]] = None,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    open_socket: Callable[[str, Optional[str]], Any] = open_capture_socket,
) -> None:
    """Read packets from one interface, and call the handler with each one.

    The call opens the capture socket and then calls `sniff` with that socket and a
    short timeout, in a loop. The socket stays open across the calls, because
    `AsyncSniffer._run` closes the sockets it opened itself and no other socket. A loop
    that reopened the socket would lose every packet the host buffered between two
    calls.

    The loop reads the stop request after each timeout, so an operator waits at most one
    poll interval after the signal. #54 shipped `stop_filter` alone, and `scapy` applies
    that filter to a packet and to nothing else: an interface that carries no traffic
    therefore held the monitor until the next packet arrived. #320 records that gap.

    `store=0` is required: without it `scapy` keeps every packet it read, and the monitor
    then grows whatever the connection table bounds.

    The call passes no `filter` to `sniff`. `AsyncSniffer._run` reads that argument only
    where it opens the socket itself, so a filter stated there would reach no socket.

    The call raises what the capture layer raises. `describe_capture_failure` reads that
    failure, so this call classifies nothing.

    Verified against `scapy` 2.7.0, at `scapy/sendrecv.py:1268`, `scapy/sendrecv.py:1331`
    and `scapy/sendrecv.py:1391`, read on 2026-08-08.

    Args:
        interface: The interface name. The name `any` reads the default interface of the
            capture layer.
        handle_packet: The callable that reads one packet.
        stop_filter: The callable that ends the capture when it returns True for a
            packet, or None to read until the stop request arrives.
            `StopRequest.stop_after` is the callable the command passes.
        capture_filter: The Berkeley Packet Filter expression the capture applies, or
            None to read every packet. FR-live-capture-11 asks for it.
        stop_requested: The callable that reports True after a termination signal
            arrived, or None to read until the process ends. `StopRequest.requested` is
            the callable the command passes.
        poll_interval: The count of seconds one `sniff` call reads before it returns to
            the loop.
        open_socket: The callable that opens the capture socket. A caller states one to
            read a socket it supplies, and a test states one to open no interface. The
            socket it returns holds `closed`, which `SuperSocket` holds as a class
            attribute.

    Raises:
        Scapy_Exception: The host refuses the `/dev/bpf` device, or `libpcap` refuses
            the capture filter.
        OSError: The host refuses the capture socket, or it holds no such interface.
        ValueError: The host holds no interface of that name, or `poll_interval` is no
            positive finite number.
    """
    from scapy.all import sniff

    # `AsyncSniffer._run` breaks before it waits while the remaining time is at or below
    # zero, so a poll interval of zero would turn this loop into a spin. #55 shipped the
    # same guard for `--stats-interval`, where `nan` produced the same defect.
    if not math.isfinite(poll_interval) or poll_interval <= 0:
        raise ValueError(f"the poll interval must be a positive finite number: {poll_interval!r}")

    stopped = False

    def stop_after(packet: Packet) -> bool:
        """Return True when the stop filter ends the capture at this packet.

        The loop reads the answer too, because `sniff` reports the reason it returned to
        no caller.

        Args:
            packet: The packet the capture just reported.

        Returns:
            True when the capture stops after this packet, and False before it.
        """
        nonlocal stopped
        if stop_filter is not None and stop_filter(packet):
            stopped = True
        return stopped

    capture_socket = open_socket(interface, capture_filter)
    try:
        while not stopped:
            sniff(
                prn=handle_packet,
                store=0,
                opened_socket=capture_socket,
                timeout=poll_interval,
                stop_filter=stop_after,
            )
            if stop_requested is not None and stop_requested():
                return
            # `AsyncSniffer._run` closes a socket whose read raised at
            # `scapy/sendrecv.py:1370`, and it drops that
            # socket from its list. A loop that called `sniff` again would wait on a
            # closed socket for as long as the monitor runs.
            if capture_socket.closed:
                return
    finally:
        capture_socket.close()
