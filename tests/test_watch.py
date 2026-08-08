"""The connection table and the monitor loop of `ja4plus watch`.

`docs/specs/features/06-live-capture.md` states the requirements this file measures.

- FR-live-capture-1 asks for the command `ja4plus watch <interface>`.
- FR-live-capture-2 asks the command to evict a connection that stops sending.
- FR-live-capture-3 asks for the `--max-connections` option.
- FR-live-capture-4 asks for the `--connection-timeout` option.
- FR-live-capture-14 keeps `ja4plus live` as an alias of `ja4plus watch`.

Version 0.6.0 called `cleanup_connection` never, so a monitor grew until the host
stopped it. Each test below fails against that code.

No test here opens a capture interface. Every test drives the monitor from an injected
packet source, so the measured behaviour is the loop and not the capture layer.
"""

import io
import sys
import unittest
from unittest.mock import patch

from scapy.all import IP, TCP, Ether

from ja4plus.processor import Processor
from ja4plus.watch import (
    DEFAULT_CONNECTION_TIMEOUT,
    DEFAULT_MAX_CONNECTIONS,
    Monitor,
    connection_key,
)


def tcp_packet(src_ip="10.0.0.1", src_port=1024, dst_ip="10.0.0.2", dst_port=443, when=0.0):
    """Return one TCP packet with the stated endpoints and capture time.

    Args:
        src_ip: The source address.
        src_port: The source port.
        dst_ip: The destination address.
        dst_port: The destination port.
        when: The capture time, in seconds since the epoch.

    Returns:
        A `scapy` packet.
    """
    packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S")
    packet.time = when
    return packet


class CleanupRecorder:
    """A stand-in for `Processor` that records every `cleanup_connection` call.

    The real processor drops the state of ten methods, and a test that reads its tables
    measures the drop rather than the call. This recorder measures the call itself.

    Attributes:
        calls: One tuple for each call, holding the five arguments the monitor passed.
    """

    def __init__(self):
        self.calls = []

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        self.calls.append((src_ip, src_port, dst_ip, dst_port, proto))


def no_report(packet):
    """Report nothing. A test that measures the connection table needs no output."""


class TheConnectionKeyNamesOneConnection(unittest.TestCase):
    """The monitor holds one entry for one connection, whichever direction it reads."""

    def test_the_key_of_the_two_directions_of_one_connection_is_one_key(self):
        forward = connection_key(tcp_packet("10.0.0.1", 1024, "10.0.0.2", 443))
        backward = connection_key(tcp_packet("10.0.0.2", 443, "10.0.0.1", 1024))
        self.assertIsNotNone(forward)
        self.assertEqual(forward, backward)

    def test_the_key_of_a_packet_that_carries_no_port_is_none(self):
        self.assertIsNone(connection_key(Ether()))


class TheMonitorBoundsTheConnectionCount(unittest.TestCase):
    """FR-live-capture-3 — `--max-connections` bounds the tracked-connection count."""

    def test_one_hundred_thousand_packets_hold_the_count_at_the_maximum(self):
        """The acceptance criterion of #53, measured at its stated size.

        The packets name 50000 connections and the bound is 10000, so the table stays at
        the bound and the monitor evicts the rest.
        """
        recorder = CleanupRecorder()
        monitor = Monitor(recorder, no_report)
        packet = tcp_packet()
        for count in range(100000):
            packet[TCP].sport = 10000 + count % 50000
            monitor.handle_packet(packet)
        self.assertLessEqual(len(monitor.tracked_connections()), DEFAULT_MAX_CONNECTIONS)
        self.assertEqual(len(monitor.tracked_connections()), DEFAULT_MAX_CONNECTIONS)
        self.assertGreater(monitor.evictions, 0)

    def test_the_monitor_evicts_the_least_recently_used_connection(self):
        recorder = CleanupRecorder()
        monitor = Monitor(recorder, no_report, max_connections=3)
        for port in (1024, 1025, 1026, 1027):
            monitor.handle_packet(tcp_packet(src_port=port))
        tracked = {key[2] for key in monitor.tracked_connections()}
        self.assertEqual(len(tracked), 3)
        self.assertNotIn(1024, tracked)

    def test_the_monitor_calls_cleanup_connection_for_the_connection_it_evicts(self):
        """An eviction that leaves the per-method state is a leak that wears a bound."""
        recorder = CleanupRecorder()
        monitor = Monitor(recorder, no_report, max_connections=1)
        monitor.handle_packet(tcp_packet(src_ip="10.0.0.1", src_port=1024))
        monitor.handle_packet(tcp_packet(src_ip="10.0.0.1", src_port=1025))
        self.assertEqual(recorder.calls, [("10.0.0.1", 1024, "10.0.0.2", 443, "tcp")])


class TheMonitorEvictsAnIdleConnection(unittest.TestCase):
    """FR-live-capture-2 and FR-live-capture-4 — the age bound sheds an idle connection."""

    def test_a_connection_that_stops_sending_leaves_the_table(self):
        """The eviction reads the capture time, so no test waits for a wall clock."""
        recorder = CleanupRecorder()
        monitor = Monitor(recorder, no_report)
        idle = tcp_packet(src_ip="10.0.0.9", src_port=2048, when=0.0)
        monitor.handle_packet(idle)
        self.assertIn(("tcp", "10.0.0.2", 443, "10.0.0.9", 2048), monitor.tracked_connections())

        # The age pass runs on a packet schedule, so the traffic below drives it. The
        # default schedule runs one pass every 1000 packets.
        for count in range(1, 1201):
            monitor.handle_packet(tcp_packet(src_ip="10.0.0.8", src_port=3000, when=float(count)))

        self.assertNotIn(("tcp", "10.0.0.2", 443, "10.0.0.9", 2048), monitor.tracked_connections())
        self.assertIn(("10.0.0.2", 443, "10.0.0.9", 2048, "tcp"), recorder.calls)

    def test_a_connection_that_keeps_sending_stays_in_the_table(self):
        """A bound that evicts a busy connection loses the traffic it must fingerprint."""
        recorder = CleanupRecorder()
        monitor = Monitor(recorder, no_report)
        for count in range(1, 1201):
            monitor.handle_packet(tcp_packet(src_ip="10.0.0.9", src_port=2048, when=float(count)))
            monitor.handle_packet(tcp_packet(src_ip="10.0.0.8", src_port=3000, when=float(count)))
        self.assertIn(("tcp", "10.0.0.2", 443, "10.0.0.9", 2048), monitor.tracked_connections())
        self.assertEqual(recorder.calls, [])

    def test_the_timeout_the_caller_states_decides_the_age(self):
        recorder = CleanupRecorder()
        monitor = Monitor(recorder, no_report, connection_timeout=10.0, eviction_interval=2)
        monitor.handle_packet(tcp_packet(src_ip="10.0.0.9", src_port=2048, when=0.0))
        monitor.handle_packet(tcp_packet(src_ip="10.0.0.8", src_port=3000, when=5.0))
        self.assertIn(("tcp", "10.0.0.2", 443, "10.0.0.9", 2048), monitor.tracked_connections())
        monitor.handle_packet(tcp_packet(src_ip="10.0.0.8", src_port=3000, when=50.0))
        monitor.handle_packet(tcp_packet(src_ip="10.0.0.8", src_port=3000, when=51.0))
        self.assertNotIn(("tcp", "10.0.0.2", 443, "10.0.0.9", 2048), monitor.tracked_connections())


def stored_entries(processor):
    """Return the count of entries the state tables of all ten methods hold.

    Args:
        processor: The processor the monitor drives.

    Returns:
        The sum of the entry counts the processor reports.
    """
    return sum(report.entries for report in processor.stats().values())


class TheEvictionDropsThePerMethodState(unittest.TestCase):
    """The eviction reaches the state tables of the ten methods, and not the key alone.

    An eviction that drops the entry of the connection table and leaves the state of the
    ten methods is the leak wearing a bound as a disguise. The two tests below measure
    the same two packets against two bounds, so the second is the control of the first.
    """

    def test_the_processor_holds_no_entry_of_the_connection_the_monitor_evicts(self):
        processor = Processor()
        monitor = Monitor(processor, processor.process_packet, max_connections=1)
        monitor.handle_packet(tcp_packet(src_ip="10.0.0.1", src_port=1024))
        first = stored_entries(processor)
        self.assertGreater(first, 0, "the first packet leaves state to drop")

        monitor.handle_packet(tcp_packet(src_ip="10.0.0.3", src_port=1025))
        self.assertEqual(
            stored_entries(processor),
            first,
            "the eviction of the first connection makes room for the second",
        )

    def test_the_processor_holds_both_connections_when_the_bound_holds_both(self):
        processor = Processor()
        monitor = Monitor(processor, processor.process_packet, max_connections=2)
        monitor.handle_packet(tcp_packet(src_ip="10.0.0.1", src_port=1024))
        first = stored_entries(processor)
        monitor.handle_packet(tcp_packet(src_ip="10.0.0.3", src_port=1025))
        self.assertEqual(stored_entries(processor), 2 * first)


class TheMonitorReportsEveryPacket(unittest.TestCase):
    """The monitor reads the packet before it reports it, so no eviction loses a packet."""

    def test_the_monitor_reports_one_packet_once(self):
        seen = []
        monitor = Monitor(CleanupRecorder(), seen.append, max_connections=1)
        first = tcp_packet(src_port=1024)
        second = tcp_packet(src_port=1025)
        monitor.handle_packet(first)
        monitor.handle_packet(second)
        self.assertEqual(seen, [first, second])

    def test_the_monitor_reports_a_packet_that_names_no_connection(self):
        """A packet the key reader refuses still reaches the ten methods."""
        seen = []
        monitor = Monitor(CleanupRecorder(), seen.append)
        packet = Ether()
        monitor.handle_packet(packet)
        self.assertEqual(seen, [packet])
        self.assertEqual(monitor.tracked_connections(), [])


def run_cli(*argv, source=None, monitor_factory=None):
    """Run the command-line program and return its standard output, error and status.

    The call replaces the capture with the packets the test states, so it opens no
    interface. It also reports the user identity zero, because the privilege check of
    version 0.6.0 reads `os.geteuid` and #56 owns the replacement.

    Args:
        argv: The arguments to pass, without the program name.
        source: A list of packets the fake capture replays, or None for no packet.
        monitor_factory: A callable to install in place of `ja4plus.cli.Monitor`, or
            None to let the command build the real monitor.

    Returns:
        A tuple of the standard output, the standard error and the exit status.
    """
    from ja4plus.cli import main

    def read_interface(interface, handle_packet):
        for packet in source or []:
            handle_packet(packet)

    captured_out = io.StringIO()
    captured_err = io.StringIO()
    patches = [
        patch("sys.argv", ["ja4plus"] + list(argv)),
        patch("sys.stdout", captured_out),
        patch("sys.stderr", captured_err),
        patch("ja4plus.cli.read_interface", read_interface),
        patch("os.geteuid", lambda: 0, create=True),
    ]
    if monitor_factory is not None:
        patches.append(patch("ja4plus.cli.Monitor", monitor_factory))

    status = 0
    try:
        for entered in patches:
            entered.start()
        try:
            main()
        except SystemExit as e:
            status = e.code if e.code is not None else 0
    finally:
        for entered in reversed(patches):
            entered.stop()

    return captured_out.getvalue(), captured_err.getvalue(), status


class TheWatchCommandDocumentsItsOptions(unittest.TestCase):
    """FR-live-capture-3 and FR-live-capture-4 — `--help` names both options."""

    def test_the_help_names_the_two_connection_table_options(self):
        out, _, status = run_cli("watch", "--help")
        self.assertEqual(status, 0)
        self.assertIn("--max-connections", out)
        self.assertIn("--connection-timeout", out)

    def test_the_help_states_the_default_of_each_option(self):
        out, _, _ = run_cli("watch", "--help")
        self.assertIn(str(DEFAULT_MAX_CONNECTIONS), out)
        self.assertIn(str(int(DEFAULT_CONNECTION_TIMEOUT)), out)


class TheLiveCommandIsAnAliasOfWatch(unittest.TestCase):
    """FR-live-capture-14 — `ja4plus live eth0` behaves the same as `ja4plus watch eth0`."""

    def test_the_two_commands_write_the_same_result(self):
        packets = [tcp_packet(src_port=1024, when=1.0)]
        watched = run_cli("--format", "json", "watch", "eth0", source=packets)
        lived = run_cli("--format", "json", "live", "eth0", source=packets)
        self.assertEqual(watched[2], 0, watched[1])
        self.assertTrue(watched[0].strip(), "the capture produced no result")
        self.assertEqual(watched[0], lived[0])

    def test_the_two_commands_accept_the_same_options(self):
        """One parser serves both names, so one help text describes both."""
        watched, _, status = run_cli("watch", "--help")
        lived, _, _ = run_cli("live", "--help")
        self.assertEqual(status, 0)
        self.assertIn("--max-connections", watched)
        self.assertEqual(watched, lived)


class TheCommandPassesTheBoundsToTheMonitor(unittest.TestCase):
    """FR-live-capture-3 and FR-live-capture-4 — the option reaches the table."""

    def test_the_command_builds_the_monitor_with_the_bounds_the_user_stated(self):
        built = []

        def factory(processor, report, **bounds):
            built.append(bounds)
            return Monitor(processor, report, **bounds)

        _, err, status = run_cli(
            "watch",
            "eth0",
            "--max-connections",
            "7",
            "--connection-timeout",
            "11.5",
            monitor_factory=factory,
        )
        self.assertEqual(status, 0, err)
        self.assertEqual(built, [{"max_connections": 7, "connection_timeout": 11.5}])

    def test_the_command_refuses_a_maximum_below_one(self):
        _, err, status = run_cli("watch", "eth0", "--max-connections", "0")
        self.assertNotEqual(status, 0)
        self.assertIn("--max-connections", err)

    def test_the_command_refuses_a_timeout_below_zero(self):
        _, err, status = run_cli("watch", "eth0", "--connection-timeout", "-1")
        self.assertNotEqual(status, 0)
        self.assertIn("--connection-timeout", err)


if __name__ == "__main__":
    sys.exit(unittest.main())
