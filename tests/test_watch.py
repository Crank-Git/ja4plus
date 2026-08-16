"""The connection table and the monitor loop of `ja4plus watch`.

`docs/specs/features/06-live-capture.md` states the requirements this file measures.

- FR-live-capture-1 asks for the command `ja4plus watch <interface>`.
- FR-live-capture-2 asks the command to evict a connection that stops sending.
- FR-live-capture-3 asks for the `--max-connections` option.
- FR-live-capture-4 asks for the `--connection-timeout` option.
- FR-live-capture-5 asks for a clean exit on `SIGINT`.
- FR-live-capture-6 asks for a clean exit on `SIGTERM`.
- FR-live-capture-7 asks the command to flush its output before it exits.
- FR-live-capture-14 keeps `ja4plus live` as an alias of `ja4plus watch`.

Version 0.6.0 called `cleanup_connection` never, so a monitor grew until the host
stopped it. Each test below fails against that code.

No test here opens a capture interface. Every test drives the monitor from an injected
packet source, so the measured behavior is the loop and not the capture layer.
"""

import io
import json
import os
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

from scapy.all import IP, TCP, Ether

from ja4plus.processor import Processor
from ja4plus.watch import (
    DEFAULT_CONNECTION_TIMEOUT,
    DEFAULT_MAX_CONNECTIONS,
    Monitor,
    MonitorStats,
    StopRequest,
    connection_key,
    stop_on_signal,
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

    The real processor drops the state of ten fingerprinters, and a test that reads its tables
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
    """Return the count of entries the state tables of all ten fingerprinters hold.

    Args:
        processor: The processor the monitor drives.

    Returns:
        The sum of the entry counts the processor reports.
    """
    return sum(report.entries for report in processor.stats().values())


class TheEvictionDropsThePerMethodState(unittest.TestCase):
    """The eviction reaches the state tables of the ten fingerprinters, and not the key alone.

    An eviction that drops the entry of the connection table and leaves the state of the
    ten fingerprinters is the leak wearing a bound as a disguise. The two tests below measure
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
        """A packet the key reader refuses still reaches the ten fingerprinters."""
        seen = []
        monitor = Monitor(CleanupRecorder(), seen.append)
        packet = Ether()
        monitor.handle_packet(packet)
        self.assertEqual(seen, [packet])
        self.assertEqual(monitor.tracked_connections(), [])


def run_cli(*argv, source=None, monitor_factory=None):
    """Run the command-line program and return its standard output, error and status.

    The call replaces the capture with the packets the test states, so it opens no
    interface. The command reads no user identity: #56 replaced the `os.geteuid` check
    of version 0.6.0 with a failed capture attempt.

    Args:
        argv: The arguments to pass, without the program name.
        source: A list of packets the fake capture replays, or None for no packet.
        monitor_factory: A callable to install in place of `ja4plus.cli.Monitor`, or
            None to let the command build the real monitor.

    Returns:
        A tuple of the standard output, the standard error and the exit status.
    """
    from ja4plus.cli import main

    def read_interface(
        interface,
        handle_packet,
        stop_filter=None,
        capture_filter=None,
        stop_requested=None,
        drop_count=None,
    ):
        """Replay the packets the test states, the way `scapy` reads an interface.

        `scapy` reports one packet through `prn` and then applies `stop_filter` to the
        same packet, and it ends the capture when the filter returns True.
        `scapy/sendrecv.py` holds that order in `AsyncSniffer._run`, at the line
        `if (stop_filter and stop_filter(p))`, which follows the `prn` call.

        #320 added the loop that reads `stop_requested` after each poll interval, and
        this replay reads it after each packet. `tests/test_watch_stop.py` measures that
        loop against the real `scapy` capture loop.
        """
        for packet in source or []:
            handle_packet(packet)
            if stop_filter is not None and stop_filter(packet):
                break
            if stop_requested is not None and stop_requested():
                break

    captured_out = io.StringIO()
    captured_err = io.StringIO()
    patches = [
        patch("sys.argv", ["ja4plus"] + list(argv)),
        patch("sys.stdout", captured_out),
        patch("sys.stderr", captured_err),
        patch("ja4plus.cli.read_interface", read_interface),
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
        self.assertEqual(len(built), 1)
        # #423 passes the counts too, because the `dropped` field reads the capture
        # socket. The case reads the two bounds it names, and it names no other key.
        bounds = {name: value for name, value in built[0].items() if name != "stats"}
        self.assertEqual(bounds, {"max_connections": 7, "connection_timeout": 11.5})
        self.assertIsInstance(built[0]["stats"], MonitorStats)

    def test_the_command_refuses_a_maximum_below_one(self):
        _, err, status = run_cli("watch", "eth0", "--max-connections", "0")
        self.assertNotEqual(status, 0)
        self.assertIn("--max-connections", err)

    def test_the_command_refuses_a_timeout_below_zero(self):
        _, err, status = run_cli("watch", "eth0", "--connection-timeout", "-1")
        self.assertNotEqual(status, 0)
        self.assertIn("--connection-timeout", err)


class TheHandlerSetsTheFlagAndReturns(unittest.TestCase):
    """FR-live-capture-5 and FR-live-capture-6 — the handler sets a flag and returns.

    A handler that called `sys.exit` would end the run at the point the signal arrived,
    and that point holds half a line whenever the signal arrives during a write. Version
    0.6.0 called `sys.exit` inside the handler of `ja4plus/collector.py`.
    """

    def test_the_flag_is_clear_before_a_signal_arrives(self):
        self.assertFalse(StopRequest().requested())

    def test_the_handler_sets_the_flag(self):
        stop = StopRequest()
        stop.request(signal.SIGTERM, None)
        self.assertTrue(stop.requested())

    def test_the_handler_raises_no_system_exit(self):
        """A handler that exits truncates the line the command holds half written."""
        stop = StopRequest()
        try:
            self.assertIsNone(stop.request(signal.SIGTERM, None))
        except SystemExit:  # pragma: no cover - the failure of this case
            self.fail("the handler called sys.exit")

    def test_the_stop_filter_reads_the_flag(self):
        stop = StopRequest()
        packet = tcp_packet()
        self.assertFalse(stop.stop_after(packet))
        stop.request(signal.SIGINT, None)
        self.assertTrue(stop.stop_after(packet))


class SignalGuard(unittest.TestCase):
    """A case that installs a handler of its own for each termination signal.

    Each case below sends a real signal to this process. The default handler of `SIGTERM`
    ends the process, so a build that installs no handler would end the test run rather
    than fail one case. The guard replaces both handlers first, and restores them after.
    """

    def setUp(self):
        self.previous = {
            number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)
        }
        for number in self.previous:
            signal.signal(number, lambda number, frame: None)

    def tearDown(self):
        for number, handler in self.previous.items():
            signal.signal(number, handler)


class TheCommandInstallsTheTwoHandlers(SignalGuard):
    """FR-live-capture-5 and FR-live-capture-6 — `SIGINT` and `SIGTERM` both stop it."""

    def test_a_real_sigterm_sets_the_flag(self):
        with stop_on_signal() as stop:
            os.kill(os.getpid(), signal.SIGTERM)
            self.assertTrue(stop.requested())

    def test_a_real_sigint_sets_the_flag(self):
        with stop_on_signal() as stop:
            os.kill(os.getpid(), signal.SIGINT)
            self.assertTrue(stop.requested())

    def test_the_call_restores_the_handler_it_replaced(self):
        """A monitor that ran twice in one process must leave no handler behind."""
        previous = signal.getsignal(signal.SIGTERM)
        with stop_on_signal():
            self.assertNotEqual(signal.getsignal(signal.SIGTERM), previous)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_the_call_restores_the_handler_after_an_error(self):
        previous = signal.getsignal(signal.SIGINT)
        with self.assertRaises(ValueError):
            with stop_on_signal():
                raise ValueError("the capture failed")
        self.assertEqual(signal.getsignal(signal.SIGINT), previous)


def packets_with_a_signal_at(number, packets, index):
    """Return a packet source that sends one signal to this process, then continues.

    Args:
        number: The signal number to send.
        packets: The packets the source replays.
        index: The position of the packet the signal arrives before.

    Yields:
        Each packet in turn. The signal arrives while the loop holds the packet at
        `index`, so a handler that stops the loop early loses the rest.
    """
    for position, packet in enumerate(packets):
        if position == index:
            os.kill(os.getpid(), number)
        yield packet


class TheMonitorStopsOnATerminationSignal(SignalGuard):
    """FR-live-capture-5 and FR-live-capture-6 — the command exits cleanly on a signal.

    Each case sends a real signal to this process while the loop reads a packet.
    """

    def read_three_packets(self, number):
        """Run the command against three packets, with one signal before the third.

        Args:
            number: The signal number the source sends.

        Returns:
            A tuple of the ports the output names and the exit status.
        """
        packets = [tcp_packet(src_port=port, when=1.0) for port in (1024, 1025, 1026)]
        source = packets_with_a_signal_at(number, packets, 2)
        out, err, status = run_cli("--format", "json", "watch", "eth0", source=source)
        ports = [json.loads(line)["src_port"] for line in out.splitlines() if line.strip()]
        return ports, status, err

    def test_sigterm_ends_the_run_with_the_status_zero(self):
        _, status, err = self.read_three_packets(signal.SIGTERM)
        self.assertEqual(status, 0, err)

    def test_sigint_ends_the_run_with_the_status_zero(self):
        _, status, err = self.read_three_packets(signal.SIGINT)
        self.assertEqual(status, 0, err)

    def test_the_capture_reads_the_packet_the_signal_arrives_during(self):
        """The loop finishes the packet it holds, so the output holds its fingerprint."""
        ports, _, err = self.read_three_packets(signal.SIGTERM)
        self.assertIn(1026, ports, err)

    def test_the_capture_reads_no_packet_after_the_signal(self):
        """The stop filter ends the capture, so the source keeps its last packet."""
        packets = [tcp_packet(src_port=port, when=1.0) for port in (1024, 1025, 1026)]
        source = packets_with_a_signal_at(signal.SIGTERM, packets, 1)
        out, err, status = run_cli("--format", "json", "watch", "eth0", source=source)
        ports = [json.loads(line)["src_port"] for line in out.splitlines() if line.strip()]
        self.assertEqual(status, 0, err)
        self.assertEqual(ports, [1024, 1025])

    def test_the_capture_reads_every_packet_when_no_signal_arrives(self):
        """The control of the case above: the same three packets, and no signal."""
        packets = [tcp_packet(src_port=port, when=1.0) for port in (1024, 1025, 1026)]
        out, err, status = run_cli("--format", "json", "watch", "eth0", source=packets)
        ports = [json.loads(line)["src_port"] for line in out.splitlines() if line.strip()]
        self.assertEqual(status, 0, err)
        self.assertEqual(ports, [1024, 1025, 1026])


class RecordingStream(io.StringIO):
    """A stream that records the order of the write calls, the flush call and the close.

    Python flushes every stream when the interpreter shuts down. A case that ends the
    program and then reads a complete file therefore passes against a command that
    flushes never. This stream records the calls themselves, so a case reads the order:
    the last line, then the flush, then the close.

    Attributes:
        events: One name for each call, in the order the calls arrived.
    """

    def __init__(self):
        super().__init__()
        self.events = []

    def write(self, text):
        self.events.append("write")
        return super().write(text)

    def flush(self):
        self.events.append("flush")
        return super().flush()

    def close(self):
        # The buffer stays open, because a closed `StringIO` answers `getvalue` never.
        self.events.append("close")


def run_cli_against_a_recorded_file(*argv, source=None):
    """Run the command with `--output`, and return the stream that recorded the calls.

    The call replaces the builtin `open`, so the command opens the real
    `_result_stream` path and writes to the recorder. Standard output records nothing
    here: `main` flushes standard output for every subcommand, and a recorder in that
    position would report that flush as the flush of this feature.

    Args:
        argv: The arguments to pass, without the program name and without `--output`.
        source: The packets the fake capture replays.

    Returns:
        A tuple of the recorder and the exit status.
    """
    recorder = RecordingStream()
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "results")
        with patch("builtins.open", lambda *args, **kwargs: recorder):
            _, err, status = run_cli(*argv, "--output", path, source=source)
    return recorder, status, err


class TheCommandFlushesTheOutputBeforeItExits(unittest.TestCase):
    """FR-live-capture-7 — the command flushes its output before it exits.

    The interpreter flushes a stream at shutdown and `close` flushes a file, so neither
    a complete file nor a green exit proves that this command flushes. Each case below
    reads the recorded call order instead.
    """

    def test_the_command_flushes_the_output_that_holds_no_fingerprint(self):
        """The case that fails without the flush this issue adds.

        The header is the one line the run writes, and no fingerprint follows it, so the
        per-result flush of the report call never runs.
        """
        recorder, status, err = run_cli_against_a_recorded_file(
            "--format", "csv", "watch", "eth0", source=[]
        )
        self.assertEqual(status, 0, err)
        self.assertIn("flush", recorder.events)
        self.assertEqual(recorder.events[-2:], ["flush", "close"])

    def test_the_command_flushes_after_the_last_line_it_writes(self):
        packets = [tcp_packet(src_port=1024, when=1.0)]
        recorder, status, err = run_cli_against_a_recorded_file(
            "--format", "json", "watch", "eth0", source=packets
        )
        self.assertEqual(status, 0, err)
        self.assertEqual(recorder.events[-2:], ["flush", "close"])
        self.assertGreater(recorder.events.index("write"), -1)

    def test_the_flush_precedes_the_close_of_the_output_file(self):
        """A flush that the close performs is the close, and not this command."""
        packets = [tcp_packet(src_port=1024, when=1.0)]
        recorder, _, _ = run_cli_against_a_recorded_file(
            "--format", "json", "watch", "eth0", source=packets
        )
        self.assertLess(recorder.events.index("flush"), recorder.events.index("close"))


class TheOutputFileHoldsEveryFingerprintTheMonitorReported(SignalGuard):
    """The third acceptance criterion of #54, read from a real file on disk."""

    def test_the_file_written_before_sigterm_holds_every_fingerprint(self):
        packets = [tcp_packet(src_port=port, when=1.0) for port in (1024, 1025, 1026)]
        source = packets_with_a_signal_at(signal.SIGTERM, packets, 2)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "results.jsonl")
            out, err, status = run_cli(
                "--format", "json", "watch", "eth0", "--output", path, source=source
            )
            with open(path, encoding="utf-8") as handle:
                lines = [line for line in handle.read().splitlines() if line.strip()]
        self.assertEqual(status, 0, err)
        self.assertEqual(out, "")
        self.assertEqual([json.loads(line)["src_port"] for line in lines], [1024, 1025, 1026])


if __name__ == "__main__":
    sys.exit(unittest.main())
