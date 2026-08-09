"""The statistics line of `ja4plus watch`, and the thread that writes it.

`docs/specs/features/06-live-capture.md` states the requirements this file measures.

- FR-live-capture-8 asks the command to report statistics on exit.
- FR-live-capture-9 asks for the `--stats-interval` option.
- FR-live-capture-10 asks the command to write statistics to standard error.

The statistics thread reads counters that the capture thread writes. `MonitorStats`
holds one lock over every write and over every read, so a reader reads the counts of
one instant. The counts of one test hold four different values, so a field wired to
another counter fails the test that names it.

No test here opens a capture interface. Every test drives the monitor from an injected
packet source, so the measured behaviour is the loop and not the capture layer.
"""

import io
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.all import IP, TCP, Ether, rdpcap

from ja4plus.watch import (
    STATISTICS_THREAD_NAME,
    Monitor,
    MonitorStats,
    StatisticsReporter,
    StatisticsSnapshot,
    format_statistics,
    write_statistics,
)

from tests.test_watch import CleanupRecorder, no_report, tcp_packet

# The line `docs/specs/features/06-live-capture.md` publishes, reproduced verbatim.
SPECIFIED_LINE = (
    "[ja4plus] packets=1284302 fingerprints=48211 connections=8134 "
    "evicted=112094 dropped=0 uptime=3600s"
)


class FakeClock:
    """A clock the test moves by hand.

    A real clock makes an uptime test read the speed of the host. This clock returns
    the value the test states.

    Args:
        start: The value the first call returns.
    """

    def __init__(self, start=0.0):
        self.now = start

    def __call__(self):
        return self.now


def run_watch(*argv, source=None, during=None):
    """Run the command-line program against an injected packet source.

    The call replaces the capture with the packets the test states, so it opens no
    interface. The command reads no user identity: #56 replaced the `os.geteuid` check
    of version 0.6.0 with a failed capture attempt.

    Args:
        argv: The arguments to pass, without the program name.
        source: A list of packets the fake capture replays, or None for no packet.
        during: A callable the fake capture calls once, before it replays the packets.
            A test that measures the statistics thread runs inside the capture, because
            the thread stops when the capture returns.

    Returns:
        A tuple of the standard output, the standard error and the exit status.
    """
    from ja4plus.cli import main

    def read_interface(
        interface, handle_packet, stop_filter=None, capture_filter=None, stop_requested=None
    ):
        if during is not None:
            during()
        for packet in source or []:
            handle_packet(packet)
            if stop_filter is not None and stop_filter(packet):
                break
            # #320 added the loop that reads the stop request after each poll interval.
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


def statistics_lines(text):
    """Return every statistics line the text holds.

    Args:
        text: The text the command wrote to standard error.

    Returns:
        A list of the lines that start with the statistics prefix.
    """
    return [line for line in text.splitlines() if line.startswith("[ja4plus] packets=")]


def monitor_that_read(packets, fingerprints, max_connections):
    """Return a monitor that read the packets, with the fingerprint count recorded.

    Args:
        packets: The packets to feed to `handle_packet`.
        fingerprints: The count of fingerprints the report announces, spread one for
            each of the first `fingerprints` packets.
        max_connections: The maximum entry count of the connection table.

    Returns:
        The monitor, after it read every packet.
    """
    monitor = Monitor(
        CleanupRecorder(),
        no_report,
        max_connections=max_connections,
        connection_timeout=1e9,
    )
    for index, packet in enumerate(packets):
        if index < fingerprints:
            monitor.stats.count_fingerprints(1)
        monitor.handle_packet(packet)
    return monitor


def one_handshake():
    """Return the two packets of one TCP handshake, in one connection.

    The pair produces three fingerprints, so the packet count, the fingerprint count
    and the connection count of the case are 2, 3 and 1.

    Returns:
        A list of two `scapy` packets, a SYN and a SYN-ACK.
    """
    syn = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1024, dport=443, flags="S")
    syn.time = 0.0
    syn_ack = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=443, dport=1024, flags="SA")
    syn_ack.time = 0.1
    return [syn, syn_ack]


def seven_packets_across_five_connections():
    """Return seven packets that name five connections, the last one three times."""
    packets = [tcp_packet(src_port=1000 + index, when=float(index)) for index in range(5)]
    packets.append(tcp_packet(src_port=1004, when=5.0))
    packets.append(tcp_packet(src_port=1004, when=6.0))
    return packets


class TheStatisticsLineHoldsTheFieldsTheSpecificationStates(unittest.TestCase):
    """FR-live-capture-8 — the line names the packet, fingerprint and table counts."""

    def test_the_line_equals_the_line_the_specification_publishes(self):
        snapshot = StatisticsSnapshot(
            packets=1284302,
            fingerprints=48211,
            connections=8134,
            evicted=112094,
            dropped=0,
            uptime=3600.0,
        )
        self.assertEqual(format_statistics(snapshot), SPECIFIED_LINE)

    def test_the_line_writes_null_where_the_capture_layer_reports_no_drop_count(self):
        snapshot = StatisticsSnapshot(
            packets=1, fingerprints=2, connections=3, evicted=4, dropped=None, uptime=5.0
        )
        self.assertIn("dropped=null", format_statistics(snapshot))

    def test_the_line_writes_the_drop_count_the_capture_layer_states(self):
        snapshot = StatisticsSnapshot(
            packets=1, fingerprints=2, connections=3, evicted=4, dropped=17, uptime=5.0
        )
        self.assertIn("dropped=17", format_statistics(snapshot))

    def test_the_snapshot_repr_names_every_count(self):
        """A failed comparison reads the six counts, and not an object address."""
        snapshot = StatisticsSnapshot(
            packets=1, fingerprints=2, connections=3, evicted=4, dropped=5, uptime=6.0
        )
        text = repr(snapshot)
        for field in ("packets=1", "fingerprints=2", "connections=3", "evicted=4"):
            self.assertIn(field, text)
        self.assertIn("dropped=5", text)
        self.assertIn("uptime=6.0", text)

    def test_the_line_truncates_the_uptime_to_a_whole_second(self):
        snapshot = StatisticsSnapshot(
            packets=1, fingerprints=2, connections=3, evicted=4, dropped=0, uptime=60.9
        )
        self.assertIn("uptime=60s", format_statistics(snapshot))


class TheCountsReportTheTrafficTheMonitorRead(unittest.TestCase):
    """FR-live-capture-8 — each count reports its own measurement.

    The monitor reads seven packets across five connections, and it holds three of
    them. The four counts are therefore 7, 4, 3 and 2. No two are equal, so a field
    that reads another counter fails the case that names it.
    """

    def setUp(self):
        self.monitor = monitor_that_read(
            seven_packets_across_five_connections(), fingerprints=4, max_connections=3
        )
        self.snapshot = self.monitor.stats.snapshot()

    def test_the_packet_count_reports_every_packet_the_monitor_read(self):
        self.assertEqual(self.snapshot.packets, 7)

    def test_the_fingerprint_count_reports_every_fingerprint_the_monitor_reported(self):
        self.assertEqual(self.snapshot.fingerprints, 4)

    def test_the_connection_count_reports_the_entries_the_table_holds(self):
        self.assertEqual(self.snapshot.connections, 3)
        self.assertEqual(len(self.monitor.tracked_connections()), 3)

    def test_the_eviction_count_reports_every_connection_the_table_evicted(self):
        self.assertEqual(self.snapshot.evicted, 2)
        self.assertEqual(self.monitor.evictions, 2)

    def test_a_monitor_that_read_no_packet_reports_zero_counts(self):
        stats = MonitorStats()
        snapshot = stats.snapshot()
        self.assertEqual(
            (snapshot.packets, snapshot.fingerprints, snapshot.connections, snapshot.evicted),
            (0, 0, 0, 0),
        )


class TheUptimeReportsTheSecondsSinceTheMonitorStarted(unittest.TestCase):
    """FR-live-capture-8 — the line reports how long the monitor ran."""

    def test_the_uptime_reads_the_clock_the_monitor_started_from(self):
        clock = FakeClock(100.0)
        stats = MonitorStats(clock=clock)
        clock.now = 160.5
        self.assertEqual(stats.snapshot().uptime, 60.5)

    def test_the_uptime_of_a_monitor_that_just_started_is_zero(self):
        clock = FakeClock(100.0)
        self.assertEqual(MonitorStats(clock=clock).snapshot().uptime, 0.0)


class TheDropCountComesFromTheCaptureLayer(unittest.TestCase):
    """The `dropped` field reports a measurement, and `null` where none exists.

    `scapy` 2.7.0 gives the monitor no drop count through `sniff`, so the command
    passes no source and the field reads `null`. The docstring of `MonitorStats` in
    `ja4plus/watch.py` holds the measurement.
    """

    def test_the_count_is_null_when_the_capture_layer_states_none(self):
        self.assertIsNone(MonitorStats().snapshot().dropped)

    def test_the_count_reads_the_source_the_caller_states(self):
        stats = MonitorStats(dropped_source=lambda: 42)
        self.assertEqual(stats.snapshot().dropped, 42)

    def test_a_source_that_reports_nothing_leaves_the_count_null(self):
        stats = MonitorStats(dropped_source=lambda: None)
        self.assertIsNone(stats.snapshot().dropped)


class TheSnapshotReadsOneInstant(unittest.TestCase):
    """The statistics thread reads counters that the capture thread writes.

    `MonitorStats` publishes the four counts under one lock, so a reader reads them
    together. The capture thread is the only thread that reads the connection table.

    Warning: a case that reads an invariant while another thread writes it measures
    nothing here. The measurement of 2026-08-08 ran one reader against one writer for
    20000 writes, with the lock and without it. Both read 97635 snapshots and both
    found 0 broken invariants, at the default switch interval and at one microsecond.
    CPython leaves one thread inside three attribute stores that hold no call and no
    backward jump, so the reader never samples the gap. The case below therefore holds
    the reader inside the guarded region by hand, and it measures the wait of the
    writer.
    """

    def test_the_snapshot_reads_no_connection_table(self):
        """A snapshot holds against a table that raises on every read."""

        class RaisingTable:
            def __len__(self):
                raise AssertionError("the statistics thread read the connection table")

            def __getattr__(self, name):
                raise AssertionError("the statistics thread read the connection table")

        monitor = monitor_that_read(
            seven_packets_across_five_connections(), fingerprints=4, max_connections=3
        )
        monitor._connections = RaisingTable()
        snapshot = monitor.stats.snapshot()
        self.assertEqual(snapshot.packets, 7)
        self.assertEqual(snapshot.connections, 3)

    def test_a_write_waits_while_a_read_holds_the_guarded_region(self):
        """One thread at a time reads or writes the four counts.

        The clock of the snapshot blocks, so the reader stays inside the guarded
        region. The writer then calls `record_packet`, and it reaches no count until
        the reader leaves. A `MonitorStats` that acquires nothing lets the writer
        finish, and this case reports that.
        """
        inside = threading.Event()
        release = threading.Event()
        calls = []

        def blocking_clock():
            calls.append(1)
            # The constructor reads the clock once, and that read starts no thread.
            if len(calls) > 1:
                inside.set()
                release.wait(5.0)
            return 0.0

        stats = MonitorStats(clock=blocking_clock)
        reader = threading.Thread(target=stats.snapshot)
        reader.start()
        self.assertTrue(inside.wait(5.0), "the reader entered no guarded region")

        writer = threading.Thread(target=stats.record_packet, args=(1, 0))
        writer.start()
        writer.join(0.2)
        wrote_beside_the_read = not writer.is_alive()
        release.set()
        reader.join(5.0)
        writer.join(5.0)

        self.assertFalse(wrote_beside_the_read, "the write ran beside the read")
        self.assertEqual(stats.snapshot().packets, 1)

    def test_eight_writers_lose_no_count(self):
        stats = MonitorStats()

        def write():
            for _ in range(2000):
                stats.count_fingerprints(1)
                stats.record_packet(connections=1, evicted=0)

        threads = [threading.Thread(target=write) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        snapshot = stats.snapshot()
        self.assertEqual(snapshot.packets, 16000)
        self.assertEqual(snapshot.fingerprints, 16000)


class ScriptedWait:
    """A wait that the test scripts, in place of the wait on the stop event.

    The reporter calls the wait once for each interval. It writes one line for each call
    that returns False. This call returns False for the count of intervals the test
    states, and True after them. The count of lines is therefore the count the test
    states, and not the count the host delivered.

    The call records every timeout it received, so a case reads the interval the
    reporter asked for.

    Args:
        intervals: The count of intervals that pass before the stop arrives.
    """

    def __init__(self, intervals):
        self._remaining = intervals
        self.timeouts = []

    def __call__(self, timeout):
        self.timeouts.append(timeout)
        if self._remaining == 0:
            return True
        self._remaining -= 1
        return False


class TheReporterWritesOneLinePerInterval(unittest.TestCase):
    """FR-live-capture-9 — `--stats-interval 1` writes a statistics line every second.

    Every case here drives the reporter from a scripted wait, so it states the schedule
    rather than samples it. #369 removed the earlier form, which slept a fraction of a
    second and counted the lines that arrived. That form measured how promptly the host
    scheduled a thread. The `macos-latest, 3.12` job of the run for `8ef8acc` read 2
    lines where the case asked for 3. The sweep of #369 read 4 lines of 5 due, on an
    idle host, at a 0.25 second sleep.

    A case that waits one second per line costs the suite more than it measures. A case
    that waits less than that reports a defect the package does not hold. **No case here
    asserts the elapsed time between two lines**, and #369 removed that assertion on
    purpose, because the host decides that time.

    The reporter still runs on its own thread here, so the cases measure the thread and
    not a loop the case wrote. `stop` joins that thread. The thread blocks on nothing
    once the scripted wait returns True, so the join is a liveness bound and no
    measurement of promptness. Each case names the end of the thread, so a join that
    timed out reports itself rather than shortening a stream.

    `TheReporterStopsCleanly` measures the default wait against the real stop event.
    """

    def run_reporter(self, intervals, interval=0.05, stream=None):
        """Return the stream and the scripted wait, after the reporter thread ends.

        Args:
            intervals: The count of intervals that pass before the stop arrives.
            interval: The count of seconds the caller asks for.
            stream: The stream to write to, or None for a plain one.

        Returns:
            A tuple of the stream and the scripted wait.
        """
        stream = io.StringIO() if stream is None else stream
        wait = ScriptedWait(intervals)
        reporter = StatisticsReporter(MonitorStats(), interval, stream, wait=wait)
        reporter.start()
        reporter.stop()
        self.assertFalse(reporter.is_alive(), "the reporter thread did not end")
        return stream, wait

    def test_the_reporter_writes_one_line_for_each_interval_that_passes(self):
        stream, _ = self.run_reporter(intervals=4)
        self.assertEqual(len(statistics_lines(stream.getvalue())), 4)

    def test_the_reporter_writes_no_second_line_for_one_interval(self):
        """One interval produces one line, so a reporter that wrote a pair fails here."""
        stream, _ = self.run_reporter(intervals=1)
        self.assertEqual(len(statistics_lines(stream.getvalue())), 1)

    def test_the_reporter_asks_the_wait_for_the_interval_the_caller_states(self):
        """FR-live-capture-9 — the interval reaches the wait unchanged.

        The reporter asks for one timeout per interval, and one more for the call that
        reports the stop. Two intervals run, so a reporter that holds a constant fails
        one of them.
        """
        for interval in (0.05, 1.0):
            with self.subTest(interval=interval):
                _, wait = self.run_reporter(intervals=3, interval=interval)
                self.assertEqual(wait.timeouts, [interval] * 4)

    def test_the_reporter_writes_no_line_before_the_first_interval_passes(self):
        """The wait comes first, so a stop that arrives inside interval one writes none."""
        stream, wait = self.run_reporter(intervals=0, interval=10.0)
        self.assertEqual(statistics_lines(stream.getvalue()), [])
        self.assertEqual(wait.timeouts, [10.0])

    def test_the_reporter_flushes_each_line(self):
        """A monitor runs for weeks, so the operator reads each line as it is written."""
        flushes = []

        class FlushRecorder(io.StringIO):
            def flush(self):
                flushes.append(len(statistics_lines(self.getvalue())))
                return super().flush()

        self.run_reporter(intervals=3, stream=FlushRecorder())
        self.assertEqual(flushes, [1, 2, 3])

    def test_the_reporter_waits_on_the_stop_event_when_the_caller_injects_no_wait(self):
        """The scripted wait proves nothing unless the default wait is the real one.

        The cases above read the timeout the reporter passed to an injected wait. This
        case binds that seam to the shipped path: a reporter the caller builds without a
        wait waits on the event that `stop` sets. `TheReporterStopsCleanly` then
        measures that the stop ends the thread.
        """
        reporter = StatisticsReporter(MonitorStats(), 60.0, io.StringIO())
        self.assertEqual(reporter._wait, reporter._stop.wait)


class TheReporterStopsCleanly(unittest.TestCase):
    """The statistics thread ends with the capture, and it writes nothing after."""

    def test_the_thread_ends_after_the_stop(self):
        reporter = StatisticsReporter(MonitorStats(), 60.0, io.StringIO())
        reporter.start()
        reporter.stop()
        self.assertFalse(reporter.is_alive())

    def test_the_stop_waits_no_whole_interval(self):
        """A monitor that waits 60 seconds for its thread would delay every exit."""
        reporter = StatisticsReporter(MonitorStats(), 60.0, io.StringIO())
        reporter.start()
        started = time.monotonic()
        reporter.stop()
        self.assertLess(time.monotonic() - started, 1.0)

    def test_the_thread_writes_no_line_after_the_stop(self):
        stream = io.StringIO()
        reporter = StatisticsReporter(MonitorStats(), 0.02, stream)
        reporter.start()
        time.sleep(0.1)
        reporter.stop()
        after_the_stop = stream.getvalue()
        time.sleep(0.1)
        self.assertEqual(stream.getvalue(), after_the_stop)

    def test_a_second_stop_raises_nothing(self):
        reporter = StatisticsReporter(MonitorStats(), 60.0, io.StringIO())
        reporter.start()
        reporter.stop()
        reporter.stop()
        self.assertFalse(reporter.is_alive())


class TheCommandStartsTheThreadOnlyWithTheOption(unittest.TestCase):
    """The statistics thread is the only thread the command starts."""

    def setUp(self):
        self.seen = []

    def record_threads(self):
        self.seen.append([thread.name for thread in threading.enumerate()])

    def test_the_command_starts_no_thread_without_the_option(self):
        _, err, status = run_watch("watch", "eth0", during=self.record_threads)
        self.assertEqual(status, 0, err)
        self.assertNotIn(STATISTICS_THREAD_NAME, self.seen[0])

    def test_the_command_starts_one_thread_with_the_option(self):
        _, err, status = run_watch(
            "watch", "eth0", "--stats-interval", "60", during=self.record_threads
        )
        self.assertEqual(status, 0, err)
        self.assertIn(STATISTICS_THREAD_NAME, self.seen[0])
        self.assertEqual(self.seen[0].count(STATISTICS_THREAD_NAME), 1)

    def test_the_thread_ends_before_the_command_returns(self):
        run_watch("watch", "eth0", "--stats-interval", "60", during=self.record_threads)
        names = [thread.name for thread in threading.enumerate()]
        self.assertNotIn(STATISTICS_THREAD_NAME, names)


class TheStatisticsGoToStandardError(unittest.TestCase):
    """FR-live-capture-10 — the command writes statistics to standard error."""

    def test_the_final_line_reaches_standard_error(self):
        out, err, status = run_watch("watch", "eth0", source=[tcp_packet(when=1.0)])
        self.assertEqual(status, 0, err)
        self.assertEqual(len(statistics_lines(err)), 1)

    def test_the_final_line_reaches_no_standard_output(self):
        out, err, status = run_watch(
            "--format", "json", "watch", "eth0", source=[tcp_packet(when=1.0)]
        )
        self.assertEqual(status, 0, err)
        self.assertNotIn("[ja4plus] packets=", out)

    def test_the_periodic_line_reaches_standard_error(self):
        _, err, status = run_watch(
            "watch",
            "eth0",
            "--stats-interval",
            "0.05",
            during=lambda: time.sleep(0.3),
        )
        self.assertEqual(status, 0, err)
        self.assertGreaterEqual(len(statistics_lines(err)), 2)

    def test_the_final_line_reports_the_packets_the_monitor_read(self):
        packets = [tcp_packet(src_port=1000 + index, when=float(index)) for index in range(3)]
        _, err, status = run_watch("watch", "eth0", source=packets)
        self.assertEqual(status, 0, err)
        self.assertIn("packets=3", statistics_lines(err)[0])
        self.assertIn("connections=3", statistics_lines(err)[0])

    def test_the_final_line_counts_every_fingerprint_the_command_wrote(self):
        """The three counts differ, so a field that reads another counter fails here.

        One handshake produces two packets, three fingerprints and one connection.
        """
        out, err, status = run_watch("--format", "json", "watch", "eth0", source=one_handshake())
        self.assertEqual(status, 0, err)
        written = len([line for line in out.splitlines() if line.strip()])
        line = statistics_lines(err)[0]
        self.assertEqual(written, 3)
        self.assertIn(f"fingerprints={written}", line)
        self.assertIn("packets=2", line)
        self.assertIn("connections=1", line)

    def test_the_final_line_counts_the_trailing_window(self):
        """A capture that ends holds a JA4SSH window open, and #214 emits that window.

        The self-review of #55 found the gap: the command wrote the trailing window and
        counted it never. `ssh.pcapng` produces two fingerprints, and one of them is
        the trailing window.
        """
        packets = list(rdpcap(str(Path(__file__).parent / "foxio_vectors" / "ssh.pcapng")))
        out, err, status = run_watch("--format", "json", "watch", "eth0", source=packets)
        self.assertEqual(status, 0, err)
        written = len([line for line in out.splitlines() if line.strip()])
        self.assertEqual(written, 2)
        self.assertIn(f"fingerprints={written}", statistics_lines(err)[0])

    def test_the_final_line_follows_the_stop_message(self):
        """The exit summary is the last thing the operator reads."""
        _, err, status = run_watch("watch", "eth0", source=[tcp_packet(when=1.0)])
        self.assertEqual(status, 0, err)
        lines = err.splitlines()
        self.assertTrue(lines[-1].startswith("[ja4plus] packets="))


class TheCommandDocumentsTheOption(unittest.TestCase):
    """FR-live-capture-9 — `watch --help` names `--stats-interval`."""

    def test_the_help_names_the_option(self):
        out, _, status = run_watch("watch", "--help")
        self.assertEqual(status, 0)
        self.assertIn("--stats-interval", out)

    def test_the_command_refuses_an_interval_of_zero(self):
        _, err, status = run_watch("watch", "eth0", "--stats-interval", "0")
        self.assertNotEqual(status, 0)
        self.assertIn("--stats-interval", err)

    def test_the_command_refuses_an_interval_that_is_no_number(self):
        _, err, status = run_watch("watch", "eth0", "--stats-interval", "often")
        self.assertNotEqual(status, 0)
        self.assertIn("--stats-interval", err)

    def test_the_command_refuses_an_interval_that_is_no_finite_number(self):
        """`Event.wait` returns at once for `nan` and it raises for `inf`.

        A monitor that accepted `nan` would write a statistics line without an end. A
        monitor that accepted `inf` would lose the statistics thread to an
        `OverflowError` and keep running.
        """
        for text in ("nan", "inf", "-inf"):
            with self.subTest(interval=text):
                _, err, status = run_watch("watch", "eth0", "--stats-interval", text)
                self.assertNotEqual(status, 0)
                self.assertIn("--stats-interval", err)


class TheWriterWritesOneLine(unittest.TestCase):
    """`write_statistics` writes the exit summary the command reports."""

    def test_the_writer_writes_one_line_that_ends_with_a_line_feed(self):
        stream = io.StringIO()
        write_statistics(MonitorStats(), stream)
        text = stream.getvalue()
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(len(statistics_lines(text)), 1)


if __name__ == "__main__":
    unittest.main()
