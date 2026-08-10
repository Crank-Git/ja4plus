"""The drop count the monitor reads from its capture socket.

`docs/specs/features/06-live-capture.md` states the requirement this file measures.
FR-live-capture-15 asks the statistics line to report the drop count, and the `dropped`
field holds it.

#423 states the boundary. **An injected socket proves that the code connects the parts,
and it proves no capture layer.** The live cases of this file open a real capture socket
of this host. On macOS they read the `BIOCGSTATS` ioctl through `_L2bpfSocket.get_stats`,
and on Linux they read `getsockopt(SOL_PACKET, PACKET_STATISTICS)` on the packet socket.
**Where the host opens no capture device, each live case skips and none of them passes.**
A green run on a host that grants no capture device therefore reports no met criterion.

**A `dropped` field that reads 0 is indistinguishable from a field no code writes.**
`TheDroppedFieldReadsRealDrops` therefore forces the kernel buffer to overflow and reads
a count above zero, on each of the two platforms.

**The two platforms differ on one rule, and #326 owns the Linux half.** The `BIOCGSTATS`
ioctl resets no counter, and `PACKET_STATISTICS` resets both counters as the read returns
them. The monitor therefore adds each Linux reading to a running total.
"""

import errno
import socket as socket_module
import struct
import sys
import threading
import time
import unittest
from unittest.mock import patch

from ja4plus.watch import (
    PACKET_STATISTICS,
    SOL_PACKET,
    CaptureDropCount,
    MonitorStats,
    capture_drop_count,
    format_statistics,
    open_capture_socket,
    packet_statistics_drops,
    read_interface,
)

from tests.test_watch_stop import SilentSocket, one_socket

# The loopback interface of this host. A live case captures on this interface alone, and
# it generates every packet it reads. macOS names the interface `lo0` and Linux names it
# `lo`, so a case that stated one name would open the wrong interface on the other host.
LOOPBACK_INTERFACE = "lo0" if sys.platform == "darwin" else "lo"

# The layout of `struct tpacket_stats`, at `/usr/include/linux/if_packet.h:77`. A case
# packs this structure to model the answer of the kernel.
TPACKET_STATS = struct.Struct("=II")

# The ports the live cases use. Each case holds its own port, so two cases that run in
# one process read no traffic of each other.
LIVE_TCP_PORT = 18427
LIVE_UDP_PORT = 18428

# The count of bytes the kernel holds for one capture socket in the drop case. `scapy`
# states 65535, and a smaller buffer overflows on a burst a case can afford to send.
SMALL_BUFFER_LENGTH = 4096

# The count of packets the drop case sends, and the length of each one. The product is
# far greater than `SMALL_BUFFER_LENGTH`, so the kernel drops what the buffer cannot
# hold.
BURST_PACKETS = 50
BURST_LENGTH = 1400

# The count of seconds a live case waits before it stops. A case that hangs reports
# nothing, so every live loop holds a deadline.
LIVE_DEADLINE = 20.0

# The count of seconds a case waits for a thread it expects to stay blocked. A longer
# wait costs the whole suite that time on every run.
BLOCKED_WAIT = 0.2

# The count of seconds the drop case waits for the kernel to count the burst. A loaded
# host counts the burst later than an idle one, and the case reads the count again.
COUNT_DEADLINE = 5.0

# The count of bytes the kernel holds for one Linux packet socket in the drop case. The
# kernel raises a smaller request to `SOCK_MIN_RCVBUF`, so the case reads the length the
# kernel granted rather than the length it asked for.
SMALL_RECEIVE_BUFFER = 1024

# The count of packets the second Linux burst sends. It is far below `BURST_PACKETS`, so
# a monitor that reported the last reading rather than the running total would report a
# smaller count after the second burst than after the first one.
SECOND_BURST_PACKETS = 8


class FakeCaptureSocket:
    """A capture socket that reports the statistics one case states.

    Args:
        received: The count the fake ioctl reports as received.
        dropped: The count the fake ioctl reports as dropped.
        closed: True where the socket reports itself closed.
    """

    def __init__(self, received=0, dropped=0, closed=False):
        self.received = received
        self.dropped = dropped
        self.closed = closed

    def get_stats(self):
        """Return the received count and the drop count.

        Returns:
            A tuple of two counts, in the order `_L2bpfSocket.get_stats` returns them.
        """
        return (self.received, self.dropped)


class SilentCaptureSocket:
    """A capture socket that reports no statistics at all.

    The Linux capture socket of `scapy` 2.7.0 holds no `get_stats` method, so the
    monitor reads no count from it.
    """

    closed = False


class StatisticsSocket(SilentSocket):
    """A capture socket the capture loop drives, which reports the count one case states.

    `SilentSocket` holds the four members `scapy` reads. This class adds the fifth
    member the drop count reads.

    Args:
        dropped: The count the fake ioctl reports as dropped.
        received: The count the fake ioctl reports as received.

    Attributes:
        stats_reads: The count of `get_stats` calls the socket answered.
        reads_at_close: The value of `stats_reads` at the close, or None before it.
    """

    def __init__(self, dropped=0, received=0):
        super().__init__()
        self.dropped = dropped
        self.received = received
        self.stats_reads = 0
        self.reads_at_close = None

    def get_stats(self):
        """Return the received count and the drop count.

        Returns:
            A tuple of two counts, in the order `_L2bpfSocket.get_stats` returns them.
        """
        self.stats_reads += 1
        return (self.received, self.dropped)

    def close(self):
        """Record the count of reads the socket answered, and close it."""
        self.reads_at_close = self.stats_reads
        super().close()


def the_capture_socket_or_skip(case, capture_filter, buffer_length=None):
    """Return an open capture socket of the loopback interface, or skip the case.

    **A `bpf` device opens exclusively, so the grant is the one the case measures now.**
    A host whose four `/dev/bpf*` nodes are busy refuses the open, and the case skips
    rather than passes.

    Args:
        case: The case that reads the socket.
        capture_filter: The Berkeley Packet Filter expression the socket attaches.
        buffer_length: The count of bytes the kernel holds for the socket, or None to
            keep the length `scapy` states.

    Returns:
        The open capture socket. The caller closes it.
    """
    if sys.platform != "darwin":
        case.skipTest("the /dev/bpf devices are macOS, and this host runs another platform")
    import scapy.arch.bpf.supersocket as supersocket

    try:
        if buffer_length is None:
            return open_capture_socket(LOOPBACK_INTERFACE, capture_filter)
        with patch.object(supersocket, "BPF_BUFFER_LENGTH", buffer_length):
            return open_capture_socket(LOOPBACK_INTERFACE, capture_filter)
    except Exception as error:  # noqa: BLE001 - the case reports every refusal the same way
        case.skipTest(f"this host opened no capture socket on {LOOPBACK_INTERFACE!r}: {error}")


def send_one_loopback_connection(port):
    """Open one TCP connection to the loopback address, and close it.

    The call generates the traffic a live case reads. It reaches no host but this one.

    Args:
        port: The port the listening socket holds.
    """
    listener = socket_module.socket()
    listener.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)

    def connect():
        client = socket_module.create_connection(("127.0.0.1", port))
        client.sendall(b"ja4plus 423")
        client.close()

    caller = threading.Thread(target=connect)
    caller.start()
    accepted, _ = listener.accept()
    accepted.recv(64)
    accepted.close()
    listener.close()
    caller.join(LIVE_DEADLINE)


def send_one_loopback_burst(port, packets=BURST_PACKETS):
    """Send a bounded burst of UDP packets to the loopback address.

    The burst overflows the kernel buffer of a capture socket that reads no packet, so
    the drop count of that socket rises above zero. The count is fixed, so the call ends
    whatever the host does.

    Args:
        port: The destination port. No process listens on it, and the kernel discards
            each packet after the capture socket reads it.
        packets: The count of packets the burst sends.
    """
    sender = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
    payload = b"y" * BURST_LENGTH
    try:
        for _ in range(packets):
            sender.sendto(payload, ("127.0.0.1", port))
    finally:
        sender.close()


def the_packet_socket_or_skip(case, capture_filter, receive_buffer=None):
    """Return an open Linux packet socket of the loopback interface, or skip the case.

    **An `AF_PACKET` socket needs the `CAP_NET_RAW` capability**, so a host that grants
    no capability refuses the open and the case skips rather than passes.

    Args:
        case: The case that reads the socket.
        capture_filter: The Berkeley Packet Filter expression the socket attaches.
        receive_buffer: The count of bytes the case asks the kernel to hold for the
            socket, or None to keep the length the kernel states. The kernel raises a
            request below `SOCK_MIN_RCVBUF` to that floor.

    Returns:
        The open packet socket. The caller closes it.
    """
    if sys.platform != "linux":
        case.skipTest("the AF_PACKET sockets are Linux, and this host runs another platform")
    try:
        capture_socket = open_capture_socket(LOOPBACK_INTERFACE, capture_filter)
    except Exception as error:  # noqa: BLE001 - the case reports every refusal the same way
        case.skipTest(f"this host opened no capture socket on {LOOPBACK_INTERFACE!r}: {error}")
    if receive_buffer is not None:
        # A large buffer holds the whole burst, and the socket then drops nothing. The
        # case asks for a small one so that the kernel counts a real drop.
        capture_socket.ins.setsockopt(
            socket_module.SOL_SOCKET, socket_module.SO_RCVBUF, receive_buffer
        )
    return capture_socket


def read_packet_statistics(capture_socket):
    """Return the two counters of one Linux packet socket, and reset them.

    The call reads the kernel directly, so a case measures the socket without the code
    this issue builds.

    Args:
        capture_socket: The open packet socket to read.

    Returns:
        A tuple of `tp_packets` and `tp_drops`, in the order the kernel returns them.
    """
    payload = capture_socket.ins.getsockopt(SOL_PACKET, PACKET_STATISTICS, TPACKET_STATS.size)
    received, dropped = TPACKET_STATS.unpack_from(payload)
    return (received, dropped)


class TheDropCountReadsOneCaptureSocket(unittest.TestCase):
    """`capture_drop_count` reads the drop count of one capture socket."""

    def test_it_reads_the_drop_count_of_a_socket_that_reports_one(self):
        self.assertEqual(capture_drop_count(FakeCaptureSocket(received=12, dropped=4)), 4)

    def test_it_reads_no_count_from_a_socket_that_reports_none(self):
        self.assertIsNone(capture_drop_count(SilentCaptureSocket()))

    def test_it_reads_no_count_where_the_ioctl_failed(self):
        # `_L2bpfSocket.get_stats` returns two `None` values where the ioctl raised.
        silent = FakeCaptureSocket()
        silent.get_stats = lambda: (None, None)
        self.assertIsNone(capture_drop_count(silent))

    def test_it_reads_no_count_from_a_closed_socket(self):
        # A closed socket holds no file descriptor, and the kernel gives that number to
        # the next file the process opens.
        self.assertIsNone(capture_drop_count(FakeCaptureSocket(dropped=4, closed=True)))

    def test_it_reads_no_count_where_no_socket_is_attached(self):
        self.assertIsNone(capture_drop_count(None))


class ResettingPacketSocket:
    """A Linux packet socket that resets its drop counter as the read returns it.

    **The kernel resets both counters of `PACKET_STATISTICS` as the read returns them.**
    `man 7 packet` states the rule, and `TheDropCountReadsTheKernelReset` measures it on a
    real socket of the granted host. This class models that measured rule, so a case
    states the accumulation without the capture privilege.

    Args:
        readings: The drop counts the socket reports, one for each read. The socket
            reports zero after the last one, which is what a kernel that counted no
            further drop returns.

    Attributes:
        reads: The count of reads the socket answered.
    """

    closed = False

    def __init__(self, readings):
        self._readings = list(readings)
        self.reads = 0
        # `SuperSocket` holds the packet socket in this name, so a reader of the fake
        # reaches the same member it reaches on the real socket.
        self.ins = self

    def getsockopt(self, level, option, length):
        """Return one packed `struct tpacket_stats`, and reset the counters.

        Args:
            level: The socket level the caller states.
            option: The socket option the caller states.
            length: The count of bytes the caller asks for.

        Returns:
            The packed structure, of `length` bytes.

        Raises:
            AssertionError: The caller stated another level or another option.
        """
        assert level == SOL_PACKET
        assert option == PACKET_STATISTICS
        dropped = self._readings[self.reads] if self.reads < len(self._readings) else 0
        self.reads += 1
        return TPACKET_STATS.pack(dropped, dropped)[:length]


class RefusingPacketSocket:
    """A socket whose `getsockopt` refuses the `PACKET_STATISTICS` option.

    A host that holds no packet socket answers `ENOPROTOOPT` for this option, and the
    monitor reports `null` there rather than a wrong count.
    """

    closed = False

    def __init__(self):
        self.ins = self

    def getsockopt(self, level, option, length):
        """Refuse the read the way a socket of another family refuses it.

        Args:
            level: The socket level the caller states.
            option: The socket option the caller states.
            length: The count of bytes the caller asks for.

        Raises:
            OSError: Always. The error number is `ENOPROTOOPT`.
        """
        raise OSError(errno.ENOPROTOOPT, "Protocol not available")


class TheDropCountReadsThePacketStatistics(unittest.TestCase):
    """`packet_statistics_drops` reads `tp_drops` of one Linux packet socket."""

    def test_it_reads_the_drop_count_the_kernel_returned(self):
        self.assertEqual(packet_statistics_drops(ResettingPacketSocket([13])), 13)

    def test_it_reads_the_second_field_of_the_structure(self):
        # `struct tpacket_stats` holds `tp_packets` and then `tp_drops`. A reader of the
        # first field would report the received count as the drop count.
        class TwoFieldSocket:
            closed = False

            def __init__(self):
                self.ins = self

            def getsockopt(self, level, option, length):
                return TPACKET_STATS.pack(70, 5)

        self.assertEqual(packet_statistics_drops(TwoFieldSocket()), 5)

    def test_it_reads_no_count_where_the_socket_refuses_the_option(self):
        self.assertIsNone(packet_statistics_drops(RefusingPacketSocket()))

    def test_it_reads_no_count_from_a_socket_that_holds_no_inner_socket(self):
        self.assertIsNone(packet_statistics_drops(SilentCaptureSocket()))

    def test_it_reads_no_count_from_a_closed_socket(self):
        # The kernel gives the file descriptor of a closed socket to the next file the
        # process opens, so a read there reaches a file this module does not own.
        capture_socket = ResettingPacketSocket([13])
        capture_socket.closed = True
        self.assertIsNone(packet_statistics_drops(capture_socket))

    def test_it_reads_no_count_where_no_socket_is_attached(self):
        self.assertIsNone(packet_statistics_drops(None))

    def test_it_reads_no_count_where_the_answer_is_shorter_than_the_structure(self):
        class ShortSocket:
            closed = False

            def __init__(self):
                self.ins = self

            def getsockopt(self, level, option, length):
                return b"\x00\x00"

        self.assertIsNone(packet_statistics_drops(ShortSocket()))


class TheDropCountAccumulatesAcrossTheReset(unittest.TestCase):
    """`CaptureDropCount` adds each Linux reading to a running total.

    **The kernel resets the counter as the read returns it**, so the last reading is the
    count since the previous read and not the count of the whole run. A monitor that
    reported the last reading would report a total below the true one on every line after
    the first.
    """

    def test_it_reports_the_sum_of_two_readings_and_not_the_last_one(self):
        drop_count = CaptureDropCount()
        drop_count.attach(ResettingPacketSocket([3, 4]))
        self.assertEqual(drop_count(), 3)
        # A monitor that reported the last reading would report 4 here.
        self.assertEqual(drop_count(), 7)

    def test_it_holds_the_total_where_the_kernel_counts_no_further_drop(self):
        drop_count = CaptureDropCount()
        drop_count.attach(ResettingPacketSocket([6]))
        self.assertEqual(drop_count(), 6)
        self.assertEqual(drop_count(), 6)

    def test_the_statistics_line_reads_the_running_total(self):
        drop_count = CaptureDropCount()
        drop_count.attach(ResettingPacketSocket([2, 5, 1]))
        stats = MonitorStats(dropped_source=drop_count)
        self.assertIn("dropped=2", format_statistics(stats.snapshot()))
        self.assertIn("dropped=7", format_statistics(stats.snapshot()))
        self.assertIn("dropped=8", format_statistics(stats.snapshot()))

    def test_the_release_adds_the_last_reading_to_the_total(self):
        drop_count = CaptureDropCount()
        capture_socket = ResettingPacketSocket([2, 5])
        drop_count.attach(capture_socket)
        self.assertEqual(drop_count(), 2)
        self.assertEqual(drop_count.release(), 7)
        self.assertEqual(drop_count(), 7)

    def test_it_reads_the_socket_no_more_after_the_release(self):
        drop_count = CaptureDropCount()
        capture_socket = ResettingPacketSocket([2, 5, 9])
        drop_count.attach(capture_socket)
        self.assertEqual(drop_count.release(), 2)
        reads = capture_socket.reads
        self.assertEqual(drop_count(), 2)
        self.assertEqual(capture_socket.reads, reads)

    def test_the_statistics_line_reads_null_where_the_socket_refuses_the_option(self):
        drop_count = CaptureDropCount()
        drop_count.attach(RefusingPacketSocket())
        stats = MonitorStats(dropped_source=drop_count)
        self.assertIn("dropped=null", format_statistics(stats.snapshot()))


class TheDropCountHoldsTheCaptureSocket(unittest.TestCase):
    """`CaptureDropCount` reads the socket the capture attached to it."""

    def test_it_reads_no_count_before_the_capture_socket_opens(self):
        self.assertIsNone(CaptureDropCount()())

    def test_it_reads_the_count_of_the_socket_it_holds(self):
        drop_count = CaptureDropCount()
        drop_count.attach(FakeCaptureSocket(dropped=7))
        self.assertEqual(drop_count(), 7)

    def test_it_reads_the_count_again_after_the_count_rises(self):
        capture_socket = FakeCaptureSocket(dropped=7)
        drop_count = CaptureDropCount()
        drop_count.attach(capture_socket)
        self.assertEqual(drop_count(), 7)
        capture_socket.dropped = 9
        self.assertEqual(drop_count(), 9)

    def test_it_reads_the_last_count_after_the_capture_socket_closes(self):
        # The exit summary of FR-live-capture-8 runs after the capture closed the socket.
        capture_socket = FakeCaptureSocket(dropped=7)
        drop_count = CaptureDropCount()
        drop_count.attach(capture_socket)
        drop_count.refresh()
        capture_socket.closed = True
        self.assertEqual(drop_count(), 7)

    def test_it_reads_no_count_after_a_silent_socket_closes(self):
        capture_socket = SilentCaptureSocket()
        drop_count = CaptureDropCount()
        drop_count.attach(capture_socket)
        drop_count.refresh()
        self.assertIsNone(drop_count())

    def test_it_reads_the_socket_no_more_after_the_release(self):
        capture_socket = FakeCaptureSocket(dropped=5)
        drop_count = CaptureDropCount()
        drop_count.attach(capture_socket)
        self.assertEqual(drop_count.release(), 5)
        capture_socket.dropped = 9
        self.assertEqual(drop_count(), 5)

    def test_the_release_reads_the_socket_one_last_time(self):
        capture_socket = FakeCaptureSocket(dropped=5)
        drop_count = CaptureDropCount()
        drop_count.attach(capture_socket)
        capture_socket.dropped = 11
        self.assertEqual(drop_count.release(), 11)


class TheReleaseWaitsForTheStatisticsThread(unittest.TestCase):
    """The release of the capture socket waits while another thread reads the socket.

    The capture closes the socket after the release returns, and the kernel gives the
    file descriptor of a closed socket to the next file the process opens. A release
    that returned while the statistics thread stood inside the ioctl would leave that
    thread reading a file this project does not own.
    """

    def test_the_release_waits_while_a_read_holds_the_socket(self):
        entered = threading.Event()
        allowed = threading.Event()

        class BlockingSocket(FakeCaptureSocket):
            """A capture socket whose first ioctl waits until the case allows it.

            **Only the first read waits.** A socket that made every read wait would
            block the release inside the ioctl too, and the case would then pass against
            a release that acquires no lock.
            """

            def get_stats(self):
                """Return the two counts, after the case allows the first return.

                Returns:
                    A tuple of two counts.
                """
                if not entered.is_set():
                    entered.set()
                    allowed.wait(LIVE_DEADLINE)
                return (0, 4)

        drop_count = CaptureDropCount()
        drop_count.attach(BlockingSocket())
        released = []

        reader = threading.Thread(target=drop_count)
        reader.start()
        self.assertTrue(entered.wait(LIVE_DEADLINE))

        releaser = threading.Thread(target=lambda: released.append(drop_count.release()))
        releaser.start()
        releaser.join(BLOCKED_WAIT)
        self.assertEqual(released, [], "the release returned while a read held the socket")

        allowed.set()
        releaser.join(LIVE_DEADLINE)
        reader.join(LIVE_DEADLINE)
        self.assertEqual(released, [4])
        self.assertFalse(releaser.is_alive())


class TheStatisticsLineReadsTheDropCount(unittest.TestCase):
    """The `dropped` field of the statistics line holds the count of the socket."""

    def test_the_line_reads_the_count_of_the_attached_socket(self):
        drop_count = CaptureDropCount()
        drop_count.attach(FakeCaptureSocket(dropped=41))
        line = format_statistics(MonitorStats(dropped_source=drop_count).snapshot())
        self.assertIn("dropped=41", line)

    def test_the_line_reads_null_where_the_socket_reports_no_count(self):
        drop_count = CaptureDropCount()
        drop_count.attach(SilentCaptureSocket())
        line = format_statistics(MonitorStats(dropped_source=drop_count).snapshot())
        self.assertIn("dropped=null", line)


class TheCaptureReportsItsSocket(unittest.TestCase):
    """`read_interface` attaches the socket it opened to the drop count."""

    def test_it_attaches_the_socket_it_opened(self):
        capture_socket = StatisticsSocket(dropped=3)
        drop_count = CaptureDropCount()
        read_interface(
            "eth0",
            lambda packet: None,
            stop_requested=lambda: True,
            open_socket=one_socket(capture_socket),
            drop_count=drop_count,
        )
        self.assertEqual(drop_count(), 3)

    def test_it_reads_the_count_before_it_closes_the_socket(self):
        # A drop count the capture read after the close would report the value `null`,
        # and the exit summary is the line the operator reads most.
        capture_socket = StatisticsSocket(dropped=5)
        drop_count = CaptureDropCount()
        read_interface(
            "eth0",
            lambda packet: None,
            stop_requested=lambda: True,
            open_socket=one_socket(capture_socket),
            drop_count=drop_count,
        )
        self.assertTrue(capture_socket.closed)
        self.assertEqual(drop_count(), 5)

    def test_it_releases_the_socket_before_it_closes_the_socket(self):
        capture_socket = StatisticsSocket(dropped=5)
        drop_count = CaptureDropCount()
        read_interface(
            "eth0",
            lambda packet: None,
            stop_requested=lambda: True,
            open_socket=one_socket(capture_socket),
            drop_count=drop_count,
        )
        # The capture read the socket while it was open, and the release then dropped it.
        self.assertGreaterEqual(capture_socket.reads_at_close, 1)
        # The kernel gives the file descriptor of a closed socket to the next file the
        # process opens. A socket that reads open again, under another count, models
        # that state. A drop count that still held the socket would read the new file.
        capture_socket.closed = False
        capture_socket.dropped = 9
        reads = capture_socket.stats_reads
        self.assertEqual(drop_count(), 5)
        self.assertEqual(capture_socket.stats_reads, reads)

    def test_it_opens_the_capture_without_a_drop_count(self):
        capture_socket = StatisticsSocket()
        read_interface(
            "eth0",
            lambda packet: None,
            stop_requested=lambda: True,
            open_socket=one_socket(capture_socket),
        )
        self.assertEqual(capture_socket.closes, 1)


class TheWatchCommandReadsTheDropCount(unittest.TestCase):
    """`ja4plus watch` reports the drop count of the capture socket it opened."""

    def test_the_exit_summary_reads_the_count_of_the_capture_socket(self):
        import io

        from ja4plus.cli import main

        def read_interface_stub(
            interface,
            handle_packet,
            stop_filter=None,
            capture_filter=None,
            stop_requested=None,
            drop_count=None,
        ):
            if drop_count is not None:
                drop_count.attach(FakeCaptureSocket(received=2, dropped=17))

        captured_out = io.StringIO()
        captured_err = io.StringIO()
        with (
            patch("sys.argv", ["ja4plus", "watch", "eth0"]),
            patch("sys.stdout", captured_out),
            patch("sys.stderr", captured_err),
            patch("ja4plus.cli.read_interface", read_interface_stub),
            patch("os.geteuid", lambda: 0, create=True),
        ):
            try:
                main()
            except SystemExit as exit_request:
                self.assertIn(exit_request.code, (0, None))
        lines = [line for line in captured_err.getvalue().splitlines() if "[ja4plus]" in line]
        # An aggregate over an empty set passes, so the case reads the line it found.
        self.assertEqual(len(lines), 1, captured_err.getvalue())
        self.assertIn("dropped=17", lines[0])


@unittest.skipUnless(sys.platform == "darwin", "the /dev/bpf devices are macOS")
class TheMonitorReadsARealCaptureSocket(unittest.TestCase):
    """A monitor on macOS reports a whole number in the `dropped` field.

    #423 holds this criterion. The socket is a real `_L2bpfSocket` of this host, and the
    count comes from the `BIOCGSTATS` ioctl.
    """

    def test_a_monitor_reports_a_whole_number_in_the_dropped_field(self):
        from scapy.arch.bpf.supersocket import _L2bpfSocket

        probe = the_capture_socket_or_skip(self, f"tcp port {LIVE_TCP_PORT}")
        probe.close()

        opened = []

        def open_socket(interface, capture_filter):
            capture_socket = open_capture_socket(interface, capture_filter)
            opened.append(capture_socket)
            return capture_socket

        read_packets = []

        def handle_packet(packet):
            """Count one packet, and hold it for the assertions below.

            `sniff` prints what the handler returns, so this handler returns None.

            Args:
                packet: The packet the capture just reported.
            """
            read_packets.append(packet)
            stats.record_packet(1, 0)

        drop_count = CaptureDropCount()
        stats = MonitorStats(dropped_source=drop_count)
        deadline = time.monotonic() + LIVE_DEADLINE
        traffic = threading.Timer(1.0, send_one_loopback_connection, [LIVE_TCP_PORT])
        traffic.start()
        try:
            read_interface(
                LOOPBACK_INTERFACE,
                handle_packet,
                stop_filter=lambda packet: len(read_packets) >= 4,
                capture_filter=f"tcp port {LIVE_TCP_PORT}",
                stop_requested=lambda: time.monotonic() > deadline,
                open_socket=open_socket,
                drop_count=drop_count,
            )
        finally:
            traffic.join(LIVE_DEADLINE)

        self.assertEqual(len(opened), 1)
        # Criterion 2 of #423: the reading comes from `_L2bpfSocket.get_stats`.
        self.assertIsInstance(opened[0], _L2bpfSocket)
        # The capture read the traffic this case generated. A capture that read none
        # would leave every count below at zero for a second reason.
        self.assertGreater(len(read_packets), 0)

        snapshot = stats.snapshot()
        self.assertIsInstance(snapshot.dropped, int)
        self.assertNotIsInstance(snapshot.dropped, bool)
        self.assertGreaterEqual(snapshot.dropped, 0)
        self.assertIn(f"dropped={snapshot.dropped}", format_statistics(snapshot))
        print(
            f"#423 live reading: packets={len(read_packets)} "
            f"dropped={snapshot.dropped} socket={type(opened[0]).__name__}"
        )


@unittest.skipUnless(sys.platform == "darwin", "the /dev/bpf devices are macOS")
class TheDroppedFieldReadsRealDrops(unittest.TestCase):
    """The `dropped` field carries a drop the kernel counted.

    **A field that reads 0 on a clean capture proves nothing.** This case fills the
    kernel buffer of a real capture socket and reads a count above zero, so it separates
    a written field from an absent one.
    """

    def test_the_dropped_field_reads_a_count_above_zero(self):
        from scapy.arch.bpf.supersocket import _L2bpfSocket

        capture_socket = the_capture_socket_or_skip(
            self, f"udp port {LIVE_UDP_PORT}", buffer_length=SMALL_BUFFER_LENGTH
        )
        try:
            self.assertIsInstance(capture_socket, _L2bpfSocket)
            drop_count = CaptureDropCount()
            drop_count.attach(capture_socket)
            stats = MonitorStats(dropped_source=drop_count)
            self.assertEqual(stats.snapshot().dropped, 0)

            send_one_loopback_burst(LIVE_UDP_PORT)
            # The kernel counts a packet after it delivers it to the capture socket, so
            # a case that read once would read the state of one instant. The read
            # repeats until the count rises or the deadline passes, and a burst that
            # dropped nothing therefore fails the assertion below rather than the wait.
            deadline = time.monotonic() + COUNT_DEADLINE
            while time.monotonic() < deadline and stats.snapshot().dropped == 0:
                time.sleep(0.05)

            snapshot = stats.snapshot()
            received, dropped = capture_socket.get_stats()
            self.assertGreater(received, 0)
            self.assertGreater(snapshot.dropped, 0)
            self.assertIn(f"dropped={snapshot.dropped}", format_statistics(snapshot))
            print(
                f"#423 live drop reading: sent={BURST_PACKETS} received={received} "
                f"dropped={dropped} snapshot={snapshot.dropped}"
            )
        finally:
            capture_socket.close()


@unittest.skipUnless(sys.platform == "linux", "the AF_PACKET sockets are Linux")
class TheMonitorReadsARealPacketSocket(unittest.TestCase):
    """A monitor on Linux reports a whole number in the `dropped` field.

    #326 holds this criterion. The socket is a real `L2ListenSocket` of this host, and
    the count comes from `getsockopt(SOL_PACKET, PACKET_STATISTICS)` on that socket.
    """

    def test_a_monitor_reports_a_whole_number_in_the_dropped_field(self):
        from scapy.arch.linux import L2ListenSocket

        probe = the_packet_socket_or_skip(self, f"tcp port {LIVE_TCP_PORT}")
        probe.close()

        opened = []

        def open_socket(interface, capture_filter):
            capture_socket = open_capture_socket(interface, capture_filter)
            opened.append(capture_socket)
            return capture_socket

        read_packets = []

        def handle_packet(packet):
            """Count one packet, and hold it for the assertions below.

            `sniff` prints what the handler returns, so this handler returns None.

            Args:
                packet: The packet the capture just reported.
            """
            read_packets.append(packet)
            stats.record_packet(1, 0)

        drop_count = CaptureDropCount()
        stats = MonitorStats(dropped_source=drop_count)
        deadline = time.monotonic() + LIVE_DEADLINE
        traffic = threading.Timer(1.0, send_one_loopback_connection, [LIVE_TCP_PORT])
        traffic.start()
        try:
            read_interface(
                LOOPBACK_INTERFACE,
                handle_packet,
                stop_filter=lambda packet: len(read_packets) >= 4,
                capture_filter=f"tcp port {LIVE_TCP_PORT}",
                stop_requested=lambda: time.monotonic() > deadline,
                open_socket=open_socket,
                drop_count=drop_count,
            )
        finally:
            traffic.join(LIVE_DEADLINE)

        self.assertEqual(len(opened), 1)
        # Criterion 1 of #326: the reading comes from a real `AF_PACKET` socket.
        self.assertIsInstance(opened[0], L2ListenSocket)
        # The capture read the traffic this case generated. A capture that read none
        # would leave every count below at zero for a second reason.
        self.assertGreater(len(read_packets), 0)

        snapshot = stats.snapshot()
        self.assertIsInstance(snapshot.dropped, int)
        self.assertNotIsInstance(snapshot.dropped, bool)
        self.assertGreaterEqual(snapshot.dropped, 0)
        self.assertIn(f"dropped={snapshot.dropped}", format_statistics(snapshot))
        print(
            f"#326 live reading: packets={len(read_packets)} "
            f"dropped={snapshot.dropped} socket={type(opened[0]).__name__}"
        )


@unittest.skipUnless(sys.platform == "linux", "the AF_PACKET sockets are Linux")
class TheDropCountReadsTheKernelReset(unittest.TestCase):
    """The kernel resets `tp_drops` as the read returns it.

    **This case measures the reset on a real packet socket**, and
    `TheDropCountAccumulatesAcrossTheReset` states the rule the monitor builds on that
    measurement. A case that read the source alone would state a premise.
    """

    def test_a_second_read_of_one_socket_reports_no_drop_of_the_first_burst(self):
        capture_socket = the_packet_socket_or_skip(
            self, f"udp port {LIVE_UDP_PORT}", receive_buffer=SMALL_RECEIVE_BUFFER
        )
        try:
            send_one_loopback_burst(LIVE_UDP_PORT)
            deadline = time.monotonic() + COUNT_DEADLINE
            first = read_packet_statistics(capture_socket)
            while time.monotonic() < deadline and first[1] == 0:
                time.sleep(0.05)
                first = read_packet_statistics(capture_socket)
            # The kernel counted the burst, so the field the monitor reads holds a real
            # drop rather than a zero no code wrote.
            self.assertGreater(first[1], 0)

            # The case sends no packet between the two reads, so a counter that held its
            # value would report the same count again.
            second = read_packet_statistics(capture_socket)
            self.assertEqual(second[1], 0)
            print(
                f"#326 kernel reset reading: first={first} second={second} "
                f"buffer={capture_socket.ins.getsockopt(socket_module.SOL_SOCKET, socket_module.SO_RCVBUF)}"
            )
        finally:
            capture_socket.close()


@unittest.skipUnless(sys.platform == "linux", "the AF_PACKET sockets are Linux")
class TheDroppedFieldReadsRealDropsOnLinux(unittest.TestCase):
    """The `dropped` field carries a drop the Linux kernel counted.

    **A field that reads 0 on a clean capture proves nothing.** This case fills the
    receive buffer of a real packet socket and reads a count above zero, so it separates
    a written field from an absent one.

    **The second burst is far smaller than the first one.** A monitor that reported the
    last reading rather than the running total would therefore report a smaller count
    after the second burst, and the case fails there.
    """

    def test_the_dropped_field_reads_a_count_above_zero_and_it_accumulates(self):
        from scapy.arch.linux import L2ListenSocket

        capture_socket = the_packet_socket_or_skip(
            self, f"udp port {LIVE_UDP_PORT}", receive_buffer=SMALL_RECEIVE_BUFFER
        )
        try:
            self.assertIsInstance(capture_socket, L2ListenSocket)
            drop_count = CaptureDropCount()
            drop_count.attach(capture_socket)
            stats = MonitorStats(dropped_source=drop_count)
            self.assertEqual(stats.snapshot().dropped, 0)

            send_one_loopback_burst(LIVE_UDP_PORT)
            # The kernel counts a packet after it queues it on the capture socket, so a
            # case that read once would read the state of one instant. Each read adds to
            # the running total, so a repeated read costs the count nothing.
            deadline = time.monotonic() + COUNT_DEADLINE
            while time.monotonic() < deadline and stats.snapshot().dropped == 0:
                time.sleep(0.05)
            first = stats.snapshot().dropped
            self.assertGreater(first, 0)

            send_one_loopback_burst(LIVE_UDP_PORT, packets=SECOND_BURST_PACKETS)
            deadline = time.monotonic() + COUNT_DEADLINE
            while time.monotonic() < deadline and stats.snapshot().dropped == first:
                time.sleep(0.05)

            snapshot = stats.snapshot()
            self.assertGreater(snapshot.dropped, first)
            self.assertIn(f"dropped={snapshot.dropped}", format_statistics(snapshot))
            print(
                f"#326 live drop reading: first_burst={BURST_PACKETS} "
                f"second_burst={SECOND_BURST_PACKETS} first_total={first} "
                f"second_total={snapshot.dropped}"
            )
        finally:
            capture_socket.close()


if __name__ == "__main__":
    unittest.main()
