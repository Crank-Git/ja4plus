"""The stop of `ja4plus watch` on an interface that carries no traffic.

`docs/specs/features/06-live-capture.md` states the requirements this file measures.

- FR-live-capture-5 asks for a clean exit on `SIGINT`.
- FR-live-capture-6 asks for a clean exit on `SIGTERM`.
- FR-live-capture-11 asks for the `--bpf` option.

#54 shipped `sniff(stop_filter=...)`, and `scapy` applies that filter to a packet and to
nothing else. Its capture loop waits in `select` without an end while the interface
carries no traffic, so a monitor there reads the stop flag when the next packet arrives
and not when the signal arrives. #320 records the gap and the user chose the repair:
`read_interface` opens the capture socket and calls `sniff` with `opened_socket` and a
short `timeout` in a loop.

No test here opens a capture interface. Every case supplies the capture socket, so the
real `scapy` capture loop runs against a socket this file controls. `SilentSocket`
reports no packet until a case delivers one, which is the state the defect needs.
"""

import collections
import io
import os
import signal
import sys
import threading
import time
import unittest
from unittest.mock import patch

from scapy.error import Scapy_Exception

from ja4plus.watch import (
    DEFAULT_POLL_INTERVAL,
    StopRequest,
    open_capture_socket,
    read_interface,
    stop_on_signal,
)

from tests.test_watch import tcp_packet

# The poll interval every case below states. It sits far below the one-second bound of
# the acceptance criterion, so a case measures the loop rather than the wait.
TEST_POLL_INTERVAL = 0.05

# The bound the first acceptance criterion of #320 states, in seconds.
STOP_BOUND = 1.0


class SilentSocket:
    """A capture socket that reports no packet until a case delivers one.

    `scapy` 2.7.0 reads four members of a capture socket. `AsyncSniffer._run` reads
    `nonblocking_socket` and `select`, `DefaultSession.recv` reads `recv`, and the dead
    socket path reads `close`. A True `nonblocking_socket` keeps the control pipe of
    `scapy` out of the socket list, so the loop this class drives holds one socket.

    Verified against `scapy` 2.7.0, at `scapy/sendrecv.py:1205` and
    `scapy/sessions.py:79`, read on 2026-08-08.

    Args:
        before_wait: A callable the socket calls before it waits, with the socket. The
            case that measures the stop bound sends the signal there, because a signal
            that arrives after the wait measures no wait.
        after_wait: A callable the socket calls after it waits, with the socket. The
            case that measures the loop boundary delivers its packet there, because that
            instant is the instant the timeout expires.

    Attributes:
        queue: The packets the socket reports next.
        waits: The count of waits the socket completed.
        receives: The count of `recv` calls the capture loop made.
        closes: The count of `close` calls the capture loop made.
    """

    # `AsyncSniffer._run` adds a control pipe for a socket that reports False here.
    nonblocking_socket = True

    def __init__(self, before_wait=None, after_wait=None):
        self.queue = collections.deque()
        self.waits = 0
        self.receives = 0
        self.closes = 0
        # `SuperSocket` holds this name as a class attribute and `close` sets it, so a
        # reader of the capture socket reads the same name on the real socket.
        self.closed = False
        self._before_wait = before_wait
        self._after_wait = after_wait

    def select(self, sockets, remain=None):
        """Return the sockets that hold a packet, after a wait of `remain` seconds.

        Args:
            sockets: The sockets the capture loop holds. The list names this socket
                alone, because `nonblocking_socket` keeps the control pipe out.
            remain: The count of seconds the capture loop still allows.

        Returns:
            A list holding this socket while the queue holds a packet, else an empty
            list.
        """
        if self.queue:
            return [self]
        if self._before_wait is not None:
            self._before_wait(self)
        if remain is not None and remain > 0:
            time.sleep(remain)
        self.waits += 1
        if self._after_wait is not None:
            self._after_wait(self)
        return []

    def recv(self, size=None):
        """Return the next packet of the queue, or None where the queue holds none."""
        self.receives += 1
        return self.queue.popleft() if self.queue else None

    def close(self):
        """Count the close, and hold the socket closed."""
        self.closes += 1
        self.closed = True


def deliver_once(packet):
    """Return a callable that puts one packet on the queue of a socket, one time.

    Args:
        packet: The packet to deliver.

    Returns:
        The callable, for the `after_wait` argument of `SilentSocket`.
    """
    delivered = []

    def deliver(capture):
        if not delivered:
            delivered.append(packet)
            capture.queue.append(packet)

    return deliver


def send_once(number):
    """Return a callable that sends one signal to this process, one time.

    The callable records the time it sent the signal, so a case measures the count of
    seconds between the signal and the return of the capture.

    Args:
        number: The signal number to send.

    Returns:
        A tuple of the callable and the list it appends the send time to.
    """
    sent = []

    def send(capture):
        if not sent:
            sent.append(time.monotonic())
            os.kill(os.getpid(), number)

    return send, sent


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


def one_socket(capture, opens=None):
    """Return an `open_socket` callable that returns one socket, and records the call.

    Args:
        capture: The socket to return.
        opens: A list the callable appends its two arguments to, or None to record
            nothing.

    Returns:
        The callable.
    """

    def open_socket(interface, capture_filter):
        if opens is not None:
            opens.append((interface, capture_filter))
        return capture

    return open_socket


class TheMonitorStopsOnAnInterfaceThatCarriesNoTraffic(SignalGuard):
    """The first acceptance criterion of #320, measured as the number it states.

    The interface carries no traffic at all in these cases: the capture loop calls
    `recv` never. A case that needed a packet to pass would measure the mechanism #54
    already shipped.
    """

    def test_the_capture_returns_within_one_second_of_a_real_sigterm(self):
        reported = []
        send, sent = send_once(signal.SIGTERM)
        capture = SilentSocket(before_wait=send)

        with stop_on_signal() as stop:
            read_interface(
                "eth0",
                reported.append,
                stop.stop_after,
                stop_requested=stop.requested,
                poll_interval=TEST_POLL_INTERVAL,
                open_socket=one_socket(capture),
            )

        self.assertTrue(sent, "the case sent no signal")
        self.assertLess(time.monotonic() - sent[0], STOP_BOUND)
        self.assertTrue(stop.requested())
        self.assertEqual(capture.receives, 0, "the interface carried traffic")
        self.assertEqual(reported, [])

    def test_the_capture_returns_within_one_second_of_a_real_sigint(self):
        send, sent = send_once(signal.SIGINT)
        capture = SilentSocket(before_wait=send)

        with stop_on_signal() as stop:
            read_interface(
                "eth0",
                lambda packet: None,
                stop.stop_after,
                stop_requested=stop.requested,
                poll_interval=TEST_POLL_INTERVAL,
                open_socket=one_socket(capture),
            )

        self.assertLess(time.monotonic() - sent[0], STOP_BOUND)
        self.assertEqual(capture.receives, 0, "the interface carried traffic")

    def test_the_capture_waits_while_the_flag_is_clear(self):
        """A loop that returned without the flag would end a monitor that must run on."""
        waits = []
        stop = StopRequest()

        def request_after_three(capture):
            waits.append(capture.waits)
            if len(waits) >= 3:
                stop.request(signal.SIGTERM, None)

        capture = SilentSocket(before_wait=request_after_three)
        read_interface(
            "eth0",
            lambda packet: None,
            stop.stop_after,
            stop_requested=stop.requested,
            poll_interval=TEST_POLL_INTERVAL,
            open_socket=one_socket(capture),
        )
        self.assertEqual(capture.waits, 3)

    def test_the_default_poll_interval_holds_the_stop_below_the_stated_bound(self):
        self.assertLess(DEFAULT_POLL_INTERVAL, STOP_BOUND)
        self.assertGreater(DEFAULT_POLL_INTERVAL, 0)


class TheMonitorHoldsOneSocketAcrossTheCalls(unittest.TestCase):
    """The second acceptance criterion of #320 — the loop boundary loses no packet.

    A `read_interface` that opened a socket for each `sniff` call would pass every case
    of `test_watch.py`, and it would drop every packet the host buffered between two
    calls. This is the case that tells the two designs apart.
    """

    def test_a_packet_that_arrives_as_the_timeout_expires_still_reaches_the_report(self):
        packet = tcp_packet(src_port=1024, when=1.0)
        reported = []
        opens = []
        stop = StopRequest()

        def report(read):
            reported.append(read)
            # The monitor stops after this packet, so the case ends rather than waits.
            stop.request(signal.SIGTERM, None)

        capture = SilentSocket(after_wait=deliver_once(packet))
        read_interface(
            "eth0",
            report,
            stop.stop_after,
            stop_requested=stop.requested,
            poll_interval=TEST_POLL_INTERVAL,
            open_socket=one_socket(capture, opens),
        )

        self.assertEqual(len(reported), 1, "the loop boundary lost the packet")
        self.assertEqual(opens, [("eth0", None)], "the loop opened a second socket")
        self.assertGreaterEqual(capture.waits, 1, "the case delivered no timeout")

    def test_the_capture_closes_the_socket_it_opened(self):
        stop = StopRequest()
        stop.request(signal.SIGTERM, None)
        capture = SilentSocket()
        read_interface(
            "eth0",
            lambda packet: None,
            stop.stop_after,
            stop_requested=stop.requested,
            poll_interval=TEST_POLL_INTERVAL,
            open_socket=one_socket(capture),
        )
        self.assertEqual(capture.closes, 1)

    def test_the_capture_closes_the_socket_after_a_failure(self):
        """A monitor that raised and held the socket would hold the interface open."""
        failure = Scapy_Exception("the host went away")

        class FailingSocket(SilentSocket):
            def select(self, sockets, remain=None):
                raise failure

        capture = FailingSocket()
        with self.assertRaises(Scapy_Exception):
            read_interface(
                "eth0",
                lambda packet: None,
                None,
                stop_requested=lambda: True,
                poll_interval=TEST_POLL_INTERVAL,
                open_socket=one_socket(capture),
            )
        self.assertEqual(capture.closes, 1)

    def test_the_capture_returns_when_the_capture_layer_drops_the_socket(self):
        """`AsyncSniffer._run` closes a socket whose read raised, and it reports it dead.

        The loop must return there. A loop that called `sniff` again would wait on a
        closed socket for as long as the monitor runs.

        Verified against `scapy` 2.7.0, at `scapy/sendrecv.py:1229`, read on 2026-08-08.
        """
        capture = SilentSocket()
        capture.queue.append(tcp_packet())

        def report(packet):
            raise ValueError("the report path failed")

        read_interface(
            "eth0",
            report,
            None,
            stop_requested=lambda: False,
            poll_interval=TEST_POLL_INTERVAL,
            open_socket=one_socket(capture),
        )
        self.assertTrue(capture.closed)

    def test_a_failure_of_the_socket_open_reaches_the_caller(self):
        """#56 classifies that failure, and this call classifies nothing."""
        failure = Scapy_Exception("Permission denied: could not open /dev/bpf0")

        def open_socket(interface, capture_filter):
            raise failure

        with self.assertRaises(Scapy_Exception) as raised:
            read_interface("eth0", lambda packet: None, open_socket=open_socket)
        self.assertIs(raised.exception, failure)


class TheCaptureCallStatesTheOpenedSocketAndTheTimeout(unittest.TestCase):
    """The mechanism the user chose, read from the arguments the call passes."""

    def test_every_call_passes_the_same_socket_and_the_poll_interval(self):
        seen = []

        def sniff(**kwargs):
            seen.append(kwargs)

        capture = SilentSocket()
        rounds = []

        def stop_requested():
            rounds.append(1)
            return len(rounds) >= 2

        with patch("scapy.all.sniff", sniff):
            read_interface(
                "eth0",
                lambda packet: None,
                None,
                stop_requested=stop_requested,
                poll_interval=TEST_POLL_INTERVAL,
                open_socket=one_socket(capture),
            )

        self.assertEqual(len(seen), 2)
        self.assertIs(seen[0]["opened_socket"], capture)
        self.assertIs(seen[1]["opened_socket"], capture)
        self.assertEqual(seen[0]["timeout"], TEST_POLL_INTERVAL)
        self.assertEqual(seen[0]["store"], 0)

    def test_the_call_passes_no_filter_to_the_capture_loop(self):
        """`AsyncSniffer._run` reads `filter` only where it opens the socket itself.

        A filter passed there reaches no socket, so the filter would apply to nothing.
        """
        seen = []

        def sniff(**kwargs):
            seen.append(kwargs)

        with patch("scapy.all.sniff", sniff):
            read_interface(
                "eth0",
                lambda packet: None,
                None,
                capture_filter="tcp port 443",
                stop_requested=lambda: True,
                poll_interval=TEST_POLL_INTERVAL,
                open_socket=one_socket(SilentSocket()),
            )
        self.assertNotIn("filter", seen[0])


class TheCaptureFilterReachesTheSocket(unittest.TestCase):
    """FR-live-capture-11 — the `--bpf` expression still compiles against the socket.

    #56 shipped the filter, and the socket moved. `libpcap` compiles the expression when
    the socket opens, so the filter failure `describe_capture_failure` classifies still
    travels out of `read_interface`.
    """

    def test_the_filter_reaches_the_socket_the_call_opens(self):
        opens = []
        read_interface(
            "eth0",
            lambda packet: None,
            None,
            capture_filter="tcp port 443",
            stop_requested=lambda: True,
            poll_interval=TEST_POLL_INTERVAL,
            open_socket=one_socket(SilentSocket(), opens),
        )
        self.assertEqual(opens, [("eth0", "tcp port 443")])

    def test_the_socket_open_states_the_interface_and_the_filter(self):
        """The real open, with the interface resolution replaced. It opens nothing."""
        from scapy.data import ETH_P_ALL

        seen = {}

        class Interface:
            def l2listen(self):
                def build(**kwargs):
                    seen.update(kwargs)
                    return SilentSocket()

                return build

        with patch("scapy.interfaces.resolve_iface", lambda name: Interface()):
            open_capture_socket("eth0", "tcp port 443")

        self.assertEqual(seen["iface"], "eth0")
        self.assertEqual(seen["filter"], "tcp port 443")
        self.assertEqual(seen["type"], ETH_P_ALL)

    def test_the_socket_open_reads_no_filter_without_the_option(self):
        seen = {}

        class Interface:
            def l2listen(self):
                def build(**kwargs):
                    seen.update(kwargs)
                    return SilentSocket()

                return build

        with patch("scapy.interfaces.resolve_iface", lambda name: Interface()):
            open_capture_socket("eth0")
        self.assertIsNone(seen["filter"])

    def test_the_name_any_reads_the_default_interface_of_the_capture_layer(self):
        """`AsyncSniffer._run` reads `iface or conf.iface`, and this call reads the same."""
        from scapy.config import conf

        names = []

        class Interface:
            def l2listen(self):
                return lambda **kwargs: SilentSocket()

        def resolve(name):
            names.append(name)
            return Interface()

        # `conf.iface` is a descriptor of the `Conf` class, and a write to the instance
        # resolves the name it receives. The class attribute holds a plain name.
        with patch("scapy.interfaces.resolve_iface", resolve):
            with patch.object(type(conf), "iface", "en9"):
                open_capture_socket("any")
        self.assertEqual(names, ["en9"])


def run_watch(capture, *argv, poll_interval=TEST_POLL_INTERVAL):
    """Run the command-line program against a supplied capture socket.

    The real `read_interface` runs, so the real `scapy` capture loop reads the socket.
    The call opens no interface.

    Args:
        capture: The capture socket the monitor reads.
        argv: The arguments to pass, without the program name.
        poll_interval: The count of seconds one `sniff` call reads.

    Returns:
        A tuple of the standard output, the standard error and the exit status.
    """
    from ja4plus import watch as watch_module
    from ja4plus.cli import main

    def read_interface_on_the_socket(
        interface, handle_packet, stop_filter=None, capture_filter=None, stop_requested=None
    ):
        watch_module.read_interface(
            interface,
            handle_packet,
            stop_filter,
            capture_filter,
            stop_requested=stop_requested,
            poll_interval=poll_interval,
            open_socket=one_socket(capture),
        )

    captured_out = io.StringIO()
    captured_err = io.StringIO()
    patches = [
        patch("sys.argv", ["ja4plus"] + list(argv)),
        patch("sys.stdout", captured_out),
        patch("sys.stderr", captured_err),
        patch("ja4plus.cli.read_interface", read_interface_on_the_socket),
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


class TheCommandStopsOnASilentInterface(SignalGuard):
    """The acceptance criteria of #320, measured through the command-line program."""

    def test_the_command_exits_within_one_second_of_a_real_sigterm(self):
        send, sent = send_once(signal.SIGTERM)
        capture = SilentSocket(before_wait=send)
        _, err, status = run_watch(capture, "watch", "eth0")
        self.assertEqual(status, 0, err)
        self.assertLess(time.monotonic() - sent[0], STOP_BOUND)
        self.assertIn("Capture stopped.", err)
        self.assertEqual(capture.receives, 0, "the interface carried traffic")

    def test_the_command_reports_the_statistics_of_a_silent_interface(self):
        send, _ = send_once(signal.SIGTERM)
        capture = SilentSocket(before_wait=send)
        _, err, status = run_watch(capture, "watch", "eth0")
        self.assertEqual(status, 0, err)
        self.assertIn("[ja4plus] packets=0", err)

    def test_the_command_starts_no_thread_on_a_silent_interface(self):
        """The third acceptance criterion — `--stats-interval` starts the only thread."""
        send, _ = send_once(signal.SIGTERM)
        alive = []

        def read_the_threads(capture):
            alive.append(threading.active_count())
            send(capture)

        capture = SilentSocket(before_wait=read_the_threads)
        before = threading.active_count()
        _, err, status = run_watch(capture, "watch", "eth0")
        self.assertEqual(status, 0, err)
        self.assertTrue(alive, "the capture loop waited never")
        self.assertEqual(max(alive), before)

    def test_the_command_reports_a_packet_that_arrives_as_the_timeout_expires(self):
        """The second acceptance criterion, measured through the whole command."""
        packet = tcp_packet(src_port=1024, when=1.0)
        send, _ = send_once(signal.SIGTERM)

        def stop_after_the_first_wait(capture):
            # The packet arrives at the first timeout, and the signal arrives at the
            # second one. A signal at the first timeout would end the monitor before it
            # read the packet, and that case would measure another rule.
            if capture.waits >= 1:
                send(capture)

        capture = SilentSocket(
            before_wait=stop_after_the_first_wait, after_wait=deliver_once(packet)
        )
        _, err, status = run_watch(capture, "watch", "eth0")
        self.assertEqual(status, 0, err)
        self.assertIn("[ja4plus] packets=1", err)


if __name__ == "__main__":
    sys.exit(unittest.main())
