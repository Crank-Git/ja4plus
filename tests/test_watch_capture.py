"""The capture filter of `ja4plus watch`, and the failures the capture layer reports.

`docs/specs/features/06-live-capture.md` states the requirements this file measures.

- FR-live-capture-11 asks for the `--bpf` option.
- FR-live-capture-12 asks for a clear error when the command lacks the privilege.
- FR-live-capture-13 asks the command to work on Linux and on macOS.

Version 0.6.0 read `os.geteuid() != 0`. That check holds two defects. `os.geteuid` is
absent on Windows, so the command raises `AttributeError` there. A Linux host also
grants `CAP_NET_RAW` without granting the user identity zero, so the check refuses a
permitted operator. The command now attempts the capture and reads the failure.

No test here opens a capture interface. Three cases produce a real `scapy` failure from
a call that opens none, and they feed that failure to the classifier. The command-level
cases inject the failure into the capture call.
"""

import io
import os
import sys
import unittest
from unittest.mock import patch

from scapy.error import Scapy_Exception

from ja4plus.watch import (
    CAPTURE_FAILURES,
    available_interfaces,
    describe_capture_failure,
    read_interface,
    unsupported_platform_message,
)

from tests.test_watch import tcp_packet

# The name of an interface no host holds. Three cases read the failure it produces.
ABSENT_INTERFACE = "nosuchif0"

# A filter expression `libpcap` refuses. `tcp port` names no port number.
INVALID_FILTER = "tcp port"


def run_watch(*argv, source=None, failure=None, calls=None, platform=None, euid=0):
    """Run the command-line program against an injected capture, and return its result.

    The call replaces the capture, so it opens no interface.

    Args:
        argv: The arguments to pass, without the program name.
        source: A list of packets the fake capture replays, or None for no packet.
        failure: An exception the fake capture raises in place of the replay, or None
            to replay the packets.
        calls: A list the fake capture appends its arguments to, or None to record
            nothing.
        platform: The value to report as `sys.platform`, or None to report the real one.
        euid: The user identity to report from `os.geteuid`. The default is zero, and a
            case that measures the removed check passes a value above zero.

    Returns:
        A tuple of the standard output, the standard error and the exit status.
    """
    from ja4plus.cli import main

    def read_interface_stub(
        interface, handle_packet, stop_filter=None, capture_filter=None, stop_requested=None
    ):
        if calls is not None:
            calls.append(
                {
                    "interface": interface,
                    "stop_filter": stop_filter,
                    "capture_filter": capture_filter,
                }
            )
        if failure is not None:
            raise failure
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
        patch("ja4plus.cli.read_interface", read_interface_stub),
        patch("os.geteuid", lambda: euid, create=True),
    ]
    if platform is not None:
        patches.append(patch("sys.platform", platform))

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


def the_privilege_failure():
    """Return the failure the macOS capture layer reports without the privilege.

    The call opens `/dev/bpf0` and it opens no interface. A caller that holds the
    privilege receives the file descriptor instead, so the case that reads this failure
    skips under the user identity zero.

    Returns:
        The `Scapy_Exception` the call raised.

    Raises:
        AssertionError: The call raised nothing.
    """
    from scapy.arch.bpf.core import get_dev_bpf

    try:
        get_dev_bpf()
    except Scapy_Exception as error:
        return error
    raise AssertionError("the host granted the capture privilege")


def the_absent_interface_failure():
    """Return the failure `scapy` reports for an interface no host holds.

    The call reads the interface list of the host and it opens no interface.

    Returns:
        The `ValueError` the call raised.

    Raises:
        AssertionError: The call raised nothing.
    """
    from scapy.all import resolve_iface

    try:
        resolve_iface(ABSENT_INTERFACE)
    except ValueError as error:
        return error
    raise AssertionError("the host holds an interface named " + ABSENT_INTERFACE)


def the_filter_failure():
    """Return the failure `libpcap` reports for a filter it refuses.

    The call compiles the expression against the Ethernet link type and it opens no
    interface.

    Returns:
        The `Scapy_Exception` the call raised.

    Raises:
        AssertionError: The call raised nothing.
    """
    from scapy.arch.common import compile_filter

    try:
        # Link type 1 is Ethernet. `compile_filter` reads a link type rather than an
        # interface, and that path asks `libpcap` for no privilege.
        compile_filter(INVALID_FILTER, linktype=1)
    except Scapy_Exception as error:
        return error
    raise AssertionError("libpcap accepted the expression " + INVALID_FILTER)


def describe(error, capture_filter=None, interfaces=("en0", "lo0")):
    """Return the message the command writes for one failure.

    Args:
        error: The failure the capture layer reported.
        capture_filter: The filter the operator stated, or None.
        interfaces: The interface names the host holds.

    Returns:
        The message, as one string.
    """
    return describe_capture_failure(
        error,
        interface="en0",
        command="watch",
        capture_filter=capture_filter,
        interfaces=list(interfaces),
    )


class TheCommandNamesTheCapturePrivilege(unittest.TestCase):
    """FR-live-capture-12 — the command names the privilege the host needs."""

    def test_the_message_names_both_privileges_the_two_platforms_use(self):
        error = PermissionError(1, "Operation not permitted")
        message = describe(error)
        self.assertIn("CAP_NET_RAW", message)
        self.assertIn("/dev/bpf*", message)

    def test_the_message_repeats_what_the_capture_layer_reported(self):
        error = PermissionError(13, "Permission denied")
        self.assertIn("Permission denied", describe(error))

    def test_the_message_names_the_command_that_raises_the_privilege(self):
        message = describe(PermissionError(1, "Operation not permitted"))
        self.assertIn("sudo ja4plus watch en0", message)

    @unittest.skipUnless(sys.platform == "darwin", "the /dev/bpf devices are macOS")
    @unittest.skipIf(os.geteuid() == 0, "the user identity zero holds the privilege")
    def test_the_message_reads_the_failure_this_host_reports(self):
        """The macOS reading, taken from the real capture layer of this host."""
        message = describe(the_privilege_failure())
        self.assertIn("CAP_NET_RAW", message)
        self.assertIn("/dev/bpf*", message)
        self.assertIn("could not open /dev/bpf", message)


class TheCommandListsTheInterfacesItFound(unittest.TestCase):
    """FR-live-capture-12 — an absent interface produces a list of the real ones."""

    def test_the_message_lists_every_interface_the_host_holds(self):
        message = describe(the_absent_interface_failure(), interfaces=("en0", "lo0"))
        self.assertIn("en0", message)
        self.assertIn("lo0", message)

    def test_the_message_reads_a_host_that_holds_no_interface(self):
        message = describe(the_absent_interface_failure(), interfaces=())
        self.assertIn("no interface", message)

    def test_a_missing_device_number_reads_as_an_absent_interface(self):
        """Linux reports `ENODEV` from the bind call rather than a `ValueError`."""
        message = describe(OSError(19, "No such device"))
        self.assertIn("lo0", message)

    def test_the_interface_list_of_this_host_holds_a_name(self):
        """`available_interfaces` needs no privilege, so an error message can read it."""
        names = available_interfaces()
        self.assertTrue(names, "the host reported no interface")
        self.assertTrue(all(isinstance(name, str) for name in names))

    def test_a_capture_layer_that_reports_no_list_produces_an_empty_list(self):
        """This call runs while the command reports another failure.

        A second failure here would replace that report with a stack trace.
        """

        def get_if_list():
            raise Scapy_Exception("no interface provider")

        with patch("scapy.all.get_if_list", get_if_list):
            self.assertEqual(available_interfaces(), [])


class TheCommandReportsTheFilterError(unittest.TestCase):
    """FR-live-capture-11 — an invalid capture filter produces the filter error."""

    def test_the_message_names_the_filter_the_operator_stated(self):
        message = describe(the_filter_failure(), capture_filter=INVALID_FILTER)
        self.assertIn(INVALID_FILTER, message)

    def test_the_message_repeats_what_the_capture_layer_reported(self):
        message = describe(the_filter_failure(), capture_filter=INVALID_FILTER)
        self.assertIn("Failed to compile filter expression", message)

    def test_a_filter_error_of_the_linux_socket_reads_as_a_filter_error(self):
        """Linux wraps the same failure as `Cannot set filter: ...`."""
        error = Scapy_Exception("Cannot set filter: Failed to compile filter expression")
        message = describe(error, capture_filter=INVALID_FILTER)
        self.assertIn(INVALID_FILTER, message)

    def test_a_privilege_failure_reads_as_a_privilege_failure_beside_a_filter(self):
        """The privilege reading comes first, so a filter hides no privilege failure."""
        message = describe(PermissionError(1, "Operation not permitted"), capture_filter="ip")
        self.assertIn("CAP_NET_RAW", message)


class TheCommandReportsAnUnclassifiedFailure(unittest.TestCase):
    """A failure of no known class still reaches the operator."""

    def test_the_message_repeats_what_the_capture_layer_reported(self):
        message = describe(OSError(28, "No space left on device"))
        self.assertIn("No space left on device", message)


class TheCommandRunsOnLinuxAndOnMacOS(unittest.TestCase):
    """FR-live-capture-13 — the command runs on Linux and on macOS, and reports Windows."""

    def test_the_command_reports_that_windows_carries_no_monitor(self):
        self.assertIn("Windows", unsupported_platform_message("win32", "watch") or "")

    def test_the_command_reports_the_same_for_cygwin(self):
        self.assertIsNotNone(unsupported_platform_message("cygwin", "watch"))

    def test_linux_carries_the_monitor(self):
        self.assertIsNone(unsupported_platform_message("linux", "watch"))

    def test_macos_carries_the_monitor(self):
        self.assertIsNone(unsupported_platform_message("darwin", "watch"))


class TheCaptureFailureEndsTheRunWithTheStatusOne(unittest.TestCase):
    """Each failure the capture layer reports ends the run with the status 1."""

    def test_a_privilege_failure_ends_the_run_with_the_status_one(self):
        _, err, status = run_watch(
            "watch", "eth0", failure=PermissionError(1, "Operation not permitted")
        )
        self.assertEqual(status, 1)
        self.assertIn("CAP_NET_RAW", err)
        self.assertIn("/dev/bpf*", err)

    def test_an_absent_interface_ends_the_run_with_the_status_one(self):
        _, err, status = run_watch(
            "watch", ABSENT_INTERFACE, failure=the_absent_interface_failure()
        )
        self.assertEqual(status, 1)
        self.assertIn(ABSENT_INTERFACE, err)
        for name in available_interfaces():
            self.assertIn(name, err)

    def test_an_invalid_filter_ends_the_run_with_the_status_one(self):
        _, err, status = run_watch(
            "watch", "eth0", "--bpf", INVALID_FILTER, failure=the_filter_failure()
        )
        self.assertEqual(status, 1)
        self.assertIn(INVALID_FILTER, err)
        self.assertIn("Failed to compile filter expression", err)

    def test_the_command_reports_no_statistics_line_after_a_failed_start(self):
        """A monitor that read no packet reports no count."""
        _, err, status = run_watch("watch", "eth0", failure=PermissionError(1, "denied"))
        self.assertEqual(status, 1)
        self.assertNotIn("[ja4plus] packets=", err)


class TheCommandReportsAFailureOfNoCaptureClass(unittest.TestCase):
    """A failure outside `CAPTURE_FAILURES` still ends the run with the status 1.

    The command holds that clause from version 0.6.0. #319 owns the bare catches of
    `ja4plus/cli.py`, and this case states what the clause reports today.
    """

    def test_the_command_reports_it_and_ends_with_the_status_one(self):
        _, err, status = run_watch("watch", "eth0", failure=RuntimeError("the host went away"))
        self.assertEqual(status, 1)
        self.assertIn("the host went away", err)


class TheCommandRefusesWindows(unittest.TestCase):
    """The fourth acceptance criterion of #56, read from the command."""

    def test_the_command_reports_windows_and_ends_with_the_status_one(self):
        _, err, status = run_watch("watch", "eth0", platform="win32")
        self.assertEqual(status, 1)
        self.assertIn("Windows", err)

    def test_the_command_opens_no_interface_on_windows(self):
        calls = []
        _, _, status = run_watch("watch", "eth0", platform="win32", calls=calls)
        self.assertEqual(status, 1)
        self.assertEqual(calls, [])

    def test_the_command_reads_no_user_identity(self):
        """`os.geteuid` is absent on Windows, and the command must raise no
        `AttributeError` there."""
        with patch.object(os, "geteuid", side_effect=AttributeError("geteuid")):
            _, err, status = run_watch("watch", "eth0", platform="win32", euid=0)
        self.assertEqual(status, 1)
        self.assertIn("Windows", err)


class TheCommandReadsNoUserIdentity(unittest.TestCase):
    """FR-live-capture-12 — a permitted operator without the identity zero is not refused.

    A Linux host grants `CAP_NET_RAW` without granting the user identity zero. The
    check of version 0.6.0 refused that operator.
    """

    def test_an_operator_above_the_identity_zero_reads_the_interface(self):
        packets = [tcp_packet(src_port=1024, when=1.0)]
        out, err, status = run_watch("--format", "json", "watch", "eth0", source=packets, euid=1000)
        self.assertEqual(status, 0, err)
        self.assertTrue(out.strip(), "the capture produced no result")


class TheCaptureFilterReachesTheCaptureLayer(unittest.TestCase):
    """FR-live-capture-11 — the `--bpf` option applies a capture filter."""

    def test_the_help_names_the_option(self):
        out, _, status = run_watch("watch", "--help")
        self.assertEqual(status, 0)
        self.assertIn("--bpf", out)

    def test_the_option_reaches_the_capture_call(self):
        calls = []
        _, err, status = run_watch("watch", "eth0", "--bpf", "tcp port 443", calls=calls)
        self.assertEqual(status, 0, err)
        self.assertEqual([call["capture_filter"] for call in calls], ["tcp port 443"])

    def test_the_capture_reads_no_filter_without_the_option(self):
        calls = []
        _, err, status = run_watch("watch", "eth0", calls=calls)
        self.assertEqual(status, 0, err)
        self.assertEqual([call["capture_filter"] for call in calls], [None])

    def test_the_capture_call_passes_the_filter_to_the_socket_it_opens(self):
        """`read_interface` opens the socket with the filter, and it opens no interface.

        #320 moved the socket out of `sniff`, so `libpcap` compiles the expression when
        the socket opens. `AsyncSniffer._run` reads the `filter` argument only where it
        opens the socket itself, so an expression stated there would reach no socket.
        """
        seen = []

        def open_socket(interface, capture_filter):
            seen.append((interface, capture_filter))
            raise Scapy_Exception("the case reads the open and opens no interface")

        with self.assertRaises(Scapy_Exception):
            read_interface(
                "eth0",
                lambda packet: None,
                capture_filter="tcp port 443",
                open_socket=open_socket,
            )
        self.assertEqual(seen, [("eth0", "tcp port 443")])


class TheCaptureFailuresNameTheClassesTheCaptureLayerRaises(unittest.TestCase):
    """The command catches the classes `scapy` raises, and it catches no bare failure."""

    def test_the_three_real_failures_are_all_caught(self):
        for error in (
            PermissionError(1, "Operation not permitted"),
            the_absent_interface_failure(),
            the_filter_failure(),
        ):
            self.assertIsInstance(error, CAPTURE_FAILURES)

    def test_the_broken_pipe_reads_as_no_capture_failure(self):
        """`BrokenPipeError` inherits `OSError`, and `main` alone ends that run.

        A reader of standard output that goes away is no capture failure, so the
        command reports no privilege and no interface list for it.
        """
        packets = [tcp_packet(src_port=1024, when=1.0)]
        _, err, _ = run_watch(
            "--format", "json", "watch", "eth0", source=packets, failure=BrokenPipeError()
        )
        self.assertNotIn("CAP_NET_RAW", err)
        self.assertNotIn("Error during capture", err)


class TheExampleDaemonIsAbsent(unittest.TestCase):
    """The last acceptance criterion of `features/06-live-capture.md`.

    `ja4plus watch` is the supported monitor, and nothing tested the example.
    """

    def test_the_repository_holds_no_monitoring_daemon_example(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.assertFalse(os.path.exists(os.path.join(root, "examples", "monitoring_daemon.py")))


if __name__ == "__main__":
    sys.exit(unittest.main())
