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

import contextlib
import importlib.abc
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

# The module `compile_filter` imports to reach `libpcap`. `scapy` 2.7.0 imports it at
# `scapy/arch/common.py:81`, and the loader raises `OSError` there where the host holds no
# such shared library.
LIBPCAP_MODULE = "scapy.libs.winpcapy"


@contextlib.contextmanager
def no_libpcap():
    """Hold `compile_filter` in the state a host without `libpcap` produces.

    The finder here raises `OSError` from the import of `scapy.libs.winpcapy`, which is
    the failure the loader reports where it cannot open the shared library. `scapy` 2.7.0
    catches that class at `scapy/arch/common.py:86` and raises
    `ImportError("libpcap is not available. Cannot compile filter !")` at line 87. A
    stand-in for `compile_filter` would prove the guard against a class this file chose,
    and this route proves it against the class `scapy` raises.

    Yields:
        None, while the import of `scapy.libs.winpcapy` fails.
    """

    class Finder(importlib.abc.MetaPathFinder):
        """A finder that refuses one module and answers for no other."""

        def find_spec(self, fullname, path=None, target=None):
            """Raise `OSError` for the `libpcap` module and return None for the rest.

            Args:
                fullname: The name of the module the import system asks for.
                path: The search path, which this finder does not read.
                target: The module to reload, which this finder does not read.

            Returns:
                None, so the next finder answers.

            Raises:
                OSError: The import asks for `scapy.libs.winpcapy`.
            """
            if fullname == LIBPCAP_MODULE:
                raise OSError("the case reports that this host holds no libpcap")
            return None

    finder = Finder()
    # An import reads `sys.modules` before it reads `sys.meta_path`, so a cached module
    # would reach `compile_filter` and the finder would never run.
    cached = sys.modules.pop(LIBPCAP_MODULE, None)
    sys.meta_path.insert(0, finder)
    try:
        yield
    finally:
        sys.meta_path.remove(finder)
        if cached is not None:
            sys.modules[LIBPCAP_MODULE] = cached


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

    The call opens `/dev/bpf0` and it opens no interface. A host that grants the
    privilege returns the file descriptor instead, and this call then reports no
    failure. The caller reads that result as the state of the host. #424 records why:
    the user identity and the platform do not decide the grant. A case that reads the
    grant through those two alone fails on a host that grants read access to the
    `/dev/bpf*` devices.

    Returns:
        The `Scapy_Exception` the call raised, or None where the host granted the
        privilege.
    """
    from scapy.arch.bpf.core import get_dev_bpf

    try:
        descriptor, _ = get_dev_bpf()
    except Scapy_Exception as error:
        return error
    # `get_dev_bpf` returns an open descriptor, and no caller of this module closes it.
    os.close(descriptor)
    return None


def the_absent_interface_failure():
    """Return the failure `scapy` reports for an interface no host holds.

    The call reads the interface list of the host and it opens no interface. A host that
    holds an interface named `nosuchif0` resolves the name, and this call then reports no
    failure. The caller reads that result as the state of the host. #426 records why: the
    name is a premise about the host, and this project does not control the interface list.

    Returns:
        The `ValueError` the call raised, or None where the host holds the interface.
    """
    from scapy.all import resolve_iface

    try:
        resolve_iface(ABSENT_INTERFACE)
    except ValueError as error:
        return error
    return None


def the_absent_interface_failure_or_skip(case):
    """Return the absent interface failure, or skip the case that reads it.

    Args:
        case: The case that reads the failure.

    Returns:
        The `ValueError` `resolve_iface` raised.
    """
    error = the_absent_interface_failure()
    if error is None:
        case.skipTest("this host holds an interface named " + ABSENT_INTERFACE)
    return error


def the_filter_failure():
    """Return the failure `libpcap` reports for a filter it refuses.

    The call compiles the expression against the Ethernet link type and it opens no
    interface. A host that holds no `libpcap` compiles no expression, and this call then
    reports no failure. The caller reads that result as the state of the host. #426 records
    why. A minimal Linux container holds no `libpcap`. The earlier form ended such a run
    with an error rather than with a skip.

    Returns:
        The `Scapy_Exception` the call raised, or None where the host holds no `libpcap`.

    Raises:
        AssertionError: `libpcap` accepted the expression.
    """
    from scapy.arch.common import compile_filter

    try:
        # Link type 1 is Ethernet. `compile_filter` reads a link type rather than an
        # interface, and that path asks `libpcap` for no privilege.
        compile_filter(INVALID_FILTER, linktype=1)
    except Scapy_Exception as error:
        return error
    except ImportError:
        # `scapy` 2.7.0 raises this class at `scapy/arch/common.py:87` where the loader
        # cannot open `libpcap`. It reports the state of the host and not a fault of the
        # expression, so no case that reads the expression can run here.
        return None
    # A host that compiled `tcp port` reports no filter failure for any expression, and
    # that is a finding rather than a state of the host.
    raise AssertionError("libpcap accepted the expression " + INVALID_FILTER)


def the_filter_failure_or_skip(case):
    """Return the filter failure, or skip the case that reads it.

    Args:
        case: The case that reads the failure.

    Returns:
        The `Scapy_Exception` `compile_filter` raised.
    """
    error = the_filter_failure()
    if error is None:
        case.skipTest("this host holds no libpcap, so it compiles no filter expression")
    return error


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
        error = the_privilege_failure()
        if error is None:
            self.skipTest("this host grants the capture privilege to this account")
        message = describe(error)
        self.assertIn("CAP_NET_RAW", message)
        self.assertIn("/dev/bpf*", message)
        self.assertIn("could not open /dev/bpf", message)


class TheCapturePrivilegeCaseGuardsOnTheHostState(unittest.TestCase):
    """#424 — the case that reads the real capture layer guards on the privilege.

    The case above reads the failure of this host, so its result depends on whether
    this host grants the capture privilege to this account. A guard proved in one
    direction can skip on every host, and a case that always skips measures nothing.
    The first two cases here force each direction and read what the guarded case does.
    The third case reads the descriptor a granting host returns.
    """

    # The message `scapy` 2.7.0 raises at `scapy/arch/bpf/core.py:59`, read on
    # 2026-08-09. The guarded case asserts on this text, so a paraphrase would prove
    # nothing about the real denial.
    DENIAL = (
        "Permission denied: could not open /dev/bpf0. "
        "Make sure to be running Scapy as root ! (sudo)"
    )

    def the_guarded_case(self):
        """Return the guarded case, ready to run.

        Returns:
            The `TheCommandNamesTheCapturePrivilege` case that reads this host.
        """
        return TheCommandNamesTheCapturePrivilege(
            "test_the_message_reads_the_failure_this_host_reports"
        )

    @unittest.skipUnless(sys.platform == "darwin", "the /dev/bpf devices are macOS")
    @unittest.skipIf(os.geteuid() == 0, "the user identity zero holds the privilege")
    def test_the_case_runs_and_passes_where_the_host_denies_the_privilege(self):
        """A host without the privilege still reads the message from the capture layer."""
        denial = Scapy_Exception(self.DENIAL)
        with patch("scapy.arch.bpf.core.get_dev_bpf", side_effect=denial):
            result = self.the_guarded_case().run()
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.failures, [])
        self.assertEqual(result.skipped, [])

    @unittest.skipUnless(sys.platform == "darwin", "the /dev/bpf devices are macOS")
    @unittest.skipIf(os.geteuid() == 0, "the user identity zero holds the privilege")
    def test_the_case_skips_where_the_host_grants_the_privilege(self):
        """A host with the privilege reports no failure, so the case skips."""
        granted = os.open(os.devnull, os.O_RDONLY)
        with patch("scapy.arch.bpf.core.get_dev_bpf", return_value=(granted, 0)):
            result = self.the_guarded_case().run()
        self.assertEqual(result.errors, [])
        self.assertEqual(result.failures, [])
        self.assertEqual(len(result.skipped), 1)
        self.assertIn("grants the capture privilege", result.skipped[0][1])

    @unittest.skipUnless(sys.platform == "darwin", "the /dev/bpf devices are macOS")
    def test_the_probe_closes_the_descriptor_a_granting_host_returns(self):
        """`get_dev_bpf` returns an open descriptor, and nothing else closes it."""
        granted = os.open(os.devnull, os.O_RDONLY)
        with patch("scapy.arch.bpf.core.get_dev_bpf", return_value=(granted, 0)):
            self.assertIsNone(the_privilege_failure())
        with self.assertRaises(OSError):
            os.fstat(granted)


class TheCommandListsTheInterfacesItFound(unittest.TestCase):
    """FR-live-capture-12 — an absent interface produces a list of the real ones."""

    def test_the_message_lists_every_interface_the_host_holds(self):
        error = the_absent_interface_failure_or_skip(self)
        message = describe(error, interfaces=("en0", "lo0"))
        self.assertIn("en0", message)
        self.assertIn("lo0", message)

    def test_the_message_reads_a_host_that_holds_no_interface(self):
        error = the_absent_interface_failure_or_skip(self)
        message = describe(error, interfaces=())
        self.assertIn("no interface", message)

    def test_a_missing_device_number_reads_as_an_absent_interface(self):
        """Linux reports `ENODEV` from the bind call rather than a `ValueError`."""
        message = describe(OSError(19, "No such device"))
        self.assertIn("lo0", message)

    def test_the_interface_list_of_this_host_holds_a_name(self):
        """`available_interfaces` needs no privilege, so an error message can read it."""
        names = available_interfaces()
        if not names:
            # #426 records the guard. A minimal container reports no interface, and the
            # empty list is then the state of the host rather than a fault of the call.
            self.skipTest("the capture layer of this host reports no interface")
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
        error = the_filter_failure_or_skip(self)
        message = describe(error, capture_filter=INVALID_FILTER)
        self.assertIn(INVALID_FILTER, message)

    def test_the_message_repeats_what_the_capture_layer_reported(self):
        error = the_filter_failure_or_skip(self)
        message = describe(error, capture_filter=INVALID_FILTER)
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
            "watch", ABSENT_INTERFACE, failure=the_absent_interface_failure_or_skip(self)
        )
        self.assertEqual(status, 1)
        self.assertIn(ABSENT_INTERFACE, err)
        for name in available_interfaces():
            self.assertIn(name, err)

    def test_an_invalid_filter_ends_the_run_with_the_status_one(self):
        _, err, status = run_watch(
            "watch", "eth0", "--bpf", INVALID_FILTER, failure=the_filter_failure_or_skip(self)
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
            the_absent_interface_failure_or_skip(self),
            the_filter_failure_or_skip(self),
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


class TheFilterCasesGuardOnTheAmbientLibpcap(unittest.TestCase):
    """#426 — the four cases that read a real filter failure guard on `libpcap`.

    `the_filter_failure` calls `compile_filter`, and that call reaches `libpcap` through
    the host. A host that holds no `libpcap` compiles no expression, so the four cases
    below read a state this project does not control. A guard proved in one direction can
    skip on every host, and a case that always skips measures nothing. Each case here
    forces one direction and reads what the four guarded cases do.
    """

    def the_guarded_cases(self):
        """Return the four cases that read a real filter failure, ready to run.

        The list is built here and not in the class body, because two of the four classes
        are defined below this one.

        Returns:
            A list of pairs, each holding the case name and the case.
        """
        names = (
            (
                TheCommandReportsTheFilterError,
                "test_the_message_names_the_filter_the_operator_stated",
            ),
            (
                TheCommandReportsTheFilterError,
                "test_the_message_repeats_what_the_capture_layer_reported",
            ),
            (
                TheCaptureFailureEndsTheRunWithTheStatusOne,
                "test_an_invalid_filter_ends_the_run_with_the_status_one",
            ),
            (
                TheCaptureFailuresNameTheClassesTheCaptureLayerRaises,
                "test_the_three_real_failures_are_all_caught",
            ),
        )
        return [(name, case(name)) for case, name in names]

    def this_host_holds_libpcap(self):
        """Return whether `compile_filter` reaches `libpcap` on this host.

        The read calls `compile_filter` and not `the_filter_failure`. A prover that reads
        the state through the guard it proves cannot tell two states apart. One is a guard
        that skips on every host. The other is a host that holds no `libpcap`. The run
        direction is the direction such a prover loses.

        Returns:
            True where `compile_filter` compiled the expression or refused it.
        """
        from scapy.arch.common import compile_filter

        try:
            compile_filter(INVALID_FILTER, linktype=1)
        except Scapy_Exception:
            return True
        except ImportError:
            return False
        return True

    def test_the_probe_reads_the_import_error_scapy_raises(self):
        """`compile_filter` raises `ImportError` where the host holds no `libpcap`."""
        from scapy.arch.common import compile_filter

        with no_libpcap():
            with self.assertRaises(ImportError) as raised:
                compile_filter(INVALID_FILTER, linktype=1)
        # The guard reads the class. The message reaches the reader of a skip reason, so
        # the case holds the class exactly and the message by the one word that names it.
        self.assertIn("libpcap", str(raised.exception))

    def test_the_probe_reports_no_failure_where_the_host_holds_no_libpcap(self):
        """`the_filter_failure` returns None, because the expression reached no `libpcap`."""
        with no_libpcap():
            self.assertIsNone(the_filter_failure())

    def test_each_case_skips_where_the_host_holds_no_libpcap(self):
        """A host without `libpcap` skips all four cases, and each reason names it.

        One of the four cases reads the absent interface as well, and it reads that state
        first. This case therefore pins the interface state to the state of a host that
        holds no `nosuchif0`. Without that, a host holding both anomalies would skip on the
        interface and the reason would name the wrong state.
        """
        with no_libpcap():
            with patch("scapy.all.resolve_iface", side_effect=ValueError(ABSENT_INTERFACE)):
                results = [(name, case.run()) for name, case in self.the_guarded_cases()]
        for name, result in results:
            with self.subTest(case=name):
                self.assertEqual(result.errors, [])
                self.assertEqual(result.failures, [])
                self.assertEqual(len(result.skipped), 1)
                self.assertIn("libpcap", result.skipped[0][1])

    def test_each_case_runs_and_passes_where_the_host_holds_libpcap(self):
        """A host with `libpcap` runs all four cases, and each one passes.

        The case pins the interface state for the reason the skip direction states.
        """
        if not self.this_host_holds_libpcap():
            self.skipTest("this host holds no libpcap, so no case here can run")
        for name, case in self.the_guarded_cases():
            with self.subTest(case=name):
                with patch("scapy.all.resolve_iface", side_effect=ValueError(ABSENT_INTERFACE)):
                    result = case.run()
                self.assertEqual(result.testsRun, 1)
                self.assertEqual(result.errors, [])
                self.assertEqual(result.failures, [])
                self.assertEqual(result.skipped, [])


class TheAbsentInterfaceCasesGuardOnTheNameTheHostHolds(unittest.TestCase):
    """#426 — the four cases that read an absent interface guard on the name.

    `the_absent_interface_failure` asks `resolve_iface` for `nosuchif0`, and a host that
    holds an interface of that name resolves it. The name is a premise about the host, and
    this project does not control it. A guard proved in one direction can skip on every
    host, and a case that always skips measures nothing. Each case here forces one
    direction and reads what the four guarded cases do.
    """

    class ResolvedInterface:
        """A stand-in for the interface a host that holds `nosuchif0` would resolve.

        `resolve_iface` returns a `NetworkInterface` for a name the host holds. No case
        here reads a member of the result, because the guard reads whether the call
        raised.
        """

    def the_guarded_cases(self):
        """Return the four cases that read an absent interface, ready to run.

        Returns:
            A list of pairs, each holding the case name and the case.
        """
        names = (
            (
                TheCommandListsTheInterfacesItFound,
                "test_the_message_lists_every_interface_the_host_holds",
            ),
            (
                TheCommandListsTheInterfacesItFound,
                "test_the_message_reads_a_host_that_holds_no_interface",
            ),
            (
                TheCaptureFailureEndsTheRunWithTheStatusOne,
                "test_an_absent_interface_ends_the_run_with_the_status_one",
            ),
            (
                TheCaptureFailuresNameTheClassesTheCaptureLayerRaises,
                "test_the_three_real_failures_are_all_caught",
            ),
        )
        return [(name, case(name)) for case, name in names]

    @contextlib.contextmanager
    def a_host_that_holds_the_name(self):
        """Hold `resolve_iface` in the state a host that holds `nosuchif0` produces.

        Yields:
            None, while `resolve_iface` resolves every name.
        """
        with patch("scapy.all.resolve_iface", return_value=self.ResolvedInterface()):
            yield

    def this_host_holds_the_name(self):
        """Return whether this host holds an interface named `nosuchif0`.

        The read calls `resolve_iface` and not `the_absent_interface_failure`. A prover
        that reads the state through the guard it proves cannot tell two states apart. One
        is a guard that skips on every host. The other is a host that holds the name.

        Returns:
            True where `resolve_iface` resolved the name.
        """
        from scapy.all import resolve_iface

        try:
            resolve_iface(ABSENT_INTERFACE)
        except ValueError:
            return False
        return True

    def test_the_probe_reports_no_failure_where_the_host_holds_the_name(self):
        """`the_absent_interface_failure` returns None, because the call raised nothing."""
        with self.a_host_that_holds_the_name():
            self.assertIsNone(the_absent_interface_failure())

    def test_each_case_skips_where_the_host_holds_the_name(self):
        """A host that holds `nosuchif0` skips all four cases, and each reason names it."""
        with self.a_host_that_holds_the_name():
            results = [(name, case.run()) for name, case in self.the_guarded_cases()]
        for name, result in results:
            with self.subTest(case=name):
                self.assertEqual(result.errors, [])
                self.assertEqual(result.failures, [])
                self.assertEqual(len(result.skipped), 1)
                self.assertIn(ABSENT_INTERFACE, result.skipped[0][1])

    def test_each_case_runs_and_passes_where_the_host_holds_no_such_name(self):
        """A host without `nosuchif0` runs all four cases, and each one passes.

        One of the four cases reads the `libpcap` state as well. This case therefore pins
        that state to the failure a host with `libpcap` reports for a filter it refuses.
        Without that, a host without `libpcap` would skip on the filter state here.
        """
        if self.this_host_holds_the_name():
            self.skipTest("this host holds an interface named " + ABSENT_INTERFACE)
        # The text `libpcap` writes for this expression, which `test_the_probe_reads_...`
        # of the class above reads from the real call.
        refusal = Scapy_Exception(f"Failed to compile filter expression {INVALID_FILTER} (-1)")
        for name, case in self.the_guarded_cases():
            with self.subTest(case=name):
                with patch("scapy.arch.common.compile_filter", side_effect=refusal):
                    result = case.run()
                self.assertEqual(result.testsRun, 1)
                self.assertEqual(result.errors, [])
                self.assertEqual(result.failures, [])
                self.assertEqual(result.skipped, [])


class TheInterfaceListCaseGuardsOnTheListTheHostReports(unittest.TestCase):
    """#426 — the case that reads the interface list guards on the list.

    `test_the_interface_list_of_this_host_holds_a_name` asks the capture layer for the
    interface list of the host. A host whose capture layer reports no interface fails it,
    and a container is such a host. A guard proved in one direction can skip on every
    host, and a case that always skips measures nothing. The two cases here force each
    direction.
    """

    def the_guarded_case(self):
        """Return the case that reads the interface list, ready to run.

        Returns:
            The `TheCommandListsTheInterfacesItFound` case that reads this host.
        """
        return TheCommandListsTheInterfacesItFound(
            "test_the_interface_list_of_this_host_holds_a_name"
        )

    def test_the_case_skips_where_the_host_reports_no_interface(self):
        """A capture layer that reports no interface skips the case."""
        with patch("scapy.all.get_if_list", return_value=[]):
            result = self.the_guarded_case().run()
        self.assertEqual(result.errors, [])
        self.assertEqual(result.failures, [])
        self.assertEqual(len(result.skipped), 1)
        self.assertIn("no interface", result.skipped[0][1])

    def test_the_case_runs_and_passes_where_the_host_reports_one_interface(self):
        """A capture layer that reports one interface runs the case, and it passes."""
        with patch("scapy.all.get_if_list", return_value=["en0"]):
            result = self.the_guarded_case().run()
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.failures, [])
        self.assertEqual(result.skipped, [])


if __name__ == "__main__":
    sys.exit(unittest.main())
