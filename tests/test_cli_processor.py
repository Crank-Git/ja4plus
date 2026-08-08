"""Tests for the command-line program that #51 builds on `Processor`.

`docs/specs/features/05-structured-output.md` states the two requirements this file
measures. FR-structured-output-11 asks the program to build one `Processor` rather than
a dictionary of fingerprinters. FR-structured-output-12 asks the program to report a
fingerprinter error rather than to swallow it.

Version 0.6.0 caught every error with `except Exception` and continued, so no earlier
test could measure the diagnostic. Each test below fails against that code.
"""

import io
import json
import os
import sys
import unittest
from unittest.mock import patch

from ja4plus.processor import Processor

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
HTTP_CAP = os.path.join(DATA_DIR, "http.cap")

# `http.cap` holds this many packets, and `PcapReader` gives every one of them to the
# processor. A method that raises on each packet therefore produces this many lines.
HTTP_CAP_PACKETS = 43


class ProcessorFactory:
    """A stand-in for `ja4plus.cli.Processor` that makes one method raise.

    A fingerprinter of this project raises on no capture in the test data, so a test
    that wants the diagnostic path installs the failure. The factory builds the real
    `Processor` and replaces the `process_packet` of one method.

    Args:
        method: The method name that raises, such as `ja4h`.
        message: The message the error carries.

    Attributes:
        calls: The count of processors the command built. FR-structured-output-11 asks
            for one.
    """

    def __init__(self, method=None, message="this parser cannot read the packet"):
        self.method = method
        self.message = message
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        processor = Processor(*args, **kwargs)
        if self.method is not None:

            def raise_the_error(packet):
                raise ValueError(self.message)

            processor.fingerprinters[self.method].process_packet = raise_the_error
        return processor


def run_cli(*argv, factory=None):
    """Run the command-line program and return its standard output, error and status.

    Args:
        argv: The arguments to pass, without the program name.
        factory: A `ProcessorFactory` to install in place of `ja4plus.cli.Processor`, or
            None to let the command build the real processor.

    Returns:
        A tuple of the standard output, the standard error and the exit status. The
        status is 0 when `main` returns without an exit.
    """
    from ja4plus.cli import main

    captured_out = io.StringIO()
    captured_err = io.StringIO()
    patches = [
        patch("sys.argv", ["ja4plus"] + list(argv)),
        patch("sys.stdout", captured_out),
        patch("sys.stderr", captured_err),
    ]
    if factory is not None:
        patches.append(patch("ja4plus.cli.Processor", factory))

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


def error_lines(err):
    """Return the standard error lines that report a fingerprinter error.

    Args:
        err: The whole standard error text of one run.

    Returns:
        A list of the lines that hold `could not read a packet`.
    """
    return [line for line in err.splitlines() if "could not read a packet" in line]


class TheProgramBuildsOneProcessor(unittest.TestCase):
    """FR-structured-output-11 — the program builds one `Processor`."""

    def test_the_analyze_command_builds_one_processor(self):
        factory = ProcessorFactory()
        _, err, status = run_cli("analyze", HTTP_CAP, factory=factory)
        self.assertEqual(status, 0, err)
        self.assertEqual(factory.calls, 1)

    def test_the_module_holds_no_dictionary_of_fingerprinter_classes(self):
        import ja4plus.cli as cli

        self.assertFalse(hasattr(cli, "ALL_FINGERPRINTERS"))
        self.assertFalse(hasattr(cli, "_build_fingerprinters"))


class TheProgramReportsAFingerprinterError(unittest.TestCase):
    """FR-structured-output-12 — the program reports the error rather than swallow it."""

    def test_the_program_names_the_method_that_raised(self):
        factory = ProcessorFactory("ja4h")
        _, err, status = run_cli("--format", "json", "analyze", HTTP_CAP, factory=factory)
        self.assertEqual(status, 0, err)
        lines = error_lines(err)
        self.assertTrue(lines, f"the program wrote no diagnostic. stderr: {err!r}")
        self.assertIn("ja4h", lines[0])

    def test_the_program_writes_the_message_the_error_carries(self):
        factory = ProcessorFactory("ja4h", "the parser read a length field it cannot trust")
        _, err, _ = run_cli("--format", "json", "analyze", HTTP_CAP, factory=factory)
        self.assertIn("the parser read a length field it cannot trust", err)

    def test_the_program_writes_the_diagnostic_to_standard_error(self):
        factory = ProcessorFactory("ja4h")
        out, err, _ = run_cli("--format", "json", "analyze", HTTP_CAP, factory=factory)
        # FR-structured-output-9 asks for results on standard output and diagnostics on
        # standard error, so a downstream tool that reads standard output reads no
        # diagnostic.
        self.assertNotIn("could not read a packet", out)
        self.assertIn("could not read a packet", err)

    def test_the_run_continues_after_a_method_raises(self):
        factory = ProcessorFactory("ja4h")
        out, err, status = run_cli("--format", "json", "analyze", HTTP_CAP, factory=factory)
        self.assertEqual(status, 0, err)
        types = {json.loads(line)["type"] for line in out.splitlines() if line.strip()}
        self.assertIn("ja4t", types, "a method that raises stops no other method")
        self.assertNotIn("ja4h", types)

    def test_the_program_writes_one_line_for_every_packet_that_raises(self):
        factory = ProcessorFactory("ja4h")
        _, err, _ = run_cli("--format", "json", "analyze", HTTP_CAP, factory=factory)
        self.assertEqual(len(error_lines(err)), HTTP_CAP_PACKETS)

    def test_the_program_writes_no_diagnostic_when_no_method_raises(self):
        _, err, status = run_cli("--format", "json", "analyze", HTTP_CAP)
        self.assertEqual(status, 0, err)
        self.assertEqual(error_lines(err), [])

    def test_the_program_reports_an_error_of_a_method_the_types_option_excludes(self):
        """The program filters the results it reports. It filters no error.

        The processor runs every method whatever `--types` names, so it evicts the
        connections of a method the user filtered out and it reports that method's
        errors.
        """
        factory = ProcessorFactory("ja4h")
        out, err, status = run_cli(
            "--format", "json", "--types", "ja4t", "analyze", HTTP_CAP, factory=factory
        )
        self.assertEqual(status, 0, err)
        lines = error_lines(err)
        self.assertTrue(lines, f"the program wrote no diagnostic. stderr: {err!r}")
        self.assertIn("ja4h", lines[0])
        types = {json.loads(line)["type"] for line in out.splitlines() if line.strip()}
        self.assertEqual(types, {"ja4t"})


class TheProgramHoldsNoError(unittest.TestCase):
    """The program keeps no exception object after it reports one.

    A returned exception carries no traceback, because a traceback holds the packet as a
    local of every frame. `CLAUDE.md` states that no code holds a reference to a packet
    object after `process_packet` returns. The program writes each error and keeps
    none, so nothing grows across the capture.
    """

    def test_the_module_holds_no_list_of_errors_after_the_run(self):
        import ja4plus.cli as cli
        import gc

        factory = ProcessorFactory("ja4h")
        run_cli("--format", "json", "analyze", HTTP_CAP, factory=factory)
        gc.collect()
        held = [
            name
            for name, value in vars(cli).items()
            if isinstance(value, list) and any(isinstance(item, BaseException) for item in value)
        ]
        self.assertEqual(held, [])


if __name__ == "__main__":
    sys.exit(unittest.main())
