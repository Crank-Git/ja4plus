"""Tests for the result channel, the output file and the closed pipe that #52 builds.

`docs/specs/features/05-structured-output.md` states the three requirements this file
measures.

- FR-structured-output-6 asks the `--format` option to accept `table`, `json` and `csv`.
- FR-structured-output-9 asks the program to write results to standard output and
  diagnostics to standard error.
- FR-structured-output-10 asks the `--output` option to write results to a file.

Every test below fails against the base commit. The base parser holds `--format` on the
main parser alone, so it rejects the option after the subcommand name. The base parser
holds no `--output` option and no `--force` option. The base program lets a
`BrokenPipeError` reach the top level as a traceback.
"""

import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
HTTP_CAP = os.path.join(DATA_DIR, "http.cap")
CERT_DER = os.path.join(DATA_DIR, "test_cert.der")

# The 24 bytes of a libpcap file header, in little-endian form: the magic number
# `d4c3b2a1`, the version 2.4, the zone 0, the accuracy 0, the snapshot length 65535 and
# the link type 1 for Ethernet. A file that holds this header and no packet is the empty
# capture that the acceptance criteria of #52 name.
EMPTY_PCAP = bytes.fromhex("d4c3b2a1") + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)


def run_cli(*argv):
    """Return the standard output, the standard error and the exit status of one run.

    Args:
        argv: The command-line words that follow the program name.

    Returns:
        A tuple of the standard output text, the standard error text and the exit
        status. The status is 0 when `main` returns without a `SystemExit`.
    """
    from ja4plus.cli import main

    captured_out = io.StringIO()
    captured_err = io.StringIO()

    exit_code = 0
    with (
        patch("sys.argv", ["ja4plus"] + list(argv)),
        patch("sys.stdout", captured_out),
        patch("sys.stderr", captured_err),
    ):
        try:
            main()
        except SystemExit as e:
            exit_code = e.code if e.code is not None else 0

    return captured_out.getvalue(), captured_err.getvalue(), exit_code


class EmptyCapture:
    """A context manager that holds the path of a capture file with no packet."""

    def __enter__(self):
        handle = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        handle.write(EMPTY_PCAP)
        handle.close()
        self.path = handle.name
        return self.path

    def __exit__(self, *exc_info):
        os.unlink(self.path)
        return False


class TheFormatOptionFollowsTheSubcommandName(unittest.TestCase):
    """The acceptance criteria of #52 write every option after the subcommand name.

    `ja4plus analyze <capture> --format csv` is one of them. The main parser keeps the
    same options, so a command that writes an option before the subcommand name still
    runs.
    """

    def test_the_analyze_command_accepts_the_format_option_after_the_subcommand_name(self):
        out, err, code = run_cli("analyze", HTTP_CAP, "--format", "json")
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        lines = [line for line in out.strip().splitlines() if line.strip()]
        self.assertGreater(len(lines), 0)
        for line in lines:
            json.loads(line)

    def test_the_analyze_command_keeps_the_format_option_written_before_the_name(self):
        out, err, code = run_cli("--format", "json", "analyze", HTTP_CAP)
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        lines = [line for line in out.strip().splitlines() if line.strip()]
        self.assertGreater(len(lines), 0)
        for line in lines:
            json.loads(line)

    def test_the_analyze_command_accepts_the_types_option_after_the_subcommand_name(self):
        out, err, code = run_cli("analyze", HTTP_CAP, "--format", "json", "--types", "ja4t")
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        lines = [line for line in out.strip().splitlines() if line.strip()]
        for line in lines:
            self.assertEqual(json.loads(line)["type"], "ja4t")

    def test_the_cert_command_accepts_the_format_option_after_the_subcommand_name(self):
        out, err, code = run_cli("cert", CERT_DER, "--format", "json")
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        lines = [line for line in out.strip().splitlines() if line.strip()]
        self.assertEqual(json.loads(lines[0])["type"], "ja4x")


class ACaptureWithNoPacketWritesTheHeaderAlone(unittest.TestCase):
    """The edge-case table of the feature states what each format writes for this case.

    The JSON format writes nothing. The CSV format writes the header only. The table
    format writes the header and a message on standard error.
    """

    def test_the_csv_format_writes_the_header_and_no_data_row(self):
        from ja4plus.output import CSV_COLUMNS

        with EmptyCapture() as path:
            out, err, code = run_cli("analyze", path, "--format", "csv")
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        lines = [line for line in out.splitlines() if line.strip()]
        self.assertEqual(lines, [",".join(CSV_COLUMNS)])

    def test_the_json_format_writes_nothing_to_standard_output(self):
        with EmptyCapture() as path:
            out, err, code = run_cli("analyze", path, "--format", "json")
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        self.assertEqual(out, "")

    def test_the_table_format_writes_the_message_to_standard_error(self):
        with EmptyCapture() as path:
            out, err, code = run_cli("analyze", path, "--format", "table")
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        self.assertIn("no fingerprint", err.lower())

    def test_the_table_format_writes_no_message_to_standard_output(self):
        with EmptyCapture() as path:
            out, err, code = run_cli("analyze", path, "--format", "table")
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        self.assertNotIn("no fingerprint", out.lower())

    def test_the_csv_format_writes_no_message_to_standard_error(self):
        with EmptyCapture() as path:
            out, err, code = run_cli("analyze", path, "--format", "csv")
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        self.assertEqual(err, "")


class TheOutputOptionWritesTheResultsToAFile(unittest.TestCase):
    """FR-structured-output-10 asks the `--output` option to write results to a file."""

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.path = os.path.join(self.directory, "out.json")

    def tearDown(self):
        for name in os.listdir(self.directory):
            os.unlink(os.path.join(self.directory, name))
        os.rmdir(self.directory)

    def test_the_file_holds_the_lines_that_standard_output_holds_without_the_option(self):
        expected, _, _ = run_cli("analyze", HTTP_CAP, "--format", "json")
        out, err, code = run_cli("analyze", HTTP_CAP, "--format", "json", "--output", self.path)
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        with open(self.path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), expected)

    def test_standard_output_holds_nothing_when_the_option_names_a_file(self):
        out, err, code = run_cli("analyze", HTTP_CAP, "--format", "json", "--output", self.path)
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        self.assertEqual(out, "")

    def test_the_cert_command_writes_the_results_to_the_file(self):
        out, err, code = run_cli("cert", CERT_DER, "--format", "json", "--output", self.path)
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        with open(self.path, encoding="utf-8") as handle:
            self.assertEqual(json.loads(handle.readline())["type"], "ja4x")


class TheProgramRefusesToOverwriteAFileThatExists(unittest.TestCase):
    """The behaviour rules state that the program refuses unless `--force` is passed.

    A refusal that no test exercises is no refusal. Each case below fails when the guard
    goes away.
    """

    EXISTING = "the earlier run wrote this line\n"

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.path = os.path.join(self.directory, "existing.json")
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(self.EXISTING)

    def tearDown(self):
        for name in os.listdir(self.directory):
            os.unlink(os.path.join(self.directory, name))
        os.rmdir(self.directory)

    def read_bytes(self):
        with open(self.path, "rb") as handle:
            return handle.read()

    def test_the_command_exits_with_the_status_1(self):
        out, err, code = run_cli("analyze", HTTP_CAP, "--format", "json", "--output", self.path)
        self.assertEqual(code, 1)

    def test_the_command_leaves_the_file_byte_for_byte_unchanged(self):
        run_cli("analyze", HTTP_CAP, "--format", "json", "--output", self.path)
        self.assertEqual(self.read_bytes(), self.EXISTING.encode("utf-8"))

    def test_the_command_names_the_file_on_standard_error(self):
        out, err, code = run_cli("analyze", HTTP_CAP, "--format", "json", "--output", self.path)
        self.assertIn(self.path, err)
        self.assertIn("--force", err)

    def test_the_command_writes_nothing_to_standard_output(self):
        out, err, code = run_cli("analyze", HTTP_CAP, "--format", "json", "--output", self.path)
        self.assertEqual(out, "")

    def test_the_command_writes_through_no_symbolic_link(self):
        """A link whose target is absent is refused, and the target stays absent.

        `os.path.exists` follows a link and reports False for a link with no target, so
        the test above cannot see it. The open mode `x` refuses it.
        """
        target = os.path.join(self.directory, "victim.txt")
        link = os.path.join(self.directory, "link.json")
        os.symlink(target, link)
        out, err, code = run_cli("analyze", HTTP_CAP, "--format", "json", "--output", link)
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(target))

    def test_the_command_refuses_a_file_that_arrives_after_the_test(self):
        """The open mode `x` refuses the file, because the test above cannot see it."""
        real_exists = os.path.exists

        def missing(candidate):
            return False if candidate == self.path else real_exists(candidate)

        with patch("ja4plus.cli.os.path.exists", side_effect=missing):
            out, err, code = run_cli("analyze", HTTP_CAP, "--format", "json", "--output", self.path)
        self.assertEqual(code, 1)
        self.assertIn("--force", err)
        self.assertEqual(self.read_bytes(), self.EXISTING.encode("utf-8"))

    def test_the_force_option_overwrites_the_file(self):
        out, err, code = run_cli(
            "analyze", HTTP_CAP, "--format", "json", "--output", self.path, "--force"
        )
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        self.assertNotEqual(self.read_bytes(), self.EXISTING.encode("utf-8"))

    def test_the_force_option_writes_the_lines_that_standard_output_holds(self):
        expected, _, _ = run_cli("analyze", HTTP_CAP, "--format", "json")
        run_cli("analyze", HTTP_CAP, "--format", "json", "--output", self.path, "--force")
        with open(self.path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), expected)


class ClosedPipe(io.StringIO):
    """A stand-in for standard output that raises the error a closed pipe raises."""

    def write(self, text):
        raise BrokenPipeError(32, "Broken pipe")


class TheProgramExitsQuietlyWhenTheWriteFails(unittest.TestCase):
    """A reader that closes the pipe early makes every later write raise.

    This case replaces standard output rather than a pipe, so it needs no race between
    two processes. `TheProgramExitsQuietlyWhenTheReaderClosesThePipe` runs the real pipe.
    """

    def test_the_program_exits_with_the_status_1(self):
        out, err, code = run_cli("--format", "json", "analyze", HTTP_CAP)
        self.assertEqual(code, 0, f"the capture must produce output. stderr: {err}")
        from ja4plus.cli import main

        exit_code = None
        captured_err = io.StringIO()
        with (
            patch("sys.argv", ["ja4plus", "--format", "json", "analyze", HTTP_CAP]),
            patch("sys.stdout", ClosedPipe()),
            patch("sys.stderr", captured_err),
        ):
            try:
                main()
            except SystemExit as e:
                exit_code = e.code
        self.assertEqual(exit_code, 1)
        self.assertNotIn("Error reading PCAP file", captured_err.getvalue())


# The program writes this capture as more than 64 kilobytes of JSON, so it still has
# data to write after `head -1` closes the pipe. A capture whose whole output fits in
# one write never reaches the closed pipe.
LARGE_VECTOR = os.path.join(os.path.dirname(__file__), "foxio_vectors", "tls-handshake.pcapng")


class TheProgramExitsQuietlyWhenTheReaderClosesThePipe(unittest.TestCase):
    """The edge-case table states that the program exits without a traceback.

    The case runs the program as a real process. A `BrokenPipeError` needs a real pipe,
    and the interpreter writes its shutdown message to a real file descriptor.
    """

    def run_through_head(self, *argv):
        """Return the standard error of one run whose reader closes the pipe early."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # `scapy` imports a deprecated `cryptography` name and the interpreter writes
        # that warning to standard error. `-W ignore` removes it, so the assertions
        # below read the lines the program itself wrote.
        program = subprocess.Popen(
            [sys.executable, "-W", "ignore", "-m", "ja4plus.cli", *argv],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=root,
        )
        reader = subprocess.Popen(["head", "-1"], stdin=program.stdout, stdout=subprocess.DEVNULL)
        program.stdout.close()
        reader.wait()
        error = program.stderr.read().decode("utf-8", "replace")
        program.stderr.close()
        program.wait()
        return error

    @unittest.skipUnless(os.path.exists(LARGE_VECTOR), "the FoxIO vector tls-handshake.pcapng")
    def test_the_program_writes_no_traceback(self):
        error = self.run_through_head("--format", "json", "analyze", LARGE_VECTOR)
        self.assertNotIn("Traceback", error)

    @unittest.skipUnless(os.path.exists(LARGE_VECTOR), "the FoxIO vector tls-handshake.pcapng")
    def test_the_program_writes_no_broken_pipe_message(self):
        error = self.run_through_head("--format", "json", "analyze", LARGE_VECTOR)
        self.assertNotIn("BrokenPipeError", error)

    @unittest.skipUnless(os.path.exists(LARGE_VECTOR), "the FoxIO vector tls-handshake.pcapng")
    def test_the_program_writes_no_shutdown_message(self):
        error = self.run_through_head("--format", "json", "analyze", LARGE_VECTOR)
        self.assertNotIn("Exception ignored", error)

    @unittest.skipUnless(os.path.exists(LARGE_VECTOR), "the FoxIO vector tls-handshake.pcapng")
    def test_the_program_writes_nothing_to_standard_error(self):
        error = self.run_through_head("--format", "json", "analyze", LARGE_VECTOR)
        self.assertEqual(error, "")


if __name__ == "__main__":
    unittest.main()
