"""
Tests for ja4plus CLI (ja4plus/cli.py).
"""

import csv
import io
import json
import os
import sys
import unittest
from unittest.mock import patch

# Path to test data
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
HTTP_CAP = os.path.join(DATA_DIR, "http.cap")
CERT_DER = os.path.join(DATA_DIR, "test_cert.der")


def run_cli(*argv):
    """
    Run the CLI main() function with the given arguments.
    Captures stdout/stderr and the exit code.
    Returns (stdout_str, stderr_str, exit_code).
    exit_code is 0 if main() returns normally.
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


class TestAnalyzePcap(unittest.TestCase):
    def test_analyze_pcap(self):
        """analyze command produces fingerprint output for http.cap."""
        out, err, code = run_cli("analyze", HTTP_CAP)
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        # Should have some output lines (table header + data)
        lines = out.strip().splitlines()
        self.assertGreater(len(lines), 1, "Expected at least a header and one fingerprint row")

    def test_analyze_json_format(self):
        """--format json produces valid JSONL output."""
        out, err, code = run_cli("--format", "json", "analyze", HTTP_CAP)
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        lines = [line for line in out.strip().splitlines() if line.strip()]
        self.assertGreater(len(lines), 0, "Expected at least one JSON line")
        for line in lines:
            obj = json.loads(line)
            # #49 replaced the composite `source` field with the four endpoint fields.
            # `tests/test_output_schema.py` holds the whole field set.
            self.assertNotIn("source", obj)
            self.assertIn("src_ip", obj)
            self.assertIn("src_port", obj)
            self.assertIn("dst_ip", obj)
            self.assertIn("dst_port", obj)
            self.assertIn("type", obj)
            self.assertIn("fingerprint", obj)

    def test_analyze_csv_format(self):
        """--format csv produces CSV with headers and data rows."""
        out, err, code = run_cli("--format", "csv", "analyze", HTTP_CAP)
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        reader = csv.reader(io.StringIO(out))
        rows = list(reader)
        self.assertGreater(len(rows), 1, "Expected header + at least one data row")
        # #49 fixed the column order. `tests/test_output_schema.py` compares the header
        # against the documented list.
        from ja4plus.output import CSV_COLUMNS

        self.assertEqual(rows[0], list(CSV_COLUMNS))
        for row in rows[1:]:
            if row:  # skip blank lines
                self.assertEqual(
                    len(row), len(CSV_COLUMNS), f"Expected {len(CSV_COLUMNS)} columns, got: {row}"
                )

    def test_analyze_types_filter(self):
        """--types ja4t restricts output to JA4T fingerprints only."""
        out, err, code = run_cli("--format", "json", "--types", "ja4t", "analyze", HTTP_CAP)
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        lines = [line for line in out.strip().splitlines() if line.strip()]
        # May be zero lines if no TCP packets match, but if there are lines they must be ja4t
        for line in lines:
            obj = json.loads(line)
            self.assertEqual(obj["type"], "ja4t", f"Expected only ja4t but got: {obj['type']}")

    def test_analyze_file_not_found(self):
        """analyze with nonexistent file exits with code 1 and error message."""
        out, err, code = run_cli("analyze", "/nonexistent/path/file.pcap")
        self.assertEqual(code, 1)
        self.assertIn("not found", err.lower())

    def test_analyze_table_has_header(self):
        """Default table format starts with a Source/Type/Fingerprint header."""
        out, err, code = run_cli("analyze", HTTP_CAP)
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        self.assertIn("Source", out)
        self.assertIn("Type", out)
        self.assertIn("Fingerprint", out)


class TestCertCommand(unittest.TestCase):
    def test_cert_command(self):
        """cert command produces a JA4X fingerprint for example_cert.der."""
        out, err, code = run_cli("cert", CERT_DER)
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        self.assertIn("ja4x", out.lower())

    def test_cert_json_format(self):
        """cert --format json includes type=ja4x in output."""
        out, err, code = run_cli("--format", "json", "cert", CERT_DER)
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        lines = [line for line in out.strip().splitlines() if line.strip()]
        self.assertGreater(len(lines), 0)
        obj = json.loads(lines[0])
        self.assertEqual(obj["type"], "ja4x")
        self.assertIn("fingerprint", obj)

    def test_cert_file_not_found(self):
        """cert with nonexistent file exits with code 1 and error message."""
        out, err, code = run_cli("cert", "/nonexistent/cert.der")
        self.assertEqual(code, 1)
        self.assertIn("not found", err.lower())


class TestVersionFlag(unittest.TestCase):
    def test_version_flag(self):
        """--version prints the version string."""
        out, err, code = run_cli("--version")
        # argparse sends --version output to stdout in Python 3.4+
        combined = out + err
        self.assertIn("ja4plus", combined.lower())
        # Should contain a version number (digits and dots)
        import re

        self.assertTrue(
            re.search(r"\d+\.\d+", combined), f"No version number found in: {combined!r}"
        )


SSH2_VECTOR = os.path.join(os.path.dirname(__file__), "foxio_vectors", "ssh2.pcapng")


class TestTheTrailingJA4SSHWindow(unittest.TestCase):
    """The `analyze` command reads a file, so the capture ends at the last packet.

    `ssh2.pcapng` carries no FIN+ACK packet on port 22, so the connection holds its last
    window open. #214 decided that this project emits that window.
    """

    @unittest.skipUnless(os.path.exists(SSH2_VECTOR), "the FoxIO vector ssh2.pcapng is absent")
    def test_analyze_writes_the_window_the_connection_holds_open(self):
        out, err, code = run_cli("--format", "json", "--types", "ja4ssh", "analyze", SSH2_VECTOR)
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        records = [json.loads(line) for line in out.strip().splitlines() if line.strip()]
        values = [record["fingerprint"] for record in records]
        self.assertEqual(values, ["c36s36_c76s124_c74s5", "c36s52_c42s76_c51s2"])
        # No packet closes this window, so #49 reads the four endpoint fields back from
        # the connection key that the fingerprinter reported.
        self.assertEqual(records[1]["src_ip"], "172.16.225.48")
        self.assertEqual(records[1]["src_port"], 57377)
        self.assertEqual(records[1]["dst_ip"], "54.160.114.75")
        self.assertEqual(records[1]["dst_port"], 22)


class TestInvalidTypes(unittest.TestCase):
    def test_invalid_types(self):
        """--types with unknown type exits with code 1 and lists valid types."""
        out, err, code = run_cli("--format", "json", "--types", "notatype", "analyze", HTTP_CAP)
        self.assertEqual(code, 1)
        self.assertIn("invalid", err.lower())
        # Should mention at least one valid type
        self.assertIn("ja4", err.lower())

    def test_valid_types_accepted(self):
        """All valid type names are accepted without error."""
        from ja4plus.cli import VALID_TYPES, _parse_types

        for t in VALID_TYPES:
            result = _parse_types(t)
            self.assertEqual(result, [t])


if __name__ == "__main__":
    unittest.main()
