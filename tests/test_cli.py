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
    with patch("sys.argv", ["ja4plus"] + list(argv)), \
         patch("sys.stdout", captured_out), \
         patch("sys.stderr", captured_err):
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
        lines = [l for l in out.strip().splitlines() if l.strip()]
        self.assertGreater(len(lines), 0, "Expected at least one JSON line")
        for line in lines:
            obj = json.loads(line)
            self.assertIn("source", obj)
            self.assertIn("type", obj)
            self.assertIn("fingerprint", obj)

    def test_analyze_csv_format(self):
        """--format csv produces CSV with headers and data rows."""
        out, err, code = run_cli("--format", "csv", "analyze", HTTP_CAP)
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        reader = csv.reader(io.StringIO(out))
        rows = list(reader)
        self.assertGreater(len(rows), 1, "Expected header + at least one data row")
        self.assertEqual(rows[0], ["source", "type", "fingerprint"])
        # All data rows should have 3 columns
        for row in rows[1:]:
            if row:  # skip blank lines
                self.assertEqual(len(row), 3, f"Expected 3 columns, got: {row}")

    def test_analyze_types_filter(self):
        """--types ja4t restricts output to JA4T fingerprints only."""
        out, err, code = run_cli("--format", "json", "--types", "ja4t", "analyze", HTTP_CAP)
        self.assertEqual(code, 0, f"CLI exited with {code}. stderr: {err}")
        lines = [l for l in out.strip().splitlines() if l.strip()]
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
        lines = [l for l in out.strip().splitlines() if l.strip()]
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
            re.search(r"\d+\.\d+", combined),
            f"No version number found in: {combined!r}"
        )


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
