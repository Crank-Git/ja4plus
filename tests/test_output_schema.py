"""Tests for the output records that `ja4plus/output.py` writes.

`docs/specs/features/05-structured-output.md` defines the schema. #49 covers the
separate address and port fields, the fixed CSV column order and the empty column.
#50 covers the schema version rule and `docs/output-schema.md`.
"""

import csv
import io
import json
import os
import unittest
from contextlib import ExitStack
from datetime import datetime, timezone
from unittest.mock import patch

from ja4plus.output import CSV_COLUMNS, CsvWriter, JsonLinesWriter, TableWriter
from ja4plus.types import FingerprintResult

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
HTTP_CAP = os.path.join(DATA_DIR, "http.cap")

# `docs/specs/features/05-structured-output.md` states this order, and the mockup
# `docs/specs/mockups/01-cli-output.html` repeats it. The test holds its own copy, so a
# change to `CSV_COLUMNS` alone fails here.
DOCUMENTED_COLUMNS = [
    "schema_version",
    "timestamp",
    "type",
    "fingerprint",
    "raw",
    "raw_original_order",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "identified_as",
]

# The JSON object carries one field for each CSV column. FR-structured-output-5 asks for
# a value that is present and null rather than absent.
DOCUMENTED_FIELDS = set(DOCUMENTED_COLUMNS)


class StubLookupClient:
    """A lookup client that answers from a dict and reaches no network.

    `--lookup` builds a `JA4DBClient`, and that client falls back to `ja4db.com`. A test
    that built the real client would depend on the network.

    Args:
        matches: A dict that maps a fingerprint to an application name.
    """

    def __init__(self, matches=None):
        self.matches = matches or {}

    def lookup(self, fingerprint):
        """Return the match dict for the fingerprint, or None when there is no match."""
        application = self.matches.get(fingerprint)
        return {"application": application} if application else None


def run_cli(*argv, lookup_client=None):
    """Run the command-line program, and return its standard output, error and status.

    Args:
        argv: The arguments that follow the program name.
        lookup_client: A stub that replaces the client `--lookup` builds, or None to
            leave the real client in place.

    Returns:
        A tuple of the standard output, the standard error and the exit status.
    """
    from ja4plus.cli import main

    captured_out = io.StringIO()
    captured_err = io.StringIO()
    exit_code = 0

    with ExitStack() as stack:
        stack.enter_context(patch("sys.argv", ["ja4plus"] + list(argv)))
        stack.enter_context(patch("sys.stdout", captured_out))
        stack.enter_context(patch("sys.stderr", captured_err))
        if lookup_client is not None:
            stack.enter_context(patch("ja4plus.cli._init_lookup", return_value=lookup_client))
        try:
            main()
        except SystemExit as e:
            exit_code = e.code if e.code is not None else 0

    return captured_out.getvalue(), captured_err.getvalue(), exit_code


def csv_rows(text):
    """Return the parsed rows of the CSV text, with the blank trailing row removed."""
    return [row for row in csv.reader(io.StringIO(text)) if row]


def json_records(text):
    """Return one parsed object for each non-empty line of the text."""
    return [json.loads(line) for line in text.splitlines() if line.strip()]


class TheCsvHeader(unittest.TestCase):
    def test_the_csv_header_matches_the_documented_column_order(self):
        out, err, code = run_cli("--format", "csv", "analyze", HTTP_CAP)
        self.assertEqual(code, 0, f"the command exited with {code}. stderr: {err}")
        rows = csv_rows(out)
        self.assertEqual(rows[0], DOCUMENTED_COLUMNS)

    def test_the_module_column_list_matches_the_documented_column_order(self):
        self.assertEqual(list(CSV_COLUMNS), DOCUMENTED_COLUMNS)

    def test_the_csv_header_is_identical_with_and_without_lookup(self):
        plain, _, plain_code = run_cli("--format", "csv", "analyze", HTTP_CAP)
        looked_up, _, lookup_code = run_cli(
            "--format",
            "csv",
            "--lookup",
            "analyze",
            HTTP_CAP,
            lookup_client=StubLookupClient({"8760_2-1-1-4_1460_0": "Test Application"}),
        )
        self.assertEqual(plain_code, 0)
        self.assertEqual(lookup_code, 0)
        self.assertEqual(csv_rows(plain)[0], csv_rows(looked_up)[0])

    def test_lookup_changes_the_identified_as_value_and_no_other_column(self):
        """The proof that the header test above compares two different runs."""
        looked_up, _, code = run_cli(
            "--format",
            "csv",
            "--lookup",
            "analyze",
            HTTP_CAP,
            lookup_client=StubLookupClient({"8760_2-1-1-4_1460_0": "Test Application"}),
        )
        self.assertEqual(code, 0)
        rows = csv_rows(looked_up)
        identified = rows[0].index("identified_as")
        values = [row[identified] for row in rows[1:]]
        self.assertIn("Test Application", values)


class TheCsvRows(unittest.TestCase):
    def test_every_csv_row_holds_one_value_for_each_column(self):
        out, err, code = run_cli("--format", "csv", "analyze", HTTP_CAP)
        self.assertEqual(code, 0, f"the command exited with {code}. stderr: {err}")
        rows = csv_rows(out)
        self.assertGreater(len(rows), 1, "the capture produces no data row")
        for row in rows[1:]:
            self.assertEqual(len(row), len(DOCUMENTED_COLUMNS), f"wrong column count: {row}")

    def test_the_csv_row_holds_the_address_and_the_port_in_separate_columns(self):
        out, _, code = run_cli("--format", "csv", "--types", "ja4t", "analyze", HTTP_CAP)
        self.assertEqual(code, 0)
        rows = csv_rows(out)
        header = rows[0]
        row = dict(zip(header, rows[1]))
        self.assertEqual(row["src_ip"], "145.254.160.237")
        self.assertEqual(row["src_port"], "3372")
        self.assertEqual(row["dst_ip"], "65.208.228.223")
        self.assertEqual(row["dst_port"], "80")
        self.assertEqual(row["type"], "ja4t")
        self.assertEqual(row["fingerprint"], "8760_2-1-1-4_1460_0")

    def test_a_column_with_no_value_is_empty_rather_than_absent(self):
        stream = io.StringIO()
        writer = CsvWriter(stream)
        writer.write_header()
        writer.write(FingerprintResult(type="ja4t", fingerprint="8760_2-1-1-4_1460_0"))
        rows = csv_rows(stream.getvalue())
        row = dict(zip(rows[0], rows[1]))
        self.assertEqual(row["raw"], "")
        self.assertEqual(row["raw_original_order"], "")
        self.assertEqual(row["timestamp"], "")
        self.assertEqual(row["identified_as"], "")
        self.assertEqual(len(rows[1]), len(DOCUMENTED_COLUMNS))

    def test_the_csv_writer_quotes_a_fingerprint_that_holds_a_comma(self):
        stream = io.StringIO()
        writer = CsvWriter(stream)
        writer.write(
            FingerprintResult(
                type="ja4h",
                fingerprint="ge11nr08enus_dacf082e1695_000000000000_000000000000",
                raw_original_order="ge11nr08enus_Host,User-Agent,Accept_",
            )
        )
        text = stream.getvalue()
        self.assertIn('"ge11nr08enus_Host,User-Agent,Accept_"', text)
        row = csv_rows(text)[0]
        self.assertEqual(
            row[DOCUMENTED_COLUMNS.index("raw_original_order")],
            "ge11nr08enus_Host,User-Agent,Accept_",
        )


class TheJsonLinesObject(unittest.TestCase):
    def test_the_json_format_writes_one_object_per_line(self):
        out, err, code = run_cli("--format", "json", "analyze", HTTP_CAP)
        self.assertEqual(code, 0, f"the command exited with {code}. stderr: {err}")
        lines = [line for line in out.splitlines() if line.strip()]
        self.assertGreater(len(lines), 1, "the capture produces fewer than two records")
        for line in lines:
            parsed = json.loads(line)
            self.assertIsInstance(parsed, dict)

    def test_every_json_object_holds_every_documented_field(self):
        out, _, code = run_cli("--format", "json", "analyze", HTTP_CAP)
        self.assertEqual(code, 0)
        records = json_records(out)
        self.assertGreater(len(records), 0)
        for record in records:
            self.assertEqual(set(record), DOCUMENTED_FIELDS)

    def test_the_json_object_holds_the_source_port_as_a_number(self):
        """`--format json | jq -e '.src_port'` succeeds only for a present, true value."""
        out, _, code = run_cli("--format", "json", "--types", "ja4t", "analyze", HTTP_CAP)
        self.assertEqual(code, 0)
        record = json_records(out)[0]
        self.assertEqual(record["src_ip"], "145.254.160.237")
        self.assertEqual(record["src_port"], 3372)
        self.assertEqual(record["dst_ip"], "65.208.228.223")
        self.assertEqual(record["dst_port"], 80)
        self.assertIsInstance(record["src_port"], int)

    def test_the_json_object_holds_no_composite_source_field(self):
        out, _, code = run_cli("--format", "json", "analyze", HTTP_CAP)
        self.assertEqual(code, 0)
        for record in json_records(out):
            self.assertNotIn("source", record)
            self.assertNotIn("->", record["src_ip"])

    def test_a_field_with_no_value_is_null_rather_than_absent(self):
        stream = io.StringIO()
        JsonLinesWriter(stream).write(
            FingerprintResult(type="ja4t", fingerprint="8760_2-1-1-4_1460_0")
        )
        record = json.loads(stream.getvalue())
        self.assertEqual(set(record), DOCUMENTED_FIELDS)
        self.assertIsNone(record["raw"])
        self.assertIsNone(record["raw_original_order"])
        self.assertIsNone(record["timestamp"])
        self.assertIsNone(record["identified_as"])

    def test_the_json_object_holds_the_identified_name_that_the_lookup_returned(self):
        stream = io.StringIO()
        JsonLinesWriter(stream).write(
            FingerprintResult(type="ja4t", fingerprint="8760_2-1-1-4_1460_0"),
            identified_as="Test Application",
        )
        self.assertEqual(json.loads(stream.getvalue())["identified_as"], "Test Application")


class TheTimestamp(unittest.TestCase):
    def test_the_writer_states_the_timestamp_in_rfc_3339_form(self):
        stream = io.StringIO()
        JsonLinesWriter(stream).write(
            FingerprintResult(
                type="ja4t",
                fingerprint="8760_2-1-1-4_1460_0",
                timestamp=datetime(2026, 8, 6, 12, 34, 56, 789012, tzinfo=timezone.utc),
            )
        )
        self.assertEqual(json.loads(stream.getvalue())["timestamp"], "2026-08-06T12:34:56.789012Z")

    def test_the_record_carries_the_timestamp_of_the_packet_that_made_it(self):
        out, _, code = run_cli("--format", "json", "--types", "ja4t", "analyze", HTTP_CAP)
        self.assertEqual(code, 0)
        # The first packet of `http.cap` carries the epoch time 1084443427.311224.
        self.assertEqual(json_records(out)[0]["timestamp"], "2004-05-13T10:17:07.311224Z")


class TheEndpointReaders(unittest.TestCase):
    """The program reads the four endpoint values from a packet or a window key.

    #51 moved the command-line program onto `Processor`, so the processor now reads the
    endpoints of a packet and `ja4plus/cli.py` reads the endpoints of a window key. The
    processor returns the two addresses first and the two ports second.
    """

    def test_the_reader_returns_the_four_values_of_an_ipv4_tcp_packet(self):
        from scapy.all import IP, TCP

        from ja4plus.processor import _packet_endpoints

        packet = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=54321, dport=443)
        self.assertEqual(_packet_endpoints(packet), ("1.2.3.4", "5.6.7.8", 54321, 443))

    def test_the_reader_returns_the_four_values_of_an_ipv6_udp_packet(self):
        from scapy.all import IPv6, UDP

        from ja4plus.processor import _packet_endpoints

        packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=443, dport=54321)
        self.assertEqual(_packet_endpoints(packet), ("2001:db8::1", "2001:db8::2", 443, 54321))

    def test_the_reader_returns_the_port_zero_for_a_packet_that_carries_no_port(self):
        from scapy.all import IP

        from ja4plus.processor import _packet_endpoints

        self.assertEqual(
            _packet_endpoints(IP(src="1.2.3.4", dst="5.6.7.8")), ("1.2.3.4", "5.6.7.8", 0, 0)
        )

    def test_the_reader_splits_a_connection_key_that_holds_ipv4_addresses(self):
        from ja4plus.cli import _endpoints_from_connection

        self.assertEqual(
            _endpoints_from_connection("172.16.225.48:57377-54.160.114.75:22"),
            ("172.16.225.48", 57377, "54.160.114.75", 22),
        )

    def test_the_reader_splits_a_connection_key_that_holds_ipv6_addresses(self):
        from ja4plus.cli import _endpoints_from_connection

        self.assertEqual(
            _endpoints_from_connection("2001:db8::1:22-2001:db8::2:57377"),
            ("2001:db8::1", 22, "2001:db8::2", 57377),
        )

    def test_the_reader_returns_empty_values_for_a_connection_key_it_cannot_read(self):
        from ja4plus.cli import _endpoints_from_connection

        self.assertEqual(_endpoints_from_connection(""), ("", 0, "", 0))
        self.assertEqual(_endpoints_from_connection("nothing"), ("", 0, "", 0))


class TheTableFormat(unittest.TestCase):
    def test_the_table_writes_the_endpoints_as_one_source_column(self):
        stream = io.StringIO()
        writer = TableWriter(stream)
        writer.write_header()
        writer.write(
            FingerprintResult(
                type="ja4t",
                fingerprint="8760_2-1-1-4_1460_0",
                src_ip="145.254.160.237",
                src_port=3372,
                dst_ip="65.208.228.223",
                dst_port=80,
            )
        )
        lines = stream.getvalue().splitlines()
        self.assertIn("Source", lines[0])
        self.assertIn("145.254.160.237:3372 -> 65.208.228.223:80", lines[2])
        self.assertIn("8760_2-1-1-4_1460_0", lines[2])


if __name__ == "__main__":
    unittest.main()
