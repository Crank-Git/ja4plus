"""The command prints the address pair of every window the packet source leaves open.

#742 measured the defect. `ja4plus analyze tests/foxio_vectors/tls3.pcapng` printed
`unknown` in place of the address pair for the value `JA4L-S=3583_57_quic`, and 22 values
of the committed captures printed that word.

**Every guard that stood when the defect shipped read a fingerprint entry, and no guard
read a printed line.** The entry of `JA4LFingerprinter` carries the four endpoint fields,
so a reader of the entry sees a correct address pair. The loss happens between the entry
and the line. `Processor.close_open_windows` dropped the four fields, and the command then
read the endpoints back from the connection key. The conformance suite compares the value
at the key `tls3.pcapng/25:61884/JA4L-S.1` and it reads no line of the command. It
therefore reported 1684 passed with the defect live, and the cases below read the printed
line.

The captures of `CAPTURES_THAT_HOLD_A_WINDOW` are the committed captures that publish a
value from `close_open_windows`. A census of 2026-08-16 read 28 such values: 22 from JA4L
and 6 from JA4SSH. The 22 are the count the register row of #606 states.
"""

import io
import os
import sys
import unittest
from unittest.mock import patch

VECTOR_DIR = os.path.join(os.path.dirname(__file__), "foxio_vectors")

# The committed captures that leave a window open, with the count of values each one
# publishes from `close_open_windows`. The census of 2026-08-16 measured every capture of
# `tests/foxio_vectors/` and found these eight.
CAPTURES_THAT_HOLD_A_WINDOW = {
    "ssh-scp-1050.pcap": 1,
    "ssh.pcapng": 1,
    "ssh2-malformed.pcap": 1,
    "ssh2-moloch-crash.pcap": 1,
    "ssh2.pcapng": 2,
    "tcpdump-geneve.pcap": 1,
    "tls-handshake.pcapng": 20,
    "tls3.pcapng": 1,
}

# The count of values the eight captures publish. 22 belong to JA4L and 6 belong to
# JA4SSH.
CLOSED_WINDOW_VALUE_COUNT = 28

# The line of `tls3.pcapng` that #742 measured, and the address pair it must carry.
TLS3_QUIC_SERVER_VALUE = "JA4L-S=3583_57_quic"
TLS3_QUIC_SERVER_PAIR = "104.21.234.234:443 -> 192.168.1.169:61884"


def run_analyze(capture):
    """Return the standard output that `ja4plus analyze` writes for one capture.

    The call runs the command in this process, because a subprocess costs an interpreter
    start for each capture and reads the same code.

    Args:
        capture: The file name of a capture of `tests/foxio_vectors/`.

    Returns:
        The standard output of the run, as one string.
    """
    from ja4plus.cli import main

    captured_out = io.StringIO()
    captured_err = io.StringIO()
    argv = ["ja4plus", "analyze", os.path.join(VECTOR_DIR, capture)]
    with patch.object(sys, "argv", argv):
        with patch.object(sys, "stdout", captured_out):
            with patch.object(sys, "stderr", captured_err):
                try:
                    main()
                except SystemExit as end:
                    assert end.code in (None, 0), captured_err.getvalue()
    return captured_out.getvalue()


def closed_window_entries(capture):
    """Return every entry that `close_open_windows` publishes for one capture.

    Args:
        capture: The file name of a capture of `tests/foxio_vectors/`.

    Returns:
        The list of result dicts the processor returns after it reads every packet.
    """
    from scapy.utils import rdpcap

    from ja4plus import Processor

    processor = Processor()
    for packet in rdpcap(os.path.join(VECTOR_DIR, capture)):
        processor.process_packet(packet)
    return processor.close_open_windows()


class TheCommandPrintsAnAddressPairForEveryClosedWindow(unittest.TestCase):
    """#742 — the printed line carries the address pair, and never the word `unknown`."""

    def test_the_command_prints_the_address_pair_of_the_quic_server_value_of_tls3(self):
        lines = [
            line
            for line in run_analyze("tls3.pcapng").splitlines()
            if TLS3_QUIC_SERVER_VALUE in line
        ]
        self.assertEqual(len(lines), 1, lines)
        self.assertTrue(
            lines[0].startswith(TLS3_QUIC_SERVER_PAIR),
            f"the line reads {lines[0]!r} and it must start with {TLS3_QUIC_SERVER_PAIR!r}",
        )

    def test_no_capture_that_holds_an_open_window_prints_unknown(self):
        for capture in sorted(CAPTURES_THAT_HOLD_A_WINDOW):
            with self.subTest(capture=capture):
                unknown = [
                    line for line in run_analyze(capture).splitlines() if line.startswith("unknown")
                ]
                self.assertEqual(unknown, [], f"{capture} prints {len(unknown)} lines of unknown")

    def test_the_eight_captures_publish_the_count_of_values_the_census_measured(self):
        counted = {
            capture: len(closed_window_entries(capture))
            for capture in sorted(CAPTURES_THAT_HOLD_A_WINDOW)
        }
        self.assertEqual(counted, CAPTURES_THAT_HOLD_A_WINDOW)
        self.assertEqual(sum(counted.values()), CLOSED_WINDOW_VALUE_COUNT)


class TheProcessorCarriesTheEndpointsOfTheEntry(unittest.TestCase):
    """The result of `close_open_windows` holds the four endpoint fields of the entry."""

    def test_the_quic_server_value_of_tls3_carries_the_four_endpoint_fields(self):
        entries = closed_window_entries("tls3.pcapng")
        self.assertEqual(len(entries), 1, entries)
        entry = entries[0]
        self.assertEqual(entry["src"], "104.21.234.234")
        self.assertEqual(entry["srcport"], 443)
        self.assertEqual(entry["dst"], "192.168.1.169")
        self.assertEqual(entry["dstport"], 61884)

    def test_a_ja4ssh_window_carries_no_endpoint_field_and_carries_the_key(self):
        entries = closed_window_entries("ssh.pcapng")
        self.assertEqual(len(entries), 1, entries)
        entry = entries[0]
        self.assertEqual(entry["type"], "ja4ssh")
        self.assertEqual(entry["connection"], "172.16.225.48:57377-54.160.114.75:22")
        # The fallback exists for this entry. `JA4SSHFingerprinter._close_window` writes
        # no endpoint field, so the key is the one source the command holds.
        self.assertIsNone(entry["src"])
        self.assertIsNone(entry["srcport"])


class TheKeyParseReadsEveryFormAFingerprinterWrites(unittest.TestCase):
    """The fallback reads both key forms, because the two fingerprinters disagree."""

    def test_the_parse_reads_the_hyphen_form_that_ja4ssh_writes(self):
        from ja4plus.cli import _endpoints_from_connection

        self.assertEqual(
            _endpoints_from_connection("172.16.225.48:57377-54.160.114.75:22"),
            ("172.16.225.48", 57377, "54.160.114.75", 22),
        )

    def test_the_parse_reads_the_underscore_form_that_ja4l_writes(self):
        from ja4plus.cli import _endpoints_from_connection

        self.assertEqual(
            _endpoints_from_connection("udp_104.21.234.234:443_192.168.1.169:61884"),
            ("104.21.234.234", 443, "192.168.1.169", 61884),
        )

    def test_the_parse_reads_an_ipv6_pair_of_the_underscore_form(self):
        from ja4plus.cli import _endpoints_from_connection

        # An IPv6 address holds a colon and no underscore, so the two separators of the
        # underscore form still name the two halves.
        self.assertEqual(
            _endpoints_from_connection("udp_2001:db8::1:443_2001:db8::2:61884"),
            ("2001:db8::1", 443, "2001:db8::2", 61884),
        )

    def test_the_parse_returns_empty_values_for_a_key_of_neither_form(self):
        from ja4plus.cli import _endpoints_from_connection

        self.assertEqual(_endpoints_from_connection("no separator here"), ("", 0, "", 0))


class TheDocstringsNameNoSingleMethodThatHoldsAWindow(unittest.TestCase):
    """#606 ended the premise that JA4SSH is the one method that holds a window.

    `JA4LFingerprinter.close_open_windows` publishes the QUIC server value of every
    connection that never fills point `D`. A reader who trusts the older sentence reads
    the JA4L path as dead code.
    """

    def test_the_command_docstring_names_ja4l_beside_ja4ssh(self):
        from ja4plus.cli import _close_open_windows

        text = _close_open_windows.__doc__ or ""
        self.assertNotIn("JA4SSH is the only method", text)
        self.assertNotIn("JA4SSH is the one method", text)
        self.assertIn("JA4L", text)

    def test_the_processor_docstring_names_ja4l_beside_ja4ssh(self):
        from ja4plus.processor import Processor

        text = Processor.close_open_windows.__doc__ or ""
        self.assertNotIn("JA4SSH is the only method", text)
        self.assertNotIn("JA4SSH is the one method", text)
        self.assertIn("JA4L", text)


if __name__ == "__main__":
    unittest.main()
