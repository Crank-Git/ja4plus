"""Tests for the header block terminator of an HTTP message.

The maintainer ruled on 2026-08-14, on `Crank-Git/ja4plus-go#298`, that the header block
terminator is one line ending followed by another line ending. A line ending is the two
bytes `\\r\\n`, or one line feed, which `LINE_ENDING_PATTERN` already states. The four
byte groups `\\r\\n\\r\\n`, `\\n\\n`, `\\n\\r\\n` and `\\r\\n\\n` therefore each end a
header block.

Two literals, `\\r\\n\\r\\n` and `\\n\\n`, held the rule before this change. A header block
that ends `\\n\\r\\n` matched neither one, so `header_block_end` reported no end and JA4H
produced no value. #614 records the defect.

No FoxIO vector carries a mixed line ending, so no reference value moves.
"""

from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
from ja4plus.utils.http_utils import header_block_end

# The head of one request. Each case below appends one terminator and one body byte, so
# the expected end offset is the length of the head plus the length of the terminator.
HEAD = b"GET / HTTP/1.1\r\nHost: example.com"
BODY = b"BODY"


def test_reads_a_header_block_that_ends_with_two_carriage_return_line_feed_pairs():
    data = HEAD + b"\r\n\r\n" + BODY
    assert header_block_end(data) == len(HEAD) + 4


def test_reads_a_header_block_that_ends_with_two_line_feeds():
    data = HEAD + b"\n\n" + BODY
    assert header_block_end(data) == len(HEAD) + 2


def test_reads_a_header_block_that_ends_with_a_line_feed_and_a_pair():
    data = HEAD + b"\n\r\n" + BODY
    assert header_block_end(data) == len(HEAD) + 3


def test_reads_a_header_block_that_ends_with_a_pair_and_a_line_feed():
    """The end offset lies past the whole terminator, and not past part of it.

    The `\\n\\n` literal matched the last two bytes of `\\r\\n\\n`, which starts one byte
    into the terminator. That match reported the same end offset by coincidence. This case
    holds the offset so that a later reader keeps it.
    """
    data = HEAD + b"\r\n\n" + BODY
    assert header_block_end(data) == len(HEAD) + 3


def test_reports_no_end_for_bytes_that_hold_no_complete_header_block():
    assert header_block_end(HEAD + b"\r\n") is None


def test_reports_the_end_of_the_first_terminator_the_bytes_hold():
    """A body that holds a second terminator moves no end offset.

    The `\\r\\n\\r\\n` literal reported the end of a later terminator, because the earlier
    `\\n\\r\\n` matched neither literal.
    """
    data = HEAD + b"\n\r\n" + BODY + b"\r\n\r\n"
    assert header_block_end(data) == len(HEAD) + 3


def test_ja4h_produces_a_value_for_a_request_that_ends_with_a_line_feed_and_a_pair():
    """The repair reaches the fingerprinter, and not the reader alone."""
    request = b"GET / HTTP/1.1\nHost: example.com\nUser-Agent: probe\n\r\n"
    packet = (
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=100) / Raw(load=request)
    )
    fingerprinter = JA4HFingerprinter()
    assert fingerprinter.process_packet(packet) is not None
