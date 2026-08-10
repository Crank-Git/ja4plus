"""JA4H tests for a request that ends every line with one line feed.

`technical_details/JA4H.md` states that JA4H fingerprints the HTTP client "based on each
HTTP request", and it names no line ending. `tests/foxio_vectors/http-empty-useragent.pcap`
holds a request whose lines end with one line feed, and the FoxIO expected-output file
holds a JA4H value for it.

The parser read the two bytes `\\r\\n` as the only line ending, so it read the whole
request as one line and produced nothing. #193 records the defect.
"""

from pathlib import Path

import pytest
from scapy.all import IP, TCP, Raw, rdpcap

from ja4plus.fingerprinters.ja4h import JA4HFingerprinter, _extract_http_info_from_bytes
from ja4plus.utils.http_utils import extract_http_info, parse_http_request

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"

# The values `tests/foxio_vectors/http-empty-useragent.pcap.json` holds for stream 0.
EXPECTED_JA4H = "ge10nn010000_b8bcd45ac095_000000000000_000000000000"
EXPECTED_JA4H_RO = "ge10nn010000_User-Agent_"

# The request the capture carries. Every line ends with one line feed, and the
# `User-Agent` header carries no value.
LINE_FEED_REQUEST = b"GET / HTTP/1.0\nUser-Agent:\n\n"


@pytest.fixture(scope="module")
def empty_useragent_results():
    """Return the JA4H entries `http-empty-useragent.pcap` produces."""
    fingerprinter = JA4HFingerprinter()
    for packet in rdpcap(str(VECTORS_DIR / "http-empty-useragent.pcap")):
        fingerprinter.process_packet(packet)
    return fingerprinter.get_fingerprints()


def test_produces_one_ja4h_value_for_a_request_that_ends_each_line_with_a_line_feed(
    empty_useragent_results,
):
    assert len(empty_useragent_results) == 1


def test_the_line_feed_request_produces_the_reference_ja4h_value(empty_useragent_results):
    assert empty_useragent_results[0]["fingerprint"] == EXPECTED_JA4H


def test_the_line_feed_request_produces_the_reference_raw_original_order_value(
    empty_useragent_results,
):
    assert empty_useragent_results[0]["raw_original_order"] == EXPECTED_JA4H_RO


def test_counts_a_header_that_carries_no_value():
    """The reference counts `User-Agent:` as one header, so part a reads `01`."""
    info = _extract_http_info_from_bytes(LINE_FEED_REQUEST)
    assert info is not None
    assert info["headers"] == ["User-Agent"]


def test_the_packet_path_reads_a_line_feed_request():
    """The packet path and the stream path read one line ending rule.

    Changelog round 40 records three code paths that each build one JA4H value. A rule
    that reaches one path makes one request give a value on one path and none on another.
    """
    packet = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, seq=100)
        / Raw(load=LINE_FEED_REQUEST)
    )
    info = extract_http_info(packet)
    assert info is not None
    assert info["headers"] == ["User-Agent"]


def test_the_request_parser_reads_a_line_feed_request():
    """`parse_http_request` reads the same line ending rule as the other two paths."""
    parsed = parse_http_request(LINE_FEED_REQUEST)
    assert parsed is not None
    assert parsed["version"] == "HTTP/1.0"
    assert list(parsed["headers"]) == ["user-agent"]


def test_a_carriage_return_line_feed_request_still_reads_the_same_headers():
    """The repair adds a line ending and removes none."""
    request = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
    info = _extract_http_info_from_bytes(request)
    assert info is not None
    assert info["headers"] == ["Host", "Accept"]


def test_one_line_feed_ends_a_line_inside_a_header_value():
    """A line feed ends a line wherever it sits, which is the reading `tshark` holds.

    `tshark` reads the request below and reports one header line, `X-Data: line1\\n`. The
    FoxIO Python implementation reads the `tshark` fields, so that reading is the
    reference. The self-review of #193 measured it, and the measurement is recorded in
    `docs/implementation_notes.md`.
    """
    request = b"GET / HTTP/1.1\r\nX-Data: line1\n\nHost: example.com\r\nUser-Agent: probe\r\n\r\n"
    info = _extract_http_info_from_bytes(request)
    assert info is not None
    assert info["headers"] == ["X-Data"]
