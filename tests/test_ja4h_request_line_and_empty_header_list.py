"""Tests for the request-line pattern and for the empty header list of JA4H.

The maintainer ruled two rules on 2026-08-14, and #612 records both.

Rule 1 is the request line. `REQUEST_LINE_PATTERN` read the path with `(\\S+)`, which
matches no path that holds a space. Frame 4 of `gre-erspan-vxlan.pcap` holds
`GET /Hello Arkime HTTP/1.0`, so the request reached no JA4H value. The same reading
found two further defects of that pattern, which the second comment of #612 records.

Rule 2 is the empty header list. Part b substituted the zero sentinel `000000000000`
where the header string is empty, and it hashes that string instead. R18 of the JA4H
image is a rank 1 rule and it names no sentinel. R27 confines the sentinel to part c and
part d.

The two rules land together. A repair of rule 1 alone produces
`ge10nn000000_000000000000_000000000000_000000000000` for frame 4, against the reference
value below.
"""

import time

from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
from ja4plus.utils.http_utils import is_http_request, parse_http_request

# The reference value of frame 4 of `gre-erspan-vxlan.pcap`. The FoxIO Wireshark
# dissector wrote it, and `tests/foxio_vectors/wireshark_expected/gre-erspan-vxlan.pcap.json`
# holds it.
FRAME_4_REQUEST = b"GET /Hello Arkime HTTP/1.0\r\n\r\n"
FRAME_4_JA4H = "ge10nn000000_e3b0c44298fc_000000000000_000000000000"

# The SHA-256 of the empty string, truncated to 12 hexadecimal characters. Part b of an
# empty header list reads this value.
EMPTY_HASH = "e3b0c44298fc"


def _ja4h(request: bytes) -> str | None:
    """Return the JA4H value of one request that one TCP segment carries.

    Args:
        request: The bytes of the request, terminator included.

    Returns:
        The JA4H value, or None where the fingerprinter produces none.
    """
    packet = (
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=100) / Raw(load=request)
    )
    return JA4HFingerprinter().process_packet(packet)


def test_reads_a_request_path_that_holds_a_space():
    parsed = parse_http_request(FRAME_4_REQUEST)
    assert parsed is not None
    assert parsed["path"] == "/Hello Arkime"
    assert parsed["method"] == "GET"
    assert parsed["version"] == "HTTP/1.0"


def test_reads_no_request_line_that_spans_two_lines():
    """A separator reads a space or a horizontal tab, and never a line ending.

    `\\s` matches a line feed, so the match crossed into the second line and read a
    request line that no line holds. `is_http_request` gates a JA4L measurement point, so
    the match moved a JA4L value.
    """
    payload = b"SSH-2.0-OpenSSH_9.6\r\n/a HTTP/1.1\r\n"
    assert is_http_request(payload) is False
    assert parse_http_request(payload) is None


def test_reads_no_path_that_holds_a_carriage_return():
    """The path group reads no carriage return, so rule 1 opens no new hole.

    A group of any character matches a bare carriage return, and the path then holds two
    lines of the payload. The non-space group read no such path, and this case keeps that
    reading. `is_http_request` admits every payload that starts with one of the nine
    method tokens, so it reads this payload whatever the pattern holds, and #219 records
    that ruling.
    """
    payload = b"GET /a\rFAKE HTTP/1.1\r\nReal: 1\r\n\r\n"
    assert parse_http_request(payload) is None
    assert _ja4h(payload) is None


def test_reads_the_earlier_version_token_of_a_line_that_holds_two():
    """The path group is lazy, so the match reads the first version token.

    The non-space group read the earlier token, and this case holds that reading.
    """
    parsed = parse_http_request(b"GET /a HTTP/1.1 HTTP/1.0\r\n\r\n")
    assert parsed is not None
    assert parsed["path"] == "/a"
    assert parsed["version"] == "HTTP/1.1"


def test_reads_a_line_of_spaces_that_holds_no_version_token_in_linear_time():
    """The pattern holds no unbounded backtracking on hostile input.

    A path group that accepts a leading space makes the two adjacent quantifiers
    ambiguous, and the match then costs the square of the line length. The path group
    reads a first character that is neither a space nor a horizontal tab, so one run of
    spaces admits one split. 3000 spaces cost about 9000000 steps under the ambiguous
    form, and they cost about 3000 under this one.
    """
    payload = b"GET" + b" " * 3000
    start = time.monotonic()
    assert parse_http_request(payload) is None
    assert time.monotonic() - start < 2.0


def test_hashes_an_empty_header_list():
    """Part b of a request that carries no header holds the hash of the empty string."""
    value = _ja4h(b"GET / HTTP/1.1\r\n\r\n")
    assert value is not None
    assert value.split("_")[1] == EMPTY_HASH


def test_writes_no_zero_sentinel_in_part_b():
    """R27 confines the zero sentinel to part c and to part d."""
    value = _ja4h(b"GET / HTTP/1.1\r\n\r\n")
    assert value is not None
    assert value.split("_")[1] != "000000000000"


def test_produces_the_reference_value_of_frame_4_of_the_gre_capture():
    """The two rules close one comparison of the shared FoxIO vector set."""
    assert _ja4h(FRAME_4_REQUEST) == FRAME_4_JA4H
