"""Tests for the request-line pattern and for the empty header list of JA4H.

The maintainer ruled two rules on 2026-08-14, and #612 records both.

Rule 1 is the request line. `REQUEST_LINE_PATTERN` read the path with `(\\S+)`, which
matches no path that holds a space. Frame 4 of `gre-erspan-vxlan.pcap` holds
`GET /Hello Arkime HTTP/1.0`, so the request reached no JA4H value. The same reading
found two further defects of that pattern, which the second comment of #612 records.

Rule 2 is the empty header list. Part b substituted the zero sentinel `000000000000`
where the header string is empty, and it hashes that string instead. R12 of
`docs/specs/foxio/JA4H.md` is a rank 1 image rule, and it names no sentinel. R17 of that
page confines the sentinel to part c and part d. R19 holds the ruling of 2026-08-14.

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
    """The path group reads no carriage return, so rule 1 admits no such path.

    A group of any character matches a bare carriage return, and the path then holds two
    lines of the payload. The non-space group read no such path, and this case keeps that
    read. `is_http_request` admits every payload that starts with one of the nine method
    tokens. It reads this payload whatever the pattern holds, and #219 records that
    ruling.
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
    """A run of spaces after the method costs the line length and not its square.

    The greedy separator reads the whole run, and the path group then reads no first
    character. Each shorter separator fails at the same character.
    """
    payload = b"GET" + b" " * 3000
    start = time.monotonic()
    assert parse_http_request(payload) is None
    assert time.monotonic() - start < 2.0


def test_reads_a_line_that_almost_holds_a_version_token_in_linear_time():
    """A path, a run of spaces and a near version token cost the line length.

    This is the shape that the case above does not reach, and it is the one that costs
    the square of the line length under a path group that ends on a space. The lazy path
    body accepts a space and the greedy separator accepts a space, so a run of spaces
    admits one split for each space and `HTTPX` fails every one of them. A read of
    2026-08-15 puts this payload at 3017.9 milliseconds under that form and at 0.630
    milliseconds under this one, so the limit below separates the two by a factor above
    1000 in each direction.
    """
    payload = b"GET a" + b" " * 32000 + b"HTTPX"
    start = time.monotonic()
    assert parse_http_request(payload) is None
    assert time.monotonic() - start < 1.0


def test_reads_a_line_of_spaces_and_tabs_that_almost_holds_a_version_token_in_linear_time():
    """A separator of mixed spaces and tabs reaches the same bound.

    A rule that names the space alone leaves the tab, and the two characters carry one
    separator. A read of 2026-08-15 puts this payload at 3320.0 milliseconds under a path
    group that ends on a space, and at 0.593 milliseconds under this one.
    """
    payload = b"GET a" + b" \t" * 16000 + b"HTTP/x"
    start = time.monotonic()
    assert parse_http_request(payload) is None
    assert time.monotonic() - start < 1.0


def test_reads_a_path_that_ends_with_no_space():
    """The path holds every character between the two separators, and no separator.

    The rule that bounds the work reads the last character of the path, so a path of one
    character and a path that holds a space must both survive it.
    """
    for line, path in (
        (b"GET / HTTP/1.1\r\n\r\n", "/"),
        (b"GET /a b HTTP/1.1\r\n\r\n", "/a b"),
        (b"GET  /a  HTTP/1.1\r\n\r\n", "/a"),
        (b"GET /a\tb HTTP/1.1\r\n\r\n", "/a\tb"),
        (b"CONNECT example.com:443 HTTP/1.1\r\n\r\n", "example.com:443"),
    ):
        parsed = parse_http_request(line)
        assert parsed is not None, line
        assert parsed["path"] == path, line


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
