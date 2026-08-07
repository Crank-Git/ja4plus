"""JA4H builds both cookie hashes from one ordered cookie list.

The tests cover two requirements of `docs/specs/features/02-correctness-audit.md`:

- FR-correctness-audit-6 — JA4H builds both cookie hashes from the same list of cookies.
- FR-correctness-audit-7 — JA4H keeps every occurrence of a repeated cookie name.
"""

import hashlib

from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4h import (
    _convert_parsed_to_extract_format,
    _extract_http_info_from_bytes,
    _generate_ja4h_from_info,
    _generate_ja4h_raw_from_info,
    generate_ja4h,
)
from ja4plus.utils.http_utils import extract_http_info, parse_http_request


def _request(request_line, cookie_header=None):
    """Return the bytes of one HTTP request.

    Args:
        request_line: The first line of the request, without the line terminator.
        cookie_header: The value of the Cookie header, or None for a request that
            carries no cookie.

    Returns:
        The complete request, with the empty line that ends the headers.
    """
    lines = [request_line, "Host: example.com"]
    if cookie_header is not None:
        lines.append("Cookie: {}".format(cookie_header))
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def _packet(data):
    """Return one TCP packet that carries the given payload."""
    return IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80) / Raw(load=data)


def _hash(text):
    """Return the 12-character JA4H hash of the given hash input string."""
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def test_a_repeated_cookie_name_reaches_both_cookie_hashes():
    """A request with two cookies named `a` hashes two cookies into part c and part d."""
    info = _extract_http_info_from_bytes(_request("GET / HTTP/1.1", "a=1; a=2"))

    fingerprint = _generate_ja4h_from_info(info)

    assert fingerprint is not None
    part_c, part_d = fingerprint.split("_")[2:4]
    assert part_c == _hash("a,a")
    assert part_d == _hash("a=1,a=2")


def test_a_repeated_cookie_name_reaches_both_hashes_of_the_packet_path():
    """The packet path keeps a repeated cookie name in part c and in part d."""
    fingerprint = generate_ja4h(_packet(_request("GET / HTTP/1.1", "a=1; a=2")))

    assert fingerprint is not None
    part_c, part_d = fingerprint.split("_")[2:4]
    assert part_c == _hash("a,a")
    assert part_d == _hash("a=1,a=2")


def test_the_cookie_value_hash_reads_the_same_cookie_list_as_the_raw_form():
    """Part d hashes the cookie pairs that the raw original-order form lists."""
    info = _extract_http_info_from_bytes(_request("GET / HTTP/1.1", "b=2; a=1; b=3"))

    fingerprint = _generate_ja4h_from_info(info)
    raw = _generate_ja4h_raw_from_info(info)

    assert raw.endswith("_b,a,b_b=2,a=1,b=3")
    assert fingerprint.split("_")[3] == _hash("a=1,b=2,b=3")


def test_a_request_line_without_a_minor_version_produces_the_version_code_20():
    """The request line `GET / HTTP/2` produces a fingerprint whose version code is 20."""
    info = _extract_http_info_from_bytes(_request("GET / HTTP/2"))

    fingerprint = _generate_ja4h_from_info(info)

    assert fingerprint is not None
    assert fingerprint[2:4] == "20"


def test_the_packet_path_reads_a_request_line_without_a_minor_version():
    """`extract_http_info` reads `GET / HTTP/2` and reports the version code 20."""
    fingerprint = generate_ja4h(_packet(_request("GET / HTTP/2")))

    assert fingerprint is not None
    assert fingerprint[2:4] == "20"


def test_a_request_line_that_names_no_version_produces_no_fingerprint():
    """A malformed version token produces no fingerprint, not a fingerprint that collides.

    `HTTP/11` names no HTTP version. The parser that reads it as `HTTP/1` reports the
    version code `11`, which is the code of `HTTP/1.1`, and the two requests then carry
    one fingerprint. A request the parser cannot read produces nothing.
    """
    for request_line in ("GET / HTTP/11", "GET / HTTP/1", "GET / HTTP/23", "GET / HTTP/"):
        data = _request(request_line)
        assert _extract_http_info_from_bytes(data) is None, request_line
        assert generate_ja4h(_packet(data)) is None, request_line


def test_a_request_line_with_a_minor_version_keeps_its_version_code():
    """The request line `GET / HTTP/1.1` still produces the version code 11."""
    assert generate_ja4h(_packet(_request("GET / HTTP/1.1")))[2:4] == "11"


def test_the_parsed_request_path_keeps_a_repeated_cookie_name():
    """`_convert_parsed_to_extract_format` keeps both cookies that carry the name `a`."""
    parsed = parse_http_request(_request("GET / HTTP/1.1", "a=1; a=2"))

    info = _convert_parsed_to_extract_format(parsed)

    assert info["cookie_fields"] == ["a", "a"]
    assert info["cookie_values"] == ["1", "2"]


def test_a_cookie_header_with_no_repeated_name_keeps_its_fingerprint():
    """A request whose cookie names are unique produces the hashes it produced before."""
    fingerprint = generate_ja4h(_packet(_request("GET / HTTP/1.1", "tasty=b; yummy=a")))

    part_c, part_d = fingerprint.split("_")[2:4]
    assert part_c == _hash("tasty,yummy")
    assert part_d == _hash("tasty=b,yummy=a")


def test_the_packet_path_and_the_stream_path_report_the_same_cookie_list():
    """`extract_http_info` and `_extract_http_info_from_bytes` read one cookie list."""
    data = _request("GET / HTTP/1.1", "a=1; a=2; b=3")

    from_packet = extract_http_info(_packet(data))
    from_bytes = _extract_http_info_from_bytes(data)

    assert from_packet["cookie_fields"] == from_bytes["cookie_fields"] == ["a", "a", "b"]
    assert from_packet["cookie_values"] == from_bytes["cookie_values"] == ["1", "2", "3"]
