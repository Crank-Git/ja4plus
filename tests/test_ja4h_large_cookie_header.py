"""A large Cookie header produces a complete JA4H value.

The cookie list carries no maximum entry count and no maximum length. The user decided
that on 2026-08-08 in #175. The FoxIO reference caps nothing, the Go port caps nothing,
and no FoxIO vector reaches any candidate bound.

A bound merged as `be3604f` and reverted as `042e8c3`. Past the bound the cookie parse
produced no result, so the request produced no JA4H value at all. Part a and part b read
the method, the HTTP version, the header count, the `Accept-Language` value and the
header names. None of them reads a cookie, and all of them were lost.

Every case here holds a Cookie header past all three reverted bounds: 512 cookie pairs,
256 bytes of cookie name and 4096 bytes of cookie value.
"""

import hashlib

from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4h import (
    _convert_parsed_to_extract_format,
    _extract_http_info_from_bytes,
    generate_ja4h,
)
from ja4plus.utils.http_utils import extract_http_info, parse_http_request

# Each number passes the bound the reverted work held, so a rebuilt bound fails a case.
LARGE_PAIR_COUNT = 5000
LONG_NAME_BYTES = 1024
LONG_VALUE_BYTES = 8192


def _pairs(count):
    """Return the given number of cookie pairs, each with its own name.

    Args:
        count: The number of pairs.

    Returns:
        A list of `(name, value)` pairs in wire order.
    """
    return [("c{:05d}".format(index), "v{:05d}".format(index)) for index in range(count)]


def _request(pairs):
    """Return the bytes of one HTTP request that carries the given cookie pairs.

    Args:
        pairs: The `(name, value)` pairs the Cookie header holds, in wire order.

    Returns:
        The complete request, with the empty line that ends the headers.
    """
    header = "; ".join("{}={}".format(name, value) for name, value in pairs)
    lines = ["GET / HTTP/1.1", "Host: example.com", "Cookie: {}".format(header)]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def _packet(data):
    """Return one TCP packet that carries the given payload."""
    return IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80) / Raw(load=data)


def _hash(text):
    """Return the 12-character JA4H hash of the given hash input string."""
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def _expected_cookie_hashes(pairs):
    """Return the part c and the part d that the given cookie pairs produce.

    Args:
        pairs: The `(name, value)` pairs in wire order.

    Returns:
        The cookie-name hash and the cookie-value hash, as a pair of strings.
    """
    part_c = _hash(",".join(sorted(name for name, _ in pairs)))
    sorted_pairs = sorted(pairs, key=lambda pair: pair[0])
    part_d = _hash(",".join("{}={}".format(name, value) for name, value in sorted_pairs))
    return part_c, part_d


def test_a_cookie_header_of_5000_pairs_produces_a_complete_ja4h_value():
    """A request with 5000 cookie pairs produces parts a, b, c and d."""
    pairs = _pairs(LARGE_PAIR_COUNT)

    fingerprint = generate_ja4h(_packet(_request(pairs)))

    assert fingerprint is not None
    part_a, part_b, part_c, part_d = fingerprint.split("_")
    assert part_a == "ge11cn010000"
    assert part_b == _hash("Host")
    assert (part_c, part_d) == _expected_cookie_hashes(pairs)


def test_a_cookie_header_of_5000_pairs_keeps_the_parts_that_read_no_cookie():
    """Part a and part b of a large Cookie header equal those of a one-cookie request."""
    large = generate_ja4h(_packet(_request(_pairs(LARGE_PAIR_COUNT))))
    small = generate_ja4h(_packet(_request(_pairs(1))))

    assert large is not None
    assert small is not None
    assert large.split("_")[:2] == small.split("_")[:2]


def test_a_1024_byte_cookie_name_reaches_both_cookie_hashes():
    """A cookie name of 1024 bytes reaches part c and part d of the JA4H value.

    A parser that refuses the name produces no JA4H value. A parser that shortens the
    name to 256 bytes produces two hashes that this case does not expect.
    """
    pairs = [("n" * LONG_NAME_BYTES, "1")]

    fingerprint = generate_ja4h(_packet(_request(pairs)))

    assert fingerprint is not None
    part_c, part_d = fingerprint.split("_")[2:4]
    assert (part_c, part_d) == _expected_cookie_hashes(pairs)


def test_a_8192_byte_cookie_value_reaches_both_cookie_hashes():
    """A cookie value of 8192 bytes reaches part c and part d of the JA4H value.

    A parser that refuses the value produces no JA4H value. A parser that shortens the
    value to 4096 bytes produces a part d that this case does not expect.
    """
    pairs = [("a", "v" * LONG_VALUE_BYTES)]

    fingerprint = generate_ja4h(_packet(_request(pairs)))

    assert fingerprint is not None
    part_c, part_d = fingerprint.split("_")[2:4]
    assert (part_c, part_d) == _expected_cookie_hashes(pairs)


def test_every_parser_site_reads_all_5000_pairs_of_a_large_cookie_header():
    """The three parser sites each report 5000 cookie pairs.

    `parse_http_request` and `extract_http_info` sit in `ja4plus/utils/http_utils.py`.
    `_extract_http_info_from_bytes` sits in `ja4plus/fingerprinters/ja4h.py`, and the
    JA4H reassembled-stream path reads it.
    """
    pairs = _pairs(LARGE_PAIR_COUNT)
    data = _request(pairs)
    names = [name for name, _ in pairs]
    values = [value for _, value in pairs]

    from_parse = _convert_parsed_to_extract_format(parse_http_request(data))
    from_packet = extract_http_info(_packet(data))
    from_bytes = _extract_http_info_from_bytes(data)

    for site in (from_parse, from_packet, from_bytes):
        assert site is not None
        assert site["cookie_fields"] == names
        assert site["cookie_values"] == values
