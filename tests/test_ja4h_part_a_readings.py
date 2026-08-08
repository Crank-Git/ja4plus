"""JA4H tests for the four part-a readings the user decided on 2026-08-08.

`docs/specs/foxio/JA4H.md` transcribes `technical_details/JA4H.png` and measures four
readings where this project disagreed with every FoxIO reference. #219 holds the four
decisions.

- D1. R3 states that field a1 is the first two characters of the method.
  `http_utils.py` named nine methods and produced no JA4H value for any other.
- D2. R5 states that field a3 reads the Cookie header. `ja4h.py` read the parsed cookie
  list, so a Cookie header whose value holds no `=` wrote `n`.
- D3. R6 states that field a4 reads the Referer header. `ja4h.py` read the header value,
  so an empty Referer value wrote `n`.
- D4. R9 states that field a5 counts the list part b hashes. `ja4h.py` counted a header
  whose name is empty, and part b dropped it.

No FoxIO vector reaches any of the four readings, so every case here is constructed. The
conformance suite proves that no vector value moves.
"""

import hashlib

import pytest
from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4h import (
    JA4HFingerprinter,
    _extract_http_info_from_bytes,
    _generate_ja4h_from_info,
)
from ja4plus.utils.http_utils import extract_http_info, is_http_request, parse_http_request

# The first 12 characters of the SHA-256 of the one header name `Host`.
HOST_HASH = hashlib.sha256(b"Host").hexdigest()[:12]
NO_COOKIE = "000000000000"


def _packet(data):
    """Return one TCP packet that carries the given bytes."""
    return IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80, seq=1) / Raw(load=data)


def _from_stream(data):
    """Return the JA4H value the reassembly parse path produces."""
    info = _extract_http_info_from_bytes(data)
    return None if info is None else _generate_ja4h_from_info(info)


def _from_packet(data):
    """Return the JA4H value the single-packet parse path produces."""
    info = extract_http_info(_packet(data))
    return None if info is None else _generate_ja4h_from_info(info)


def _from_processor(data):
    """Return the JA4H entry the fingerprinter records for one packet."""
    fingerprinter = JA4HFingerprinter()
    fingerprinter.process_packet(_packet(data))
    entries = fingerprinter.get_fingerprints()
    return entries[0] if entries else None


# Each request carries a `Host` header, so part b hashes one name and the expected value
# names `HOST_HASH`. Nothing else in the request reaches part b, part c or part d.
VALUELESS_COOKIE = b"GET / HTTP/1.1\r\nHost: a\r\nCookie: sessionid\r\n\r\n"
EMPTY_REFERER = b"GET / HTTP/1.1\r\nHost: a\r\nReferer: \r\n\r\n"
EMPTY_HEADER_NAME = b"GET / HTTP/1.1\r\nHost: a\r\n : b\r\n\r\n"
PROPFIND = b"PROPFIND / HTTP/1.1\r\nHost: a\r\n\r\n"

PARSE_PATHS = pytest.mark.parametrize("parse", [_from_stream, _from_packet])


# D2 — field a3 reads the Cookie header.


@PARSE_PATHS
def test_writes_c_for_a_cookie_header_whose_value_holds_no_pair(parse):
    """R5. A Cookie header writes `c`, whatever the header value holds."""
    assert parse(VALUELESS_COOKIE) == "ge11cn010000_{}_{}_{}".format(
        HOST_HASH, NO_COOKIE, NO_COOKIE
    )


def test_the_processor_writes_c_for_a_cookie_header_whose_value_holds_no_pair():
    entry = _from_processor(VALUELESS_COOKIE)
    assert entry is not None
    assert entry["fingerprint"][4] == "c"


@PARSE_PATHS
def test_writes_n_when_the_request_carries_no_cookie_header(parse):
    """R5. The flag is `n` when the request carries no Cookie header."""
    assert parse(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")[4] == "n"


@PARSE_PATHS
def test_a_valueless_cookie_header_leaves_part_c_and_part_d_at_twelve_zeros(parse):
    """R17. The header carries no cookie pair, so part c and part d write 12 zeros.

    The decision moves field a3 alone. This case holds part c and part d still.
    """
    parts = parse(VALUELESS_COOKIE).split("_")
    assert parts[2] == NO_COOKIE
    assert parts[3] == NO_COOKIE


# D3 — field a4 reads the Referer header.


@PARSE_PATHS
def test_writes_r_for_a_referer_header_that_carries_an_empty_value(parse):
    """R6. A Referer header writes `r`, whatever the header value holds."""
    assert parse(EMPTY_REFERER) == "ge11nr010000_{}_{}_{}".format(HOST_HASH, NO_COOKIE, NO_COOKIE)


def test_the_processor_writes_r_for_a_referer_header_that_carries_an_empty_value():
    entry = _from_processor(EMPTY_REFERER)
    assert entry is not None
    assert entry["fingerprint"][5] == "r"


@PARSE_PATHS
def test_writes_n_when_the_request_carries_no_referer_header(parse):
    """R6. The flag is `n` when the request carries no Referer header."""
    assert parse(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")[5] == "n"


@PARSE_PATHS
def test_reads_the_referer_header_name_without_regard_to_its_case(parse):
    """R6. The reference reads the header name, and a header name is case-insensitive."""
    assert parse(b"GET / HTTP/1.1\r\nHost: a\r\nREFERER: \r\n\r\n")[5] == "r"


# D4 — field a5 counts the list part b hashes.


@PARSE_PATHS
def test_field_a5_omits_a_header_whose_name_is_empty(parse):
    """R9. Part b drops a header whose name is empty, so field a5 must drop it too."""
    assert parse(EMPTY_HEADER_NAME) == "ge11nn010000_{}_{}_{}".format(
        HOST_HASH, NO_COOKIE, NO_COOKIE
    )


def test_the_raw_original_order_form_names_as_many_headers_as_field_a5_counts():
    """R9. The count and the raw form read one list, so the reader can check the count."""
    entry = _from_processor(EMPTY_HEADER_NAME)
    assert entry is not None
    assert entry["fingerprint"][6:8] == "01"
    assert entry["raw_original_order"].split("_")[1] == "Host"


@PARSE_PATHS
def test_field_a5_counts_every_name_part_b_hashes(parse):
    """R9. Four headers reach part b, and field a5 reports `04`."""
    request = (
        b"GET / HTTP/1.1\r\nHost: a\r\nAccept: b\r\nUser-Agent: c\r\nAccept-Encoding: d\r\n"
        b"Cookie: x=1\r\nReferer: z\r\n : q\r\n\r\n"
    )
    names = b"Host,Accept,User-Agent,Accept-Encoding"
    value = parse(request)
    assert value[6:8] == "04"
    assert value.split("_")[1] == hashlib.sha256(names).hexdigest()[:12]


@PARSE_PATHS
def test_field_a5_writes_99_for_a_request_that_carries_more_than_99_headers(parse):
    """R8. The count that reads the hashed list keeps the cap the reference applies.

    The repair of D4 rewrote the expression that holds the cap, and no case held it.
    """
    headers = b"".join(b"H%d: v\r\n" % index for index in range(120))
    assert parse(b"GET / HTTP/1.1\r\n" + headers + b"\r\n")[6:8] == "99"


@PARSE_PATHS
def test_field_a5_writes_the_exact_count_below_the_cap(parse):
    """R7. 99 headers write `99`, and the cap does not hide a wrong count."""
    headers = b"".join(b"H%d: v\r\n" % index for index in range(98))
    assert parse(b"GET / HTTP/1.1\r\n" + headers + b"\r\n")[6:8] == "98"


# D1 — field a1 reads the first two characters of any method.


@PARSE_PATHS
def test_reads_a_method_the_nine_named_methods_omit(parse):
    """R3. `PROPFIND` writes the method code `pr`, as `python/ja4h.py:9` does."""
    assert parse(PROPFIND) == "pr11nn010000_{}_{}_{}".format(HOST_HASH, NO_COOKIE, NO_COOKIE)


def test_the_processor_reads_a_method_the_nine_named_methods_omit():
    entry = _from_processor(PROPFIND)
    assert entry is not None
    assert entry["fingerprint"].startswith("pr11")


@pytest.mark.parametrize(
    "method,code",
    [
        (b"PROPFIND", "pr"),
        (b"MKCOL", "mk"),
        (b"LOCK", "lo"),
        (b"SEARCH", "se"),
        (b"M-SEARCH", "m-"),
        (b"BREW", "br"),
    ],
)
def test_the_method_code_is_the_first_two_characters_lowercased(method, code):
    """R3. The code is `method.lower()[:2]`, and the method list is open."""
    value = _from_stream(method + b" / HTTP/1.1\r\nHost: a\r\n\r\n")
    assert value is not None
    assert value[:2] == code


def test_parse_http_request_reads_a_method_the_nine_named_methods_omit():
    """The third parse path reads the same method list as the other two."""
    parsed = parse_http_request(PROPFIND)
    assert parsed is not None
    assert parsed["method"] == "PROPFIND"


def test_parse_http_request_refuses_a_token_that_names_no_http_version():
    """The third parse path reads the same version list as the other two.

    The path split the request line on one space and read no version, so `HTTP/11` wrote
    the version token `HTTP/11`. #35 records the defect for the other two paths.
    """
    assert parse_http_request(b"GET / HTTP/11\r\nHost: a\r\n\r\n") is None


def test_parse_http_request_reads_a_request_line_that_holds_two_spaces():
    """The path split on one space, so a second space wrote the path `` and the version `/`."""
    parsed = parse_http_request(b"GET  /  HTTP/1.1\r\nHost: a\r\n\r\n")
    assert parsed is not None
    assert parsed["path"] == "/"
    assert parsed["version"] == "HTTP/1.1"


def test_the_reassembly_gate_admits_a_method_the_nine_named_methods_omit():
    """`ja4h.py` reads a reassembled stream only when this gate admits it."""
    assert is_http_request(PROPFIND)


@pytest.mark.parametrize(
    "payload",
    [
        b"\x16\x03\x03",
        b"SSH-2.0-OpenSSH_9.6\r\n",
        b"random data",
        b"HTTP/1.1 200 OK\r\nHost: a\r\n\r\n",
    ],
)
def test_the_reassembly_gate_refuses_a_payload_that_holds_no_request_line(payload):
    """The open method list must not admit another protocol, or JA4L moves with it.

    `ja4l.py:365` reads this gate to decide whether a packet holds a whole HTTP request,
    and a payload it admits by mistake moves a JA4L measurement point.
    """
    assert not is_http_request(payload)


def test_the_reassembly_gate_reads_no_more_than_the_request_line_limit():
    """The gate reads 8192 leading bytes, so a long stream costs one bounded read.

    `ja4l.py:365` calls the gate for every TCP payload, and a stream buffer grows to
    1048576 bytes. Without the bound, 200 calls on a buffer of 1000003 bytes cost 9.2 ms.
    With it they cost 0.3 ms.
    """
    inside = b"PROPFIND /" + b"a" * 8000 + b" HTTP/1.1\r\nHost: a\r\n\r\n"
    past = b"PROPFIND /" + b"a" * 9000 + b" HTTP/1.1\r\nHost: a\r\n\r\n"
    assert is_http_request(inside)
    assert not is_http_request(past)


def test_a_request_split_across_two_segments_reads_a_method_the_nine_omit():
    """The reassembly path reads a method the nine omit, and not the packet path alone."""
    fingerprinter = JA4HFingerprinter()
    first = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80, seq=1) / Raw(load=b"PROPF")
    second = (
        IP(src="1.1.1.1", dst="2.2.2.2")
        / TCP(sport=1234, dport=80, seq=6)
        / Raw(load=b"IND / HTTP/1.1\r\nHost: a\r\n\r\n")
    )
    fingerprinter.process_packet(first)
    fingerprinter.process_packet(second)
    entries = fingerprinter.get_fingerprints()
    assert len(entries) == 1
    assert entries[0]["fingerprint"] == "pr11nn010000_{}_{}_{}".format(
        HOST_HASH, NO_COOKIE, NO_COOKIE
    )
