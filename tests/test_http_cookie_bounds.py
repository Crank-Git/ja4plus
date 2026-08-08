"""The HTTP cookie parser holds a maximum entry count and two maximum lengths.

`CLAUDE.md` states that nothing grows without a limit. Three parsers split the Cookie
header and append one entry per pair, and none of the three held a bound before #175.

Past any bound the cookie parse produces no result, and the request therefore produces
no JA4H value. The user decided that on 2026-08-08. The JA4H cookie hash reads the
content and the order of the list. A truncated list therefore produces a value that
compares equal to a different sender's. A tool whose purpose is to compare one output
against another must not emit a value that describes traffic the sender did not send.
"""

from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4h import (
    JA4HFingerprinter,
    _convert_parsed_to_extract_format,
    _extract_http_info_from_bytes,
    generate_ja4h,
)
from ja4plus.utils import http_utils
from ja4plus.utils.http_utils import (
    MAX_COOKIE_NAME_BYTES,
    MAX_COOKIE_PAIRS,
    MAX_COOKIE_VALUE_BYTES,
    extract_http_info,
    parse_cookie_header,
    parse_http_request,
)


def _request(cookie_header):
    """Return the bytes of one HTTP request that carries the given Cookie header."""
    lines = ["GET / HTTP/1.1", "Host: example.com", "Cookie: {}".format(cookie_header)]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def _packet(data):
    """Return one TCP packet that carries the given payload."""
    return IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80) / Raw(load=data)


def _pairs(count):
    """Return a Cookie header that carries the given number of cookie pairs."""
    return "; ".join("c{}=1".format(index) for index in range(count))


def _every_path_refuses(cookie_header):
    """Assert that all three parsers and both JA4H entry points produce nothing.

    Args:
        cookie_header: The value of the Cookie header under test.
    """
    data = _request(cookie_header)
    packet = _packet(data)
    assert parse_cookie_header(cookie_header) is None
    assert parse_http_request(data) is None
    assert extract_http_info(packet) is None
    assert _extract_http_info_from_bytes(data) is None
    assert generate_ja4h(packet) is None


def _every_path_accepts(cookie_header, count):
    """Assert that all three parsers report the given number of cookie pairs.

    Args:
        cookie_header: The value of the Cookie header under test.
        count: The number of cookie pairs the header carries.
    """
    data = _request(cookie_header)
    packet = _packet(data)
    assert len(parse_cookie_header(cookie_header)[1]) == count
    assert len(parse_http_request(data)["cookie_fields"]) == count
    assert len(extract_http_info(packet)["cookie_fields"]) == count
    assert len(_extract_http_info_from_bytes(data)["cookie_fields"]) == count
    assert generate_ja4h(packet) is not None


def test_the_three_bounds_hold_the_values_the_user_decided_on_2026_08_08():
    """The bounds are 512 pairs, 256 name bytes and 4096 value bytes, and not a default.

    The user decided these three numbers on 2026-08-08, on #175. The decision comment is
    https://github.com/Crank-Git/ja4plus/issues/175#issuecomment-5223660889, and it
    records the vector readings each number sits above: 14 pairs, a 41-byte name and a
    264-byte value.

    Every other case in this file builds its input from the constant, as
    `MAX_COOKIE_PAIRS + 1`. Those cases prove that the refusal happens at the constant.
    They prove nothing about the constant, and all of them stay green when the three
    values change. A later `MAX_COOKIE_PAIRS = 5` would then suppress the JA4H value of
    ordinary traffic against a green suite. This case reads the numbers, so that change
    fails here.
    """
    assert MAX_COOKIE_PAIRS == 512
    assert MAX_COOKIE_NAME_BYTES == 256
    assert MAX_COOKIE_VALUE_BYTES == 4096


def test_a_cookie_header_above_the_pair_cap_produces_no_parse_result():
    """A header of 513 pairs produces nothing on all three parsers and no JA4H value."""
    _every_path_refuses(_pairs(MAX_COOKIE_PAIRS + 1))


def test_a_cookie_header_at_the_pair_cap_still_parses():
    """A header of 512 pairs produces a list of 512 pairs on all three parsers."""
    _every_path_accepts(_pairs(MAX_COOKIE_PAIRS), MAX_COOKIE_PAIRS)


def test_a_cookie_name_above_the_name_cap_produces_no_parse_result():
    """A cookie name of 257 bytes produces nothing, although the pair count is 1."""
    _every_path_refuses("{}=1".format("n" * (MAX_COOKIE_NAME_BYTES + 1)))


def test_a_cookie_name_at_the_name_cap_still_parses():
    """A cookie name of 256 bytes produces one cookie pair."""
    _every_path_accepts("{}=1".format("n" * MAX_COOKIE_NAME_BYTES), 1)


def test_a_cookie_value_above_the_value_cap_produces_no_parse_result():
    """A cookie value of 4097 bytes produces nothing, although the pair count is 1."""
    _every_path_refuses("a={}".format("v" * (MAX_COOKIE_VALUE_BYTES + 1)))


def test_a_cookie_value_at_the_value_cap_still_parses():
    """A cookie value of 4096 bytes produces one cookie pair."""
    _every_path_accepts("a={}".format("v" * MAX_COOKIE_VALUE_BYTES), 1)


def test_a_length_cap_reads_the_byte_count_and_not_the_character_count():
    """A name of 129 two-byte characters is 258 bytes, so it passes the 256-byte cap.

    The character count of that name is 129, which is far below the cap. A parser that
    counts characters accepts a name of 512 bytes.
    """
    accented = "é"
    assert len(accented.encode("utf-8")) == 2

    at_cap = accented * (MAX_COOKIE_NAME_BYTES // 2)
    above_cap = accented * (MAX_COOKIE_NAME_BYTES // 2 + 1)

    assert parse_cookie_header("{}=1".format(at_cap)) is not None
    assert parse_cookie_header("{}=1".format(above_cap)) is None


def test_one_pair_above_a_cap_refuses_the_whole_header():
    """A header whose last pair holds a long value produces nothing, not the other pairs.

    A parser that drops the one pair reports a list the sender did not send, and the
    JA4H cookie hash of that list compares equal to another sender's.
    """
    header = "a=1; b=2; c={}".format("v" * (MAX_COOKIE_VALUE_BYTES + 1))

    _every_path_refuses(header)


def test_the_parsed_request_path_converts_a_header_at_the_cap_and_nothing_above_it():
    """`_convert_parsed_to_extract_format` reads 512 pairs, and reads nothing above 512.

    The converter reports the cookie list that JA4H hashes. A parse that truncated would
    reach the converter with 512 of the 513 pairs, and the request would carry a
    fingerprint.
    """
    at_cap = parse_http_request(_request(_pairs(MAX_COOKIE_PAIRS)))
    above_cap = parse_http_request(_request(_pairs(MAX_COOKIE_PAIRS + 1)))

    assert above_cap is None
    assert len(_convert_parsed_to_extract_format(at_cap)["cookie_fields"]) == MAX_COOKIE_PAIRS


def test_the_reassembled_stream_path_produces_no_ja4h_value_above_a_cap():
    """A request split across two TCP segments produces no JA4H value past the pair cap.

    This path reads `_extract_http_info_from_bytes`, which the issue body did not name.
    """
    data = _request(_pairs(MAX_COOKIE_PAIRS + 1))
    head, tail = data[:40], data[40:]
    fingerprinter = JA4HFingerprinter()

    fingerprinter.process_packet(
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, seq=1) / Raw(load=head)
    )
    fingerprinter.process_packet(
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80, seq=1 + len(head))
        / Raw(load=tail)
    )

    assert fingerprinter.get_fingerprints() == []


def test_the_reassembled_stream_path_still_produces_a_value_at_the_pair_cap():
    """The same split request produces one JA4H value when it carries 512 pairs."""
    data = _request(_pairs(MAX_COOKIE_PAIRS))
    head, tail = data[:40], data[40:]
    fingerprinter = JA4HFingerprinter()

    fingerprinter.process_packet(
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, seq=1) / Raw(load=head)
    )
    fingerprinter.process_packet(
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80, seq=1 + len(head))
        / Raw(load=tail)
    )

    assert len(fingerprinter.get_fingerprints()) == 1


def test_the_parser_reads_no_more_segments_than_one_past_the_pair_cap(monkeypatch):
    """A header of 100000 pairs makes the parser read 513 segments, not 100000.

    The bound covers the list the parser builds, not the value it returns. A parser that
    splits the whole header first allocates one entry for every pair before it refuses.
    """
    read = []
    original = http_utils._cookie_segments

    def counted(text):
        for segment in original(text):
            read.append(segment)
            yield segment

    monkeypatch.setattr(http_utils, "_cookie_segments", counted)

    assert parse_cookie_header(_pairs(100000)) is None
    # An empty list would pass the upper bound alone, and it names a parser that never
    # called the reader at all.
    assert 0 < len(read) <= MAX_COOKIE_PAIRS + 1


def test_a_cookie_header_of_empty_segments_stays_inside_the_pair_cap():
    """A header of 100000 separators and one pair produces one pair, because a segment
    without an equals sign contributes no entry."""
    header = "a=1" + ";" * 100000

    result = parse_cookie_header(header)

    assert result is not None
    assert result[1] == ["a"]


def test_a_request_that_carries_no_cookie_still_produces_a_ja4h_value():
    """The bounds leave a request that carries no Cookie header unchanged."""
    data = ("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").encode()

    assert generate_ja4h(_packet(data)) is not None
    assert parse_http_request(data) is not None
    assert _extract_http_info_from_bytes(data) is not None
