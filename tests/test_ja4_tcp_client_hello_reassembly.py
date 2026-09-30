"""JA4 reads a TLS ClientHello that spans more than one TCP segment.

`pcap/sigalg-grease.pcapng` of FoxIO commit `16b96d95` carries a ClientHello of 2039
bytes in frame 4, with 1400 bytes, and frame 5, with 639 bytes. A reader of one segment
finds an incomplete handshake in each frame, so it produces no JA4 value. #772 records
the defect.

The expected values come from `tests/foxio_vectors/sigalg-grease.pcapng.json`, which is
`python/test/testdata/sigalg-grease.pcapng.json` of the same commit. Every other case of
this module cuts the same ClientHello into its own segments, so each case compares
against the same FoxIO values.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Raw, rdpcap

from ja4plus.fingerprinters.ja4 import (
    MAX_TCP_HELLO_AGE_SECONDS,
    MAX_TCP_HELLO_BYTES,
    MAX_TCP_HELLO_SEGMENTS,
    MAX_TCP_HELLO_STREAMS,
    JA4Fingerprinter,
)
from ja4plus.processor import Processor
from ja4plus.utils.tls_utils import client_hello_end

VECTORS = Path(__file__).parent / "foxio_vectors"
CAPTURE = VECTORS / "sigalg-grease.pcapng"
EXPECTED = json.loads((VECTORS / "sigalg-grease.pcapng.json").read_text())[0]

CLIENT_IP = "192.168.0.1"
SERVER_IP = "10.10.10.1"
CLIENT_PORT = 56544
SERVER_PORT = 443
FIRST_SEQ = 1230333283


def _hello_bytes() -> bytes:
    """Return the ClientHello of the capture, which frames 4 and 5 carry."""
    packets = rdpcap(str(CAPTURE))
    return bytes(packets[3][Raw]) + bytes(packets[4][Raw])


HELLO = _hello_bytes()


def _segment(
    payload: bytes,
    seq: int,
    *,
    sport: int = CLIENT_PORT,
    flags: str = "PA",
    timestamp: float | None = None,
    to_server: bool = True,
):
    """Return one TCP segment of the client stream, or of the server stream."""
    if to_server:
        packet = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(
            sport=sport, dport=SERVER_PORT, seq=seq, flags=flags
        )
    else:
        packet = IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(
            sport=SERVER_PORT, dport=sport, seq=seq, flags=flags
        )
    if payload:
        packet = packet / Raw(load=payload)
    if timestamp is not None:
        packet.time = timestamp
    return packet


def _cut(hello: bytes, *offsets: int, seq: int = FIRST_SEQ) -> list:
    """Return the segments that cut the hello at each offset, in stream order."""
    bounds = [0, *offsets, len(hello)]
    return [
        _segment(hello[start:end], (seq + start) & 0xFFFFFFFF)
        for start, end in zip(bounds, bounds[1:])
    ]


def _feed(fingerprinter: JA4Fingerprinter, packets) -> list:
    """Return the value of each packet, in the order the fingerprinter read them."""
    return [fingerprinter.process_packet(packet) for packet in packets]


def _held(fingerprinter: JA4Fingerprinter) -> int:
    """Return the count of streams that wait for more ClientHello bytes."""
    return len(fingerprinter._tcp_hellos.streams)


class TestTheFoxIOVector:
    def test_the_capture_gives_the_foxio_ja4_value_once(self):
        fingerprinter = JA4Fingerprinter()
        _feed(fingerprinter, rdpcap(str(CAPTURE)))

        entries = fingerprinter.get_fingerprints()
        assert [entry["fingerprint"] for entry in entries] == [EXPECTED["JA4.1"]]

    def test_the_capture_gives_the_three_other_foxio_forms(self):
        fingerprinter = JA4Fingerprinter()
        _feed(fingerprinter, rdpcap(str(CAPTURE)))

        entry = fingerprinter.get_fingerprints()[0]
        assert entry["fingerprint_original_order"] == EXPECTED["JA4_o.1"]
        assert entry["raw"] == EXPECTED["JA4_r.1"]
        assert entry["raw_original_order"] == EXPECTED["JA4_ro.1"]

    def test_the_value_names_the_connection_of_the_client(self):
        fingerprinter = JA4Fingerprinter()
        _feed(fingerprinter, rdpcap(str(CAPTURE)))

        entry = fingerprinter.get_fingerprints()[0]
        assert (entry["src"], entry["srcport"]) == (EXPECTED["src"], int(EXPECTED["srcport"]))
        assert (entry["dst"], entry["dstport"]) == (EXPECTED["dst"], int(EXPECTED["dstport"]))

    def test_the_processor_reports_one_ja4_result_for_the_capture(self):
        processor = Processor()
        values = [
            result.fingerprint
            for packet in rdpcap(str(CAPTURE))
            for result in processor.process_packet(packet)
            if result.type == "ja4"
        ]
        assert values == [EXPECTED["JA4.1"]]

    def test_the_fingerprinter_holds_no_stream_after_the_value(self):
        fingerprinter = JA4Fingerprinter()
        _feed(fingerprinter, rdpcap(str(CAPTURE)))
        assert _held(fingerprinter) == 0


class TestTheSegmentsThatCarryTheHello:
    def test_emits_the_value_on_the_segment_that_completes_two_segments(self):
        assert _feed(JA4Fingerprinter(), _cut(HELLO, 1400)) == [None, EXPECTED["JA4.1"]]

    def test_emits_the_value_on_the_segment_that_completes_three_segments(self):
        results = _feed(JA4Fingerprinter(), _cut(HELLO, 600, 1300))
        assert results == [None, None, EXPECTED["JA4.1"]]

    def test_starts_a_stream_on_a_segment_that_cuts_the_handshake_header(self):
        # Seven bytes hold the record header and two of the four handshake header bytes.
        results = _feed(JA4Fingerprinter(), _cut(HELLO, 7))
        assert results == [None, EXPECTED["JA4.1"]]

    def test_emits_one_value_when_the_first_segment_arrives_twice(self):
        first, second = _cut(HELLO, 1400)
        results = _feed(JA4Fingerprinter(), [first, first, second])
        assert results == [None, None, EXPECTED["JA4.1"]]

    def test_emits_the_value_when_two_segments_overlap(self):
        first = _segment(HELLO[:1400], FIRST_SEQ)
        second = _segment(HELLO[1300:], FIRST_SEQ + 1300)
        assert _feed(JA4Fingerprinter(), [first, second]) == [None, EXPECTED["JA4.1"]]

    def test_emits_the_value_across_a_wrap_of_the_sequence_number(self):
        segments = _cut(HELLO, 1400, seq=0xFFFFFFFF - 700)
        assert _feed(JA4Fingerprinter(), segments) == [None, EXPECTED["JA4.1"]]

    def test_emits_the_value_of_a_hello_that_one_segment_holds(self):
        fingerprinter = JA4Fingerprinter()
        assert _feed(fingerprinter, [_segment(HELLO, FIRST_SEQ)]) == [EXPECTED["JA4.1"]]
        assert _held(fingerprinter) == 0


class TestAGapInTheStream:
    def test_emits_no_value_while_a_segment_is_missing(self):
        first, _, third = _cut(HELLO, 600, 1300)
        fingerprinter = JA4Fingerprinter()
        assert _feed(fingerprinter, [first, third]) == [None, None]
        assert _held(fingerprinter) == 1

    def test_fills_the_gap_from_the_segment_that_arrives_and_never_from_zeros(self):
        first, second, third = _cut(HELLO, 600, 1300)
        results = _feed(JA4Fingerprinter(), [first, third, second])
        assert results == [None, None, EXPECTED["JA4.1"]]

    def test_emits_no_value_when_the_later_segment_arrives_first(self):
        first, second = _cut(HELLO, 1400)
        assert _feed(JA4Fingerprinter(), [second, first]) == [None, None]

    def test_ignores_a_segment_that_starts_before_the_hello(self):
        first, second = _cut(HELLO, 1400)
        earlier = _segment(b"\x00" * 100, FIRST_SEQ - 100)
        results = _feed(JA4Fingerprinter(), [first, earlier, second])
        assert results == [None, None, EXPECTED["JA4.1"]]


class TestTheBounds:
    def test_holds_no_stream_for_a_hello_longer_than_the_byte_cap(self):
        declared = MAX_TCP_HELLO_BYTES
        header = b"\x16\x03\x01" + (declared - 4).to_bytes(2, "big")
        handshake = b"\x01" + (declared - 9 + 1).to_bytes(3, "big")
        fingerprinter = JA4Fingerprinter()
        assert _feed(fingerprinter, [_segment(header + handshake + b"\x03\x03", 1)]) == [None]
        assert _held(fingerprinter) == 0

    def test_releases_a_stream_that_reaches_the_segment_cap(self):
        first = _segment(HELLO[:9], FIRST_SEQ)
        rest = [
            _segment(HELLO[offset : offset + 1], FIRST_SEQ + offset)
            for offset in range(9, 9 + MAX_TCP_HELLO_SEGMENTS + 5)
        ]
        fingerprinter = JA4Fingerprinter()
        assert set(_feed(fingerprinter, [first, *rest])) == {None}
        assert _held(fingerprinter) == 0

    def test_holds_no_more_streams_than_the_entry_cap(self):
        fingerprinter = JA4Fingerprinter()
        for port in range(1024, 1024 + MAX_TCP_HELLO_STREAMS + 10):
            fingerprinter.process_packet(_segment(HELLO[:1400], FIRST_SEQ, sport=port))
        assert _held(fingerprinter) == MAX_TCP_HELLO_STREAMS

    def test_emits_no_value_after_the_stream_passes_the_maximum_age(self):
        first = _segment(HELLO[:1400], FIRST_SEQ, timestamp=1000.0)
        second = _segment(
            HELLO[1400:], FIRST_SEQ + 1400, timestamp=1000.0 + MAX_TCP_HELLO_AGE_SECONDS + 1
        )
        assert _feed(JA4Fingerprinter(), [first, second]) == [None, None]

    def test_emits_the_value_inside_the_maximum_age(self):
        first = _segment(HELLO[:1400], FIRST_SEQ, timestamp=1000.0)
        second = _segment(
            HELLO[1400:], FIRST_SEQ + 1400, timestamp=1000.0 + MAX_TCP_HELLO_AGE_SECONDS - 1
        )
        assert _feed(JA4Fingerprinter(), [first, second]) == [None, EXPECTED["JA4.1"]]

    def test_the_stream_table_reaches_the_processor_stats(self):
        assert "_tcp_hellos" in JA4Fingerprinter().state_tables()


class TestTheRelease:
    @pytest.mark.parametrize("flags", ["FA", "R", "RA"])
    def test_a_closing_client_segment_releases_the_stream(self, flags):
        first, second = _cut(HELLO, 1400)
        close = _segment(b"", FIRST_SEQ + 1400, flags=flags)
        fingerprinter = JA4Fingerprinter()
        assert _feed(fingerprinter, [first, close]) == [None, None]
        assert _held(fingerprinter) == 0
        assert fingerprinter.process_packet(second) is None

    def test_a_server_reset_releases_the_client_stream(self):
        first, _ = _cut(HELLO, 1400)
        reset = _segment(b"", 1, flags="R", to_server=False)
        fingerprinter = JA4Fingerprinter()
        _feed(fingerprinter, [first, reset])
        assert _held(fingerprinter) == 0

    def test_cleanup_connection_releases_the_stream(self):
        first, _ = _cut(HELLO, 1400)
        fingerprinter = JA4Fingerprinter()
        fingerprinter.process_packet(first)
        fingerprinter.cleanup_connection(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT, "tcp")
        assert _held(fingerprinter) == 0

    def test_reset_releases_the_stream(self):
        first, _ = _cut(HELLO, 1400)
        fingerprinter = JA4Fingerprinter()
        fingerprinter.process_packet(first)
        fingerprinter.reset()
        assert _held(fingerprinter) == 0


class TestHostileInput:
    def test_a_payload_that_is_no_tls_record_starts_no_stream(self):
        fingerprinter = JA4Fingerprinter()
        request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assert _feed(fingerprinter, [_segment(request, 1)]) == [None]
        assert _held(fingerprinter) == 0

    def test_a_server_hello_record_starts_no_stream(self):
        fingerprinter = JA4Fingerprinter()
        cut_server_hello = b"\x16\x03\x03\x04\xba\x02\x00\x04\xb6\x03\x03"
        assert _feed(fingerprinter, [_segment(cut_server_hello, 1)]) == [None]
        assert _held(fingerprinter) == 0

    def test_a_short_hello_gives_the_value_one_segment_of_the_same_bytes_gives(self):
        # The single-segment reader accepts a hello that stops after the version field.
        # The reassembled bytes reach the same reader, so the two paths agree.
        short = b"\x16\x03\x01\x00\x0a\x01\x00\x00\x06" + b"\xff" * 6
        alone = JA4Fingerprinter().process_packet(_segment(short, 1))
        fingerprinter = JA4Fingerprinter()
        assert _feed(fingerprinter, _cut(short, 9)) == [None, alone]
        assert _held(fingerprinter) == 0

    def test_a_completed_record_that_holds_no_client_hello_leaves_nothing(self):
        # The handshake header claims 1 byte, and the reader needs 2 for the version.
        truncated = b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x03"
        fingerprinter = JA4Fingerprinter()
        assert _feed(fingerprinter, _cut(truncated, 9)) == [None, None]
        assert _held(fingerprinter) == 0

    def test_a_segment_after_the_value_starts_no_stream(self):
        fingerprinter = JA4Fingerprinter()
        _feed(fingerprinter, _cut(HELLO, 1400))
        after = _segment(b"\x17\x03\x03\x00\x20" + b"\x00" * 32, FIRST_SEQ + len(HELLO))
        assert fingerprinter.process_packet(after) is None
        assert _held(fingerprinter) == 0


class TestClientHelloEnd:
    def test_names_the_end_of_the_hello_in_the_first_segment(self):
        assert client_hello_end(HELLO[:1400]) == len(HELLO)

    def test_names_the_least_end_a_cut_handshake_header_allows(self):
        assert client_hello_end(HELLO[:7]) == 9

    def test_counts_a_change_cipher_spec_record_before_the_hello(self):
        change_cipher_spec = b"\x14\x03\x03\x00\x01\x01"
        assert client_hello_end(change_cipher_spec + HELLO[:1400]) == 6 + len(HELLO)

    @pytest.mark.parametrize(
        "payload",
        [
            b"",
            b"\x16\x03\x01\x07",
            b"GET / HTTP/1.1\r\n",
            b"\x16\x02\x01\x07\xf2\x01\x00\x07\xee",
            b"\x16\x03\x03\x04\xba\x02\x00\x04\xb6",
            b"\x14\x03\x03\x00\x01",
        ],
    )
    def test_names_no_end_for_bytes_that_open_no_client_hello(self, payload):
        assert client_hello_end(payload) is None
