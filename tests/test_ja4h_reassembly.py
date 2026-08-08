"""Tests for JA4H TCP stream reassembly."""

import unittest
from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4h import JA4HFingerprinter


class TestJA4HReassembly(unittest.TestCase):
    def test_single_packet_still_works(self):
        fp = JA4HFingerprinter()
        http_data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
        pkt = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, seq=100)
            / Raw(load=http_data)
        )
        result = fp.process_packet(pkt)
        self.assertIsNotNone(result, "Single-packet HTTP should produce fingerprint")

    def test_multi_segment_http(self):
        fp = JA4HFingerprinter()
        part1 = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
        part2 = b"User-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n"
        pkt1 = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, seq=100)
            / Raw(load=part1)
        )
        pkt2 = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, seq=100 + len(part1))
            / Raw(load=part2)
        )
        result1 = fp.process_packet(pkt1)
        result2 = fp.process_packet(pkt2)
        self.assertTrue(
            result1 is not None or result2 is not None,
            "Multi-segment HTTP should produce fingerprint",
        )

    def test_a_buffer_that_cannot_become_an_http_request_leaves_the_reassembler(self):
        fp = JA4HFingerprinter()
        # A TLS record starts with 0x16, which no HTTP request line starts with.
        first = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=443, seq=100)
            / Raw(load=b"\x16\x03\x01\x00\x2c" + b"\x00" * 44)
        )
        second = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=443, seq=149)
            / Raw(load=b"\x00" * 20)
        )
        fp.process_packet(first)
        fp.process_packet(second)
        self.assertEqual(fp.reassembler.streams, {})

    def test_a_reordered_request_head_still_produces_a_fingerprint(self):
        fp = JA4HFingerprinter()
        head = b"GET /index.html HTTP/1.1\r\n"
        tail = b"Host: example.com\r\nAccept: text/html\r\n\r\n"
        # The tail arrives first, so the buffer starts in the middle of the request line
        # and no HTTP request line starts with those bytes.
        tail_packet = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, seq=100 + len(head))
            / Raw(load=tail)
        )
        head_packet = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, seq=100)
            / Raw(load=head)
        )
        self.assertIsNone(fp.process_packet(tail_packet))
        self.assertIsNotNone(fp.process_packet(head_packet))

    def test_the_table_of_waiting_streams_stays_inside_the_stream_cap(self):
        fp = JA4HFingerprinter()
        # Each connection sends one segment that starts no HTTP request, so each one
        # makes an entry that waits for a second packet that never arrives.
        for port in range(1024, 1024 + 300):
            pkt = (
                IP(src="10.0.0.1", dst="10.0.0.2")
                / TCP(sport=port, dport=443, seq=100)
                / Raw(load=b"\x16\x03\x01\x00\x2c")
            )
            fp.process_packet(pkt)
        self.assertLessEqual(len(fp.unusable_base), fp.reassembler.max_streams)

    def test_a_partial_method_name_stays_in_the_reassembler(self):
        fp = JA4HFingerprinter()
        pkt = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, seq=100)
            / Raw(load=b"GE")
        )
        fp.process_packet(pkt)
        self.assertIn("10.0.0.1:12345-10.0.0.2:80", fp.reassembler.streams)

    def test_a_request_that_spans_two_segments_stays_in_the_reassembler(self):
        fp = JA4HFingerprinter()
        part1 = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
        pkt = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, seq=100)
            / Raw(load=part1)
        )
        fp.process_packet(pkt)
        self.assertIn("10.0.0.1:12345-10.0.0.2:80", fp.reassembler.streams)


class TestJA4HUnreadableRequest(unittest.TestCase):
    """Tests the removal of a stream whose complete header block produces no value."""

    KEY = "10.0.0.1:12345-10.0.0.2:80"

    # The version token `HTTP/11` names no HTTP version, so the request line matches no
    # pattern and the parse produces nothing. #35 records the reading.
    REFUSED_REQUEST = b"GET / HTTP/11\r\nHost: example.com\r\nAccept: text/html\r\n\r\n"

    def _packet(self, payload, seq):
        return (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, seq=seq)
            / Raw(load=payload)
        )

    def test_a_complete_header_block_that_produces_nothing_leaves_no_entry(self):
        fp = JA4HFingerprinter()
        self.assertIsNone(fp.process_packet(self._packet(self.REFUSED_REQUEST, 100)))
        # The removal waits for one packet that leaves the base sequence number in place,
        # because a segment that arrives out of order lowers that number.
        fp.process_packet(self._packet(b"x" * 40, 100 + len(self.REFUSED_REQUEST)))
        self.assertEqual(fp.reassembler.streams, {})

    def test_the_buffer_of_a_refused_request_stops_growing(self):
        fp = JA4HFingerprinter()
        seq = 100
        fp.process_packet(self._packet(self.REFUSED_REQUEST, seq))
        seq += len(self.REFUSED_REQUEST)
        widest = 0
        for _ in range(300):
            fp.process_packet(self._packet(b"x" * 1400, seq))
            seq += 1400
            stream = fp.reassembler.streams.get(self.KEY)
            if stream is not None:
                widest = max(widest, stream["bytes"])
        # The base behaviour holds every byte of the connection, which is 420036 bytes
        # over 300 packets. #190 records the measurement.
        self.assertLess(widest, 8192)

    def test_a_reordered_request_whose_head_arrives_late_produces_a_fingerprint(self):
        fp = JA4HFingerprinter()
        head = b"POST /a HTTP/1.1\r\nX-Note: "
        # The tail starts with a method token and ends a header block, so the buffer it
        # forms on its own reads as a complete request that produces nothing.
        tail = b"GET / HTTP/11\r\n\r\n"
        self.assertIsNone(fp.process_packet(self._packet(tail, 100 + len(head))))
        self.assertIsNotNone(fp.process_packet(self._packet(head, 100)))


class TestJA4HStreamAge(unittest.TestCase):
    """Tests that JA4H states the packet time to the reassembler."""

    # A capture time from 2001, far from the wall clock.
    OLD_CAPTURE_TIME = 1000000000.0

    def _partial_request(self, sport, seconds):
        """Return one packet that starts an HTTP request and completes no header."""
        packet = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=sport, dport=80, seq=100)
            / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: exam")
        )
        packet.time = seconds
        return packet

    def test_the_stream_holds_the_packet_time_of_its_most_recent_segment(self):
        fp = JA4HFingerprinter()
        fp.process_packet(self._partial_request(12345, self.OLD_CAPTURE_TIME))
        key = "10.0.0.1:12345-10.0.0.2:80"
        self.assertEqual(fp.reassembler.streams[key]["last_seen"], self.OLD_CAPTURE_TIME)

    def test_a_stream_that_passes_the_maximum_age_leaves_the_reassembler(self):
        fp = JA4HFingerprinter()
        fp.reassembler.max_stream_age = 100
        fp.process_packet(self._partial_request(12345, self.OLD_CAPTURE_TIME))
        fp.process_packet(self._partial_request(12346, self.OLD_CAPTURE_TIME + 101))
        self.assertNotIn("10.0.0.1:12345-10.0.0.2:80", fp.reassembler.streams)
        self.assertIn("10.0.0.1:12346-10.0.0.2:80", fp.reassembler.streams)


if __name__ == "__main__":
    unittest.main()
