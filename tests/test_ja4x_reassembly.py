"""Tests for JA4X TCP stream reassembly with out-of-order segments."""

import unittest
from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4x import JA4XFingerprinter


class TestJA4XReassembly(unittest.TestCase):
    def test_in_order_still_works(self):
        fp = JA4XFingerprinter()
        data = b"\x16\x03\x01\x00\x05\x0b\x00\x00\x01\x00"
        pkt = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=443, dport=12345, seq=100)
            / Raw(load=data)
        )
        fp.process_packet(pkt)
        # May return None (not enough cert data), but should not crash

    def test_out_of_order_segments(self):
        fp = JA4XFingerprinter()
        tls_header = b"\x16\x03\x01\x00\x0a"
        tls_body = b"\x0b\x00\x00\x06\x00\x00\x03\x00\x00\x00"
        part1 = tls_header + tls_body[:5]
        part2 = tls_body[5:]
        pkt2 = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=443, dport=12345, seq=100 + len(part1))
            / Raw(load=part2)
        )
        fp.process_packet(pkt2)
        pkt1 = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=443, dport=12345, seq=100)
            / Raw(load=part1)
        )
        fp.process_packet(pkt1)
        # Should not crash; reassembly should handle ordering


class TestJA4XStreamAge(unittest.TestCase):
    """Tests that JA4X states the packet time to the reassembler."""

    # A capture time from 2001, far from the wall clock.
    OLD_CAPTURE_TIME = 1000000000.0

    def _partial_record(self, sport, seconds):
        """Return one packet that starts a TLS record and completes no handshake."""
        packet = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=sport, dport=12345, seq=100)
            / Raw(load=b"\x16\x03\x01\x00\x05\x0b\x00\x00\x01\x00")
        )
        packet.time = seconds
        return packet

    def test_the_stream_holds_the_packet_time_of_its_most_recent_segment(self):
        fp = JA4XFingerprinter()
        fp.process_packet(self._partial_record(443, self.OLD_CAPTURE_TIME))
        key = "10.0.0.1:443-10.0.0.2:12345"
        self.assertEqual(fp.reassembler.streams[key]["last_seen"], self.OLD_CAPTURE_TIME)

    def test_a_stream_that_passes_the_maximum_age_leaves_the_reassembler(self):
        fp = JA4XFingerprinter()
        fp.reassembler.max_stream_age = 100
        fp.process_packet(self._partial_record(443, self.OLD_CAPTURE_TIME))
        fp.process_packet(self._partial_record(444, self.OLD_CAPTURE_TIME + 101))
        self.assertNotIn("10.0.0.1:443-10.0.0.2:12345", fp.reassembler.streams)
        self.assertIn("10.0.0.1:444-10.0.0.2:12345", fp.reassembler.streams)


if __name__ == "__main__":
    unittest.main()
