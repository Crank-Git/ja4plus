"""Tests for JA4X TCP stream reassembly with out-of-order segments."""

import unittest
from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4x import JA4XFingerprinter


class TestJA4XReassembly(unittest.TestCase):

    def test_in_order_still_works(self):
        fp = JA4XFingerprinter()
        data = b"\x16\x03\x01\x00\x05\x0b\x00\x00\x01\x00"
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=443, dport=12345, seq=100) / Raw(load=data)
        result = fp.process_packet(pkt)
        # May return None (not enough cert data), but should not crash

    def test_out_of_order_segments(self):
        fp = JA4XFingerprinter()
        tls_header = b"\x16\x03\x01\x00\x0a"
        tls_body = b"\x0b\x00\x00\x06\x00\x00\x03\x00\x00\x00"
        part1 = tls_header + tls_body[:5]
        part2 = tls_body[5:]
        pkt2 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=443, dport=12345, seq=100 + len(part1)
        ) / Raw(load=part2)
        fp.process_packet(pkt2)
        pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=443, dport=12345, seq=100
        ) / Raw(load=part1)
        result = fp.process_packet(pkt1)
        # Should not crash; reassembly should handle ordering


if __name__ == "__main__":
    unittest.main()
