"""Tests for JA4H TCP stream reassembly."""

import unittest
from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4h import JA4HFingerprinter


class TestJA4HReassembly(unittest.TestCase):

    def test_single_packet_still_works(self):
        fp = JA4HFingerprinter()
        http_data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=100) / Raw(load=http_data)
        result = fp.process_packet(pkt)
        self.assertIsNotNone(result, "Single-packet HTTP should produce fingerprint")

    def test_multi_segment_http(self):
        fp = JA4HFingerprinter()
        part1 = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
        part2 = b"User-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n"
        pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=100) / Raw(load=part1)
        pkt2 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=100 + len(part1)) / Raw(load=part2)
        result1 = fp.process_packet(pkt1)
        result2 = fp.process_packet(pkt2)
        self.assertTrue(result1 is not None or result2 is not None,
                        "Multi-segment HTTP should produce fingerprint")


if __name__ == "__main__":
    unittest.main()
