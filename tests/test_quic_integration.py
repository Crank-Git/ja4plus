"""Integration tests for QUIC support in extract_tls_info."""

import unittest
from unittest.mock import patch
from scapy.all import IP, UDP, TCP, Raw

from ja4plus.utils.tls_utils import extract_tls_info


class TestExtractTlsInfoQuicPath(unittest.TestCase):

    def _make_udp_packet(self, payload):
        return IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=12345, dport=443) / Raw(load=payload)

    @patch("ja4plus.utils.tls_utils.parse_quic_initial")
    def test_udp_triggers_quic(self, mock_quic):
        mock_quic.return_value = {
            "type": "client_hello", "is_quic": True,
            "version": 0x0303, "ciphers": [0x1301], "extensions": [],
        }
        result = extract_tls_info(self._make_udp_packet(b"\xC0" + b"\x00" * 50))
        mock_quic.assert_called_once()
        self.assertTrue(result["is_quic"])

    @patch("ja4plus.utils.tls_utils.parse_quic_initial")
    def test_quic_none_falls_through(self, mock_quic):
        mock_quic.return_value = None
        result = extract_tls_info(self._make_udp_packet(b"\x00" * 50))
        self.assertIsNone(result)

    @patch("ja4plus.utils.tls_utils.parse_quic_initial")
    def test_tcp_skips_quic(self, mock_quic):
        pkt = IP() / TCP(sport=12345, dport=443) / Raw(load=b"\x16\x03\x01" + b"\x00" * 50)
        extract_tls_info(pkt)
        mock_quic.assert_not_called()


class TestQuicJA4Integration(unittest.TestCase):

    def test_quic_ja4_starts_with_q(self):
        from ja4plus.fingerprinters.ja4 import generate_ja4
        tls_info = {
            "type": "client_hello", "is_quic": True, "is_dtls": False,
            "version": 0x0303, "supported_versions": [0x0304],
            "sni": "example.com", "ciphers": [0x1301, 0x1302, 0x1303],
            "extensions": [0x0000, 0x000A, 0x000B, 0x002B, 0x0010],
            "alpn_protocols": ["h2"], "signature_algorithms": [0x0804],
        }
        result = generate_ja4(tls_info)
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("q"))


if __name__ == "__main__":
    unittest.main()
