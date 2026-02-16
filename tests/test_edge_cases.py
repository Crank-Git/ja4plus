"""
Edge case and error handling tests for all JA4+ fingerprinters.

Tests that fingerprinters handle malformed, empty, truncated, and unexpected
input gracefully without crashing.
"""

import unittest
import time
from scapy.all import IP, TCP, UDP, Raw, Ether

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter, generate_ja4
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter, generate_ja4s
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter, generate_ja4h
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter, generate_ja4t
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter, generate_ja4ts
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter, generate_ja4l
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter, generate_ja4ssh
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter, generate_ja4x
from ja4plus.fingerprinters.base import BaseFingerprinter


# ===========================================================================
# Empty and None input tests
# ===========================================================================
class TestEmptyInputs(unittest.TestCase):
    """All fingerprinters should handle empty/None gracefully."""

    def test_ja4_none_tls_info(self):
        self.assertIsNone(generate_ja4(None))

    def test_ja4_empty_tls_info(self):
        self.assertIsNone(generate_ja4({}))

    def test_ja4_wrong_type(self):
        """generate_ja4 with server_hello type should return None."""
        self.assertIsNone(generate_ja4({"type": "server_hello"}))

    def test_ja4s_non_tls_packet(self):
        packet = IP() / TCP(sport=443, dport=54321) / Raw(load=b"not tls")
        self.assertIsNone(generate_ja4s(packet))

    def test_ja4s_no_raw(self):
        packet = IP() / TCP(sport=443, dport=54321)
        self.assertIsNone(generate_ja4s(packet))

    def test_ja4h_non_http_packet(self):
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=b"\x16\x03\x03")
        self.assertIsNone(generate_ja4h(packet))

    def test_ja4h_no_raw(self):
        packet = IP() / TCP(sport=12345, dport=80)
        self.assertIsNone(generate_ja4h(packet))

    def test_ja4t_no_tcp(self):
        packet = IP() / UDP(sport=12345, dport=443)
        self.assertIsNone(generate_ja4t(packet))

    def test_ja4t_no_ip(self):
        """Packet without IP layer - still has TCP."""
        packet = Ether() / TCP(sport=12345, dport=443, flags="S")
        fp = generate_ja4t(packet)
        # Should still work since it only checks TCP layer
        # (or return None depending on implementation)

    def test_ja4ts_no_tcp(self):
        packet = IP() / UDP(sport=443, dport=54321)
        self.assertIsNone(generate_ja4ts(packet))

    def test_ja4l_no_conn(self):
        packet = IP(ttl=64) / TCP(sport=443, dport=54321, flags="SA")
        self.assertIsNone(generate_ja4l(packet, None))

    def test_ja4l_no_ip(self):
        packet = TCP(sport=443, dport=54321, flags="SA")
        conn = {"proto": "tcp", "timestamps": {}, "ttls": {}}
        self.assertIsNone(generate_ja4l(packet, conn))

    def test_ja4x_none_cert_info(self):
        self.assertIsNone(generate_ja4x(None))

    def test_ja4x_empty_cert_info(self):
        self.assertIsNone(generate_ja4x({}))

    def test_ja4ssh_no_tcp(self):
        """SSH fingerprinter requires TCP layer."""
        packet = IP() / UDP(sport=12345, dport=22) / Raw(load=b"SSH-2.0-test\r\n")
        fp = JA4SSHFingerprinter(packet_count=1)
        result = fp.process_packet(packet)
        self.assertIsNone(result)


# ===========================================================================
# Malformed TLS data tests
# ===========================================================================
class TestMalformedTLS(unittest.TestCase):
    """Test fingerprinters with malformed TLS records."""

    def setUp(self):
        self.ja4 = JA4Fingerprinter()
        self.ja4s = JA4SFingerprinter()

    def test_truncated_tls_record(self):
        """TLS record header says 200 bytes but only 10 present."""
        data = b"\x16\x03\x03\x00\xc8" + b"\x01" * 10
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=data)
        self.assertIsNone(self.ja4.process_packet(packet))

    def test_wrong_record_type(self):
        """Application data (0x17) instead of handshake (0x16)."""
        data = b"\x17\x03\x03\x00\x05\x01\x02\x03\x04\x05"
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=data)
        self.assertIsNone(self.ja4.process_packet(packet))

    def test_zero_length_record(self):
        data = b"\x16\x03\x03\x00\x00"
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=data)
        self.assertIsNone(self.ja4.process_packet(packet))

    def test_single_byte_data(self):
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=b"\x16")
        self.assertIsNone(self.ja4.process_packet(packet))

    def test_random_bytes(self):
        """Random non-TLS data should not crash."""
        import os
        data = os.urandom(256)
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=data)
        # Should not raise, just return None
        result = self.ja4.process_packet(packet)
        # Either None or a result, but should not crash

    def test_very_large_packet(self):
        """Large payload should not hang or crash."""
        data = b"\x16\x03\x03" + b"\x00" * 5000
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=data)
        result = self.ja4.process_packet(packet)
        # Should not hang or crash


# ===========================================================================
# Malformed HTTP data tests
# ===========================================================================
class TestMalformedHTTP(unittest.TestCase):
    """Test JA4H with malformed HTTP data."""

    def setUp(self):
        self.ja4h = JA4HFingerprinter()

    def test_incomplete_request_line(self):
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=b"GET")
        self.assertIsNone(self.ja4h.process_packet(packet))

    def test_binary_data(self):
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=b"\x00\x01\x02\x03")
        self.assertIsNone(self.ja4h.process_packet(packet))

    def test_headers_without_colon(self):
        """Malformed headers without colon separator."""
        data = b"GET / HTTP/1.1\r\nBadHeader\r\nHost: test.com\r\n\r\n"
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=data)
        result = self.ja4h.process_packet(packet)
        # Should still work, just skip bad header
        self.assertIsNotNone(result)

    def test_empty_cookie_value(self):
        """Cookie with empty value."""
        data = b"GET / HTTP/1.1\r\nHost: test.com\r\nCookie: session=\r\n\r\n"
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=data)
        result = self.ja4h.process_packet(packet)
        self.assertIsNotNone(result)

    def test_tls_data_on_http_port(self):
        """TLS data passed to HTTP fingerprinter."""
        data = b"\x16\x03\x03\x00\x10" + b"\x00" * 16
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=data)
        self.assertIsNone(self.ja4h.process_packet(packet))


# ===========================================================================
# Malformed TCP tests
# ===========================================================================
class TestMalformedTCP(unittest.TestCase):
    """Test JA4T/JA4TS with unexpected TCP flag combinations."""

    def test_ja4t_rst_packet(self):
        """RST packet should be ignored."""
        packet = IP() / TCP(sport=12345, dport=443, flags="R")
        self.assertIsNone(generate_ja4t(packet))

    def test_ja4t_fin_packet(self):
        """FIN packet should be ignored."""
        packet = IP() / TCP(sport=12345, dport=443, flags="F")
        self.assertIsNone(generate_ja4t(packet))

    def test_ja4t_push_ack_packet(self):
        """PSH-ACK should be ignored."""
        packet = IP() / TCP(sport=12345, dport=443, flags="PA")
        self.assertIsNone(generate_ja4t(packet))

    def test_ja4ts_syn_only(self):
        """SYN-only (no ACK) should be ignored by JA4TS."""
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535)
        self.assertIsNone(generate_ja4ts(packet))

    def test_ja4ts_ack_only(self):
        """ACK-only should be ignored by JA4TS."""
        packet = IP() / TCP(sport=443, dport=54321, flags="A", window=14600)
        self.assertIsNone(generate_ja4ts(packet))

    def test_ja4t_synack_rejected(self):
        """SYN-ACK should be rejected by JA4T (handled by JA4TS)."""
        packet = IP() / TCP(sport=443, dport=54321, flags="SA", window=14600,
                            options=[("MSS", 1460)])
        self.assertIsNone(generate_ja4t(packet))


# ===========================================================================
# Non-SSH data to SSH fingerprinter
# ===========================================================================
class TestMalformedSSH(unittest.TestCase):
    """Test SSH fingerprinter with non-SSH data."""

    def setUp(self):
        self.ja4ssh = JA4SSHFingerprinter(packet_count=10)

    def test_http_data_to_ssh(self):
        """HTTP data should not produce SSH fingerprints."""
        packet = (IP(src="10.0.0.1", dst="10.0.0.2")
                  / TCP(sport=12345, dport=22)
                  / Raw(load=b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"))
        result = self.ja4ssh.process_packet(packet)
        self.assertIsNone(result)

    def test_tls_data_to_ssh(self):
        """TLS data should not produce SSH fingerprints."""
        packet = (IP(src="10.0.0.1", dst="10.0.0.2")
                  / TCP(sport=12345, dport=22)
                  / Raw(load=b"\x16\x03\x03\x00\x10" + b"\x00" * 16))
        result = self.ja4ssh.process_packet(packet)
        self.assertIsNone(result)

    def test_empty_payload(self):
        """Empty payload should not produce SSH fingerprints."""
        packet = (IP(src="10.0.0.1", dst="10.0.0.2")
                  / TCP(sport=12345, dport=22)
                  / Raw(load=b""))
        result = self.ja4ssh.process_packet(packet)
        self.assertIsNone(result)


# ===========================================================================
# X.509 edge cases
# ===========================================================================
class TestX509EdgeCases(unittest.TestCase):
    """Test JA4X with edge case certificate data."""

    def test_invalid_der_data(self):
        """Invalid DER data should not crash."""
        fp = JA4XFingerprinter()
        result = fp.fingerprint_certificate(b"\x30\x82\x00\x00")
        self.assertIsNone(result)

    def test_empty_der_data(self):
        """Empty data should return None."""
        fp = JA4XFingerprinter()
        result = fp.fingerprint_certificate(b"")
        self.assertIsNone(result)

    def test_text_data(self):
        """Text data should not crash."""
        fp = JA4XFingerprinter()
        result = fp.fingerprint_certificate(b"not a certificate")
        self.assertIsNone(result)

    def test_generate_ja4x_empty_lists(self):
        """Empty RDN/extension lists should produce hashes of empty strings."""
        import hashlib
        cert_info = {
            "issuer_rdns": [],
            "subject_rdns": [],
            "extensions": []
        }
        result = generate_ja4x(cert_info)
        self.assertIsNotNone(result)
        parts = result.split("_")
        for part in parts:
            self.assertEqual(part, "000000000000")


# ===========================================================================
# BaseFingerprinter interface tests
# ===========================================================================
class TestBaseFingerprinter(unittest.TestCase):
    """Test the BaseFingerprinter abstract interface."""

    def test_process_packet_raises(self):
        """BaseFingerprinter.process_packet should raise NotImplementedError."""
        base = BaseFingerprinter()
        with self.assertRaises(NotImplementedError):
            base.process_packet(IP() / TCP())

    def test_add_fingerprint(self):
        """add_fingerprint should store the fingerprint."""
        base = BaseFingerprinter()
        packet = IP() / TCP()
        base.add_fingerprint("test_fp", packet)
        fps = base.get_fingerprints()
        self.assertEqual(len(fps), 1)
        self.assertEqual(fps[0]["fingerprint"], "test_fp")

    def test_reset(self):
        """reset should clear all fingerprints."""
        base = BaseFingerprinter()
        base.add_fingerprint("fp1", IP() / TCP())
        base.add_fingerprint("fp2", IP() / TCP())
        self.assertEqual(len(base.get_fingerprints()), 2)
        base.reset()
        self.assertEqual(len(base.get_fingerprints()), 0)

    def test_initial_state(self):
        """New fingerprinter should have empty fingerprints list."""
        base = BaseFingerprinter()
        self.assertEqual(base.get_fingerprints(), [])


# ===========================================================================
# All fingerprinters graceful error handling
# ===========================================================================
class TestAllFingerprinterGraceful(unittest.TestCase):
    """Verify every fingerprinter handles edge cases without exceptions."""

    def _all_fingerprinters(self):
        return [
            JA4Fingerprinter(),
            JA4SFingerprinter(),
            JA4HFingerprinter(),
            JA4TFingerprinter(),
            JA4TSFingerprinter(),
            JA4LFingerprinter(),
            JA4XFingerprinter(),
            JA4SSHFingerprinter(packet_count=10),
        ]

    def test_all_handle_bare_ip_tcp(self):
        """All fingerprinters should handle IP/TCP without crashing."""
        packet = IP() / TCP()
        for fp in self._all_fingerprinters():
            name = fp.__class__.__name__
            with self.subTest(fingerprinter=name):
                try:
                    fp.process_packet(packet)
                except Exception as e:
                    self.fail(f"{name} raised {e} on bare IP/TCP packet")

    def test_all_handle_empty_raw(self):
        """All fingerprinters should handle empty Raw payload."""
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=b"")
        for fp in self._all_fingerprinters():
            name = fp.__class__.__name__
            with self.subTest(fingerprinter=name):
                try:
                    fp.process_packet(packet)
                except Exception as e:
                    self.fail(f"{name} raised {e} on empty Raw payload")

    def test_all_handle_random_payload(self):
        """All fingerprinters should handle random bytes without crashing."""
        import os
        data = os.urandom(128)
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=data)
        for fp in self._all_fingerprinters():
            name = fp.__class__.__name__
            with self.subTest(fingerprinter=name):
                try:
                    fp.process_packet(packet)
                except Exception as e:
                    self.fail(f"{name} raised {e} on random payload")

    def test_all_reset_works(self):
        """All fingerprinters should reset cleanly."""
        for fp in self._all_fingerprinters():
            name = fp.__class__.__name__
            with self.subTest(fingerprinter=name):
                fp.reset()
                self.assertEqual(len(fp.get_fingerprints()), 0,
                                 f"{name} did not reset properly")


# ===========================================================================
# JA4L timing edge cases
# ===========================================================================
class TestJA4LEdgeCases(unittest.TestCase):
    """Test JA4L with edge case timing scenarios."""

    def test_synack_before_syn(self):
        """SYN-ACK arriving before SYN should not crash."""
        fp = JA4LFingerprinter()
        synack = IP(src="10.0.0.2", dst="10.0.0.1", ttl=64) / TCP(
            sport=443, dport=54321, flags="SA"
        )
        result = fp.process_packet(synack)
        # SYN-ACK without prior SYN should produce a fingerprint
        # since B timestamp is set but A may not be - depends on impl
        # Main point: no crash

    def test_duplicate_syn(self):
        """Processing two SYN packets should not crash."""
        fp = JA4LFingerprinter()
        syn = IP(src="10.0.0.1", dst="10.0.0.2", ttl=128) / TCP(
            sport=54321, dport=443, flags="S"
        )
        fp.process_packet(syn)
        time.sleep(0.001)
        fp.process_packet(syn)
        # Should not crash

    def test_reset_clears_connections(self):
        """Reset should clear connection tracking."""
        fp = JA4LFingerprinter()
        syn = IP(src="10.0.0.1", dst="10.0.0.2", ttl=128) / TCP(
            sport=54321, dport=443, flags="S"
        )
        fp.process_packet(syn)
        self.assertGreater(len(fp.connections), 0)
        fp.reset()
        self.assertEqual(len(fp.connections), 0)

    def test_ttl_boundary_values(self):
        """Test TTL boundary values for OS estimation."""
        fp = JA4LFingerprinter()
        # TTL exactly 64 (Linux boundary)
        self.assertIn("Linux", fp.estimate_os(64))
        # TTL exactly 128 (Windows boundary)
        self.assertIn("Windows", fp.estimate_os(128))
        # TTL = 255 (network device)
        self.assertIn("Cisco", fp.estimate_os(255))
        # TTL = 1
        self.assertIn("Linux", fp.estimate_os(1))

    def test_hop_count_zero_hops(self):
        """TTL at initial value means 0 hops."""
        fp = JA4LFingerprinter()
        self.assertEqual(fp.estimate_hop_count(64), 0)
        self.assertEqual(fp.estimate_hop_count(128), 0)
        self.assertEqual(fp.estimate_hop_count(255), 0)


if __name__ == "__main__":
    unittest.main()
