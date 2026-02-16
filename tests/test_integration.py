import unittest
import hashlib
from scapy.all import IP, TCP, UDP, Raw
from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter


class TestIntegration(unittest.TestCase):
    """Integration tests using constructed packets (no live capture needed)."""

    def setUp(self):
        self.ja4 = JA4Fingerprinter()
        self.ja4s = JA4SFingerprinter()
        self.ja4h = JA4HFingerprinter()
        self.ja4l = JA4LFingerprinter()
        self.ja4t = JA4TFingerprinter()
        self.ja4ts = JA4TSFingerprinter()

        # HTTP request packet
        self.http_request = (
            IP()
            / TCP(sport=12345, dport=80)
            / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )

        # TCP SYN packet
        self.syn_packet = IP() / TCP(
            sport=54321,
            dport=443,
            flags="S",
            window=65535,
            options=[
                ("MSS", 1460),
                ("NOP", None),
                ("WScale", 7),
                ("SAckOK", ""),
                ("Timestamp", (0, 0)),
            ],
        )

        # TCP SYN-ACK packet
        self.synack_packet = IP() / TCP(
            sport=443,
            dport=54321,
            flags="SA",
            window=14600,
            options=[
                ("MSS", 1460),
                ("NOP", None),
                ("WScale", 0),
                ("SAckOK", b""),
                ("NOP", None),
                ("NOP", None),
            ],
        )

    def test_multiple_fingerprinters(self):
        """Test that multiple fingerprinters can process packets without errors."""
        # JA4H should process HTTP request
        ja4h_fp = self.ja4h.process_packet(self.http_request)
        self.assertIsNotNone(ja4h_fp, "JA4H should fingerprint HTTP request")

        # JA4T should process SYN packet
        ja4t_fp = self.ja4t.process_packet(self.syn_packet)
        self.assertIsNotNone(ja4t_fp, "JA4T should fingerprint SYN packet")

        # JA4TS should process SYN-ACK packet
        ja4ts_fp = self.ja4ts.process_packet(self.synack_packet)
        self.assertIsNotNone(ja4ts_fp, "JA4TS should fingerprint SYN-ACK packet")

    def test_ja4t_ja4ts_together(self):
        """Test JA4T and JA4TS fingerprinting a TCP handshake."""
        ja4t_fp = self.ja4t.process_packet(self.syn_packet)
        ja4ts_fp = self.ja4ts.process_packet(self.synack_packet)

        self.assertIsNotNone(ja4t_fp)
        self.assertIsNotNone(ja4ts_fp)

        # JA4T and JA4TS have same format: window_options_mss_wscale
        for fp in [ja4t_fp, ja4ts_fp]:
            parts = fp.split("_")
            self.assertEqual(len(parts), 4, f"Fingerprint {fp} has wrong format")

        print(f"JA4T:  {ja4t_fp}")
        print(f"JA4TS: {ja4ts_fp}")

        # They should be different (client vs server)
        self.assertNotEqual(ja4t_fp, ja4ts_fp)

    def test_tls_client_hello_raw(self):
        """Test JA4 with a raw TLS ClientHello packet."""
        # Build a proper TLS ClientHello
        client_hello = bytearray()
        client_hello += b"\x03\x03"  # TLS 1.2
        client_hello += b"\x00" * 32  # Random
        client_hello += b"\x00"  # Session ID length
        # Cipher suites: TLS_AES_128_GCM, TLS_AES_256_GCM, ECDHE_RSA_AES_128
        client_hello += b"\x00\x06"
        client_hello += b"\x13\x01\x13\x02\xc0\x2f"
        client_hello += b"\x01\x00"  # Compression

        # Extensions
        ext_data = bytearray()
        # SNI extension (0x0000)
        sni_hostname = b"example.com"
        sni_entry = b"\x00" + len(sni_hostname).to_bytes(2, "big") + sni_hostname
        sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
        ext_data += b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list

        # supported_versions (0x002b) with TLS 1.3
        sv_list = b"\x02\x03\x04"  # length=2, TLS 1.3
        ext_data += b"\x00\x2b" + len(sv_list).to_bytes(2, "big") + sv_list

        # ALPN (0x0010) with h2
        alpn_proto = b"\x02h2"  # length=2, "h2"
        alpn_list = len(alpn_proto).to_bytes(2, "big") + alpn_proto
        ext_data += b"\x00\x10" + len(alpn_list).to_bytes(2, "big") + alpn_list

        # signature_algorithms (0x000d)
        sig_algs = b"\x00\x04\x04\x03\x08\x04"  # length=4, two algorithms
        ext_data += b"\x00\x0d" + len(sig_algs).to_bytes(2, "big") + sig_algs

        client_hello += len(ext_data).to_bytes(2, "big") + ext_data

        # Wrap in handshake + record
        handshake = b"\x01" + len(client_hello).to_bytes(3, "big") + client_hello
        record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

        packet = (
            IP(src="192.168.1.100", dst="93.184.216.34")
            / TCP(sport=54321, dport=443)
            / Raw(load=bytes(record))
        )

        fingerprint = self.ja4.process_packet(packet)
        self.assertIsNotNone(fingerprint, "JA4 should fingerprint raw ClientHello")
        print(f"JA4 from raw packet: {fingerprint}")

        parts = fingerprint.split("_")
        self.assertEqual(len(parts), 3)

        # Should detect TLS 1.3 from supported_versions
        self.assertTrue(parts[0].startswith("t13"), f"Expected TLS 1.3, got {parts[0]}")
        # Should detect SNI present
        self.assertIn("d", parts[0])

    def test_non_tls_ignored(self):
        """Test that non-TLS packets are properly ignored by TLS fingerprinters."""
        random_data = IP() / TCP(sport=12345, dport=443) / Raw(load=b"not tls data")
        self.assertIsNone(self.ja4.process_packet(random_data))
        self.assertIsNone(self.ja4s.process_packet(random_data))

    def test_all_fingerprinters_reset(self):
        """Test that all fingerprinters reset properly."""
        for fp in [self.ja4, self.ja4s, self.ja4h, self.ja4l, self.ja4t, self.ja4ts]:
            fp.reset()
            self.assertEqual(len(fp.get_fingerprints()), 0)


if __name__ == "__main__":
    unittest.main()
