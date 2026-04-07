"""Tests that fingerprinters work with IPv6 packets."""

import unittest
import time
from scapy.all import IPv6, IP, TCP, UDP, Raw


def _build_tls_client_hello():
    ch = bytearray()
    ch += (0x0303).to_bytes(2, "big")
    ch += b"\x00" * 32
    ch += b"\x00"
    ch += b"\x00\x02\x13\x01"
    ch += b"\x01\x00"
    hostname = b"test.com"
    sni_entry = b"\x00" + len(hostname).to_bytes(2, "big") + hostname
    sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
    ext_data = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    ch += len(ext_data).to_bytes(2, "big") + ext_data
    hs = b"\x01" + len(ch).to_bytes(3, "big") + bytes(ch)
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


class TestJA4TIPv6(unittest.TestCase):
    def test_ja4t_ipv6(self):
        from ja4plus.fingerprinters.ja4t import generate_ja4t
        pkt = IPv6(src="::1", dst="::2") / TCP(sport=12345, dport=443, flags="S", window=65535, options=[("MSS", 1460)])
        result = generate_ja4t(pkt)
        self.assertIsNotNone(result, "JA4T should work with IPv6")


class TestJA4TSIPv6(unittest.TestCase):
    def test_ja4ts_ipv6(self):
        from ja4plus.fingerprinters.ja4ts import generate_ja4ts
        pkt = IPv6(src="::1", dst="::2") / TCP(sport=443, dport=12345, flags="SA", window=14600, options=[("MSS", 1460)])
        result = generate_ja4ts(pkt)
        self.assertIsNotNone(result, "JA4TS should work with IPv6")


class TestJA4LIPv6(unittest.TestCase):
    def test_ja4l_ipv6_handshake(self):
        from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
        fp = JA4LFingerprinter()
        syn = IPv6(src="::1", dst="::2", hlim=64) / TCP(sport=12345, dport=443, flags="S")
        result = fp.process_packet(syn)
        self.assertIsNone(result)
        time.sleep(0.002)
        synack = IPv6(src="::2", dst="::1", hlim=128) / TCP(sport=443, dport=12345, flags="SA")
        result = fp.process_packet(synack)
        self.assertIsNotNone(result, "JA4L should work with IPv6 SYN-ACK")
        self.assertTrue(result.startswith("JA4L-S="))


class TestJA4SSHIPv6(unittest.TestCase):
    def test_ja4ssh_ipv6(self):
        from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter
        fp = JA4SSHFingerprinter(packet_count=1)
        pkt = IPv6(src="::1", dst="::2") / TCP(sport=12345, dport=22) / Raw(load=b"SSH-2.0-OpenSSH_8.9\r\n")
        result = fp.process_packet(pkt)
        # Should not crash due to missing IP layer — that's the key test


class TestJA4XIPv6(unittest.TestCase):
    def test_ja4x_ipv6_no_crash(self):
        from ja4plus.fingerprinters.ja4x import JA4XFingerprinter
        fp = JA4XFingerprinter()
        pkt = IPv6(src="::1", dst="::2") / TCP(sport=12345, dport=443, seq=100) / Raw(load=b"\x16\x03\x01\x00\x05\x0b\x00\x00\x01\x00")
        result = fp.process_packet(pkt)
        # May return None (not enough data), but must not crash


if __name__ == "__main__":
    unittest.main()
