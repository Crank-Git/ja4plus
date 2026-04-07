"""Tests for JA4SSH client/server direction on non-standard ports."""

import unittest
from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter


class TestSSHDirectionNonStandardPort(unittest.TestCase):

    def test_lower_port_is_server(self):
        """Port 2222 (lower) should be server, 50000 (higher) should be client."""
        fp = JA4SSHFingerprinter(packet_count=1)
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=50000, dport=2222
        ) / Raw(load=b"SSH-2.0-OpenSSH_8.9\r\n")
        fp.process_packet(pkt)
        self.assertEqual(len(fp.connections), 1)
        conn = list(fp.connections.values())[0]
        self.assertEqual(conn["client_ip"], "10.0.0.1",
                         "Higher port (50000) should be client")
        self.assertEqual(conn["server_ip"], "10.0.0.2",
                         "Lower port (2222) should be server")

    def test_standard_port_22_unchanged(self):
        fp = JA4SSHFingerprinter(packet_count=1)
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=50000, dport=22
        ) / Raw(load=b"SSH-2.0-OpenSSH_8.9\r\n")
        fp.process_packet(pkt)
        conn = list(fp.connections.values())[0]
        self.assertEqual(conn["client_ip"], "10.0.0.1")
        self.assertEqual(conn["server_ip"], "10.0.0.2")

    def test_server_to_client_nonstandard(self):
        fp = JA4SSHFingerprinter(packet_count=1)
        pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=50000, dport=2222
        ) / Raw(load=b"SSH-2.0-OpenSSH_8.9\r\n")
        fp.process_packet(pkt1)
        pkt2 = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(
            sport=2222, dport=50000
        ) / Raw(load=b"SSH-2.0-OpenSSH_8.9p1\r\n")
        fp.process_packet(pkt2)
        conn = list(fp.connections.values())[0]
        self.assertIsNotNone(conn["client_id"])
        self.assertIsNotNone(conn["server_id"])


if __name__ == "__main__":
    unittest.main()
