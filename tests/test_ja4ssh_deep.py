"""
Deep tests for JA4SSH (SSH Traffic) fingerprinting.

Covers packet mode calculation, client/server ratios, ACK ratios,
HASSH extraction from KEXINIT, session type interpretation,
connection tracking, and the fingerprinter class interface.
"""

import unittest
import hashlib
import time
from scapy.all import IP, TCP, Raw, Ether

from ja4plus.fingerprinters.ja4ssh import (
    JA4SSHFingerprinter,
    generate_ja4ssh,
)
from ja4plus.utils.ssh_utils import (
    is_ssh_packet,
    parse_ssh_packet,
    extract_hassh,
)


def _ssh_banner(src, dst, sport, dport, banner):
    """Build an SSH banner packet."""
    return (Ether() / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport)
            / Raw(load=banner))


def _ssh_data(src, dst, sport, dport, size):
    """Build an SSH data packet with specified payload size."""
    return (Ether() / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport)
            / Raw(load=b"SSH-2.0-" + b"X" * (size - 8)))


def _kexinit_packet(src, dst, sport, dport, kex="curve25519-sha256",
                     enc="aes128-ctr", mac="hmac-sha2-256", comp="none"):
    """Build a simplified KEXINIT packet."""
    payload = (b"\x00\x00\x05\xdc\x06\x14AAAAAAAAAA"
               b"SSH_MSG_KEXINIT" +
               f"{kex};{enc};{mac};{comp}".encode())
    return (Ether() / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport)
            / Raw(load=payload))


class TestJA4SSHInteractiveSession(unittest.TestCase):
    """Test fingerprinting of interactive SSH sessions."""

    def test_interactive_session_fingerprint(self):
        """Interactive session: small equal-sized packets, balanced ratio."""
        fp = JA4SSHFingerprinter(packet_count=10)

        # Banners
        fp.process_packet(_ssh_banner("10.0.0.1", "10.0.0.2", 52416, 22,
                                       b"SSH-2.0-OpenSSH_8.2p1\r\n"))
        fp.process_packet(_ssh_banner("10.0.0.2", "10.0.0.1", 22, 52416,
                                       b"SSH-2.0-OpenSSH_7.6p1\r\n"))

        # Interactive data: 36-byte packets (SSH-2.0- + 28 bytes)
        result = None
        for i in range(20):
            r = fp.process_packet(_ssh_data("10.0.0.1", "10.0.0.2", 52416, 22, 36))
            if r:
                result = r
                break
            r = fp.process_packet(_ssh_data("10.0.0.2", "10.0.0.1", 22, 52416, 36))
            if r:
                result = r
                break

        self.assertIsNotNone(result, "Should generate fingerprint for interactive session")
        # Should contain 'c' and 's' for client/server modes
        self.assertIn("c", result)
        self.assertIn("s", result)


class TestJA4SSHFileTransfer(unittest.TestCase):
    """Test fingerprinting of SSH file transfer sessions."""

    def test_download_large_server_packets(self):
        """File download: server sends large packets."""
        fp = JA4SSHFingerprinter(packet_count=10)

        fp.process_packet(_ssh_banner("10.0.0.1", "10.0.0.2", 52416, 22,
                                       b"SSH-2.0-OpenSSH_8.2p1\r\n"))
        fp.process_packet(_ssh_banner("10.0.0.2", "10.0.0.1", 22, 52416,
                                       b"SSH-2.0-OpenSSH_7.6p1\r\n"))

        result = None
        for i in range(20):
            r = fp.process_packet(_ssh_data("10.0.0.2", "10.0.0.1", 22, 52416, 1460))
            if r:
                result = r
                break

        self.assertIsNotNone(result, "Should generate fingerprint for file transfer")


class TestJA4SSHInterpretation(unittest.TestCase):
    """Test fingerprint interpretation."""

    def setUp(self):
        self.fp = JA4SSHFingerprinter()

    def test_interactive_interpretation(self):
        result = self.fp.interpret_fingerprint("c36s36_c50s50_c70s30")
        self.assertEqual(result["session_type"], "Interactive SSH Session")
        self.assertIn("details", result)

    def test_file_transfer_download(self):
        result = self.fp.interpret_fingerprint("c36s1460_c10s90_c50s50")
        self.assertEqual(result["session_type"], "SSH File Transfer")

    def test_file_transfer_upload(self):
        result = self.fp.interpret_fingerprint("c1460s36_c90s10_c50s50")
        self.assertEqual(result["session_type"], "SSH File Transfer (Upload)")

    def test_reverse_ssh(self):
        result = self.fp.interpret_fingerprint("c100s100_c50s50_c30s70")
        self.assertEqual(result["session_type"], "Reverse SSH Session")

    def test_unknown_pattern(self):
        result = self.fp.interpret_fingerprint("c500s500_c50s50_c50s50")
        self.assertIn("session_type", result)

    def test_invalid_format(self):
        result = self.fp.interpret_fingerprint("invalid")
        self.assertIn("error", result)

    def test_detail_extraction(self):
        result = self.fp.interpret_fingerprint("c36s36_c50s50_c70s30")
        details = result["details"]
        self.assertEqual(details["packet_sizes"]["client"], 36)
        self.assertEqual(details["packet_sizes"]["server"], 36)
        self.assertEqual(details["ssh_ratio"]["client"], 50)
        self.assertEqual(details["ssh_ratio"]["server"], 50)
        self.assertEqual(details["ack_ratio"]["client"], 70)
        self.assertEqual(details["ack_ratio"]["server"], 30)


class TestJA4SSHHASSSExtraction(unittest.TestCase):
    """Test HASSH extraction from KEXINIT packets."""

    def test_hassh_from_generate_ja4ssh(self):
        """generate_ja4ssh should extract HASSH from KEXINIT."""
        packet = _kexinit_packet("10.0.0.1", "10.0.0.2", 52416, 22)
        result = generate_ja4ssh(packet)
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("hassh-client_"))

    def test_server_hassh(self):
        """Server KEXINIT should produce hassh-server."""
        packet = _kexinit_packet("10.0.0.2", "10.0.0.1", 22, 52416)
        result = generate_ja4ssh(packet)
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("hassh-server_"))

    def test_hassh_value_is_md5(self):
        """HASSH should be 32-char hex MD5."""
        packet = _kexinit_packet("10.0.0.1", "10.0.0.2", 52416, 22)
        result = generate_ja4ssh(packet)
        hassh_value = result.split("_")[1]
        self.assertEqual(len(hassh_value), 32)
        self.assertTrue(all(c in "0123456789abcdef" for c in hassh_value))

    def test_hassh_matches_manual_computation(self):
        """Verify HASSH value against manual MD5 computation."""
        kex = "curve25519-sha256"
        enc = "aes128-ctr"
        mac = "hmac-sha2-256"
        comp = "none"
        packet = _kexinit_packet("10.0.0.1", "10.0.0.2", 52416, 22,
                                  kex=kex, enc=enc, mac=mac, comp=comp)
        result = generate_ja4ssh(packet)
        hassh_value = result.split("_")[1]

        expected_str = f"{kex};{enc};{mac};{comp}"
        expected = hashlib.md5(expected_str.encode()).hexdigest()
        self.assertEqual(hassh_value, expected)

    def test_different_algorithms_different_hassh(self):
        """Different algorithm sets should produce different HASSH."""
        pkt_a = _kexinit_packet("10.0.0.1", "10.0.0.2", 52416, 22,
                                 kex="curve25519-sha256", enc="aes128-ctr")
        pkt_b = _kexinit_packet("10.0.0.1", "10.0.0.2", 52416, 22,
                                 kex="diffie-hellman-group14-sha256", enc="aes256-ctr")
        result_a = generate_ja4ssh(pkt_a)
        result_b = generate_ja4ssh(pkt_b)
        self.assertNotEqual(result_a, result_b)


class TestJA4SSHHASSSDatabase(unittest.TestCase):
    """Test HASSH database lookup."""

    def setUp(self):
        self.fp = JA4SSHFingerprinter()

    def test_known_cyberduck(self):
        result = self.fp.lookup_hassh("8a8ae540028bf433cd68356c1b9e8d5b")
        self.assertIn("CyberDuck", result["identified_as"])

    def test_known_openssh(self):
        result = self.fp.lookup_hassh("06046964c022c6407d15a27b12a6a4fb")
        self.assertIn("OpenSSH", result["identified_as"])

    def test_known_dropbear(self):
        result = self.fp.lookup_hassh("16f898dd8ed8279e1055350b4e20666c")
        self.assertIn("Dropbear", result["identified_as"])

    def test_known_paramiko(self):
        result = self.fp.lookup_hassh("b5752e36ba6c5979a575e43178908adf")
        self.assertIn("Paramiko", result["identified_as"])

    def test_unknown_hassh(self):
        result = self.fp.lookup_hassh("0000000000000000000000000000dead")
        self.assertEqual(result["identified_as"], "Unknown")
        self.assertIsNone(result["source"])


class TestJA4SSHConnectionTracking(unittest.TestCase):
    """Test connection tracking across packets."""

    def test_multiple_connections_tracked_separately(self):
        fp = JA4SSHFingerprinter(packet_count=5)

        # Connection 1
        fp.process_packet(_ssh_banner("10.0.0.1", "10.0.0.2", 52416, 22,
                                       b"SSH-2.0-OpenSSH_8.2p1\r\n"))
        # Connection 2
        fp.process_packet(_ssh_banner("10.0.0.3", "10.0.0.4", 52417, 22,
                                       b"SSH-2.0-OpenSSH_8.2p1\r\n"))

        self.assertEqual(len(fp.connections), 2)

    def test_hassh_collected_via_fingerprinter(self):
        """HASSH should be collected in connection tracking."""
        fp = JA4SSHFingerprinter(packet_count=100)

        fp.process_packet(_ssh_banner("10.0.0.1", "10.0.0.2", 52416, 22,
                                       b"SSH-2.0-OpenSSH_8.2p1\r\n"))
        fp.process_packet(_kexinit_packet("10.0.0.1", "10.0.0.2", 52416, 22))

        hassh_fps = fp.get_hassh_fingerprints()
        self.assertGreaterEqual(len(hassh_fps), 1)
        self.assertEqual(hassh_fps[0]["type"], "client")


class TestJA4SSHFingerprinterClass(unittest.TestCase):
    """Test JA4SSHFingerprinter class interface."""

    def test_packet_count_parameter(self):
        """Custom packet_count should be respected."""
        fp = JA4SSHFingerprinter(packet_count=50)
        self.assertEqual(fp.packet_count, 50)

    def test_reset(self):
        fp = JA4SSHFingerprinter(packet_count=10)
        fp.process_packet(_ssh_banner("10.0.0.1", "10.0.0.2", 52416, 22,
                                       b"SSH-2.0-OpenSSH_8.2p1\r\n"))
        fp.reset()
        self.assertEqual(len(fp.fingerprints), 0)
        self.assertEqual(len(fp.connections), 0)
        self.assertEqual(len(fp.hassh_fingerprints), 0)

    def test_non_ssh_ignored(self):
        """Non-SSH packets should be ignored."""
        fp = JA4SSHFingerprinter(packet_count=10)
        packet = (Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
                  / TCP(sport=12345, dport=22)
                  / Raw(load=b"GET / HTTP/1.1\r\n\r\n"))
        result = fp.process_packet(packet)
        self.assertIsNone(result)

    def test_no_raw_layer_ignored(self):
        """Packet without Raw layer should return None."""
        fp = JA4SSHFingerprinter(packet_count=10)
        packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=52416, dport=22)
        result = fp.process_packet(packet)
        self.assertIsNone(result)

    def test_no_tcp_ignored(self):
        """Packet without TCP should return None."""
        fp = JA4SSHFingerprinter(packet_count=10)
        from scapy.all import UDP
        packet = (Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
                  / UDP(sport=52416, dport=22)
                  / Raw(load=b"SSH-2.0-test\r\n"))
        result = fp.process_packet(packet)
        self.assertIsNone(result)


class TestJA4SSHFormat(unittest.TestCase):
    """Test JA4SSH fingerprint format: cXsY_cXsY_cXsY."""

    def test_format_three_parts(self):
        fp = JA4SSHFingerprinter(packet_count=5)

        fp.process_packet(_ssh_banner("10.0.0.1", "10.0.0.2", 52416, 22,
                                       b"SSH-2.0-OpenSSH_8.2p1\r\n"))
        fp.process_packet(_ssh_banner("10.0.0.2", "10.0.0.1", 22, 52416,
                                       b"SSH-2.0-OpenSSH_7.6p1\r\n"))

        result = None
        for i in range(20):
            r = fp.process_packet(_ssh_data("10.0.0.1", "10.0.0.2", 52416, 22, 36))
            if r:
                result = r
                break
            r = fp.process_packet(_ssh_data("10.0.0.2", "10.0.0.1", 22, 52416, 36))
            if r:
                result = r
                break

        if result:
            parts = result.split("_")
            self.assertEqual(len(parts), 3, f"Expected 3 parts, got {result}")
            for part in parts:
                self.assertTrue(part.startswith("c"), f"Part should start with 'c': {part}")
                self.assertIn("s", part, f"Part should contain 's': {part}")


if __name__ == "__main__":
    unittest.main()
