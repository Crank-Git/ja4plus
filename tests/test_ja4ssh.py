import unittest
import time
from scapy.all import IP, TCP, Raw, Ether
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter, generate_ja4ssh


class TestJA4SSH(unittest.TestCase):
    def setUp(self):
        self.ja4ssh_fp = JA4SSHFingerprinter(packet_count=10)

        # SSH Banner packets
        self.ssh_client_banner = (
            Ether()
            / IP(src="192.168.1.100", dst="192.168.1.200")
            / TCP(sport=52416, dport=22)
            / Raw(load=b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4\r\n")
        )
        self.ssh_server_banner = (
            Ether()
            / IP(src="192.168.1.200", dst="192.168.1.100")
            / TCP(sport=22, dport=52416)
            / Raw(load=b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n")
        )

        # SSH KEXINIT packets (simplified test format)
        self.ssh_client_kexinit = (
            Ether()
            / IP(src="192.168.1.100", dst="192.168.1.200")
            / TCP(sport=52416, dport=22)
            / Raw(
                load=b"\x00\x00\x05\xdc\x06\x14AAAAAAAAAASSH_MSG_KEXINIT"
                b"curve25519-sha256@libssh.org,ecdh-sha2-nistp256;"
                b"aes128-ctr,aes256-ctr;hmac-sha1,hmac-sha2-256;none"
            )
        )
        self.ssh_server_kexinit = (
            Ether()
            / IP(src="192.168.1.200", dst="192.168.1.100")
            / TCP(sport=22, dport=52416)
            / Raw(
                load=b"\x00\x00\x05\xdc\x06\x14AAAAAAAAAASSH_MSG_KEXINIT"
                b"curve25519-sha256@libssh.org;"
                b"aes128-ctr,aes256-ctr;hmac-sha2-256;none"
            )
        )

        # Interactive session packets (36-byte payloads = SSH encrypted data)
        self.interactive_packets = []
        for i in range(20):
            # Client sends command (36 bytes) - use SSH banner prefix so is_ssh_packet detects them
            self.interactive_packets.append(
                Ether()
                / IP(src="192.168.1.100", dst="192.168.1.200")
                / TCP(sport=52416, dport=22)
                / Raw(load=b"SSH-2.0-" + b"A" * 28)
            )
            # Server responds (36 bytes)
            self.interactive_packets.append(
                Ether()
                / IP(src="192.168.1.200", dst="192.168.1.100")
                / TCP(sport=22, dport=52416)
                / Raw(load=b"SSH-2.0-" + b"B" * 28)
            )

        # File transfer packets (large server payloads)
        self.file_transfer_packets = []
        for i in range(20):
            self.file_transfer_packets.append(
                Ether()
                / IP(src="192.168.1.200", dst="192.168.1.100")
                / TCP(sport=22, dport=52416)
                / Raw(load=b"SSH-2.0-" + b"C" * 1452)
            )

    def test_hassh_extraction(self):
        """Test HASSH extraction from KEXINIT packets."""
        # Process banner packets first
        self.ja4ssh_fp.process_packet(self.ssh_client_banner)
        self.ja4ssh_fp.process_packet(self.ssh_server_banner)

        # Use generate_ja4ssh for HASSH extraction
        client_fp = generate_ja4ssh(self.ssh_client_kexinit)
        server_fp = generate_ja4ssh(self.ssh_server_kexinit)

        print(f"Client HASSH fingerprint: {client_fp}")
        print(f"Server HASSH fingerprint: {server_fp}")

        self.assertIsNotNone(client_fp, "Failed to extract client HASSH")
        self.assertIsNotNone(server_fp, "Failed to extract server HASSH")

        # Verify format
        self.assertTrue(
            client_fp.startswith("hassh-client_"),
            f"Client HASSH has wrong format: {client_fp}",
        )
        self.assertTrue(
            server_fp.startswith("hassh-server_"),
            f"Server HASSH has wrong format: {server_fp}",
        )

    def test_ja4ssh_interactive_session(self):
        """Test JA4SSH fingerprinting for an interactive SSH session."""
        # Process initial handshake
        self.ja4ssh_fp.process_packet(self.ssh_client_banner)
        self.ja4ssh_fp.process_packet(self.ssh_server_banner)

        # Process interactive session packets
        fp = None
        for packet in self.interactive_packets:
            result = self.ja4ssh_fp.process_packet(packet)
            if result:
                fp = result
                print(f"JA4SSH fingerprint: {fp}")
                break

        self.assertIsNotNone(fp, "No JA4SSH fingerprint generated for interactive session")
        self.assertGreaterEqual(len(self.ja4ssh_fp.fingerprints), 1)

        # Interpret the fingerprint
        interpretation = self.ja4ssh_fp.interpret_fingerprint(fp)
        print(f"Interpretation: {interpretation['session_type']}")

    def test_ja4ssh_file_transfer(self):
        """Test JA4SSH fingerprinting for SSH file transfer."""
        self.ja4ssh_fp.reset()

        # Process initial handshake
        self.ja4ssh_fp.process_packet(self.ssh_client_banner)
        self.ja4ssh_fp.process_packet(self.ssh_server_banner)

        # Process file transfer packets
        fp = None
        for packet in self.file_transfer_packets:
            result = self.ja4ssh_fp.process_packet(packet)
            if result:
                fp = result
                print(f"JA4SSH file transfer fingerprint: {fp}")
                break

        self.assertIsNotNone(fp, "No JA4SSH fingerprints generated for file transfer")
        self.assertGreaterEqual(len(self.ja4ssh_fp.fingerprints), 1)

    def test_hassh_database(self):
        """Test HASSH database lookup for known fingerprints."""
        common_hassh_values = [
            ("8a8ae540028bf433cd68356c1b9e8d5b", "CyberDuck"),
            ("06046964c022c6407d15a27b12a6a4fb", "OpenSSH 7.6"),
            ("16f898dd8ed8279e1055350b4e20666c", "Dropbear"),
        ]

        for hassh, expected_substr in common_hassh_values:
            lookup_result = self.ja4ssh_fp.lookup_hassh(hassh)
            print(f"HASSH {hassh} identified as: {lookup_result['identified_as']}")
            self.assertNotEqual(
                lookup_result["identified_as"],
                "Unknown",
                f"Failed to identify known HASSH: {hassh}",
            )
            self.assertIn(expected_substr, lookup_result["identified_as"])

    def test_interpret_fingerprint(self):
        """Test fingerprint interpretation."""
        # Interactive session
        result = self.ja4ssh_fp.interpret_fingerprint("c36s36_c50s50_c70s30")
        self.assertEqual(result["session_type"], "Interactive SSH Session")

        # Unknown pattern
        result = self.ja4ssh_fp.interpret_fingerprint("c100s100_c50s50_c50s50")
        self.assertIn("session_type", result)

    def test_reset(self):
        """Test fingerprinter reset."""
        self.ja4ssh_fp.process_packet(self.ssh_client_banner)
        self.ja4ssh_fp.reset()
        self.assertEqual(len(self.ja4ssh_fp.fingerprints), 0)
        self.assertEqual(len(self.ja4ssh_fp.connections), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
