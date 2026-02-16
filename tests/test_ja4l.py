import unittest
import time
from scapy.all import IP, TCP, Raw
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter, generate_ja4l


class TestJA4L(unittest.TestCase):
    def setUp(self):
        self.ja4l_fp = JA4LFingerprinter()

        # Create test packets for a TCP handshake
        self.syn_packet = IP(src="192.168.1.100", dst="93.184.216.34", ttl=128) / TCP(
            sport=54321, dport=443, flags="S"
        )
        self.synack_packet = IP(src="93.184.216.34", dst="192.168.1.100", ttl=64) / TCP(
            sport=443, dport=54321, flags="SA"
        )
        self.ack_packet = IP(src="192.168.1.100", dst="93.184.216.34", ttl=128) / TCP(
            sport=54321, dport=443, flags="A"
        )

    def test_ja4l_direct_generation(self):
        """Test JA4L with direct conn dict providing timestamps."""
        # Simulate timestamps from a real handshake
        now = time.time()
        conn = {
            'proto': 'tcp',
            'timestamps': {
                'A': now - 0.050,  # SYN 50ms ago
                'B': now - 0.020,  # SYN-ACK 20ms ago
            },
            'ttls': {
                'client': 128,
                'server': 64,
            },
        }

        # SYN-ACK generates server fingerprint - but only if timestamps A exists
        # and we're processing a SYN-ACK packet
        ja4l_server = generate_ja4l(self.synack_packet, conn)
        print(f"JA4L Server fingerprint: {ja4l_server}")

        # ACK generates client fingerprint
        ja4l_client = generate_ja4l(self.ack_packet, conn)
        print(f"JA4L Client fingerprint: {ja4l_client}")

        # Server should have generated from the SYN-ACK
        self.assertIsNotNone(ja4l_server, "JA4L server fingerprinting failed")
        self.assertTrue(ja4l_server.startswith("JA4L-S="), "Server fingerprint should start with JA4L-S=")

        # Client should have generated from the ACK
        self.assertIsNotNone(ja4l_client, "JA4L client fingerprinting failed")
        self.assertTrue(ja4l_client.startswith("JA4L-C="), "Client fingerprint should start with JA4L-C=")

        # Both should contain TTL
        self.assertRegex(ja4l_server, r'JA4L-S=\d+_\d+')
        self.assertRegex(ja4l_client, r'JA4L-C=\d+_\d+')

    def test_ja4l_fingerprinter_class(self):
        """Test the JA4LFingerprinter class processes handshake correctly."""
        # Process the packets in order - these happen in real time
        result_syn = self.ja4l_fp.process_packet(self.syn_packet)
        self.assertIsNone(result_syn, "SYN should not generate fingerprint")

        # Small delay to ensure non-zero latency
        time.sleep(0.001)
        result_synack = self.ja4l_fp.process_packet(self.synack_packet)
        self.assertIsNotNone(result_synack, "SYN-ACK should generate server fingerprint")
        self.assertTrue(result_synack.startswith("JA4L-S="))

        time.sleep(0.001)
        result_ack = self.ja4l_fp.process_packet(self.ack_packet)
        self.assertIsNotNone(result_ack, "ACK should generate client fingerprint")
        self.assertTrue(result_ack.startswith("JA4L-C="))

        # Should have collected 2 fingerprints
        self.assertEqual(len(self.ja4l_fp.fingerprints), 2)
        print(f"Collected fingerprints:")
        for fp in self.ja4l_fp.fingerprints:
            print(f"  - {fp['fingerprint']}")

    def test_ja4l_distance_calculation(self):
        """Test distance calculation from latency."""
        # 1000 us = 1ms latency
        distance_miles = self.ja4l_fp.calculate_distance(1000)
        self.assertGreater(distance_miles, 0)
        # 1000us * 0.128 / 1.6 = 80 miles
        self.assertAlmostEqual(distance_miles, 80.0, places=1)

        distance_km = self.ja4l_fp.calculate_distance_km(1000)
        self.assertGreater(distance_km, 0)

    def test_ja4l_os_estimation(self):
        """Test OS estimation from TTL."""
        self.assertIn("Windows", self.ja4l_fp.estimate_os(120))
        self.assertIn("Linux", self.ja4l_fp.estimate_os(60))
        self.assertIn("Cisco", self.ja4l_fp.estimate_os(250))

    def test_ja4l_hop_count(self):
        """Test hop count estimation."""
        self.assertEqual(self.ja4l_fp.estimate_hop_count(120), 8)  # 128 - 120
        self.assertEqual(self.ja4l_fp.estimate_hop_count(60), 4)   # 64 - 60
        self.assertEqual(self.ja4l_fp.estimate_hop_count(250), 5)  # 255 - 250


if __name__ == "__main__":
    unittest.main(verbosity=2)
