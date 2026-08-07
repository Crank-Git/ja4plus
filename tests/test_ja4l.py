import unittest
import time
from scapy.all import IP, TCP, Raw
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter, generate_ja4l


class TestJA4L(unittest.TestCase):
    def setUp(self):
        self.ja4l_fp = JA4LFingerprinter()

        # Create test packets for a TCP handshake. The client measurement point needs
        # the relative sequence number 1 and the relative acknowledgement number 1, so
        # the packets carry the sequence numbers a real handshake carries.
        self.syn_packet = IP(src="192.168.1.100", dst="93.184.216.34", ttl=128) / TCP(
            sport=54321, dport=443, flags="S", seq=0
        )
        self.synack_packet = IP(src="93.184.216.34", dst="192.168.1.100", ttl=64) / TCP(
            sport=443, dport=54321, flags="SA", seq=0, ack=1
        )
        self.ack_packet = IP(src="192.168.1.100", dst="93.184.216.34", ttl=128) / TCP(
            sport=54321, dport=443, flags="A", seq=1, ack=1
        )

    def test_ja4l_direct_generation(self):
        """Test JA4L with a conn dict the caller supplies."""
        conn = {
            "proto": "tcp",
            "timestamps": {},
            "ttls": {},
            "isns": {},
        }

        # The SYN records the client point, and the SYN-ACK reports the server value.
        self.assertIsNone(generate_ja4l(self.syn_packet, conn))
        ja4l_server = generate_ja4l(self.synack_packet, conn)
        ja4l_client = generate_ja4l(self.ack_packet, conn)

        self.assertIsNotNone(ja4l_server, "JA4L server fingerprinting failed")
        self.assertTrue(
            ja4l_server.startswith("JA4L-S="), "Server fingerprint should start with JA4L-S="
        )

        self.assertIsNotNone(ja4l_client, "JA4L client fingerprinting failed")
        self.assertTrue(
            ja4l_client.startswith("JA4L-C="), "Client fingerprint should start with JA4L-C="
        )

        # Both should contain TTL
        self.assertRegex(ja4l_server, r"JA4L-S=\d+_\d+")
        self.assertRegex(ja4l_client, r"JA4L-C=\d+_\d+")

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
        print("Collected fingerprints:")
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
        self.assertEqual(self.ja4l_fp.estimate_hop_count(60), 4)  # 64 - 60
        self.assertEqual(self.ja4l_fp.estimate_hop_count(250), 5)  # 255 - 250


class TestJA4LPropagationFactor(unittest.TestCase):
    """The propagation factor follows the FoxIO hop-count table.

    The table maps a hop count of 21 or fewer to 1.5, 22 to 1.6, 23 to 1.7, 24 to 1.8,
    25 to 1.9, and 26 or more to 2.0. An initial TTL of 64 gives the hop count
    `64 - ttl`, so each case below names the TTL that implies the hop count it tests.

    Verified against https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4L.png
    (retrieved 2026-08-06).
    """

    def setUp(self):
        self.fingerprinter = JA4LFingerprinter()

    def test_reads_a_different_distance_for_20_hops_and_for_30_hops(self):
        """The table gives 1.5 for 20 hops and 2.0 for 30 hops."""
        twenty_hops = self.fingerprinter.calculate_distance(1000, ttl=44)
        thirty_hops = self.fingerprinter.calculate_distance(1000, ttl=34)

        self.assertNotEqual(twenty_hops, thirty_hops)
        self.assertAlmostEqual(twenty_hops, 1000 * 0.128 / 1.5, places=6)
        self.assertAlmostEqual(thirty_hops, 1000 * 0.128 / 2.0, places=6)

    def test_reads_each_row_of_the_foxio_table(self):
        """Every hop count reads the factor of its row."""
        rows = ((0, 1.5), (21, 1.5), (22, 1.6), (23, 1.7), (24, 1.8), (25, 1.9), (26, 2.0))
        for hop_count, factor in rows:
            with self.subTest(hop_count=hop_count):
                distance = self.fingerprinter.calculate_distance(1000, ttl=64 - hop_count)
                self.assertAlmostEqual(distance, 1000 * 0.128 / factor, places=6)

    def test_reads_the_factor_2_0_for_a_hop_count_above_26(self):
        """A TTL that implies 40 hops reads the last row of the table."""
        distance = self.fingerprinter.calculate_distance(1000, ttl=24)

        self.assertAlmostEqual(distance, 1000 * 0.128 / 2.0, places=6)

    def test_clamps_a_negative_hop_count_to_zero_hops(self):
        """A TTL above 255 implies a negative hop count, and the factor stays 1.5."""
        distance = self.fingerprinter.calculate_distance(1000, ttl=300)

        self.assertAlmostEqual(distance, 1000 * 0.128 / 1.5, places=6)

    def test_an_explicit_propagation_factor_overrides_the_table(self):
        """The caller's factor wins over the row the TTL selects."""
        distance = self.fingerprinter.calculate_distance(1000, ttl=34, propagation_factor=1.6)

        self.assertAlmostEqual(distance, 80.0, places=6)

    def test_keeps_the_factor_1_6_when_the_caller_passes_no_ttl(self):
        """A call without a TTL gives no hop count, so the table cannot answer."""
        self.assertAlmostEqual(self.fingerprinter.calculate_distance(1000), 80.0, places=6)

    def test_reads_the_foxio_table_for_a_distance_in_kilometers(self):
        """The kilometer form reads the same table as the mile form."""
        distance = self.fingerprinter.calculate_distance_km(1000, ttl=34)

        self.assertAlmostEqual(distance, 1000 * 0.206 / 2.0, places=6)


if __name__ == "__main__":
    unittest.main(verbosity=2)
