import unittest
from scapy.all import IP, TCP
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter, generate_ja4t

class TestJA4T(unittest.TestCase):
    def setUp(self):
        """Set up test cases"""
        print("\nSetting up JA4T test cases...")
        self.ja4t = JA4TFingerprinter()
        
        # Create a mock TCP packet with typical Chrome/Windows values
        self.tcp_packet = IP()/TCP(
            window=65535,
            options=[
                ('NOP', None),           # 1
                ('MSS', 1460),           # 2
                ('WScale', 7),           # 3
                ('SAckOK', ''),          # 4
                ('Timestamp', (0,0))     # 8
            ]
        )
        print(f"Created test packet with window size {self.tcp_packet[TCP].window}")

    def test_ja4t_format(self):
        """Test JA4T fingerprint format"""
        print("\nTesting JA4T fingerprint format...")
        fingerprint = generate_ja4t(self.tcp_packet)
        print(f"Generated fingerprint: {fingerprint}")
        self.assertIsNotNone(fingerprint)

        # Check format: window_options_mss_wscale
        parts = fingerprint.split('_')
        self.assertEqual(len(parts), 4)

        # Check values - options preserve original packet order per JA4T spec
        self.assertEqual(parts[0], '65535')  # Window size
        self.assertEqual(parts[1], '1-2-3-4-8')  # Options in original order (NOP,MSS,WScale,SAckOK,Timestamp)
        self.assertEqual(parts[2], '1460')  # MSS
        self.assertEqual(parts[3], '7')  # Window scale
        print("Format test passed")

    def test_different_window_sizes(self):
        """Test different window sizes"""
        print("\nTesting different window sizes...")
        packets = [
            (IP()/TCP(window=65535), '65535'),
            (IP()/TCP(window=29200), '29200'),
            (IP()/TCP(window=16384), '16384')
        ]
        
        for packet, expected in packets:
            fingerprint = generate_ja4t(packet)
            print(f"Window size {expected} -> {fingerprint}")
            self.assertTrue(fingerprint.startswith(expected))
        print("✓ Window size test passed")

    def test_option_ordering(self):
        """Test TCP option ordering preserves original order per JA4T spec"""
        print("\nTesting TCP option ordering...")
        # Test with options in a specific order - JA4T preserves original order
        options = [
            ('MSS', 1460),
            ('NOP', None),
            ('WScale', 7),
            ('SAckOK', ''),
            ('Timestamp', (0,0))
        ]

        packet = IP()/TCP(window=65535, options=options)
        fingerprint = generate_ja4t(packet)
        print(f"Options in original order -> {fingerprint}")

        # Options should preserve original order: MSS(2), NOP(1), WScale(3), SAckOK(4), Timestamp(8)
        self.assertTrue('2-1-3-4-8' in fingerprint)
        print("Option ordering test passed")

    def test_fingerprinter_class(self):
        """Test the JA4TFingerprinter class"""
        print("\nTesting JA4TFingerprinter class...")
        
        # Process a packet
        fingerprint = self.ja4t.process_packet(self.tcp_packet)
        print(f"Processed fingerprint: {fingerprint}")
        self.assertIsNotNone(fingerprint)
        
        # Check stored fingerprints
        stored = self.ja4t.get_fingerprints()
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]['fingerprint'], fingerprint)
        
        # Test reset
        self.ja4t.reset()
        self.assertEqual(len(self.ja4t.get_fingerprints()), 0)
        print("✓ Fingerprinter class test passed")

if __name__ == '__main__':
    unittest.main(verbosity=2) 