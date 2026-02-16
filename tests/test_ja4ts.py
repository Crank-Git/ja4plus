import unittest
from scapy.all import IP, TCP, Raw
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter, generate_ja4ts

class TestJA4TS(unittest.TestCase):
    def setUp(self):
        """Set up test cases."""
        self.ja4ts_fp = JA4TSFingerprinter()
        
        # Create sample SYN-ACK packets based on real server responses
        
        # F5 BIG-IP response to Windows 10
        self.bigip_to_win = IP()/TCP(
            flags='SA',  # SYN-ACK
            window=14600,
            options=[
                ('MSS', 1460),
                ('NOP', None),
                ('WScale', 0),
                ('SAckOK', b''),
                ('NOP', None),
                ('NOP', None)
            ]
        )
        
        # F5 BIG-IP response to Linux
        self.bigip_to_linux = IP()/TCP(
            flags='SA',  # SYN-ACK
            window=14600,
            options=[
                ('MSS', 1460),
                ('NOP', None),
                ('WScale', 0),
                ('SAckOK', b''),
                ('Timestamp', (0, 0))
            ]
        )
        
        # F5 BIG-IP response to Linux Proxy
        self.bigip_to_proxy = IP()/TCP(
            flags='SA',  # SYN-ACK
            window=13960,
            options=[
                ('MSS', 1460),
                ('NOP', None),
                ('WScale', 0),
                ('SAckOK', b''),
                ('Timestamp', (0, 0))
            ]
        )
        
    def test_bigip_responses(self):
        """Test F5 BIG-IP server responses."""
        print("\nTesting F5 BIG-IP responses...")
        
        # Test response to Windows 10
        fp = generate_ja4ts(self.bigip_to_win)
        print(f"BIG-IP -> Windows 10: {fp}")
        self.assertEqual(fp, "14600_2-1-3-4-1-1_1460_0", 
                        "Incorrect fingerprint for BIG-IP response to Windows")
        
        # Test response to Linux
        fp = generate_ja4ts(self.bigip_to_linux)
        print(f"BIG-IP -> Linux: {fp}")
        self.assertEqual(fp, "14600_2-1-3-4-8_1460_0",
                        "Incorrect fingerprint for BIG-IP response to Linux")
        
        # Test response to Linux Proxy
        fp = generate_ja4ts(self.bigip_to_proxy)
        print(f"BIG-IP -> Linux Proxy: {fp}")
        self.assertEqual(fp, "13960_2-1-3-4-8_1460_0",
                        "Incorrect fingerprint for BIG-IP response to Proxy")
    
    def test_fingerprinter_collection(self):
        """Test that fingerprinter collects fingerprints correctly."""
        print("\nTesting fingerprint collection...")
        
        # Process all test packets
        self.ja4ts_fp.process_packet(self.bigip_to_win)
        self.ja4ts_fp.process_packet(self.bigip_to_linux)
        self.ja4ts_fp.process_packet(self.bigip_to_proxy)
        
        # Check collected fingerprints
        fingerprints = self.ja4ts_fp.get_fingerprints()
        self.assertEqual(len(fingerprints), 3, 
                        "Should have collected 3 fingerprints")
        
        # Print collected fingerprints
        for fp in fingerprints:
            print(f"Collected: {fp['fingerprint']}")
    
    def test_non_synack_packets(self):
        """Test that non-SYN-ACK packets are ignored."""
        print("\nTesting non-SYN-ACK packet handling...")
        
        # Create a non-SYN-ACK packet
        regular_packet = IP()/TCP(
            flags='A',  # ACK only
            window=14600,
            options=[('MSS', 1460)]
        )
        
        fp = generate_ja4ts(regular_packet)
        self.assertIsNone(fp, "Should ignore non-SYN-ACK packets")
        print("Successfully ignored non-SYN-ACK packet")

    def test_large_mss(self):
        """Test handling of large MSS values - all values recorded as-is per spec."""
        pkt = IP()/TCP(
            flags='SA',  # SYN-ACK
            window=22000,
            options=[
                ('MSS', 65495),
                ('NOP', None),
                ('WScale', 7)
            ]
        )

        fp = generate_ja4ts(pkt)
        self.assertEqual(fp, "22000_2-1-3_65495_7",
                        "All MSS values should be recorded as-is per spec")

if __name__ == '__main__':
    unittest.main() 