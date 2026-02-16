import unittest
import sys
import os

# Add the parent directory to the path to ensure imports work correctly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scapy.all import IP, TCP, Raw
from ja4plus.fingerprinters.ja4 import JA4Fingerprinter, generate_ja4
from ja4plus.utils.tls_utils import extract_tls_info

class TestJA4(unittest.TestCase):
    def setUp(self):
        self.ja4_fp = JA4Fingerprinter()
    
    def test_basic_functionality(self):
        """Test basic fingerprinter functionality"""
        # Just make sure it initializes properly
        self.assertIsNotNone(self.ja4_fp)
        self.assertEqual(len(self.ja4_fp.fingerprints), 0)
    
    def test_client_hello_fingerprint(self):
        """Test fingerprinting a TLS ClientHello"""
        # Create a sample ClientHello packet
        client_hello_packet = create_client_hello_packet()
        
        # Debug: Print tls_info attribute to verify it exists
        print(f"DEBUG: Does packet have tls_info? {hasattr(client_hello_packet, 'tls_info')}")
        if hasattr(client_hello_packet, 'tls_info'):
            print(f"DEBUG: tls_info keys: {client_hello_packet.tls_info.keys()}")
        
        # Ensure our packet has the tls_info attribute properly set
        self.assertTrue(hasattr(client_hello_packet, 'tls_info'), 
                      "Test packet missing tls_info attribute")
        
        # Generate fingerprint
        fingerprint = self.ja4_fp.process_packet(client_hello_packet)
        
        # Check that we got a fingerprint
        self.assertIsNotNone(fingerprint, "Failed to generate JA4 fingerprint")
        print(f"DEBUG: Generated fingerprint: {fingerprint}")
        
        # JA4 format is t[ver][sni][ciphercount][extcount][alpn]_[hash of ciphers]_[hash of extensions]
        parts = fingerprint.split('_')
        self.assertEqual(len(parts), 3, "JA4 fingerprint has incorrect format")
        
        # First part should start with 't'
        self.assertTrue(parts[0].startswith('t'), "JA4 version part doesn't start with 't'")
        
        # Since we have TLS 1.3 in supported_versions, it should use that value instead of TLS 1.2
        self.assertTrue('13' in parts[0], "JA4 version should be '13' when TLS 1.3 is in supported_versions")
        
        # Check if the fingerprinter collected this fingerprint
        self.assertEqual(len(self.ja4_fp.fingerprints), 1, "Fingerprinter didn't collect the fingerprint")

def create_client_hello_packet():
    """Create a sample TLS ClientHello packet for testing."""
    # Create a packet with embedded TLS info for testing
    packet = IP()/TCP()
    
    # Add TLS info directly for testing
    packet.tls_info = {
        'type': 'client_hello',
        'version': 0x0303,  # TLS 1.2
        'is_quic': False,
        'is_dtls': False,
        'supported_versions': [0x0304],  # TLS 1.3
        'sni': 'example.com',
        'ciphers': [0x1301, 0x1302, 0x1303, 0xc02f, 0xc02b],
        'extensions': [0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x0023],
        'alpn_protocols': ['h2', 'http/1.1'],
        'signature_algorithms': [0x0403, 0x0804, 0x0401, 0x0503]
    }
    
    return packet

if __name__ == '__main__':
    unittest.main() 