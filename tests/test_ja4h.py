import unittest
from scapy.all import IP, TCP, Raw
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter, generate_ja4h
import binascii

class TestJA4H(unittest.TestCase):
    def setUp(self):
        print("\nSetting up JA4H test...")
        self.ja4h_fp = JA4HFingerprinter()
        
        # Create a mock HTTP request packet
        http_request = (
            "GET /index.html HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.5\r\n"
            "Accept-Encoding: gzip, deflate, br\r\n"
            "Connection: keep-alive\r\n"
            "Upgrade-Insecure-Requests: 1\r\n"
            "Cache-Control: max-age=0\r\n"
            "Cookie: session=abc123; theme=dark\r\n"
            "\r\n"
        )
        
        self.http_packet = IP(src="192.168.1.100", dst="93.184.216.34")/TCP(sport=54321, dport=80)/Raw(load=http_request)
        print("Setup complete.")
    
    def test_http_request_fingerprint(self):
        print("\nTesting JA4H with HTTP request...")
        
        # Generate JA4H fingerprint
        ja4h_fp = self.ja4h_fp.process_packet(self.http_packet)
        print(f"JA4H fingerprint: {ja4h_fp}")
        
        # Try direct generation
        if not ja4h_fp:
            print("Trying direct JA4H generation...")
            ja4h_fp = generate_ja4h(self.http_packet)
            print(f"Directly generated JA4H: {ja4h_fp}")
        
        # Verify extracted HTTP info
        from ja4plus.utils.http_utils import extract_http_info
        http_info = extract_http_info(self.http_packet)
        if http_info:
            print("Extracted HTTP information:")
            print(f"  Method: {http_info.get('method')}")
            print(f"  Path: {http_info.get('path')}")
            print(f"  Version: {http_info.get('version')}")
            print(f"  Header names: {http_info.get('headers')}")
            if 'cookies' in http_info:
                print("  Cookies:")
                for name, value in http_info.get('cookies', {}).items():
                    print(f"    {name}: {value}")
        else:
            print("No HTTP information extracted")
        
        # We should get a non-None fingerprint
        self.assertIsNotNone(ja4h_fp, "JA4H fingerprinting failed")
        
        # JA4H should follow the expected structure (a_b_c_d)
        parts = ja4h_fp.split('_')
        self.assertEqual(len(parts), 4, f"JA4H fingerprint has incorrect format: {ja4h_fp}")
        
        print("JA4H test successful.")

if __name__ == "__main__":
    unittest.main(verbosity=2) 