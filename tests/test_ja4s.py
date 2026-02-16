import unittest
import hashlib
from scapy.all import IP, TCP, Raw
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter, generate_ja4s


def build_server_hello_bytes(version=0x0303, cipher=0xc02f, extensions=None):
    """Build a minimal TLS ServerHello raw bytes payload."""
    if extensions is None:
        extensions = []

    # Handshake: ServerHello
    server_hello = bytearray()
    server_hello += version.to_bytes(2, 'big')  # Server version
    server_hello += b'\x00' * 32  # Random (32 bytes)
    server_hello += b'\x00'  # Session ID length (0)
    server_hello += cipher.to_bytes(2, 'big')  # Cipher suite
    server_hello += b'\x00'  # Compression method

    # Extensions
    ext_data = bytearray()
    for ext_type in extensions:
        ext_data += ext_type.to_bytes(2, 'big')  # Extension type
        ext_data += b'\x00\x00'  # Extension data length (0)

    if ext_data:
        server_hello += len(ext_data).to_bytes(2, 'big')
        server_hello += ext_data

    # Handshake header
    handshake = bytearray()
    handshake += b'\x02'  # ServerHello type
    handshake += len(server_hello).to_bytes(3, 'big')
    handshake += server_hello

    # TLS record header
    record = bytearray()
    record += b'\x16'  # Handshake content type
    record += b'\x03\x03'  # TLS 1.2 record version
    record += len(handshake).to_bytes(2, 'big')
    record += handshake

    return bytes(record)


class TestJA4S(unittest.TestCase):
    def setUp(self):
        self.ja4s_fp = JA4SFingerprinter()

    def test_basic_functionality(self):
        """Test basic fingerprinter functionality"""
        self.assertIsNotNone(self.ja4s_fp)
        self.assertEqual(len(self.ja4s_fp.fingerprints), 0)

    def test_server_hello_fingerprint(self):
        """Test fingerprinting a TLS ServerHello"""
        extensions = [0x0000, 0x000b, 0xff01]
        raw_data = build_server_hello_bytes(
            version=0x0303,
            cipher=0xc02f,
            extensions=extensions,
        )

        packet = IP(src="93.184.216.34", dst="192.168.1.100") / TCP(
            sport=443, dport=54321
        ) / Raw(load=raw_data)

        fingerprint = self.ja4s_fp.process_packet(packet)

        self.assertIsNotNone(fingerprint, "Failed to generate JA4S fingerprint")
        print(f"Generated JA4S fingerprint: {fingerprint}")

        # JA4S format: <proto><version><ext_count><alpn>_<cipher>_<ext_hash>
        parts = fingerprint.split('_')
        self.assertEqual(len(parts), 3, "JA4S fingerprint has incorrect format")

        # First part: t (TCP), 12 (TLS 1.2), 03 (3 extensions), 00 (no ALPN)
        self.assertEqual(parts[0], 't120300')

        # Second part: cipher in hex
        self.assertEqual(parts[1], 'c02f')

        # Third part: 12-char hash of extensions
        self.assertEqual(len(parts[2]), 12)

        # Verify extension hash manually
        ext_str = ','.join([f"{e:04x}" for e in extensions])
        expected_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
        self.assertEqual(parts[2], expected_hash)

        # Check that the fingerprinter collected it
        self.assertEqual(len(self.ja4s_fp.fingerprints), 1)

    def test_server_hello_tls13(self):
        """Test ServerHello with TLS 1.3 via supported_versions extension."""
        # Build a ServerHello that advertises TLS 1.2 in record but has
        # supported_versions extension selecting TLS 1.3
        server_hello = bytearray()
        server_hello += b'\x03\x03'  # TLS 1.2 in handshake
        server_hello += b'\x00' * 32  # Random
        server_hello += b'\x00'  # Session ID length
        server_hello += b'\x13\x01'  # TLS_AES_128_GCM_SHA256
        server_hello += b'\x00'  # Compression

        # Extensions with supported_versions selecting TLS 1.3
        ext_data = bytearray()
        # supported_versions extension (0x002b)
        ext_data += b'\x00\x2b'  # Extension type
        ext_data += b'\x00\x02'  # Length = 2
        ext_data += b'\x03\x04'  # TLS 1.3

        server_hello += len(ext_data).to_bytes(2, 'big')
        server_hello += ext_data

        # Wrap in handshake + record headers
        handshake = b'\x02' + len(server_hello).to_bytes(3, 'big') + server_hello
        record = b'\x16\x03\x03' + len(handshake).to_bytes(2, 'big') + handshake

        packet = IP() / TCP(sport=443, dport=54321) / Raw(load=bytes(record))
        fingerprint = self.ja4s_fp.process_packet(packet)

        self.assertIsNotNone(fingerprint)
        print(f"TLS 1.3 JA4S: {fingerprint}")

        parts = fingerprint.split('_')
        # Should detect TLS 1.3 from supported_versions
        self.assertTrue(parts[0].startswith('t13'))

    def test_non_server_hello_ignored(self):
        """Test that non-ServerHello packets are ignored."""
        # Build a ClientHello instead
        client_hello = bytearray()
        client_hello += b'\x03\x03'  # Version
        client_hello += b'\x00' * 32  # Random
        client_hello += b'\x00'  # Session ID length
        client_hello += b'\x00\x02\x13\x01'  # Cipher suites
        client_hello += b'\x01\x00'  # Compression

        handshake = b'\x01' + len(client_hello).to_bytes(3, 'big') + client_hello
        record = b'\x16\x03\x03' + len(handshake).to_bytes(2, 'big') + handshake

        packet = IP() / TCP(sport=54321, dport=443) / Raw(load=bytes(record))
        fingerprint = self.ja4s_fp.process_packet(packet)
        self.assertIsNone(fingerprint)

    def test_reset(self):
        """Test fingerprinter reset."""
        raw_data = build_server_hello_bytes()
        packet = IP() / TCP(sport=443, dport=54321) / Raw(load=raw_data)
        self.ja4s_fp.process_packet(packet)
        self.assertEqual(len(self.ja4s_fp.fingerprints), 1)

        self.ja4s_fp.reset()
        self.assertEqual(len(self.ja4s_fp.fingerprints), 0)


if __name__ == '__main__':
    unittest.main()
