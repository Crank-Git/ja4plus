"""
Comprehensive tests for JA4+ utility modules.

Covers tls_utils, http_utils, ssh_utils, and x509_utils.
"""

import unittest
import hashlib
import struct
from scapy.all import IP, TCP, UDP, Raw

from ja4plus.utils.tls_utils import (
    is_grease_value,
    extract_tls_info,
    parse_tls_handshake,
)
from ja4plus.utils.http_utils import (
    parse_http_request,
    is_http_request,
    extract_http_info,
)
from ja4plus.utils.ssh_utils import (
    is_ssh_packet,
    parse_ssh_packet,
    extract_hassh,
)
from ja4plus.utils.x509_utils import oid_to_hex


# ===========================================================================
# GREASE detection tests
# ===========================================================================
class TestGREASEDetection(unittest.TestCase):
    """Exhaustive GREASE value detection tests."""

    GREASE_VALUES = [
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
        0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
        0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    ]

    def test_all_16_grease_values(self):
        """All 16 GREASE values must be detected."""
        for val in self.GREASE_VALUES:
            with self.subTest(value=f"0x{val:04x}"):
                self.assertTrue(is_grease_value(val))

    def test_common_non_grease_cipher_suites(self):
        """Common cipher suites must NOT be flagged as GREASE."""
        non_grease = [
            0x1301,  # TLS_AES_128_GCM_SHA256
            0x1302,  # TLS_AES_256_GCM_SHA384
            0x1303,  # TLS_CHACHA20_POLY1305_SHA256
            0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA
            0x00FF,  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        ]
        for val in non_grease:
            with self.subTest(value=f"0x{val:04x}"):
                self.assertFalse(is_grease_value(val))

    def test_common_extension_types_not_grease(self):
        """Common extension types must NOT be flagged."""
        extensions = [
            0x0000,  # SNI
            0x000A,  # supported_groups
            0x000B,  # ec_point_formats
            0x000D,  # signature_algorithms
            0x0010,  # ALPN
            0x0017,  # extended_master_secret
            0x002B,  # supported_versions
            0x002D,  # psk_key_exchange_modes
            0x0033,  # key_share
            0xFF01,  # renegotiation_info
        ]
        for val in extensions:
            with self.subTest(value=f"0x{val:04x}"):
                self.assertFalse(is_grease_value(val))

    def test_grease_as_hex_string(self):
        """GREASE detection should work with hex string input."""
        self.assertTrue(is_grease_value("0x0a0a"))
        self.assertTrue(is_grease_value("0x1A1A"))
        self.assertTrue(is_grease_value("0xfafa"))

    def test_non_grease_hex_string(self):
        """Non-GREASE hex strings should not match."""
        self.assertFalse(is_grease_value("0x1234"))
        self.assertFalse(is_grease_value("0xc02f"))
        self.assertFalse(is_grease_value("0x0000"))

    def test_grease_edge_values(self):
        """Edge values that look similar to GREASE but are not."""
        self.assertFalse(is_grease_value(0x0A0B))  # Different low bytes
        self.assertFalse(is_grease_value(0x1A2A))  # Different high nibbles
        self.assertFalse(is_grease_value(0x0B0B))  # Low nibble != 0xA
        self.assertFalse(is_grease_value(0xABAB))  # Low nibble != 0xA

    def test_grease_none_and_zero(self):
        """None and zero should not be GREASE."""
        self.assertFalse(is_grease_value(None))
        self.assertFalse(is_grease_value(0))

    def test_grease_empty_string(self):
        """Empty string should not be GREASE."""
        self.assertFalse(is_grease_value(""))

    def test_grease_invalid_types(self):
        """Invalid types should not raise exceptions."""
        self.assertFalse(is_grease_value([]))
        self.assertFalse(is_grease_value({}))
        self.assertFalse(is_grease_value(3.14))


# ===========================================================================
# TLS parsing tests
# ===========================================================================
class TestTLSParsing(unittest.TestCase):
    """Tests for TLS handshake parsing."""

    def _build_client_hello(self, version=0x0303, ciphers=None, sni=None,
                            alpn=None, supported_versions=None, sig_algs=None):
        """Build a raw TLS ClientHello record."""
        if ciphers is None:
            ciphers = [0x1301]

        ch = bytearray()
        ch += version.to_bytes(2, "big")
        ch += b"\x00" * 32  # Random
        ch += b"\x00"  # Session ID length

        cs = bytearray()
        for c in ciphers:
            cs += c.to_bytes(2, "big")
        ch += len(cs).to_bytes(2, "big") + cs
        ch += b"\x01\x00"  # Compression

        ext_data = bytearray()

        if sni:
            hostname = sni.encode()
            sni_entry = b"\x00" + len(hostname).to_bytes(2, "big") + hostname
            sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
            ext_data += b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list

        if supported_versions:
            sv = bytearray()
            sv.append(len(supported_versions) * 2)
            for v in supported_versions:
                sv += v.to_bytes(2, "big")
            ext_data += b"\x00\x2b" + len(sv).to_bytes(2, "big") + bytes(sv)

        if alpn:
            ad = bytearray()
            for proto in alpn:
                pb = proto.encode()
                ad += len(pb).to_bytes(1, "big") + pb
            al = len(ad).to_bytes(2, "big") + ad
            ext_data += b"\x00\x10" + len(al).to_bytes(2, "big") + al

        if sig_algs:
            sd = bytearray()
            for alg in sig_algs:
                sd += alg.to_bytes(2, "big")
            sl = len(sd).to_bytes(2, "big") + sd
            ext_data += b"\x00\x0d" + len(sl).to_bytes(2, "big") + bytes(sl)

        if ext_data:
            ch += len(ext_data).to_bytes(2, "big") + ext_data

        handshake = b"\x01" + len(ch).to_bytes(3, "big") + bytes(ch)
        return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

    def test_parse_client_hello_basic(self):
        """Parse a basic ClientHello and verify structure."""
        raw = self._build_client_hello(ciphers=[0x1301, 0xC02F])
        result = parse_tls_handshake(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "client_hello")
        self.assertEqual(result["version"], 0x0303)
        self.assertIn(0x1301, result["ciphers"])
        self.assertIn(0xC02F, result["ciphers"])

    def test_parse_client_hello_with_sni(self):
        """SNI hostname should be extracted."""
        raw = self._build_client_hello(sni="www.example.com")
        result = parse_tls_handshake(raw)
        self.assertEqual(result["sni"], "www.example.com")

    def test_parse_client_hello_without_sni(self):
        """No SNI should leave sni key absent or None."""
        raw = self._build_client_hello()
        result = parse_tls_handshake(raw)
        self.assertIsNotNone(result)
        self.assertIsNone(result.get("sni"))

    def test_parse_supported_versions(self):
        """supported_versions extension should be parsed."""
        raw = self._build_client_hello(supported_versions=[0x0304, 0x0303])
        result = parse_tls_handshake(raw)
        self.assertIn(0x0304, result["supported_versions"])
        self.assertIn(0x0303, result["supported_versions"])

    def test_parse_alpn(self):
        """ALPN protocols should be parsed."""
        raw = self._build_client_hello(alpn=["h2", "http/1.1"])
        result = parse_tls_handshake(raw)
        self.assertEqual(result["alpn_protocols"], ["h2", "http/1.1"])

    def test_parse_signature_algorithms(self):
        """Signature algorithms should be parsed."""
        raw = self._build_client_hello(sig_algs=[0x0403, 0x0804, 0x0401])
        result = parse_tls_handshake(raw)
        self.assertEqual(result["signature_algorithms"], [0x0403, 0x0804, 0x0401])

    def test_parse_empty_data(self):
        """Empty data should return None."""
        self.assertIsNone(parse_tls_handshake(b""))

    def test_parse_too_short(self):
        """Data shorter than TLS header should return None."""
        self.assertIsNone(parse_tls_handshake(b"\x16\x03"))

    def test_parse_non_handshake(self):
        """Non-handshake record type should return None."""
        self.assertIsNone(parse_tls_handshake(b"\x17\x03\x03\x00\x05\x01\x02\x03\x04\x05"))

    def test_parse_server_hello(self):
        """ServerHello should be parsed correctly."""
        sh = bytearray()
        sh += (0x0303).to_bytes(2, "big")
        sh += b"\x00" * 32
        sh += b"\x00"  # Session ID len
        sh += (0xC02F).to_bytes(2, "big")  # Cipher
        sh += b"\x00"  # Compression

        handshake = b"\x02" + len(sh).to_bytes(3, "big") + bytes(sh)
        record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake

        result = parse_tls_handshake(record)
        self.assertIsNotNone(result)
        self.assertEqual(result["handshake_type"], "server_hello")
        self.assertEqual(result["cipher"], 0xC02F)

    def test_extract_tls_info_from_packet(self):
        """extract_tls_info should work with scapy packets."""
        raw = self._build_client_hello(sni="test.com", ciphers=[0x1301])
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        result = extract_tls_info(packet)
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "client_hello")

    def test_extract_tls_info_no_raw(self):
        """Packet without Raw layer should return None."""
        packet = IP() / TCP(sport=12345, dport=443)
        result = extract_tls_info(packet)
        self.assertIsNone(result)

    def test_extract_tls_info_with_tls_info_attr(self):
        """Packet with tls_info attribute should use it directly."""
        packet = IP() / TCP()
        packet.tls_info = {"type": "client_hello", "version": 0x0304}
        result = extract_tls_info(packet)
        self.assertEqual(result["type"], "client_hello")
        self.assertEqual(result["version"], 0x0304)

    def test_grease_in_ciphers_parsed(self):
        """GREASE values in cipher list should be parsed (filtering happens in fingerprinter)."""
        raw = self._build_client_hello(ciphers=[0x0A0A, 0x1301, 0xFAFA])
        result = parse_tls_handshake(raw)
        self.assertEqual(len(result["ciphers"]), 3)
        self.assertIn(0x0A0A, result["ciphers"])


# ===========================================================================
# HTTP parsing tests
# ===========================================================================
class TestHTTPParsing(unittest.TestCase):
    """Tests for HTTP request parsing."""

    def test_parse_get_request(self):
        """Parse a basic GET request."""
        data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = parse_http_request(data)
        self.assertIsNotNone(result)
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["path"], "/index.html")
        self.assertEqual(result["version"], "HTTP/1.1")

    def test_parse_post_request(self):
        """Parse a POST request."""
        data = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n"
        result = parse_http_request(data)
        self.assertEqual(result["method"], "POST")

    def test_parse_all_methods(self):
        """All standard HTTP methods should be recognized."""
        methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"]
        for method in methods:
            with self.subTest(method=method):
                data = f"{method} / HTTP/1.1\r\nHost: test.com\r\n\r\n".encode()
                result = parse_http_request(data)
                self.assertIsNotNone(result, f"{method} should be recognized")
                self.assertEqual(result["method"], method)

    def test_parse_cookies(self):
        """Cookies should be extracted correctly."""
        data = b"GET / HTTP/1.1\r\nHost: test.com\r\nCookie: session=abc123; user=john\r\n\r\n"
        result = parse_http_request(data)
        self.assertEqual(result["cookies"]["session"], "abc123")
        self.assertEqual(result["cookies"]["user"], "john")

    def test_parse_no_cookies(self):
        """Request without cookies should have empty cookies dict."""
        data = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"
        result = parse_http_request(data)
        self.assertEqual(result["cookies"], {})

    def test_is_http_request_true(self):
        """is_http_request should detect HTTP request data."""
        self.assertTrue(is_http_request(b"GET / HTTP/1.1"))
        self.assertTrue(is_http_request(b"POST /api HTTP/2"))

    def test_is_http_request_false(self):
        """Non-HTTP data should not be detected."""
        self.assertFalse(is_http_request(b"\x16\x03\x03"))  # TLS
        self.assertFalse(is_http_request(b"SSH-2.0-OpenSSH"))
        self.assertFalse(is_http_request(b"random data"))

    def test_is_http_request_string_input(self):
        """is_http_request should handle string input."""
        self.assertTrue(is_http_request("GET / HTTP/1.1"))
        self.assertFalse(is_http_request("not http"))

    def test_parse_empty_data(self):
        """Empty data should return None."""
        self.assertIsNone(parse_http_request(b""))
        self.assertIsNone(parse_http_request(None))

    def test_parse_non_http_data(self):
        """Non-HTTP data should return None."""
        self.assertIsNone(parse_http_request(b"\x16\x03\x03\x00\x00"))

    def test_extract_http_info_from_packet(self):
        """extract_http_info should work with scapy packets."""
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept-Language: en-US\r\n\r\n"
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=data)
        result = extract_http_info(packet)
        self.assertIsNotNone(result)
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["language"], "en-US")

    def test_extract_http_info_headers_as_list(self):
        """extract_http_info should return header names as a list."""
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=data)
        result = extract_http_info(packet)
        self.assertIsInstance(result["headers"], list)
        self.assertIn("Host", result["headers"])

    def test_extract_http_info_cookie_fields(self):
        """extract_http_info should extract cookie field names."""
        data = b"GET / HTTP/1.1\r\nHost: test.com\r\nCookie: a=1; b=2\r\n\r\n"
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=data)
        result = extract_http_info(packet)
        self.assertIn("a", result["cookie_fields"])
        self.assertIn("b", result["cookie_fields"])

    def test_extract_http_info_referer(self):
        """Referer header should be extracted."""
        data = b"GET / HTTP/1.1\r\nHost: test.com\r\nReferer: https://google.com\r\n\r\n"
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=data)
        result = extract_http_info(packet)
        self.assertEqual(result["referer"], "https://google.com")

    def test_extract_http_info_no_raw(self):
        """Packet without Raw layer should return None."""
        packet = IP() / TCP(sport=12345, dport=80)
        result = extract_http_info(packet)
        self.assertIsNone(result)


# ===========================================================================
# SSH parsing tests
# ===========================================================================
class TestSSHParsing(unittest.TestCase):
    """Tests for SSH packet parsing."""

    def test_is_ssh_banner(self):
        """SSH banner should be detected."""
        self.assertTrue(is_ssh_packet(b"SSH-2.0-OpenSSH_8.2p1\r\n"))
        self.assertTrue(is_ssh_packet(b"SSH-2.0-dropbear_2019.78"))

    def test_is_ssh_kexinit_test_format(self):
        """Test format KEXINIT should be detected."""
        data = b"\x00\x00\x05\xdc\x06\x14AAAAAAAAAA" + b"SSH_MSG_KEXINIT" + b"algo1;algo2;algo3;algo4"
        self.assertTrue(is_ssh_packet(data))

    def test_is_not_ssh(self):
        """Non-SSH data should not be detected."""
        self.assertFalse(is_ssh_packet(b"GET / HTTP/1.1"))
        self.assertFalse(is_ssh_packet(b"\x16\x03\x03"))
        self.assertFalse(is_ssh_packet(b""))
        self.assertFalse(is_ssh_packet(None))
        self.assertFalse(is_ssh_packet(b"\x00"))

    def test_parse_ssh_banner(self):
        """SSH banner should be parsed into version info."""
        result = parse_ssh_packet(b"SSH-2.0-OpenSSH_8.2p1\r\n")
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "version")
        self.assertIn("OpenSSH", result["version_string"])

    def test_parse_test_kexinit(self):
        """Test format KEXINIT should parse algorithm lists."""
        data = (b"\x00\x00\x05\xdc\x06\x14AAAAAAAAAA"
                b"SSH_MSG_KEXINIT"
                b"curve25519-sha256;aes128-ctr;hmac-sha2-256;none")
        result = parse_ssh_packet(data)
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "kexinit")

    def test_extract_hassh_from_kexinit(self):
        """HASSH should be extracted as MD5 of algorithm string."""
        data = (b"\x00\x00\x05\xdc\x06\x14AAAAAAAAAA"
                b"SSH_MSG_KEXINIT"
                b"curve25519-sha256;aes128-ctr;hmac-sha2-256;none")
        hassh = extract_hassh(data)
        self.assertIsNotNone(hassh)
        self.assertEqual(len(hassh), 32)  # MD5 hex length

        # Verify manually
        expected_str = "curve25519-sha256;aes128-ctr;hmac-sha2-256;none"
        expected_hash = hashlib.md5(expected_str.encode()).hexdigest()
        self.assertEqual(hassh, expected_hash)

    def test_extract_hassh_non_kexinit(self):
        """Non-KEXINIT data should not produce HASSH."""
        hassh = extract_hassh(b"SSH-2.0-OpenSSH_8.2p1\r\n")
        self.assertIsNone(hassh)

    def test_parse_empty_data(self):
        """Empty data should return None."""
        self.assertIsNone(parse_ssh_packet(b""))
        self.assertIsNone(parse_ssh_packet(None))

    def test_parse_short_data(self):
        """Data shorter than minimum should return None."""
        self.assertIsNone(parse_ssh_packet(b"\x00\x01"))


# ===========================================================================
# X.509 OID encoding tests
# ===========================================================================
class TestOIDEncoding(unittest.TestCase):
    """Tests for OID to hex encoding."""

    def test_common_oids(self):
        """Common OIDs should be encoded using ASN.1 encoding."""
        # CommonName: 2.5.4.3 -> 0x55=2*40+5, 0x04=4, 0x03=3
        result = oid_to_hex("2.5.4.3")
        self.assertEqual(result, "550403")

        # OrganizationName: 2.5.4.10 -> 0x55, 0x04, 0x0a
        result = oid_to_hex("2.5.4.10")
        self.assertEqual(result, "55040a")

        # CountryName: 2.5.4.6 -> 0x55, 0x04, 0x06
        result = oid_to_hex("2.5.4.6")
        self.assertEqual(result, "550406")

    def test_extension_oids(self):
        """Extension OIDs should be encoded using ASN.1 encoding."""
        # BasicConstraints: 2.5.29.19 -> 0x55, 0x1d, 0x13
        result = oid_to_hex("2.5.29.19")
        self.assertEqual(result, "551d13")

        # KeyUsage: 2.5.29.15 -> 0x55, 0x1d, 0x0f
        result = oid_to_hex("2.5.29.15")
        self.assertEqual(result, "551d0f")

        # SubjectAltName: 2.5.29.17 -> 0x55, 0x1d, 0x11
        result = oid_to_hex("2.5.29.17")
        self.assertEqual(result, "551d11")

    def test_state_province_oid(self):
        """StateOrProvinceName OID: 2.5.4.8 -> ASN.1 encoding"""
        result = oid_to_hex("2.5.4.8")
        self.assertEqual(result, "550408")

    def test_oid_consistent(self):
        """Same OID should always produce same hex."""
        oid = "2.5.4.3"
        self.assertEqual(oid_to_hex(oid), oid_to_hex(oid))

    def test_different_oids_produce_different_hex(self):
        """Different OIDs should produce different hex."""
        self.assertNotEqual(oid_to_hex("2.5.4.3"), oid_to_hex("2.5.4.10"))


if __name__ == "__main__":
    unittest.main()
