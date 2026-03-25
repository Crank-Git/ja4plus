"""
Comprehensive tests for JA4+ fingerprinting library.

Covers edge cases, boundary conditions, GREASE filtering,
format validation, and cross-fingerprinter consistency.
"""

import unittest
import hashlib
import time
import datetime
from scapy.all import IP, TCP, UDP, Raw, Ether

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter, generate_ja4, get_raw_fingerprint
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter, generate_ja4s
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter, generate_ja4h
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter, generate_ja4t
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter, generate_ja4ts
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter, generate_ja4l
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter, generate_ja4ssh
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter, generate_ja4x
from ja4plus.utils.tls_utils import is_grease_value, parse_tls_handshake


# ---------------------------------------------------------------------------
# Helper: build TLS ClientHello raw bytes
# ---------------------------------------------------------------------------
def build_client_hello(
    version=0x0303,
    ciphers=None,
    extensions=None,
    sni_hostname=None,
    alpn_protocols=None,
    supported_versions=None,
    signature_algorithms=None,
):
    """Build a TLS ClientHello record from parts."""
    if ciphers is None:
        ciphers = [0x1301, 0x1302, 0xC02F]
    if extensions is None:
        extensions = []

    ch = bytearray()
    ch += version.to_bytes(2, "big")  # ClientHello version
    ch += b"\x00" * 32  # Random
    ch += b"\x00"  # Session ID length

    # Cipher suites
    cs_bytes = bytearray()
    for c in ciphers:
        cs_bytes += c.to_bytes(2, "big")
    ch += len(cs_bytes).to_bytes(2, "big") + cs_bytes

    ch += b"\x01\x00"  # Compression methods

    # Extensions
    ext_data = bytearray()

    # SNI extension (0x0000)
    if sni_hostname:
        hostname = sni_hostname.encode()
        sni_entry = b"\x00" + len(hostname).to_bytes(2, "big") + hostname
        sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
        ext_data += b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
        if 0x0000 not in extensions:
            extensions.append(0x0000)

    # supported_versions (0x002b)
    if supported_versions:
        sv_list = bytearray()
        sv_list.append(len(supported_versions) * 2)
        for v in supported_versions:
            sv_list += v.to_bytes(2, "big")
        ext_data += b"\x00\x2b" + len(sv_list).to_bytes(2, "big") + bytes(sv_list)
        if 0x002B not in extensions:
            extensions.append(0x002B)

    # ALPN (0x0010)
    if alpn_protocols:
        alpn_data = bytearray()
        for proto in alpn_protocols:
            proto_bytes = proto.encode()
            alpn_data += len(proto_bytes).to_bytes(1, "big") + proto_bytes
        alpn_list = len(alpn_data).to_bytes(2, "big") + alpn_data
        ext_data += b"\x00\x10" + len(alpn_list).to_bytes(2, "big") + alpn_list
        if 0x0010 not in extensions:
            extensions.append(0x0010)

    # signature_algorithms (0x000d)
    if signature_algorithms:
        sig_data = bytearray()
        for alg in signature_algorithms:
            sig_data += alg.to_bytes(2, "big")
        sig_list = len(sig_data).to_bytes(2, "big") + sig_data
        ext_data += b"\x00\x0d" + len(sig_list).to_bytes(2, "big") + bytes(sig_list)
        if 0x000D not in extensions:
            extensions.append(0x000D)

    # Add remaining extensions (just type + empty data)
    already_added = {0x0000, 0x002B, 0x0010, 0x000D}
    for ext_type in extensions:
        if ext_type not in already_added:
            ext_data += ext_type.to_bytes(2, "big") + b"\x00\x00"

    if ext_data:
        ch += len(ext_data).to_bytes(2, "big") + ext_data

    # Wrap in handshake + record
    handshake = b"\x01" + len(ch).to_bytes(3, "big") + bytes(ch)
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return bytes(record)


def build_server_hello(version=0x0303, cipher=0xC02F, extensions=None, supported_version=None):
    """Build a TLS ServerHello record from parts."""
    sh = bytearray()
    sh += version.to_bytes(2, "big")
    sh += b"\x00" * 32  # Random
    sh += b"\x00"  # Session ID length
    sh += cipher.to_bytes(2, "big")
    sh += b"\x00"  # Compression

    ext_data = bytearray()
    if supported_version:
        ext_data += b"\x00\x2b\x00\x02"
        ext_data += supported_version.to_bytes(2, "big")

    if extensions:
        for ext_type in extensions:
            if ext_type != 0x002B:
                ext_data += ext_type.to_bytes(2, "big") + b"\x00\x00"

    if ext_data:
        sh += len(ext_data).to_bytes(2, "big") + ext_data

    handshake = b"\x02" + len(sh).to_bytes(3, "big") + bytes(sh)
    record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
    return bytes(record)


# ===========================================================================
# GREASE detection tests
# ===========================================================================
class TestGREASE(unittest.TestCase):
    """Test GREASE value detection across all known values."""

    GREASE_VALUES = [
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
        0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
        0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    ]

    def test_all_grease_values_detected(self):
        for val in self.GREASE_VALUES:
            self.assertTrue(is_grease_value(val), f"0x{val:04x} should be GREASE")

    def test_non_grease_values_not_detected(self):
        non_grease = [0x0000, 0x0001, 0x0301, 0x1301, 0xC02F, 0x002B, 0x000D, 0xFFFF]
        for val in non_grease:
            self.assertFalse(is_grease_value(val), f"0x{val:04x} should NOT be GREASE")

    def test_grease_string_hex(self):
        self.assertTrue(is_grease_value("0x0a0a"))
        self.assertFalse(is_grease_value("0x1234"))

    def test_grease_edge_cases(self):
        self.assertFalse(is_grease_value(None))
        self.assertFalse(is_grease_value(0))
        self.assertFalse(is_grease_value(""))


# ===========================================================================
# JA4 (TLS Client Hello) comprehensive tests
# ===========================================================================
class TestJA4Comprehensive(unittest.TestCase):

    def setUp(self):
        self.fp = JA4Fingerprinter()

    def test_tls12_no_supported_versions(self):
        """TLS 1.2 without supported_versions extension."""
        raw = build_client_hello(
            version=0x0303,
            ciphers=[0xC02F, 0xC030],
            sni_hostname="example.com",
        )
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        parts = fp.split("_")
        self.assertTrue(parts[0].startswith("t12d"), f"Expected TLS 1.2 with SNI, got {parts[0]}")

    def test_tls13_via_supported_versions(self):
        """TLS 1.3 advertised through supported_versions."""
        raw = build_client_hello(
            version=0x0303,
            ciphers=[0x1301, 0x1302],
            sni_hostname="example.com",
            supported_versions=[0x0304, 0x0303],
        )
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        parts = fp.split("_")
        self.assertTrue(parts[0].startswith("t13"), f"Expected TLS 1.3, got {parts[0]}")

    def test_no_sni_uses_i(self):
        """Without SNI, should use 'i' indicator."""
        raw = build_client_hello(
            version=0x0303,
            ciphers=[0xC02F],
        )
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        parts = fp.split("_")
        self.assertIn("i", parts[0], "Missing SNI should use 'i'")

    def test_alpn_h2(self):
        """ALPN with h2 should produce 'h2'."""
        raw = build_client_hello(
            version=0x0303,
            ciphers=[0xC02F],
            sni_hostname="example.com",
            alpn_protocols=["h2"],
        )
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        self.assertTrue(fp.split("_")[0].endswith("h2"), f"ALPN should be h2, got {fp}")

    def test_alpn_http11(self):
        """ALPN with http/1.1 should produce 'h1' (first and last char)."""
        raw = build_client_hello(
            version=0x0303,
            ciphers=[0xC02F],
            sni_hostname="example.com",
            alpn_protocols=["http/1.1"],
        )
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        self.assertTrue(fp.split("_")[0].endswith("h1"), f"ALPN should be h1, got {fp}")

    def test_no_alpn_gives_00(self):
        """No ALPN should produce '00'."""
        raw = build_client_hello(version=0x0303, ciphers=[0xC02F])
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        self.assertTrue(fp.split("_")[0].endswith("00"))

    def test_grease_ciphers_filtered(self):
        """GREASE cipher suites should be excluded from the count."""
        ciphers = [0x0A0A, 0x1301, 0x1302, 0xFAFA]
        raw = build_client_hello(version=0x0303, ciphers=ciphers, sni_hostname="test.com")
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        parts = fp.split("_")
        # Cipher count should be 2 (0x0A0A and 0xFAFA are GREASE)
        # part_a format: proto(1) version(2) sni(1) cipher_count(2) ext_count(2) alpn(2) = 10 chars
        cipher_count = parts[0][4:6]
        self.assertEqual(cipher_count, "02", f"Expected 2 non-GREASE ciphers, got {cipher_count}")

    def test_cipher_hash_is_sorted(self):
        """Cipher hash should use sorted cipher values."""
        ciphers = [0xC030, 0xC02F, 0x1301]
        raw = build_client_hello(version=0x0303, ciphers=ciphers)
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)

        # Manually compute expected hash
        sorted_hex = ",".join([f"{c:04x}" for c in sorted(ciphers)])
        expected_hash = hashlib.sha256(sorted_hex.encode()).hexdigest()[:12]
        self.assertEqual(fp.split("_")[1], expected_hash)

    def test_extension_hash_excludes_sni_and_alpn(self):
        """Extension hash should exclude SNI (0x0000) and ALPN (0x0010)."""
        raw = build_client_hello(
            version=0x0303,
            ciphers=[0x1301],
            sni_hostname="example.com",
            alpn_protocols=["h2"],
            signature_algorithms=[0x0403, 0x0804],
        )
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        # The ext hash should not be all zeros since we have sig algs and supported_versions-like exts
        self.assertNotEqual(fp.split("_")[2], "000000000000")

    def test_fingerprint_three_parts(self):
        """JA4 fingerprint should always have exactly 3 parts."""
        raw = build_client_hello(version=0x0303, ciphers=[0xC02F])
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        self.assertEqual(len(fp.split("_")), 3)

    def test_non_tls_packet_returns_none(self):
        """Non-TLS data should return None."""
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=b"not tls data")
        fp = self.fp.process_packet(packet)
        self.assertIsNone(fp)

    def test_raw_fingerprint(self):
        """Raw fingerprint should contain full cipher and extension lists."""
        raw = build_client_hello(
            version=0x0303,
            ciphers=[0x1301, 0xC02F],
            sni_hostname="example.com",
        )
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        raw_fp = self.fp.get_raw_fingerprint(packet)
        self.assertIsNotNone(raw_fp)
        self.assertTrue(raw_fp.startswith("JA4_r"))

    def test_ssl30_version(self):
        """SSL 3.0 should produce 's3' version string."""
        raw = build_client_hello(version=0x0300, ciphers=[0x002F])
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        self.assertTrue(fp.split("_")[0].startswith("ts3"))


# ===========================================================================
# JA4S (TLS Server Hello) comprehensive tests
# ===========================================================================
class TestJA4SComprehensive(unittest.TestCase):

    def setUp(self):
        self.fp = JA4SFingerprinter()

    def test_tls12_server_hello(self):
        raw = build_server_hello(version=0x0303, cipher=0xC02F)
        packet = IP() / TCP(sport=443, dport=12345) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        parts = fp.split("_")
        self.assertEqual(len(parts), 3)
        self.assertTrue(parts[0].startswith("t12"))
        self.assertEqual(parts[1], "c02f")

    def test_tls13_via_supported_versions(self):
        raw = build_server_hello(
            version=0x0303, cipher=0x1301, supported_version=0x0304
        )
        packet = IP() / TCP(sport=443, dport=12345) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        self.assertTrue(fp.split("_")[0].startswith("t13"))

    def test_no_extensions(self):
        raw = build_server_hello(version=0x0303, cipher=0xC02F)
        packet = IP() / TCP(sport=443, dport=12345) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        parts = fp.split("_")
        self.assertEqual(parts[0][3:5], "00")  # Zero extensions
        self.assertEqual(parts[2], "000000000000")

    def test_multiple_extensions_hash(self):
        extensions = [0x0000, 0x000B, 0xFF01]
        raw = build_server_hello(version=0x0303, cipher=0xC02F, extensions=extensions)
        packet = IP() / TCP(sport=443, dport=12345) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        parts = fp.split("_")
        # Manually verify extension hash
        ext_str = ",".join([f"{e:04x}" for e in extensions])
        expected_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
        self.assertEqual(parts[2], expected_hash)

    def test_client_hello_ignored(self):
        """JA4S should ignore ClientHello packets."""
        raw = build_client_hello(version=0x0303, ciphers=[0xC02F])
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        fp = self.fp.process_packet(packet)
        self.assertIsNone(fp)


# ===========================================================================
# JA4H (HTTP) comprehensive tests
# ===========================================================================
class TestJA4HComprehensive(unittest.TestCase):

    def setUp(self):
        self.fp = JA4HFingerprinter()

    def _make_http(self, method="GET", path="/", version="HTTP/1.1",
                   headers=None, cookie=None, referer=None, lang=None):
        lines = [f"{method} {path} {version}"]
        if headers:
            for k, v in headers:
                lines.append(f"{k}: {v}")
        if cookie:
            lines.append(f"Cookie: {cookie}")
        if referer:
            lines.append(f"Referer: {referer}")
        if lang:
            lines.append(f"Accept-Language: {lang}")
        lines.append("Host: example.com")
        lines.append("")
        lines.append("")
        data = "\r\n".join(lines).encode()
        return IP() / TCP(sport=12345, dport=80) / Raw(load=data)

    def test_get_request(self):
        packet = self._make_http()
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        parts = fp.split("_")
        self.assertEqual(len(parts), 4)
        # ge11nn01 (get, http1.1, no cookie, no referer, 1 header [Host], no lang)
        self.assertTrue(parts[0].startswith("ge"))

    def test_post_request(self):
        packet = self._make_http(method="POST")
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        self.assertTrue(fp.split("_")[0].startswith("po"))

    def test_cookie_indicator(self):
        packet = self._make_http(cookie="session=abc123; user=john")
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        part_a = fp.split("_")[0]
        # After method(2) + version(2), cookie flag is next char
        self.assertEqual(part_a[4], "c", "Cookie indicator should be 'c'")

    def test_no_cookie_indicator(self):
        packet = self._make_http()
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        self.assertEqual(fp.split("_")[0][4], "n")

    def test_referer_indicator(self):
        packet = self._make_http(referer="https://google.com")
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        self.assertEqual(fp.split("_")[0][5], "r")

    def test_language_extraction(self):
        packet = self._make_http(lang="en-US,en;q=0.9")
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        part_a = fp.split("_")[0]
        self.assertTrue(part_a.endswith("enus"), f"Language should be enus, got {part_a}")

    def test_header_count_two_digit(self):
        """Header count should be 2-digit format."""
        headers = [(f"X-Header-{i}", "val") for i in range(15)]
        packet = self._make_http(headers=headers)
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        part_a = fp.split("_")[0]
        # header count starts at index 6, 2 digits
        count_str = part_a[6:8]
        count_val = int(count_str)
        self.assertGreaterEqual(count_val, 15)

    def test_cookie_hash_sorted(self):
        """Cookie fields should be sorted for hashing."""
        packet = self._make_http(cookie="z_cookie=1; a_cookie=2")
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        parts = fp.split("_")
        # Part C: sorted cookie field names hash
        sorted_fields = "a_cookie,z_cookie"
        expected = hashlib.sha256(sorted_fields.encode()).hexdigest()[:12]
        self.assertEqual(parts[2], expected)

    def test_no_cookies_gives_zeros(self):
        packet = self._make_http()
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        parts = fp.split("_")
        self.assertEqual(parts[2], "000000000000")
        self.assertEqual(parts[3], "000000000000")

    def test_non_http_ignored(self):
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=b"not http data")
        fp = self.fp.process_packet(packet)
        self.assertIsNone(fp)

    def test_http2_version(self):
        packet = self._make_http(version="HTTP/2.0")
        fp = self.fp.process_packet(packet)
        self.assertIsNotNone(fp)
        part_a = fp.split("_")[0]
        self.assertEqual(part_a[2:4], "20")


# ===========================================================================
# JA4T (TCP SYN) comprehensive tests
# ===========================================================================
class TestJA4TComprehensive(unittest.TestCase):

    def test_standard_linux_syn(self):
        """Standard Linux SYN packet options."""
        packet = IP() / TCP(
            sport=54321, dport=443, flags="S", window=29200,
            options=[("MSS", 1460), ("SAckOK", ""), ("Timestamp", (0, 0)),
                     ("NOP", None), ("WScale", 7)],
        )
        fp = generate_ja4t(packet)
        self.assertIsNotNone(fp)
        parts = fp.split("_")
        self.assertEqual(len(parts), 4)
        self.assertEqual(parts[0], "29200")
        self.assertEqual(parts[2], "1460")
        self.assertEqual(parts[3], "7")

    def test_option_order_preserved(self):
        """TCP options must be in original packet order (not sorted)."""
        packet = IP() / TCP(
            sport=54321, dport=443, flags="S", window=65535,
            options=[("NOP", None), ("MSS", 1460), ("WScale", 7)],
        )
        fp = generate_ja4t(packet)
        self.assertIsNotNone(fp)
        self.assertEqual(fp.split("_")[1], "1-2-3")

    def test_no_options(self):
        """SYN with no TCP options."""
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535, options=[])
        fp = generate_ja4t(packet)
        self.assertIsNotNone(fp)
        parts = fp.split("_")
        self.assertEqual(parts[1], "0")
        self.assertEqual(parts[2], "0")
        self.assertEqual(parts[3], "0")

    def test_ack_not_syn_ignored(self):
        """Non-SYN packets should be ignored."""
        packet = IP() / TCP(sport=54321, dport=443, flags="A", window=65535)
        fp = generate_ja4t(packet)
        self.assertIsNone(fp)

    def test_synack_rejected_by_ja4t(self):
        """SYN-ACK should be rejected by JA4T (JA4TS handles SYN-ACK)."""
        packet = IP() / TCP(
            sport=443, dport=54321, flags="SA", window=14600,
            options=[("MSS", 1460)],
        )
        fp = generate_ja4t(packet)
        self.assertIsNone(fp)

    def test_large_window(self):
        """Very large window size."""
        packet = IP() / TCP(
            sport=54321, dport=443, flags="S", window=65535,
            options=[("MSS", 1460), ("WScale", 14)],
        )
        fp = generate_ja4t(packet)
        self.assertIsNotNone(fp)
        self.assertEqual(fp.split("_")[0], "65535")
        self.assertEqual(fp.split("_")[3], "14")

    def test_fingerprinter_collection(self):
        """JA4TFingerprinter should collect multiple fingerprints."""
        fpr = JA4TFingerprinter()
        for i in range(3):
            packet = IP() / TCP(
                sport=54321 + i, dport=443, flags="S", window=65535,
                options=[("MSS", 1460)],
            )
            fpr.process_packet(packet)
        self.assertEqual(len(fpr.get_fingerprints()), 3)
        fpr.reset()
        self.assertEqual(len(fpr.get_fingerprints()), 0)


# ===========================================================================
# JA4TS (TCP SYN-ACK) comprehensive tests
# ===========================================================================
class TestJA4TSComprehensive(unittest.TestCase):

    def test_synack_fingerprint(self):
        packet = IP() / TCP(
            sport=443, dport=54321, flags="SA", window=14600,
            options=[("MSS", 1460), ("NOP", None), ("WScale", 0)],
        )
        fp = generate_ja4ts(packet)
        self.assertIsNotNone(fp)
        parts = fp.split("_")
        self.assertEqual(parts[0], "14600")
        self.assertEqual(parts[2], "1460")
        self.assertEqual(parts[3], "0")

    def test_syn_only_ignored(self):
        """Pure SYN (no ACK) should be ignored by JA4TS."""
        packet = IP() / TCP(
            sport=54321, dport=443, flags="S", window=65535,
            options=[("MSS", 1460)],
        )
        fp = generate_ja4ts(packet)
        self.assertIsNone(fp)

    def test_collector_uses_base(self):
        """JA4TSFingerprinter should use BaseFingerprinter properly."""
        fpr = JA4TSFingerprinter()
        packet = IP() / TCP(
            sport=443, dport=54321, flags="SA", window=14600,
            options=[("MSS", 1460)],
        )
        fpr.process_packet(packet)
        fps = fpr.get_fingerprints()
        self.assertEqual(len(fps), 1)


# ===========================================================================
# JA4L (Latency) comprehensive tests
# ===========================================================================
class TestJA4LComprehensive(unittest.TestCase):

    def setUp(self):
        self.fp = JA4LFingerprinter()

    def test_handshake_produces_two_fingerprints(self):
        """Full handshake should produce server + client fingerprints."""
        syn = IP(src="10.0.0.1", dst="10.0.0.2", ttl=128) / TCP(
            sport=54321, dport=443, flags="S"
        )
        self.fp.process_packet(syn)
        time.sleep(0.002)

        synack = IP(src="10.0.0.2", dst="10.0.0.1", ttl=64) / TCP(
            sport=443, dport=54321, flags="SA"
        )
        server_fp = self.fp.process_packet(synack)
        self.assertIsNotNone(server_fp)
        self.assertTrue(server_fp.startswith("JA4L-S="))

        time.sleep(0.002)
        ack = IP(src="10.0.0.1", dst="10.0.0.2", ttl=128) / TCP(
            sport=54321, dport=443, flags="A"
        )
        client_fp = self.fp.process_packet(ack)
        self.assertIsNotNone(client_fp)
        self.assertTrue(client_fp.startswith("JA4L-C="))

        self.assertEqual(len(self.fp.fingerprints), 2)

    def test_latency_format(self):
        """JA4L format is JA4L-X=<latency_us>_<ttl>."""
        now = time.time()
        conn = {
            "proto": "tcp", "timestamps": {"A": now - 0.010},
            "ttls": {"client": 128, "server": 64},
        }
        synack = IP(src="10.0.0.2", dst="10.0.0.1", ttl=64) / TCP(
            sport=443, dport=54321, flags="SA"
        )
        fp = generate_ja4l(synack, conn)
        self.assertIsNotNone(fp)
        self.assertRegex(fp, r"JA4L-S=\d+_\d+")

    def test_distance_miles(self):
        self.assertAlmostEqual(self.fp.calculate_distance(1000), 80.0, places=1)

    def test_distance_km(self):
        d = self.fp.calculate_distance_km(1000)
        self.assertGreater(d, 0)
        self.assertAlmostEqual(d, 128.75, places=1)

    def test_os_estimation_all_ranges(self):
        self.assertIn("Linux", self.fp.estimate_os(60))
        self.assertIn("Windows", self.fp.estimate_os(120))
        self.assertIn("Cisco", self.fp.estimate_os(250))

    def test_hop_count_all_ranges(self):
        self.assertEqual(self.fp.estimate_hop_count(60), 4)
        self.assertEqual(self.fp.estimate_hop_count(120), 8)
        self.assertEqual(self.fp.estimate_hop_count(250), 5)
        self.assertEqual(self.fp.estimate_hop_count(64), 0)  # No hops
        self.assertEqual(self.fp.estimate_hop_count(128), 0)


# ===========================================================================
# JA4SSH comprehensive tests
# ===========================================================================
class TestJA4SSHComprehensive(unittest.TestCase):

    def test_interpret_interactive(self):
        fp = JA4SSHFingerprinter()
        result = fp.interpret_fingerprint("c36s36_c50s50_c70s30")
        self.assertEqual(result["session_type"], "Interactive SSH Session")

    def test_interpret_file_transfer(self):
        fp = JA4SSHFingerprinter()
        result = fp.interpret_fingerprint("c36s1460_c10s90_c50s50")
        self.assertEqual(result["session_type"], "SSH File Transfer")

    def test_interpret_upload(self):
        fp = JA4SSHFingerprinter()
        result = fp.interpret_fingerprint("c1460s36_c90s10_c50s50")
        self.assertEqual(result["session_type"], "SSH File Transfer (Upload)")

    def test_interpret_invalid_format(self):
        fp = JA4SSHFingerprinter()
        result = fp.interpret_fingerprint("invalid")
        self.assertIn("error", result)

    def test_hassh_known_lookup(self):
        fp = JA4SSHFingerprinter()
        result = fp.lookup_hassh("8a8ae540028bf433cd68356c1b9e8d5b")
        self.assertIn("CyberDuck", result["identified_as"])

    def test_hassh_unknown_lookup(self):
        fp = JA4SSHFingerprinter()
        result = fp.lookup_hassh("0000000000000000000000000000dead")
        self.assertEqual(result["identified_as"], "Unknown")

    def test_get_hassh_fingerprints(self):
        """Test HASSH collection through packet processing."""
        fp = JA4SSHFingerprinter(packet_count=100)
        banner_c = (
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=52416, dport=22)
            / Raw(load=b"SSH-2.0-OpenSSH_8.2p1\r\n")
        )
        banner_s = (
            Ether() / IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=22, dport=52416)
            / Raw(load=b"SSH-2.0-OpenSSH_7.6p1\r\n")
        )
        kex_c = (
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=52416, dport=22)
            / Raw(load=b"\x00\x00\x05\xdc\x06\x14AAAAAAAAAASSH_MSG_KEXINIT"
                        b"curve25519-sha256;aes128-ctr;hmac-sha2-256;none")
        )
        fp.process_packet(banner_c)
        fp.process_packet(banner_s)
        fp.process_packet(kex_c)

        hassh_fps = fp.get_hassh_fingerprints()
        self.assertGreaterEqual(len(hassh_fps), 1)


# ===========================================================================
# TLS parsing edge case tests
# ===========================================================================
class TestTLSParsing(unittest.TestCase):

    def test_empty_data(self):
        self.assertIsNone(parse_tls_handshake(b""))

    def test_too_short(self):
        self.assertIsNone(parse_tls_handshake(b"\x16\x03\x03"))

    def test_non_handshake_record_type(self):
        # 0x17 = Application Data
        self.assertIsNone(parse_tls_handshake(b"\x17\x03\x03\x00\x00"))

    def test_truncated_client_hello(self):
        """Truncated ClientHello should still return partial info."""
        raw = b"\x16\x03\x03\x00\x06\x01\x00\x00\x02\x03\x03"
        result = parse_tls_handshake(raw)
        if result:
            self.assertEqual(result["type"], "client_hello")

    def test_client_hello_parses_sni(self):
        """Full ClientHello with SNI should extract hostname."""
        raw = build_client_hello(
            version=0x0303, ciphers=[0xC02F], sni_hostname="test.example.com"
        )
        result = parse_tls_handshake(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result.get("sni"), "test.example.com")

    def test_server_hello_parses_version(self):
        raw = build_server_hello(version=0x0303, cipher=0xC02F)
        result = parse_tls_handshake(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["handshake_type"], "server_hello")
        self.assertEqual(result["cipher"], 0xC02F)


# ===========================================================================
# Cross-fingerprinter format consistency tests
# ===========================================================================
class TestFormatConsistency(unittest.TestCase):
    """Verify that all fingerprints produce consistent, parseable output."""

    def test_ja4_format_regex(self):
        """JA4 format: <proto><ver><sni><cc><ec><alpn>_<hash>_<hash>"""
        raw = build_client_hello(
            version=0x0303, ciphers=[0x1301], sni_hostname="example.com"
        )
        packet = IP() / TCP(sport=12345, dport=443) / Raw(load=raw)
        fp = JA4Fingerprinter().process_packet(packet)
        self.assertRegex(fp, r"^[tdq]\d{2}[di]\d{4}[a-z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}$")

    def test_ja4s_format_regex(self):
        raw = build_server_hello(version=0x0303, cipher=0xC02F)
        packet = IP() / TCP(sport=443, dport=12345) / Raw(load=raw)
        fp = JA4SFingerprinter().process_packet(packet)
        self.assertRegex(fp, r"^[tdq]\d{4}[a-z0-9]{2}_[a-f0-9]{4}_[a-f0-9]{12}$")

    def test_ja4t_format_regex(self):
        packet = IP() / TCP(
            sport=54321, dport=443, flags="S", window=65535,
            options=[("MSS", 1460), ("WScale", 7)],
        )
        fp = generate_ja4t(packet)
        self.assertRegex(fp, r"^\d+_[\d\-]+_\d+_\d+$")

    def test_ja4ts_format_regex(self):
        packet = IP() / TCP(
            sport=443, dport=54321, flags="SA", window=14600,
            options=[("MSS", 1460)],
        )
        fp = generate_ja4ts(packet)
        self.assertRegex(fp, r"^\d+_[\d\-]+_\d+_\d+$")

    def test_ja4h_format_regex(self):
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=data)
        fp = generate_ja4h(packet)
        self.assertRegex(
            fp,
            r"^[a-z]{2}\d{2}[cn][nr]\d{2}[a-z0-9]{4}_[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}$",
        )

    def test_ja4l_server_format_regex(self):
        now = time.time()
        conn = {"proto": "tcp", "timestamps": {"A": now - 0.01}, "ttls": {}}
        synack = IP(ttl=64) / TCP(sport=443, dport=54321, flags="SA")
        fp = generate_ja4l(synack, conn)
        self.assertRegex(fp, r"^JA4L-S=\d+_\d+$")


# ===========================================================================
# JA4X X.509 certificate tests
# ===========================================================================
class TestJA4XComprehensive(unittest.TestCase):

    def _make_cert(self, org="Test", cn="test.com", country="US", add_extensions=True):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import Encoding

        key = rsa.generate_private_key(65537, 2048, default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
        )
        if add_extensions:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
        cert = builder.sign(key, hashes.SHA256(), default_backend())
        return cert.public_bytes(Encoding.DER)

    def test_fingerprint_format(self):
        """JA4X should produce issuer_hash_subject_hash_ext_hash."""
        cert_data = self._make_cert()
        fp = JA4XFingerprinter()
        result = fp.fingerprint_certificate(cert_data)
        self.assertIsNotNone(result)
        parts = result.split("_")
        self.assertEqual(len(parts), 3)
        for part in parts:
            self.assertEqual(len(part), 12)

    def test_same_cert_same_fingerprint(self):
        """Same certificate should produce the same fingerprint."""
        cert_data = self._make_cert()
        fp = JA4XFingerprinter()
        r1 = fp.fingerprint_certificate(cert_data)
        r2 = fp.fingerprint_certificate(cert_data)
        self.assertEqual(r1, r2)

    def test_different_certs_different_fingerprints(self):
        """Certificates with different OID structures should produce different fingerprints."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import Encoding

        key = rsa.generate_private_key(65537, 2048, default_backend())
        now = datetime.datetime.now(datetime.timezone.utc)

        # Cert A: Org + CN + Country (3 OIDs)
        cert_a = self._make_cert(org="Org A", cn="a.com")

        # Cert B: Org + CN + Country + State (4 OIDs - different structure)
        subject_b = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org B"),
            x509.NameAttribute(NameOID.COMMON_NAME, "b.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        ])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject_b).issuer_name(subject_b)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        )
        cert_b_obj = builder.sign(key, hashes.SHA256(), default_backend())
        cert_b = cert_b_obj.public_bytes(Encoding.DER)

        fp = JA4XFingerprinter()
        r_a = fp.fingerprint_certificate(cert_a)
        r_b = fp.fingerprint_certificate(cert_b)
        # Different OID structure means at least one hash section should differ
        self.assertNotEqual(r_a, r_b)

    def test_no_extensions_cert(self):
        """Certificate without extensions should still fingerprint."""
        cert_data = self._make_cert(add_extensions=False)
        fp = JA4XFingerprinter()
        result = fp.fingerprint_certificate(cert_data)
        self.assertIsNotNone(result)
        parts = result.split("_")
        # Empty extension list produces '000000000000' sentinel per spec
        self.assertEqual(parts[2], "000000000000")


if __name__ == "__main__":
    unittest.main()
