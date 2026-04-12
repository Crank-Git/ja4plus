"""
Deep tests for JA4 (TLS Client Hello) fingerprinting.

Covers GREASE filtering, cipher sorting, extension hashing, ALPN encoding,
version mapping, SNI detection, count capping, empty values, and raw formats.
"""

import unittest
import hashlib
from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4 import (
    JA4Fingerprinter,
    generate_ja4,
    get_raw_fingerprint,
)
from ja4plus.utils.tls_utils import is_grease_value


def _build_ch(version=0x0303, ciphers=None, sni=None, alpn=None,
              supported_versions=None, sig_algs=None, extra_exts=None):
    """Helper to build a TLS ClientHello record."""
    if ciphers is None:
        ciphers = [0x1301]
    if extra_exts is None:
        extra_exts = []

    ch = bytearray()
    ch += version.to_bytes(2, "big")
    ch += b"\x00" * 32  # random
    ch += b"\x00"  # session ID length

    cs = bytearray()
    for c in ciphers:
        cs += c.to_bytes(2, "big")
    ch += len(cs).to_bytes(2, "big") + cs
    ch += b"\x01\x00"  # compression

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

    for ext_type in extra_exts:
        ext_data += ext_type.to_bytes(2, "big") + b"\x00\x00"

    if ext_data:
        ch += len(ext_data).to_bytes(2, "big") + ext_data

    hs = b"\x01" + len(ch).to_bytes(3, "big") + bytes(ch)
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def _make_packet(raw_bytes):
    return IP() / TCP(sport=12345, dport=443) / Raw(load=raw_bytes)


def _tls_info(**kwargs):
    """Build a tls_info dict for direct generate_ja4 testing."""
    defaults = {
        "type": "client_hello",
        "version": 0x0303,
        "is_quic": False,
        "is_dtls": False,
        "supported_versions": [],
        "sni": None,
        "ciphers": [0x1301],
        "extensions": [0x000a, 0x000b],
        "alpn_protocols": [],
        "signature_algorithms": [],
    }
    defaults.update(kwargs)
    return defaults


class TestJA4VersionMapping(unittest.TestCase):
    """Test TLS/SSL/DTLS version string mapping."""

    def _fp_version(self, version, supported_versions=None):
        info = _tls_info(version=version, supported_versions=supported_versions or [])
        fp = generate_ja4(info)
        return fp.split("_")[0][1:3]  # version portion

    def test_tls13(self):
        self.assertEqual(self._fp_version(0x0303, [0x0304]), "13")

    def test_tls12(self):
        self.assertEqual(self._fp_version(0x0303), "12")

    def test_tls11(self):
        self.assertEqual(self._fp_version(0x0302), "11")

    def test_tls10(self):
        self.assertEqual(self._fp_version(0x0301), "10")

    def test_ssl30(self):
        self.assertEqual(self._fp_version(0x0300), "s3")

    def test_ssl20(self):
        self.assertEqual(self._fp_version(0x0200), "s2")

    def test_dtls10(self):
        self.assertEqual(self._fp_version(0xFEFF), "d1")

    def test_dtls12(self):
        self.assertEqual(self._fp_version(0xFEFD), "d2")

    def test_dtls13(self):
        self.assertEqual(self._fp_version(0xFEFC), "d3")

    def test_unknown_version(self):
        self.assertEqual(self._fp_version(0x1234), "00")

    def test_supported_versions_overrides_protocol_version(self):
        """supported_versions extension should take priority."""
        info = _tls_info(version=0x0301, supported_versions=[0x0304, 0x0303])
        fp = generate_ja4(info)
        self.assertTrue(fp.split("_")[0].startswith("t13"))


class TestJA4SNI(unittest.TestCase):
    """Test SNI indicator in JA4 fingerprint."""

    def test_sni_present_uses_d(self):
        info = _tls_info(sni="example.com")
        fp = generate_ja4(info)
        self.assertEqual(fp.split("_")[0][3], "d")

    def test_sni_absent_uses_i(self):
        info = _tls_info(sni=None)
        fp = generate_ja4(info)
        self.assertEqual(fp.split("_")[0][3], "i")

    def test_sni_empty_string_uses_i(self):
        info = _tls_info(sni="")
        fp = generate_ja4(info)
        self.assertEqual(fp.split("_")[0][3], "i")

    def test_sni_from_raw_packet(self):
        raw = _build_ch(sni="test.example.com")
        packet = _make_packet(raw)
        fp = JA4Fingerprinter()
        result = fp.process_packet(packet)
        self.assertIsNotNone(result)
        self.assertEqual(result.split("_")[0][3], "d")


class TestJA4ALPN(unittest.TestCase):
    """Test ALPN encoding (first + last char of first protocol)."""

    def test_h2_gives_h2(self):
        info = _tls_info(alpn_protocols=["h2"])
        fp = generate_ja4(info)
        self.assertTrue(fp.split("_")[0].endswith("h2"))

    def test_http11_gives_h1(self):
        info = _tls_info(alpn_protocols=["http/1.1"])
        fp = generate_ja4(info)
        self.assertTrue(fp.split("_")[0].endswith("h1"))

    def test_no_alpn_gives_00(self):
        info = _tls_info(alpn_protocols=[])
        fp = generate_ja4(info)
        self.assertTrue(fp.split("_")[0].endswith("00"))

    def test_multiple_alpn_uses_first(self):
        """Only the first ALPN protocol is used."""
        info = _tls_info(alpn_protocols=["h2", "http/1.1"])
        fp = generate_ja4(info)
        self.assertTrue(fp.split("_")[0].endswith("h2"))

    def test_single_char_protocol(self):
        """Single char protocol uses same char for both positions."""
        info = _tls_info(alpn_protocols=["x"])
        fp = generate_ja4(info)
        self.assertTrue(fp.split("_")[0].endswith("xx"))

    def test_empty_first_protocol_gives_00(self):
        info = _tls_info(alpn_protocols=[""])
        fp = generate_ja4(info)
        self.assertTrue(fp.split("_")[0].endswith("00"))

    def test_alpn_from_raw_packet(self):
        raw = _build_ch(sni="test.com", alpn=["h2"])
        packet = _make_packet(raw)
        fp = JA4Fingerprinter()
        result = fp.process_packet(packet)
        self.assertIsNotNone(result)
        self.assertTrue(result.split("_")[0].endswith("h2"))


class TestJA4GREASEFiltering(unittest.TestCase):
    """Test that GREASE values are filtered from counts and hashes."""

    def test_grease_ciphers_excluded_from_count(self):
        ciphers = [0x0A0A, 0x1301, 0x1302, 0xFAFA]
        info = _tls_info(ciphers=ciphers, sni="test.com")
        fp = generate_ja4(info)
        # Only 2 non-GREASE ciphers
        cipher_count = fp.split("_")[0][4:6]
        self.assertEqual(cipher_count, "02")

    def test_grease_extensions_excluded_from_count(self):
        extensions = [0x0A0A, 0x000A, 0x000B, 0x1A1A]
        info = _tls_info(extensions=extensions, sni="test.com")
        fp = generate_ja4(info)
        ext_count = fp.split("_")[0][6:8]
        self.assertEqual(ext_count, "02")

    def test_grease_ciphers_excluded_from_hash(self):
        """Cipher hash should not include GREASE values."""
        ciphers = [0x0A0A, 0x1301, 0xFAFA]
        info = _tls_info(ciphers=ciphers)
        fp = generate_ja4(info)
        # Hash should be based only on [0x1301] sorted
        expected = hashlib.sha256("1301".encode()).hexdigest()[:12]
        self.assertEqual(fp.split("_")[1], expected)

    def test_grease_in_supported_versions_filtered(self):
        """GREASE values in supported_versions should be filtered."""
        info = _tls_info(
            version=0x0303,
            supported_versions=[0x0A0A, 0x0304, 0xFAFA]
        )
        fp = generate_ja4(info)
        self.assertTrue(fp.split("_")[0].startswith("t13"))


class TestJA4CipherHash(unittest.TestCase):
    """Test that cipher hash uses sorted hex values."""

    def test_ciphers_sorted_for_hash(self):
        ciphers = [0xC030, 0xC02F, 0x1301]
        info = _tls_info(ciphers=ciphers)
        fp = generate_ja4(info)
        sorted_hex = ",".join([f"{c:04x}" for c in sorted(ciphers)])
        expected = hashlib.sha256(sorted_hex.encode()).hexdigest()[:12]
        self.assertEqual(fp.split("_")[1], expected)

    def test_single_cipher(self):
        info = _tls_info(ciphers=[0xC02F])
        fp = generate_ja4(info)
        expected = hashlib.sha256("c02f".encode()).hexdigest()[:12]
        self.assertEqual(fp.split("_")[1], expected)

    def test_empty_ciphers_give_zeros(self):
        info = _tls_info(ciphers=[])
        fp = generate_ja4(info)
        self.assertEqual(fp.split("_")[1], "000000000000")


class TestJA4ExtensionHash(unittest.TestCase):
    """Test extension hash: excludes SNI/ALPN, sorts, appends sig_algs."""

    def test_sni_and_alpn_excluded(self):
        """Extensions 0x0000 (SNI) and 0x0010 (ALPN) should be excluded."""
        extensions = [0x0000, 0x000A, 0x0010, 0x000B]
        info = _tls_info(extensions=extensions)
        fp = generate_ja4(info)
        # Only 0x000A and 0x000B should be in hash (sorted)
        ext_str = "000a,000b"
        expected = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
        self.assertEqual(fp.split("_")[2], expected)

    def test_extensions_sorted(self):
        """Remaining extensions should be sorted by hex value."""
        extensions = [0x0033, 0x000A, 0x002B]
        info = _tls_info(extensions=extensions)
        fp = generate_ja4(info)
        ext_str = "000a,002b,0033"
        expected = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
        self.assertEqual(fp.split("_")[2], expected)

    def test_sig_algs_appended_in_original_order(self):
        """Signature algorithms should be appended after underscore in original order."""
        extensions = [0x000A, 0x000D]
        sig_algs = [0x0804, 0x0403, 0x0401]
        info = _tls_info(extensions=extensions, signature_algorithms=sig_algs)
        fp = generate_ja4(info)
        # Extensions (sorted, excl SNI/ALPN): 000a,000d
        # sig_algs (original order): 0804,0403,0401
        ext_str = "000a,000d_0804,0403,0401"
        expected = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
        self.assertEqual(fp.split("_")[2], expected)

    def test_no_extensions_give_zeros(self):
        info = _tls_info(extensions=[])
        fp = generate_ja4(info)
        self.assertEqual(fp.split("_")[2], "000000000000")

    def test_only_sni_and_alpn_gives_zeros(self):
        """If only SNI and ALPN are present, hash should be empty->zeros."""
        info = _tls_info(extensions=[0x0000, 0x0010])
        fp = generate_ja4(info)
        self.assertEqual(fp.split("_")[2], "000000000000")


class TestJA4CountCapping(unittest.TestCase):
    """Test that cipher and extension counts are capped at 99."""

    def test_cipher_count_capped_at_99(self):
        ciphers = list(range(0x0001, 0x0001 + 150))  # 150 ciphers
        info = _tls_info(ciphers=ciphers, sni="test.com")
        fp = generate_ja4(info)
        cipher_count = fp.split("_")[0][4:6]
        self.assertEqual(cipher_count, "99")

    def test_extension_count_capped_at_99(self):
        extensions = list(range(0x0100, 0x0100 + 150))  # 150 extensions
        info = _tls_info(extensions=extensions, sni="test.com")
        fp = generate_ja4(info)
        ext_count = fp.split("_")[0][6:8]
        self.assertEqual(ext_count, "99")


class TestJA4Protocol(unittest.TestCase):
    """Test protocol indicator (t, q, d)."""

    def test_tcp_protocol(self):
        info = _tls_info(is_quic=False, is_dtls=False)
        fp = generate_ja4(info)
        self.assertEqual(fp[0], "t")

    def test_quic_protocol(self):
        info = _tls_info(is_quic=True, is_dtls=False)
        fp = generate_ja4(info)
        self.assertEqual(fp[0], "q")

    def test_dtls_protocol(self):
        info = _tls_info(is_quic=False, is_dtls=True)
        fp = generate_ja4(info)
        self.assertEqual(fp[0], "d")


class TestJA4Format(unittest.TestCase):
    """Test overall JA4 fingerprint format."""

    def test_three_parts(self):
        info = _tls_info()
        fp = generate_ja4(info)
        self.assertEqual(len(fp.split("_")), 3)

    def test_part_a_length(self):
        """part_a should be 10 chars: proto(1)+ver(2)+sni(1)+cc(2)+ec(2)+alpn(2)."""
        info = _tls_info(sni="test.com", alpn_protocols=["h2"])
        fp = generate_ja4(info)
        part_a = fp.split("_")[0]
        self.assertEqual(len(part_a), 10)

    def test_hash_parts_are_12_chars(self):
        info = _tls_info(ciphers=[0x1301], extensions=[0x000A])
        fp = generate_ja4(info)
        parts = fp.split("_")
        self.assertEqual(len(parts[1]), 12)
        self.assertEqual(len(parts[2]), 12)


class TestJA4RawFingerprint(unittest.TestCase):
    """Test raw fingerprint generation (JA4_r and JA4_ro)."""

    def test_raw_sorted_format(self):
        info = _tls_info(ciphers=[0xC02F, 0x1301], sni="test.com")
        raw = get_raw_fingerprint(info, original_order=False)
        self.assertIsNotNone(raw)
        # Returns clean fingerprint string (no "JA4_r = " prefix)
        self.assertFalse(raw.startswith("JA4_"))
        self.assertIn("_", raw)

    def test_raw_original_order_format(self):
        info = _tls_info(ciphers=[0xC02F, 0x1301], sni="test.com")
        raw = get_raw_fingerprint(info, original_order=True)
        self.assertIsNotNone(raw)
        # Returns clean fingerprint string (no "JA4_ro = " prefix)
        self.assertFalse(raw.startswith("JA4_"))
        self.assertIn("_", raw)

    def test_raw_contains_cipher_hex(self):
        info = _tls_info(ciphers=[0x1301, 0xC02F])
        raw = get_raw_fingerprint(info, original_order=False)
        self.assertIn("1301", raw)
        self.assertIn("c02f", raw)

    def test_raw_not_client_hello_returns_none(self):
        info = {"type": "server_hello"}
        self.assertIsNone(get_raw_fingerprint(info))

    def test_raw_none_returns_none(self):
        self.assertIsNone(get_raw_fingerprint(None))


class TestJA4FingerprinterClass(unittest.TestCase):
    """Test the JA4Fingerprinter class interface."""

    def test_process_and_collect(self):
        raw = _build_ch(sni="test.com", ciphers=[0x1301])
        packet = _make_packet(raw)
        fp = JA4Fingerprinter()
        result = fp.process_packet(packet)
        self.assertIsNotNone(result)
        self.assertEqual(len(fp.get_fingerprints()), 1)

    def test_multiple_packets(self):
        fp = JA4Fingerprinter()
        for i in range(5):
            raw = _build_ch(sni=f"test{i}.com", ciphers=[0x1301])
            packet = _make_packet(raw)
            fp.process_packet(packet)
        self.assertEqual(len(fp.get_fingerprints()), 5)

    def test_reset(self):
        fp = JA4Fingerprinter()
        raw = _build_ch(sni="test.com", ciphers=[0x1301])
        fp.process_packet(_make_packet(raw))
        fp.reset()
        self.assertEqual(len(fp.get_fingerprints()), 0)

    def test_get_raw_fingerprint_via_class(self):
        raw = _build_ch(sni="test.com", ciphers=[0x1301, 0xC02F])
        packet = _make_packet(raw)
        fp = JA4Fingerprinter()
        result = fp.get_raw_fingerprint(packet)
        self.assertIsNotNone(result)
        # Returns clean fingerprint string (no "JA4_r = " prefix)
        self.assertFalse(result.startswith("JA4_"))
        self.assertIn("_", result)


if __name__ == "__main__":
    unittest.main()
