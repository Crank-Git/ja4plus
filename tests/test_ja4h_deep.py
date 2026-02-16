"""
Deep tests for JA4H (HTTP Request) fingerprinting.

Covers all HTTP methods, version parsing, cookie/referer indicators,
header counting, language extraction, and hash computation.
"""

import unittest
import hashlib
from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4h import JA4HFingerprinter, generate_ja4h


def _make_http(method="GET", path="/", version="HTTP/1.1",
               headers=None, cookie=None, referer=None, lang=None):
    """Build an HTTP request packet."""
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


class TestJA4HMethodEncoding(unittest.TestCase):
    """Test HTTP method encoding (first 2 chars, lowercase)."""

    def _get_method_code(self, method):
        packet = _make_http(method=method)
        fp = generate_ja4h(packet)
        self.assertIsNotNone(fp, f"Fingerprint failed for method {method}")
        return fp.split("_")[0][:2]

    def test_get(self):
        self.assertEqual(self._get_method_code("GET"), "ge")

    def test_post(self):
        self.assertEqual(self._get_method_code("POST"), "po")

    def test_put(self):
        self.assertEqual(self._get_method_code("PUT"), "pu")

    def test_delete(self):
        self.assertEqual(self._get_method_code("DELETE"), "de")

    def test_head(self):
        self.assertEqual(self._get_method_code("HEAD"), "he")

    def test_options(self):
        self.assertEqual(self._get_method_code("OPTIONS"), "op")

    def test_patch(self):
        self.assertEqual(self._get_method_code("PATCH"), "pa")

    def test_connect(self):
        self.assertEqual(self._get_method_code("CONNECT"), "co")

    def test_trace(self):
        self.assertEqual(self._get_method_code("TRACE"), "tr")


class TestJA4HVersionParsing(unittest.TestCase):
    """Test HTTP version parsing."""

    def _get_version_code(self, version):
        packet = _make_http(version=version)
        fp = generate_ja4h(packet)
        self.assertIsNotNone(fp)
        return fp.split("_")[0][2:4]

    def test_http11(self):
        self.assertEqual(self._get_version_code("HTTP/1.1"), "11")

    def test_http10(self):
        self.assertEqual(self._get_version_code("HTTP/1.0"), "10")

    def test_http20(self):
        self.assertEqual(self._get_version_code("HTTP/2.0"), "20")


class TestJA4HCookieIndicator(unittest.TestCase):
    """Test cookie presence indicator (c/n)."""

    def test_cookie_present(self):
        packet = _make_http(cookie="session=abc")
        fp = generate_ja4h(packet)
        self.assertEqual(fp.split("_")[0][4], "c")

    def test_cookie_absent(self):
        packet = _make_http()
        fp = generate_ja4h(packet)
        self.assertEqual(fp.split("_")[0][4], "n")

    def test_multiple_cookies(self):
        packet = _make_http(cookie="a=1; b=2; c=3")
        fp = generate_ja4h(packet)
        self.assertEqual(fp.split("_")[0][4], "c")


class TestJA4HRefererIndicator(unittest.TestCase):
    """Test referer presence indicator (r/n)."""

    def test_referer_present(self):
        packet = _make_http(referer="https://google.com")
        fp = generate_ja4h(packet)
        self.assertEqual(fp.split("_")[0][5], "r")

    def test_referer_absent(self):
        packet = _make_http()
        fp = generate_ja4h(packet)
        self.assertEqual(fp.split("_")[0][5], "n")


class TestJA4HHeaderCount(unittest.TestCase):
    """Test header counting (excluding Cookie and Referer)."""

    def test_single_header(self):
        """Only Host header (added by _make_http)."""
        packet = _make_http()
        fp = generate_ja4h(packet)
        part_a = fp.split("_")[0]
        count = int(part_a[6:8])
        self.assertEqual(count, 1)  # Just Host

    def test_multiple_headers(self):
        headers = [
            ("User-Agent", "Mozilla/5.0"),
            ("Accept", "text/html"),
            ("Accept-Encoding", "gzip"),
        ]
        packet = _make_http(headers=headers)
        fp = generate_ja4h(packet)
        part_a = fp.split("_")[0]
        count = int(part_a[6:8])
        # 3 explicit headers + Host = 4
        self.assertEqual(count, 4)

    def test_cookie_and_referer_excluded_from_count(self):
        """Cookie and Referer should not be counted."""
        headers = [("User-Agent", "test"), ("Accept", "*/*")]
        packet = _make_http(headers=headers, cookie="a=1", referer="https://x.com")
        fp = generate_ja4h(packet)
        part_a = fp.split("_")[0]
        count = int(part_a[6:8])
        # User-Agent + Accept + Host = 3 (Cookie and Referer excluded)
        self.assertEqual(count, 3)

    def test_header_count_two_digit_format(self):
        """Count should always be 2 digits."""
        packet = _make_http()
        fp = generate_ja4h(packet)
        part_a = fp.split("_")[0]
        count_str = part_a[6:8]
        self.assertEqual(len(count_str), 2)
        self.assertTrue(count_str.isdigit())

    def test_many_headers(self):
        """Many headers should produce a proper count."""
        headers = [(f"X-Custom-{i}", f"val{i}") for i in range(20)]
        packet = _make_http(headers=headers)
        fp = generate_ja4h(packet)
        part_a = fp.split("_")[0]
        count = int(part_a[6:8])
        # 20 custom + Host = 21
        self.assertEqual(count, 21)


class TestJA4HLanguageExtraction(unittest.TestCase):
    """Test Accept-Language extraction (first 4 alphanumeric chars)."""

    def test_enus(self):
        packet = _make_http(lang="en-US,en;q=0.9")
        fp = generate_ja4h(packet)
        part_a = fp.split("_")[0]
        self.assertTrue(part_a.endswith("enus"))

    def test_no_language(self):
        packet = _make_http()
        fp = generate_ja4h(packet)
        part_a = fp.split("_")[0]
        self.assertTrue(part_a.endswith("0000"))

    def test_german(self):
        packet = _make_http(lang="de-DE,de;q=0.9")
        fp = generate_ja4h(packet)
        part_a = fp.split("_")[0]
        self.assertTrue(part_a.endswith("dede"))

    def test_french(self):
        packet = _make_http(lang="fr-FR")
        fp = generate_ja4h(packet)
        part_a = fp.split("_")[0]
        self.assertTrue(part_a.endswith("frfr"))

    def test_short_language(self):
        packet = _make_http(lang="en")
        fp = generate_ja4h(packet)
        part_a = fp.split("_")[0]
        # "en" -> "en" (only 2 alphanum chars)
        self.assertIn("en", part_a[-4:])


class TestJA4HHeaderHash(unittest.TestCase):
    """Test part_b: header names hash (original order)."""

    def test_header_hash_computed(self):
        """Header hash should be SHA256[:12] of comma-separated header names."""
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=data)
        fp = generate_ja4h(packet)
        parts = fp.split("_")
        # Header names in original order: Host,User-Agent
        expected = hashlib.sha256("Host,User-Agent".encode()).hexdigest()[:12]
        self.assertEqual(parts[1], expected)

    def test_no_headers_gives_zeros(self):
        """A request with no headers at all (just request line) - Host is always there."""
        # In practice Host is always present in _make_http, but test the hash itself
        data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=data)
        fp = generate_ja4h(packet)
        parts = fp.split("_")
        # Should have a proper hash for "Host"
        self.assertEqual(len(parts[1]), 12)


class TestJA4HCookieHash(unittest.TestCase):
    """Test part_c (sorted cookie field names) and part_d (sorted cookie name=value)."""

    def test_cookie_fields_sorted(self):
        """Cookie field names should be sorted alphabetically."""
        packet = _make_http(cookie="z_cookie=1; a_cookie=2; m_cookie=3")
        fp = generate_ja4h(packet)
        parts = fp.split("_")
        # Part C: sorted cookie field names
        sorted_fields = "a_cookie,m_cookie,z_cookie"
        expected = hashlib.sha256(sorted_fields.encode()).hexdigest()[:12]
        self.assertEqual(parts[2], expected)

    def test_cookie_values_sorted_by_name(self):
        """Cookie name=value pairs should be sorted by field name."""
        packet = _make_http(cookie="z_cookie=zval; a_cookie=aval")
        fp = generate_ja4h(packet)
        parts = fp.split("_")
        # Part D: sorted by name: a_cookie=aval,z_cookie=zval
        sorted_pairs = "a_cookie=aval,z_cookie=zval"
        expected = hashlib.sha256(sorted_pairs.encode()).hexdigest()[:12]
        self.assertEqual(parts[3], expected)

    def test_no_cookies_gives_zeros(self):
        packet = _make_http()
        fp = generate_ja4h(packet)
        parts = fp.split("_")
        self.assertEqual(parts[2], "000000000000")
        self.assertEqual(parts[3], "000000000000")

    def test_single_cookie(self):
        packet = _make_http(cookie="session=abc123")
        fp = generate_ja4h(packet)
        parts = fp.split("_")
        # Part C: just "session"
        expected_c = hashlib.sha256("session".encode()).hexdigest()[:12]
        self.assertEqual(parts[2], expected_c)
        # Part D: "session=abc123"
        expected_d = hashlib.sha256("session=abc123".encode()).hexdigest()[:12]
        self.assertEqual(parts[3], expected_d)


class TestJA4HFormat(unittest.TestCase):
    """Test overall JA4H fingerprint format."""

    def test_four_parts(self):
        packet = _make_http()
        fp = generate_ja4h(packet)
        self.assertEqual(len(fp.split("_")), 4)

    def test_all_hash_parts_12_chars(self):
        packet = _make_http(cookie="a=1")
        fp = generate_ja4h(packet)
        parts = fp.split("_")
        for i in range(1, 4):
            self.assertEqual(len(parts[i]), 12, f"Part {i+1} should be 12 chars")

    def test_non_http_returns_none(self):
        packet = IP() / TCP(sport=12345, dport=80) / Raw(load=b"\x16\x03\x03")
        fp = generate_ja4h(packet)
        self.assertIsNone(fp)


class TestJA4HFingerprinterClass(unittest.TestCase):
    """Test JA4HFingerprinter class interface."""

    def test_process_and_collect(self):
        fp = JA4HFingerprinter()
        packet = _make_http()
        result = fp.process_packet(packet)
        self.assertIsNotNone(result)
        self.assertEqual(len(fp.get_fingerprints()), 1)

    def test_reset(self):
        fp = JA4HFingerprinter()
        fp.process_packet(_make_http())
        fp.reset()
        self.assertEqual(len(fp.get_fingerprints()), 0)


if __name__ == "__main__":
    unittest.main()
