"""
Deep tests for JA4X (X.509 Certificate) fingerprinting.

Covers real certificate generation, OID dotted string hashing,
different issuer/subject RDN combinations, extension OID extraction,
determinism, and structural differentiation.
"""

import unittest
import hashlib
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

from ja4plus.fingerprinters.ja4x import JA4XFingerprinter, generate_ja4x
from ja4plus.utils.x509_utils import oid_to_hex


def _generate_key():
    return rsa.generate_private_key(65537, 2048, default_backend())


def _make_cert(subject_attrs, issuer_attrs=None, extensions=None):
    """Build a DER-encoded test certificate."""
    key = _generate_key()
    if issuer_attrs is None:
        issuer_attrs = subject_attrs
    if extensions is None:
        extensions = []

    subject = x509.Name(subject_attrs)
    issuer = x509.Name(issuer_attrs)
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
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical=critical)

    cert = builder.sign(key, hashes.SHA256(), default_backend())
    return cert.public_bytes(Encoding.DER)


class TestJA4XOIDHashing(unittest.TestCase):
    """Test that JA4X hashes OID dotted strings (structure), not values."""

    def test_oid_hex_encoding(self):
        """OIDs are converted to ASN.1 hex before hashing."""
        # CommonName: 2.5.4.3 -> 0x55=2*40+5, 0x04, 0x03
        result = oid_to_hex("2.5.4.3")
        self.assertEqual(result, "550403")

    def test_same_structure_same_hash(self):
        """Two certs with same OID structure but different values should have same fingerprint."""
        cert_a = _make_cert([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org A"),
            x509.NameAttribute(NameOID.COMMON_NAME, "a.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        cert_b = _make_cert([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org B"),
            x509.NameAttribute(NameOID.COMMON_NAME, "b.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        ])
        fp = JA4XFingerprinter()
        fp_a = fp.fingerprint_certificate(cert_a)
        fp_b = fp.fingerprint_certificate(cert_b)
        # Same OID structure -> same fingerprint (values don't matter)
        self.assertEqual(fp_a, fp_b)


class TestJA4XDifferentStructures(unittest.TestCase):
    """Test that different OID structures produce different fingerprints."""

    def test_different_subject_oids(self):
        """Different number/types of subject OIDs should differ."""
        cert_a = _make_cert([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "a.com"),
        ])
        cert_b = _make_cert([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "b.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        fp = JA4XFingerprinter()
        fp_a = fp.fingerprint_certificate(cert_a)
        fp_b = fp.fingerprint_certificate(cert_b)
        self.assertNotEqual(fp_a, fp_b)

    def test_different_issuer_oids(self):
        """Different issuer OID structure should change fingerprint."""
        subject = [
            x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
        ]
        issuer_a = [
            x509.NameAttribute(NameOID.COMMON_NAME, "CA A"),
        ]
        issuer_b = [
            x509.NameAttribute(NameOID.COMMON_NAME, "CA B"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org"),
        ]
        cert_a = _make_cert(subject, issuer_attrs=issuer_a)
        cert_b = _make_cert(subject, issuer_attrs=issuer_b)
        fp = JA4XFingerprinter()
        fp_a = fp.fingerprint_certificate(cert_a)
        fp_b = fp.fingerprint_certificate(cert_b)
        self.assertNotEqual(fp_a, fp_b)

    def test_different_extensions(self):
        """Different extension sets should change fingerprint."""
        subject = [
            x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
        cert_a = _make_cert(subject, extensions=[
            (x509.BasicConstraints(ca=True, path_length=None), True),
        ])
        cert_b = _make_cert(subject, extensions=[
            (x509.BasicConstraints(ca=True, path_length=None), True),
            (x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False
            ), True),
        ])
        fp = JA4XFingerprinter()
        fp_a = fp.fingerprint_certificate(cert_a)
        fp_b = fp.fingerprint_certificate(cert_b)
        self.assertNotEqual(fp_a, fp_b)


class TestJA4XDeterminism(unittest.TestCase):
    """Test that same certificate always produces same fingerprint."""

    def test_same_cert_same_result(self):
        cert = _make_cert([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ], extensions=[
            (x509.BasicConstraints(ca=True, path_length=None), True),
        ])
        fp = JA4XFingerprinter()
        r1 = fp.fingerprint_certificate(cert)
        r2 = fp.fingerprint_certificate(cert)
        r3 = fp.fingerprint_certificate(cert)
        self.assertEqual(r1, r2)
        self.assertEqual(r2, r3)


class TestJA4XFormat(unittest.TestCase):
    """Test JA4X fingerprint format: issuer_hash_subject_hash_ext_hash."""

    def test_three_parts(self):
        cert = _make_cert([
            x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
        ])
        fp = JA4XFingerprinter()
        result = fp.fingerprint_certificate(cert)
        self.assertIsNotNone(result)
        parts = result.split("_")
        self.assertEqual(len(parts), 3)

    def test_each_part_12_chars(self):
        cert = _make_cert([
            x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
        ], extensions=[
            (x509.BasicConstraints(ca=True, path_length=None), True),
        ])
        fp = JA4XFingerprinter()
        result = fp.fingerprint_certificate(cert)
        parts = result.split("_")
        for i, part in enumerate(parts):
            self.assertEqual(len(part), 12, f"Part {i} should be 12 chars, got {len(part)}")

    def test_parts_are_hex(self):
        cert = _make_cert([
            x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
        ])
        fp = JA4XFingerprinter()
        result = fp.fingerprint_certificate(cert)
        parts = result.split("_")
        for part in parts:
            self.assertTrue(all(c in "0123456789abcdef" for c in part))


class TestJA4XNoExtensions(unittest.TestCase):
    """Test certificate without extensions."""

    def test_no_extensions_still_fingerprints(self):
        cert = _make_cert([
            x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
        ], extensions=[])
        fp = JA4XFingerprinter()
        result = fp.fingerprint_certificate(cert)
        self.assertIsNotNone(result)

    def test_no_extensions_hash_is_zero_sentinel(self):
        """Empty extensions should produce '000000000000' sentinel per spec."""
        cert = _make_cert([
            x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
        ], extensions=[])
        fp = JA4XFingerprinter()
        result = fp.fingerprint_certificate(cert)
        parts = result.split("_")
        self.assertEqual(parts[2], "000000000000")


class TestJA4XSelfSignedVsCA(unittest.TestCase):
    """Test self-signed vs CA-signed certificate structural differences."""

    def test_self_signed_issuer_equals_subject(self):
        """Self-signed cert: issuer hash == subject hash."""
        subject = [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Self"),
            x509.NameAttribute(NameOID.COMMON_NAME, "self.com"),
        ]
        cert = _make_cert(subject)  # issuer defaults to subject
        fp = JA4XFingerprinter()
        result = fp.fingerprint_certificate(cert)
        parts = result.split("_")
        self.assertEqual(parts[0], parts[1])

    def test_ca_signed_issuer_differs_from_subject(self):
        """CA-signed cert: different issuer structure -> different hash."""
        subject = [
            x509.NameAttribute(NameOID.COMMON_NAME, "server.com"),
        ]
        issuer = [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Root CA"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
        cert = _make_cert(subject, issuer_attrs=issuer)
        fp = JA4XFingerprinter()
        result = fp.fingerprint_certificate(cert)
        parts = result.split("_")
        self.assertNotEqual(parts[0], parts[1])


class TestJA4XGenerateFunction(unittest.TestCase):
    """Test the generate_ja4x function directly."""

    def test_none_input(self):
        self.assertIsNone(generate_ja4x(None))

    def test_empty_dict(self):
        self.assertIsNone(generate_ja4x({}))

    def test_manual_cert_info(self):
        cert_info = {
            "issuer_rdns": [oid_to_hex("2.5.4.3"), oid_to_hex("2.5.4.6")],
            "subject_rdns": [oid_to_hex("2.5.4.3")],
            "extensions": [oid_to_hex("2.5.29.19")],
        }
        result = generate_ja4x(cert_info)
        self.assertIsNotNone(result)
        parts = result.split("_")
        self.assertEqual(len(parts), 3)

        # Verify issuer hash manually
        issuer_str = ",".join(cert_info["issuer_rdns"])
        expected_issuer = hashlib.sha256(issuer_str.encode()).hexdigest()[:12]
        self.assertEqual(parts[0], expected_issuer)


class TestJA4XFingerprinterClass(unittest.TestCase):
    """Test JA4XFingerprinter class methods."""

    def test_fingerprint_certificate(self):
        cert = _make_cert([
            x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
        ])
        fp = JA4XFingerprinter()
        result = fp.fingerprint_certificate(cert)
        self.assertIsNotNone(result)

    def test_invalid_cert_data(self):
        fp = JA4XFingerprinter()
        result = fp.fingerprint_certificate(b"not a cert")
        self.assertIsNone(result)

    def test_reset(self):
        fp = JA4XFingerprinter()
        cert = _make_cert([x509.NameAttribute(NameOID.COMMON_NAME, "test.com")])
        fp.fingerprint_certificate(cert)
        fp.reset()
        self.assertEqual(len(fp.get_fingerprints()), 0)
        self.assertEqual(fp.reassembler.stream_count(), 0)
        self.assertEqual(len(fp.processed_certs), 0)

    def test_get_cert_details(self):
        """get_cert_details should extract OID hex lists."""
        cert_data = _make_cert([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
        ], extensions=[
            (x509.BasicConstraints(ca=True, path_length=None), True),
        ])
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        fp = JA4XFingerprinter()
        details = fp.get_cert_details(cert)
        self.assertIsNotNone(details)
        self.assertIn("issuer_rdns", details)
        self.assertIn("subject_rdns", details)
        self.assertIn("extensions", details)
        self.assertEqual(len(details["issuer_rdns"]), 2)
        self.assertEqual(len(details["subject_rdns"]), 2)
        self.assertGreaterEqual(len(details["extensions"]), 1)


if __name__ == "__main__":
    unittest.main()
