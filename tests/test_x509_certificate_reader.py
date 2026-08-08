"""Measure `extract_certificate_from_bytes` on both paths that find a certificate.

The reader holds two paths. The record reader finds a certificate inside a TLS
Certificate handshake record. The ASN.1 reader scans for a DER sequence, and the caller
opts into it with `try_asn1`.

`ja4plus/utils/x509_utils.py` imported `x509` and `default_backend` inside the ASN.1
path, which made both names locals of the whole function. That shape raised
`UnboundLocalError` in `extract_certificate_info`, and #309 repaired that copy. #314
removes `extract_certificate_info` and repairs the copy here.

**The shape here is latent, and no case turns it red.** The block that imports the two
names also reads them, so the read follows the import for every input. Both cases below
therefore pass before the repair and after it. They exist because the ASN.1 path carried
no case at all, and a path that no case reaches is the defect this module has already
paid for twice.
"""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from ja4plus.utils import x509_utils


def _self_signed_der() -> bytes:
    """Return the DER form of one self-signed certificate."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ja4plus.test")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(4309)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(Encoding.DER)


@pytest.fixture(scope="module")
def certificate_der() -> bytes:
    """Return the DER form of one self-signed certificate."""
    return _self_signed_der()


@pytest.fixture(scope="module")
def asn1_only_certificate() -> bytes:
    """Return the DER form of one certificate that the record reader does not find.

    The record reader scans for the byte `0x16` with the byte `0x0b` five positions
    later, and a certificate body carries that pair by chance. The fixture therefore
    builds certificates until the record reader rejects one, so the ASN.1 reader is the
    only reader that finds it.

    Returns:
        The DER form of one certificate.

    Raises:
        AssertionError: No certificate of 10 avoided the record reader.
    """
    for _ in range(10):
        der = _self_signed_der()
        if x509_utils.extract_certificate_from_bytes(der) is None:
            return der
    raise AssertionError("no certificate of 10 avoided the record reader")


def _three_byte_length(value: int) -> bytes:
    """Return the 3-byte big-endian form that a TLS length field holds."""
    return value.to_bytes(3, "big")


def certificate_record(der: bytes) -> bytes:
    """Return one TLS Certificate handshake record that carries the certificate.

    Args:
        der: The DER form of one certificate.

    Returns:
        The record bytes, from the record header to the last certificate byte.
    """
    body = _three_byte_length(len(der) + 3) + _three_byte_length(len(der)) + der
    handshake = b"\x0b" + _three_byte_length(len(body)) + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def test_the_reader_finds_the_certificate_of_a_tls_certificate_record(certificate_der):
    """The byte reader returns the certificate a Certificate message carries."""
    found = x509_utils.extract_certificate_from_bytes(certificate_record(certificate_der))
    assert found == certificate_der


def test_the_asn1_reader_finds_a_certificate_that_no_record_carries(asn1_only_certificate):
    """The ASN.1 path returns the certificate, and it reads the module `x509`."""
    found = x509_utils.extract_certificate_from_bytes(asn1_only_certificate, try_asn1=True)
    assert found == asn1_only_certificate


def test_the_asn1_reader_returns_nothing_for_a_sequence_that_is_no_certificate():
    """The loader raises for a sequence that carries the OID pattern and no certificate."""
    body = b"\x06\x03\x55\x04" + b"\x00" * 40
    candidate = b"\x30" + len(body).to_bytes(1, "big") + body

    assert x509_utils.extract_certificate_from_bytes(candidate, try_asn1=True) is None


def test_the_reader_returns_nothing_for_bytes_that_carry_no_certificate():
    """Every packet is hostile input, so the reader returns nothing and does not raise."""
    assert x509_utils.extract_certificate_from_bytes(b"\xff" * 200, try_asn1=True) is None
