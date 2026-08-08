"""Measure `extract_certificate_info` on the path that finds a certificate.

`ja4plus/utils/x509_utils.py` imported `x509` and `default_backend` inside one branch of
`extract_certificate_info`, which made both names locals of the whole function. The parse
below that branch therefore raised `UnboundLocalError` for every packet whose payload
carried a certificate the reader found, and the wide handler of the function returned
nothing instead. #294 found the defect and #309 repairs it.

No case reached that path before, because no caller inside `ja4plus/` calls the function.
The path that raised is the path a reader takes for a real TLS Certificate message, so
every case here builds one.
"""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from scapy.all import Raw

from ja4plus.utils import x509_utils

# The OID of `commonName`, in the hex form `oid_to_hex` writes. The reader reports one
# entry for each relative distinguished name, so the stub certificate names one.
COMMON_NAME_OID_HEX = "550403"


@pytest.fixture(scope="module")
def certificate_der() -> bytes:
    """Return the DER form of one self-signed certificate."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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


def test_the_packet_reader_returns_the_details_of_a_certificate_it_found(certificate_der):
    """The packet reader returns the detail dictionary on the path that raised.

    The parse below the branch resolved no `x509` before #309, so the function returned
    nothing for a packet that carried a certificate.
    """
    packet = Raw(certificate_record(certificate_der))

    details = x509_utils.extract_certificate_info(packet)

    assert details is not None
    assert details["subject_rdns"] == [COMMON_NAME_OID_HEX]
    assert details["issuer_rdns"] == [COMMON_NAME_OID_HEX]
    assert details["serial"] == "4309"


def test_the_packet_reader_returns_nothing_for_a_packet_that_carries_no_payload():
    """A packet without a payload holds no certificate, so the reader returns nothing."""
    assert x509_utils.extract_certificate_info(Raw()) is None
