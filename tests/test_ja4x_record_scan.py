"""Tests for the JA4X scan of the TLS record layer.

The FoxIO implementation computes one JA4X value for each certificate, and it holds no
cache. See `python/ja4x.py` of the FoxIO repository, which states "JA4X does not use any
caching from common.py". Two streams that carry one certificate therefore produce two
JA4X values.

A TLS record carries one or more handshake messages, and a handshake message can span
two records. The scan reads the record layer first, then the handshake messages inside
it.
"""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4x import JA4XFingerprinter

SERVER_HELLO_TYPE = 0x02
CERTIFICATE_TYPE = 0x0B


def _certificate_bytes(common_name):
    """Return one self-signed certificate in DER form.

    Args:
        common_name: The common name of the subject and of the issuer.

    Returns:
        The DER bytes of the certificate.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256(), backend=default_backend())
    )
    return certificate.public_bytes(encoding=Encoding.DER)


@pytest.fixture(scope="module")
def certificate():
    """Return the DER bytes of one certificate, built once for the module."""
    return _certificate_bytes("first.example.com")


def _handshake_message(message_type, body):
    """Return one TLS handshake message with its four-byte header."""
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def _certificate_message(*certificates):
    """Return one TLS Certificate message that carries the given certificates."""
    entries = b"".join(len(item).to_bytes(3, "big") + item for item in certificates)
    return _handshake_message(CERTIFICATE_TYPE, len(entries).to_bytes(3, "big") + entries)


def _record(payload):
    """Return one TLS handshake record that carries the payload."""
    return b"\x16\x03\x03" + len(payload).to_bytes(2, "big") + payload


def _packet(payload, src="10.0.0.2", sport=443, dst="10.0.0.1", dport=54321, seq=1000):
    """Return one TCP packet that carries the payload."""
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq) / Raw(load=payload)


def _values(fingerprinter):
    """Return the JA4X values the fingerprinter holds, in order."""
    return [entry["fingerprint"] for entry in fingerprinter.get_fingerprints()]


def test_the_scan_reads_a_certificate_message_that_follows_a_server_hello(certificate):
    """A record that starts with a ServerHello still yields the Certificate message."""
    server_hello = _handshake_message(SERVER_HELLO_TYPE, b"\x00" * 64)
    payload = _record(server_hello + _certificate_message(certificate))

    fingerprinter = JA4XFingerprinter()
    fingerprinter.process_packet(_packet(payload))

    assert len(_values(fingerprinter)) == 1


def test_the_scan_reads_a_certificate_message_that_spans_two_records(certificate):
    """A Certificate message split across two records yields one value."""
    message = _certificate_message(certificate)
    half = len(message) // 2
    payload = _record(message[:half]) + _record(message[half:])

    fingerprinter = JA4XFingerprinter()
    fingerprinter.process_packet(_packet(payload))

    assert len(_values(fingerprinter)) == 1


def test_the_scan_reads_every_certificate_of_one_message(certificate):
    """A Certificate message that carries two certificates yields two values."""
    second = _certificate_bytes("second.example.com")
    payload = _record(_certificate_message(certificate, second))

    fingerprinter = JA4XFingerprinter()
    fingerprinter.process_packet(_packet(payload))

    assert len(_values(fingerprinter)) == 2


def test_the_fingerprinter_emits_one_value_for_each_stream_that_carries_one_certificate(
    certificate,
):
    """Two streams that carry the same certificate produce two values.

    FoxIO holds no cache across streams, so a value on the second stream is not a
    duplicate of the value on the first.
    """
    payload = _record(_certificate_message(certificate))

    fingerprinter = JA4XFingerprinter()
    fingerprinter.process_packet(_packet(payload, dport=54321))
    fingerprinter.process_packet(_packet(payload, dport=54322))

    values = _values(fingerprinter)
    assert len(values) == 2
    assert values[0] == values[1]


def test_the_fingerprinter_emits_one_value_for_one_certificate_on_one_stream(certificate):
    """The same certificate on one stream produces one value, not one for each packet."""
    payload = _record(_certificate_message(certificate))

    fingerprinter = JA4XFingerprinter()
    fingerprinter.process_packet(_packet(payload, seq=1000))
    fingerprinter.process_packet(_packet(payload, seq=1000 + len(payload)))

    assert len(_values(fingerprinter)) == 1


def test_the_scan_reads_no_certificate_from_a_record_the_stream_holds_in_part(certificate):
    """A record the capture truncates yields no value."""
    payload = _record(_certificate_message(certificate))

    fingerprinter = JA4XFingerprinter()
    fingerprinter.process_packet(_packet(payload[: len(payload) // 2]))

    assert _values(fingerprinter) == []


def test_the_scan_reads_no_certificate_from_a_length_field_the_record_lies_about(certificate):
    """A certificate length that exceeds the message yields no value."""
    message = _certificate_message(certificate)
    hostile = message[:7] + b"\xff\xff\xff" + message[10:]

    fingerprinter = JA4XFingerprinter()
    fingerprinter.process_packet(_packet(_record(hostile)))

    assert _values(fingerprinter) == []


def test_the_scan_reads_a_certificate_that_follows_a_proxy_preamble(certificate):
    """A stream that starts with proxy bytes still yields the Certificate message.

    A SOCKS proxy writes its own handshake before the TLS record layer starts, so the
    scan cannot assume that the stream starts on a record boundary.
    """
    preamble = b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50"
    payload = preamble + _record(_certificate_message(certificate))

    fingerprinter = JA4XFingerprinter()
    fingerprinter.process_packet(_packet(payload))

    assert len(_values(fingerprinter)) == 1


def test_the_scan_reads_a_record_that_two_packets_carry(certificate):
    """A record the first packet truncates yields its value when the second completes it.

    The scan resumes where the last packet left it, so it must resume at the start of
    the run, not after the record the stream held in part.
    """
    payload = _record(_certificate_message(certificate))
    half = len(payload) // 2

    fingerprinter = JA4XFingerprinter()
    fingerprinter.process_packet(_packet(payload[:half], seq=1000))
    assert _values(fingerprinter) == []
    fingerprinter.process_packet(_packet(payload[half:], seq=1000 + half))

    assert len(_values(fingerprinter)) == 1


def test_the_scan_reads_a_certificate_that_follows_application_data(certificate):
    """A Certificate message after encrypted records yields its value.

    The scan resumes after the records it already read, and encrypted payload holds no
    record boundary the scan can trust.
    """
    application_data = b"\x17\x03\x03" + (2000).to_bytes(2, "big") + b"\xa5" * 2000

    fingerprinter = JA4XFingerprinter()
    fingerprinter.process_packet(_packet(application_data, seq=1000))
    fingerprinter.process_packet(
        _packet(_record(_certificate_message(certificate)), seq=1000 + len(application_data))
    )

    assert len(_values(fingerprinter)) == 1


def test_the_scan_reads_the_stream_once(certificate):
    """The scan cost grows with the stream length, not with its square."""
    application_data = b"\x17\x03\x03" + (1400).to_bytes(2, "big") + b"\xa5" * 1400

    fingerprinter = JA4XFingerprinter()
    seq = 1000
    for _ in range(50):
        fingerprinter.process_packet(_packet(application_data, seq=seq))
        seq += len(application_data)

    # The scan keeps the offset it reached, so the next packet reads no byte twice.
    length = 50 * len(application_data)
    assert fingerprinter.scan_offsets["10.0.0.2:443-10.0.0.1:54321"] > length - 5


def test_the_cleanup_drops_the_certificate_state_of_the_connection(certificate):
    """`cleanup_connection` removes what the stream holds, so the state stays bounded."""
    payload = _record(_certificate_message(certificate))

    fingerprinter = JA4XFingerprinter()
    fingerprinter.process_packet(_packet(payload))
    fingerprinter.cleanup_connection("10.0.0.2", 443, "10.0.0.1", 54321, "tcp")

    assert len(fingerprinter.processed_certs) == 0
