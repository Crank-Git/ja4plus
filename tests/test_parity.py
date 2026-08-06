"""Parity tests: confirm Python ja4plus exposes the same surface area
that ja4plus-go exposes: ComputeJA4XFromPEM/DER, FingerprintResult.Raw /
RawOriginalOrder fields, CLI VALID_TYPES coverage."""

import os

import pytest


def test_cli_accepts_ja4d_in_types_arg():
    """ja4d must be in VALID_TYPES per the user spec."""
    from ja4plus.cli import VALID_TYPES, ALL_FINGERPRINTERS

    assert "ja4d" in VALID_TYPES
    assert "ja4d6" in VALID_TYPES
    assert "ja4d" in ALL_FINGERPRINTERS
    assert "ja4d6" in ALL_FINGERPRINTERS


def test_compute_ja4x_from_der_module_helper():
    """compute_ja4x_from_der() should match JA4XFingerprinter().fingerprint_certificate()."""
    from ja4plus import compute_ja4x_from_der
    from ja4plus.fingerprinters.ja4x import JA4XFingerprinter

    # Use any real cert from the test suite
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes
    import datetime

    # Generate a self-signed cert in-memory
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .sign(key, hashes.SHA256(), default_backend())
    )
    der = cert.public_bytes(Encoding.DER)

    via_helper = compute_ja4x_from_der(der)
    via_class = JA4XFingerprinter().fingerprint_certificate(der)
    assert via_helper == via_class
    assert via_helper is not None
    assert via_helper.count("_") == 2  # JA4X: 3 parts


def test_compute_ja4x_from_pem_matches_der():
    """PEM and DER variants must produce the same fingerprint."""
    from ja4plus import compute_ja4x_from_der, compute_ja4x_from_pem
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(2)
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .sign(key, hashes.SHA256(), default_backend())
    )
    der = cert.public_bytes(Encoding.DER)
    pem = cert.public_bytes(Encoding.PEM)

    assert compute_ja4x_from_pem(pem) == compute_ja4x_from_der(der)


def test_compute_ja4x_from_pem_accepts_str():
    from ja4plus import compute_ja4x_from_pem

    assert compute_ja4x_from_pem("-----not a real PEM-----") is None


def test_ja4_fingerprinter_exposes_raw_and_raw_original_order():
    """Per spec: JA4 result must include 'raw' and 'raw_original_order'."""
    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    fp = JA4Fingerprinter()
    # No packet processed yet
    assert fp.last_raw is None
    assert fp.last_raw_original_order is None

    # Simulate a parse via direct dict — easier than building a full pcap
    # We'll use a real ClientHello pcap if available
    pcap = "tests/foxio_vectors/pcap/tls-handshake.pcapng"
    if not os.path.exists(pcap):
        pytest.skip("tls-handshake.pcapng fixture missing")

    from scapy.all import rdpcap

    pkts = rdpcap(pcap)
    fingerprinted = False
    for pkt in pkts:
        result = fp.process_packet(pkt)
        if result:
            fingerprinted = True
            break

    assert fingerprinted
    assert fp.last_raw is not None
    assert fp.last_raw_original_order is not None
    # Stored entry must include raw fields
    entry = fp.fingerprints[-1]
    assert "raw" in entry
    assert "raw_original_order" in entry
    assert entry["raw"] == fp.last_raw
    assert entry["raw_original_order"] == fp.last_raw_original_order


def test_ja4s_fingerprinter_exposes_raw_and_raw_original_order():
    """Per spec: JA4S result must include 'raw' and 'raw_original_order'."""
    from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

    fp = JA4SFingerprinter()
    assert fp.last_raw is None
    assert fp.last_raw_original_order is None

    pcap = "tests/foxio_vectors/pcap/tls-handshake.pcapng"
    if not os.path.exists(pcap):
        pytest.skip("tls-handshake.pcapng fixture missing")

    from scapy.all import rdpcap

    pkts = rdpcap(pcap)
    fingerprinted = False
    for pkt in pkts:
        result = fp.process_packet(pkt)
        if result:
            fingerprinted = True
            break

    if not fingerprinted:
        pytest.skip("no ServerHello found in fixture")
    assert fp.last_raw is not None
    assert fp.last_raw_original_order is not None
    entry = fp.fingerprints[-1]
    assert "raw" in entry
    assert "raw_original_order" in entry
