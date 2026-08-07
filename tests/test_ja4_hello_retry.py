"""JA4 reads the second ClientHello of a HelloRetryRequest flow.

A TLS 1.3 client that receives a HelloRetryRequest sends a second ClientHello. The
compatibility-mode ChangeCipherSpec record precedes that hello in the same TCP segment,
so the first byte of the segment is `0x14` and not `0x16`. The reader walks the records
of the segment to reach the hello.

The vectors are `tls-handshake.pcapng` and `tls-sni.pcapng`, stream 38, port 50159.
"""

import json
from pathlib import Path

import pytest

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.utils.tls_utils import parse_tls_handshake

VECTOR_DIR = Path(__file__).parent / "foxio_vectors"

# The TLS 1.3 compatibility-mode ChangeCipherSpec record. It carries one payload byte.
CHANGE_CIPHER_SPEC = b"\x14\x03\x03\x00\x01\x01"


def _client_hello_record(ciphers=(0x1301,)):
    """Return one TLS handshake record that holds a minimal ClientHello."""
    body = bytearray(b"\x03\x03")
    body += b"\x00" * 32  # Random
    body += b"\x00"  # Session ID length
    suites = b"".join(c.to_bytes(2, "big") for c in ciphers)
    body += len(suites).to_bytes(2, "big") + suites
    body += b"\x01\x00"  # Compression
    handshake = b"\x01" + len(body).to_bytes(3, "big") + bytes(body)
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _reference_stream(capture, port):
    """Return the reference element of one capture that names the port."""
    elements = json.loads((VECTOR_DIR / (capture + ".json")).read_text())
    for element in elements:
        if port in (element.get("srcport"), element.get("dstport")):
            return element
    raise AssertionError("The reference holds no stream on port " + port)


def _produced_on_port(capture, port):
    """Return every JA4 entry the fingerprinter produces on one TCP port."""
    from scapy.all import TCP, rdpcap

    fingerprinter = JA4Fingerprinter()
    for packet in rdpcap(str(VECTOR_DIR / capture)):
        if TCP not in packet:
            continue
        if str(packet[TCP].sport) != port and str(packet[TCP].dport) != port:
            continue
        fingerprinter.process_packet(packet)
    return fingerprinter.fingerprints


def test_the_reader_parses_a_hello_behind_a_change_cipher_spec_record():
    """A segment that starts with ChangeCipherSpec still yields its ClientHello."""
    info = parse_tls_handshake(CHANGE_CIPHER_SPEC + _client_hello_record())
    assert info is not None
    assert info["type"] == "client_hello"
    assert info["ciphers"] == [0x1301]


def test_the_reader_returns_nothing_when_a_record_length_overruns_the_buffer():
    """A record length the packet inflates returns nothing, and raises nothing."""
    # The declared length is 0xffff, and the buffer holds three payload bytes.
    assert parse_tls_handshake(b"\x14\x03\x03\xff\xff\x01\x02\x03") is None


def test_the_reader_returns_nothing_when_no_record_holds_a_hello():
    """A segment of application data records yields nothing."""
    assert parse_tls_handshake(b"\x17\x03\x03\x00\x02\x01\x02" * 3) is None


@pytest.mark.parametrize("capture", ["tls-handshake.pcapng", "tls-sni.pcapng"])
def test_the_capture_produces_both_reference_ja4_values(capture):
    """Stream 38 produces the two JA4 values, and all four forms, the reference holds."""
    reference = _reference_stream(capture, "50159")
    produced = _produced_on_port(capture, "50159")

    assert len(produced) == 2
    for occurrence, entry in enumerate(produced, start=1):
        suffix = ".{}".format(occurrence)
        assert entry["fingerprint"] == reference["JA4" + suffix]
        assert entry["raw"] == reference["JA4_r" + suffix]
        assert entry["fingerprint_original_order"] == reference["JA4_o" + suffix]
        assert entry["raw_original_order"] == reference["JA4_ro" + suffix]
