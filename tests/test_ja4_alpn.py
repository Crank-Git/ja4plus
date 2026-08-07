"""The JA4 ALPN value.

The FoxIO prose gives the first and the last character of the hex form. The FoxIO
Python implementation and the FoxIO Rust implementation give `99`. #127 settled that
this project follows the two implementations.
"""

import json
from pathlib import Path

import pytest

from ja4plus.fingerprinters.ja4 import compute_alpn_value

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"
CAPTURE_PATH = VECTORS_DIR / "tls-non-ascii-alpn.pcapng"
EXPECTED_PATH = VECTORS_DIR / "tls-non-ascii-alpn.pcapng.json"


@pytest.mark.parametrize(
    "alpn_bytes,expected",
    [
        # The first byte, the last byte, or both fall outside the alphanumeric ranges.
        (b"\xab", "99"),
        (b"\x20", "99"),
        (b"\xab\xcd", "99"),
        (b"\x20\x61", "99"),
        (b"\x30\xab", "99"),
        (b"\x61\x20", "99"),
        (b"\x30\x31\xab\xcd", "99"),
        # Both ends are alphanumeric, so the two bytes pass through.
        (b"\x30\xab\xcd\x31", "01"),
        (b"", "00"),
        (b"h", "hh"),
        (b"h2", "h2"),
        (b"http/1.1", "h1"),
        (b"h3", "h3"),
    ],
)
def test_compute_alpn_value(alpn_bytes, expected):
    assert compute_alpn_value(alpn_bytes) == expected


def test_compute_alpn_value_none_returns_00():
    assert compute_alpn_value(None) == "00"


def test_compute_alpn_via_generate_ja4():
    """A tls_info dictionary with a non-alphanumeric ALPN byte produces `99`."""
    from ja4plus.fingerprinters.ja4 import generate_ja4

    info = {
        "handshake_type": "client_hello",
        "type": "client_hello",
        "version": 0x0303,
        "is_quic": False,
        "is_dtls": False,
        "ciphers": [0x1301],
        "extensions": [],
        "alpn_protocols": [""],  # ascii decode dropped non-ascii bytes
        "alpn_raw": [b"\x30\xab"],  # but raw bytes are preserved
        "signature_algorithms": [],
        "supported_versions": [],
        "sni": None,
    }
    fp = generate_ja4(info)
    assert fp is not None
    # part_a: t12i0100<alpn>
    part_a = fp.split("_")[0]
    # The last byte 0xab falls outside the alphanumeric ranges, so the value is `99`.
    assert part_a.endswith("99"), f"got {part_a!r}"


def _reference_ja4():
    """Return the JA4 value the FoxIO expected-output file holds for the capture.

    Returns:
        The `JA4.1` value of the first stream.

    Raises:
        FileNotFoundError: The expected-output file is absent.
        AssertionError: The expected-output file names no stream.
    """
    with open(EXPECTED_PATH) as handle:
        entries = json.load(handle)
    # An empty file holds no reference value. This check names that cause, because the
    # index below raises IndexError instead.
    assert entries, "{} names no stream".format(EXPECTED_PATH)
    return entries[0]["JA4.1"]


def _produced_ja4():
    """Return every JA4 value the fingerprinter produces from the FoxIO capture."""
    from scapy.all import rdpcap

    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    fingerprinter = JA4Fingerprinter()
    produced = []
    for packet in rdpcap(str(CAPTURE_PATH)):
        fingerprint = fingerprinter.process_packet(packet)
        if fingerprint:
            produced.append(fingerprint)
    return produced


def test_the_foxio_capture_carries_a_first_alpn_value_that_is_not_ascii():
    """The first ALPN value of `tls-non-ascii-alpn.pcapng` is the two bytes `0xba 0xad`."""
    from scapy.all import Raw, rdpcap

    from ja4plus.utils.tls_utils import parse_tls_handshake

    client_hellos = []
    for packet in rdpcap(str(CAPTURE_PATH)):
        if not packet.haslayer(Raw):
            continue
        info = parse_tls_handshake(bytes(packet[Raw].load))
        if info and info.get("type") == "client_hello":
            client_hellos.append(info)

    assert len(client_hellos) == 1
    # The parser keeps the ALPN bytes, because the ASCII decode drops the first value.
    assert client_hellos[0]["alpn_raw"] == [b"\xba\xad", b"http/1.1"]
    assert client_hellos[0]["alpn_protocols"] == ["", "http/1.1"]


def test_the_foxio_capture_produces_the_reference_ja4_value():
    """`tls-non-ascii-alpn.pcapng` produces the JA4 value the FoxIO reference holds."""
    assert _produced_ja4() == [_reference_ja4()]
