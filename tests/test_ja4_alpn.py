"""JA4 ALPN value handling per FoxIO PR #277.

Spec: if first or last byte of the first ALPN value is not ASCII alnum
(0x30-0x39, 0x41-0x5A, 0x61-0x7A), use the first/last character of the
hex representation of the FULL first ALPN string.
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
        # From the FoxIO PR #277 examples
        (b"\xab", "ab"),  # single non-alnum byte -> hex first/last
        (b"\x20", "20"),
        (b"\xab\xcd", "ad"),
        (b"\x20\x61", "21"),
        (b"\x30\xab", "3b"),  # first alnum, last not -> hex
        (b"\x61\x20", "60"),
        (b"\x30\x31\xab\xcd", "3d"),
        (b"\x30\xab\xcd\x31", "01"),  # both ends alnum -> bytes directly
        # Additional sanity checks
        (b"", "00"),  # empty -> '00'
        (b"h", "hh"),  # single alnum byte -> duplicate
        (b"h2", "h2"),  # standard ALPN, both ends alnum
        (b"http/1.1", "h1"),
        (b"h3", "h3"),
    ],
)
def test_compute_alpn_value(alpn_bytes, expected):
    assert compute_alpn_value(alpn_bytes) == expected


def test_compute_alpn_value_none_returns_00():
    assert compute_alpn_value(None) == "00"


def test_compute_alpn_via_generate_ja4():
    """End-to-end: a tls_info dict with non-ascii alpn_raw produces hex ALPN."""
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
    # ALPN bytes \x30\xab -> first alnum '0', last not -> hex '30ab' -> "3b"
    assert part_a.endswith("3b"), f"got {part_a!r}"


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


@pytest.mark.xfail(
    strict=True,
    reason=(
        "issue #127: the FoxIO prose gives the hex characters `bd`, and two FoxIO "
        "implementations give `99`."
    ),
)
def test_the_foxio_capture_produces_the_reference_ja4_value():
    """`tls-non-ascii-alpn.pcapng` produces the JA4 value the FoxIO reference holds."""
    assert _produced_ja4() == [_reference_ja4()]
