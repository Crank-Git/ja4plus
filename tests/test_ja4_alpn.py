"""JA4 ALPN value handling per FoxIO PR #277.

Spec: if first or last byte of the first ALPN value is not ASCII alnum
(0x30-0x39, 0x41-0x5A, 0x61-0x7A), use the first/last character of the
hex representation of the FULL first ALPN string.
"""

import pytest

from ja4plus.fingerprinters.ja4 import compute_alpn_value


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


def test_compute_alpn_real_pcap_tls_non_ascii():
    """If the FoxIO non-ASCII ALPN fixture is present, sanity-check the parse."""
    import os
    from scapy.all import rdpcap
    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    path = "tests/foxio_vectors/pcap/tls-non-ascii-alpn.pcapng"
    if not os.path.exists(path):
        pytest.skip(f"fixture missing: {path}")

    fp_engine = JA4Fingerprinter()
    pkts = rdpcap(path)
    fingerprints = []
    for pkt in pkts:
        fp = fp_engine.process_packet(pkt)
        if fp:
            fingerprints.append(fp)

    assert fingerprints, "no JA4 fingerprints produced from non-ascii ALPN pcap"
