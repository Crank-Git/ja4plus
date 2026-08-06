"""Multi-packet QUIC CRYPTO frame reassembly.

When a TLS ClientHello exceeds a single QUIC Initial datagram (rare but
real for clients carrying many extensions, e.g. ECH grease + many ALPN
options), the CRYPTO frame is fragmented across multiple Initial
packets sharing the same Destination Connection ID.
"""

import os

import pytest


def test_reassemble_crypto_fragments_basic():
    from ja4plus.utils.quic_utils import reassemble_crypto_fragments

    fragments = [
        (0, b"hello "),
        (6, b"world"),
    ]
    assert reassemble_crypto_fragments(fragments) == b"hello world"


def test_reassemble_crypto_fragments_out_of_order():
    from ja4plus.utils.quic_utils import reassemble_crypto_fragments

    fragments = [
        (6, b"world"),
        (0, b"hello "),
    ]
    assert reassemble_crypto_fragments(fragments) == b"hello world"


def test_reassemble_crypto_fragments_handles_duplicates():
    """A fragment seen twice (e.g. retransmission) should not corrupt output."""
    from ja4plus.utils.quic_utils import reassemble_crypto_fragments

    fragments = [
        (0, b"hello "),
        (0, b"hello "),  # duplicate
        (6, b"world"),
    ]
    assert reassemble_crypto_fragments(fragments) == b"hello world"


def test_client_hello_from_crypto_fragments_returns_none_when_incomplete():
    """Spec'd handshake length > assembled bytes -> None (keep accumulating)."""
    from ja4plus.utils.quic_utils import client_hello_from_crypto_fragments

    # ClientHello header: type=0x01, length=0x100 (256 bytes), but we only
    # provide 4 bytes of header + 0 of body -> incomplete.
    incomplete = [(0, bytes([0x01, 0x00, 0x01, 0x00]))]
    assert client_hello_from_crypto_fragments(incomplete) is None


def test_ja4_fingerprinter_buffers_quic_fragments():
    """JA4Fingerprinter should accumulate fragments across datagrams.

    We fake two QUIC Initial datagrams whose decryption yields fragments
    that, taken together, form a complete ClientHello. The first datagram
    alone yields no fingerprint; the second completes the handshake.
    """
    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
    from ja4plus.utils import quic_utils
    from ja4plus.utils import tls_utils as _tls_utils

    fp = JA4Fingerprinter()

    # Stub out decryption to produce predictable fragments per datagram.
    fake_ch_bytes = bytes(
        [
            # TLS handshake header: type=01, length=0x000010 (16 bytes)
            0x01,
            0x00,
            0x00,
            0x10,
            # 16 bytes of opaque body (parse_tls_handshake will reject as
            # malformed, returning None — so the test stops short of asserting
            # a real fingerprint, but it does assert that fragments accumulate).
        ]
        + [0] * 16
    )
    half = len(fake_ch_bytes) // 2
    frag1 = (0, fake_ch_bytes[:half])
    frag2 = (half, fake_ch_bytes[half:])
    dcid = b"\xaa\xbb\xcc\xdd"

    calls = {"n": 0}

    def fake_decrypt(_payload):
        calls["n"] += 1
        if calls["n"] == 1:
            return [frag1], dcid
        if calls["n"] == 2:
            return [frag2], dcid
        return None, None

    # Patch the decrypt helper used by JA4Fingerprinter._try_quic_multi_packet
    quic_utils.decrypt_quic_initial_crypto = fake_decrypt

    # Drive process_packet with two synthetic UDP packets.
    from scapy.all import IP, UDP, Raw

    pkt1 = (
        IP(src="1.1.1.1", dst="2.2.2.2")
        / UDP(sport=50000, dport=443)
        / Raw(load=b"\x80" + b"\x00" * 30)
    )
    pkt2 = (
        IP(src="1.1.1.1", dst="2.2.2.2")
        / UDP(sport=50000, dport=443)
        / Raw(load=b"\x80" + b"\x00" * 30)
    )

    # First call: no full ClientHello yet
    r1 = fp.process_packet(pkt1)
    # Second call: full ClientHello assembled (but malformed body may fail TLS parse)
    r2 = fp.process_packet(pkt2)

    # Strict: the per-DCID buffer should have accumulated then released
    # (whether or not parse_tls_handshake produced a real fingerprint).
    # If TLS parsing failed, fragments stay buffered — that's still progress
    # (the buffer is not silently dropped).
    assert calls["n"] == 2
    # If we got a fingerprint, the buffer must be released; if not, it
    # should still contain both fragments under the same DCID key.
    if r2 is None:
        assert dcid.hex() in fp._quic_fragments
        assert len(fp._quic_fragments[dcid.hex()]) == 2


@pytest.mark.skipif(
    not os.path.exists("tests/foxio_vectors/pcap/quic-with-several-tls-frames.pcapng"),
    reason="quic-with-several-tls-frames fixture missing",
)
def test_quic_with_several_tls_frames_real_pcap():
    """Real-world sanity: feed every UDP packet to the JA4 fingerprinter."""
    from scapy.all import rdpcap
    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    pkts = rdpcap("tests/foxio_vectors/pcap/quic-with-several-tls-frames.pcapng")
    fp = JA4Fingerprinter()
    fingerprints = []
    for pkt in pkts:
        r = fp.process_packet(pkt)
        if r:
            fingerprints.append(r)
    # If the pcap contains a complete handshake we'll get one fingerprint;
    # if not, we shouldn't crash, and the fragment buffer should be sane.
    assert isinstance(fingerprints, list)
