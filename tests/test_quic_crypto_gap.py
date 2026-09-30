"""A gap in the QUIC CRYPTO stream stops the reassembler.

#762 reports the defect. The reassembler allocated a buffer up to the highest fragment
end and left each unreceived range as zero bytes. A ClientHello whose last fragment
arrived before a middle fragment then passed the length check, and the TLS reader parsed
the zero bytes as extensions. The reader produced a JA4 value that no reference holds.

The cases below replay the fragment layout of #762 against the ClientHello of the FoxIO
capture `quic-with-several-tls-frames.pcapng`. That ClientHello holds 295 bytes, so the
layout keeps the shape of the report and scales the offsets.
"""

from pathlib import Path

from scapy.all import IP, UDP, Raw, rdpcap

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.utils import quic_utils
from ja4plus.utils.quic_utils import (
    client_hello_from_crypto_fragments,
    decrypt_quic_initial_crypto,
    reassemble_crypto_fragments,
    server_hello_is_complete,
)

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"
CAPTURE_PATH = VECTORS_DIR / "quic-with-several-tls-frames.pcapng"
EXPECTED_PATH = (
    VECTORS_DIR / "rust_expected" / "ja4__insta@quic-with-several-tls-frames.pcapng.snap"
)


def _client_hello_bytes():
    """Return the whole ClientHello that the one Initial packet of the capture carries."""
    for packet in rdpcap(str(CAPTURE_PATH)):
        if UDP not in packet:
            continue
        fragments, _ = decrypt_quic_initial_crypto(bytes(packet[UDP].payload))
        if fragments:
            return reassemble_crypto_fragments(fragments)
    raise AssertionError(f"{CAPTURE_PATH} holds no QUIC client Initial packet")


def _reference_ja4():
    """Return the one JA4 value the FoxIO snapshot holds for the capture."""
    values = [
        line.strip()[len("ja4: ") :]
        for line in EXPECTED_PATH.read_text().splitlines()
        if line.strip().startswith("ja4: ")
    ]
    assert len(values) == 1, f"{EXPECTED_PATH} holds {len(values)} JA4 values"
    return values[0]


def _split(data, bounds):
    """Return the (offset, bytes) pair of each half-open range in `bounds`."""
    return [(start, data[start:end]) for start, end in bounds]


def _issue_layout(client_hello):
    """Return the fragments of the two datagrams, in the shape #762 reports.

    The first datagram carries the head and the tail, and the second one carries the
    middle. The first datagram alone therefore reaches the last byte and leaves a gap.
    """
    end = len(client_hello)
    first = _split(client_hello, [(0, 36), (36, 70), (200, end)])
    second = _split(client_hello, [(70, 115), (115, 200)])
    return first, second


def test_the_reassembler_stops_at_the_first_gap():
    assert reassemble_crypto_fragments([(0, b"ab"), (5, b"xy")]) == b"ab"


def test_the_reassembler_returns_nothing_when_no_fragment_starts_at_offset_zero():
    assert reassemble_crypto_fragments([(3, b"xyz")]) == b""


def test_the_reassembler_joins_overlapping_fragments():
    assert reassemble_crypto_fragments([(0, b"hello"), (3, b"lo world")]) == b"hello world"


def test_the_reassembler_keeps_a_fragment_that_a_longer_one_covers():
    fragments = [(0, b"hello world"), (6, b"wor")]
    assert reassemble_crypto_fragments(fragments) == b"hello world"


def test_a_client_hello_with_a_gap_produces_no_parse():
    client_hello = _client_hello_bytes()
    first, _ = _issue_layout(client_hello)
    assert client_hello_from_crypto_fragments(first) is None


def test_the_client_hello_parses_once_the_gap_fills():
    client_hello = _client_hello_bytes()
    first, second = _issue_layout(client_hello)
    whole = client_hello_from_crypto_fragments([(0, client_hello)])
    assert whole is not None
    assert client_hello_from_crypto_fragments(first + second) == whole


def test_a_server_hello_with_a_gap_is_not_complete():
    server_hello = bytes([0x02, 0x00, 0x00, 0x06]) + b"abcdef"
    assert not server_hello_is_complete([(0, server_hello[:4]), (8, server_hello[8:])])
    assert server_hello_is_complete([(0, server_hello[:4]), (4, server_hello[4:])])


def _quic_packet():
    """Return one UDP datagram whose payload starts a QUIC long header."""
    return (
        IP(src="1.1.1.1", dst="2.2.2.2")
        / UDP(sport=50000, dport=443)
        / Raw(load=b"\x80" + b"\x00" * 30)
    )


def test_the_fingerprinter_waits_for_the_gap_and_then_produces_the_reference_ja4(
    monkeypatch,
):
    """The first datagram produces nothing, and the second one produces the FoxIO value.

    The `monkeypatch` fixture restores the decryption function on teardown.
    """
    first, second = _issue_layout(_client_hello_bytes())
    dcid = b"\xaa\xbb\xcc\xdd"
    datagrams = iter([(first, dcid), (second, dcid)])
    monkeypatch.setattr(quic_utils, "decrypt_quic_initial_crypto", lambda _: next(datagrams))

    fingerprinter = JA4Fingerprinter()
    assert fingerprinter.process_packet(_quic_packet()) is None
    assert fingerprinter.process_packet(_quic_packet()) == _reference_ja4()
