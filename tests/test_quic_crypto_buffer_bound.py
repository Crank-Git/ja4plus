"""The bound on the QUIC CRYPTO fragment buffer of the JA4 fingerprinter.

RFC 9000 Section 16 lets a CRYPTO frame offset reach 4611686018427387903, and
`reassemble_crypto_fragments` allocates a buffer that reaches the highest offset. A
client Initial packet derives its keys from the connection ID the same packet carries
in cleartext, so a sender needs no handshake to reach the allocation. Issue #122
carries the measurement: one fragment at offset 2**40 names a buffer of 1024 GiB.

Every test here asserts the bound rather than the crash, so each one still means
something after the fix, and none of them allocates a large buffer.
"""

import pytest
from scapy.all import IP, UDP, Raw

from ja4plus.fingerprinters.ja4 import (
    MAX_QUIC_FRAGMENT_AGE_SECONDS,
    MAX_QUIC_FRAGMENT_CONNECTIONS,
    JA4Fingerprinter,
)
from ja4plus.utils import quic_utils
from ja4plus.utils.quic_utils import (
    MAXIMUM_CRYPTO_BUFFER_BYTES,
    reassemble_crypto_fragments,
)

# The highest offset RFC 9000 Section 16 encodes.
RFC_9000_MAXIMUM_OFFSET = 4611686018427387903

# A TLS ClientHello header that names a 16-byte body the fragments never carry, so the
# reader keeps the buffer instead of releasing it.
INCOMPLETE_CLIENT_HELLO = bytes([0x01, 0x00, 0x00, 0x10])


def test_the_reassembler_drops_a_fragment_past_the_limit():
    """A fragment whose offset reaches past the limit produces no buffer.

    The reader returns nothing. It does not raise, and it does not allocate.
    """
    assert reassemble_crypto_fragments([(2**40, b"x")]) == b""


def test_the_reassembler_drops_the_highest_offset_the_rfc_encodes():
    """The reader holds against the largest offset a CRYPTO frame can carry."""
    assert reassemble_crypto_fragments([(RFC_9000_MAXIMUM_OFFSET, b"x")]) == b""


def test_the_reassembler_keeps_the_real_fragment_beside_a_hostile_one():
    """A fragment past the limit drops, and the fragment below it survives."""
    fragments = [(0, b"hello "), (2**40, b"x"), (6, b"world")]
    assert reassemble_crypto_fragments(fragments) == b"hello world"


def test_the_reassembler_allocates_no_more_than_the_limit():
    """The buffer never passes `MAXIMUM_CRYPTO_BUFFER_BYTES`."""
    fragments = [(MAXIMUM_CRYPTO_BUFFER_BYTES - 1, b"x")]
    assert len(reassemble_crypto_fragments(fragments)) == MAXIMUM_CRYPTO_BUFFER_BYTES


def test_the_reassembler_drops_a_fragment_that_ends_one_byte_past_the_limit():
    """The limit is the last byte the buffer holds, not the first it drops."""
    assert reassemble_crypto_fragments([(MAXIMUM_CRYPTO_BUFFER_BYTES, b"x")]) == b""


def _quic_packet(sport=50000):
    """Return one UDP datagram whose payload starts a QUIC long header."""
    return (
        IP(src="1.1.1.1", dst="2.2.2.2")
        / UDP(sport=sport, dport=443)
        / Raw(load=b"\x80" + b"\x00" * 30)
    )


def _stub_decrypt(monkeypatch, fragments_for):
    """Point `decrypt_quic_initial_crypto` at a function the test drives.

    Args:
        monkeypatch: The pytest fixture, which restores the module on teardown.
        fragments_for: A function of the call count returning (fragments, dcid).
    """
    calls = {"n": 0}

    def fake_decrypt(_payload):
        calls["n"] += 1
        return fragments_for(calls["n"])

    monkeypatch.setattr(quic_utils, "decrypt_quic_initial_crypto", fake_decrypt)
    return calls


def test_the_fingerprinter_collects_no_fragment_past_the_limit(monkeypatch):
    """A decrypted packet naming a huge offset leaves the per-DCID buffer empty."""
    dcid = b"\xaa\xbb\xcc\xdd"
    _stub_decrypt(monkeypatch, lambda _n: ([(2**40, b"x")], dcid))

    fingerprinter = JA4Fingerprinter()
    assert fingerprinter.process_packet(_quic_packet()) is None
    assert fingerprinter._quic_fragments[dcid.hex()] == []


def test_the_fingerprinter_bounds_its_fragment_table_by_entry_count(monkeypatch):
    """A sender that names a new connection ID on each datagram fills no table.

    The table holds one entry for each Destination Connection ID, so a flood of
    connection IDs grows it without a limit unless the fingerprinter evicts.
    """
    _stub_decrypt(
        monkeypatch,
        lambda n: ([(0, INCOMPLETE_CLIENT_HELLO)], n.to_bytes(8, "big")),
    )

    fingerprinter = JA4Fingerprinter()
    for _ in range(MAX_QUIC_FRAGMENT_CONNECTIONS + 200):
        fingerprinter.process_packet(_quic_packet())

    assert len(fingerprinter._quic_fragments) <= MAX_QUIC_FRAGMENT_CONNECTIONS
    # The bookkeeping tables track the fragment table rather than outliving it.
    assert len(fingerprinter._quic_dcid_to_tuple) <= MAX_QUIC_FRAGMENT_CONNECTIONS
    assert len(fingerprinter._quic_fragment_seen) <= MAX_QUIC_FRAGMENT_CONNECTIONS


def test_the_fingerprinter_bounds_its_fragment_table_by_age(monkeypatch):
    """A connection that adds no fragment for the maximum age leaves the table."""
    first_dcid = b"\x01" * 8
    second_dcid = b"\x02" * 8
    _stub_decrypt(
        monkeypatch,
        lambda n: (
            [(0, INCOMPLETE_CLIENT_HELLO)],
            first_dcid if n == 1 else second_dcid,
        ),
    )

    fingerprinter = JA4Fingerprinter()

    first = _quic_packet()
    first.time = 1000.0
    fingerprinter.process_packet(first)
    assert first_dcid.hex() in fingerprinter._quic_fragments

    second = _quic_packet()
    second.time = 1000.0 + MAX_QUIC_FRAGMENT_AGE_SECONDS + 1
    fingerprinter.process_packet(second)

    assert first_dcid.hex() not in fingerprinter._quic_fragments
    assert first_dcid.hex() not in fingerprinter._quic_dcid_to_tuple
    assert first_dcid.hex() not in fingerprinter._quic_fragment_seen
    assert second_dcid.hex() in fingerprinter._quic_fragments


def test_the_fingerprinter_keeps_a_connection_inside_the_maximum_age(monkeypatch):
    """A connection that is still inside the maximum age keeps its fragments."""
    first_dcid = b"\x01" * 8
    second_dcid = b"\x02" * 8
    _stub_decrypt(
        monkeypatch,
        lambda n: (
            [(0, INCOMPLETE_CLIENT_HELLO)],
            first_dcid if n == 1 else second_dcid,
        ),
    )

    fingerprinter = JA4Fingerprinter()

    first = _quic_packet()
    first.time = 1000.0
    fingerprinter.process_packet(first)

    second = _quic_packet()
    second.time = 1000.0 + MAX_QUIC_FRAGMENT_AGE_SECONDS - 1
    fingerprinter.process_packet(second)

    assert first_dcid.hex() in fingerprinter._quic_fragments
    assert second_dcid.hex() in fingerprinter._quic_fragments


def test_the_fingerprinter_reset_empties_every_fragment_table(monkeypatch):
    """`reset` drops the age table beside the two tables it already dropped."""
    _stub_decrypt(
        monkeypatch,
        lambda _n: ([(0, INCOMPLETE_CLIENT_HELLO)], b"\xaa" * 8),
    )

    fingerprinter = JA4Fingerprinter()
    fingerprinter.process_packet(_quic_packet())
    fingerprinter.reset()

    assert fingerprinter._quic_fragments == {}
    assert fingerprinter._quic_dcid_to_tuple == {}
    assert fingerprinter._quic_fragment_seen == {}


def test_the_fingerprinter_cleanup_drops_the_age_entry(monkeypatch):
    """`cleanup_connection` drops every table entry the connection holds."""
    dcid = b"\xaa" * 8
    _stub_decrypt(monkeypatch, lambda _n: ([(0, INCOMPLETE_CLIENT_HELLO)], dcid))

    fingerprinter = JA4Fingerprinter()
    fingerprinter.process_packet(_quic_packet())
    fingerprinter.cleanup_connection("1.1.1.1", 50000, "2.2.2.2", 443, "udp")

    assert dcid.hex() not in fingerprinter._quic_fragments
    assert dcid.hex() not in fingerprinter._quic_dcid_to_tuple
    assert dcid.hex() not in fingerprinter._quic_fragment_seen


@pytest.mark.parametrize("exponent", [28, 34, 40, 62])
def test_the_reassembler_names_no_large_buffer_for_any_hostile_offset(exponent):
    """No offset the RFC encodes produces a buffer above the limit.

    The test names the offsets of the issue #122 measurement. Each one produced a
    buffer of that many bytes before the bound existed.
    """
    offset = min(2**exponent, RFC_9000_MAXIMUM_OFFSET)
    assert len(reassemble_crypto_fragments([(offset, b"x")])) <= MAXIMUM_CRYPTO_BUFFER_BYTES
