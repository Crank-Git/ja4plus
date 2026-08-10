"""Tests for the server-side QUIC Initial reader.

RFC 9000 Section 12.2 lets a sender put several QUIC packets in one datagram. A server
commonly puts a Handshake packet behind its Initial packet. The AEAD tag of the Initial
packet covers only the bytes the Length field names. A reader that decrypts to the end
of the datagram fails on the tag. Issue #102 carries the measurement.
"""

from ja4plus.utils.quic_utils import (
    MAXIMUM_CRYPTO_BUFFER_BYTES,
    QUIC_HANDSHAKE,
    _initial_packet_end,
    collect_crypto_fragments,
    decrypt_quic_server_initial_crypto,
    initial_packet_dcid,
    parse_quic_server_initial,
    server_hello_is_complete,
)
from tests.quic_builder import (
    ACK_FRAME,
    QUIC_VERSION_2,
    client_initial,
    crypto_frame,
    server_hello,
    server_initial,
)

CLIENT_DCID = bytes.fromhex("203f9e9f68698274")


def test_the_packet_end_reader_reads_the_length_field():
    """The reader returns the offset the Length field of the long header gives."""
    packet = server_initial(CLIENT_DCID, ACK_FRAME)
    assert _initial_packet_end(packet + b"\xe0" * 40) == len(packet)


def test_the_packet_end_reader_returns_the_datagram_length_for_a_length_field_that_overruns():
    """The reader returns the datagram length when the Length field names more bytes."""
    packet = bytearray(server_initial(CLIENT_DCID, ACK_FRAME))
    # Byte 8 holds the two-byte Length field of a header with two empty connection
    # identifiers and an empty token.
    packet[8] = 0x7F
    packet[9] = 0xFF
    assert _initial_packet_end(bytes(packet)) == len(packet)


def test_the_packet_end_reader_returns_the_datagram_length_for_a_truncated_header():
    """The reader returns the datagram length for a header it cannot read."""
    assert _initial_packet_end(b"\xc0\x00\x00\x00\x01") == 5


def test_the_connection_id_reader_reads_a_client_initial_packet():
    """The reader returns the destination connection ID of an Initial packet."""
    assert initial_packet_dcid(client_initial(CLIENT_DCID)) == CLIENT_DCID


def test_the_connection_id_reader_rejects_a_handshake_packet():
    """The reader returns None for a packet that is no Initial packet."""
    packet = bytes([0xC0 | (QUIC_HANDSHAKE << 4)]) + b"\x00\x00\x00\x01" + b"\x00" * 16
    assert initial_packet_dcid(packet) is None


def test_the_connection_id_reader_rejects_a_length_byte_that_overruns():
    """The reader returns None when the length byte names bytes the datagram lacks."""
    packet = b"\xc0" + b"\x00\x00\x00\x01" + b"\x20" + b"\x00" * 4
    assert initial_packet_dcid(packet) is None


def test_the_server_reader_returns_the_crypto_fragments_of_one_packet():
    """The reader returns the CRYPTO fragments a server Initial packet carries."""
    message = server_hello()
    packet = server_initial(CLIENT_DCID, crypto_frame(0, message))
    assert decrypt_quic_server_initial_crypto(packet, CLIENT_DCID) == [(0, message)]


def test_the_server_reader_reads_a_packet_that_a_second_quic_packet_follows():
    """The reader decrypts an Initial packet that shares a datagram with another packet."""
    message = server_hello()
    packet = server_initial(CLIENT_DCID, crypto_frame(0, message), trailer=b"\xe0" * 64)
    assert decrypt_quic_server_initial_crypto(packet, CLIENT_DCID) == [(0, message)]


def test_the_server_reader_returns_no_fragment_for_a_packet_that_carries_an_ack():
    """The reader returns an empty list for an Initial packet that holds an ACK frame."""
    packet = server_initial(CLIENT_DCID, ACK_FRAME)
    assert decrypt_quic_server_initial_crypto(packet, CLIENT_DCID) == []


def test_the_server_reader_rejects_a_wrong_connection_id():
    """The reader returns None when the connection ID derives the wrong keys."""
    packet = server_initial(CLIENT_DCID, crypto_frame(0, server_hello()))
    assert decrypt_quic_server_initial_crypto(packet, b"\x01" * 8) is None


# A packet of dummy bytes makes the reader return None whichever guard runs, so such a
# case measures the decryption rather than the guard it names. Every guard case below
# therefore carries a protected ServerHello the reader decrypts. The AEAD tag covers the
# header, so each case builds the rejected header rather than changing a byte of a built
# packet. #348 records the measurement.
def rejected_packet(client_dcid=CLIENT_DCID, **header):
    """Return one server Initial packet that decrypts and carries a ServerHello.

    Args:
        client_dcid: The connection ID the server Initial keys derive from.
        header: The header fields `server_initial` writes.

    Returns:
        The bytes of the UDP payload.
    """
    return server_initial(client_dcid, crypto_frame(0, server_hello()), **header)


def test_the_server_reader_returns_none_for_a_truncated_long_header():
    """The reader returns None for a long header that holds three version bytes.

    The reader unpacks the version field outside its `try` block, so the length guard is
    the only thing that stops a `struct.error` reaching the caller. No packet under five
    bytes can carry a ServerHello, so this case measures the length guard by the
    exception it prevents rather than by a result.
    """
    assert decrypt_quic_server_initial_crypto(b"\xc0\x00\x00\x00", CLIENT_DCID) is None


def test_the_server_reader_rejects_a_short_header():
    """The reader returns None for a datagram that holds a short header."""
    assert (
        decrypt_quic_server_initial_crypto(rejected_packet(long_header=False), CLIENT_DCID) is None
    )


def test_the_server_reader_rejects_an_empty_connection_id():
    """The reader returns None when the caller passes no connection ID.

    The packet derives its keys from the empty connection ID, so a reader that drops
    this guard derives the keys the packet holds and returns the CRYPTO fragments.
    """
    assert decrypt_quic_server_initial_crypto(rejected_packet(b""), b"") is None


def test_the_server_reader_rejects_a_version_negotiation_packet():
    """The reader returns None for a packet whose version number is zero."""
    # The reader reads version 0 as version 1, so the builder protects the packet under
    # the version 1 salt. The version guard is then the only rejection.
    packet = rejected_packet(version=0, type_code=0, key_version=1)
    assert decrypt_quic_server_initial_crypto(packet, CLIENT_DCID) is None


def test_the_server_reader_rejects_a_handshake_packet():
    """The reader returns None for a packet that is no Initial packet."""
    packet = rejected_packet(type_code=QUIC_HANDSHAKE)
    assert decrypt_quic_server_initial_crypto(packet, CLIENT_DCID) is None


def test_the_server_reader_rejects_a_version_2_handshake_packet():
    """The reader returns None for a version 2 packet that is no Initial packet."""
    # Version 2 gives a Handshake packet the type code 3. RFC 9369 Section 3.2 states
    # the code. The version 2 arm of the type guard rejects it.
    packet = rejected_packet(version=QUIC_VERSION_2, type_code=3)
    assert decrypt_quic_server_initial_crypto(packet, CLIENT_DCID) is None


def test_the_server_reader_reads_a_version_2_initial_packet():
    """The reader returns the CRYPTO fragments a version 2 Initial packet carries."""
    message = server_hello()
    packet = server_initial(CLIENT_DCID, crypto_frame(0, message), version=QUIC_VERSION_2)
    assert decrypt_quic_server_initial_crypto(packet, CLIENT_DCID) == [(0, message)]


def test_the_server_initial_parser_drops_a_fragment_that_names_a_huge_offset():
    """The parser returns None rather than allocating the buffer the offset names.

    `ja4s.py` calls this parser on every server Initial packet. RFC 9000 Section 16
    lets a CRYPTO frame offset reach 4611686018427387903, and a reassembly allocates a
    buffer that reaches the highest offset. One datagram would otherwise make the
    parser allocate a terabyte.
    """
    packet = server_initial(CLIENT_DCID, crypto_frame(2**40, server_hello()))
    assert parse_quic_server_initial(packet, CLIENT_DCID) is None


def test_the_fragment_collector_drops_an_offset_past_the_limit():
    """The collector adds no fragment whose offset reaches past the buffer limit."""
    assert collect_crypto_fragments([], [(2**40, b"abc")]) == []


def test_the_fragment_collector_stops_before_it_passes_the_limit():
    """The collector holds no more than `MAXIMUM_CRYPTO_BUFFER_BYTES` bytes."""
    fragment = (0, b"\x00" * 1024)
    collected = collect_crypto_fragments([], [fragment] * 24)
    assert sum(len(data) for _, data in collected) == MAXIMUM_CRYPTO_BUFFER_BYTES


def test_the_fragment_collector_keeps_a_fragment_that_fits():
    """The collector adds a fragment that the limit holds."""
    assert collect_crypto_fragments([], [(0, b"abc")]) == [(0, b"abc")]


def test_the_server_hello_reader_reports_a_whole_message():
    """The reader reports True when the fragments hold every byte of the ServerHello."""
    assert server_hello_is_complete([(0, server_hello())])


def test_the_server_hello_reader_reports_an_incomplete_message():
    """The reader reports False while the fragments miss the end of the ServerHello."""
    message = server_hello()
    assert not server_hello_is_complete([(0, message[:20])])


def test_the_server_hello_reader_joins_two_fragments():
    """The reader reports True when two fragments together hold the ServerHello."""
    message = server_hello()
    fragments = [(0, message[:20]), (20, message[20:])]
    assert server_hello_is_complete(fragments)


def test_the_server_hello_reader_rejects_another_handshake_type():
    """The reader reports False for a message that is no ServerHello."""
    assert not server_hello_is_complete([(0, b"\x01\x00\x00\x02ab")])


def test_the_server_hello_reader_rejects_an_empty_fragment_list():
    """The reader reports False when the caller passes no fragment."""
    assert not server_hello_is_complete([])
