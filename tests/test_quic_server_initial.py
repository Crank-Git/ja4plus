"""Tests for the server-side QUIC Initial reader.

RFC 9000 Section 12.2 lets a sender put several QUIC packets in one datagram, and a
server commonly puts a Handshake packet behind its Initial packet. The AEAD tag of the
Initial packet covers only the bytes the Length field names, so a reader that decrypts
to the end of the datagram fails on the tag. Issue #102 carries the measurement.
"""

from ja4plus.utils.quic_utils import (
    QUIC_HANDSHAKE,
    _initial_packet_end,
    decrypt_quic_server_initial_crypto,
    initial_packet_dcid,
    server_hello_is_complete,
)
from tests.quic_builder import (
    ACK_FRAME,
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


def test_the_server_reader_rejects_a_short_header():
    """The reader returns None for a datagram that holds a short header."""
    assert decrypt_quic_server_initial_crypto(b"\x40" + b"\x00" * 40, CLIENT_DCID) is None


def test_the_server_reader_rejects_an_empty_connection_id():
    """The reader returns None when the caller passes no connection ID."""
    packet = server_initial(CLIENT_DCID, crypto_frame(0, server_hello()))
    assert decrypt_quic_server_initial_crypto(packet, b"") is None


def test_the_server_reader_rejects_a_version_negotiation_packet():
    """The reader returns None for a packet whose version number is zero."""
    packet = b"\xc0" + b"\x00\x00\x00\x00" + b"\x00" * 40
    assert decrypt_quic_server_initial_crypto(packet, CLIENT_DCID) is None


def test_the_server_reader_rejects_a_handshake_packet():
    """The reader returns None for a packet that is no Initial packet."""
    packet = bytes([0xC0 | (QUIC_HANDSHAKE << 4)]) + b"\x00\x00\x00\x01" + b"\x00" * 40
    assert decrypt_quic_server_initial_crypto(packet, CLIENT_DCID) is None


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
