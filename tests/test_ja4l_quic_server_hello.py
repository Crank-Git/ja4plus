"""JA4L server point tests for the QUIC form.

The reference records the server measurement point on the Initial packet that
completes the ServerHello. `python/ja4.py` reads the point where `packet_type` is `0`
and `tls.handshake.type` is `2`. A server that sends an Initial packet without a
ServerHello therefore moves no point, and a server that splits the ServerHello across
two Initial packets gives the timestamp of the second one.

`tests/quic_builder.py` builds the packets. Issue #102 carries the measurement.
"""

from scapy.all import IP, UDP, Raw

from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.utils.quic_utils import QUIC_INITIAL
from tests.quic_builder import (
    ACK_FRAME,
    client_initial,
    crypto_frame,
    server_hello,
    server_initial,
)

CLIENT_IP = "192.168.1.50"
SERVER_IP = "10.0.0.1"
CLIENT_PORT = 50000
SERVER_PORT = 443
CLIENT_DCID = bytes.fromhex("203f9e9f68698274")


def _to_server(payload, t):
    """Return one client packet that carries the payload at the timestamp."""
    packet = (
        IP(src=CLIENT_IP, dst=SERVER_IP)
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / Raw(load=payload)
    )
    packet.time = t
    return packet


def _from_server(payload, t):
    """Return one server packet that carries the payload at the timestamp."""
    packet = (
        IP(src=SERVER_IP, dst=CLIENT_IP)
        / UDP(sport=SERVER_PORT, dport=CLIENT_PORT)
        / Raw(load=payload)
    )
    packet.time = t
    return packet


def test_the_server_point_skips_an_initial_packet_that_carries_no_server_hello():
    """The fingerprinter reads the second Initial packet when the first holds an ACK."""
    fingerprinter = JA4LFingerprinter()
    fingerprinter.process_packet(_to_server(client_initial(CLIENT_DCID), 0.0))
    first = fingerprinter.process_packet(
        _from_server(server_initial(CLIENT_DCID, ACK_FRAME), 0.010)
    )
    second = fingerprinter.process_packet(
        _from_server(
            server_initial(CLIENT_DCID, crypto_frame(0, server_hello()), packet_number=1), 0.020
        )
    )

    assert first is None
    assert second == "JA4L-S=10000_64"


def test_the_server_point_waits_for_the_fragment_that_completes_the_server_hello():
    """The fingerprinter reads the Initial packet that carries the last fragment."""
    message = server_hello()
    fingerprinter = JA4LFingerprinter()
    fingerprinter.process_packet(_to_server(client_initial(CLIENT_DCID), 0.0))
    first = fingerprinter.process_packet(
        _from_server(server_initial(CLIENT_DCID, crypto_frame(0, message[:20])), 0.010)
    )
    second = fingerprinter.process_packet(
        _from_server(
            server_initial(CLIENT_DCID, crypto_frame(20, message[20:]), packet_number=1), 0.030
        )
    )

    assert first is None
    assert second == "JA4L-S=15000_64"


def test_the_server_point_reads_an_initial_packet_that_a_handshake_packet_follows():
    """The fingerprinter reads an Initial packet that shares a datagram with another packet.

    RFC 9000 Section 12.2 lets a server put a Handshake packet behind its Initial
    packet. The AEAD tag then covers the bytes the Length field names, and a reader
    that decrypts to the end of the datagram fails on the tag.
    """
    fingerprinter = JA4LFingerprinter()
    fingerprinter.process_packet(_to_server(client_initial(CLIENT_DCID), 0.0))
    result = fingerprinter.process_packet(
        _from_server(
            server_initial(CLIENT_DCID, crypto_frame(0, server_hello()), trailer=b"\xe0" * 64),
            0.012,
        )
    )

    assert result == "JA4L-S=6000_64"


def test_the_fingerprinter_reports_no_server_value_when_the_initial_packet_does_not_decrypt():
    """The fingerprinter emits no server value for an Initial packet it cannot read.

    A packet that does not decrypt hides the handshake type, so nothing states whether
    this packet carries the ServerHello. A value read from it names a point the
    reference does not hold.
    """
    fingerprinter = JA4LFingerprinter()
    fingerprinter.process_packet(_to_server(client_initial(CLIENT_DCID), 0.0))
    unreadable = bytes([0xC0 | (QUIC_INITIAL << 4)]) + b"\x00\x00\x00\x01" + b"\x00" * 40
    result = fingerprinter.process_packet(_from_server(unreadable, 0.010))

    assert result is None
    assert fingerprinter.get_fingerprints() == []


def test_the_fingerprinter_drops_a_crypto_fragment_that_names_a_huge_offset():
    """The fingerprinter reads no fragment whose offset reaches past the buffer limit.

    A CRYPTO frame offset is a 62-bit number, and a reassembly allocates a buffer that
    reaches the highest offset. A server that names an offset of 2**40 would make the
    fingerprinter allocate a terabyte inside `process_packet`.
    """
    fingerprinter = JA4LFingerprinter()
    fingerprinter.process_packet(_to_server(client_initial(CLIENT_DCID), 0.0))
    result = fingerprinter.process_packet(
        _from_server(server_initial(CLIENT_DCID, crypto_frame(2**40, server_hello())), 0.010)
    )

    assert result is None
    assert fingerprinter.connections[next(iter(fingerprinter.connections))]["server_crypto"] == []


def test_the_fingerprinter_reads_the_server_hello_after_it_drops_a_huge_offset():
    """The fingerprinter still reads a later Initial packet that carries the ServerHello."""
    fingerprinter = JA4LFingerprinter()
    fingerprinter.process_packet(_to_server(client_initial(CLIENT_DCID), 0.0))
    fingerprinter.process_packet(
        _from_server(server_initial(CLIENT_DCID, crypto_frame(2**40, b"\x02\x00\x00\x01x")), 0.010)
    )
    result = fingerprinter.process_packet(
        _from_server(
            server_initial(CLIENT_DCID, crypto_frame(0, server_hello()), packet_number=1), 0.020
        )
    )

    assert result == "JA4L-S=10000_64"


def test_the_fingerprinter_reports_no_server_value_when_the_client_sends_no_initial_packet():
    """The fingerprinter emits no server value without the client connection ID.

    The server Initial keys derive from the connection ID the client chose. A capture
    that starts after the client Initial packet holds no such value.
    """
    fingerprinter = JA4LFingerprinter()
    result = fingerprinter.process_packet(
        _from_server(server_initial(CLIENT_DCID, crypto_frame(0, server_hello())), 0.010)
    )

    assert result is None
    assert fingerprinter.get_fingerprints() == []
