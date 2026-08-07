"""Tests for the direction of a QUIC Initial packet on the JA4S path.

A client Initial packet and a server Initial packet carry the same long-header packet
type. The port names the direction, and `ja4l.py` reads it the same way. A server
Initial packet names the client with the connection ID the client chose as its source,
so the packet itself supplies no client connection ID. Issue #118 carries the
measurement.

The expected value comes from the FoxIO material. `chrome-cloudflare-quic-with-secrets`
holds `JA4S` `t130200_1301_234ea6891581` with `JA4S_r` `t130200_1301_0033,002b`. The
ServerHello this module builds carries the same TLS version, the same cipher and the
same two extensions in the same order, so only the transport letter differs.

`tests/quic_builder.py` builds the QUIC packets.
"""

import struct

from scapy.all import IP, UDP, Raw

from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

from tests.quic_builder import ACK_FRAME, client_initial, crypto_frame, server_initial

CLIENT_IP = "192.168.1.50"
SERVER_IP = "10.0.0.1"
CLIENT_PORT = 50280
SERVER_PORT = 443
CLIENT_DCID = bytes.fromhex("203f9e9f68698274")

CLIENT_KEY = "{}:{}-{}:{}".format(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)
SERVER_KEY = "{}:{}-{}:{}".format(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)

EXPECTED_JA4S = "q130200_1301_234ea6891581"
EXPECTED_JA4S_RAW = "q130200_1301_0033,002b"


def _extension(identifier, data):
    """Return one TLS extension with the identifier and the data."""
    return struct.pack("!HH", identifier, len(data)) + data


def _server_hello():
    """Return one TLS 1.3 ServerHello that JA4S reads.

    The message names cipher `1301`, and it carries extension `0033` before extension
    `002b`. The FoxIO `JA4S_r` value `t130200_1301_0033,002b` gives that order.

    Returns:
        The handshake message bytes.
    """
    key_share = _extension(0x0033, struct.pack("!HH", 0x001D, 32) + b"\x11" * 32)
    supported_versions = _extension(0x002B, struct.pack("!H", 0x0304))
    extensions = key_share + supported_versions
    body = struct.pack("!H", 0x0303) + b"\x22" * 32
    body += b"\x00"  # An empty session identifier.
    body += struct.pack("!H", 0x1301)
    body += b"\x00"  # The null compression method.
    body += struct.pack("!H", len(extensions)) + extensions
    return b"\x02" + len(body).to_bytes(3, "big") + body


def _to_server(payload, sport=CLIENT_PORT, dport=SERVER_PORT):
    """Return one client packet that carries the payload."""
    return IP(src=CLIENT_IP, dst=SERVER_IP) / UDP(sport=sport, dport=dport) / Raw(load=payload)


def _from_server(payload, sport=SERVER_PORT, dport=CLIENT_PORT):
    """Return one server packet that carries the payload."""
    return IP(src=SERVER_IP, dst=CLIENT_IP) / UDP(sport=sport, dport=dport) / Raw(load=payload)


def _server_hello_packet():
    """Return one server Initial packet that carries the whole ServerHello."""
    return server_initial(CLIENT_DCID, crypto_frame(0, _server_hello()))


def test_the_fingerprinter_reads_a_quic_server_initial_packet():
    """The fingerprinter returns the JA4S value of a QUIC server Initial packet."""
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(_to_server(client_initial(CLIENT_DCID)))

    assert fingerprinter.process_packet(_from_server(_server_hello_packet())) == EXPECTED_JA4S


def test_the_fingerprinter_records_the_raw_value_of_a_quic_server_initial_packet():
    """The fingerprinter records the raw JA4S value in the wire order of the extensions."""
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(_to_server(client_initial(CLIENT_DCID)))
    fingerprinter.process_packet(_from_server(_server_hello_packet()))

    assert fingerprinter.last_raw == EXPECTED_JA4S_RAW


def test_the_fingerprinter_keeps_the_client_connection_id():
    """The fingerprinter stores no connection ID from a server Initial packet."""
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(_to_server(client_initial(CLIENT_DCID)))
    fingerprinter.process_packet(_from_server(_server_hello_packet()))

    assert fingerprinter._quic_dcids == {CLIENT_KEY: CLIENT_DCID}


def test_the_fingerprinter_keeps_the_client_connection_id_after_a_second_client_packet():
    """The fingerprinter reads the connection ID of the latest client Initial packet.

    A Retry packet makes the client choose another connection ID, so the latest client
    Initial packet supplies the value.
    """
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(_to_server(client_initial(CLIENT_DCID)))
    fingerprinter.process_packet(_from_server(server_initial(CLIENT_DCID, ACK_FRAME)))
    second = bytes.fromhex("0102030405060708")
    fingerprinter.process_packet(_to_server(client_initial(second)))

    assert fingerprinter._quic_dcids == {CLIENT_KEY: second}


def test_the_fingerprinter_reads_no_server_initial_packet_before_the_client_one():
    """The fingerprinter returns None when it holds no client connection ID."""
    fingerprinter = JA4SFingerprinter()

    assert fingerprinter.process_packet(_from_server(_server_hello_packet())) is None
    assert fingerprinter._quic_dcids == {}


def test_the_fingerprinter_reads_no_initial_packet_that_carries_no_server_hello():
    """The fingerprinter returns None for a server Initial packet that holds an ACK frame."""
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(_to_server(client_initial(CLIENT_DCID)))

    assert (
        fingerprinter.process_packet(_from_server(server_initial(CLIENT_DCID, ACK_FRAME))) is None
    )


def test_the_fingerprinter_reads_no_direction_when_both_ports_are_443():
    """The fingerprinter returns None when the two ports of the flow name no server.

    A flow whose two ports are 443 names no server, so the direction of a packet is
    unknown and every value it gives is a guess.
    """
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(_to_server(client_initial(CLIENT_DCID), sport=SERVER_PORT))
    result = fingerprinter.process_packet(_from_server(_server_hello_packet(), dport=SERVER_PORT))

    assert result is None
    assert fingerprinter._quic_dcids == {}


def test_the_fingerprinter_reads_no_quic_packet_that_holds_a_short_header():
    """The fingerprinter returns None for a datagram whose header is a short header."""
    fingerprinter = JA4SFingerprinter()

    assert fingerprinter.process_packet(_from_server(b"\x40" + b"\x00" * 40)) is None


def test_the_cleanup_removes_the_client_connection_id():
    """The fingerprinter drops the stored connection ID of a connection that closes."""
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(_to_server(client_initial(CLIENT_DCID)))
    fingerprinter.cleanup_connection(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, "udp")

    assert CLIENT_KEY not in fingerprinter._quic_dcids
    assert SERVER_KEY not in fingerprinter._quic_dcids
