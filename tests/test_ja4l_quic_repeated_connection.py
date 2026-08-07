"""Tests for the JA4L QUIC measurement points across a repeated connection.

Issue #123 asks the QUIC path to restart its measurement points when a client repeats
the handshake over one address pair and port pair, and to complete the server value
when a server Initial packet arrives before its client Initial packet. The FoxIO Rust
implementation is the only FoxIO implementation that reads a QUIC handshake, so it
decides both cases. A measurement of it at the pinned commit rejects both changes.

The measurement used two synthetic captures that `tests/quic_builder.py` builds:

    ja4 /tmp/quic_repeat.pcap     -> ja4l_c: 500_64   ja4l_s: 5000_56
    ja4 /tmp/quic_mirrored.pcap   -> []

The first capture holds two complete handshakes over one address pair and port pair.
The reference reports one value pair, and it reads the first handshake. The second
capture holds one server Initial packet before its client Initial packet. The
reference reports nothing, so it never completes the server value.

`rust/ja4/src/time/udp.rs` states the mechanism. The state machine holds a terminal
`Done` state that ignores every later packet, and its `Handshake` state discards a
later `ClientInitial`. Its first state discards a `ServerInitial`.

These tests hold the two readers together on the cases the vector set omits. A restart
would make this project report a value pair the reference does not report.

Measured against the FoxIO reference at commit
27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8, which `tests/download_test_vectors.py` pins.
"""

from scapy.all import IP, UDP, Raw

from ja4plus.fingerprinters.ja4l import JA4LFingerprinter

from tests.quic_builder import (
    ACK_FRAME,
    client_initial,
    crypto_frame,
    handshake_packet,
    server_hello,
    server_initial,
)

CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 44444
SERVER_PORT = 443

FIRST_DCID = bytes.fromhex("0102030405060708")
SECOND_DCID = bytes.fromhex("1112131415161718")

SERVER_HELLO_FRAMES = crypto_frame(0, server_hello()) + ACK_FRAME

CLIENT_TTL = 64
SERVER_TTL = 56


def _to_server(payload, t):
    """Return one client packet that carries the payload at the timestamp."""
    packet = (
        IP(src=CLIENT_IP, dst=SERVER_IP, ttl=CLIENT_TTL)
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / Raw(load=payload)
    )
    packet.time = t
    return packet


def _from_server(payload, t):
    """Return one server packet that carries the payload at the timestamp."""
    packet = (
        IP(src=SERVER_IP, dst=CLIENT_IP, ttl=SERVER_TTL)
        / UDP(sport=SERVER_PORT, dport=CLIENT_PORT)
        / Raw(load=payload)
    )
    packet.time = t
    return packet


def _handshake_round(fingerprinter, dcid, base):
    """Send the four packets of one complete QUIC handshake to the fingerprinter."""
    fingerprinter.process_packet(_to_server(client_initial(dcid), base + 0.000))
    fingerprinter.process_packet(
        _from_server(server_initial(dcid, SERVER_HELLO_FRAMES), base + 0.010)
    )
    fingerprinter.process_packet(_from_server(handshake_packet(), base + 0.011))
    fingerprinter.process_packet(_to_server(handshake_packet(), base + 0.012))


def test_a_repeated_quic_handshake_reports_one_value_pair():
    """The fingerprinter reads the first handshake and reports no second value pair.

    The reference reports `ja4l_c: 500_64` and `ja4l_s: 5000_56` for this traffic. A
    restart on the second client Initial packet would report the second handshake as
    well, and no FoxIO implementation reports it.
    """
    fingerprinter = JA4LFingerprinter()
    _handshake_round(fingerprinter, FIRST_DCID, 1000.0)
    _handshake_round(fingerprinter, SECOND_DCID, 1001.0)

    values = [entry["fingerprint"] for entry in fingerprinter.get_fingerprints()]
    assert values == ["JA4L-S=5000_56", "JA4L-C=500_64"]


def test_a_server_initial_packet_before_its_client_initial_packet_gives_no_server_value():
    """The fingerprinter completes no server value from a server Initial packet that leads.

    The reference reports nothing at all for this traffic, so it holds no server value.
    A server measurement point taken from the leading packet would report a latency the
    reference does not report.
    """
    fingerprinter = JA4LFingerprinter()
    fingerprinter.process_packet(
        _from_server(server_initial(FIRST_DCID, SERVER_HELLO_FRAMES), 2000.000)
    )
    fingerprinter.process_packet(_to_server(client_initial(FIRST_DCID), 2000.010))
    fingerprinter.process_packet(_from_server(handshake_packet(), 2000.011))
    fingerprinter.process_packet(_to_server(handshake_packet(), 2000.012))

    values = [entry["fingerprint"] for entry in fingerprinter.get_fingerprints()]
    assert not [value for value in values if value.startswith("JA4L-S=")]
