"""The JA4S reader of a ServerHello that two QUIC Initial packets split.

RFC 9000 Section 12.2 lets a server split a CRYPTO stream across several Initial
packets. Neither packet then holds the whole ServerHello, so a reader of one packet
produces no JA4S value. Issue #130 carries the case.

No FoxIO vector splits a ServerHello across two Initial packets, so every test here
carries its own capture. `tests/quic_builder.py` builds the packets.
"""

from scapy.all import IP, UDP, Raw

from ja4plus.fingerprinters.ja4 import (
    MAX_QUIC_FRAGMENT_AGE_SECONDS,
    MAX_QUIC_FRAGMENT_CONNECTIONS,
)
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
from tests.quic_builder import client_initial, crypto_frame, server_initial

CLIENT_DCID = bytes.fromhex("203f9e9f68698274")
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 50000
SERVER_PORT = 443

# The JA4S value of the ServerHello this module builds. The message names QUIC, TLS 1.3,
# one extension, no ALPN, and the cipher 0x1301. The hash is the first 12 characters of
# the SHA-256 of `002b`, which is the one extension the message carries.
EXPECTED_JA4S = "q130100_1301_b9a491fefe05"

# The offset that splits the ServerHello. The first packet then carries the handshake
# header and part of the body, so a reader of that packet alone finds no whole message.
SPLIT_OFFSET = 20


def server_hello_message():
    """Return one TLS ServerHello that the JA4S reader parses.

    The message names TLS 1.2 in its legacy version field and TLS 1.3 in its
    supported_versions extension, which is the form a TLS 1.3 server sends.

    Returns:
        The bytes of the handshake message.
    """
    body = (
        b"\x03\x03"  # The legacy version field.
        + b"\x00" * 32  # The random field.
        + b"\x00"  # An empty session identifier.
        + b"\x13\x01"  # The cipher TLS_AES_128_GCM_SHA256.
        + b"\x00"  # The null compression method.
        + b"\x00\x06"  # The length of the extension block.
        + b"\x00\x2b\x00\x02\x03\x04"  # supported_versions names TLS 1.3.
    )
    return b"\x02" + len(body).to_bytes(3, "big") + body


def datagram(payload, src_ip, src_port, dst_ip, dst_port, timestamp=None):
    """Return one UDP datagram that carries the payload."""
    packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=payload)
    if timestamp is not None:
        packet.time = timestamp
    return packet


def client_datagram(src_port=CLIENT_PORT, timestamp=None):
    """Return the client Initial packet that names the connection identifier."""
    return datagram(
        client_initial(CLIENT_DCID), CLIENT_IP, src_port, SERVER_IP, SERVER_PORT, timestamp
    )


def server_datagram(plaintext, dst_port=CLIENT_PORT, packet_number=0, timestamp=None):
    """Return one server Initial packet that carries the frames."""
    return datagram(
        server_initial(CLIENT_DCID, plaintext, packet_number=packet_number),
        SERVER_IP,
        SERVER_PORT,
        CLIENT_IP,
        dst_port,
        timestamp,
    )


def split_server_datagrams(dst_port=CLIENT_PORT, timestamp=None):
    """Return the two server Initial packets that split one ServerHello."""
    message = server_hello_message()
    first = server_datagram(
        crypto_frame(0, message[:SPLIT_OFFSET]),
        dst_port=dst_port,
        packet_number=0,
        timestamp=timestamp,
    )
    second = server_datagram(
        crypto_frame(SPLIT_OFFSET, message[SPLIT_OFFSET:]),
        dst_port=dst_port,
        packet_number=1,
        timestamp=timestamp,
    )
    return first, second


def test_the_fingerprinter_reads_a_server_hello_that_two_packets_split():
    """Two Initial packets that split one ServerHello produce one JA4S value."""
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(client_datagram())
    first, second = split_server_datagrams()

    assert fingerprinter.process_packet(first) is None
    assert fingerprinter.process_packet(second) == EXPECTED_JA4S


def test_the_fingerprinter_emits_one_value_for_a_split_server_hello():
    """The two packets together produce exactly one fingerprint entry."""
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(client_datagram())
    first, second = split_server_datagrams()
    fingerprinter.process_packet(first)
    fingerprinter.process_packet(second)

    assert len(fingerprinter.get_fingerprints()) == 1


def test_the_fingerprinter_reads_a_server_hello_that_one_packet_carries():
    """One Initial packet that carries the whole ServerHello still produces the value."""
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(client_datagram())
    packet = server_datagram(crypto_frame(0, server_hello_message()))

    assert fingerprinter.process_packet(packet) == EXPECTED_JA4S


def test_the_fingerprinter_reads_no_value_without_the_client_packet():
    """A server Initial packet alone produces no value, because it derives no key."""
    fingerprinter = JA4SFingerprinter()
    first, second = split_server_datagrams()

    assert fingerprinter.process_packet(first) is None
    assert fingerprinter.process_packet(second) is None


def test_the_fingerprinter_releases_the_fragments_it_read():
    """The fingerprinter drops the buffer of a connection whose message it read."""
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(client_datagram())
    first, second = split_server_datagrams()
    fingerprinter.process_packet(first)
    fingerprinter.process_packet(second)

    assert fingerprinter._quic_server_crypto == {}


def test_the_fingerprinter_holds_the_fragments_of_an_incomplete_message():
    """The fingerprinter keeps the buffer while a fragment is still missing."""
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(client_datagram())
    first, _ = split_server_datagrams()
    fingerprinter.process_packet(first)

    assert len(fingerprinter._quic_server_crypto) == 1


def test_the_fingerprinter_bounds_its_fragment_table_by_entry_count():
    """A server that starts a message on many connections fills no table."""
    fingerprinter = JA4SFingerprinter()
    first, _ = split_server_datagrams()
    incomplete = bytes(first[UDP].payload)

    for index in range(MAX_QUIC_FRAGMENT_CONNECTIONS + 200):
        port = 30000 + index
        fingerprinter.process_packet(client_datagram(src_port=port))
        fingerprinter.process_packet(datagram(incomplete, SERVER_IP, SERVER_PORT, CLIENT_IP, port))

    assert len(fingerprinter._quic_server_crypto) <= MAX_QUIC_FRAGMENT_CONNECTIONS


def test_the_fingerprinter_bounds_its_fragment_table_by_age():
    """A connection that adds no fragment for the maximum age leaves the table.

    Every packet of the case states its own time. A packet that states none moves the
    table to the wall clock, and the entries of the packets that state a time then age
    out at once.
    """
    fingerprinter = JA4SFingerprinter()
    first, _ = split_server_datagrams(timestamp=1000.0)
    fingerprinter.process_packet(client_datagram(timestamp=1000.0))
    fingerprinter.process_packet(first)
    assert len(fingerprinter._quic_server_crypto) == 1

    later_port = 50001
    later_time = 1000.0 + MAX_QUIC_FRAGMENT_AGE_SECONDS + 1
    later, _ = split_server_datagrams(dst_port=later_port, timestamp=later_time)
    fingerprinter.process_packet(client_datagram(src_port=later_port, timestamp=later_time))
    fingerprinter.process_packet(later)

    key = f"{CLIENT_IP}:{CLIENT_PORT}-{SERVER_IP}:{SERVER_PORT}"
    assert key not in fingerprinter._quic_server_crypto
    assert len(fingerprinter._quic_server_crypto) == 1


def test_the_fingerprinter_keeps_a_connection_inside_the_maximum_age():
    """A connection that is still inside the maximum age keeps its fragments."""
    fingerprinter = JA4SFingerprinter()
    first, _ = split_server_datagrams(timestamp=1000.0)
    fingerprinter.process_packet(client_datagram(timestamp=1000.0))
    fingerprinter.process_packet(first)

    later_port = 50001
    later_time = 1000.0 + MAX_QUIC_FRAGMENT_AGE_SECONDS - 1
    later, _ = split_server_datagrams(dst_port=later_port, timestamp=later_time)
    fingerprinter.process_packet(client_datagram(src_port=later_port, timestamp=later_time))
    fingerprinter.process_packet(later)

    assert len(fingerprinter._quic_server_crypto) == 2


def test_the_fingerprinter_cleanup_drops_the_fragments_of_the_connection():
    """`cleanup_connection` drops every fragment table entry the connection holds."""
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(client_datagram())
    first, _ = split_server_datagrams()
    fingerprinter.process_packet(first)

    fingerprinter.cleanup_connection(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, "udp")

    assert fingerprinter._quic_server_crypto == {}


def test_the_fingerprinter_reset_empties_every_fragment_table():
    """`reset` drops the fragment table and the age table."""
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(client_datagram())
    first, _ = split_server_datagrams()
    fingerprinter.process_packet(first)

    fingerprinter.reset()

    assert fingerprinter._quic_server_crypto == {}
