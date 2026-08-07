"""JA4L state tests for a connection that is reused, reordered or absent.

No FoxIO vector holds these packet orders. The tests state what the fingerprinter
reports when a capture holds them, because a wrong answer here reaches a caller as a
latency that no packet in the capture supports.
"""

from scapy.all import IP, Raw, TCP

from ja4plus.fingerprinters.ja4l import JA4LFingerprinter

CLIENT, SERVER = "1.1.1.1", "2.2.2.2"
CLIENT_PORT, SERVER_PORT = 50000, 443


def _client(flags, sequence, acknowledgement, when, payload=b""):
    """Build one packet the client sends."""
    packet = (
        IP(src=CLIENT, dst=SERVER, ttl=128)
        / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags=flags, seq=sequence, ack=acknowledgement)
        / Raw(payload)
    )
    packet.time = when
    return packet


def _server(flags, sequence, acknowledgement, when, payload=b""):
    """Build one packet the server sends."""
    packet = (
        IP(src=SERVER, dst=CLIENT, ttl=64)
        / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags=flags, seq=sequence, ack=acknowledgement)
        / Raw(payload)
    )
    packet.time = when
    return packet


def _values(packets):
    """Return the values one packet list leaves in the fingerprinter."""
    fingerprinter = JA4LFingerprinter()
    for packet in packets:
        fingerprinter.process_packet(packet)
    return [entry["fingerprint"] for entry in fingerprinter.get_fingerprints()]


def test_a_second_connection_on_the_same_endpoints_gets_its_own_values():
    """A later connection reads no measurement point of the connection before it."""
    values = _values(
        [
            _client("S", 0, 0, 0.000),
            _server("SA", 0, 1, 0.001),
            _client("A", 1, 1, 0.002),
            _client("FA", 1, 1, 0.003),
            # The client opens a second connection with another initial sequence
            # number, five seconds later.
            _client("S", 9000, 0, 5.000),
            _server("SA", 7000, 9001, 5.004),
            _client("A", 9001, 7001, 5.006),
        ]
    )
    # The FIN of the first connection also carries the relative sequence number 1 and
    # the relative acknowledgement number 1, so it moves the client point once more.
    assert values == ["JA4L-S=500_64", "JA4L-C=1000_128", "JA4L-S=2000_64", "JA4L-C=1000_128"]


def test_a_reordered_capture_still_reports_the_server_value():
    """The fingerprinter reports the server value when the SYN-ACK reaches it first.

    A capture that merges two interfaces holds the packets of one connection out of
    order. The timestamps still state the order the network gave.
    """
    values = _values(
        [
            _server("SA", 0, 1, 0.002),
            _client("S", 0, 0, 0.000),
            _client("A", 1, 1, 0.003),
        ]
    )
    assert "JA4L-S=1000_64" in values


def test_a_repeated_syn_that_carries_the_same_number_changes_nothing():
    """A retransmitted SYN keeps the measurement point of the first one."""
    values = _values(
        [
            _client("S", 0, 0, 0.000),
            _client("S", 0, 0, 0.001),
            _server("SA", 0, 1, 0.002),
            _client("A", 1, 1, 0.003),
        ]
    )
    assert values == ["JA4L-S=1000_64", "JA4L-C=500_128"]


def test_a_capture_that_starts_after_the_handshake_reports_nothing():
    """The fingerprinter needs the SYN, so a capture without one gives no value."""
    assert _values([_client("A", 1, 1, 0.000), _client("PA", 1, 1, 0.001, b"hello")]) == []
