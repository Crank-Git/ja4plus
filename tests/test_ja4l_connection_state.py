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


def test_a_retransmitted_syn_ack_reports_no_second_server_value():
    """A retransmitted SYN-ACK reaches no new measurement point, so it gives no value.

    The first SYN-ACK sets point `B`. A later SYN-ACK finds point `B` already set and
    changes neither the point nor the TTL, so a second value would repeat the first one.
    The reference publishes one server value for one connection. `ssh2.pcapng` stream 15
    proves it: the expected-output file holds `JA4L-S=6252_58` once, and #272 measured
    that this project produced it twice.
    """
    values = _values(
        [
            _client("S", 0, 0, 0.000),
            _server("SA", 0, 1, 0.001),
            _server("SA", 0, 1, 0.005),
            _client("A", 1, 1, 0.006),
        ]
    )
    assert values == ["JA4L-S=500_64", "JA4L-C=2500_128"]


def test_a_connection_of_100_bare_acks_stores_one_client_value():
    """The stored list holds one client value for one connection.

    A bare ACK carries the relative sequence number 1 and the relative acknowledgement
    number 1, so every one of the 100 ACKs moves the client measurement point. The
    reference holds one client value for one connection, so the later point replaces the
    value the fingerprinter already stored.
    """
    packets = [_client("S", 0, 0, 0.000), _server("SA", 0, 1, 0.001)]
    for index in range(100):
        packets.append(_client("A", 1, 1, 0.002 + index * 0.001))
    client_values = [value for value in _values(packets) if value.startswith("JA4L-C=")]
    # The reference measures to the last packet that holds both relative numbers, which
    # is the 100th ACK at 0.101s. `browsers-x509.pcapng` stream 0 proves the rule: the
    # reference value 278_128 comes from the Client Hello, and the bare ACK gives 56.
    assert client_values == ["JA4L-C=50000_128"]


def test_a_capture_that_starts_after_the_handshake_reports_nothing():
    """The fingerprinter needs the SYN, so a capture without one gives no value."""
    assert _values([_client("A", 1, 1, 0.000), _client("PA", 1, 1, 0.001, b"hello")]) == []


def test_a_syn_with_no_syn_ack_reports_no_value():
    """A connection that never answers the SYN gives no value on either direction.

    The reference reads point `B` from the SYN-ACK. Point `B` ends the server value and
    starts the client value, so a connection without a SYN-ACK reaches neither one.
    `ssh2.pcapng` holds 11 such connections, and its expected-output file names none of
    them. Read #156 for the measurement.
    """
    assert _values([_client("S", 0, 0, 0.000), _client("S", 0, 0, 1.000)]) == []


def test_a_syn_ack_with_no_client_packet_reports_the_server_value_alone():
    """A connection that stops after the SYN-ACK still gives the server value.

    The reference gates the two values apart. Point `A` and point `B` complete the
    server value, and the client value needs point `C` as well. A rule that held the
    server value back until the client point arrived would drop this value.

    Two committed vectors prove the split on the QUIC form. The connection at
    `ssh2.pcapng` stream 33 and the connection at `tls3.pcapng` stream 25 each hold a
    `JA4L-S` and no `JA4L-C` in the expected-output file.
    """
    assert _values([_client("S", 0, 0, 0.000), _server("SA", 0, 1, 0.001)]) == ["JA4L-S=500_64"]
