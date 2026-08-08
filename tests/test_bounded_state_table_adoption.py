"""Every state table a fingerprinter holds is a `BoundedStateTable`.

FR-concurrency-safety-7 states that every state table holds a maximum entry count.
FR-concurrency-safety-8 states that every state table evicts an entry that receives no
read for longer than a maximum age. #38 built `BoundedStateTable`, and #39 moves the
tables onto it.

Three shapes of case sit here.

1. `TABLES` names each moved table, and one case reads the class and the two bounds of
   each one. The case states the bounds as literal values. #175 derived a boundary case
   from the constant it asserted, and raising the constant then left the case green.
2. One case for each table feeds packets and reads the entry count against a bound the
   case sets. A bound the case sets keeps the case short, and
   FR-concurrency-safety-9 makes both bounds constructor arguments.
3. One case for each stateful method replays a connection whose span passes the maximum
   age while no gap inside it reaches that age. The connection produces every value it
   produces today. A capture replays faster than real time, so the age reads the packet
   timestamp and never the wall clock.
"""

import pytest
from scapy.all import IP, TCP, UDP, Raw

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter, SynAckTracker
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter
from ja4plus.utils.state_table import BoundedStateTable

# The table each fingerprinter holds, with the maximum entry count and the maximum age
# of that table in seconds. Each number is a literal, and no entry reads the constant
# the source states.
TABLES = [
    (JA4Fingerprinter, "_quic_fragments", 1000, 30),
    (JA4Fingerprinter, "_quic_dcid_to_tuple", 1000, 30),
    (JA4SFingerprinter, "_quic_dcids", 10000, 600),
    (JA4SFingerprinter, "_quic_server_crypto", 1000, 30),
    (JA4HFingerprinter, "consumed_seq", 100, 600),
    (JA4HFingerprinter, "unusable_base", 100, 600),
    (JA4LFingerprinter, "connections", 10000, 600),
    (JA4LFingerprinter, "grouping_keys", 10000, 600),
    (JA4XFingerprinter, "processed_certs", 1000, 600),
    (JA4XFingerprinter, "scan_offsets", 50, 600),
    (JA4SSHFingerprinter, "connections", 10000, 600),
    (JA4SSHFingerprinter, "_handshake_clients", 1000, 600),
    (JA4TFingerprinter, "connections", 10000, 600),
    (SynAckTracker, "times", 1000, 120),
    (SynAckTracker, "prefixes", 1000, 120),
]

TABLE_IDS = [f"{cls.__name__}.{name}" for cls, name, _, _ in TABLES]


@pytest.mark.parametrize(("holder", "name", "count", "age"), TABLES, ids=TABLE_IDS)
def test_every_state_table_is_a_bounded_state_table(holder, name, count, age):
    """Each table reads the class of #38 and the two bounds this issue states."""
    table = getattr(holder(), name)
    assert isinstance(table, BoundedStateTable)
    assert table.max_connections == count
    assert table.max_connection_age == age


@pytest.mark.parametrize(("holder", "name", "count", "age"), TABLES, ids=TABLE_IDS)
def test_reset_leaves_every_state_table_bounded_and_empty(holder, name, count, age):
    """`reset` builds a new table rather than a dictionary that holds no bound."""
    instance = holder()
    reset = getattr(instance, "reset", None) or getattr(instance, "clear")
    reset()
    table = getattr(instance, name)
    assert isinstance(table, BoundedStateTable)
    assert len(table) == 0
    assert table.max_connections == count


def _tcp(src, sport, dst, dport, flags, seconds, seq=0, ack=0, payload=None):
    """Return one TCP packet that carries the stated capture timestamp."""
    packet = IP(src=src, dst=dst, ttl=64) / TCP(
        sport=sport, dport=dport, flags=flags, seq=seq, ack=ack
    )
    if payload is not None:
        packet = packet / Raw(load=payload)
    packet.time = seconds
    return packet


def test_the_ja4l_connection_table_holds_its_entry_count():
    """A flood of connections leaves the JA4L table at the count the caller states."""
    fingerprinter = JA4LFingerprinter()
    fingerprinter.connections.max_connections = 4
    fingerprinter.grouping_keys.max_connections = 4

    for port in range(50000, 50020):
        fingerprinter.process_packet(_tcp("10.0.0.1", port, "10.0.0.2", 443, "S", 1000.0))

    assert len(fingerprinter.connections) == 4
    assert len(fingerprinter.grouping_keys) == 4


def test_the_ja4l_connection_table_evicts_an_entry_that_passes_the_maximum_age():
    """A connection that receives no packet for longer than the age leaves the table."""
    fingerprinter = JA4LFingerprinter()
    fingerprinter.connections.max_connection_age = 60
    fingerprinter.connections.eviction_interval = 1

    fingerprinter.process_packet(_tcp("10.0.0.1", 50000, "10.0.0.2", 443, "S", 1000.0))
    assert len(fingerprinter.connections) == 1

    fingerprinter.process_packet(_tcp("10.0.0.3", 50001, "10.0.0.4", 443, "S", 1100.0))

    assert len(fingerprinter.connections) == 1
    assert "tcp_10.0.0.1:50000_10.0.0.2:443" not in fingerprinter.connections


def test_ja4l_reads_a_handshake_whose_span_passes_the_maximum_age():
    """A slow handshake produces both values, because no gap inside it reaches the age.

    The three packets span 1000 seconds and the maximum age is 600 seconds. Each gap is
    500 seconds, so no entry ages out between two packets.
    """
    fingerprinter = JA4LFingerprinter()
    fingerprinter.connections.eviction_interval = 1
    fingerprinter.grouping_keys.eviction_interval = 1

    fingerprinter.process_packet(_tcp("10.0.0.1", 50000, "10.0.0.2", 443, "S", 1000.0, seq=0))
    server = fingerprinter.process_packet(
        _tcp("10.0.0.2", 443, "10.0.0.1", 50000, "SA", 1500.0, seq=0, ack=1)
    )
    client = fingerprinter.process_packet(
        _tcp("10.0.0.1", 50000, "10.0.0.2", 443, "A", 2000.0, seq=1, ack=1)
    )

    assert server is not None and server.startswith("JA4L-S=")
    assert client is not None and client.startswith("JA4L-C=")


def _ssh_data(client_port, seconds, to_server=True, payload=b"\x00\x00\x00\x20\x0a" + b"z" * 27):
    """Return one SSH data packet of one connection at the stated time."""
    if to_server:
        return _tcp("10.0.0.1", client_port, "10.0.0.2", 22, "PA", seconds, payload=payload)
    return _tcp("10.0.0.2", 22, "10.0.0.1", client_port, "PA", seconds, payload=payload)


def test_the_ja4ssh_connection_table_holds_its_entry_count():
    """A flood of SSH connections leaves the table at the count the caller states."""
    fingerprinter = JA4SSHFingerprinter()
    fingerprinter.connections.max_connections = 4

    for port in range(50000, 50020):
        fingerprinter.process_packet(_ssh_data(port, 1000.0))

    assert len(fingerprinter.connections) == 4


def test_the_ja4ssh_connection_table_evicts_an_entry_that_passes_the_maximum_age():
    """An SSH connection that goes quiet for longer than the age leaves the table."""
    fingerprinter = JA4SSHFingerprinter()
    fingerprinter.connections.max_connection_age = 60
    fingerprinter.connections.eviction_interval = 1

    fingerprinter.process_packet(_ssh_data(50000, 1000.0))
    assert len(fingerprinter.connections) == 1

    fingerprinter.process_packet(_ssh_data(50001, 1100.0))

    assert len(fingerprinter.connections) == 1
    assert "10.0.0.1:50000-10.0.0.2:22" not in fingerprinter.connections


def test_ja4ssh_emits_the_window_of_a_connection_whose_span_passes_the_maximum_age():
    """A connection that spans 2000 seconds still emits the window it holds open.

    Each gap between two packets is 100 seconds and the maximum age is 600 seconds, so
    the table holds the connection to the end of the capture.
    """
    fingerprinter = JA4SSHFingerprinter()
    fingerprinter.connections.eviction_interval = 1

    for index in range(20):
        fingerprinter.process_packet(_ssh_data(50000, 1000.0 + index * 100.0))

    emitted = fingerprinter.close_open_windows()

    # The 20 packets each carry 32 payload bytes to the server, so the window reports
    # the client packet size 32, the client packet count 20, and no server value.
    assert len(emitted) == 1
    assert emitted[0]["fingerprint"] == "c32s0_c20s0_c0s0"


def test_the_ja4ssh_handshake_table_evicts_an_entry_that_passes_the_maximum_age():
    """A handshake that no SSH packet follows leaves the handshake table."""
    fingerprinter = JA4SSHFingerprinter()
    fingerprinter._handshake_clients.max_connection_age = 60
    fingerprinter._handshake_clients.eviction_interval = 1

    fingerprinter.process_packet(_tcp("10.0.0.1", 50000, "10.0.0.2", 2222, "S", 1000.0))
    assert len(fingerprinter._handshake_clients) == 1

    fingerprinter.process_packet(_tcp("10.0.0.3", 50001, "10.0.0.4", 2222, "S", 1100.0))

    assert len(fingerprinter._handshake_clients) == 1


def test_the_ja4s_connection_identifier_table_holds_its_entry_count():
    """A flood of QUIC client Initial packets leaves the DCID table at its count."""
    fingerprinter = JA4SFingerprinter()
    fingerprinter._quic_dcids.max_connections = 4

    for port in range(50000, 50020):
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=port, dport=443)
        # A long-header Initial packet with a four-byte destination connection ID.
        packet = packet / Raw(load=b"\xc0\x00\x00\x00\x01\x04\xaa\xbb\xcc\xdd\x00" + b"\x00" * 40)
        packet.time = 1000.0
        fingerprinter.process_packet(packet)

    assert len(fingerprinter._quic_dcids) <= 4


def _quic_client_initial(src_port, seconds):
    """Return one QUIC client Initial packet that names a connection identifier."""
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=src_port, dport=443)
    # A long-header Initial packet with a four-byte destination connection ID.
    packet = packet / Raw(load=b"\xc0\x00\x00\x00\x01\x04\xaa\xbb\xcc\xdd\x00" + b"\x00" * 40)
    packet.time = seconds
    return packet


def test_the_ja4s_connection_identifier_table_evicts_an_entry_past_the_maximum_age():
    """A connection whose client Initial packet ages out leaves the DCID table."""
    fingerprinter = JA4SFingerprinter()
    fingerprinter._quic_dcids.max_connection_age = 60
    fingerprinter._quic_dcids.eviction_interval = 1

    fingerprinter.process_packet(_quic_client_initial(50000, 1000.0))
    assert len(fingerprinter._quic_dcids) == 1

    fingerprinter.process_packet(_quic_client_initial(50001, 1100.0))

    assert "10.0.0.1:50000-10.0.0.2:443" not in fingerprinter._quic_dcids
    assert len(fingerprinter._quic_dcids) == 1


def test_the_ja4l_grouping_key_table_evicts_an_entry_past_the_maximum_age():
    """A connection that receives no packet for longer than the age leaves the map."""
    fingerprinter = JA4LFingerprinter()
    fingerprinter.grouping_keys.max_connection_age = 60
    fingerprinter.grouping_keys.eviction_interval = 1

    fingerprinter.process_packet(_tcp("10.0.0.1", 50000, "10.0.0.2", 443, "S", 1000.0))
    assert len(fingerprinter.grouping_keys) == 1

    fingerprinter.process_packet(_tcp("10.0.0.3", 50001, "10.0.0.4", 443, "S", 1100.0))

    assert len(fingerprinter.grouping_keys) == 1


def _tls_segment(client_port, seconds, seq=1):
    """Return one TCP packet whose payload starts a TLS record and holds no request."""
    payload = b"\x16\x03\x03\x00\x20" + b"\x00" * 32
    return _tcp("10.0.0.1", client_port, "10.0.0.2", 443, "PA", seconds, seq=seq, payload=payload)


def test_the_ja4x_scan_offset_table_evicts_an_entry_past_the_maximum_age():
    """A stream that receives no segment for longer than the age leaves the map."""
    fingerprinter = JA4XFingerprinter()
    fingerprinter.scan_offsets.max_connection_age = 60
    fingerprinter.scan_offsets.eviction_interval = 1

    fingerprinter.process_packet(_tls_segment(50000, 1000.0))
    assert len(fingerprinter.scan_offsets) == 1

    fingerprinter.process_packet(_tls_segment(50001, 1100.0))

    assert "10.0.0.1:50000-10.0.0.2:443" not in fingerprinter.scan_offsets
    assert len(fingerprinter.scan_offsets) == 1


def _unusable_segment(client_port, seconds, seq=1):
    """Return one TCP packet whose payload starts no HTTP request."""
    return _tcp("10.0.0.1", client_port, "10.0.0.2", 80, "PA", seconds, seq=seq, payload=b"zzzz")


def test_the_ja4h_waiting_stream_table_evicts_an_entry_past_the_maximum_age():
    """A stream that waits and then goes quiet leaves the waiting-stream table."""
    fingerprinter = JA4HFingerprinter()
    fingerprinter.unusable_base.max_connection_age = 60
    fingerprinter.unusable_base.eviction_interval = 1

    fingerprinter.process_packet(_unusable_segment(50000, 1000.0))
    assert len(fingerprinter.unusable_base) == 1

    fingerprinter.process_packet(_unusable_segment(50001, 1100.0))

    assert "10.0.0.1:50000-10.0.0.2:80" not in fingerprinter.unusable_base
    assert len(fingerprinter.unusable_base) == 1


def _http_request(client_port, seconds, seq=1, body=b""):
    """Return one packet that carries a whole HTTP request."""
    request = b"GET /a HTTP/1.1\r\nHost: e.com\r\nUser-Agent: t\r\n\r\n" + body
    return _tcp("10.0.0.1", client_port, "10.0.0.2", 80, "PA", seconds, seq=seq, payload=request)


def test_the_ja4h_consumed_request_table_holds_its_entry_count():
    """A flood of HTTP connections leaves the consumed-request table at its count."""
    fingerprinter = JA4HFingerprinter()
    fingerprinter.consumed_seq.max_connections = 4

    for port in range(50000, 50020):
        fingerprinter.process_packet(_http_request(port, 1000.0))

    assert len(fingerprinter.consumed_seq) == 4


def test_ja4h_reads_two_requests_of_a_connection_whose_span_passes_the_maximum_age():
    """Two requests 1000 seconds apart both produce a value.

    The gap is above no bound this fingerprinter holds, because the maximum age of the
    consumed-request table is 600 seconds and the entry it evicts holds no value the
    second request needs.
    """
    fingerprinter = JA4HFingerprinter()
    fingerprinter.consumed_seq.eviction_interval = 1

    first = fingerprinter.process_packet(_http_request(50000, 1000.0, seq=1))
    second = fingerprinter.process_packet(_http_request(50000, 2000.0, seq=1000))

    assert first is not None
    assert second is not None
    assert len(fingerprinter.get_fingerprints()) == 2


def test_the_synack_table_holds_its_entry_count():
    """A flood of SYN-ACK packets leaves the JA4TS table at the count it states."""
    tracker = SynAckTracker()
    tracker.times.max_connections = 4

    for port in range(50000, 50020):
        tracker.record(f"10.0.0.2:443-10.0.0.1:{port}", 1000.0, "64240_2_1460_0")

    assert len(tracker.times) == 4


def test_the_synack_table_evicts_a_connection_that_passes_the_maximum_age():
    """A connection whose last SYN-ACK is older than the age leaves the table."""
    tracker = SynAckTracker()
    tracker.times.max_connection_age = 60
    tracker.times.eviction_interval = 1

    tracker.record("first", 1000.0, "64240_2_1460_0")
    tracker.record("second", 1100.0, "64240_2_1460_0")

    assert "first" not in tracker.times
    assert "second" in tracker.times


def _connection_traffic(index, second):
    """Return the packets of one connection, each with its own capture timestamp."""
    client = f"10.{(index >> 16) & 0xFF}.{(index >> 8) & 0xFF}.{index & 0xFF}"
    port = 20000 + (index % 40000)
    http = b"GET /a HTTP/1.1\r\nHost: e.com\r\nUser-Agent: t\r\n\r\n"
    ssh = b"\x00\x00\x00\x20\x0a" + b"z" * 27
    tls = b"\x16\x03\x03\x00\x20" + b"\x00" * 32
    quic = b"\xc0\x00\x00\x00\x01\x04\xaa\xbb\xcc\xdd\x00" + b"\x00" * 40
    built = [
        _tcp(client, port, "10.9.9.9", 22, "S", second),
        _tcp("10.9.9.9", 22, client, port, "SA", second),
        _tcp(client, port, "10.9.9.9", 22, "PA", second, payload=ssh),
        _tcp(client, port, "10.9.9.9", 80, "PA", second, payload=http),
        _tcp(client, port, "10.9.9.9", 443, "PA", second, payload=tls),
        IP(src=client, dst="10.9.9.9") / UDP(sport=port, dport=443) / Raw(load=quic),
    ]
    built[-1].time = second
    return built


def test_no_state_table_passes_its_entry_count_under_a_flood_of_connections():
    """A flood of 2000 connections leaves every table at or below its entry count.

    The traffic reaches every stateful method, so each table of the processor builds
    entries. The case reads the entry count of each table against the bound that table
    states, which is FR-concurrency-safety-7.
    """
    from ja4plus.processor import Processor

    processor = Processor()
    for index in range(2000):
        for packet in _connection_traffic(index, 1000.0 + index * 0.1):
            processor.process_packet(packet)

    counted = 0
    for name, fingerprinter in processor.fingerprinters.items():
        holders = [fingerprinter, getattr(fingerprinter, "syn_ack_times", None)]
        for holder in holders:
            if holder is None:
                continue
            for attribute, table in vars(holder).items():
                if isinstance(table, BoundedStateTable):
                    counted += 1
                    assert len(table) <= table.max_connections, f"{name}.{attribute}"

    # The processor holds ten fingerprinters and fifteen bounded tables, so the loop
    # reads every table rather than nothing. #285 added the fourteenth,
    # `SynAckTracker.prefixes`, and #215 added the fifteenth, `JA4TFingerprinter
    # .connections`.
    assert counted == 15


def test_the_ja4t_connection_table_holds_its_entry_count():
    """A flood of connections leaves the JA4T table at the count the caller states."""
    fingerprinter = JA4TFingerprinter()
    fingerprinter.connections.max_connections = 4

    for port in range(50000, 50020):
        fingerprinter.process_packet(_tcp("10.0.0.1", port, "10.0.0.2", 443, "S", 1000.0))

    assert len(fingerprinter.connections) == 4


def test_the_ja4t_connection_table_evicts_an_entry_that_passes_the_maximum_age():
    """A connection that receives no packet for longer than the age leaves the table."""
    fingerprinter = JA4TFingerprinter()
    fingerprinter.connections.max_connection_age = 60
    fingerprinter.connections.eviction_interval = 1

    fingerprinter.process_packet(_tcp("10.0.0.1", 50000, "10.0.0.2", 443, "S", 1000.0))
    assert len(fingerprinter.connections) == 1

    fingerprinter.process_packet(_tcp("10.0.0.3", 50001, "10.0.0.4", 443, "S", 1100.0))

    assert len(fingerprinter.connections) == 1
    assert ("10.0.0.1", 50000, "10.0.0.2", 443) not in fingerprinter.connections


def test_ja4t_reads_one_syn_of_a_connection_whose_span_passes_the_maximum_age():
    """A connection that repeats its SYN across 1000 seconds still holds one value.

    Each gap is 500 seconds and the maximum age is 600 seconds, so the entry survives
    every gap and the second SYN and the third SYN produce nothing.
    """
    fingerprinter = JA4TFingerprinter()
    fingerprinter.connections.eviction_interval = 1

    first = fingerprinter.process_packet(_tcp("10.0.0.1", 50000, "10.0.0.2", 443, "S", 1000.0))
    second = fingerprinter.process_packet(_tcp("10.0.0.1", 50000, "10.0.0.2", 443, "S", 1500.0))
    third = fingerprinter.process_packet(_tcp("10.0.0.1", 50000, "10.0.0.2", 443, "S", 2000.0))

    assert first is not None
    assert second is None
    assert third is None


def test_ja4ts_reads_two_synack_packets_whose_gap_stays_inside_the_maximum_age():
    """Part e reports the delay of a retransmission that arrives 100 seconds later.

    The maximum age of the table is 120 seconds, so the entry survives the gap.
    """
    fingerprinter = JA4TSFingerprinter()

    first = _tcp("10.0.0.2", 443, "10.0.0.1", 50000, "SA", 1000.0)
    second = _tcp("10.0.0.2", 443, "10.0.0.1", 50000, "SA", 1100.0)

    fingerprinter.process_packet(first)
    value = fingerprinter.process_packet(second)

    assert value is not None
    assert value.endswith("_100")
