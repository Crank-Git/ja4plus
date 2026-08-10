"""JA4SSH decides which endpoint is the server, and it records how it decided.

`docs/specs/features/02-correctness-audit.md` row 12 records the defect. On a
non-standard port the lower port number decided, which is arbitrary when both endpoints
use an ephemeral port.

The order is: an endpoint on port 22 decides, else the TCP handshake decides, else the
lower port decides and the fingerprinter records the guess.

Every test that reads the handshake places the client on the LOWER port. The lower-port
fallback then names the client as the server, so the test fails when the fingerprinter
falls back instead of reading the handshake.
"""

import pytest
from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4ssh import (
    MAX_HANDSHAKE_CONNECTIONS,
    JA4SSHFingerprinter,
)

BANNER = b"SSH-2.0-OpenSSH_8.9\r\n"

# The client uses the lower port, so the lower-port fallback names it the server. A
# test that reads the handshake therefore cannot pass through the fallback.
CLIENT = ("10.0.0.1", 2000)
SERVER = ("10.0.0.2", 3000)


def syn(source, destination):
    """Return the SYN packet that opens one connection."""
    return IP(src=source[0], dst=destination[0]) / TCP(
        sport=source[1], dport=destination[1], flags="S"
    )


def syn_ack(source, destination):
    """Return the SYN+ACK packet that accepts one connection."""
    return IP(src=source[0], dst=destination[0]) / TCP(
        sport=source[1], dport=destination[1], flags="SA"
    )


def banner(source, destination, payload=BANNER):
    """Return one packet that carries an SSH banner."""
    return (
        IP(src=source[0], dst=destination[0])
        / TCP(sport=source[1], dport=destination[1], flags="PA")
        / Raw(load=payload)
    )


def one_connection(fingerprinter):
    """Return the one connection the fingerprinter holds.

    Args:
        fingerprinter: One JA4SSH fingerprinter.

    Returns:
        The connection dictionary.
    """
    assert len(fingerprinter.connections) == 1, (
        f"the fingerprinter holds {len(fingerprinter.connections)} connections"
    )
    return list(fingerprinter.connections.values())[0]


def test_the_syn_sender_is_the_client_when_no_endpoint_uses_port_22():
    """The SYN sender is the client, and the lower port does not decide.

    The client uses port 2000 and the server uses port 3000, so the lower-port fallback
    names the client as the server. This test fails when the fingerprinter falls back.
    """
    fingerprinter = JA4SSHFingerprinter(packet_count=1)
    fingerprinter.process_packet(syn(CLIENT, SERVER))
    fingerprinter.process_packet(syn_ack(SERVER, CLIENT))
    fingerprinter.process_packet(banner(SERVER, CLIENT))

    conn = one_connection(fingerprinter)
    assert conn["client_ip"] == CLIENT[0], "the SYN sender must be the client"
    assert conn["client_port"] == CLIENT[1]
    assert conn["server_ip"] == SERVER[0], "the SYN receiver must be the server"
    assert conn["server_port"] == SERVER[1]
    assert conn["server_decided_by"] == "handshake"


def test_the_syn_ack_sender_is_the_server_when_the_capture_holds_no_syn():
    """The SYN+ACK sender is the server when the capture starts after the SYN.

    A capture that starts inside a connection holds no SYN. The SYN+ACK names the same
    two endpoints, so the fingerprinter reads it instead of the lower port.
    """
    fingerprinter = JA4SSHFingerprinter(packet_count=1)
    fingerprinter.process_packet(syn_ack(SERVER, CLIENT))
    fingerprinter.process_packet(banner(SERVER, CLIENT))

    conn = one_connection(fingerprinter)
    assert conn["client_ip"] == CLIENT[0]
    assert conn["server_ip"] == SERVER[0]
    assert conn["server_decided_by"] == "handshake"


def test_the_lower_port_decides_when_the_capture_holds_no_handshake():
    """The lower port decides when the capture holds no SYN and no SYN+ACK.

    The fingerprinter records the guess, because the lower port is arbitrary when both
    endpoints use an ephemeral port.
    """
    fingerprinter = JA4SSHFingerprinter(packet_count=1)
    fingerprinter.process_packet(banner(SERVER, CLIENT))

    conn = one_connection(fingerprinter)
    # The lower port is 2000, so the fallback names `10.0.0.1` the server.
    assert conn["server_ip"] == CLIENT[0]
    assert conn["server_decided_by"] == "guess"


def test_an_endpoint_on_port_22_decides_before_the_handshake():
    """Port 22 decides which endpoint is the server, and the handshake does not.

    FoxIO tracks a connection for JA4SSH only when one endpoint uses port 22, so the
    port carries more weight than the handshake. A capture that records a SYN from the
    endpoint on port 22 does not move the server to the other endpoint.
    """
    on_port_22 = ("10.0.0.2", 22)
    other = ("10.0.0.1", 50000)
    fingerprinter = JA4SSHFingerprinter(packet_count=1)
    fingerprinter.process_packet(syn(on_port_22, other))
    fingerprinter.process_packet(banner(other, on_port_22))

    conn = one_connection(fingerprinter)
    assert conn["server_ip"] == on_port_22[0], "port 22 must decide"
    assert conn["server_port"] == 22
    assert conn["server_decided_by"] == "port"


@pytest.mark.parametrize(
    ("description", "packets", "expected"),
    [
        ("a handshake", [syn(CLIENT, SERVER), banner(SERVER, CLIENT)], "handshake"),
        ("no handshake", [banner(SERVER, CLIENT)], "guess"),
    ],
    ids=["a handshake", "no handshake"],
)
def test_the_fingerprint_entry_records_how_the_server_was_decided(description, packets, expected):
    """Every JA4SSH entry names the rule that named the server.

    A consumer reads a measured side and a guessed side differently, so the source
    reaches the result and not only a log line.
    """
    fingerprinter = JA4SSHFingerprinter(packet_count=1)
    for packet in packets:
        fingerprinter.process_packet(packet)

    entries = fingerprinter.get_fingerprints()
    assert entries, f"{description} produced no JA4SSH value"
    assert entries[0]["server_decided_by"] == expected


def test_the_handshake_table_holds_no_more_than_its_maximum_entry_count():
    """The handshake table holds a bounded number of connections.

    A monitor reads a SYN for every TCP connection on the wire, and few of them carry
    SSH. `CLAUDE.md` states that a state table has a maximum entry count.
    """
    fingerprinter = JA4SSHFingerprinter()
    for index in range(MAX_HANDSHAKE_CONNECTIONS * 2):
        source = (f"10.1.{index // 250}.{index % 250}", 2000)
        fingerprinter.process_packet(syn(source, SERVER))
    assert len(fingerprinter._handshake_clients) <= MAX_HANDSHAKE_CONNECTIONS


def test_the_handshake_table_forgets_a_connection_the_processor_cleans_up():
    """`cleanup_connection` removes the handshake entry beside the connection."""
    fingerprinter = JA4SSHFingerprinter(packet_count=1)
    fingerprinter.process_packet(syn(CLIENT, SERVER))
    assert fingerprinter._handshake_clients, "the SYN recorded no handshake"
    fingerprinter.cleanup_connection(CLIENT[0], CLIENT[1], SERVER[0], SERVER[1], "tcp")
    assert fingerprinter._handshake_clients == {}


@pytest.mark.parametrize(
    ("description", "flags"),
    [("a SYN and a RST", "SR"), ("a SYN, an ACK and a RST", "SAR")],
    ids=["a SYN and a RST", "a SYN, an ACK and a RST"],
)
def test_a_packet_that_carries_the_rst_flag_names_no_endpoint(description, flags):
    """A packet that carries the RST flag opens no connection and accepts none.

    Every packet is hostile input. A sender that sets the SYN flag and the RST flag
    together would otherwise name the client of a connection it never opened, and the
    next connection on that endpoint pair would read the planted name.
    """
    fingerprinter = JA4SSHFingerprinter(packet_count=1)
    hostile = IP(src=SERVER[0], dst=CLIENT[0]) / TCP(sport=SERVER[1], dport=CLIENT[1], flags=flags)
    fingerprinter.process_packet(hostile)
    assert fingerprinter._handshake_clients == {}, f"{description} named an endpoint"


def test_one_reader_of_the_tcp_handshake_serves_both_fingerprinters():
    """JA4L and JA4SSH read the TCP handshake through one function.

    Two readers of one handshake that disagree would name two different clients for one
    connection.
    """
    from ja4plus.fingerprinters import ja4l
    from ja4plus.utils.packet_utils import opens_a_connection

    assert ja4l._opens_a_connection is opens_a_connection
