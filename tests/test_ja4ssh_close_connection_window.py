"""Tests for `JA4SSHFingerprinter.close_connection_window`.

A long-running monitor evicts one connection when that connection ends, and the
reference publishes the final window at that moment. `rust/ja4/src/ssh.rs:45-55` and
`zeek/ja4ssh/main.zeek:160-164` both emit at teardown. `cleanup_connection` emits
nothing, and `close_open_windows` reaches every connection at once, so neither one
serves one connection.

No FoxIO vector separates the two answers, because the conformance suite reads each
capture to its end and calls no eviction. These cases are the record of the ruling.
The maintainer ruled the method on `Crank-Git/ja4plus-go` issue #216, on 2026-08-12,
and `Crank-Git/ja4plus-go` pull request #263 names the interface this file reads.
"""

import struct

from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
CLIENT_PORT = 50000
SERVER_PORT = 22
SECOND_CLIENT_PORT = 50001


def ssh_packet(to_server=True, client_port=CLIENT_PORT, size=36):
    """Return one SSH data packet of the given payload size.

    Args:
        to_server: True for a client packet, False for a server packet.
        client_port: The port of the client endpoint.
        size: The payload length in bytes. The minimum is 6.

    Returns:
        A scapy packet that `is_ssh_packet` accepts.
    """
    payload = struct.pack(">I", size - 4) + bytes([4, 94]) + b"A" * (size - 6)
    if to_server:
        return (
            IP(src=CLIENT, dst=SERVER)
            / TCP(sport=client_port, dport=SERVER_PORT)
            / Raw(load=payload)
        )
    return (
        IP(src=SERVER, dst=CLIENT) / TCP(sport=SERVER_PORT, dport=client_port) / Raw(load=payload)
    )


def bare_ack(to_server=True, client_port=CLIENT_PORT):
    """Return one bare ACK packet, which carries no payload."""
    if to_server:
        return IP(src=CLIENT, dst=SERVER) / TCP(sport=client_port, dport=SERVER_PORT, flags="A")
    return IP(src=SERVER, dst=CLIENT) / TCP(sport=SERVER_PORT, dport=client_port, flags="A")


def open_a_window(fingerprinter, client_port=CLIENT_PORT, packets=10):
    """Fill part of one window, and emit no fingerprint."""
    for index in range(packets):
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0, client_port=client_port))


def test_the_method_emits_the_window_the_connection_holds_open():
    fingerprinter = JA4SSHFingerprinter()
    open_a_window(fingerprinter)

    emitted = fingerprinter.close_connection_window(CLIENT, CLIENT_PORT, SERVER, SERVER_PORT, "tcp")

    assert [entry["fingerprint"] for entry in emitted] == ["c36s36_c5s5_c0s0"]
    assert fingerprinter.get_fingerprints() == emitted


def test_the_method_removes_the_connection_it_emits():
    fingerprinter = JA4SSHFingerprinter()
    open_a_window(fingerprinter)

    fingerprinter.close_connection_window(CLIENT, CLIENT_PORT, SERVER, SERVER_PORT, "tcp")

    assert len(fingerprinter.connections) == 0


def test_the_method_reads_the_two_endpoints_in_either_order():
    fingerprinter = JA4SSHFingerprinter()
    open_a_window(fingerprinter)

    emitted = fingerprinter.close_connection_window(SERVER, SERVER_PORT, CLIENT, CLIENT_PORT, "tcp")

    assert [entry["fingerprint"] for entry in emitted] == ["c36s36_c5s5_c0s0"]
    assert len(fingerprinter.connections) == 0


def test_the_method_leaves_every_other_connection_open():
    fingerprinter = JA4SSHFingerprinter()
    open_a_window(fingerprinter)
    open_a_window(fingerprinter, client_port=SECOND_CLIENT_PORT, packets=4)

    fingerprinter.close_connection_window(CLIENT, CLIENT_PORT, SERVER, SERVER_PORT, "tcp")

    assert list(fingerprinter.connections) == [f"{CLIENT}:{SECOND_CLIENT_PORT}-{SERVER}:22"]
    assert len(fingerprinter.get_fingerprints()) == 1


def test_the_method_produces_no_value_for_a_connection_the_table_omits():
    fingerprinter = JA4SSHFingerprinter()

    emitted = fingerprinter.close_connection_window(CLIENT, CLIENT_PORT, SERVER, SERVER_PORT, "tcp")

    assert emitted == []
    assert fingerprinter.get_fingerprints() == []


def test_the_method_removes_a_connection_whose_window_holds_no_ssh_packet():
    fingerprinter = JA4SSHFingerprinter()
    for _ in range(3):
        fingerprinter.process_packet(bare_ack())

    emitted = fingerprinter.close_connection_window(CLIENT, CLIENT_PORT, SERVER, SERVER_PORT, "tcp")

    assert emitted == []
    assert fingerprinter.get_fingerprints() == []
    assert len(fingerprinter.connections) == 0


def test_a_second_call_produces_no_value():
    fingerprinter = JA4SSHFingerprinter()
    open_a_window(fingerprinter)
    fingerprinter.close_connection_window(CLIENT, CLIENT_PORT, SERVER, SERVER_PORT, "tcp")

    emitted = fingerprinter.close_connection_window(CLIENT, CLIENT_PORT, SERVER, SERVER_PORT, "tcp")

    assert emitted == []
    assert len(fingerprinter.get_fingerprints()) == 1


def test_the_method_removes_the_handshake_entry_of_the_connection():
    """The handshake table outlives the connection otherwise.

    `cleanup_connection` removes the same entry, and this method names the connection
    by the same key.
    """
    fingerprinter = JA4SSHFingerprinter()
    high_port = 2222
    fingerprinter.process_packet(
        IP(src=CLIENT, dst=SERVER) / TCP(sport=CLIENT_PORT, dport=high_port, flags="S")
    )
    assert len(fingerprinter._handshake_clients) == 1

    fingerprinter.close_connection_window(CLIENT, CLIENT_PORT, SERVER, high_port, "tcp")

    assert len(fingerprinter._handshake_clients) == 0


def test_cleanup_connection_still_emits_nothing():
    """The ruling of `Crank-Git/ja4plus-go` issue #216 keeps `cleanup_connection` silent.

    A caller that only reclaims memory receives no fingerprint it did not ask for.
    """
    fingerprinter = JA4SSHFingerprinter()
    open_a_window(fingerprinter)

    assert fingerprinter.cleanup_connection(CLIENT, CLIENT_PORT, SERVER, SERVER_PORT, "tcp") is None
    assert fingerprinter.get_fingerprints() == []
    assert len(fingerprinter.connections) == 0
