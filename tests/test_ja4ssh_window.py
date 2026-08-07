"""Tests for the JA4SSH window.

FoxIO states the interval verbatim in `technical_details/JA4SSH.png`:
`(runs every 200 SSH packets by default)`. The image lists the SSH packet counts and
the bare ACK counts as separate fields, so a bare ACK does not advance the window.

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details
(retrieved 2026-08-06).
"""

import struct
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
CLIENT_PORT = 50000
SERVER_PORT = 22

VECTOR = Path(__file__).parent / "foxio_vectors" / "ssh.pcapng"

# The reference value for `ssh.pcapng`, stream 0.
# Verified against:
# https://github.com/FoxIO-LLC/ja4/blob/main/python/test/testdata/ssh.pcapng.json
# (retrieved 2026-08-06).
SSH_PCAPNG_EXPECTED = "c36s36_c76s124_c0s0"


def ssh_packet(to_server=True, size=36):
    """Return one SSH data packet of the given payload size.

    Args:
        to_server: True for a client packet, False for a server packet.
        size: The payload length in bytes. The minimum is 6.

    Returns:
        A scapy packet that `is_ssh_packet` accepts.
    """
    payload = struct.pack(">I", size - 4) + bytes([4, 94]) + b"A" * (size - 6)
    if to_server:
        return (
            IP(src=CLIENT, dst=SERVER)
            / TCP(sport=CLIENT_PORT, dport=SERVER_PORT)
            / Raw(load=payload)
        )
    return (
        IP(src=SERVER, dst=CLIENT) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT) / Raw(load=payload)
    )


def bare_ack(to_server=True):
    """Return one bare ACK packet, which carries no payload."""
    if to_server:
        return IP(src=CLIENT, dst=SERVER) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A")
    return IP(src=SERVER, dst=CLIENT) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="A")


def test_the_default_window_emits_no_fingerprint_at_ten_packets():
    fingerprinter = JA4SSHFingerprinter()
    for index in range(10):
        assert fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0)) is None
    assert fingerprinter.get_fingerprints() == []


def test_the_default_window_emits_one_fingerprint_at_two_hundred_packets():
    fingerprinter = JA4SSHFingerprinter()
    results = [
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0)) for index in range(200)
    ]
    assert results[:199] == [None] * 199
    assert results[199] == "c36s36_c100s100_c0s0"
    assert len(fingerprinter.get_fingerprints()) == 1


def test_a_bare_ack_does_not_advance_the_window():
    fingerprinter = JA4SSHFingerprinter()
    for index in range(199):
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0))
    for _ in range(50):
        assert fingerprinter.process_packet(bare_ack()) is None
    assert fingerprinter.process_packet(ssh_packet(to_server=False)) == "c36s36_c100s100_c50s0"


def test_the_window_counters_reset_after_a_fingerprint():
    fingerprinter = JA4SSHFingerprinter()
    for index in range(200):
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0))
    for index in range(200):
        result = fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0))
    assert result == "c36s36_c100s100_c0s0"
    assert len(fingerprinter.get_fingerprints()) == 2


def test_the_caller_sets_the_window_size():
    fingerprinter = JA4SSHFingerprinter(packet_count=10)
    results = [
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0)) for index in range(10)
    ]
    assert results[:9] == [None] * 9
    assert results[9] == "c36s36_c5s5_c0s0"


def test_both_hassh_values_do_not_emit_a_fingerprint():
    """A complete key exchange fills no window. Only 200 SSH packets do."""
    fingerprinter = JA4SSHFingerprinter()
    kexinit = (
        b"\x00\x00\x05\xdc\x06\x14AAAAAAAAAASSH_MSG_KEXINIT"
        b"curve25519-sha256@libssh.org,ecdh-sha2-nistp256;"
        b"aes128-ctr,aes256-ctr;hmac-sha1,hmac-sha2-256;none"
    )
    client = (
        IP(src=CLIENT, dst=SERVER) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT) / Raw(load=kexinit)
    )
    server = (
        IP(src=SERVER, dst=CLIENT) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT) / Raw(load=kexinit)
    )
    assert fingerprinter.process_packet(client) is None
    assert fingerprinter.process_packet(server) is None
    connection = list(fingerprinter.connections.values())[0]
    assert connection["hassh"] is not None
    assert connection["hasshServer"] is not None
    assert fingerprinter.get_fingerprints() == []


@pytest.mark.skipif(not VECTOR.exists(), reason="the FoxIO vector is not available")
def test_the_ssh_vector_produces_one_fingerprint():
    from scapy.all import rdpcap

    fingerprinter = JA4SSHFingerprinter()
    for packet in rdpcap(str(VECTOR)):
        fingerprinter.process_packet(packet)

    values = [entry["fingerprint"] for entry in fingerprinter.get_fingerprints()]
    assert values == [SSH_PCAPNG_EXPECTED]
