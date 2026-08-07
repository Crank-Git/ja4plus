"""Tests for what JA4SSH does after the first window closes.

#28 set the window to 200 SSH packets. A capture that holds one window conforms after
that change, and a capture that holds several does not. This module covers the bare-ACK
rule that a long connection needs, and the window a connection holds open when it
closes.

1. A bare ACK is one packet that carries the ACK flag alone and no payload. FoxIO counts
   one only when the TCP flags equal `0x0010`, so a SYN+ACK, a FIN+ACK and a RST+ACK are
   not bare ACKs.
2. The ACK of the TCP handshake is a bare ACK, and it arrives before the first SSH
   packet of the connection. FoxIO counts it.
3. A connection that closes emits no value for the window it holds open. #92 owns the
   condition FoxIO applies, which the vectors do not settle.

The FoxIO reference states rule 1 and rule 2 in `python/ja4ssh.py`.

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4ssh.py
(retrieved 2026-08-06).
Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/python/test/testdata
(retrieved 2026-08-06).
"""

import json
import struct
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
CLIENT_PORT = 50000
SERVER_PORT = 22

VECTORS = Path(__file__).parent / "foxio_vectors"


def ssh_packet(to_server=True, size=36):
    """Return one SSH data packet of the given payload size.

    Args:
        to_server: True for a client packet, False for a server packet.
        size: The payload length in bytes. The minimum is 6.

    Returns:
        A scapy packet that `is_ssh_packet` accepts.
    """
    payload = struct.pack(">I", size - 4) + bytes([4, 94]) + b"A" * (size - 6)
    return _tcp(to_server, "PA") / Raw(load=payload)


def _tcp(to_server, flags):
    """Return one TCP packet of the given direction and flags, with no payload."""
    if to_server:
        return IP(src=CLIENT, dst=SERVER) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags=flags)
    return IP(src=SERVER, dst=CLIENT) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags=flags)


def handshake(fingerprinter):
    """Send the three packets of the TCP handshake to the fingerprinter."""
    fingerprinter.process_packet(_tcp(True, "S"))
    fingerprinter.process_packet(_tcp(False, "SA"))
    fingerprinter.process_packet(_tcp(True, "A"))


def fill_window(fingerprinter, count=200):
    """Send `count` SSH packets, one direction after the other."""
    result = None
    for index in range(count):
        result = fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0))
    return result


# ---------------------------------------------------------------------------
# The bare ACK
# ---------------------------------------------------------------------------


def test_the_window_counts_the_ack_of_the_tcp_handshake():
    """FoxIO counts every bare ACK on a port-22 connection, including the third
    packet of the TCP handshake, which arrives before the first SSH packet."""
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    assert fill_window(fingerprinter) == "c36s36_c100s100_c1s0"


def test_a_syn_ack_is_not_a_bare_ack():
    fingerprinter = JA4SSHFingerprinter()
    fingerprinter.process_packet(_tcp(True, "S"))
    fingerprinter.process_packet(_tcp(False, "SA"))
    assert fill_window(fingerprinter) == "c36s36_c100s100_c0s0"


def test_a_fin_ack_is_not_a_bare_ack():
    """The FIN+ACK arrives while the window is empty, so the close rule emits nothing
    and the server ACK counter stays at zero."""
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    assert fingerprinter.process_packet(_tcp(False, "FA")) is None
    assert fill_window(fingerprinter) == "c36s36_c100s100_c1s0"


def test_a_reset_packet_is_not_a_bare_ack():
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    fingerprinter.process_packet(_tcp(False, "RA"))
    assert fill_window(fingerprinter) == "c36s36_c100s100_c1s0"


def test_a_bare_ack_alone_emits_no_fingerprint():
    """A port scan that sends bare ACKs holds no SSH packet, and it emits nothing."""
    fingerprinter = JA4SSHFingerprinter()
    for _ in range(500):
        assert fingerprinter.process_packet(_tcp(True, "A")) is None
    assert fingerprinter.get_fingerprints() == []


# ---------------------------------------------------------------------------
# The close of the connection
# ---------------------------------------------------------------------------


def test_a_connection_that_closes_emits_no_partial_window():
    """FoxIO holds no JA4SSH value for `gre-sample.pcap`, `sshv1.pcap` and `v6.pcap`.
    Each of those captures holds one SSH connection that carries a banner, data packets
    and a FIN packet, and each fills no window. A rule that emits the open window on a
    FIN packet gives all three a value the reference does not hold. #92 owns the
    condition FoxIO applies."""
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    for index in range(11):
        assert fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0)) is None
    assert fingerprinter.process_packet(_tcp(True, "FA")) is None
    assert fingerprinter.process_packet(_tcp(False, "FA")) is None
    assert fingerprinter.get_fingerprints() == []


# ---------------------------------------------------------------------------
# The FoxIO vectors
# ---------------------------------------------------------------------------


def produced(name):
    """Return the JA4SSH values of one capture, grouped by connection key."""
    from scapy.all import rdpcap

    fingerprinter = JA4SSHFingerprinter()
    for packet in rdpcap(str(VECTORS / name)):
        fingerprinter.process_packet(packet)
    values = {}
    for entry in fingerprinter.get_fingerprints():
        values.setdefault(entry["connection"], []).append(entry["fingerprint"])
    return values


def expected(name):
    """Return the JA4SSH occurrence keys of one expected-output file, by source port."""
    with open(VECTORS / (name + ".json")) as handle:
        records = json.load(handle)
    values = {}
    for record in records:
        for key in sorted(record):
            if key.startswith("JA4SSH."):
                port = record["srcport"] if record["dstport"] == "22" else record["dstport"]
                values.setdefault(port, []).append(record[key])
    return values


def vector(name):
    """Skip the test when the capture or its expected-output file is absent."""
    return pytest.mark.skipif(
        not (VECTORS / name).exists() or not (VECTORS / (name + ".json")).exists(),
        reason="the FoxIO vector {} is not available".format(name),
    )


@vector("ssh.pcapng")
def test_the_one_window_vector_keeps_its_value():
    """`ssh.pcapng` conforms after #28, and the bare-ACK rule must not disturb it."""
    values = produced("ssh.pcapng")
    assert list(values.values()) == [["c36s36_c76s124_c0s0"]]


@vector("ssh-r.pcap")
def test_the_reverse_ssh_vector_produces_the_reference_first_window():
    values = produced("ssh-r.pcap")
    first = values["192.168.1.169:64980-192.168.1.197:22"][0]
    assert first == expected("ssh-r.pcap")["64980"][0]
    assert first == "c64s64_c107s93_c74s10"


@vector("ssh-scp-1050.pcap")
def test_the_file_transfer_vector_produces_the_reference_ack_count():
    values = produced("ssh-scp-1050.pcap")["192.168.1.169:49237-192.168.1.197:22"]
    reference = expected("ssh-scp-1050.pcap")["49237"]
    assert len(values) == len(reference) == 4
    assert values[0] == reference[0] == "c112s1460_c52s148_c41s4"
    assert values[1] == reference[1] == "c112s1460_c13s187_c35s0"


@vector("ssh-scp-1050.pcap")
def test_a_capture_that_holds_no_fin_packet_emits_no_extra_window():
    """`ssh-scp-1050.pcap` never closes its connection, so it keeps four windows."""
    values = produced("ssh-scp-1050.pcap")
    assert [len(item) for item in values.values()] == [4]


@vector("ssh2.pcapng")
def test_the_long_capture_produces_the_reference_first_window():
    values = produced("ssh2.pcapng")["172.16.225.48:57377-54.160.114.75:22"]
    assert values[0] == expected("ssh2.pcapng")["57377"][0]
    assert values[0] == "c36s36_c76s124_c74s5"
