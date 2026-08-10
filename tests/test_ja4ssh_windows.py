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
3. A connection that closes emits the window it holds open, and an empty window emits
   nothing.
4. The end of the capture emits the window every connection still holds open. #214
   decided it, because `ssh2.pcapng` carries no FIN+ACK packet on port 22 and two FoxIO
   references hold the trailing value.

The FoxIO reference states rule 1 and rule 2 in `python/ja4ssh.py`. It states rule 3
above `finalize_ja4ssh` in `python/ja4.py`: `If the SSH connection is not terminated or
the last sample is less than 200 the finalize function just cleans up and prints the
last JA4SSH hash`. It states no rule for rule 4, and `docs/specs/foxio/JA4SSH.md` holds
that reading under R11.

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


def closed(fingerprinter):
    """Return the fingerprint of every window the end of the capture emits."""
    return [entry["fingerprint"] for entry in fingerprinter.close_open_windows()]


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


def test_the_connection_close_emits_the_open_window():
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    for index in range(11):
        assert fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0)) is None
    assert fingerprinter.process_packet(_tcp(True, "FA")) == "c36s36_c6s5_c1s0"
    assert len(fingerprinter.get_fingerprints()) == 1


def test_the_connection_close_emits_the_window_that_follows_a_full_window():
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    fill_window(fingerprinter)
    for index in range(4):
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0))
    assert fingerprinter.process_packet(_tcp(True, "FA")) == "c36s36_c2s2_c0s0"
    values = [entry["fingerprint"] for entry in fingerprinter.get_fingerprints()]
    assert values == ["c36s36_c100s100_c1s0", "c36s36_c2s2_c0s0"]


def test_the_connection_close_emits_nothing_when_the_open_window_holds_no_ssh_packet():
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    fill_window(fingerprinter)
    assert fingerprinter.process_packet(_tcp(True, "FA")) is None
    assert len(fingerprinter.get_fingerprints()) == 1


def test_two_fin_packets_emit_one_fingerprint():
    """Both endpoints close the connection. The second FIN packet finds an empty
    window, and an empty window emits nothing."""
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    for index in range(11):
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0))
    assert fingerprinter.process_packet(_tcp(True, "FA")) == "c36s36_c6s5_c1s0"
    assert fingerprinter.process_packet(_tcp(False, "FA")) is None
    assert len(fingerprinter.get_fingerprints()) == 1


def test_a_reset_packet_leaves_the_window_open():
    """FoxIO closes the window on the FIN flag and the ACK flag, and it reads no other
    flag. A connection that a RST packet ends keeps its window open."""
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    for index in range(11):
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0))
    assert fingerprinter.process_packet(_tcp(True, "R")) is None
    assert fingerprinter.process_packet(_tcp(True, "RA")) is None
    assert fingerprinter.get_fingerprints() == []


def test_a_fin_packet_on_an_unknown_connection_emits_nothing():
    fingerprinter = JA4SSHFingerprinter()
    assert fingerprinter.process_packet(_tcp(True, "FA")) is None
    assert fingerprinter.get_fingerprints() == []


def test_a_connection_the_reference_indexes_as_stream_zero_emits_its_open_window():
    """`finalize_ja4ssh` guards with `if stream:`, and the stream index 0 is false in
    Python, so the reference emits no trailing window for the connection it indexes as
    stream 0. `gre-sample.pcap`, `sshv1.pcap` and `v6.pcap` each hold their SSH
    connection at that index. The stream index describes the position of a connection
    in a capture and not the connection, so ja4plus emits the window. #105 records the
    divergence."""
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    for index in range(8):
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0))
    assert fingerprinter.process_packet(_tcp(True, "FA")) == "c36s36_c4s4_c1s0"


# ---------------------------------------------------------------------------
# The end of the capture
# ---------------------------------------------------------------------------


def test_the_end_of_the_capture_emits_the_open_window():
    """No FIN packet reaches this connection, so only the end of the capture emits it."""
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    for index in range(11):
        assert fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0)) is None
    assert closed(fingerprinter) == ["c36s36_c6s5_c1s0"]
    values = [entry["fingerprint"] for entry in fingerprinter.get_fingerprints()]
    assert values == ["c36s36_c6s5_c1s0"]


def test_the_end_of_the_capture_emits_the_window_that_follows_a_full_window():
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    fill_window(fingerprinter)
    for index in range(4):
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0))
    assert closed(fingerprinter) == ["c36s36_c2s2_c0s0"]
    values = [entry["fingerprint"] for entry in fingerprinter.get_fingerprints()]
    assert values == ["c36s36_c100s100_c1s0", "c36s36_c2s2_c0s0"]


def test_the_end_of_the_capture_emits_nothing_when_the_open_window_holds_no_ssh_packet():
    """#97 declines a fingerprint whose window holds no SSH packet, and the end of the
    capture must not resurrect it. The window that follows a full window holds none."""
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    fill_window(fingerprinter)
    assert closed(fingerprinter) == []
    assert len(fingerprinter.get_fingerprints()) == 1


def test_the_end_of_the_capture_emits_nothing_for_a_connection_of_bare_acks_alone():
    """A port scan builds a connection that holds no SSH packet. #97 declines the value
    `c0s0` that such a window would carry."""
    fingerprinter = JA4SSHFingerprinter()
    for _ in range(500):
        fingerprinter.process_packet(_tcp(True, "A"))
    assert fingerprinter.connections
    assert closed(fingerprinter) == []
    assert fingerprinter.get_fingerprints() == []


def test_the_end_of_the_capture_emits_nothing_after_the_connection_closes():
    """The FIN+ACK packet already emitted the window, so the end of the capture finds
    an empty window and emits no second value."""
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    for index in range(11):
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0))
    assert fingerprinter.process_packet(_tcp(True, "FA")) == "c36s36_c6s5_c1s0"
    assert closed(fingerprinter) == []
    assert len(fingerprinter.get_fingerprints()) == 1


def test_the_end_of_the_capture_emits_the_window_a_reset_packet_left_open():
    """A RST packet closes no window, and the end of the capture emits what it left."""
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    for index in range(11):
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0))
    assert fingerprinter.process_packet(_tcp(True, "RA")) is None
    assert closed(fingerprinter) == ["c36s36_c6s5_c1s0"]


def test_the_end_of_the_capture_emits_one_window_for_each_connection():
    """Two connections each hold a window open, and the order follows the state table."""
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    for index in range(11):
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0))
    second = IP(src="10.0.0.3", dst=SERVER) / TCP(sport=50001, dport=SERVER_PORT, flags="PA")
    payload = struct.pack(">I", 60) + bytes([4, 94]) + b"A" * 58
    fingerprinter.process_packet(second / Raw(load=payload))
    assert closed(fingerprinter) == ["c36s36_c6s5_c1s0", "c64s0_c1s0_c0s0"]


def test_a_second_call_at_the_end_of_the_capture_emits_nothing():
    """`_close_window` clears the counters, so a repeated call writes no second value."""
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    for index in range(11):
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0))
    assert closed(fingerprinter) == ["c36s36_c6s5_c1s0"]
    assert closed(fingerprinter) == []
    assert len(fingerprinter.get_fingerprints()) == 1


def test_the_end_of_the_capture_holds_no_connection_longer():
    """The method emits the open window and evicts no entry, so the state table holds
    the same keys before the call and after it. #179 owns the bound on that table."""
    fingerprinter = JA4SSHFingerprinter()
    handshake(fingerprinter)
    for index in range(11):
        fingerprinter.process_packet(ssh_packet(to_server=index % 2 == 0))
    before = set(fingerprinter.connections)
    fingerprinter.close_open_windows()
    assert set(fingerprinter.connections) == before


def test_every_fingerprinter_answers_the_end_of_the_capture():
    """The processor calls the method on every fingerprinter, so the base class holds
    it. Only JA4SSH holds a window, so every other method returns an empty list."""
    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    assert JA4Fingerprinter().close_open_windows() == []


# ---------------------------------------------------------------------------
# The FoxIO vectors
# ---------------------------------------------------------------------------


def produced(name):
    """Return the JA4SSH values of one capture, grouped by connection key.

    The helper closes the open windows at the end of the capture, as every caller in
    this project does.
    """
    from scapy.all import rdpcap

    fingerprinter = JA4SSHFingerprinter()
    for packet in rdpcap(str(VECTORS / name)):
        fingerprinter.process_packet(packet)
    fingerprinter.close_open_windows()
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
def test_the_one_window_vector_keeps_its_reference_value():
    """`ssh.pcapng` conforms after #28, and the bare-ACK rule must not disturb it. The
    capture holds the same connection as `ssh2.pcapng` and it carries no FIN+ACK packet
    either, so #214 adds the trailing window to it."""
    values = produced("ssh.pcapng")
    assert list(values.values()) == [["c36s36_c76s124_c0s0", "c36s52_c42s76_c0s0"]]
    assert values["172.16.225.48:57377-54.160.114.75:22"][0] == expected("ssh.pcapng")["57377"][0]


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
    assert len(reference) == 4
    assert values[0] == reference[0] == "c112s1460_c52s148_c41s4"
    assert values[1] == reference[1] == "c112s1460_c13s187_c35s0"


@vector("ssh-scp-1050.pcap")
def test_a_capture_that_holds_no_fin_packet_emits_the_trailing_window():
    """`ssh-scp-1050.pcap` never closes its connection, so it holds a fifth window open
    when the capture ends. #214 decided that this project emits that window, and the
    register holds the divergence from the FoxIO Python reference."""
    values = produced("ssh-scp-1050.pcap")["192.168.1.169:49237-192.168.1.197:22"]
    assert len(values) == 5
    assert values[4] == "c0s1460_c0s53_c6s0"


@vector("ssh2.pcapng")
def test_the_long_capture_produces_the_reference_first_window():
    values = produced("ssh2.pcapng")["172.16.225.48:57377-54.160.114.75:22"]
    assert values[0] == expected("ssh2.pcapng")["57377"][0]
    assert values[0] == "c36s36_c76s124_c74s5"


@vector("ssh2.pcapng")
def test_the_long_capture_produces_the_rust_and_zeek_trailing_window():
    """`ssh2.pcapng` carries no FIN+ACK packet on port 22, so the connection holds its
    last window open when the capture ends. `tests/foxio_vectors/rust_expected/
    ja4__insta@ssh2.pcapng.snap` and the Zeek baseline both hold this value. #214
    decided that this project emits it."""
    values = produced("ssh2.pcapng")["172.16.225.48:57377-54.160.114.75:22"]
    assert values == ["c36s36_c76s124_c74s5", "c36s52_c42s76_c51s2"]


@vector("ssh2.pcapng")
def test_the_long_capture_produces_no_declined_empty_window():
    """The FoxIO Python second value is `c36s36_c0s0_c2s0`, which #97 declines. The
    trailing window must not reproduce it."""
    values = produced("ssh2.pcapng")["172.16.225.48:57377-54.160.114.75:22"]
    assert "c36s36_c0s0_c2s0" not in values
