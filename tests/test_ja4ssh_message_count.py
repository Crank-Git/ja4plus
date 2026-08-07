"""Tests for the JA4SSH SSH packet count.

The FoxIO reference counts the packets `tshark` labels `ssh`. `update_ssh_entry` reads
`has_ssh = ('ssh' in x['protos'])`, and `x['protos']` is the `frame.protocols` field of
`tshark -T ek`. `tshark` reassembles an SSH message that spans two TCP segments. It
labels the segment that completes the message, and it labels the earlier segment `tcp`.

`ssh-r.pcap` holds one such message on stream 1 and one on stream 2:

```
$ tshark -r tests/foxio_vectors/ssh-r.pcap -Y "tcp.stream==2 && tcp.len>0" \
    -T fields -e frame.number -e tcp.srcport -e tcp.len -e frame.protocols \
    -e tcp.segment -e tcp.reassembled.length
395	46396	21	eth:ethertype:ip:tcp:ssh
397	22	21	eth:ethertype:ip:tcp:ssh
399	46396	1448	eth:ethertype:ip:tcp
400	46396	48	eth:ethertype:ip:tcp:ssh	399,400	1496
```

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4ssh.py
(retrieved 2026-08-06).
"""

import struct
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter
from ja4plus.utils.ssh_utils import SSHMessageTracker

VECTORS = Path(__file__).parent / "foxio_vectors"

BANNER = b"SSH-2.0-OpenSSH_8.1\r\n"


def message(body_length=32, code=94):
    """Return one complete SSH message.

    Args:
        body_length: The value of the length field, in bytes.
        code: The message code, which follows the padding length.

    Returns:
        The message bytes, which are `body_length` plus the four length bytes.
    """
    return struct.pack(">I", body_length) + bytes([4, code]) + b"A" * (body_length - 2)


def read_vector(name):
    """Return the JA4SSH values of one vector, keyed by connection.

    Args:
        name: The file name of the vector under `tests/foxio_vectors`.

    Returns:
        A map of connection key to the list of values, in the order of emission.
    """
    from scapy.all import rdpcap

    fingerprinter = JA4SSHFingerprinter()
    for packet in rdpcap(str(VECTORS / name)):
        fingerprinter.process_packet(packet)

    values = {}
    for entry in fingerprinter.get_fingerprints():
        values.setdefault(entry["connection"], []).append(entry["fingerprint"])
    return values


# ---------------------------------------------------------------------------
# The message tracker
# ---------------------------------------------------------------------------


def test_a_segment_that_holds_part_of_a_message_is_not_one_ssh_packet():
    tracker = SSHMessageTracker()
    assert tracker.completes_message(BANNER) is True
    whole = message(body_length=1492, code=20)
    assert tracker.completes_message(whole[:1448]) is False


def test_the_segment_that_completes_a_message_is_one_ssh_packet():
    tracker = SSHMessageTracker()
    tracker.completes_message(BANNER)
    whole = message(body_length=1492, code=20)
    tracker.completes_message(whole[:1448])
    assert tracker.completes_message(whole[1448:]) is True


def test_a_segment_that_holds_two_whole_messages_is_one_ssh_packet():
    tracker = SSHMessageTracker()
    tracker.completes_message(BANNER)
    assert tracker.completes_message(message() + message()) is True


def test_a_length_field_that_spans_two_segments_completes_on_the_second():
    tracker = SSHMessageTracker()
    tracker.completes_message(BANNER)
    whole = message()
    assert tracker.completes_message(whole[:2]) is False
    assert tracker.completes_message(whole[2:]) is True


def test_the_tracker_counts_every_segment_after_the_new_keys_message():
    tracker = SSHMessageTracker()
    tracker.completes_message(BANNER)
    assert tracker.completes_message(message(body_length=12, code=21)) is True
    # An encrypted message carries no length a reader can trust, so every later
    # segment is one SSH packet.
    assert tracker.completes_message(b"\x9a" * 44) is True
    assert tracker.completes_message(b"\x9a" * 8) is True


def test_the_tracker_counts_every_segment_when_the_capture_holds_no_banner():
    tracker = SSHMessageTracker()
    assert tracker.completes_message(b"\x9a" * 44) is True
    assert tracker.completes_message(b"\x9a" * 8) is True


def test_an_unreadable_length_makes_the_tracker_count_every_segment():
    tracker = SSHMessageTracker()
    tracker.completes_message(BANNER)
    assert tracker.completes_message(b"\xff\xff\xff\xff" + b"A" * 20) is True
    assert tracker.completes_message(b"A" * 8) is True


def test_a_banner_that_spans_two_segments_completes_on_the_second():
    tracker = SSHMessageTracker()
    assert tracker.completes_message(BANNER[:8]) is False
    assert tracker.completes_message(BANNER[8:]) is True


def test_a_banner_that_spans_two_segments_keeps_the_message_boundary():
    tracker = SSHMessageTracker()
    tracker.completes_message(BANNER[:8])
    tracker.completes_message(BANNER[8:])
    whole = message(body_length=1492, code=20)
    assert tracker.completes_message(whole[:1448]) is False
    assert tracker.completes_message(whole[1448:]) is True


def test_a_banner_longer_than_the_limit_makes_the_tracker_count_every_segment():
    tracker = SSHMessageTracker()
    assert tracker.completes_message(b"SSH-" + b"A" * 300) is True
    assert tracker.completes_message(b"A" * 8) is True


def test_a_new_keys_message_that_spans_two_segments_turns_the_tracker_opaque():
    tracker = SSHMessageTracker()
    tracker.completes_message(BANNER)
    new_keys = message(body_length=12, code=21)
    # The segment ends after the length field and the padding length, so the message
    # code arrives in the next segment.
    assert tracker.completes_message(new_keys[:5]) is False
    assert tracker.completes_message(new_keys[5:]) is True
    # A tracker that still reads lengths would report False for a message this
    # segment does not complete.
    assert tracker.completes_message(struct.pack(">I", 1492) + b"A" * 20) is True


def test_an_empty_segment_is_not_one_ssh_packet():
    assert SSHMessageTracker().completes_message(b"") is False


# ---------------------------------------------------------------------------
# The fingerprinter
# ---------------------------------------------------------------------------


def test_a_message_that_spans_two_segments_advances_the_window_once():
    fingerprinter = JA4SSHFingerprinter(packet_count=4)
    client = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=22)
    server = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=22, dport=50000)

    fingerprinter.process_packet(client / Raw(load=BANNER))
    fingerprinter.process_packet(server / Raw(load=BANNER))
    whole = message(body_length=1492, code=20)
    assert fingerprinter.process_packet(client / Raw(load=whole[:1448])) is None
    assert fingerprinter.process_packet(client / Raw(load=whole[1448:])) is None
    result = fingerprinter.process_packet(server / Raw(load=message()))
    assert result == "c21s21_c2s2_c0s0"


# ---------------------------------------------------------------------------
# The FoxIO vectors
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not (VECTORS / "ssh-r.pcap").exists(), reason="the FoxIO vector is not available"
)
def test_ssh_r_stream_one_holds_six_client_packets_and_five_server_packets():
    values = read_vector("ssh-r.pcap")["192.168.1.197:46394-44.212.59.210:22"]
    assert [value.split("_")[1] for value in values] == ["c6s5"]


@pytest.mark.skipif(
    not (VECTORS / "ssh-r.pcap").exists(), reason="the FoxIO vector is not available"
)
def test_ssh_r_stream_two_produces_the_reference_windows():
    values = read_vector("ssh-r.pcap")["192.168.1.197:46396-44.212.59.210:22"]
    assert values == [
        "c76s76_c104s96_c19s82",
        "c76s76_c108s92_c0s105",
        "c76s76_c106s94_c0s107",
        "c76s76_c111s89_c0s102",
        "c76s76_c66s65_c9s51",
    ]


@pytest.mark.skipif(
    not (VECTORS / "ssh.pcapng").exists(), reason="the FoxIO vector is not available"
)
def test_the_ssh_vector_keeps_its_reference_fingerprint():
    values = read_vector("ssh.pcapng")["172.16.225.48:57377-54.160.114.75:22"]
    assert values == ["c36s36_c76s124_c0s0"]


@pytest.mark.skipif(
    not (VECTORS / "ssh-scp-1050.pcap").exists(), reason="the FoxIO vector is not available"
)
def test_the_scp_vector_keeps_its_reference_packet_counts():
    values = read_vector("ssh-scp-1050.pcap")["192.168.1.169:49237-192.168.1.197:22"]
    assert [value.split("_")[1] for value in values] == ["c52s148", "c13s187", "c0s200", "c0s200"]
