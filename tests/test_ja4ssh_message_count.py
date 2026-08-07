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
from ja4plus.utils.ssh_utils import (
    MAX_PENDING_BYTES,
    MAX_PENDING_SEGMENTS,
    SEQ_SPACE,
    SSHMessageTracker,
)

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


def client_segment(payload, seq):
    """Return one client-to-server segment that carries the payload.

    Args:
        payload: The TCP payload of the segment, as bytes.
        seq: The TCP sequence number of the first payload byte.

    Returns:
        The packet.
    """
    return IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=22, seq=seq) / Raw(payload)


def server_segment(payload, seq):
    """Return one server-to-client segment that carries the payload.

    Args:
        payload: The TCP payload of the segment, as bytes.
        seq: The TCP sequence number of the first payload byte.

    Returns:
        The packet.
    """
    return IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=22, dport=50000, seq=seq) / Raw(payload)


def test_a_message_that_spans_two_segments_advances_the_window_once():
    fingerprinter = JA4SSHFingerprinter(packet_count=4)

    fingerprinter.process_packet(client_segment(BANNER, 1))
    fingerprinter.process_packet(server_segment(BANNER, 1))
    whole = message(body_length=1492, code=20)
    assert fingerprinter.process_packet(client_segment(whole[:1448], 22)) is None
    assert fingerprinter.process_packet(client_segment(whole[1448:], 1470)) is None
    result = fingerprinter.process_packet(server_segment(message(), 22))
    assert result == "c21s21_c2s2_c0s0"


# ---------------------------------------------------------------------------
# The retransmitted segment and the out-of-order segment
# ---------------------------------------------------------------------------


def test_a_retransmitted_segment_is_not_one_ssh_packet():
    tracker = SSHMessageTracker()
    assert tracker.add_segment(BANNER, 1) == [len(BANNER)]
    whole = message(body_length=1492, code=20)
    assert tracker.add_segment(whole[:1448], 22) == []
    # The direction sends the same segment again, so the tracker reads no byte of it.
    assert tracker.add_segment(whole[:1448], 22) == []
    assert tracker.add_segment(whole[1448:], 1470) == [48]


def test_a_retransmitted_segment_keeps_the_message_boundary():
    tracker = SSHMessageTracker()
    tracker.add_segment(BANNER, 1)
    whole = message(body_length=1492, code=20)
    tracker.add_segment(whole[:1448], 22)
    tracker.add_segment(whole[:1448], 22)
    tracker.add_segment(whole[1448:], 1470)
    # A tracker that read the retransmission twice would hold a length field it cannot
    # trust, and it would count this part of a message as one SSH packet.
    split = message(body_length=1492, code=20)
    assert tracker.add_segment(split[:1448], 1518) == []


def test_an_out_of_order_segment_counts_on_its_own_sequence_number():
    tracker = SSHMessageTracker()
    tracker.add_segment(BANNER, 1)
    whole = message(body_length=1492, code=20)
    # The segment that completes the message arrives first, so the tracker holds it.
    assert tracker.add_segment(whole[1448:], 1470) == []
    # The predecessor fills the gap, and the held segment completes the message.
    assert tracker.add_segment(whole[:1448], 22) == [48]


def test_a_segment_that_repeats_part_of_the_stream_is_read_once():
    tracker = SSHMessageTracker()
    tracker.add_segment(BANNER, 1)
    whole = message(body_length=32, code=94)
    tracker.add_segment(whole[:10], 22)
    # The direction sends the first ten bytes again, and eight new bytes after them.
    # The tracker reads the eight new bytes, which complete no message.
    assert tracker.add_segment(whole[:18], 22) == []
    assert tracker.add_segment(whole[18:], 40) == [len(whole) - 18]


def test_an_out_of_order_segment_that_follows_the_wrap_point_is_held():
    tracker = SSHMessageTracker()
    # The banner ends ten bytes before the sequence space wraps.
    start = SEQ_SPACE - len(BANNER) - 10
    tracker.add_segment(BANNER, start)
    whole = message(body_length=1492, code=20)
    first = (start + len(BANNER)) % SEQ_SPACE
    second = (first + 1448) % SEQ_SPACE
    assert second < 1448

    # The segment that completes the message arrives first, and it starts after the
    # wrap point. A tracker that compares the raw numbers reads it as a segment far
    # behind the next sequence number, and it drops it.
    assert tracker.add_segment(whole[1448:], second) == []
    assert tracker.add_segment(whole[:1448], first) == [48]


def test_a_retransmission_that_precedes_the_wrap_point_is_dropped():
    tracker = SSHMessageTracker()
    start = SEQ_SPACE - len(BANNER) - 10
    tracker.add_segment(BANNER, start)
    whole = message(body_length=1492, code=20)
    first = (start + len(BANNER)) % SEQ_SPACE
    tracker.add_segment(whole[:1448], first)
    tracker.add_segment(whole[1448:], (first + 1448) % SEQ_SPACE)

    # The direction sends the pre-wrap segment again. A tracker that compares the raw
    # numbers reads it as a segment far ahead of the next sequence number, and it holds
    # it until the buffer reaches its bound.
    assert tracker.add_segment(whole[:1448], first) == []
    assert tracker._pending == {}


def test_a_gap_that_never_fills_makes_the_tracker_count_every_segment():
    tracker = SSHMessageTracker()
    tracker.add_segment(BANNER, 1)
    whole = message(body_length=1492, code=20)
    # The predecessor never arrives, so the buffer reaches its bound.
    for index in range(MAX_PENDING_SEGMENTS):
        assert tracker.add_segment(whole[:100], 10_000 + index * 100) == []
    assert tracker.add_segment(whole[:100], 10_000 + MAX_PENDING_SEGMENTS * 100) == [100]
    assert tracker.add_segment(whole[:100], 22) == [100]


def test_the_held_segments_stay_below_the_byte_bound():
    tracker = SSHMessageTracker()
    tracker.add_segment(BANNER, 1)
    segment = b"A" * 1448
    held = 0
    seq = 10_000
    while held + len(segment) <= MAX_PENDING_BYTES:
        tracker.add_segment(segment, seq)
        held += len(segment)
        seq += len(segment)
    assert tracker._pending_bytes <= MAX_PENDING_BYTES


def test_a_retransmitted_segment_does_not_advance_the_window():
    fingerprinter = JA4SSHFingerprinter(packet_count=1000)
    fingerprinter.process_packet(client_segment(BANNER, 1))
    whole = message(body_length=1492, code=20)
    fingerprinter.process_packet(client_segment(whole[:1448], 22))
    fingerprinter.process_packet(client_segment(whole[:1448], 22))
    fingerprinter.process_packet(client_segment(whole[1448:], 1470))
    conn = fingerprinter.connections["10.0.0.1:50000-10.0.0.2:22"]
    assert conn["ssh_packets"]["client"] == [len(BANNER), 48]


def test_the_retransmission_capture_holds_five_client_packets_and_four_server_packets(tmp_path):
    """The retransmission capture counts the retransmitted segment once.

    `tests/build_ssh_retransmission.py` builds the capture. `.gitignore` holds no
    capture other than the FoxIO vectors, so the test writes the file and reads it
    back. Run the builder to write `tests/data/ssh-retransmission.pcap` for a reader.

    `tshark` labels five client frames and four server frames `ssh`, and it labels the
    retransmitted frame `tcp`:

    ```
    $ tshark -r tests/data/ssh-retransmission.pcap -Y "ssh" \
        -T fields -e frame.number -e tcp.srcport -e tcp.len -e frame.protocols
    4	50000	21	raw:ip:tcp:ssh
    5	22	21	raw:ip:tcp:ssh
    6	50000	1448	raw:ip:tcp
    8	50000	48	raw:ip:tcp:ssh
    9	50000	36	raw:ip:tcp:ssh
    10	22	36	raw:ip:tcp:ssh
    11	50000	36	raw:ip:tcp:ssh
    12	22	36	raw:ip:tcp:ssh
    13	50000	36	raw:ip:tcp:ssh
    14	22	36	raw:ip:tcp:ssh
    ```

    Frame 7 holds the retransmission, and `tshark` labels it `tcp`:

    ```
    $ tshark -r tests/data/ssh-retransmission.pcap \
        -Y "tcp.analysis.retransmission && tcp.port==22" \
        -T fields -e frame.number -e tcp.len
    7	1448
    ```
    """
    from scapy.all import rdpcap, wrpcap

    from tests.build_ssh_retransmission import build

    path = tmp_path / "ssh-retransmission.pcap"
    wrpcap(str(path), build())

    fingerprinter = JA4SSHFingerprinter()
    values = []
    for packet in rdpcap(str(path)):
        result = fingerprinter.process_packet(packet)
        if result:
            values.append(result)

    assert values == ["c36s36_c5s4_c1s0"]


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
