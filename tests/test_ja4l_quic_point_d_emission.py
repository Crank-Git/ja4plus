"""The frame that emits the QUIC `JA4L-S` value.

The FoxIO Wireshark dissector writes `ja4.ja4ls` and `ja4.ja4l` inside the branch that
fills `timestamp_D`, so one frame carries both values.
`wireshark/source/packet-ja4.c:1432-1451` holds that branch at the pinned commit
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`. This project filled point `B` and returned the
server value there, which is an earlier frame.

**The maintainer ruled #606 on 2026-08-16, and the ruling has two halves.** The frame
moves to the packet that fills point `D`, because one reference names a frame and it names
that one. **The value still publishes where a connection never fills point `D`**, because
the four references split two against two on that question and no side wins.
`JA4LFingerprinter.close_open_windows` publishes the held value at the end of a capture.

**A ruling that lives only in a closed issue is a ruling the next reader reverses by
accident.** These cases hold both halves. A return of the server value from
`_quic_server_initial` fails a case here, and so does a connection that publishes nothing
where point `D` never fills.
"""

import json
from pathlib import Path

from scapy.all import PcapReader

from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.processor import Processor

REPO_ROOT = Path(__file__).resolve().parent.parent

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

QUIC_SUFFIX = "_quic"

# The dissector reads every QUIC packet of one datagram, and this project reads the first
# packet alone. `docs/specs/spec.md` records that ruling under #613, and the row names
# `ssh2.pcapng` frame 1042 and `tls3.pcapng` frame 295. Point `C` therefore stays empty on
# those two connections and point `D` never fills, so `close_open_windows` publishes the
# server value of each one and no frame of the capture carries it.
FRAMES_THAT_PUBLISH_AT_THE_END_OF_THE_CAPTURE = {
    "ssh2.pcapng": (1046,),
    "tls3.pcapng": (297,),
}

# Each capture holds one QUIC connection for each frame this map names.
CAPTURES = ("chrome-cloudflare-quic-with-secrets.pcapng", "ssh2.pcapng", "tls3.pcapng")


def _produced(capture: str) -> list[tuple[int, str]]:
    """Return the frame number and the value of every QUIC JA4L value of one capture.

    Args:
        capture: The file name of a capture under `tests/foxio_vectors/`.

    Returns:
        A list of pairs, in frame order. Each pair holds the frame number and the value.
    """
    fingerprinter = JA4LFingerprinter()
    produced: list[tuple[int, str]] = []
    with PcapReader(str(VECTORS / capture)) as reader:
        for number, packet in enumerate(reader, start=1):
            value = fingerprinter.process_packet(packet)
            for one in [value] if value else []:
                if one.endswith(QUIC_SUFFIX):
                    produced.append((number, one))
            for extra in fingerprinter.last_extra_fingerprints:
                if extra.endswith(QUIC_SUFFIX):
                    produced.append((number, extra))
    return produced


def _dissector_frames(capture: str, key: str) -> list[int]:
    """Return every frame on which the dissector writes one QUIC value of one capture.

    Args:
        capture: The file name of a capture under `tests/foxio_vectors/`.
        key: The field name the dissector writes, `ja4.ja4ls` or `ja4.ja4l`.

    Returns:
        A list of frame numbers, in frame order.
    """
    rows = json.loads((VECTORS / "wireshark_expected" / f"{capture}.json").read_text())
    frames = []
    for row in rows:
        layers = row["_source"]["layers"]
        values = layers.get(key, [])
        if values and values[0].endswith(QUIC_SUFFIX):
            frames.append(int(layers["frame.number"][0]))
    return frames


def test_the_dissector_writes_the_two_quic_values_on_one_frame() -> None:
    """The reference names one frame for both values, so this case holds the premise."""
    for capture in CAPTURES:
        assert _dissector_frames(capture, "ja4.ja4ls") == _dissector_frames(capture, "ja4.ja4l")


def test_the_quic_server_value_reaches_the_frame_that_fills_point_d() -> None:
    """Every QUIC server value lands on the frame the dissector names."""
    for capture in CAPTURES:
        late = FRAMES_THAT_PUBLISH_AT_THE_END_OF_THE_CAPTURE.get(capture, ())
        expected = [frame for frame in _dissector_frames(capture, "ja4.ja4ls") if frame not in late]
        produced = [frame for frame, value in _produced(capture) if value.startswith("JA4L-S=")]
        assert produced == expected, capture


def test_the_quic_client_value_shares_the_frame_of_the_quic_server_value() -> None:
    """One QUIC frame carries the server value and the client value together."""
    for capture in CAPTURES:
        server = [frame for frame, value in _produced(capture) if value.startswith("JA4L-S=")]
        client = [frame for frame, value in _produced(capture) if value.startswith("JA4L-C=")]
        assert server == client, capture


def test_the_server_initial_packet_of_a_quic_connection_gives_no_value() -> None:
    """The frame that fills point `B` produces no value at all."""
    for capture, point_b in (("tls3.pcapng", 144), ("ssh2.pcapng", 1140)):
        frames = [frame for frame, _ in _produced(capture)]
        assert point_b not in frames, capture


def test_the_reference_value_reaches_the_reference_frame_on_the_two_captures() -> None:
    """The four pairs #606 tabulates each hold their value on the frame of the dissector."""
    expected = {
        "ssh2.pcapng": ((1147, "JA4L-S=5389_57_quic"),),
        "tls3.pcapng": ((147, "JA4L-S=4213_59_quic"), (312, "JA4L-S=3298_58_quic")),
    }
    for capture, pairs in expected.items():
        produced = set(_produced(capture))
        for pair in pairs:
            assert pair in produced, (capture, pair)


def test_a_connection_that_never_fills_point_d_publishes_its_server_value() -> None:
    """The end of a capture publishes the server value point `D` never released.

    The FoxIO references split two against two on whether this value exists, and the
    maintainer ruled on 2026-08-16 that this project publishes it. A connection that
    stops at point `B` therefore reports its server value here and nowhere else.
    """
    expected = {
        "ssh2.pcapng": ["JA4L-S=16192_57_quic"],
        "tls3.pcapng": ["JA4L-S=3583_57_quic"],
    }
    for capture, values in expected.items():
        fingerprinter = JA4LFingerprinter()
        with PcapReader(str(VECTORS / capture)) as reader:
            for packet in reader:
                fingerprinter.process_packet(packet)
        emitted = [entry["fingerprint"] for entry in fingerprinter.close_open_windows()]
        assert emitted == values, capture


def test_the_end_of_a_capture_publishes_each_held_value_once() -> None:
    """A second call publishes nothing, because the first call removes the held value."""
    fingerprinter = JA4LFingerprinter()
    with PcapReader(str(VECTORS / "tls-handshake.pcapng")) as reader:
        for packet in reader:
            fingerprinter.process_packet(packet)
    first = fingerprinter.close_open_windows()
    second = fingerprinter.close_open_windows()
    assert len(first) == 20
    assert second == []


def test_a_connection_that_fills_point_d_publishes_nothing_at_the_end() -> None:
    """The packet that fills point `D` releases the value, so the end holds none.

    A connection that published on a frame and again at the end would report its server
    value twice, and the reference publishes one server value for one connection.
    """
    fingerprinter = JA4LFingerprinter()
    with PcapReader(str(VECTORS / "chrome-cloudflare-quic-with-secrets.pcapng")) as reader:
        for packet in reader:
            fingerprinter.process_packet(packet)
    assert fingerprinter.close_open_windows() == []
    values = [
        entry["fingerprint"]
        for entry in fingerprinter.get_fingerprints()
        if entry["fingerprint"].startswith("JA4L-S=") and entry["fingerprint"].endswith(QUIC_SUFFIX)
    ]
    assert values == ["JA4L-S=10990_56_quic"]


def test_the_stored_quic_server_value_names_the_address_pair_of_the_server() -> None:
    """The stored entry of a value names the pair of the packet that measured it.

    One packet gives both QUIC values, and the two measurements read opposite
    directions. A stored server value that names the client pair reports the wrong
    direction to every caller of `get_fingerprints`.
    """
    fingerprinter = JA4LFingerprinter()
    with PcapReader(str(VECTORS / "ssh2.pcapng")) as reader:
        for packet in reader:
            fingerprinter.process_packet(packet)
    stored = [
        entry
        for entry in fingerprinter.get_fingerprints()
        if str(entry["fingerprint"]).endswith(QUIC_SUFFIX)
    ]
    server = [entry for entry in stored if entry["fingerprint"].startswith("JA4L-S=")]
    client = [entry for entry in stored if entry["fingerprint"].startswith("JA4L-C=")]
    assert len(server) == 1
    assert len(client) == 1
    assert server[0]["srcport"] == 443
    assert client[0]["dstport"] == 443
    assert server[0]["src"] == client[0]["dst"]
    assert server[0]["dst"] == client[0]["src"]


def test_the_processor_reports_both_quic_values_on_the_frame_that_fills_point_d() -> None:
    """A caller of the processor reads both values from the one packet that gives them."""
    processor = Processor()
    reported: list[str] = []
    with PcapReader(str(VECTORS / "tls3.pcapng")) as reader:
        for number, packet in enumerate(reader, start=1):
            results = processor.process_packet(packet)
            if number == 147:
                reported = [result.fingerprint for result in results if result.type == "ja4l"]
                break
    # The client value of this project differs from the value of the dissector on this
    # connection, and #606 moves no client value. The frame is the subject here.
    assert reported == ["JA4L-S=4213_59_quic", "JA4L-C=59_128_quic"]
