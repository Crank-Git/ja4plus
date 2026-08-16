"""The frame that emits the QUIC `JA4L-S` value.

The FoxIO Wireshark dissector writes `ja4.ja4ls` and `ja4.ja4l` inside the branch that
fills `timestamp_D`, so one frame carries both values.
`wireshark/source/packet-ja4.c:1432-1451` holds that branch at the pinned commit
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`. This project filled point `B` and returned the
server value there, which is an earlier frame.

**A ruling that lives only in a closed issue is a ruling the next reader reverses by
accident.** These cases hold the emission frame against the dissector. A return of the
server value from `_quic_server_initial` fails a case here.
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
# those two connections, point `D` never fills, and the frame below carries no value here.
FRAMES_THE_COALESCED_DATAGRAM_RULING_DROPS = {
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
        dropped = FRAMES_THE_COALESCED_DATAGRAM_RULING_DROPS.get(capture, ())
        expected = [
            frame for frame in _dissector_frames(capture, "ja4.ja4ls") if frame not in dropped
        ]
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
