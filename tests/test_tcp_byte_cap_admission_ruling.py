"""The segment one TCP stream refuses at its byte cap.

#620 measured 757 segments here and 750 in the port, on one stream of
`http2-with-cookies.pcapng`, and it found no cause. #654 found the cause. The two ports
read one feed, and they part on one condition: this project refuses the segment that would
cross the byte cap, and the port admits it and then refuses every segment after it.

The divergence register of `docs/specs/spec.md` holds the ruling. This file holds that row
against the module, and it holds the behaviour of this project against a constructed
stream and against the capture that raised the question.

**No case of this file builds, runs or imports the port.** Parity rule 3 bars that, so the
measurements of the port stand in the register row and this file reads them as text.
"""

import re
from functools import lru_cache
from pathlib import Path

from scapy.all import Raw, rdpcap
from scapy.layers.inet import TCP

from ja4plus.utils.packet_utils import get_ip_layer, packet_seconds
from ja4plus.utils.tcp_stream import TCPStreamReassembler

REPO_ROOT = Path(__file__).resolve().parent.parent
SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"
MODULE = REPO_ROOT / "ja4plus" / "utils" / "tcp_stream.py"
VECTOR = REPO_ROOT / "tests" / "foxio_vectors" / "http2-with-cookies.pcapng"

# The heading of the register, and the line that closes it.
# `tests/test_tcp_segment_bound_ruling.py` reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The segment one TCP stream refuses at its byte cap"

# The condition of this project, and the line it stands on.
ADMISSION_CONDITION = '        if stream["bytes"] + len(data) > self.max_stream_bytes:'
ADMISSION_LINE = 151

# The stream of the capture that separates the two ports, and the byte cap it reaches.
STREAM_KEY = "142.250.187.206:443->192.168.2.200:58847"
BYTE_CAP = 1048576

# The reading of this project on that stream, under that byte cap.
STORED_SEGMENTS = 757
STORED_BYTES = 1048554
RUN_BYTES = 1047414

# The segment the two ports treat differently. This project refuses it.
CROSSING_SEQ = 741489929
CROSSING_LENGTH = 1412

# The eight segments this project stores after that refusal, and the bytes they carry.
# The port stores none of them, so eight against one is the difference of seven.
LATER_SEGMENTS = (
    (742229817, 81),
    (742229898, 66),
    (742241260, 169),
    (742241429, 348),
    (742244306, 57),
    (742244363, 44),
    (742252472, 144),
    (742269312, 231),
)


def _register_row() -> str:
    """Return the register row that records the admission rule.

    Returns:
        The whole text of the row.

    Raises:
        AssertionError: The page holds no register, or the register holds no such row.
    """
    page = SPECIFICATION.read_text(encoding="utf-8")
    assert REGISTER_HEADING in page, f"the specification holds no {REGISTER_HEADING!r}"
    section = page[page.index(REGISTER_HEADING) : page.index(REGISTER_END)]
    for line in section.splitlines():
        if not line.startswith("|") or REGISTER_SEPARATOR.match(line):
            continue
        if line.split("|")[1].strip() == RULING_ITEM:
            return line
    raise AssertionError(f"the divergence register holds no row named {RULING_ITEM!r}")


@lru_cache(maxsize=1)
def _replay() -> tuple[int, int, int]:
    """Return the reading of this project on the stream that separates the two ports.

    The replay removes the segment bound and the age bound, so the byte cap is the one
    bound that decides which segment the stream stores.

    Returns:
        The stored segment count, the stored byte count, and the length of the run.
    """
    reassembler = TCPStreamReassembler(
        max_streams=10**6,
        max_stream_bytes=BYTE_CAP,
        max_stream_segments=10**9,
        max_stream_age=10**9,
    )
    for packet in rdpcap(str(VECTOR)):
        if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
            continue
        ip_layer = get_ip_layer(packet)
        if ip_layer is None:
            continue
        tcp = packet[TCP]
        # The port builds this key at `ja4h.go:109`, so the replay reads the stream that
        # the register row names.
        key = f"{ip_layer.src}:{tcp.sport}->{ip_layer.dst}:{tcp.dport}"
        reassembler.add_segment(key, int(tcp.seq), bytes(packet[Raw]), packet_seconds(packet))

    stream = reassembler.streams[STREAM_KEY]
    return len(stream["segments"]), stream["bytes"], len(reassembler.get_stream(STREAM_KEY))


def test_the_register_holds_a_row_for_the_admission_rule() -> None:
    """The divergence register holds the row that records the admission rule."""
    assert RULING_ITEM in _register_row()


def test_the_register_states_the_condition_of_this_project() -> None:
    """The row names the line of `ja4plus` that holds the condition, and the condition."""
    row = _register_row()
    assert "`ja4plus/utils/tcp_stream.py:151`" in row
    assert '`if stream["bytes"] + len(data) > self.max_stream_bytes`' in row


def test_the_module_holds_the_condition_on_the_line_the_register_cites() -> None:
    """The condition stands on line 151, which is the line the register row names.

    A comment that grows above the condition moves that line, so this case holds the
    citation of the row against the module rather than against a reader.
    """
    lines = MODULE.read_text(encoding="utf-8").splitlines()
    assert lines[ADMISSION_LINE - 1] == ADMISSION_CONDITION


def test_the_register_states_the_condition_of_the_port() -> None:
    """The row names the line of the port that holds the condition, and the condition."""
    row = _register_row()
    assert "`internal/parser/tcp_stream.go:170`" in row
    assert "`if stream.storedBytes >= r.storedByteBound()`" in row


def test_the_register_states_that_the_two_ports_read_one_feed() -> None:
    """The row records the replay that removes the feed as a cause."""
    row = _register_row()
    assert "offers 1336 segments in one order to each port" in row
    assert "1853328 bytes" in row


def test_the_register_names_the_segment_the_two_ports_part_on() -> None:
    """The row names the crossing segment, and the arithmetic that refuses it here."""
    row = _register_row()
    assert f"{CROSSING_SEQ}" in row
    assert f"{CROSSING_LENGTH} bytes" in row
    assert f"{RUN_BYTES} plus {CROSSING_LENGTH} crosses {BYTE_CAP}" in row


def test_the_register_names_the_eight_segments_that_follow() -> None:
    """The row names every later segment this project stores, and its length."""
    row = _register_row()
    for seq, length in LATER_SEGMENTS:
        assert f"{seq}" in row, f"the row names no segment {seq}"
        assert f"{length}" in row, f"the row names no length {length}"
    assert "1140 bytes" in row
    assert "eight against one is the seven" in row


def test_the_register_states_the_rule_each_port_breaks() -> None:
    """The row states the criterion of #33 and the run the port keeps whole."""
    row = _register_row()
    assert (
        "One stream holds no more than the configured byte cap, whatever the segment count." in row
    )
    assert f"{STORED_BYTES} bytes" in row
    assert "1048826 bytes" in row


def test_the_register_states_that_the_divergence_moves_no_value() -> None:
    """The row records the corpus replay and the two command-line readings."""
    row = _register_row()
    assert "one stream where the stored count differs" in row
    assert "the same seven values" in row


def test_the_stream_stores_the_count_the_register_records() -> None:
    """`http2-with-cookies.pcapng` stores 757 segments on the stream, under the byte cap."""
    segments, _, _ = _replay()
    assert segments == STORED_SEGMENTS


def test_the_stream_stores_no_more_bytes_than_the_byte_cap() -> None:
    """The stored bytes reach 1048554, which holds acceptance criterion 1 of #33.

    The port stores 1048826 bytes on the same stream, which crosses the cap by 250.
    """
    _, stored_bytes, _ = _replay()
    assert stored_bytes == STORED_BYTES
    assert stored_bytes <= BYTE_CAP


def test_the_run_stops_at_the_gap_the_refusal_opens() -> None:
    """`get_stream` returns 1047414 bytes, and the stream stores 1140 bytes past the gap."""
    _, stored_bytes, run_bytes = _replay()
    assert run_bytes == RUN_BYTES
    assert stored_bytes - run_bytes == sum(length for _, length in LATER_SEGMENTS)


def test_a_stream_admits_a_later_segment_that_fits_under_the_byte_cap() -> None:
    """A stream that refuses a crossing segment stores the next segment that fits.

    The port refuses every segment after the crossing one, so this case separates the two
    readings on three counts: the stored sequence numbers, the stored bytes and the run.
    """
    reassembler = TCPStreamReassembler(max_streams=4, max_stream_bytes=100)
    reassembler.add_segment("stream", 0, b"a" * 60)
    reassembler.add_segment("stream", 60, b"b" * 50)
    reassembler.add_segment("stream", 110, b"c" * 30)

    stream = reassembler.streams["stream"]
    assert [seq for seq, _ in stream["segments"]] == [0, 110]
    assert stream["bytes"] == 90
    assert len(reassembler.get_stream("stream")) == 60


def test_a_stream_stores_no_segment_that_crosses_the_byte_cap() -> None:
    """One stream holds no more than the byte cap, whatever the order of the segments.

    Acceptance criterion 1 of #33 states that rule, and this case holds it.
    """
    reassembler = TCPStreamReassembler(max_streams=4, max_stream_bytes=100)
    for index in range(20):
        reassembler.add_segment("stream", index * 30, bytes(30))
    assert reassembler.streams["stream"]["bytes"] <= 100
