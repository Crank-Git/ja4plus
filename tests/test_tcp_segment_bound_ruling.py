"""The segment count bound of one TCP stream, which #620 records.

`ja4plus/utils/tcp_stream.py:48` holds `DEFAULT_MAX_STREAM_SEGMENTS = 4096`, so one stream
stores 4096 segments at most beside its byte cap. FoxIO specifies no resource bound, so
no vector decides the value and parity rule 2 gives the port this interface.

**A ruling that lives only in a closed issue is a ruling the next reader reverses by
accident.** These cases hold the register row against the code it describes. A change of
the constant fails a case here, and so does a deletion of the row.

**The comment above the constant carried a wrong attribution, and #620 measured it again.**
The earlier comment gave both the 1336 reading and the 788 reading to
`http2-with-cookies.pcapng`. The 788 reading belongs to `ssh-scp-1050.pcap`, on the SSH
connection `192.168.1.197:22->192.168.1.169:49237`. These cases replay the whole corpus, so
a later reader reads a measurement rather than a claim.

`Crank-Git/ja4plus-go#596` adopted the same value on 2026-08-14, and
`internal/parser/tcp_stream.go:62-65` raised the attribution question this file settles. A
reversal therefore changes both repositories.
"""

from functools import lru_cache
from pathlib import Path
import re

from scapy.all import IP, TCP, Raw, rdpcap

from ja4plus.utils.packet_utils import get_ip_layer, packet_seconds
from ja4plus.utils.tcp_stream import (
    DEFAULT_MAX_STREAM_AGE,
    DEFAULT_MAX_STREAM_SEGMENTS,
    TCPStreamReassembler,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

MODULE = REPO_ROOT / "ja4plus" / "utils" / "tcp_stream.py"

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

# The heading of the register, and the line that closes it.
# `tests/test_ja4d_fqdn_name_ruling.py` reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The segment count bound of one TCP stream"

# The byte cap that `TCPStreamReassembler` holds by default. A reading under this cap is
# the reading that binds, because every stream of this library carries the cap.
BYTE_CAP = 1048576

# A byte cap that no capture of the corpus reaches. It reproduces the reading that a
# reassembler without a byte cap gives.
NO_BYTE_CAP = 10**12

# The largest segment count of one stream under the byte cap, and the stream that holds it.
BINDING_COUNT = 788
BINDING_VECTOR = "ssh-scp-1050.pcap"
BINDING_CONNECTION = "192.168.1.197:22-192.168.1.169:49237"
BINDING_PORT = 22

# The largest segment count of one stream without the byte cap, and the stream that holds
# it. The earlier comment gave the 788 reading to this same capture.
UNCAPPED_COUNT = 1336
UNCAPPED_VECTOR = "http2-with-cookies.pcapng"
UNCAPPED_CONNECTION = "142.250.187.206:443-192.168.2.200:58847"

# The count that `http2-with-cookies.pcapng` reaches under the byte cap. It is below the
# 788 of the SSH stream, which is why the earlier attribution was wrong.
UNCAPPED_VECTOR_COUNT_UNDER_THE_CAP = 757

# The count of captures the corpus holds.
CORPUS_VECTORS = 38


def _register_row() -> str:
    """Return the register row that records the bound.

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


def _captures() -> list[Path]:
    """Return every packet capture of the vector corpus, in name order.

    Returns:
        The paths of the captures, which the caller replays one at a time.
    """
    return sorted(path for path in VECTORS.glob("*.pcap*") if path.suffix in (".pcap", ".pcapng"))


def _bound_comment() -> str:
    """Return the comment that stands above the segment bound.

    The reader stops at the name of the constant and never at its value, so a change of
    the value leaves these cases measuring the comment alone.

    Returns:
        The comment text, from its first line to the line the constant stands on.

    Raises:
        AssertionError: The module holds no such comment.
    """
    source = MODULE.read_text(encoding="utf-8")
    marker = "DEFAULT_MAX_STREAM_SEGMENTS = "
    opener = "# The largest stream of the FoxIO vectors"
    assert marker in source, f"the module holds no {marker!r}"
    comment = source[: source.index(marker)]
    assert opener in comment, f"no comment above the bound opens {opener!r}"
    return comment[comment.index(opener) :]


@lru_cache(maxsize=2)
def _peak_segment_counts(byte_cap: int) -> tuple[tuple[int, str, str], ...]:
    """Return the largest segment count of every stream of the corpus, largest first.

    The replay removes the segment bound, so the reading states the demand of the corpus
    rather than the bound this file measures. It keeps the byte cap the caller states,
    because that cap decides which reading binds.

    Args:
        byte_cap: The value of `max_stream_bytes` for the replay.

    Returns:
        One tuple of (segment count, capture name, stream key) for each stream.
    """
    rows: list[tuple[int, str, str]] = []
    for capture in _captures():
        reassembler = TCPStreamReassembler(
            max_streams=10**6,
            max_stream_bytes=byte_cap,
            max_stream_segments=10**9,
            max_stream_age=10**9,
        )
        peak: dict[str, int] = {}
        for packet in rdpcap(str(capture)):
            if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
                continue
            ip_layer = get_ip_layer(packet)
            if ip_layer is None:
                continue
            tcp = packet[TCP]
            # `ja4plus/fingerprinters/ja4h.py:127` builds this key, and the replay reads
            # the same one so that the count describes the stream the library stores.
            key = f"{ip_layer.src}:{tcp.sport}-{ip_layer.dst}:{tcp.dport}"
            reassembler.add_segment(key, int(tcp.seq), bytes(packet[Raw]), packet_seconds(packet))
            stream = reassembler.streams.get(key)
            if stream is not None:
                peak[key] = max(peak.get(key, 0), len(stream["segments"]))
        rows.extend((count, capture.name, key) for key, count in peak.items())
    return tuple(sorted(rows, reverse=True))


def test_the_register_holds_a_row_for_the_bound() -> None:
    """The divergence register holds the row that records the bound."""
    assert RULING_ITEM in _register_row()


def test_the_register_states_the_line_that_holds_the_bound() -> None:
    """The row names the line of `ja4plus` that holds the constant, and its value."""
    row = _register_row()
    assert "`ja4plus/utils/tcp_stream.py:48`" in row
    assert "`DEFAULT_MAX_STREAM_SEGMENTS = 4096`" in row


def test_the_module_holds_the_constant_on_the_line_the_register_cites() -> None:
    """The constant stands on line 48, which is the line the register row names.

    A comment that grows above the constant moves that line, so this case holds the
    citation of the row against the module rather than against a reader.
    """
    lines = MODULE.read_text(encoding="utf-8").splitlines()
    numbers = [
        index + 1
        for index, line in enumerate(lines)
        if line.startswith("DEFAULT_MAX_STREAM_SEGMENTS = ")
    ]
    assert numbers == [48]
    assert lines[47] == "DEFAULT_MAX_STREAM_SEGMENTS = 4096"


def test_the_register_names_the_constant_of_the_port() -> None:
    """The row names the constant of the port and the issue that adopted it."""
    row = _register_row()
    assert "`DefaultMaxSegments = 4096`" in row
    assert "`Crank-Git/ja4plus-go#596`" in row
    assert "2026-08-14" in row


def test_the_register_states_the_binding_measurement() -> None:
    """The row gives the 788 reading to the SSH capture and never to the HTTP/2 one."""
    row = _register_row()
    assert f"{BINDING_COUNT} as the largest count under the byte cap" in row
    assert f"`{BINDING_VECTOR}`" in row
    assert "`192.168.1.197:22->192.168.1.169:49237`" in row
    assert f"port {BINDING_PORT}" in row


def test_the_register_states_the_reading_without_a_byte_cap() -> None:
    """The row gives the 1336 reading to the HTTP/2 capture."""
    row = _register_row()
    assert f"{UNCAPPED_COUNT} as the largest count without a byte cap" in row
    assert f"`{UNCAPPED_VECTOR}`" in row


def test_the_register_records_the_correction_of_the_attribution() -> None:
    """The row states that the 788 reading belongs to an SSH stream."""
    row = _register_row()
    assert "corrected the attribution" in row
    assert f"The {BINDING_COUNT} therefore belongs to an SSH stream" in row


def test_the_register_states_that_the_bound_moves_no_fingerprint_value() -> None:
    """The row states that no stream of the corpus reaches the bound."""
    row = _register_row()
    assert "moves no fingerprint value" in row
    assert f"No stream of the {CORPUS_VECTORS} captures reaches 4096" in row


def test_the_register_records_the_stream_age_difference() -> None:
    """The row records that the port bounds no stream age, and it rules nothing on it."""
    row = _register_row()
    assert "`DEFAULT_MAX_STREAM_AGE`" in row
    assert "the Go reassembler holds no stream age" in row


def test_the_comment_gives_the_binding_reading_to_the_ssh_capture() -> None:
    """The comment above the constant names the capture the measurement found."""
    comment = _bound_comment()
    assert f"{BINDING_COUNT} segments" in comment
    assert f"`{BINDING_VECTOR}`" in comment
    assert "`192.168.1.197:22->192.168.1.169:49237`" in comment


def test_the_comment_gives_the_uncapped_reading_to_the_http2_capture() -> None:
    """The comment names `http2-with-cookies.pcapng` for the 1336 reading alone."""
    comment = _bound_comment()
    uncapped = comment[: comment.index(f"{BINDING_COUNT} segments")]
    assert f"{UNCAPPED_COUNT} segments without a byte cap" in uncapped
    assert f"`{UNCAPPED_VECTOR}`" in uncapped
    assert comment.count(f"`{UNCAPPED_VECTOR}`") == 1


def test_the_corpus_holds_the_capture_count_the_row_states() -> None:
    """The vector corpus holds the capture count the register row states."""
    assert len(_captures()) == CORPUS_VECTORS


def test_the_largest_stream_under_the_byte_cap_is_the_ssh_stream() -> None:
    """A replay of the corpus reads 788 segments on the SSH connection of port 22."""
    count, capture, key = _peak_segment_counts(BYTE_CAP)[0]
    assert (count, capture, key) == (BINDING_COUNT, BINDING_VECTOR, BINDING_CONNECTION)


def test_the_binding_stream_carries_port_22() -> None:
    """The stream that holds the binding reading carries the SSH port."""
    _, _, key = _peak_segment_counts(BYTE_CAP)[0]
    source, _, _ = key.partition("-")
    assert int(source.rsplit(":", 1)[1]) == BINDING_PORT


def test_the_largest_stream_without_a_byte_cap_is_the_http2_stream() -> None:
    """A replay without the byte cap reads 1336 segments on the HTTP/2 connection."""
    count, capture, key = _peak_segment_counts(NO_BYTE_CAP)[0]
    assert (count, capture, key) == (UNCAPPED_COUNT, UNCAPPED_VECTOR, UNCAPPED_CONNECTION)


def test_the_http2_capture_reaches_no_788_under_the_byte_cap() -> None:
    """`http2-with-cookies.pcapng` reads 757 under the byte cap, which is below 788."""
    counts = [
        count
        for count, capture, key in _peak_segment_counts(BYTE_CAP)
        if capture == UNCAPPED_VECTOR and key == UNCAPPED_CONNECTION
    ]
    assert counts == [UNCAPPED_VECTOR_COUNT_UNDER_THE_CAP]
    assert UNCAPPED_VECTOR_COUNT_UNDER_THE_CAP < BINDING_COUNT


def test_no_stream_of_the_corpus_reaches_the_bound() -> None:
    """The largest stream of the corpus holds fewer segments than the bound stores."""
    assert _peak_segment_counts(BYTE_CAP)[0][0] < DEFAULT_MAX_STREAM_SEGMENTS
    assert _peak_segment_counts(NO_BYTE_CAP)[0][0] < DEFAULT_MAX_STREAM_SEGMENTS


def test_the_bound_sits_above_five_times_the_binding_reading() -> None:
    """4096 sits above five times 788, which is the reading the byte cap leaves."""
    assert DEFAULT_MAX_STREAM_SEGMENTS > 5 * BINDING_COUNT


def test_the_bound_sits_above_three_times_the_uncapped_reading() -> None:
    """4096 sits above three times 1336, which is the margin the earlier comment gave."""
    assert DEFAULT_MAX_STREAM_SEGMENTS > 3 * UNCAPPED_COUNT
    assert DEFAULT_MAX_STREAM_SEGMENTS < 4 * UNCAPPED_COUNT


def test_the_reassembler_stores_the_bound_and_refuses_the_next_segment() -> None:
    """A stream stores 4096 segments, and it refuses the segment that follows them."""
    reassembler = TCPStreamReassembler(max_stream_bytes=NO_BYTE_CAP)
    for index in range(DEFAULT_MAX_STREAM_SEGMENTS + 10):
        reassembler.add_segment("stream", index * 2, b"ab")
    assert len(reassembler.streams["stream"]["segments"]) == DEFAULT_MAX_STREAM_SEGMENTS


def test_the_byte_cap_alone_admits_far_more_than_the_bound() -> None:
    """A sender of one-byte segments passes the bound long before the byte cap."""
    reassembler = TCPStreamReassembler(max_stream_segments=10**9)
    for index in range(DEFAULT_MAX_STREAM_SEGMENTS + 1):
        reassembler.add_segment("stream", index, b"a")
    stored = len(reassembler.streams["stream"]["segments"])
    assert stored == DEFAULT_MAX_STREAM_SEGMENTS + 1
    assert reassembler.streams["stream"]["bytes"] < BYTE_CAP


def test_the_reassembler_holds_the_three_bounds_a_state_table_needs() -> None:
    """The reassembler bounds the stream count, the stored segments and the stream age."""
    reassembler = TCPStreamReassembler()
    assert reassembler.max_streams == 100
    assert reassembler.max_stream_segments == DEFAULT_MAX_STREAM_SEGMENTS
    assert reassembler.max_stream_age == DEFAULT_MAX_STREAM_AGE


def test_a_stream_that_reaches_the_bound_produces_the_same_bytes_as_one_below_it() -> None:
    """The bound refuses a segment, and it moves no byte of a stream below the bound."""
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2) / Raw(load=b"x")
    assert packet is not None
    bounded = TCPStreamReassembler()
    unbounded = TCPStreamReassembler(max_stream_segments=10**9)
    for index in range(100):
        for reassembler in (bounded, unbounded):
            reassembler.add_segment("stream", index, b"x")
    assert bounded.get_stream("stream") == unbounded.get_stream("stream")
