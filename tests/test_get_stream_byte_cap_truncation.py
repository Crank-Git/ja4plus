"""`get_stream` truncates the contiguous run at the byte cap.

#654 found that `get_stream` returned the stored bytes with no truncation, and that
`GetStream` of the port truncates. #697 holds the answer: this project truncates, and
parity rule 2 of `CLAUDE.md` decides it. FoxIO specifies no byte cap on a stream reader,
so the port holds the interface and this project adopts it.

**The truncation removes no byte today.** `add_segment` refuses the segment that would
cross the byte cap, so one stream stores no more bytes than the cap. A case therefore
reaches the truncation through a stream that stores its segments under a cap that admits
every one of them, and then reads that stream under a lower cap. The state reaches
`get_stream` through the public writer alone, and no case of this file writes
`reassembler.streams` and no case reverses the admission rule.

**No case of this file builds, runs or imports the port.** Parity rule 3 bars that.
"""

from pathlib import Path

from ja4plus.utils.tcp_stream import TCPStreamReassembler

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE = REPO_ROOT / "ja4plus" / "utils" / "tcp_stream.py"

# The key of the one stream every case of this file builds.
STREAM = "192.0.2.1:443->192.0.2.2:50000"

# The three segments of the run, each 50 bytes, and each of one repeated byte. A reader
# that returns the last bytes of the run rather than the first returns a different value.
SEGMENT_LENGTH = 50
FIRST = b"a" * SEGMENT_LENGTH
SECOND = b"b" * SEGMENT_LENGTH
THIRD = b"c" * SEGMENT_LENGTH
RUN_LENGTH = 3 * SEGMENT_LENGTH

# The cap the reader reads, which stands below the run.
LOW_CAP = 100


def _stream_past_the_byte_cap(cap: int) -> TCPStreamReassembler:
    """Return a reassembler whose one stream stores a run longer than the byte cap.

    The stream stores its three segments under a cap that admits every one of them, and
    this function then lowers the cap to the value the reader reads.

    Args:
        cap: The byte cap `get_stream` reads.

    Returns:
        A reassembler that holds one stream under the key `STREAM`.
    """
    reassembler = TCPStreamReassembler(max_stream_bytes=RUN_LENGTH)
    reassembler.add_segment(STREAM, 0, FIRST)
    reassembler.add_segment(STREAM, SEGMENT_LENGTH, SECOND)
    reassembler.add_segment(STREAM, 2 * SEGMENT_LENGTH, THIRD)
    assert reassembler.streams[STREAM]["bytes"] == RUN_LENGTH
    reassembler.max_stream_bytes = cap
    return reassembler


def test_get_stream_returns_no_more_bytes_than_the_byte_cap() -> None:
    """`get_stream` returns 100 bytes where the stream stores a run of 150 bytes."""
    reassembler = _stream_past_the_byte_cap(LOW_CAP)
    assert len(reassembler.get_stream(STREAM)) == LOW_CAP


def test_get_stream_returns_the_earliest_bytes_of_the_run() -> None:
    """The truncation drops the last bytes of the run and keeps the earliest ones.

    A fingerprinter reads the request line and the certificate message, and both stand at
    the start of the run.
    """
    reassembler = _stream_past_the_byte_cap(LOW_CAP)
    assert reassembler.get_stream(STREAM) == FIRST + SECOND


def test_get_stream_returns_no_byte_where_the_byte_cap_stands_below_zero() -> None:
    """A byte cap below zero holds no byte, and the port states the same rule.

    A plain slice would read the cap as an offset from the end of the run, so it would
    return 145 bytes for a cap of -5.
    """
    reassembler = _stream_past_the_byte_cap(-5)
    assert reassembler.get_stream(STREAM) == b""


def test_get_stream_removes_no_byte_under_the_present_admission_rule() -> None:
    """The truncation removes nothing where `add_segment` admits every stored segment.

    `add_segment` refuses the segment that would cross the cap, so the stored run stands
    below the cap and the reader returns it whole.
    """
    reassembler = TCPStreamReassembler(max_stream_bytes=LOW_CAP)
    reassembler.add_segment(STREAM, 0, FIRST)
    reassembler.add_segment(STREAM, SEGMENT_LENGTH, SECOND)
    reassembler.add_segment(STREAM, 2 * SEGMENT_LENGTH, THIRD)
    assert reassembler.streams[STREAM]["bytes"] == LOW_CAP
    assert reassembler.get_stream(STREAM) == FIRST + SECOND


def test_the_module_states_the_parity_rule_that_decides_the_truncation() -> None:
    """`ja4plus/utils/tcp_stream.py` records the answer and the rule that decides it.

    A reader of the module cannot see from the code that the truncation removes nothing
    today, or that the port decides the interface.
    """
    module = MODULE.read_text(encoding="utf-8")
    assert "parity rule 2" in module
    assert "#697" in module
