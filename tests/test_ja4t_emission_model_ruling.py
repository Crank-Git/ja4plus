"""The JA4T emission model the divergence register records under #667.

`ja4plus` gives one JA4T value to one connection, and `ja4plus-go` gives one to each
frame that carries a readable SYN header. The two libraries produce the same value and
they produce it a different number of times. R9 of `docs/specs/foxio/JA4T.md` and D4 of
#215 hold the reading of this project, and #610 measured the divergence.

**A divergence that lives only in a closed issue is a divergence the next reader closes
by accident.** These cases hold the register row against the two emission models. A
deletion of the connection gate at `ja4plus/fingerprinters/ja4t.py:178` fails a case
here, and so does a deletion of the row.
"""

from pathlib import Path
import re

from scapy.all import ICMP, IP, TCP, rdpcap

from ja4plus.fingerprinters.ja4t import JA4TFingerprinter, generate_ja4t
from ja4plus.utils.icmp_quoted import quoted_tcp_header

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

VECTOR = REPO_ROOT / "tests" / "foxio_vectors" / "ssh2.pcapng"

# The heading of the register, and the line that closes it.
# `tests/test_ja4t_syn_selection_ruling.py` reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The JA4T emission model on the TCP header an ICMP error message quotes"

# The flag bits `ja4plus/fingerprinters/ja4t.py:172` reads on the quoted header.
TCP_SYN_FLAG = 0x02
TCP_ACK_FLAG = 0x10

# The value every one of the 31 frames gives, in both libraries.
MEASURED_VALUE = "64240_2-1-3-1-1-4_1460_8"

# The counts the register row states, measured on 2026-08-15.
QUOTED_SYN_FRAMES = 31
QUOTED_CONNECTIONS = 10
VALUES_FROM_QUOTED_FRAMES = 0
VALUES_OVER_THE_CAPTURE = 19

# Each count reads as a phrase and never as a bare digit. A row that reads `5 values` in
# place of `0 values` passes a search for the digit, because the row states a date, a line
# number and the value `1460`. The self-review of #667 measured that pass.
COUNT_PHRASES = (
    "31 frames whose quoted header is a SYN that carries no ACK",
    "those 31 frames report 10 connections",
    "the 31 frames produce 0 values",
    "produces 19 JA4T values, and 0 of them come from a quoted frame",
    "produces 31 values",
)


def _register_row() -> str:
    """Return the register row that records the emission model.

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


def _quoted_syn_frames() -> list[int]:
    """Return the index of each frame of the vector whose quoted header is a SYN.

    Returns:
        The frame index of every such frame, in capture order.
    """
    frames = []
    for index, packet in enumerate(rdpcap(str(VECTOR))):
        quoted = quoted_tcp_header(packet)
        if quoted is None:
            continue
        if not (quoted.flags & TCP_SYN_FLAG) or (quoted.flags & TCP_ACK_FLAG):
            continue
        frames.append(index)
    return frames


def _icmp_report_of_a_syn(sport: int) -> object:
    """Return one ICMP error message that quotes the SYN of a connection.

    Args:
        sport: The source port of the quoted SYN, which parts one connection from
            another.

    Returns:
        The packet, read back from its own bytes. A message that scapy never serialized
        keeps a `TCP` layer, and a message of the wire carries `TCPerror` instead.
    """
    syn = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
        sport=sport, dport=443, flags="S", window=65535, options=[("WScale", 7)]
    )
    message = IP(src="10.0.0.9", dst="10.0.0.1") / ICMP(type=3, code=1) / syn
    return IP(bytes(message))


def test_the_register_holds_a_row_for_the_emission_model() -> None:
    """The divergence register holds the row that records the emission model."""
    assert RULING_ITEM in _register_row()


def test_the_register_states_the_line_that_holds_the_connection_gate() -> None:
    """The row names the line of `ja4plus` that reads the connection table."""
    assert "`ja4plus/fingerprinters/ja4t.py:178`" in _register_row()


def test_the_register_names_the_ruling_that_holds_the_reading() -> None:
    """The row names R9, the issue that built the connection table and the measurement."""
    row = _register_row()
    absent = [
        citation
        for citation in ("R9", "#215", "#610", "#667", "`ja4t_icmp_quoted_test.go:16`")
        if citation not in row
    ]
    assert absent == [], f"the row names none of these records: {absent}"


def test_the_register_states_every_count_of_the_measurement() -> None:
    """The row states the frame count, the connection count and both value counts."""
    row = _register_row()
    absent = [phrase for phrase in COUNT_PHRASES if phrase not in row]
    assert absent == [], f"the row states none of these counts: {absent}"


def test_each_count_phrase_holds_the_count_the_cases_measure() -> None:
    """Each phrase of the row carries the number the cases read from the vector."""
    counts = (
        QUOTED_SYN_FRAMES,
        QUOTED_CONNECTIONS,
        VALUES_FROM_QUOTED_FRAMES,
        VALUES_OVER_THE_CAPTURE,
    )
    numbers = {int(number) for phrase in COUNT_PHRASES for number in re.findall(r"\d+", phrase)}
    assert set(counts) <= numbers


def test_the_register_states_the_value_the_two_libraries_agree_on() -> None:
    """The row states the one value every quoted SYN frame gives."""
    assert f"`{MEASURED_VALUE}`" in _register_row()


def test_the_vector_holds_thirty_one_frames_that_quote_a_syn() -> None:
    """`ssh2.pcapng` holds 31 frames whose quoted header is a SYN without an ACK."""
    assert len(_quoted_syn_frames()) == QUOTED_SYN_FRAMES


def test_those_frames_report_ten_connections() -> None:
    """The 31 frames report 10 distinct connections."""
    packets = rdpcap(str(VECTOR))
    keys = set()
    for index in _quoted_syn_frames():
        quoted = quoted_tcp_header(packets[index])
        assert quoted is not None
        keys.add((quoted.src, quoted.sport, quoted.dst, quoted.dport))
    assert len(keys) == QUOTED_CONNECTIONS


def test_this_project_gives_no_value_to_a_quoted_frame_of_the_vector() -> None:
    """One fingerprinter over the whole capture gives no value to a quoted SYN frame."""
    packets = rdpcap(str(VECTOR))
    quoted_indices = set(_quoted_syn_frames())
    fingerprinter = JA4TFingerprinter()
    values = [(index, fingerprinter.process_packet(packet)) for index, packet in enumerate(packets)]
    produced = [(index, value) for index, value in values if value is not None]
    from_quoted = [index for index, _ in produced if index in quoted_indices]
    assert len(produced) == VALUES_OVER_THE_CAPTURE
    assert from_quoted == []


def test_the_emission_model_of_the_port_gives_one_value_to_each_quoted_frame() -> None:
    """A reader that holds no connection table gives 31 values, and each one agrees."""
    packets = rdpcap(str(VECTOR))
    values = [generate_ja4t(packets[index]) for index in _quoted_syn_frames()]
    assert values == [MEASURED_VALUE] * QUOTED_SYN_FRAMES


def test_a_captured_syn_bars_the_message_that_reports_that_same_syn() -> None:
    """The message that reports a fingerprinted SYN gives no second value."""
    fingerprinter = JA4TFingerprinter()
    syn = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
        sport=54321, dport=443, flags="S", window=65535, options=[("WScale", 7)]
    )
    assert fingerprinter.process_packet(syn) is not None
    assert fingerprinter.process_packet(_icmp_report_of_a_syn(54321)) is None


def test_the_first_message_of_a_connection_gives_a_value() -> None:
    """A message that reports a SYN of an unread connection gives one value."""
    fingerprinter = JA4TFingerprinter()
    assert fingerprinter.process_packet(_icmp_report_of_a_syn(54322)) is not None


def test_a_second_message_of_one_connection_gives_no_second_value() -> None:
    """Two messages that report one connection give one value between them."""
    fingerprinter = JA4TFingerprinter()
    assert fingerprinter.process_packet(_icmp_report_of_a_syn(54323)) is not None
    assert fingerprinter.process_packet(_icmp_report_of_a_syn(54323)) is None
