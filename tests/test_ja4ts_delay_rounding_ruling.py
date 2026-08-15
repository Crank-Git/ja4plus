"""The rule that reads a JA4TS delay in whole seconds, which #602 records.

`ja4plus/fingerprinters/ja4ts.py:63` rounds each delay to the nearest second, half away
from zero. Two FoxIO implementations split on that reading. The Wireshark dissector calls
the C `round`, and the Zeek script truncates an integer count of microseconds.

**A ruling that lives only in a closed issue is a ruling the next reader reverses by
accident.** These cases hold the register row against the code it describes. A change of
line 63 to a truncation fails a case here, and so does a deletion of the row.

`Crank-Git/ja4plus-go#56` holds the ruling of 2026-08-13, and the port rounds the same
way. A reversal therefore changes both repositories.

The body of #602 names `Crank-Git/ja4plus-go#126` for that ruling. #126 rules on the SYN
and the RST that JA4T reads, so the case below reads #56 and refuses #126.
"""

from pathlib import Path
import re

from scapy.all import IP, TCP

from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter, _delay_seconds

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

# The heading of the register, and the line that closes it.
# `tests/test_ja4t_syn_selection_ruling.py` reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The rule that reads a JA4TS delay in whole seconds"

# The delay that separates the two readings, and the value each one writes. A truncation
# writes the second number.
SEPARATING_DELAY = 1.6
ROUNDED = 2
TRUNCATED = 1

# The two SYN-ACK timestamps of `ssh2.pcapng`, which hold the one part e delay of the
# corpus. The delay is 0.0058 seconds, so both readings write `0`.
SSH2_FIRST_SYN_ACK = 1688672871.34796
SSH2_SECOND_SYN_ACK = 1688672871.353789

# The connection every constructed case below builds. Part a through part d never
# changes, so each case reads part e alone.
SERVER = "10.0.0.1"
CLIENT = "10.0.0.2"
PARTS_A_TO_D = "65535_2-1-3-1-1-4_65495_8"
SERVER_OPTIONS = [
    ("MSS", 65495),
    ("NOP", None),
    ("WScale", 8),
    ("NOP", None),
    ("NOP", None),
    ("SAckOK", b""),
]


def _register_row() -> str:
    """Return the register row that records the rule.

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


def _syn_ack(time: float) -> object:
    """Return one SYN-ACK packet that arrives at the capture time.

    Args:
        time: The capture timestamp, in seconds.

    Returns:
        The packet.
    """
    packet = IP(src=SERVER, dst=CLIENT) / TCP(
        flags="SA", window=65535, sport=443, dport=50000, options=SERVER_OPTIONS
    )
    packet.time = time
    return packet


def _reset(time: float) -> object:
    """Return one RST packet that the server sends at the capture time.

    Args:
        time: The capture timestamp, in seconds.

    Returns:
        The packet. A RST packet carries no window size and no option, so this one
        carries neither.
    """
    packet = IP(src=SERVER, dst=CLIENT) / TCP(flags="R", window=0, sport=443, dport=50000)
    packet.time = time
    return packet


def test_the_register_holds_a_row_for_the_rule() -> None:
    """The divergence register holds the row that records the rule."""
    assert RULING_ITEM in _register_row()


def test_the_register_states_the_line_that_rounds_the_delay() -> None:
    """The row names the line of `ja4plus` that rounds the delay."""
    assert "`ja4plus/fingerprinters/ja4ts.py:63`" in _register_row()


def test_the_register_cites_each_of_the_two_references() -> None:
    """The row cites the Wireshark dissector and the Zeek script, on each delay."""
    row = _register_row()
    absent = [
        citation
        for citation in (
            "`wireshark/source/packet-ja4.c:274`",
            "`wireshark/source/packet-ja4.c:277`",
            "`wireshark/source/packet-ja4.c:687`",
            "`wireshark/source/packet-ja4.c:694`",
            "`zeek/ja4t/main.zeek:180`",
            "`zeek/ja4t/main.zeek:233`",
        )
        if citation not in row
    ]
    assert absent == [], f"the row cites none of these references: {absent}"


def test_the_register_names_the_issue_that_holds_the_ruling() -> None:
    """The row names the issue of the port that holds the ruling of 2026-08-13."""
    row = _register_row()
    assert "`Crank-Git/ja4plus-go#56`" in row
    assert "2026-08-13" in row


def test_the_register_states_which_issue_of_the_port_holds_the_ruling() -> None:
    """The row reads the ruling out of #56, and it names #126 as another ruling."""
    row = _register_row()
    ruling = row.index("`Crank-Git/ja4plus-go#56`")
    assert "the same issue built it" in row[ruling : ruling + 120]
    assert "#126 rules on the SYN and the RST that JA4T reads" in row


def test_the_register_states_the_delay_that_separates_the_two_readings() -> None:
    """The row states the delay of 1.6 seconds and the value each reading writes."""
    row = _register_row()
    assert f"{SEPARATING_DELAY} seconds" in row


def test_a_delay_above_one_half_rounds_up() -> None:
    """A delay of 1.6 seconds writes `2`, and a truncation writes `1`."""
    assert _delay_seconds(SEPARATING_DELAY, 0.0) == ROUNDED
    assert int(SEPARATING_DELAY) == TRUNCATED


def test_a_delay_below_one_half_rounds_down() -> None:
    """A delay of 1.4 seconds writes `1`."""
    assert _delay_seconds(1.4, 0.0) == 1


def test_a_half_second_delay_rounds_away_from_zero() -> None:
    """A delay of half a second writes `1`, where the Python built-in writes `0`."""
    assert _delay_seconds(0.5, 0.0) == 1
    assert round(0.5) == 0


def test_a_negative_half_second_delay_rounds_away_from_zero() -> None:
    """A delay of minus half a second writes `-1`."""
    assert _delay_seconds(0.0, 0.5) == -1


def test_a_negative_delay_above_one_half_rounds_away_from_zero() -> None:
    """A delay of minus 1.6 seconds writes `-2`."""
    assert _delay_seconds(0.0, SEPARATING_DELAY) == -ROUNDED


def test_the_worked_example_of_the_deleted_foxio_file_separates_no_reading() -> None:
    """The delay `6.009` of the deleted file writes `6` under each reading."""
    assert _delay_seconds(37.723966, 31.714762) == 6
    assert int(37.723966 - 31.714762) == 6


def test_part_e_writes_the_rounded_delay() -> None:
    """A second SYN-ACK 1.6 seconds later writes `2` in part e."""
    fingerprinter = JA4TSFingerprinter()
    fingerprinter.process_packet(_syn_ack(1000.0))
    value = fingerprinter.process_packet(_syn_ack(1000.0 + SEPARATING_DELAY))
    assert value == f"{PARTS_A_TO_D}_{ROUNDED}"


def test_the_reset_suffix_writes_the_rounded_delay() -> None:
    """A RST 2.5 seconds after the last SYN-ACK writes `-R3`."""
    fingerprinter = JA4TSFingerprinter()
    fingerprinter.process_packet(_syn_ack(1000.0))
    fingerprinter.process_packet(_syn_ack(1001.0))
    value = fingerprinter.process_packet(_reset(1003.5))
    assert value == f"{PARTS_A_TO_D}_1-R3"


def test_the_one_part_e_delay_of_the_corpus_separates_no_reading() -> None:
    """The two SYN-ACKs of `ssh2.pcapng` write `0` under each reading."""
    assert (VECTORS / "ssh2.pcapng").exists()
    assert _delay_seconds(SSH2_SECOND_SYN_ACK, SSH2_FIRST_SYN_ACK) == 0
    assert int(SSH2_SECOND_SYN_ACK - SSH2_FIRST_SYN_ACK) == 0
