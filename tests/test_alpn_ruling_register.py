"""Tests that the divergence register records the JA4 ALPN ruling of 2026-08-10.

**The user ruled on 2026-08-10 that the form of `ja4plus` stands.** A first ALPN value
whose first byte or last byte falls outside `0x20-0x7E` writes `99`. A first ALPN value
of one alphanumeric byte writes `hh`.

The conformance audit of the same date named this the one condition where `ja4plus`
matches no FoxIO implementation. The two references disagree with each other, and each
one reads its own tooling rather than the packet.

| Implementation | Value | What it reads |
|---|---|---|
| `ja4plus` | `99`, `hh` | the packet bytes |
| FoxIO Python | U+FFFD | a replacement character that no packet byte holds |
| FoxIO Rust | `h9` | the escape text of `tshark` |

**A match with either reference copies an artifact of that reference tool into the
fingerprint**, and the user declines that. No FoxIO reading is therefore available to
adopt here.

**A ruling that lives only in a closed issue is a ruling the next reader reverses by
accident.** These cases hold the register to the record. A later edit that drops the
ruling fails a case here rather than passing quietly.

#141 holds the measurement of the disputed inputs, #162 records the readings of
2026-08-07, and #522 records this ruling. The sixteen entries of
`tests/foxio_deviations.json` that name #162 stand, and a case below reads that count.

These cases read prose and one JSON record. They import nothing from `ja4plus` and they
produce no fingerprint.
"""

import json
from pathlib import Path
import re
from typing import Dict, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

DEVIATIONS = REPO_ROOT / "tests" / "foxio_deviations.json"

# The heading of the register, and the line that closes it. The register is the last table
# of the parity section, and the citation below it names the port.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

# The header row and the separator row of the register. Neither one records a divergence.
REGISTER_HEADER = "| Item |"
REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The register held this many rows before #522 added one. **An aggregate over an empty set
# passes**, so a reader that found no row would satisfy every case below.
MINIMUM_REGISTER_ROWS = 30

# The first cell of the row that records the ruling.
RULING_ITEM = "The JA4 ALPN form that matches no FoxIO implementation"

# The date the user ruled.
RULING_DATE = "2026-08-10"

# The end of a sentence of a register cell. **A reader of the whole row passes on a row
# that gives one implementation the value of another.** All three values still reach such
# a reader. The reader below binds each value to the sentence that names its own
# implementation.
SENTENCE_END = ". "

# Each implementation, the phrase a reader follows to it, and the values that phrase
# states. The phrase reaches one sentence of the row, so a row that moves a value to
# another sentence fails the case.
MEASUREMENT: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    ("`ja4plus`", "reads the packet bytes", ("`99`", "`hh`")),
    ("FoxIO Python", "FoxIO Python", ("`U+FFFD`",)),
    ("FoxIO Rust", "FoxIO Rust", ("`h9`",)),
)

# The sentence that states the ruling itself.
RULING = "the form of `ja4plus` stands"

# The sentence that states that this project adopts no FoxIO reading here.
NO_READING = "No FoxIO reading is available to adopt here"

# The sentence that states the scope of the condition.
ONE_CONDITION = "the one condition where `ja4plus` matches no FoxIO implementation"

# The issue that records the ruling.
RULING_ISSUE = "#522"

# The first cell of the row that #127 wrote. **The row states the value `99`**, and #601
# restated the condition that triggers it.
CONDITION_ITEM = "JA4 ALPN value for a byte outside `0x20-0x7E`"

# The first cell of the row that states the position rule. A byte outside the printable
# range, in a position other than the first, keeps `99`.
POSITION_ITEM = "JA4 ALPN value for a byte outside `0x20-0x7E` in a position other than the first"

# The condition `compute_alpn_value` applies at `ja4plus/fingerprinters/ja4.py:99`.
PRINTABLE_RANGE = "`0x20-0x7E`"

# The condition the FoxIO prose states, which the measurement of #141 contradicts. **A row
# that states it sends a reader to the wrong test**, and the Go port read these rows.
LOOSE_CONDITION = "not alphanumeric"

# Every row of the register that states the JA4 ALPN condition of a value of two bytes or
# more.
CONDITION_ROWS = (CONDITION_ITEM, POSITION_ITEM, RULING_ITEM)

# The first cell of the row that states the one-byte rule.
ONE_BYTE_ITEM = "JA4 ALPN value for a first ALPN value of one byte"

# **A one-byte value reads the alphanumeric test and not the printable range**, which
# `ja4plus/fingerprinters/ja4.py:86` applies. A row that states the range alone writes `hh`
# for a first ALPN value of one space, and the code writes `99`.
ONE_BYTE_CONDITION = "alphanumeric"

# Every row of the register that states the JA4 ALPN condition of a one-byte value.
ONE_BYTE_ROWS = (ONE_BYTE_ITEM, RULING_ITEM)

# The issue that records the readings of 2026-08-07, and the count of entries that name it
# in `tests/foxio_deviations.json`. **The ruling of #522 moves no entry**, so a change of
# this count is a change the ruling did not authorize.
DEVIATION_ISSUE = 162
DEVIATION_ENTRIES = 16


def _register_rows() -> Dict[str, str]:
    """Return the divergence register of the specification, keyed by the first cell.

    Returns:
        The whole text of each row, keyed by the item the row names.

    Raises:
        AssertionError: The page holds no register, or the register holds fewer rows than
            the recorded floor.
    """
    page = SPECIFICATION.read_text(encoding="utf-8")
    assert REGISTER_HEADING in page, f"the specification holds no {REGISTER_HEADING!r}"
    section = page[page.index(REGISTER_HEADING) : page.index(REGISTER_END)]
    rows = {}
    for line in section.splitlines():
        if not line.startswith("|") or line.startswith(REGISTER_HEADER):
            continue
        if REGISTER_SEPARATOR.match(line):
            continue
        rows[line.split("|")[1].strip()] = line
    assert len(rows) >= MINIMUM_REGISTER_ROWS, (
        f"the reader found {len(rows)} register rows, and the floor is {MINIMUM_REGISTER_ROWS}"
    )
    return rows


def _row(item: str) -> str:
    """Return one row of the divergence register.

    Args:
        item: The text of the first cell of the row.

    Returns:
        The whole text of the row.

    Raises:
        AssertionError: The register holds no row that names the item.
    """
    rows = _register_rows()
    assert item in rows, f"the divergence register holds no row named {item!r}"
    return rows[item]


def _sentence_of(phrase: str) -> str:
    """Return the sentence of the ruling row that holds one phrase.

    Args:
        phrase: The text a reader follows to one sentence of the row.

    Returns:
        The one sentence that holds the phrase.

    Raises:
        AssertionError: The row holds no such sentence. The row holds more than one such
            sentence, and a reader cannot tell which one states the record.
    """
    found = [part for part in _row(RULING_ITEM).split(SENTENCE_END) if phrase in part]
    assert found, f"the ruling row holds no sentence that states {phrase!r}"
    assert len(found) == 1, (
        f"the ruling row holds {len(found)} sentences that state {phrase!r}, and a reader "
        f"cannot tell which one holds the record"
    )
    return found[0]


def _entries_that_name(issue: int) -> Sequence[str]:
    """Return every deviation key whose entry names one issue.

    Args:
        issue: The issue number the entry records.

    Returns:
        The keys, sorted.
    """
    register = json.loads(DEVIATIONS.read_text(encoding="utf-8"))
    return sorted(key for key, entry in register.items() if entry.get("issue") == issue)


def test_the_register_holds_a_row_for_the_alpn_ruling() -> None:
    """The divergence register names the JA4 ALPN form the ruling covers."""
    _row(RULING_ITEM)


def test_the_register_states_the_ruling() -> None:
    """The register states that the form of `ja4plus` stands."""
    assert RULING in _row(RULING_ITEM), f"the ruling row holds no {RULING!r}"


def test_the_register_states_the_date_of_the_ruling() -> None:
    """The register names the date the user ruled, beside the ruling itself."""
    assert RULING_DATE in _sentence_of(RULING), (
        f"the sentence that states the ruling names no date {RULING_DATE}"
    )


def test_the_register_states_the_value_of_each_implementation() -> None:
    """The register binds `99` and `hh` to `ja4plus`, `U+FFFD` to Python and `h9` to Rust."""
    for implementation, phrase, values in MEASUREMENT:
        sentence = _sentence_of(phrase)
        for value in values:
            assert value in sentence, (
                f"the sentence that names {implementation} states no value {value}"
            )


def test_the_register_states_that_no_foxio_reading_reaches_this_condition() -> None:
    """The register states that this project adopts no FoxIO reading here."""
    assert NO_READING in _row(RULING_ITEM), f"the ruling row holds no {NO_READING!r}"


def test_the_register_names_this_the_one_condition_that_matches_no_reference() -> None:
    """The register states the scope the conformance audit measured."""
    assert ONE_CONDITION in _row(RULING_ITEM), f"the ruling row holds no {ONE_CONDITION!r}"


def test_the_register_cites_the_issue_that_records_the_ruling() -> None:
    """The register names the issue a reader follows to the ruling."""
    assert RULING_ISSUE in _row(RULING_ITEM), f"the ruling row cites no {RULING_ISSUE}"


def test_every_alpn_row_states_the_condition_as_the_printable_ascii_range() -> None:
    """Each ALPN row of the register names the range `0x20-0x7E`."""
    for item in CONDITION_ROWS:
        assert PRINTABLE_RANGE in _row(item), (
            f"the row named {item!r} states no range {PRINTABLE_RANGE}"
        )


def test_no_alpn_row_states_the_condition_as_the_alphanumeric_test() -> None:
    """No ALPN row of the register states the condition the measurement contradicts."""
    for item in CONDITION_ROWS:
        assert LOOSE_CONDITION not in _row(item), (
            f"the row named {item!r} states the condition as {LOOSE_CONDITION!r}, and "
            f"`ja4plus/fingerprinters/ja4.py:99` tests the range {PRINTABLE_RANGE}"
        )


def test_every_one_byte_row_names_the_alphanumeric_condition() -> None:
    """Each one-byte row of the register names the condition that writes `hh`."""
    for item in ONE_BYTE_ROWS:
        assert ONE_BYTE_CONDITION in _row(item), (
            f"the row named {item!r} names no {ONE_BYTE_CONDITION} byte, and "
            f"`ja4plus/fingerprinters/ja4.py:86` writes `hh` for no other one-byte value"
        )


def test_the_ruling_moves_no_entry_of_the_deviation_register() -> None:
    """The deviation register keeps the sixteen entries that name #162."""
    entries = _entries_that_name(DEVIATION_ISSUE)
    assert len(entries) == DEVIATION_ENTRIES, (
        f"the deviation register holds {len(entries)} entries that name #{DEVIATION_ISSUE}, "
        f"and the ruling of {RULING_ISSUE} moves none of the {DEVIATION_ENTRIES}"
    )
