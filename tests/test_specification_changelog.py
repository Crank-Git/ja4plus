"""Tests that every Changelog round number of `docs/specs/spec.md` is unique.

A round number is a citation target. `tests/foxio_deviations.py` accepts the form
`Changelog round 66 settled the marker.` as the cause of a register entry, and
`tests/test_foxio_deviations.py` matches it. A reader who follows such a citation to a
number that two rows carry reaches two rounds and cannot tell which one decided.

#258 found the number 9 on two rows. The repair folded the two rows into one row and
renumbered nothing, because round numbers are identifiers and the date column carries
the order. These cases hold the repair, so that a later duplicate fails here rather than
in a review.

**#482 found a shape that the row-count rule cannot see.** `row count == highest round`
reads a table that carries 168 twice and 170 nowhere as correct, because the count and
the maximum both still read right under the wrong pairing.
`test_the_row_count_rule_passes_on_a_table_that_repeats_a_round` records that
measurement, and `_contiguity_failures` is the reader that reports the shape.

These cases read prose. They import nothing from `ja4plus` and they produce no
fingerprint.
"""

from collections import Counter
from pathlib import Path
import re

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

# A Changelog row opens with the round number and the date, as
# `| 9 | 2026-08-06 | ... |`. The date distinguishes a Changelog row from every other
# table of the page. A row of the Terms table or the divergence register therefore
# reaches no case here.
CHANGELOG_ROW = re.compile(r"^\|\s*(\d+)\s*\|\s*\d{4}-\d{2}-\d{2}\s*\|")

# The Changelog held this many numbered rows when #258 landed. A parser that reads
# nothing passes every case below on an empty list. The floor fails such a parser.
# A row whose round is the literal `TBD` carries no number, so it reaches no case here
# until the project manager assigns its round.
MINIMUM_ROWS = 124


def _table(rounds: list[str]) -> str:
    """Return a Changelog table that opens one row with each round of the list.

    Args:
        rounds: The text that opens each row, either a number or the literal `TBD`.

    Returns:
        The rows of the table, one to a line.
    """
    return "\n".join(f"| {round_read} | 2026-08-10 | #1 landed. |" for round_read in rounds)


def _round_numbers_of(text: str) -> list[int]:
    """Return the round number of every numbered Changelog row of the text, in file order.

    Args:
        text: The lines that hold the Changelog table.

    Returns:
        One integer for each numbered row, including a number that two rows carry. A row
        that reads `TBD` carries no number and reaches no entry.
    """
    return [
        int(match.group(1))
        for line in text.splitlines()
        for match in [CHANGELOG_ROW.match(line)]
        if match
    ]


def _round_numbers() -> list[int]:
    """Return the round number of every Changelog row of the specification, in file order.

    Returns:
        One integer for each row, including a number that two rows carry.

    Raises:
        AssertionError: The page holds fewer rows than the recorded floor.
    """
    numbers = _round_numbers_of(SPECIFICATION.read_text(encoding="utf-8"))
    assert len(numbers) >= MINIMUM_ROWS, (
        f"the parser read {len(numbers)} Changelog rows, and the floor is {MINIMUM_ROWS}"
    )
    return numbers


def test_every_changelog_round_number_names_one_row() -> None:
    """`docs/specs/spec.md` holds one row for each Changelog round number."""
    repeated = sorted(number for number, count in Counter(_round_numbers()).items() if count > 1)
    assert repeated == [], f"these round numbers name more than one row: {repeated}"


def test_the_changelog_row_count_equals_the_highest_round_number() -> None:
    """The Changelog holds as many rows as the highest round number it records."""
    numbers = _round_numbers()
    assert len(numbers) == max(numbers), (
        f"the Changelog holds {len(numbers)} rows and its highest round is {max(numbers)}"
    )


def test_the_changelog_assigns_every_round_from_one_to_the_row_count() -> None:
    """The Changelog carries one row for each round from 1 to the count of numbered rows."""
    assert _contiguity_failures(_round_numbers()) == []


# Four rows, and the round 2 opens two of them while no row opens with 3. The count reads
# 4 and the maximum reads 4, so `row count == highest round` passes on this table. #482
# measured that pairing on `batch/476-count-repairs` and this constant holds it.
TABLE_THAT_REPEATS_A_ROUND = _table(["1", "2", "2", "4"])

# Three rows, and no row opens with 3. A gap alone raises the maximum above the count, so
# the row-count rule reads this table. The contiguity reader reads it too, and a case
# below proves that.
TABLE_THAT_HOLDS_A_GAP = _table(["1", "2", "4"])

# Four numbered rows and two rows that wait for their round. An integration branch carries
# this shape for every member that has not reached the batch gate, so it stays legal.
TABLE_WHOSE_NEW_ROWS_WAIT = _table(["1", "2", "3", "4", "TBD", "TBD"])

TABLE_THAT_ASSIGNS_EVERY_ROUND_ONCE = _table(["1", "2", "3", "4"])

# Every row waits for its round, so the parser reads no number. An aggregate over an empty
# list passes every rule above, and the reader must fail on it instead.
TABLE_THAT_NAMES_NO_NUMBERED_ROW = _table(["TBD", "TBD"])


def test_the_row_count_rule_passes_on_a_table_that_repeats_a_round() -> None:
    """`row count == highest round` reads a table that repeats a round as correct."""
    numbers = _round_numbers_of(TABLE_THAT_REPEATS_A_ROUND)
    assert len(numbers) == max(numbers)


def test_the_reader_fails_on_a_table_that_repeats_a_round() -> None:
    """The contiguity reader reports a round number that opens two rows."""
    failures = _contiguity_failures(_round_numbers_of(TABLE_THAT_REPEATS_A_ROUND))
    assert failures == [
        "these round numbers open more than one row: [2]",
        "these rounds from 1 to 4 open no row: [3]",
    ]


def test_the_reader_fails_on_a_table_that_holds_a_gap() -> None:
    """The contiguity reader reports a round from 1 to the row count that opens no row."""
    failures = _contiguity_failures(_round_numbers_of(TABLE_THAT_HOLDS_A_GAP))
    assert failures == ["these rounds from 1 to 3 open no row: [3]"]


def test_the_reader_passes_on_a_table_that_assigns_every_round_once() -> None:
    """The contiguity reader reports nothing on a table that assigns 1 to the row count."""
    assert _contiguity_failures(_round_numbers_of(TABLE_THAT_ASSIGNS_EVERY_ROUND_ONCE)) == []


def test_the_reader_passes_on_a_table_whose_new_rows_wait_for_a_round() -> None:
    """The contiguity reader reports nothing on a table whose new rows read `TBD`."""
    assert _contiguity_failures(_round_numbers_of(TABLE_WHOSE_NEW_ROWS_WAIT)) == []


def test_the_reader_fails_on_a_table_that_names_no_numbered_row() -> None:
    """The contiguity reader reports a table from which it read no round number."""
    failures = _contiguity_failures(_round_numbers_of(TABLE_THAT_NAMES_NO_NUMBERED_ROW))
    assert failures == ["the reader read no numbered Changelog row"]
