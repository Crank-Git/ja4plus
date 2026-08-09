"""Tests that every Changelog round number of `docs/specs/spec.md` is unique.

A round number is a citation target. `tests/foxio_deviations.py` accepts the form
`Changelog round 66 settled the marker.` as the cause of a register entry, and
`tests/test_foxio_deviations.py` matches it. A reader who follows such a citation to a
number that two rows carry reaches two rounds and cannot tell which one decided.

#258 found the number 9 on two rows. The repair folded the two rows into one row and
renumbered nothing, because round numbers are identifiers and the date column carries
the order. These cases hold the repair, so that a later duplicate fails here rather than
in a review.

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


def _round_numbers() -> list[int]:
    """Return the round number of every Changelog row of the specification, in file order.

    Returns:
        One integer for each row, including a number that two rows carry.

    Raises:
        AssertionError: The page holds fewer rows than the recorded floor.
    """
    text = SPECIFICATION.read_text(encoding="utf-8")
    numbers = [
        int(match.group(1))
        for line in text.splitlines()
        for match in [CHANGELOG_ROW.match(line)]
        if match
    ]
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
