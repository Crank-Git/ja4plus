"""Tests that the divergence register records the FoxIO License 1.1 disagreement.

**Three FoxIO records at the pinned commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` name
a different set of methods.** `License FAQ.md:5` names twelve, the FoxIO `README.md:293`
names nine, and `LICENSE:3` names thirteen. **No statement of equality with FoxIO's list
can therefore be true**, and the README of this project names the ten it implements as a
subset.

The user ruled on 2026-08-10. The README does not change, the divergence register carries
the contradiction, and `JA4Scan` is recorded as not implemented with no decision taken.
#466 read the three lines again at the pinned commit and #388 measured them first.

**A measurement that lives only in a closed issue is a measurement the next reader
repeats.** These cases hold the register to that record.

Every quoted FoxIO line is reproduced verbatim. `.claude/rules/ste.md` bars a rewording of
text copied from the FoxIO material.

These cases read prose. They import nothing from `ja4plus` and they produce no
fingerprint.
"""

from pathlib import Path
import re

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

# The heading of the register, and the line that closes it. The register is the last table
# of the parity section, and the citation below it names the port.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

# The header row and the separator row of the register. Neither one records a divergence.
REGISTER_HEADER = "| Item |"
REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The register held this many rows before #466 added two. **An aggregate over an empty set
# passes**, so a reader that found no row would satisfy every case below.
MINIMUM_REGISTER_ROWS = 28

# The commit of `https://github.com/FoxIO-LLC/ja4` that #466 read the three lines at.
# `docs/specs/foxio/README.md` pins the same commit.
FOXIO_COMMIT = "27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8"

# The first cell of the row that records the disagreement between the three FoxIO records.
LICENSE_ITEM = "The methods the FoxIO License 1.1 covers"

# The first cell of the row that records the state of `JA4Scan`.
SCAN_ITEM = "JA4Scan"

# The three FoxIO lines, verbatim, read at `FOXIO_COMMIT` on 2026-08-10. Each one is the
# clause of its line that names the methods. **Never reword these**, because they are
# another party's license text.
FAQ_LINE = "__JA4S, JA4L, JA4LS, JA4H, JA4X, JA4SSH, JA4T, JA4TS, JA4TScan, JA4Scan, JA4D, JA4D6 and all future additions, (collectively referred to as JA4+)__"  # noqa: E501
FOXIO_README_LINE = "**JA4S, JA4L, JA4LS, JA4H, JA4X, JA4SSH, JA4T, JA4TS, JA4TScan and all future additions, (collectively referred to as JA4+)**"  # noqa: E501
LICENSE_LINE = "Software: JA4S, JA4H, JA4L, JA4LS, JA4X, JA4T, JA4TS, JA4TScan, JA4D, JA4D6, JA4SScan, JA4E, and JA4SSH (Collectively referred to as JA4+)"  # noqa: E501

# Each FoxIO line, the reference a reader follows to it, and the count of methods it names.
# The count is written as a word, because the register states counts in words.
FOXIO_RECORDS = (
    ("License FAQ.md:5", FAQ_LINE, "twelve"),
    ("README.md:293", FOXIO_README_LINE, "nine"),
    ("LICENSE:3", LICENSE_LINE, "thirteen"),
)

# The sentence that records the state of `JA4Scan`.
NO_DECISION = "recorded no decision about JA4Scan"

# A phrase that would turn the `JA4Scan` row into a decline. **No decision about JA4Scan is
# recorded**, so a row that states a reason for a decline states something the project
# never decided.
DECLINE_PHRASES = (
    "declines JA4Scan",
    "JA4Scan is declined",
    "JA4Scan by decision",
)


def _register_rows() -> dict[str, str]:
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


def test_the_register_quotes_each_foxio_license_list_verbatim() -> None:
    """The register reproduces the three FoxIO license lines, word for word."""
    row = _row(LICENSE_ITEM)
    for reference, line, _ in FOXIO_RECORDS:
        assert line in row, f"the register holds no verbatim copy of {reference}"


def test_the_register_names_the_file_and_line_of_each_foxio_license_list() -> None:
    """The register cites the file and the line of each FoxIO license list."""
    row = _row(LICENSE_ITEM)
    for reference, _, _ in FOXIO_RECORDS:
        assert reference in row, f"the register cites no {reference}"


def test_the_register_states_the_count_of_methods_each_foxio_license_list_names() -> None:
    """The register states that the three FoxIO lists name twelve, nine and thirteen."""
    row = _row(LICENSE_ITEM)
    for reference, _, count in FOXIO_RECORDS:
        assert count in row, f"the register states no count {count!r} for {reference}"


def test_the_register_pins_the_commit_the_three_foxio_lists_were_read_at() -> None:
    """The register names the commit a reader repeats the measurement at."""
    assert FOXIO_COMMIT in _row(LICENSE_ITEM), (
        f"the register names no commit {FOXIO_COMMIT}, so a reader measures another state"
    )


def test_the_register_records_ja4scan_as_not_implemented() -> None:
    """The register states that this project implements no JA4Scan."""
    assert "Not implemented." in _row(SCAN_ITEM), "the JA4Scan row states no implementation state"


def test_the_register_records_no_decision_about_ja4scan() -> None:
    """The register states that this project took no decision about JA4Scan."""
    assert NO_DECISION in _row(SCAN_ITEM), f"the JA4Scan row holds no {NO_DECISION!r}"


def test_the_register_states_no_reason_to_decline_ja4scan() -> None:
    """The register writes no decline of JA4Scan, because the project recorded none."""
    row = _row(SCAN_ITEM)
    found = [phrase for phrase in DECLINE_PHRASES if phrase in row]
    assert not found, f"the JA4Scan row declines the method with {found}, and none was decided"
