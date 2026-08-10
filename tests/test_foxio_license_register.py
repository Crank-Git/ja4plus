"""Tests that the divergence register records the FoxIO License 1.1 disagreement.

**Three FoxIO records at the pinned commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` name
a different set of methods.** `License FAQ.md:5` names twelve, the FoxIO `README.md:293`
names nine, and `LICENSE:3` names thirteen. **No statement of equality with FoxIO's list
can therefore be true**, and the README of this project names the ten it implements as a
subset.

The user ruled on 2026-08-10. The README does not change, the divergence register carries
the contradiction, and `JA4Scan` is recorded as not implemented with no ruling taken.
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

# The end of a sentence of a register cell. **A reader of the whole row passes on a row
# that gives one record the count of another.** All three counts still reach such a reader.
# The reader below binds each count and each quotation to the sentence that names its own
# reference.
SENTENCE_END = ". "

# Each FoxIO line, the reference a reader follows to it, and the count of methods it names.
# The count is written as a word, because the register states counts in words.
FOXIO_RECORDS = (
    ("License FAQ.md:5", FAQ_LINE, "twelve"),
    ("README.md:293", FOXIO_README_LINE, "nine"),
    ("LICENSE:3", LICENSE_LINE, "thirteen"),
)

# The sentence that records the state of `JA4Scan`.
NO_RULING = "recorded no ruling about JA4Scan"

# A phrase that would turn the `JA4Scan` row into a decline. **No ruling about JA4Scan is
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


def _sentence_of(reference: str) -> str:
    """Return the sentence of the license row that names one FoxIO reference.

    Args:
        reference: The `file:line` reference, as `License FAQ.md:5`.

    Returns:
        The one sentence that names the reference.

    Raises:
        AssertionError: The row holds no sentence that names the reference. The row holds
            more than one such sentence, and a reader cannot tell which one holds the
            record.
    """
    found = [part for part in _row(LICENSE_ITEM).split(SENTENCE_END) if reference in part]
    assert found, f"the license row cites no {reference}"
    assert len(found) == 1, (
        f"the license row holds {len(found)} sentences that name {reference}, and a reader "
        f"cannot tell which one states the record"
    )
    return found[0]


def test_the_register_names_the_file_and_line_of_each_foxio_license_list() -> None:
    """The register cites the file and the line of each FoxIO license list once."""
    for reference, _, _ in FOXIO_RECORDS:
        _sentence_of(reference)


def test_the_register_quotes_each_foxio_license_list_verbatim() -> None:
    """The register reproduces the three FoxIO license lines, word for word."""
    for reference, line, _ in FOXIO_RECORDS:
        assert line in _sentence_of(reference), (
            f"the sentence that cites {reference} holds no verbatim copy of that line"
        )


def test_the_register_states_the_count_of_methods_each_foxio_license_list_names() -> None:
    """The register states that the three FoxIO lists name twelve, nine and thirteen."""
    for reference, _, count in FOXIO_RECORDS:
        assert count in _sentence_of(reference), (
            f"the sentence that cites {reference} states no count {count!r}"
        )


def test_the_register_pins_the_commit_the_three_foxio_lists_were_read_at() -> None:
    """The register names the commit a reader repeats the measurement at."""
    assert FOXIO_COMMIT in _row(LICENSE_ITEM), (
        f"the register names no commit {FOXIO_COMMIT}, so a reader measures another state"
    )


def test_the_register_records_ja4scan_as_not_implemented() -> None:
    """The register states that this project implements no JA4Scan."""
    assert "Not implemented." in _row(SCAN_ITEM), "the JA4Scan row states no implementation state"


def test_the_register_records_no_ruling_about_ja4scan() -> None:
    """The register states that this project took no ruling about JA4Scan."""
    assert NO_RULING in _row(SCAN_ITEM), f"the JA4Scan row holds no {NO_RULING!r}"


def test_the_register_states_no_reason_to_decline_ja4scan() -> None:
    """The register writes no decline of JA4Scan, because the project recorded none."""
    row = _row(SCAN_ITEM)
    found = [phrase for phrase in DECLINE_PHRASES if phrase in row]
    assert not found, f"the JA4Scan row declines the method with {found}, and none was decided"
