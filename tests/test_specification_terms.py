"""Tests that the `Terms` table of `docs/specs/spec.md` holds one row for each term.

`.claude/rules/ste.md` names this table the controlled vocabulary of the project, and it
states one rule a reader cannot check by eye: one word, one meaning. A term that reaches
the table twice breaks that rule, because a writer who reads the first row and a writer
who reads the second row write two different things and both cite the table.

**The defect this file exists to catch is a term added twice, and not a term left out.**
An epic that writes with a new word adds a row. An epic that adds a word the table
already holds under another spelling creates the duplicate, and a reader who scrolls a
67-row table does not see it. #407 added five rows and needed the check before it wrote
them.

Every row also names the words a writer does not use for that term. A row with an empty
`Do not use` column states the meaning and bars nothing, so the next writer picks a
synonym and the table does not oppose it.

These cases read prose. They import nothing from `ja4plus` and they produce no
fingerprint.
"""

from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

# The `Terms` table is the whole body of the `## Terms` section, and `## Goals` opens the
# next section. A row of another table of the page therefore reaches no case here.
TERMS_HEADING = "## Terms"
NEXT_HEADING = "## Goals"

# The table opens with the column header and the separator, and neither is a term.
HEADER_ROWS = 2

# The table held this many rows when #407 landed: 67 before it, plus the five words
# Epic 11 writes with. A parser that reads nothing passes every case below on an empty
# list, so the floor fails such a parser.
MINIMUM_TERM_ROWS = 72

# A row carries four columns: the term, its part of speech, its meaning, and the words a
# writer does not use for it.
COLUMN_COUNT = 4


def _term_rows() -> list[list[str]]:
    """Return the columns of every row of the `Terms` table, in file order.

    Returns:
        One list of four stripped column values for each row, including a term that two
        rows carry.

    Raises:
        AssertionError: The page holds no `Terms` section, or it holds fewer rows than
            the recorded floor, or one row does not carry four columns.
    """
    lines = SPECIFICATION.read_text(encoding="utf-8").splitlines()
    assert TERMS_HEADING in lines, f"{SPECIFICATION} holds no {TERMS_HEADING} section"
    start = lines.index(TERMS_HEADING)
    assert NEXT_HEADING in lines[start:], f"{SPECIFICATION} holds no {NEXT_HEADING} heading"
    end = start + lines[start:].index(NEXT_HEADING)

    rows: list[list[str]] = []
    for line in lines[start:end]:
        if not line.startswith("|"):
            continue
        columns = [column.strip() for column in line.strip().strip("|").split("|")]
        assert len(columns) == COLUMN_COUNT, f"this row carries {len(columns)} columns: {line}"
        rows.append(columns)

    rows = rows[HEADER_ROWS:]
    assert len(rows) >= MINIMUM_TERM_ROWS, (
        f"the parser read {len(rows)} term rows, and the floor is {MINIMUM_TERM_ROWS}"
    )
    return rows


def test_every_term_of_the_specification_names_one_row() -> None:
    """The `Terms` table of `docs/specs/spec.md` holds one row for each term."""
    terms = [row[0] for row in _term_rows()]
    repeated = sorted(term for term, count in Counter(terms).items() if count > 1)
    assert repeated == [], f"these terms name more than one row: {repeated}"


def test_every_term_names_the_words_a_writer_does_not_use() -> None:
    """Every row of the `Terms` table fills its `Do not use` column."""
    bare = sorted(row[0] for row in _term_rows() if not row[3] or row[3] == "—")
    assert bare == [], f"these terms bar no synonym: {bare}"
