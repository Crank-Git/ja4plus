"""Tests that the release notes of version 1.0.0 name every breaking change the record holds.

`FR-documentation-13` asks `CHANGELOG.md` to record every breaking change of this release.
A section that lists them goes stale on the day the next one lands, so these cases hold the
list against the record instead of against a number somebody remembered.

**The record is three files, and each one reaches the notes by a rule of its own.**

1. An entry of `CHANGELOG.md` that opens with `**BREAKING` marks a breaking change. The
   issue it cites reaches the release notes.
2. The breaking-change table of `docs/migration-0.6-to-1.0.md` states the old form and the
   new form of each change. Every issue of that table reaches the release notes, and the
   `Record` cell of the notes repeats the `Record` cell of the page word for word.
3. The fingerprint section of the same page names each method whose value moves. Every
   issue that section names reaches the notes, and the prose of the section counts too,
   because `#214` sits in a paragraph and not in a row.

**These cases read one direction and not the other.** The notes hold a change the migration
page omits: #319 narrowed `compute_ja4x_from_pem` and `compute_ja4x_from_der`, so an input
that returned `None` can now raise, and #397 recorded it under round 133. The migration
page carries no row for it. A two-way comparison would therefore fail on a page this issue
does not own, so the reverse direction reads the round instead: every round the notes cite
names a row of `docs/specs/spec.md`.

These cases read prose. They import nothing from `ja4plus` and they produce no fingerprint.
"""

from pathlib import Path
import re

REPO_ROOT = Path(__file__).resolve().parent.parent

CHANGELOG = REPO_ROOT / "CHANGELOG.md"
MIGRATION = REPO_ROOT / "docs" / "migration-0.6-to-1.0.md"
SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

# The heading of the release notes. Keep a Changelog opens a version section with the
# version in brackets, as `## [0.6.0] - 2026-05`. The date arrives with the promotion of
# `dev` to `master`, so the section reads `unreleased` until then.
RELEASE_HEADING = re.compile(r"^## \[1\.0\.0\]", re.MULTILINE)

# Any second-level heading. It closes the section above it.
SECTION_HEADING = re.compile(r"^## ", re.MULTILINE)

# The two tables of the release notes. Each one opens under a fourth-level heading, and a
# fourth-level heading reaches no case of `tests/test_breaking_change_record.py`, which
# reads a third-level heading.
NOTES_INTERFACE_HEADING = "#### The interface changes"
NOTES_FINGERPRINT_HEADING = "#### The fingerprints that move"

# The heading of the fingerprint section of the migration page.
MIGRATION_FINGERPRINT_HEADING = "## The fingerprints that move"
MIGRATION_BREAKING_HEADING = "## The breaking changes"

# A table row of Markdown, as `| The change | Round 90, #45 |`. A separator row holds
# hyphens and colons alone, so this pattern skips it.
TABLE_ROW = re.compile(r"^\|(?!\s*[-: |]+\|\s*$).*\|\s*$")

ISSUE_REFERENCE = re.compile(r"#(\d+)")

# An entry cites its own issue in a parenthesis behind its title, as `(#102).`.
ISSUE_CITATION = re.compile(r"\(([^()]*#\d+[^()]*)\)")

# A round citation of the release notes, as `Round 90, #45`. The comma parts this form from
# the `Round 90.` sentence that `tests/test_changelog_round_agreement.py` reads, so a table
# row of the notes never reads as a Changelog entry there.
NOTES_ROUND = re.compile(r"Round (\d+)")

# A Changelog row of the specification opens with the round and the date, as
# `| 90 | 2026-08-08 | ... |`. An unassigned row carries the literal `TBD`.
SPECIFICATION_ROW = re.compile(r"^\|\s*(\d+)\s*\|\s*\d{4}-\d{2}-\d{2}\s*\|")

# An entry of `CHANGELOG.md` that marks a breaking change. Eight entries carry the marker
# today, and every one of them cites its issue in a parenthesis.
BREAKING_ENTRY = re.compile(r"^- \*\*BREAKING\b", re.MULTILINE)

# The record held these counts when #66 landed. A parser that reads nothing passes every
# comparison below on an empty set, so each floor fails such a parser. Every count grows
# and none of them falls, because a released breaking change stays released.
MINIMUM_BREAKING_ENTRIES = 8
MINIMUM_INTERFACE_ROWS = 12
MINIMUM_FINGERPRINT_ROWS = 8
MINIMUM_MIGRATION_ROWS = 11


def _release_notes() -> str:
    """Return the text of the version 1.0.0 section of `CHANGELOG.md`.

    Returns:
        The section text, from its heading to the next second-level heading.

    Raises:
        AssertionError: The file holds no version 1.0.0 section.
    """
    text = CHANGELOG.read_text(encoding="utf-8")
    opening = RELEASE_HEADING.search(text)
    assert opening, "CHANGELOG.md holds no `## [1.0.0]` section"
    following = SECTION_HEADING.search(text, opening.end())
    return text[opening.start() : following.start() if following else len(text)]


def _table_under(text: str, heading: str) -> list[str]:
    """Return every data row of the table that sits under one heading.

    **The header row matches the row pattern, and the reader drops it.** A count that held
    the header would read one row more than the table carries, and every floor below would
    then pass on a table that lost a row.

    Args:
        text: The text to read.
        heading: The heading line, as `#### The interface changes`.

    Returns:
        One string for each data row, holding the whole row text.

    Raises:
        AssertionError: The text holds no such heading.
    """
    start = text.find(heading)
    assert start != -1, f"the text holds no heading {heading!r}"
    rows: list[str] = []
    for line in text[start + len(heading) :].splitlines():
        if line.startswith("#"):
            break
        if TABLE_ROW.match(line):
            rows.append(line)
    assert rows, f"the table under {heading!r} holds no row"
    return rows[1:]


def _issues(rows: list[str]) -> set[int]:
    """Return every issue number the rows name.

    Args:
        rows: The table rows to read.

    Returns:
        The set of issue numbers.
    """
    return {int(number) for row in rows for number in ISSUE_REFERENCE.findall(row)}


def _record_cell(row: str) -> str:
    """Return the last cell of a table row.

    Args:
        row: The whole row text, as `| The change | Round 90, #45 |`.

    Returns:
        The text of the last cell, without the surrounding spaces.
    """
    return row.strip().strip("|").split("|")[-1].strip()


def _migration_section(heading: str) -> str:
    """Return one section of `docs/migration-0.6-to-1.0.md`.

    Args:
        heading: The heading line, as `## The breaking changes`.

    Returns:
        The section text, from its heading to the next second-level heading.

    Raises:
        AssertionError: The page holds no such heading.
    """
    text = MIGRATION.read_text(encoding="utf-8")
    start = text.find(heading)
    assert start != -1, f"{MIGRATION.name} holds no heading {heading!r}"
    following = SECTION_HEADING.search(text, start + len(heading))
    return text[start : following.start() if following else len(text)]


def _assigned_rounds() -> set[int]:
    """Return every Changelog round number that `docs/specs/spec.md` assigns.

    Returns:
        The set of assigned round numbers.
    """
    return {
        int(match.group(1))
        for line in SPECIFICATION.read_text(encoding="utf-8").splitlines()
        for match in [SPECIFICATION_ROW.match(line)]
        if match
    }


def _breaking_entries() -> list[str]:
    """Return every entry of `CHANGELOG.md` that opens with the breaking-change marker.

    Returns:
        One string for each entry, holding the whole entry text.

    Raises:
        AssertionError: The file holds fewer such entries than the recorded floor.
    """
    text = CHANGELOG.read_text(encoding="utf-8")
    entries = [entry for entry in re.split(r"\n(?=- )", text) if BREAKING_ENTRY.match(entry)]
    assert len(entries) >= MINIMUM_BREAKING_ENTRIES, (
        f"the parser read {len(entries)} breaking entries, and the floor is "
        f"{MINIMUM_BREAKING_ENTRIES}"
    )
    return entries


def _cited_issues(entry: str) -> set[int]:
    """Return the issue numbers of the first parenthesis citation of an entry.

    **The title of an entry wraps, and two breaking entries carry their citation on the
    second line.** A reader of the first line alone finds no issue on those two, so this
    reader takes the first parenthesis of the whole entry, which sits behind the title.

    Args:
        entry: The whole entry text.

    Returns:
        The issue numbers of that citation, or of the whole entry where it holds none.
    """
    citation = ISSUE_CITATION.search(entry)
    return {
        int(number) for number in ISSUE_REFERENCE.findall(citation.group(1) if citation else entry)
    }


def _notes_issues() -> set[int]:
    """Return every issue number the two tables of the release notes name.

    Returns:
        The set of issue numbers.
    """
    notes = _release_notes()
    return _issues(_table_under(notes, NOTES_INTERFACE_HEADING)) | _issues(
        _table_under(notes, NOTES_FINGERPRINT_HEADING)
    )


def test_the_changelog_holds_a_release_notes_section_for_version_1_0_0() -> None:
    """`CHANGELOG.md` opens a version 1.0.0 section that links the migration page."""
    notes = _release_notes()
    assert "migration-0.6-to-1.0.md" in notes, (
        "the release notes link no migration page, so a reader learns no replacement form"
    )
    assert NOTES_INTERFACE_HEADING in notes, (
        f"the release notes hold no {NOTES_INTERFACE_HEADING!r}"
    )
    assert NOTES_FINGERPRINT_HEADING in notes, (
        f"the release notes hold no {NOTES_FINGERPRINT_HEADING!r}"
    )


def test_the_release_notes_hold_a_row_for_each_breaking_change() -> None:
    """The two tables of the release notes hold at least the rows the record produced.

    **This case reads the notes alone and it bars an empty parser.** A table that a later
    edit empties passes every comparison below, because an empty set is a subset of every
    set.
    """
    notes = _release_notes()
    interface = _table_under(notes, NOTES_INTERFACE_HEADING)
    fingerprints = _table_under(notes, NOTES_FINGERPRINT_HEADING)
    assert len(interface) >= MINIMUM_INTERFACE_ROWS, (
        f"the interface table holds {len(interface)} rows, and the floor is "
        f"{MINIMUM_INTERFACE_ROWS}"
    )
    assert len(fingerprints) >= MINIMUM_FINGERPRINT_ROWS, (
        f"the fingerprint table holds {len(fingerprints)} rows, and the floor is "
        f"{MINIMUM_FINGERPRINT_ROWS}"
    )


def test_every_breaking_entry_of_the_changelog_reaches_the_release_notes() -> None:
    """An entry marked `**BREAKING` names an issue that the release notes also name."""
    named = _notes_issues()
    missing = [
        entry.splitlines()[0].strip()
        for entry in _breaking_entries()
        if not _cited_issues(entry) & named
    ]
    assert missing == [], f"the release notes name no issue of these breaking entries: {missing}"


def test_every_breaking_change_of_the_migration_page_reaches_the_release_notes() -> None:
    """Every issue of the migration page breaking table reaches the release notes."""
    rows = _table_under(_migration_section(MIGRATION_BREAKING_HEADING), MIGRATION_BREAKING_HEADING)
    assert len(rows) >= MINIMUM_MIGRATION_ROWS, (
        f"the migration page holds {len(rows)} breaking rows, and the floor is "
        f"{MINIMUM_MIGRATION_ROWS}"
    )
    missing = sorted(_issues(rows) - _notes_issues())
    assert missing == [], (
        f"the migration page records these breaking changes and the release notes omit them: "
        f"{missing}"
    )


def test_every_fingerprint_that_moves_reaches_the_release_notes() -> None:
    """Every issue of the migration page fingerprint section reaches the release notes.

    **This case reads the prose of the section beside its table.** #214 sits in a paragraph
    under the table, because it adds a value rather than move one, and a case that read the
    rows alone would miss it.
    """
    section = _migration_section(MIGRATION_FINGERPRINT_HEADING)
    named = {int(number) for number in ISSUE_REFERENCE.findall(section)}
    missing = sorted(named - _notes_issues())
    assert missing == [], (
        f"the migration page records these moved fingerprints and the release notes omit "
        f"them: {missing}"
    )


def test_the_release_notes_repeat_the_record_cell_of_the_migration_page() -> None:
    """A row of the release notes cites the same round and issue as the migration page.

    Two pages that cite one change under two rounds send a reader to two places. The
    `Record` cell is the last cell of both tables, so this case compares the two cells for
    every issue the migration page names.
    """
    page_rows = _table_under(
        _migration_section(MIGRATION_BREAKING_HEADING), MIGRATION_BREAKING_HEADING
    )
    notes_rows = _table_under(_release_notes(), NOTES_INTERFACE_HEADING)
    notes_records = {_record_cell(row) for row in notes_rows}
    disagreements = [
        f"{_record_cell(row)!r} of the migration page reaches no row of the release notes"
        for row in page_rows
        if _record_cell(row) not in notes_records
    ]
    assert disagreements == [], f"the two records disagree: {disagreements}"


def test_every_round_the_release_notes_cite_names_a_row_of_the_specification() -> None:
    """A round the release notes cite exists in the Changelog table of `docs/specs/spec.md`."""
    assigned = _assigned_rounds()
    assert assigned, "the specification holds no assigned Changelog round"
    cited = {int(number) for number in NOTES_ROUND.findall(_release_notes())}
    assert cited, "the release notes cite no round"
    orphans = sorted(cited - assigned)
    assert orphans == [], (
        f"the release notes cite rounds the specification does not hold: {orphans}"
    )


def test_the_release_notes_name_the_narrowed_certificate_readers() -> None:
    """The release notes hold the breaking change of #319, which the migration page omits.

    #319 narrowed `compute_ja4x_from_pem` and `compute_ja4x_from_der`, so an input that
    returned `None` now raises. #397 swept `v0.6.0..HEAD` and named the change under round
    133. `docs/migration-0.6-to-1.0.md` carries no row for it, and #65 owns that page, so
    #66 records the gap here rather than edit the page.
    """
    assert 319 in _notes_issues(), "the release notes omit the narrowed certificate readers"
