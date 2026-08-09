"""Tests that the release notes of version 1.0.0 name every breaking change the record holds.

`FR-documentation-13` asks `CHANGELOG.md` to record every breaking change of this release.
A section that lists them goes stale on the day the next one lands. These cases hold the
list against the record, and not against a number a reader keeps by hand.

**The record is three files, and each one reaches the notes by a rule of its own.**

1. An entry of `CHANGELOG.md` that opens with `**BREAKING` marks a breaking change. The
   issue it cites reaches the release notes.
2. The breaking-change table of `docs/migration-0.6-to-1.0.md` states the old form and the
   new form of each change. Every issue of that table reaches the release notes.
3. The fingerprint section of the same page names each method whose value moves. Every
   issue that section names reaches the notes. The prose of the section counts too, because
   `#214` sits in a paragraph and not in a row.

**The Changelog table of `docs/specs/spec.md` decides a round.** A `Round N, #M` citation of
the notes names the row that holds `N`, and that row mentions `#M`. The first form of this
file compared the `Record` cell of the notes against the cell of the migration page instead.
**Two files that copy one error agree, and the comparison passed on it.** #401 held that
error. The same rule now reads the citations of the migration page against the same table,
because a page that copies a wrong round from another file reads as correct.

**These cases read both directions.** #66 wrote the first direction alone, because the notes
held a change the page omitted. #319 narrowed `compute_ja4x_from_pem` and
`compute_ja4x_from_der`, so an input that returned `None` can now raise. #397 recorded the
change under round 133, and #399 added the row the page lacked.
`test_every_breaking_change_of_the_record_reaches_the_migration_page` reads the other
direction, so a breaking change the record names and the page omits fails a case.

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

# The subsection of the release notes that carries the two tables and their citations. A
# case that reads a citation reads this block alone, because an entry under `### Added`
# quotes a wrong citation as evidence and a reader of the whole section would count it.
NOTES_BREAKING_HEADING = "### The breaking changes"

# Any third-level heading. It closes the subsection above it.
SUBSECTION_HEADING = re.compile(r"^### ", re.MULTILINE)

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

# A round citation, as `Round 90, #45`. The comma parts this form from the `Round 90.`
# sentence that `tests/test_changelog_round_agreement.py` reads, so a table row of the notes
# never reads as a Changelog entry there. The migration page cites a round in the same form.
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
MINIMUM_INTERFACE_ROWS = 13
MINIMUM_FINGERPRINT_ROWS = 8

# The migration page held eleven breaking rows when #66 landed. #401 parted one row into two
# and #399 added the row of #319, so the page holds thirteen rows today.
MINIMUM_MIGRATION_ROWS = 13

# The migration page cites this many `Round N, #M` pairs today: one for each breaking row,
# and one in the fingerprint table. A reader that finds no citation passes the citation case
# on an empty set, so the floor fails such a reader.
MINIMUM_MIGRATION_CITATIONS = 14

# The breaking-change record names this many issues today. A reader that finds none passes
# the completeness case on an empty set, so the floor fails such a reader.
MINIMUM_RECORD_ISSUES = 20

# A sentence of the release notes that claims the migration page misses a breaking change.
# **Both forms read the present tense, and that is deliberate.** A past-tense sentence
# records a gap that an issue closed, which stays true forever and carries value to a later
# reader. A present-tense sentence claims a live gap, and the record decides whether one
# exists. #403 records the sentence that went stale here.
GAP_CLAIM = re.compile(
    r"reaches no row of the migration page|the migration page (?:holds|carries) no row"
)


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


def _breaking_subsection() -> str:
    """Return the `### The breaking changes` subsection of the release notes.

    Returns:
        The subsection text, from its heading to the next third-level heading.

    Raises:
        AssertionError: The release notes hold no such heading.
    """
    notes = _release_notes()
    start = notes.find(NOTES_BREAKING_HEADING)
    assert start != -1, f"the release notes hold no heading {NOTES_BREAKING_HEADING!r}"
    following = SUBSECTION_HEADING.search(notes, start + len(NOTES_BREAKING_HEADING))
    return notes[start : following.start() if following else len(notes)]


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


def _specification_rows() -> dict[int, str]:
    """Return the numbered Changelog rows of `docs/specs/spec.md`, by round number.

    An unassigned row carries the literal `TBD` in place of the round, and this reader
    skips it, because such a row records no round yet.

    Returns:
        The whole row text of each assigned round, keyed by the round number.
    """
    return {
        int(match.group(1)): line
        for line in SPECIFICATION.read_text(encoding="utf-8").splitlines()
        for match in [SPECIFICATION_ROW.match(line)]
        if match
    }


def _assigned_rounds() -> set[int]:
    """Return every Changelog round number that `docs/specs/spec.md` assigns.

    Returns:
        The set of assigned round numbers.
    """
    return set(_specification_rows())


def _citations(text: str) -> list[tuple[int, int]]:
    """Return every `Round N, #M` citation of a text, as a round and issue pair.

    The reader takes the first round of each line and every issue behind it. An issue in
    front of the round belongs to the prose of the row, and it cites no round.

    Args:
        text: The text to read.

    Returns:
        One pair for each cited issue, holding the round number and the issue number.
    """
    pairs: list[tuple[int, int]] = []
    for line in text.splitlines():
        opening = NOTES_ROUND.search(line)
        if not opening:
            continue
        round_number = int(opening.group(1))
        for issue in ISSUE_REFERENCE.findall(line[opening.end() :]):
            pairs.append((round_number, int(issue)))
    return pairs


def _wrong_citations(text: str, source: str) -> list[str]:
    """Return every citation of a text that names the wrong Changelog row.

    **A round number alone proves nothing.** A citation that names a real round beside the
    wrong issue reaches a row that records another change. A reader who follows it learns
    nothing about the change in front of them.

    **This reader compares one file against the Changelog table and never against a second
    file.** Two files that copy one error agree, and a comparison between them passes on
    the error. #401 is that case.

    Args:
        text: The text to read.
        source: The name of the text, for the failure message.

    Returns:
        One string for each wrong citation, naming the round and the issue.
    """
    rows = _specification_rows()
    wrong: list[str] = []
    for round_number, issue in _citations(text):
        if round_number not in rows:
            wrong.append(f"{source}: round {round_number} names no row")
        elif f"#{issue}" not in rows[round_number]:
            wrong.append(f"{source}: round {round_number} records no #{issue}")
    return wrong


def _migration_breaking_rows() -> list[str]:
    """Return the data rows of the breaking-change table of the migration page.

    Returns:
        One string for each data row, holding the whole row text.

    Raises:
        AssertionError: The table holds fewer rows than the recorded floor.
    """
    rows = _table_under(_migration_section(MIGRATION_BREAKING_HEADING), MIGRATION_BREAKING_HEADING)
    assert len(rows) >= MINIMUM_MIGRATION_ROWS, (
        f"the migration page holds {len(rows)} breaking rows, and the floor is "
        f"{MINIMUM_MIGRATION_ROWS}"
    )
    return rows


def _migration_issues() -> set[int]:
    """Return every issue the migration page records as a breaking change.

    **The fingerprint section reaches this set through its prose and not through its table
    alone.** #214 sits in a paragraph under the table, because it adds a value rather than
    move one.

    Returns:
        The set of issue numbers.
    """
    section = _migration_section(MIGRATION_FINGERPRINT_HEADING)
    return _issues(_migration_breaking_rows()) | {
        int(number) for number in ISSUE_REFERENCE.findall(section)
    }


def _record_issues() -> set[int]:
    """Return every issue the breaking-change record of `CHANGELOG.md` names.

    The record is the two tables of the release notes and every entry that opens with the
    `**BREAKING` marker. **The prose of the notes reaches no part of this set.** That prose
    names #47 and #94, which the sweep of #395 judged marginal, and it names the issues that
    own a gap rather than a change.

    Returns:
        The set of issue numbers.

    Raises:
        AssertionError: The reader found fewer issues than the recorded floor.
    """
    issues = _notes_issues()
    for entry in _breaking_entries():
        issues |= _cited_issues(entry)
    assert len(issues) >= MINIMUM_RECORD_ISSUES, (
        f"the reader found {len(issues)} recorded breaking changes, and the floor is "
        f"{MINIMUM_RECORD_ISSUES}"
    )
    return issues


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
    missing = sorted(_issues(_migration_breaking_rows()) - _notes_issues())
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


def test_every_citation_of_the_release_notes_names_the_row_that_records_it() -> None:
    """A `Round N, #M` citation names a specification row that holds `N` and mentions `#M`.

    **A round number alone proves nothing.** A citation that names a real round beside the
    wrong issue reaches a row that records another change, and a reader who follows it
    learns nothing about the change in front of them.

    The first form of this case compared the `Record` cell of the notes against the cell of
    `docs/migration-0.6-to-1.0.md`. **Two files that copy one error agree, and the case
    passed on it.** The page cited `Round 122, #59 and #364`, and row 123 of the
    specification is the row that records #364. #401 repaired the page. The case reads the
    specification, which is the authority the page and the notes both copy.
    """
    wrong = _wrong_citations(_breaking_subsection(), "the release notes")
    assert wrong == [], f"these citations of the release notes name the wrong row: {wrong}"


def test_every_citation_of_the_migration_page_names_the_row_that_records_it() -> None:
    """A `Round N, #M` citation of the migration page names a row that holds `N` and `#M`.

    **The page is a second copy of the record, and it copied a wrong round.** It cited
    `Round 122, #59 and #364` for the typed lookup result and for the item access. The two
    are different changes under different rounds. Row 122 records #59 and row 123 records
    #364, so a reader who followed the citation reached a row about `lookup_many`. #401
    holds the repair.

    **This case reads the Changelog table of `docs/specs/spec.md` and no other file.** The
    release notes hold the same citations, and the first citation case of #66 compared the
    two files against each other. Both held the error, so they agreed and the case passed.
    """
    text = MIGRATION.read_text(encoding="utf-8")
    citations = _citations(text)
    assert len(citations) >= MINIMUM_MIGRATION_CITATIONS, (
        f"the reader found {len(citations)} citations on the migration page, and the floor "
        f"is {MINIMUM_MIGRATION_CITATIONS}"
    )
    orphans = sorted({int(number) for number in NOTES_ROUND.findall(text)} - _assigned_rounds())
    assert orphans == [], (
        f"the migration page cites rounds the specification does not hold: {orphans}"
    )
    wrong = _wrong_citations(text, "the migration page")
    assert wrong == [], f"these citations of the migration page name the wrong row: {wrong}"


def test_every_breaking_change_of_the_record_reaches_the_migration_page() -> None:
    """Every breaking change the record names reaches a row of the migration page.

    `FR-documentation-12` asks the page to list every breaking change of this release.
    **`test_every_breaking_change_of_the_migration_page_reaches_the_release_notes` reads the
    other direction, and a page that holds fewer changes than the record passes it.** #319
    narrowed `compute_ja4x_from_pem` and `compute_ja4x_from_der`, the record held it under
    round 133, and the page carried no row for it. #399 holds the repair.
    """
    missing = sorted(_record_issues() - _migration_issues())
    assert missing == [], (
        f"the record names these breaking changes and the migration page omits them: {missing}"
    )


def test_the_release_notes_report_the_gap_the_record_shows_and_no_other() -> None:
    """The release notes claim a gap against the migration page when the record shows one.

    **The prose of the notes asserted the same thing as
    `test_every_breaking_change_of_the_record_reaches_the_migration_page`, in the opposite
    direction, and nothing connected the two.** The notes read "One breaking change reaches
    this record and reaches no row of the migration page", #399 added that row, and the
    sentence became false. No case read the paragraph, so a reader found it and the suite
    did not. #403 records it.

    **This case reads the prose against the measured set difference and never against a
    second file.** The claim is a third thing, and the comparison of the record with the
    page is the evidence that decides it.

    **The reader takes a present-tense claim alone**, because a past-tense sentence records
    a gap that an issue closed and stays true. A gap claim in words `GAP_CLAIM` does not
    hold escapes this case. That asymmetry is acceptable: the failure this case exists to
    stop is a sentence that survives a repair unchanged, and unchanged text matches.
    """
    gap = sorted(_record_issues() - _migration_issues())
    claimed = GAP_CLAIM.search(_breaking_subsection())
    if gap:
        assert claimed, (
            f"the record shows these breaking changes the migration page omits, and the "
            f"release notes report no gap: {gap}"
        )
    else:
        assert claimed is None, (
            f"the release notes claim the migration page misses a breaking change, and the "
            f"record shows none: {claimed.group(0)!r}"  # type: ignore[union-attr]
        )


def test_the_release_notes_name_the_narrowed_certificate_readers() -> None:
    """The release notes hold the breaking change of #319.

    #319 narrowed `compute_ja4x_from_pem` and `compute_ja4x_from_der`, so an input that
    returned `None` now raises. #397 swept `v0.6.0..HEAD` and named the change under round
    133. #66 found that `docs/migration-0.6-to-1.0.md` carried no row for it and recorded
    the gap here, and #399 added the row.
    """
    assert 319 in _notes_issues(), "the release notes omit the narrowed certificate readers"
