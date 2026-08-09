"""Tests that `CHANGELOG.md` and `docs/specs/spec.md` state the same Changelog round.

Every worker writes the literal `TBD` and chooses no round number, because two members of
one batch have claimed the same number before. The project manager assigns each number at
the batch gate. **An assignment that covers one file and not the other leaves an orphan**,
and a reader who follows `Round TBD` in a shipped `CHANGELOG.md` reaches nothing. #302
found three such orphans, and the handoff of session 10 records six more from an earlier
batch.

**A case here bars no `TBD`.** An integration branch carries one `TBD` for each member
that has not reached the gate, and every one of them is correct. The defect is the
disagreement between the two files, so these cases compare the files against each other.

An entry matches a row on the issue the entry names. A numbered entry matches on the
number alone, because a round number is an identifier that names one row.

**These cases reach no unassigned row that opens with no issue reference.** Sixteen rows
of the 133 open with the shipment of a batch, as `Epic 4 shipped`, and such a row carries
no issue to match. Every such row holds a number today, because the project manager writes
it at the gate. An entry that names an unassigned row of that shape therefore reads as an
orphan here. Give the row an issue reference where that happens.

These cases read prose. They import nothing from `ja4plus` and they produce no
fingerprint.
"""

from pathlib import Path
import re

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"

# A Changelog row of the specification opens with the round and the date, as
# `| 9 | 2026-08-06 | #80 landed and ... |`. The date distinguishes a Changelog row from
# every other table of the page, so a row of the Terms table reaches no case here. An
# unassigned row carries the literal `TBD` in place of the number.
SPECIFICATION_ROW = re.compile(r"^\|\s*(\d+|TBD)\s*\|\s*\d{4}-\d{2}-\d{2}\s*\|\s*\*{0,2}#(\d+)\b")

# A row that opens with no issue reference, as `| 90 | 2026-08-08 | Epic 4 shipped ...`.
# Sixteen rows take this form, and each one records the shipment of a batch or a decision
# of the user. Such a row carries a number, so the numbered cases below still reach it.
SPECIFICATION_ROW_NUMBER = re.compile(r"^\|\s*(\d+|TBD)\s*\|\s*\d{4}-\d{2}-\d{2}\s*\|")

# An entry of `CHANGELOG.md` opens the line with `- ` and names its round in a sentence
# of its own, as `Round 90.`. Thirty-eight entries of the seventy-four name no round, and
# those entries reach no case here.
# **Two entries write the round inside backticks, so the backticks are optional here.**
# A pattern that requires the bare word reads 34 entries where 36 exist, and the two it
# drops escape every case below.
# The closing period matters. It parts the round sentence of an entry from a citation of
# another round inside the prose, as `Round 12 closed with`, which #258 wrote.
CHANGELOG_ROUND = re.compile(r"Round `?(\d+|TBD)`?\.")

# An entry cites its own issue in a parenthesis in front of its round sentence, as
# `(#345).` or `(#382, absorbed by #319).`.
# **An entry also names another issue in its title, and that issue owns another row.**
# `- **The `capability` field alone bars the rows of #129** (#347).` is such an entry, so
# a reader of the whole lead collects #129 beside #347. #129 holds round 26 today and the
# entry therefore matches the wrong row on the day #129 waits for a round. Read the last
# parenthesis instead, because the citation sits closest to the round sentence.
ISSUE_CITATION = re.compile(r"\(([^()]*#\d+[^()]*)\)")

ISSUE_REFERENCE = re.compile(r"#(\d+)")

# The two files held these counts when #302 landed. A parser that reads nothing passes
# every case below on an empty list, so each floor fails such a parser. Both counts grow
# and neither falls, because both tables are append-only.
MINIMUM_SPECIFICATION_ROWS = 133
MINIMUM_CHANGELOG_ENTRIES = 36


def _specification_rounds() -> tuple[set[int], set[int]]:
    """Return the assigned rounds of the specification and the issues that await a round.

    Returns:
        The set of round numbers the Changelog table assigns, and the set of issue
        numbers that open a row reading `TBD`.

    Raises:
        AssertionError: The page holds fewer rows than the recorded floor.
    """
    text = SPECIFICATION.read_text(encoding="utf-8")
    assigned: set[int] = set()
    unassigned: set[int] = set()
    rows = 0
    for line in text.splitlines():
        number_match = SPECIFICATION_ROW_NUMBER.match(line)
        if not number_match:
            continue
        rows += 1
        if number_match.group(1) != "TBD":
            assigned.add(int(number_match.group(1)))
            continue
        issue_match = SPECIFICATION_ROW.match(line)
        if issue_match:
            unassigned.add(int(issue_match.group(2)))
    assert rows >= MINIMUM_SPECIFICATION_ROWS, (
        f"the parser read {rows} Changelog rows, and the floor is {MINIMUM_SPECIFICATION_ROWS}"
    )
    return assigned, unassigned


def _changelog_entries() -> list[tuple[str, set[int], str]]:
    """Return the round, the issues and the title of every entry that names a round.

    Returns:
        One triple for each entry: the round as it reads, the issue numbers the entry
        names before its round sentence, and the first line of the entry.

    Raises:
        AssertionError: The file holds fewer such entries than the recorded floor.
    """
    text = CHANGELOG.read_text(encoding="utf-8")
    entries: list[tuple[str, set[int], str]] = []
    for entry in re.split(r"\n(?=- )", text):
        round_match = CHANGELOG_ROUND.search(entry)
        if not round_match:
            continue
        lead = entry[: round_match.start()]
        citations = ISSUE_CITATION.findall(lead)
        # All 36 entries cite an issue. A future entry that cites none falls back to the
        # whole lead, so the cases still reach it.
        issues = {
            int(number) for number in ISSUE_REFERENCE.findall(citations[-1] if citations else lead)
        }
        entries.append((round_match.group(1), issues, entry.splitlines()[0].strip()))
    assert len(entries) >= MINIMUM_CHANGELOG_ENTRIES, (
        f"the parser read {len(entries)} entries, and the floor is {MINIMUM_CHANGELOG_ENTRIES}"
    )
    return entries


def test_every_numbered_entry_names_a_round_the_specification_records() -> None:
    """A numbered entry of `CHANGELOG.md` names a round that `docs/specs/spec.md` holds."""
    assigned, _ = _specification_rounds()
    orphans = [
        f"{title} names round {round_read}"
        for round_read, _, title in _changelog_entries()
        if round_read != "TBD" and int(round_read) not in assigned
    ]
    assert orphans == [], f"these entries name a round the specification does not record: {orphans}"


def test_an_unassigned_entry_matches_an_unassigned_row() -> None:
    """An entry reading `Round TBD` names an issue whose specification row also reads `TBD`."""
    _, unassigned = _specification_rounds()
    orphans = [
        f"{title} cites {sorted(issues)}"
        for round_read, issues, title in _changelog_entries()
        if round_read == "TBD" and not issues & unassigned
    ]
    assert orphans == [], (
        f"these entries read Round TBD and the specification assigns their row: {orphans}"
    )


def test_a_numbered_entry_holds_no_row_that_waits_for_its_number() -> None:
    """An entry names a number only after the specification assigns the round of its issue."""
    _, unassigned = _specification_rounds()
    early = [
        f"{title} names round {round_read}"
        for round_read, issues, title in _changelog_entries()
        if round_read != "TBD" and issues & unassigned
    ]
    assert early == [], (
        f"these entries name a number while their specification row reads TBD: {early}"
    )
