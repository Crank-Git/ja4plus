"""Tests that the conformance rules state what a delegated session may rule.

The `## Terms` table of `docs/specs/spec.md` defines a ruling as one determination the user
makes. **The user delegates a session to a project manager.** The rules said nothing about
what that delegation permits, so the next delegated session met the question with no
guidance.

#597 writes that rule. The user granted two delegations, and each one reaches a different
class of question.

- **The narrow delegation of 2026-08-12.** `Crank-Git/ja4plus-go` #246 records it, and
  `.claude/rules/rulings.md` of that repository holds the port half. It permits a ruling on
  a schema violation alone, under five conditions.
- **The recording delegation of 2026-08-15.** The ruling comments of #595, #607, #608 and
  #613 each state it in the same words. It permits a ruling that keeps the present behaviour
  and writes one row of the divergence register.

**A reader who found one delegation alone would read a rule that four merged rulings
contradict.** These cases therefore hold both delegations against the file, and they hold
the boundary that parts them.

These cases read prose. They import nothing from `ja4plus` and they produce no fingerprint.
"""

import re
from pathlib import Path
from typing import List

from tests.test_ported_pattern_cost import collapsed, section

REPO_ROOT = Path(__file__).resolve().parent.parent

RULE_FILE = REPO_ROOT / ".claude" / "rules" / "conformance.md"
SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

# The heading of the section #597 writes.
DELEGATION_HEADING = "## What a delegated session may rule"

# The heading of each subsection. A reader of one delegation reaches it through one of them.
NARROW_HEADING = "### The narrow delegation of 2026-08-12"
RECORDING_HEADING = "### The recording delegation of 2026-08-15"
RELATION_HEADING = "### How the two delegations relate"

# The delegation of 2026-08-15, as the ruling comments of #595, #607, #608 and #613 state
# it. **The rule file quotes it and it rewrites no word of it.** `.claude/rules/ste.md` bars
# a rewrite of anything a person said. **The quotation names the maintainer**, and the prose
# of this project names the user.
DELEGATION_OF_2026_08_15 = (
    "The maintainer granted a delegated session this carve-out on 2026-08-15: a delegated "
    "session may rule where the decision preserves the present behaviour, moves no "
    "fingerprint, and records an existing reading as a divergence register row. A decision "
    "that moves a value, that forks from `ja4plus-go`, or that changes the scope of the "
    "project stays with the maintainer."
)

# The four issues that state the delegation. The project manager ruled each one under it on
# 2026-08-15.
DELEGATION_ISSUES = ("#595", "#607", "#608", "#613")

# The issue of the port that records the narrow delegation.
PORT_ISSUE = "Crank-Git/ja4plus-go#246"

# The count of conditions the narrow delegation states. #597 lists all five.
NARROW_CONDITION_COUNT = 5

# A numbered list item of a Markdown page.
NUMBERED_ITEM = re.compile(r"^\s*(\d+)\.\s+\S")

# The sentence that states the boundary between the two classes of question.
BOUNDARY_SENTENCE = "A schema violation has one right answer, and a reference split has none."

# The words the `## Terms` table gains, because the section writes each one.
NEW_TERMS = ("delegation", "delegated ruling", "schema violation", "reference split")

# The heading of the section that holds the controlled vocabulary, and the heading below it.
TERMS_HEADING = "## Terms"
NEXT_HEADING = "## Goals"


def rule_text() -> str:
    """Return the whole text of the conformance rule file.

    Returns:
        The text, as the file holds it.
    """
    return RULE_FILE.read_text(encoding="utf-8")


def delegation_section() -> str:
    """Return the body of the section that states what a delegated session may rule.

    Returns:
        The lines below the heading, up to the next heading of the same depth.
    """
    return section(rule_text(), DELEGATION_HEADING)


def numbered_items(body: str) -> List[str]:
    """Return the text of every numbered list item of one section body.

    A condition wraps across two lines, so the reader takes the first line of each item.

    Args:
        body: The body of one Markdown section.

    Returns:
        One string for each numbered item, in file order.
    """
    return [line.strip() for line in body.splitlines() if NUMBERED_ITEM.match(line)]


def block_quotation(body: str) -> str:
    """Return the text of one section with the blockquote mark removed from every line.

    A quotation wraps across several lines, and each line opens with the mark. A reader that
    kept the mark would compare the quoted text against a text no page holds.

    Args:
        body: The body of one Markdown section.

    Returns:
        The same text on one line, with no blockquote mark.
    """
    return collapsed("\n".join(re.sub(r"^\s*>\s?", "", line) for line in body.splitlines()))


def term_rows() -> List[List[str]]:
    """Return the columns of every row of the `## Terms` table.

    Returns:
        One list of four stripped column values for each row, with the two header rows
        removed.

    Raises:
        AssertionError: The page holds no `## Terms` section.
    """
    lines = SPECIFICATION.read_text(encoding="utf-8").splitlines()
    assert TERMS_HEADING in lines, f"{SPECIFICATION} holds no {TERMS_HEADING} section"
    start = lines.index(TERMS_HEADING)
    end = start + lines[start:].index(NEXT_HEADING)
    rows = [
        [column.strip() for column in line.strip().strip("|").split("|")]
        for line in lines[start:end]
        if line.startswith("|")
    ]
    return rows[2:]


# --- The readers, driven in both directions ---------------------------------------------


def test_the_quotation_reader_joins_a_quotation_that_wraps_across_two_lines() -> None:
    """The reader returns one line for a quotation the 90-column wrap splits."""
    assert block_quotation("> a delegated\n> session may rule") == "a delegated session may rule"


def test_the_quotation_reader_leaves_a_line_that_carries_no_mark() -> None:
    """The reader leaves a plain line, so a case reads the prose beside the quotation."""
    assert block_quotation("It states three limits.") == "It states three limits."


def test_the_item_reader_reads_a_numbered_item_and_no_other_line() -> None:
    """The reader returns the numbered items of a body, and it returns no plain line."""
    body = "A plain line.\n1. The first condition.\n2. The second condition.\n"
    assert numbered_items(body) == ["1. The first condition.", "2. The second condition."]


# --- The section exists, and it holds a body -------------------------------------------


def test_the_rule_file_states_what_a_delegated_session_may_rule() -> None:
    """The conformance rules hold the section, and the section holds text.

    **A case over an empty body passes on nothing**, so this case reads the length first.
    """
    body = delegation_section()
    assert len(body.strip()) > 0, (
        f"{RULE_FILE} holds no `{DELEGATION_HEADING}` section, so a delegated session reads "
        "no statement of what the user permits it to rule"
    )


def test_the_section_names_both_delegations_the_user_granted() -> None:
    """The section holds one subsection for each delegation, and one that relates them."""
    body = delegation_section()
    for heading in (NARROW_HEADING, RECORDING_HEADING, RELATION_HEADING):
        assert heading in body, f"{RULE_FILE} holds no subsection `{heading}`"


# --- The narrow delegation of 2026-08-12 ------------------------------------------------


def test_the_narrow_delegation_states_the_boundary_of_2026_08_12() -> None:
    """The narrow delegation states the sentence that parts the two classes of question."""
    body = section(rule_text(), NARROW_HEADING)
    assert BOUNDARY_SENTENCE in collapsed(body), (
        f"{RULE_FILE} states no boundary for the narrow delegation, so a reader cannot tell "
        "a question it reaches from a question it bars"
    )


def test_the_narrow_delegation_states_all_five_conditions() -> None:
    """The narrow delegation lists the five conditions of `Crank-Git/ja4plus-go` #246.

    **A rule that states four of the five permits a ruling the user never granted.**
    """
    items = numbered_items(section(rule_text(), NARROW_HEADING))
    assert len(items) == NARROW_CONDITION_COUNT, (
        f"{RULE_FILE} lists {len(items)} conditions for the narrow delegation, and #597 "
        f"states {NARROW_CONDITION_COUNT}: {items}"
    )


def test_the_narrow_delegation_bars_a_reference_split() -> None:
    """The narrow delegation states that one implementation that departs bars the question."""
    body = collapsed(section(rule_text(), NARROW_HEADING))
    assert "Every FoxIO implementation enforces that rule." in body, (
        f"{RULE_FILE} states no unanimity condition, so a reference split reaches the narrow "
        "delegation"
    )
    assert "bars a reference split" in body, (
        f"{RULE_FILE} states nowhere that the narrow delegation bars a reference split"
    )


def test_the_section_names_the_issue_of_the_port_that_records_the_narrow_delegation() -> None:
    """The section names the port issue, because a ruling lands in both repositories.

    **The table of the section holds that issue, and the subsection below it does not.** The
    case therefore reads the whole section, and the name states that scope.
    """
    body = section(rule_text(), DELEGATION_HEADING)
    assert PORT_ISSUE in collapsed(body), (
        f"{RULE_FILE} names no `{PORT_ISSUE}`, so a reader reaches the port half through no path"
    )


# --- The recording delegation of 2026-08-15 ---------------------------------------------


def test_the_recording_delegation_quotes_the_words_of_the_user() -> None:
    """The recording delegation quotes the delegation of 2026-08-15 word for word.

    **`.claude/rules/ste.md` bars a rewrite of anything a person said.** A reworded quotation is
    no longer evidence of what the user permitted.
    """
    body = block_quotation(section(rule_text(), RECORDING_HEADING))
    assert collapsed(DELEGATION_OF_2026_08_15) in body, (
        f"{RULE_FILE} quotes no delegation of 2026-08-15, so the rule states the permission in "
        "the words of a writer rather than in the words of the user"
    )


def test_the_recording_delegation_names_every_issue_that_states_it() -> None:
    """The recording delegation names all four issues the project manager ruled under it."""
    body = section(rule_text(), RECORDING_HEADING)
    missing = [issue for issue in DELEGATION_ISSUES if issue not in body]
    assert missing == [], (
        f"{RULE_FILE} names {missing} nowhere in the recording delegation, so a reader "
        "cannot read the rulings the delegation produced"
    )


def test_the_recording_delegation_moves_no_fingerprint() -> None:
    """The recording delegation states that a ruling under it moves no fingerprint value."""
    body = collapsed(section(rule_text(), RECORDING_HEADING))
    assert "moves no fingerprint value" in body, (
        f"{RULE_FILE} states nowhere that a ruling of the recording delegation moves no "
        "fingerprint value"
    )


# --- How the two delegations relate ------------------------------------------------------


def test_the_section_states_that_neither_delegation_repeals_the_other() -> None:
    """The section states that the two delegations reach different questions."""
    body = collapsed(section(rule_text(), RELATION_HEADING))
    assert "neither one repeals the other" in body, (
        f"{RULE_FILE} states no relation between the two delegations, so a reader takes the "
        "later delegation for a replacement of the earlier one"
    )


def test_the_section_states_that_a_reference_split_is_never_a_schema_violation() -> None:
    """The section states that no reading turns a reference split into a schema violation.

    **#595 and #613 each rule a question the FoxIO implementations split on**, and each
    ruling of 2026-08-15 kept the present behaviour. A reader must not take either one for a
    ruling under the narrow delegation.
    """
    body = collapsed(section(rule_text(), RELATION_HEADING))
    assert "A reference split is never delegable as a schema violation." in body, (
        f"{RULE_FILE} states nowhere that a reference split is never delegable as a schema "
        "violation"
    )


def test_the_section_states_that_an_unconfirmed_ruling_stays_provisional() -> None:
    """The section states that the user confirms a delegated ruling, or reverses it."""
    body = collapsed(delegation_section())
    assert "The user confirms a delegated ruling, or reverses it." in body, (
        f"{RULE_FILE} states nowhere that the user confirms a delegated ruling"
    )
    assert "stays provisional" in body, (
        f"{RULE_FILE} states nowhere that an unconfirmed delegated ruling stays provisional"
    )


def test_the_section_sends_a_question_that_fails_both_delegations_to_the_user() -> None:
    """The section states what the project manager does with a question it may not rule."""
    body = collapsed(delegation_section())
    assert "status:needs-feedback" in body, (
        f"{RULE_FILE} names no label for a question that fails both delegations, so a "
        "project manager reads no procedure and improvises one"
    )


# --- The controlled vocabulary -----------------------------------------------------------


def test_the_terms_table_holds_a_row_for_every_word_the_section_writes() -> None:
    """The `## Terms` table holds one row for each domain word the section writes.

    `.claude/rules/ste.md` states that a writer who needs a word the table does not hold
    adds it to the table.
    """
    terms = {row[0] for row in term_rows()}
    missing = sorted(term for term in NEW_TERMS if term not in terms)
    assert missing == [], f"the `{TERMS_HEADING}` table holds no row for {missing}"


def test_the_terms_row_of_the_ruling_states_the_delegated_case() -> None:
    """The `## Terms` row of the ruling names the delegated case and the file that states it.

    **The row read that a ruling is one determination the user makes.** A project manager
    that reads that row alone reads that it may rule nothing, and four merged rulings of
    2026-08-15 contradict that reading.
    """
    rows = [row for row in term_rows() if row[0] == "ruling"]
    assert len(rows) == 1, f"the `{TERMS_HEADING}` table holds {len(rows)} rows for a ruling"
    assert "delegation" in rows[0][2], (
        "the `## Terms` row of the ruling names no delegation, so it states that the user "
        "makes every ruling and `.claude/rules/conformance.md` contradicts it"
    )
    assert ".claude/rules/conformance.md" in rows[0][2], (
        "the `## Terms` row of the ruling names no file that states the delegations"
    )
