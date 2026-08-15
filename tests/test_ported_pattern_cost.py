"""Tests that the parity rules state the cost of a pattern this project takes from the port.

**Parity rule 2 of `CLAUDE.md` adopts the interface the port ships, and it adopts no
statement of cost.** Go runs a finite automaton and it backtracks nowhere, and Python `re`
backtracks. One pattern therefore costs two amounts, and the rule that carries the shape
carries no proof that the shape is safe against hostile input.

#612 followed parity rule 2 literally and it shipped a backtracking defect to a branch.
Its self-review measured `GET a` plus 32000 spaces plus `HTTPX` at 3017.9 milliseconds
under the ported form and at 0.630 milliseconds under the repaired one. #650 states the
rule that measurement earned, and these cases hold the two files that state it.

These cases read prose. They import nothing from `ja4plus` and they produce no
fingerprint.
"""

from pathlib import Path
from typing import List
import re

REPO_ROOT = Path(__file__).resolve().parent.parent

RULE_FILE = REPO_ROOT / ".claude" / "rules" / "conformance.md"
REPOSITORY_GUIDE = REPO_ROOT / "CLAUDE.md"

RULE_PARITY_HEADING = "## Parity"
GUIDE_PARITY_HEADING = "## Parity with ja4plus-go"

# The two readings #612 measured, in milliseconds. A rule that states the cost without a
# number states no measurement, so each number reaches its own case.
PORTED_FORM_COST = "3017.9"
REPAIRED_FORM_COST = "0.630"

# The heading of the subsection the rule file carries. A reader of the parity rules
# reaches the rule through this line.
RULE_SUBHEADING = "### A pattern the port ships carries no statement of its cost"


def section(text: str, heading: str) -> str:
    """Return the body of one Markdown section, from its heading to the next one.

    Args:
        text: The whole text of one Markdown file.
        heading: The heading line that opens the section, without a trailing newline.

    Returns:
        The lines below the heading, up to the next heading of the same depth or a
        shallower one. It returns the empty string where the text holds no such heading.
    """
    lines = text.splitlines()
    depth = len(heading) - len(heading.lstrip("#"))
    body: List[str] = []
    inside = False
    for line in lines:
        if line.strip() == heading:
            inside = True
            continue
        if inside and line.startswith("#"):
            line_depth = len(line) - len(line.lstrip("#"))
            if line_depth <= depth:
                break
        if inside:
            body.append(line)
    return "\n".join(body)


def collapsed(text: str) -> str:
    """Return the text with every run of whitespace as one space.

    Args:
        text: The text of one Markdown section.

    Returns:
        The same text on one line. Both files wrap at 90 columns, so a phrase of more
        than a few words reaches a reader that reads a literal space on no line.
    """
    return re.sub(r"\s+", " ", text)


# --- The reader, driven in both directions --------------------------------------------

A_PAGE_THAT_HOLDS_THE_SECTION = """# A page

## Parity

The first body line.

### A deeper heading

The second body line.

## Another section

The line no reader of the first section reads.
"""

A_PAGE_THAT_HOLDS_NO_SECTION = """# A page

## Another section

The line the reader reports nothing for.
"""


def test_the_reader_returns_the_body_of_the_section_it_names() -> None:
    """The reader returns every line of the section, and it stops at the next heading."""
    body = section(A_PAGE_THAT_HOLDS_THE_SECTION, "## Parity")
    assert "The first body line." in body
    assert "The second body line." in body
    assert "The line no reader of the first section reads." not in body


def test_the_reader_returns_nothing_for_a_heading_the_page_omits() -> None:
    """The reader returns the empty string where the page holds no such heading."""
    assert section(A_PAGE_THAT_HOLDS_NO_SECTION, "## Parity") == ""


def test_the_whitespace_reader_finds_a_phrase_that_a_line_break_parts() -> None:
    """The whitespace reader reads a phrase that the 90-column wrap splits over two lines."""
    assert "no statement of cost" in collapsed("no statement\nof cost")
    assert "no statement of cost" not in "no statement\nof cost"


# --- The rule file --------------------------------------------------------------------


def test_the_parity_section_of_the_rule_file_holds_a_body() -> None:
    """The parity section holds text, because a case over an empty body passes on nothing."""
    body = section(RULE_FILE.read_text(encoding="utf-8"), RULE_PARITY_HEADING)
    assert len(body.strip()) > 0, f"{RULE_FILE} holds no `{RULE_PARITY_HEADING}` section"


def test_the_rule_file_states_that_the_port_ships_no_statement_of_cost() -> None:
    """The parity section states that parity rule 2 carries the shape and never the cost."""
    body = section(RULE_FILE.read_text(encoding="utf-8"), RULE_PARITY_HEADING)
    assert RULE_SUBHEADING in body, (
        f"{RULE_FILE} holds no subsection `{RULE_SUBHEADING}`, so a reader of the parity "
        "rules reaches no statement of the cost of a ported pattern"
    )
    assert "It adopts no statement of cost." in collapsed(body), (
        f"{RULE_FILE} states nowhere that parity rule 2 adopts no statement of cost"
    )


def test_the_rule_file_states_the_mechanism_that_parts_the_two_languages() -> None:
    """The rule names the finite automaton of Go and the backtracking of Python `re`."""
    body = section(RULE_FILE.read_text(encoding="utf-8"), RULE_PARITY_HEADING)
    assert "finite automaton" in body, (
        f"{RULE_FILE} names no finite automaton, so the rule states no mechanism"
    )
    assert "backtracks" in body, f"{RULE_FILE} names no backtracking engine"


def test_the_rule_file_requires_a_measurement_before_a_ported_pattern_lands() -> None:
    """The rule instructs a reader to measure a ported pattern against hostile input."""
    body = section(RULE_FILE.read_text(encoding="utf-8"), RULE_PARITY_HEADING)
    assert "against hostile input before it lands" in collapsed(body), (
        f"{RULE_FILE} requires no measurement before a ported pattern lands"
    )


def test_the_rule_file_names_the_measurement_that_earned_the_rule() -> None:
    """The rule quotes the two readings of #612 and it names that issue."""
    body = section(RULE_FILE.read_text(encoding="utf-8"), RULE_PARITY_HEADING)
    for evidence in ("#612", PORTED_FORM_COST, REPAIRED_FORM_COST):
        assert evidence in body, (
            f"{RULE_FILE} names no `{evidence}`, so the rule states no measurement and a "
            "reader must open #612 to find one"
        )


# --- The repository guide -------------------------------------------------------------


def test_the_parity_section_of_the_guide_holds_the_three_rules() -> None:
    """The guide holds the parity section, because a case over an empty body passes."""
    body = section(REPOSITORY_GUIDE.read_text(encoding="utf-8"), GUIDE_PARITY_HEADING)
    assert "The port decides interface." in collapsed(body), (
        f"{REPOSITORY_GUIDE} holds no `{GUIDE_PARITY_HEADING}` section that states rule 2"
    )


def test_the_guide_points_the_reader_of_parity_rule_two_at_the_cost_rule() -> None:
    """The parity section of the guide names the rule file that states the cost rule."""
    body = section(REPOSITORY_GUIDE.read_text(encoding="utf-8"), GUIDE_PARITY_HEADING)
    assert ".claude/rules/conformance.md" in body, (
        f"{REPOSITORY_GUIDE} names no `.claude/rules/conformance.md` beside parity rule 2, "
        "so a reader of the parity rules reaches the cost rule through no path"
    )
    assert "#612" in body, (
        f"{REPOSITORY_GUIDE} names no #612 beside parity rule 2, so the cross-reference "
        "states no cause"
    )
