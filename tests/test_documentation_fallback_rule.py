"""Tests that every statement of the vector-fallback rule names a reader.

`.claude/rules/external-apis.md` states the rule. **The vector fallback needs an image
that a person read and found ambiguous.** An image that nobody read is not a license to
use the fallback. Round 49 of `docs/specs/spec.md` records the correction: the earlier
wording read `where an image is ambiguous`, and that wording presumes a reading nobody
made.

#477 reported one page that kept the superseded wording, and the sweep measured three.
`docs/specs/spec.html` stated the corrected rule in one card and the superseded rule in
another, 118 lines apart. `docs/specs/features/01-spec-conformance.md` stated it in its
`## Behaviour rules` list. `docs/implementation_notes.md` stated it in the paragraph that
states why the file exists.

## Why this file reads a shape and no phrase

The user states the rule. **"A check that a rewording defeats is not a check."** #449
measured that cost on the neighbouring bullet of the same page. A case held the fixed
phrase `seven of the twelve` and the page wrote `Seven of twelve`. One missing article
therefore carried a superseded count through 97 rounds of a passing case.

Two properties follow, and each closes one half of the hole.

1. **The reader finds a statement of the rule, and it forbids no phrase.**
   `fallback_statements` matches a condition about an image that does not settle a
   question, bound to a sentence that gives the ruling to the expected-output files.
   Four word orders reach it, and the pattern needs no conjunction.
2. **The reader reports the premise and not the words.** A statement passes when a
   reader premise stands inside `CONTEXT_WINDOW` characters before it, or inside
   `TRAILING_WINDOW` characters after it. A page that drops the reader still fails,
   whatever words it chooses.

## What a case here does not read

**A dated record of a past measurement is quoted, not rewritten.** The `## Changelog`
section of `docs/specs/spec.md` records the state of the project at the time of writing.
Round 49 quotes the superseded wording, and a later round quotes the sentence #477
corrects. `readable_text` cuts that section, so a correction here destroys no record.
`CHANGELOG.md` reaches no case here at all, because `_documentation_files` never holds
it.

**An application of the rule to one transcription rule is not a statement of the rule.**
`docs/specs/foxio/JA4H.md` writes `This rule is uncertain. Keep the vector fallback.`
twelve times. Such a sentence states no condition about an image, so the reader passes
over it.

## The holes this reader keeps

A shape reads more spellings than a phrase reads, and it reads no sentence at all. Each
hole below is recorded and none is closed.

- **A wide clause.** `GAP_WIDTH` is 160 characters, so a condition further than that from
  its ruling reaches no pattern.
- **A synonym of `image`.** `diagram` and `figure` reach nothing. `.claude/rules/ste.md`
  forbids a synonym of a term, so a compliant page writes `image`.
- **A statement that spans two sentences.** `The image may be ambiguous. The
  expected-output file then decides.` holds the rule across a sentence end, and every
  pattern here stops at one.
- **A reader premise that belongs to another paragraph.** The window reads 600 characters
  before the statement and 200 after it, so a page that states the premise once at its top
  and the rule at its bottom fails a case here. A page states the premise beside the rule.
- **A neighbouring premise.** A superseded statement passes where a corrected statement of
  another rule stands inside the same window. The two windows are narrow for that reason,
  and no page of the corpus reaches the case today.
- **A sentence of another subject that borrows this vocabulary.** `The expected-output
  files decide almost everything, except where the image format the logo uses is
  ambiguous.` fails a case here, and it states no rule of this project. The reader reports
  such a sentence rather than pass it, because a false report fails loudly and a missed
  statement passes in silence.
- **A false reader premise.** The window reads that a page names a reader. It reads no
  proof that a person read an image.

These cases read prose. They import nothing from `ja4plus` and they produce no
fingerprint.
"""

import re
from pathlib import Path
from typing import List, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION_PAGE = REPO_ROOT / "docs" / "specs" / "spec.html"

# The rule this project states, held here as the record of the correction round 49 made.
# No case searches a document for it.
SUPERSEDED_PHRASE = "where an image is ambiguous"

# The heading of the section that records a state of the project at the time of writing.
# `readable_text` cuts it out of `docs/specs/spec.md`.
RECORD_SECTION = "## Changelog"

# An HTML tag, which the reader drops before it reads `docs/specs/spec.html`. A tag inside
# a sentence otherwise hides the words on each side of it.
HTML_TAG = re.compile(r"<[^>]+>")

# One character that continues a sentence. A period inside a path or inside a file name
# continues the sentence, and a period before a space ends it. A gap that stops at every
# period breaks the chain across `docs/implementation_notes.md`.
INSIDE_SENTENCE = r"(?:[^.]|\.(?!\s))"

# **Warning: the gap between two parts of one statement is 160 characters.** A wider gap
# reads a condition of one clause against the ruling of another and reports a rule the
# page never stated.
GAP_WIDTH = 160

# **Warning: the window before a statement is 600 characters.** `.claude/rules/conformance.md`
# states the reader premise in one paragraph and the ruling in the numbered list below
# it, and the two sit 250 characters apart.
CONTEXT_WINDOW = 600

# **Warning: the window after a statement is 200 characters.** `.claude/rules/external-apis.md`
# states the premise in the sentence that follows the rule. A wider window reads the
# premise of the next rule and passes a statement that names no reader of its own.
TRAILING_WINDOW = 200


def _gap(width: int = GAP_WIDTH) -> str:
    """Return a pattern that matches up to the width, inside one sentence.

    Args:
        width: The largest number of characters the gap accepts.

    Returns:
        A non-greedy pattern that crosses no sentence end.
    """
    return INSIDE_SENTENCE + "{0," + str(width) + "}?"


# The condition of the fallback. An image settles a question, or it does not.
AMBIGUITY = (
    r"(?:"
    r"ambiguous|ambiguity|unclear"
    r"|does\s+not\s+settle|settles?\s+(?:no|nothing|none)"
    r"|leaves?(?:\s+\w+){0,2}\s+open"
    r"|says?\s+nothing"
    r")"
)

# The source the fallback gives the ruling to.
AUTHORITY_SOURCE = r"(?:expected[-\s]output\s+files?|vectors?)"

# The ruling the fallback gives away. The expected-output files decide, they are the
# authority, or a passive sentence gives the ruling to them.
AUTHORITY = (
    r"(?:"
    + AUTHORITY_SOURCE
    + _gap(60)
    + r"(?:decides?|decide\b|(?:as|is|are)\s+the\s+authority)"
    + r"|(?:decided|settled)\s+by"
    + _gap(20)
    + AUTHORITY_SOURCE
    + r")"
)

# The word that binds a condition to its ruling. **The reader accepts no conjunction as
# well**, because a semicolon and the word `means` each state the same rule. A pattern
# that named one conjunction would fall to the next writer who chose another.
CONJUNCTION = r"(?:\b(?:where|when|if|whenever|because|since|unless|given\s+that)\b\s*)?"

# A reader premise. The rule needs an image that a person read, so a page states who read
# it. `the reading` names a record and no reader, and `\bread\b` therefore skips it.
READER_PREMISE = re.compile(
    r"(?:"
    r"\b(?:an?|the|no)\s+(?:person|reader|maintainer|one)\b[^.]{0,40}?\breads?\b"
    r"|\bnobody\s+reads?\b"
    r"|\breads?\s+the\s+image\b"
    r"|\bimages?\s+(?:that\s+)?(?:nobody|no\s+one|a\s+person|a\s+reader)\s+reads?\b"
    r")",
    re.IGNORECASE,
)

# The word order that opens with the condition, as in `Where an image is ambiguous, the
# expected-output files decide` and `An image is ambiguous; the expected-output files
# decide`.
CONDITION_FIRST = CONJUNCTION + r"\bimages?\b" + _gap() + AMBIGUITY + _gap() + AUTHORITY

# The word order that opens with the ruling, as in `The expected-output file decides
# where the image is ambiguous`.
AUTHORITY_FIRST = (
    AUTHORITY
    + _gap(60)
    + r"\b(?:where|when|if|whenever|because|since|unless|given\s+that)\b"
    + _gap(120)
    + (r"\bimages?\b" + _gap(120) + AMBIGUITY)
)

# The word order that states what the fallback needs, as in `The vector fallback needs an
# image that a person read and found ambiguous`. **The pattern names the vector fallback
# and not any fallback**, because a page that describes a rendering fallback of an image
# states no rule of this project.
REQUIREMENT_FORM = (
    r"\bvector\s+fallbacks?\b" + _gap(80) + r"\b(?:needs?|requires?)\b" + _gap(80) + r"\bimages?\b"
)

# The word order that opens with the ambiguous image, as in `An ambiguous image gives the
# ruling to the expected-output file`. The noun pair `ambiguous image` already states
# the condition, so this pattern needs no verb of ruling after the expected-output
# files. A bare `vector` needs that verb, because `the vectors team` names no authority.
AMBIGUOUS_IMAGE_FIRST = (
    r"\bambiguous\s+images?\b"
    + _gap(120)
    + r"(?:expected[-\s]output\s+files?|vectors?\s+(?:decides?|decide\b))"
)

FALLBACK_STATEMENTS = (
    re.compile(CONDITION_FIRST, re.IGNORECASE),
    re.compile(AUTHORITY_FIRST, re.IGNORECASE),
    re.compile(REQUIREMENT_FORM, re.IGNORECASE),
    re.compile(AMBIGUOUS_IMAGE_FIRST, re.IGNORECASE),
)

# Every page that states the rule. **An aggregate over an empty set passes**, so a case
# holds each page against the reader. A page that loses its statement fails here.
RULE_PAGES = (
    Path(".claude") / "rules" / "external-apis.md",
    Path(".claude") / "rules" / "conformance.md",
    Path("docs") / "specs" / "foxio" / "README.md",
    Path("docs") / "specs" / "spec.md",
    Path("docs") / "specs" / "spec.html",
    Path("docs") / "specs" / "features" / "01-spec-conformance.md",
)

# The count of statements the corpus holds. A sweep that reads fewer than this reports a
# reader that stopped matching rather than a corpus that states the rule.
MINIMUM_FALLBACK_STATEMENTS = len(RULE_PAGES)


def _documentation_files() -> List[Path]:
    """Return every prose file that may state the vector-fallback rule.

    Returns:
        The Markdown pages under `docs/` and `.claude/rules/`, the rendered
        `docs/specs/spec.html`, `CLAUDE.md` and `README.md`.
    """
    files = sorted((REPO_ROOT / "docs").rglob("*.md"))
    files += sorted((REPO_ROOT / ".claude" / "rules").glob("*.md"))
    files.append(SPECIFICATION_PAGE)
    files.append(REPO_ROOT / "CLAUDE.md")
    files.append(REPO_ROOT / "README.md")
    return [path for path in files if path.is_file()]


def _plain(text: str) -> str:
    """Return the text with no HTML tag and one space between words.

    A line break splits a statement of the rule, and an HTML tag hides the words beside
    it. The reader removes both before it matches a pattern.

    Args:
        text: The whole page.

    Returns:
        The text as one line.
    """
    return re.sub(r"\s+", " ", HTML_TAG.sub(" ", text)).strip()


def readable_text(path: Path, text: str) -> str:
    """Return the part of one page that states the rule of today.

    The `## Changelog` section of `docs/specs/spec.md` records a past measurement, and a
    round quotes the superseded wording word for word. A case that read the section would
    force a rewrite of the record.

    Args:
        path: The file the text comes from.
        text: The whole page.

    Returns:
        The readable text, as one line.
    """
    if path.name == "spec.md" and RECORD_SECTION in text:
        text = text.split(RECORD_SECTION)[0]
    return _plain(text)


def fallback_statements(text: str) -> List[Tuple[str, bool]]:
    """Return every statement of the vector-fallback rule the text holds.

    Args:
        text: The readable text of one page, or one sentence.

    Returns:
        One pair for each statement: the phrase, and whether a reader premise stands
        within `CONTEXT_WINDOW` characters before the end of it.
    """
    plain = _plain(text)
    found: List[Tuple[int, int]] = []
    for pattern in FALLBACK_STATEMENTS:
        for match in pattern.finditer(plain):
            found.append((match.start(), match.end()))
    # Two patterns match one sentence, so a report of both counts one statement twice.
    # The widest span of an overlapping pair is the statement, so the sort puts the
    # widest first and the loop drops what it covers.
    statements: List[Tuple[str, bool]] = []
    previous_end = -1
    for start, end in sorted(found, key=lambda span: (span[0], -span[1])):
        if start < previous_end:
            continue
        previous_end = end
        context = plain[max(0, start - CONTEXT_WINDOW) : end + TRAILING_WINDOW]
        statements.append((plain[start:end], bool(READER_PREMISE.search(context))))
    return statements


def _offenders() -> List[str]:
    """Return every statement of the corpus that names no reader.

    Returns:
        One `<path>: <phrase>` entry for each statement that fails the rule.
    """
    offenders = []
    for path in _documentation_files():
        text = readable_text(path, path.read_text(encoding="utf-8"))
        for phrase, has_reader in fallback_statements(text):
            if not has_reader:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {phrase!r}")
    return offenders


def test_every_statement_of_the_fallback_rule_names_a_reader() -> None:
    """No page states the vector fallback without the reader the rule needs."""
    assert _offenders() == [], (
        "these statements give the decision to the expected-output files without a "
        f"reader, and {SUPERSEDED_PHRASE!r} is the wording round 49 superseded: "
        f"{_offenders()}"
    )


def test_the_corpus_states_the_fallback_rule_at_least_once_for_each_page() -> None:
    """The sweep reads at least one statement for each page that states the rule."""
    total = 0
    for path in _documentation_files():
        text = readable_text(path, path.read_text(encoding="utf-8"))
        total += len(fallback_statements(text))
    assert total >= MINIMUM_FALLBACK_STATEMENTS, (
        f"the sweep reads {total} statements and the corpus holds "
        f"{MINIMUM_FALLBACK_STATEMENTS} pages that state the rule"
    )


@pytest.mark.parametrize("relative", RULE_PAGES, ids=[str(path) for path in RULE_PAGES])
def test_each_page_that_states_the_fallback_rule_holds_a_statement(relative: Path) -> None:
    """Each page of `RULE_PAGES` holds one statement of the rule that the reader finds."""
    path = REPO_ROOT / relative
    statements = fallback_statements(readable_text(path, path.read_text(encoding="utf-8")))
    assert statements, f"{relative} states no rule the reader finds"


def test_the_rendered_specification_page_states_one_form_of_the_fallback_rule() -> None:
    """`docs/specs/spec.html` states the rule twice, and both statements name a reader."""
    statements = fallback_statements(SPECIFICATION_PAGE.read_text(encoding="utf-8"))
    assert len(statements) >= 2, f"the page states {len(statements)} statements of the rule"
    without_reader = [phrase for phrase, has_reader in statements if not has_reader]
    assert without_reader == [], f"these statements of the page name no reader: {without_reader}"


# The spellings the corpus could plausibly carry for the superseded rule. #211 and #449
# each proved that one forbidden phrase guards one spelling, so the reader is proved
# against the set.
SUPERSEDED_PHRASINGS = (
    "Where an image is ambiguous, the expected-output files decide and the reading is recorded.",
    "Where the FoxIO material is an image and the image is ambiguous, the expected-output"
    " file decides, and the reading goes into `docs/implementation_notes.md`.",
    "Where an image is ambiguous, the expected-output file decides.",
    "If the image is unclear, the expected-output files decide.",
    "When an image is ambiguous, the vectors decide.",
    "Where an image settles nothing, the expected-output file is the authority.",
    "Where an image leaves the question open, the expected-output files decide.",
    "Where an image says nothing, the expected-output file decides.",
    "The expected-output file decides where the image is ambiguous.",
    "The expected-output files are the authority when an image is ambiguous.",
    "An ambiguous image gives the decision to the expected-output file.",
    "An ambiguous image reaches the expected-output files, which decide.",
    "Where an image does not settle the question, the expected-output files decide.",
    "Whenever an image is ambiguous, the expected-output file decides the bytes.",
    "Where an image carries an ambiguity, the expected-output files decide.",
    "If an image is ambiguous, the vector decides and the reading is recorded.",
    "Because an image is ambiguous, the expected-output file decides.",
    "The expected-output files decide, since the image is ambiguous.",
    "Given that an image is ambiguous, the vectors decide.",
    "An image is ambiguous; the expected-output files decide.",
    "An image that is ambiguous means the expected-output files decide.",
    "The reading is decided by the expected-output files where an image is ambiguous.",
)


@pytest.mark.parametrize("sentence", SUPERSEDED_PHRASINGS)
def test_the_reader_reads_the_superseded_rule_in_each_plausible_phrasing(sentence: str) -> None:
    """The reader reports one statement with no reader for each superseded spelling."""
    statements = fallback_statements(sentence)
    assert len(statements) == 1, f"the reader reads {len(statements)} statements in {sentence!r}"
    assert statements[0][1] is False, f"the reader finds a reader premise in {sentence!r}"


# The corrected rule, in the spellings the corpus writes today plus three more. Each
# one names the reader the rule needs.
CORRECTED_PHRASINGS = (
    "Where a reader reads the image and finds it ambiguous, the expected-output files"
    " decide and the reading goes in `docs/implementation_notes.md`.",
    "Where a reader reads the image and the image does not settle the question, the"
    " expected-output files under `python/test/testdata/` decide.",
    "Where a reader reads the image and finds it ambiguous, the project treats the"
    " expected-output files as the authority.",
    "The vector fallback needs an image that a person read and found ambiguous.",
    "Read the image before you call it ambiguous. If the image does not settle the"
    " question, the expected-output file decides.",
    "A maintainer reads the image first. Where that image is ambiguous, the"
    " expected-output files decide.",
)


@pytest.mark.parametrize("sentence", CORRECTED_PHRASINGS)
def test_the_reader_accepts_each_corrected_phrasing(sentence: str) -> None:
    """The reader reports a reader premise for each spelling of the corrected rule."""
    statements = fallback_statements(sentence)
    assert statements, f"the reader reads no statement in {sentence!r}"
    assert all(has_reader for _, has_reader in statements), (
        f"the reader finds no reader premise in {sentence!r}"
    )


# Sentences that name the fallback and state no rule about an image. A reader that
# reported one of these would fail every transcription page of `docs/specs/foxio/`.
CONTROL_SENTENCES = (
    "This rule is uncertain. Keep the vector fallback.",
    "R11 stays uncertain, and the vector fallback stays.",
    "The image settles none of this. It draws one example.",
    "No expected-output file of the 37 carries a `JA4T` key.",
    "`python/test/testdata/` decides where both directories carry a value.",
    "The expected-output file is a JSON array. Each element describes one stream.",
    "Keep the vector fallback for an uncertain rule.",
    "A reader records the reading in `docs/implementation_notes.md`.",
    "The rendering fallback needs an image with alternative text.",
    "An ambiguous image of the slide deck reached the vectors team.",
)


@pytest.mark.parametrize("sentence", CONTROL_SENTENCES)
def test_the_reader_reads_no_statement_where_a_sentence_states_another_rule(sentence: str) -> None:
    """The reader reports no statement of the rule for a sentence that states another."""
    statements = fallback_statements(sentence)
    assert statements == [], f"the reader reads {statements} in {sentence!r}"


def test_the_changelog_cut_removes_a_rule_the_record_quotes() -> None:
    """`readable_text` cuts the `## Changelog` section, which quotes the superseded rule."""
    quotation = (
        "| TBD | 2026-08-09 | A round quotes the superseded sentence: `Where an image is"
        " ambiguous, the expected-output files decide and the reading is recorded.` |"
    )
    page = f"# Spec\n\nBody.\n\n{RECORD_SECTION}\n\n{quotation}\n"
    spec = REPO_ROOT / "docs" / "specs" / "spec.md"
    assert fallback_statements(_plain(page)), "the reader reads no rule in the quotation"
    assert fallback_statements(readable_text(spec, page)) == [], (
        "the cut leaves the quoted rule of the record inside the readable text"
    )
