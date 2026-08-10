"""Tests that the prose names a determination of the user by its controlled term.

The `## Terms` table of `docs/specs/spec.md` holds one row for `ruling`. The fourth column
of that row names `decision` as a word a writer does not use. The prose of this project
rotated the two words against each other, and rule 7 of `.claude/rules/ste.md` bars that:
"One concept, one word. Never rotate synonyms for variety." #533 records the ruling of the
user, and these cases hold the result.

**A corrected sentence goes stale the next time a writer reaches for the rejected word.**
Each case here therefore reads the corpus for the word, rather than restate a sentence. The
rejected word comes out of the `## Terms` row, so a change to the row changes what the cases
forbid. `tests/test_statistics_thread_term.py` holds the same shape for #441, and this
module follows it.

## Which words a case reads

**A case reads the noun `decision` and the plural `decisions`, and it reads no verb.** Rule
6 states one word, one meaning, one part of speech, so the noun and the verb are separate
questions and #533 rules on the noun alone. `decides` and `decided` therefore reach no match
here. Two records rest on that limit.

- `tests/foxio_deviations.json` carries a `decided` field on every entry, and
  `tests/foxio_deviations.py` reads that key. **A schema key is not prose and it does not
  move.**
- "The specification decides intent and schema" states a rule of `CLAUDE.md`, and the verb
  names the authority of a document rather than a determination of the user.

## How a case reads a Python file

**A case reads a Python file as prose and never as text.** `python_prose` of
`tests/test_documented_method_count.py` parses the file, and it returns the comments and the
docstrings alone. The prose then passes `without_quoted`, so a code span, a fenced block and
a blockquote line come out of a docstring exactly as they come out of a Markdown page.

**A string literal that is no docstring reaches no case, and the reader leaves it exactly as
it reads.** Such a literal is data and not prose: a case compares it, an assertion states it,
a schema names it, or a fixture holds the sentence the case measures. The verbatim list of
`.claude/rules/ste.md` covers each of those. `test_the_reader_reads_no_code_span` builds one
such literal, which names a branch of #266, and a rewrite there would move what the case
compares.

**An identifier reaches no case either.** `python_prose` reads no code, so a function name, a
variable name and a key name all stay. `RULED_WORD` of this module binds the barred word, and
`decided_by` of `ja4plus/fingerprinters/ja4ssh.py` names a field.

**#548 reached the Python corpus, and #533 left the hole it filled.** #533 states that no
file under `ja4plus/` changes, so its reader read the Markdown corpus alone while nine
comments and docstrings under the package named the barred word.

**A dated record of a past measurement is quoted, not rewritten.** `CHANGELOG.md` records
one past round in every entry, and the `## Changelog` table of `docs/specs/spec.md` holds
one row for each round. Eighteen entries and about fifty-five rows name the rejected word,
and #533 leaves every one exactly as it reads. `readable_prose` cuts both records. #441 made
the same reading for `reporter`.

**Warning: `.claude/rules/ste.md` exempts those two records from rule 1 and rule 3 alone,
and it states that rule 7 reaches both.** The reading above therefore rests on the verbatim
list of that file and not on the exemption. That list holds "Evidence: error messages, log
excerpts, test names, stack traces, command output", and a round entry records what one
round measured. **Where the reading is unclear this project leaves the record alone**, so
these cases forbid the word in the live prose and they forbid it in no record.

**A blockquote reproduces text this project quotes rather than writes.** `readable_prose`
cuts every line that opens with `>`. `docs/specs/foxio/zeek.md:480-482` is such a line: #515
superseded a sentence and the page states "The sentence below is the state before that,
quoted rather than rewritten." The live sentence below that quotation names `ruling`.

**The `## Terms` section states the rejected word, so `readable_prose` cuts it too.** The
row is the authority these cases read, and a reader that forbade its own authority would
fail on the specification itself.

**The Markdown corpus holds `docs/specs/spec.html` beside the Markdown pages.** A writer
edits that page by hand, so a rejected word reaches a reader there as it reaches one in a
Markdown page. `documents` of `tests/test_documented_method_count.py` reads it for the same
reason.

These cases read prose. They produce no fingerprint and they open no capture socket.
"""

import re
import subprocess
from pathlib import Path
from typing import List

import pytest

from tests.test_documented_method_count import python_prose

REPO_ROOT = Path(__file__).resolve().parent.parent

# The term whose row states the controlled word and the rejected words.
CONTROLLED_TERM = "ruling"

# The heading of the section that holds the controlled vocabulary.
TERMS_HEADING = "## Terms"

# The rejected word #533 forbids. The row rejects two more words, and the module docstring
# states that a case reads this one alone.
RULED_WORD = "decision"

# The words the row rejects that no case here forbids. `call` and `verdict` each carry
# another meaning in this repository, so a sweep for either one would report a sentence that
# names no determination of the user.
UNREAD_WORDS = ("call", "verdict")

# The headings of the sections that record a past state of the project. `readable_prose`
# cuts each one out of `docs/specs/spec.md`, beside the section that states the vocabulary.
RECORD_SECTIONS = ("## Risks & open questions", "## Changelog", TERMS_HEADING)

# The file that records one past round in every entry.
RECORD_FILE = "CHANGELOG.md"

# A fence delimiter of a Markdown page. The reader drops a fenced block before it reads,
# because a fence holds code and the writing standard reproduces code verbatim.
#
# **Warning: a line that opens with three backticks is not always a fence.** An inline span
# may carry three backticks and close them on the same line. CommonMark states the rule that
# tells the two apart: "If the info string comes after a backtick fence, it may not contain
# any backtick characters." The pattern therefore requires that no backtick follows the
# delimiter on that line.
#
# Verified against https://spec.commonmark.org/0.31.2/#fenced-code-blocks (CommonMark 0.31.2,
# retrieved 2026-08-10).
#
# **A reader that takes such a line for a fence opener shifts every pair below it.** #533
# measured the cost on `docs/specs/foxio/JA4X.md`, whose line 235 reads
# ```` ```JA4X=2bab15409345_af684594efb4_000000000000```. ````. That one line paired 17
# markers wrongly and built three phantom blocks of 34, 128 and 160 lines. The reader then
# read none of the prose inside them, so a rotation there passed the gate and a review found
# it instead.
FENCE_DELIMITER = re.compile(r"^\s*```[^`]*$")

# A code span. The reader drops one before it reads. A span holds an identifier, a path or a
# command, and the writing standard reproduces each one verbatim.
#
# **Warning: the reader drops a code span one line at a time.** A search over a whole page
# pairs a backtick of one line with a backtick far below it. It then drops every word
# between them. `tests/test_statistics_thread_term.py` records the same measurement.
CODE_SPAN = re.compile(r"`[^`]*`")

# A blockquote line. The writing standard reproduces a quotation verbatim, so the reader
# drops the line rather than demand a rewrite of quoted text.
BLOCKQUOTE_LINE = re.compile(r"^\s*>")

# The git pathspec that names every tracked Markdown page. **In a default git pathspec `*`
# crosses `/`**, so this one term reaches every depth.
MARKDOWN_PATHSPEC = "*.md"

# The rendered page of the specification. A writer edits it by hand, so a rejected word
# reaches a reader there as it reaches one in a Markdown page.
RENDERED_PAGE = "docs/specs/spec.html"

# The least count of Markdown pages the corpus holds. **An aggregate over an empty set
# passes**, so a reader that named no page would report a green result for every case here.
MARKDOWN_FLOOR = 20

# Four pages that held the rejected word before #533. A case names each one, so a reader
# that stops reaching a corpus fails here rather than passes over nothing.
ANCHOR_FILES = (
    "README.md",
    "CLAUDE.md",
    "docs/implementation_notes.md",
    "docs/specs/foxio/JA4X.md",
    RENDERED_PAGE,
)


# The git pathspec that names every tracked Python source. **In a default git pathspec `*`
# crosses `/`**, so this one term reaches the package, the suite and the examples.
PYTHON_PATHSPEC = "*.py"

# The least count of Python sources the corpus holds. **An aggregate over an empty set
# passes**, so a reader that named no source would report a green result for every case.
PYTHON_FLOOR = 120

# The least count of package sources the corpus holds. **The suite alone passes
# `PYTHON_FLOOR`**, so a corpus that dropped `ja4plus/` would meet that floor and read no
# comment of the library. A read of 2026-08-10 counts 31 sources under `ja4plus/`.
PACKAGE_FLOOR = 25

# The directory of the package, as the corpus names it.
PACKAGE_DIRECTORY = "ja4plus/"

# Three sources that held the barred word before #548, and the reader itself. A case names
# each one, so a corpus that stops reaching the package fails here rather than passes over
# nothing.
PYTHON_ANCHOR_FILES = (
    "ja4plus/fingerprinters/ja4ssh.py",
    "ja4plus/fingerprinters/ja4l.py",
    "ja4plus/utils/http_utils.py",
    "tests/test_ruling_vocabulary.py",
)


# A Markdown heading of any level.
HEADING_LINE = re.compile(r"^#{1,6}\s+(.+?)\s*$")

# A phrase inside double quotation marks. **The reader normalizes the whitespace of the prose
# first**, because a cross-reference wraps across two lines and the closing mark then stands
# on the line below the opening one. `docs/specs/foxio/JA4X.md:635` is such a reference.
QUOTED_PHRASE = re.compile(r'"([^"]{8,120})"')

# The words the vocabulary folds together, so that a quoted cross-reference and the heading
# it names compare equal under the fold and unequal character for character. That pair is
# exactly the state a sweep leaves when it renames one side and not the other.
VOCABULARY_FOLD = re.compile(r"\b(rulings?|decisions?)\b", re.IGNORECASE)

# The least count of headings the corpus holds. **An aggregate over an empty set passes**, so
# a reader that collected no heading would pair every cross-reference with nothing.
HEADING_FLOOR = 200


def rejected_words() -> List[str]:
    """Return the words the `## Terms` row of the controlled term rejects.

    The reader reads the fourth column of the row whose first column is the controlled term,
    and it splits that column on the comma.

    Returns:
        Each rejected word, in the order the row holds them.

    Raises:
        AssertionError: The table holds no row for the controlled term.
    """
    text = (REPO_ROOT / "docs" / "specs" / "spec.md").read_text(encoding="utf-8")
    for line in text.splitlines():
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) == 6 and cells[1] == CONTROLLED_TERM:
            return [word.strip() for word in cells[4].split(",") if word.strip()]
    raise AssertionError(f"the `## Terms` table holds no row for {CONTROLLED_TERM!r}")


def word_pattern(word: str) -> "re.Pattern[str]":
    """Return the pattern that reads one rejected word as a whole word.

    The pattern reads the plural form. It reads no verb form, so `decides` and `decided`
    reach no match and the `decided` key of `tests/foxio_deviations.json` stays.

    Args:
        word: One rejected word of the `## Terms` row.

    Returns:
        The compiled pattern.
    """
    return re.compile(r"\b" + re.escape(word) + r"s?\b", re.IGNORECASE)


def readable_prose(name: str, text: str) -> str:
    """Return the text of one document with every passage a case does not read removed.

    Args:
        name: The path of the document, relative to the repository root.
        text: The whole text of the document.

    Returns:
        The prose a case reads. `CHANGELOG.md` reads as an empty document,
        `docs/specs/spec.md` loses the sections `RECORD_SECTIONS` names, and every page
        loses its fenced blocks, its code spans and its blockquote lines.
    """
    if Path(name).name == RECORD_FILE:
        return ""
    if Path(name).name == "spec.md":
        for heading in RECORD_SECTIONS:
            start = text.find(f"\n{heading}")
            if start == -1:
                continue
            end = text.find("\n## ", start + 1)
            text = text[:start] + (text[end:] if end != -1 else "")
    return without_quoted(text)


def without_quoted(text: str) -> str:
    """Return the text with every fenced block, code span and blockquote line removed.

    The reader drops a code span one line at a time. A search over the whole text pairs a
    backtick of one line with a backtick far below it.

    **The reader tracks a fence one line at a time**, because a line that opens with three
    backticks and closes them again is an inline span and not a fence opener.

    Args:
        text: The text of one document.

    Returns:
        The text with no fenced block, no code span and no blockquote line.
    """
    kept = []
    fenced = False
    for line in text.splitlines():
        if FENCE_DELIMITER.match(line):
            fenced = not fenced
            continue
        if fenced or BLOCKQUOTE_LINE.match(line):
            continue
        kept.append(line)
    return "\n".join(CODE_SPAN.sub(" ", line) for line in kept)


def rejected_uses(text: str, word: str) -> List[str]:
    """Return every place the text names the rejected word, with the words around it.

    Args:
        text: The prose of one document, after `readable_prose` ran.
        word: The rejected word.

    Returns:
        One passage for each match, which names the word and the words before it.
    """
    found = []
    for line in text.splitlines():
        for match in word_pattern(word).finditer(line):
            start = max(0, match.start() - 40)
            found.append(" ".join(line[start : match.end()].split()))
    return found


def markdown_documents(pathspec: str = MARKDOWN_PATHSPEC) -> List[str]:
    """Return every prose page a case reads, relative to the repository root.

    **The reader asks git for the files and it walks no directory.** The agent harness
    places a worker worktree at `.claude/worktrees/agent-<id>`, and that worktree is a whole
    checkout. A walk would therefore read the files of every live worker, and the corpus
    would grow with the count of live workers. #473 records the measurement.

    Args:
        pathspec: The git pathspec that names the pages. A case passes another pathspec to
            measure the floor.

    Returns:
        One path for each page, and `docs/specs/spec.html` beside them.

    Raises:
        AssertionError: The corpus holds fewer pages than `MARKDOWN_FLOOR`.
    """
    found = tracked_pages(pathspec)
    found.append(RENDERED_PAGE)
    assert len(found) >= MARKDOWN_FLOOR, (
        f"the corpus holds {len(found)} Markdown pages, below the floor of {MARKDOWN_FLOOR}, "
        "and an aggregate over an empty set passes"
    )
    return found


def tracked_pages(pathspec: str) -> List[str]:
    """Return every tracked file the pathspec names, with no floor applied.

    A case reads this to measure the floor of `markdown_documents`.

    Args:
        pathspec: The git pathspec that names the files.

    Returns:
        One path for each file, sorted.

    Raises:
        subprocess.CalledProcessError: The read of git failed.
    """
    listed = subprocess.run(
        ["git", "ls-files", "-z", pathspec],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split("\0")
    return sorted(name for name in listed if name)


def python_sources(pathspec: str = PYTHON_PATHSPEC) -> List[str]:
    """Return every Python source a case reads, relative to the repository root.

    **The reader asks git for the files and it walks no directory.** A walk would read the
    sources of every live worker worktree, and the corpus would grow with the count of live
    workers. #473 records the measurement.

    Args:
        pathspec: The git pathspec that names the sources. A case passes another pathspec to
            measure the floor.

    Returns:
        One path for each tracked Python source, sorted.

    Raises:
        AssertionError: The corpus holds fewer sources than `PYTHON_FLOOR`, or fewer package
            sources than `PACKAGE_FLOOR`.
    """
    found = tracked_pages(pathspec)
    assert len(found) >= PYTHON_FLOOR, (
        f"the corpus holds {len(found)} Python sources, below the floor of {PYTHON_FLOOR}, "
        "and an aggregate over an empty set passes"
    )
    package = [name for name in found if name.startswith(PACKAGE_DIRECTORY)]
    assert len(package) >= PACKAGE_FLOOR, (
        f"the corpus holds {len(package)} sources under {PACKAGE_DIRECTORY}, below the floor "
        f"of {PACKAGE_FLOOR}, and the suite alone passes the floor above"
    )
    return found


def python_readable_prose(text: str) -> str:
    """Return the prose of one Python source, with every passage a case does not read removed.

    The reader takes the comments and the docstrings, and it takes no other text. A string
    literal that is no docstring therefore stays exactly as it reads, because a case compares
    such a literal and the writing standard reproduces it verbatim.

    Args:
        text: The whole source of one Python file.

    Returns:
        The prose a case reads, with no fenced block, no code span and no blockquote line.

    Raises:
        SyntaxError: The text parses as no Python module.
    """
    return without_quoted(python_prose(text))


def headings_of(prose: str) -> List[str]:
    """Return the text of every heading of one document.

    Args:
        prose: The output of `readable_prose` for one document.

    Returns:
        One heading text for each heading line, with the marks and the spacing removed.
    """
    found = []
    for line in prose.splitlines():
        match = HEADING_LINE.match(line)
        if match:
            found.append(" ".join(match.group(1).split()))
    return found


def folded(phrase: str) -> str:
    """Return the phrase with every word of the vocabulary pair folded to one token.

    Args:
        phrase: One heading text, or one quoted cross-reference.

    Returns:
        The folded text, in lower case, with the whitespace normalized.
    """
    return VOCABULARY_FOLD.sub("TERM", " ".join(phrase.split())).casefold()


def quoted_phrases(prose: str) -> List[str]:
    """Return every phrase the prose holds inside double quotation marks.

    The reader normalizes the whitespace first, because a cross-reference wraps across two
    lines and the closing mark then stands on the line below the opening one.

    Args:
        prose: The output of `readable_prose` for one document.

    Returns:
        One phrase for each pair of quotation marks.
    """
    return [" ".join(m.group(1).split()) for m in QUOTED_PHRASE.finditer(" ".join(prose.split()))]


def corpus_headings() -> List[str]:
    """Return the text of every heading of every document a case reads.

    Returns:
        One heading text for each heading of the corpus.

    Raises:
        AssertionError: The corpus holds fewer headings than `HEADING_FLOOR`.
    """
    found = []
    for name in MARKDOWN_DOCUMENTS:
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        found.extend(headings_of(readable_prose(name, text)))
    assert len(found) >= HEADING_FLOOR, (
        f"the corpus holds {len(found)} headings, below the floor of {HEADING_FLOOR}, and a "
        "reader that collected none would pair every cross-reference with nothing"
    )
    return found


def stale_cross_references(prose: str, headings: List[str]) -> List[str]:
    """Return every quoted cross-reference that disagrees with the heading it names.

    A phrase names a heading where the two match under `folded`. Where they then differ
    character for character, one side took the controlled term and the other kept the barred
    word, which is the state a sweep leaves when it renames one side alone.

    Args:
        prose: The output of `readable_prose` for one document.
        headings: The heading text of every document of the corpus.

    Returns:
        One passage for each stale reference, which names the phrase and the heading.
    """
    exact = set(headings)
    by_fold = {}
    for heading in headings:
        by_fold.setdefault(folded(heading), heading)
    found = []
    for phrase in quoted_phrases(prose):
        if phrase in exact:
            continue
        heading = by_fold.get(folded(phrase))
        if heading is not None:
            found.append(f"{phrase!r} names the heading {heading!r}")
    return found


MARKDOWN_DOCUMENTS = markdown_documents()
CORPUS_HEADINGS = corpus_headings()
PYTHON_SOURCES = python_sources()


def test_the_terms_table_holds_the_row_for_the_ruled_term() -> None:
    """The `## Terms` table holds one row for the term #533 chose."""
    words = rejected_words()
    assert words, f"the row of {CONTROLLED_TERM!r} rejects no word"


def test_the_terms_table_rejects_the_ruled_word_for_a_determination_of_the_user() -> None:
    """The `## Terms` row of the ruling rejects the word the cases forbid."""
    assert RULED_WORD in rejected_words(), (
        f"the row of {CONTROLLED_TERM!r} rejects {rejected_words()}, and it names no "
        f"{RULED_WORD!r}, so every case here forbids a word the vocabulary admits"
    )


def test_the_reader_forbids_the_word_the_ruling_names() -> None:
    """The reader forbids one rejected word, and the row rejects two more.

    #533 rules on `decision` alone. `call` and `verdict` each carry another meaning in this
    repository, so a sweep for either one would report a sentence that names no
    determination of the user.
    """
    assert set(UNREAD_WORDS) < set(rejected_words()), (
        f"the row of {CONTROLLED_TERM!r} rejects {rejected_words()}, and the limit this "
        f"module records names {list(UNREAD_WORDS)}"
    )


@pytest.mark.parametrize("name", MARKDOWN_DOCUMENTS)
def test_no_document_names_a_determination_of_the_user_by_the_rejected_word(name: str) -> None:
    """No Markdown page names a determination of the user by the rejected word."""
    text = (REPO_ROOT / name).read_text(encoding="utf-8")
    offenders = rejected_uses(readable_prose(name, text), RULED_WORD)
    assert offenders == [], (
        f"{name} names {RULED_WORD!r} at {offenders}, and the `## Terms` row of "
        f"{CONTROLLED_TERM!r} rejects that word"
    )


@pytest.mark.parametrize("name", MARKDOWN_DOCUMENTS)
def test_no_quoted_cross_reference_disagrees_with_the_heading_it_names(name: str) -> None:
    """Every quoted cross-reference matches the heading it names, character for character.

    **A sweep that renames a heading and not the reference to it leaves a reader with a
    section that no page holds.** #533 shipped that state on `docs/specs/foxio/JA4X.md`: the
    reference at line 635 took the controlled term while the heading at line 254 kept the
    barred word. The corpus case reads one word at a time, so it reports nothing about a
    pair, and a review found this rather than a gate.
    """
    text = (REPO_ROOT / name).read_text(encoding="utf-8")
    stale = stale_cross_references(readable_prose(name, text), CORPUS_HEADINGS)
    assert stale == [], f"{name} holds a cross-reference that no heading matches: {stale}"


def test_the_reader_reports_a_cross_reference_that_lost_its_heading() -> None:
    """The reader reports a reference whose heading kept the barred word."""
    prose = 'See "The ruling of 2026-08-08" above.'
    stale = stale_cross_references(prose, ["The decision of 2026-08-08"])
    assert stale == ["'The ruling of 2026-08-08' names the heading 'The decision of 2026-08-08'"]


def test_the_reader_reports_no_cross_reference_that_matches_its_heading() -> None:
    """The reader reports nothing where the reference and the heading agree."""
    prose = 'See "The ruling of 2026-08-08" above.'
    assert stale_cross_references(prose, ["The ruling of 2026-08-08"]) == []


def test_the_reader_reports_no_quotation_that_names_no_heading() -> None:
    """The reader reports nothing for an ordinary quotation, which names no section."""
    prose = 'The standard states "One concept, one word. Never rotate synonyms for variety."'
    assert stale_cross_references(prose, ["The ruling of 2026-08-08"]) == []


def test_the_reader_pairs_a_cross_reference_that_wraps_across_two_lines() -> None:
    """The reader pairs a reference whose closing mark stands on the line below.

    `docs/specs/foxio/JA4X.md:635` opens a quotation that closes on the line below it.
    """
    prose = '"The ruling of 2026-08-08, and the\ncontradiction it records" above holds it.'
    heading = "The decision of 2026-08-08, and the contradiction it records"
    assert len(stale_cross_references(prose, [heading])) == 1


def test_the_corpus_pairs_at_least_one_cross_reference_with_its_heading() -> None:
    """The corpus holds a quoted phrase that matches a heading, so the reader pairs a real one.

    **A reader that paired nothing would report a clean corpus over every page.**
    """
    exact = set(CORPUS_HEADINGS)
    paired = []
    for name in MARKDOWN_DOCUMENTS:
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        prose = readable_prose(name, text)
        paired.extend(phrase for phrase in quoted_phrases(prose) if phrase in exact)
    assert paired, "no quoted phrase of the corpus matches a heading, so the reader pairs none"


def test_the_reader_reads_the_rejected_word_in_a_sentence() -> None:
    """The reader reads the rejected word where a sentence names it."""
    assert rejected_uses("The decision is reversible.", RULED_WORD) == ["The decision"]
    assert rejected_uses("Two decisions stand.", RULED_WORD) == ["Two decisions"]


def test_the_reader_reads_no_verb_form_of_the_rejected_word() -> None:
    """The reader reads no verb form, so the schema key and the authority rule both stay.

    `tests/foxio_deviations.json` carries a `decided` field on every entry, and `CLAUDE.md`
    states that the specification decides intent and schema.
    """
    assert rejected_uses("The user decided it on 2026-08-08.", RULED_WORD) == []
    assert rejected_uses("The specification decides intent and schema.", RULED_WORD) == []
    assert rejected_uses("The entry carries decided true.", RULED_WORD) == []


def test_the_reader_reads_no_code_span() -> None:
    """The reader reads no word inside a code span."""
    passage = "The branch `batch/266-register-gate-and-decisions` holds it."
    assert rejected_uses(without_quoted(passage), RULED_WORD) == []


def test_the_reader_reads_a_line_below_a_line_that_holds_one_backtick() -> None:
    """The reader reads a sentence below a line that holds one unpaired backtick.

    A search over a whole page pairs a backtick of one line with a backtick far below it. It
    then drops every word between them.
    """
    passage = "A line with one ` mark.\nAnother plain line.\nThe decision is reversible.\n"
    assert rejected_uses(without_quoted(passage), RULED_WORD) == ["The decision"]


def test_the_reader_reads_no_fenced_block() -> None:
    """The reader reads no word inside a fenced block."""
    passage = "A plain line.\n```\ndecision = read()\n```\nAnother plain line.\n"
    assert rejected_uses(without_quoted(passage), RULED_WORD) == []


def test_the_reader_reads_a_line_that_opens_with_an_inline_span_of_three_backticks() -> None:
    """The reader reads the prose below a line that opens with an inline triple-backtick span.

    **A line that opens with three backticks and closes them again is no fence opener.** A
    reader that takes one for a fence shifts every pair below it. #533 measured that on
    `docs/specs/foxio/JA4X.md`, where one such line built three phantom blocks of 34, 128 and
    160 lines and hid the prose inside them from every case here.
    """
    passage = "```JA4X=2bab15409345```. The parts match.\nThe decision is reversible.\n"
    assert rejected_uses(without_quoted(passage), RULED_WORD) == ["The decision"]


def test_the_reader_reads_no_blockquote_line() -> None:
    """The reader reads no line of a blockquote, which reproduces quoted text.

    `docs/specs/foxio/zeek.md` quotes a sentence #515 superseded, and that sentence names
    the rejected word. The live sentence below the quotation names the controlled term.
    """
    passage = "> adoption is its own decision.\nThe live line states the ruling.\n"
    assert rejected_uses(without_quoted(passage), RULED_WORD) == []


def test_the_reader_reads_no_record_of_a_past_round() -> None:
    """`readable_prose` cuts the two records and the section that states the vocabulary."""
    assert readable_prose(RECORD_FILE, "Round 125. The decision is reversible.") == ""
    specification = REPO_ROOT / "docs" / "specs" / "spec.md"
    whole = specification.read_text(encoding="utf-8")
    readable = readable_prose("docs/specs/spec.md", whole)
    for heading in RECORD_SECTIONS:
        assert heading in whole, f"the specification holds no {heading!r} section"
        assert heading not in readable, f"{heading!r} reaches a case that reads prose"
    assert "## Overview" in readable, "the reader cut a section that states no record"
    assert "## Issue map" in readable, "the reader swallowed the section below the Changelog"


@pytest.mark.parametrize("name", ANCHOR_FILES)
def test_the_corpus_holds_every_anchor_file(name: str) -> None:
    """A corpus names each file the reader must reach."""
    assert name in MARKDOWN_DOCUMENTS, f"no corpus names {name}"


def test_the_floor_fails_a_corpus_that_names_no_document() -> None:
    """The floor fails a reader that names no Markdown page.

    **An aggregate over an empty set passes**, so a corpus that read nothing would report a
    green run over no page at all.
    """
    assert tracked_pages("tests/foxio_vectors/*.json") != [], "the pathspec names no file"
    assert tracked_pages("*.nomatch") == [], "the pathspec names a tracked file"
    with pytest.raises(AssertionError, match="below the floor"):
        markdown_documents("*.nomatch")


@pytest.mark.parametrize("name", PYTHON_SOURCES)
def test_no_python_source_names_a_determination_of_the_user_by_the_rejected_word(
    name: str,
) -> None:
    """No comment and no docstring names a determination of the user by the rejected word."""
    text = (REPO_ROOT / name).read_text(encoding="utf-8")
    offenders = rejected_uses(python_readable_prose(text), RULED_WORD)
    assert offenders == [], (
        f"{name} names {RULED_WORD!r} at {offenders}, and the `## Terms` row of "
        f"{CONTROLLED_TERM!r} rejects that word"
    )


@pytest.mark.parametrize("name", PYTHON_ANCHOR_FILES)
def test_the_python_corpus_holds_every_anchor_source(name: str) -> None:
    """A corpus names each Python source the reader must reach."""
    assert name in PYTHON_SOURCES, f"no corpus names {name}"


def test_the_python_floor_fails_a_corpus_that_names_no_source() -> None:
    """The floor fails a reader that names no Python source.

    **An aggregate over an empty set passes**, so a corpus that read nothing would report a
    green run over no source at all.
    """
    with pytest.raises(AssertionError, match="below the floor"):
        python_sources("*.nomatch")


def test_the_package_floor_fails_a_corpus_that_names_no_package_source() -> None:
    """The floor fails a reader that reaches the suite and misses the package.

    **The suite alone stands above `PYTHON_FLOOR`**, so a corpus that dropped `ja4plus/`
    would pass that floor and read no comment of the library.
    """
    with pytest.raises(AssertionError, match=f"below the floor of {PACKAGE_FLOOR}"):
        python_sources("tests/*.py")


def test_the_python_reader_reads_a_comment() -> None:
    """The reader reads the rejected word where a comment names it."""
    source = "# The decision is reversible.\nvalue = 1\n"
    assert rejected_uses(python_readable_prose(source), RULED_WORD) == ["# The decision"]


def test_the_python_reader_reads_a_docstring() -> None:
    """The reader reads the rejected word where a docstring names it."""
    source = 'def f() -> None:\n    """Return nothing. The decision is reversible."""\n'
    assert rejected_uses(python_readable_prose(source), RULED_WORD) == [
        "Return nothing. The decision"
    ]


def test_the_python_reader_reads_no_string_literal() -> None:
    """The reader reads no string literal, which is data and not prose.

    A case compares such a literal, so a rewrite there moves what the case measures.
    `tests/foxio_deviations.json` carries the same shape in its schema key.
    """
    source = 'BRANCH = "batch/266-register-gate-and-decisions"\nMESSAGE = "one decision"\n'
    assert rejected_uses(python_readable_prose(source), RULED_WORD) == []


def test_the_python_reader_reads_no_identifier() -> None:
    """The reader reads no identifier, because it reads no code."""
    source = "decision_count = 1\n\n\ndef read_decisions() -> int:\n    return decision_count\n"
    assert rejected_uses(python_readable_prose(source), RULED_WORD) == []


def test_the_python_reader_reads_no_code_span_of_a_docstring() -> None:
    """The reader reads no word inside a code span of a docstring."""
    source = 'def f() -> None:\n    """Return nothing. `The decision` names a field."""\n'
    assert rejected_uses(python_readable_prose(source), RULED_WORD) == []


def test_the_python_reader_reads_no_verb_form() -> None:
    """The reader reads no verb form of a comment, so the authority rule stays."""
    source = "# The specification decides intent and schema.\nvalue = 1\n"
    assert rejected_uses(python_readable_prose(source), RULED_WORD) == []


def test_the_python_corpus_holds_prose_of_every_anchor_source() -> None:
    """Each anchor source yields prose, so the reader reads more than an empty text.

    **A reader that extracted nothing would report a clean corpus over every source.**
    """
    for name in PYTHON_ANCHOR_FILES:
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        assert python_readable_prose(text).strip(), f"{name} yields no prose"
