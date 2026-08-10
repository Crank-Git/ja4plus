"""Tests that the prose names the statistics thread by its controlled term.

The `## Terms` table of `docs/specs/spec.md` holds one row for the statistics thread, and
the fourth column of that row names `reporter` as a word a writer does not use. The prose
of the package used `the reporter` throughout, so the controlled vocabulary and the prose
disagreed. #441 records the ruling of the user, and these cases hold the result.

**A corrected sentence goes stale the next time a writer reaches for the rejected word.**
Each case here therefore reads the corpus for the word, rather than restate a sentence.
The rejected word comes out of the `## Terms` row, so a change to the row changes what the
cases forbid.

## What a case here reads, and what stays out of reach

**An identifier is exempt from the writing standard.** `.claude/rules/ste.md` states the
exemption, and #441 rules that `StatisticsReporter`, `report_statistics` and
`TheReporterWritesOneLinePerInterval` keep their names. The reader therefore reads a whole
word alone, so no part of a compound identifier reaches a case. It also drops every code
span and every fenced block first, so a document that quotes an identifier reports nothing.

**A case reads the comments and the docstrings of the Python corpus, and no other string.**
`python_prose` extracts that prose. A string literal that is no docstring stays out, and
the message of an assertion is such a literal. **That limit is deliberate and it is a
hole**, and `tests/test_watch_statistics.py` held one such message before #441.

**A dated record of a past measurement is quoted, not rewritten.** `CHANGELOG.md` records
one past round in every entry, and the `## Changelog` table of `docs/specs/spec.md` holds
one row for each round. The rows of #55, #369 and #371 each name the rejected word, and
#441 leaves all three exactly as they read. `readable_prose` cuts both records.

**The `## Terms` section states the rejected word, so `readable_prose` cuts it too.** The
row is the authority these cases read, and a reader that forbade its own authority would
fail on the specification itself.

## The two words the reader leaves alone

The row rejects `timer` and `ticker` beside `reporter`, and no case forbids either one.
`docs/specs/features/03-concurrency-safety.md` and
`docs/specs/features/06-live-capture.md` each state that eviction runs on packet arrival
and on no timer. Each sentence names a general mechanism and it names no statistics
thread, so each one is true. **The ruling of #441 names `reporter` alone**, and
`test_the_reader_forbids_the_word_the_ruling_names` records the limit as a measurement.

These cases read prose. They produce no fingerprint and they open no capture socket.
"""

import re
import subprocess
from pathlib import Path
from typing import List, Tuple

import pytest

from tests.test_documented_method_count import python_prose, tracked_documents

REPO_ROOT = Path(__file__).resolve().parent.parent

# The term whose row states the controlled word and the rejected words.
CONTROLLED_TERM = "statistics thread"

# The heading of the section that holds the controlled vocabulary.
TERMS_HEADING = "## Terms"

# The rejected word #441 forbids. The row rejects two more words, and the module docstring
# states why no case reads them.
RULED_WORD = "reporter"

# The words the row rejects that no case here forbids.
UNREAD_WORDS = ("timer", "ticker")

# The headings of the sections that record a past state of the project. `readable_prose`
# cuts each one out of `docs/specs/spec.md`, beside the section that states the vocabulary.
RECORD_SECTIONS = ("## Risks & open questions", "## Changelog", TERMS_HEADING)

# The file that records one past round in every entry.
RECORD_FILE = "CHANGELOG.md"

# A fenced block of a Markdown page. The reader drops one before it reads, because a fence
# holds code and the writing standard reproduces code verbatim.
FENCED_BLOCK = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)

# A code span. The reader drops one before it reads, because a span holds an identifier, a
# path or a command, and the writing standard reproduces each one verbatim.
#
# **Warning: the reader drops a code span one line at a time.** A search over a whole page
# pairs a backtick of one line with a backtick far below it, and it then drops every word
# between them. `tests/test_documented_method_count.py` records the same measurement for
# the quotation mark.
CODE_SPAN = re.compile(r"`[^`]*`")

# The git pathspec that names every tracked Markdown page. **In a default git pathspec `*`
# crosses `/`**, so this one term reaches every depth.
MARKDOWN_PATHSPEC = "*.md"

# The directories whose Python files a case reads.
PYTHON_ROOTS = ("ja4plus", "tests")

# The least count of Markdown pages the corpus holds. **An aggregate over an empty set
# passes**, so a reader that named no page would report a green result for every case here.
MARKDOWN_FLOOR = 20

# The least count of Python files the corpus holds, for the same reason.
PYTHON_FLOOR = 120

# One file of each corpus that held the rejected word before #441. A case names each one,
# so a reader that stops reaching a corpus fails here rather than passes over nothing.
ANCHOR_FILES = (
    "docs/api_reference.md",
    "ja4plus/watch.py",
    "tests/test_watch_statistics.py",
)


def rejected_words() -> List[str]:
    """Return the words the `## Terms` row of the controlled term rejects.

    The reader reads the fourth column of the row whose first column is the controlled
    term, and it splits that column on the comma.

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

    A compound identifier holds the word without a word boundary before it, so
    `StatisticsReporter` and `run_reporter` reach no match. The pattern reads the plural
    form too.

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
        loses its fenced blocks and its code spans.
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
    return without_code(text)


def without_code(text: str) -> str:
    """Return the text with every fenced block and every code span removed.

    The reader drops a code span one line at a time, because a search over the whole text
    pairs a backtick of one line with a backtick far below it.

    Args:
        text: The text of one document, or of the prose of one Python file.

    Returns:
        The text with no fenced block and no code span.
    """
    plain = FENCED_BLOCK.sub(" ", text)
    return "\n".join(CODE_SPAN.sub(" ", line) for line in plain.splitlines())


def rejected_uses(text: str, word: str) -> List[str]:
    """Return every place the text names the rejected word, with the words around it.

    Args:
        text: The prose of one document, after `readable_prose` ran.
        word: The rejected word.

    Returns:
        One passage for each match, which names the word and the four words before it.
    """
    found = []
    for line in text.splitlines():
        for match in word_pattern(word).finditer(line):
            start = max(0, match.start() - 40)
            found.append(" ".join(line[start : match.end()].split()))
    return found


def markdown_documents() -> List[str]:
    """Return every tracked Markdown page, relative to the repository root.

    Returns:
        One path for each page, sorted.

    Raises:
        AssertionError: The corpus holds fewer pages than `MARKDOWN_FLOOR`.
    """
    found = [str(path.relative_to(REPO_ROOT)) for path in tracked_documents(MARKDOWN_PATHSPEC)]
    assert len(found) >= MARKDOWN_FLOOR, (
        f"the corpus holds {len(found)} Markdown pages, below the floor of {MARKDOWN_FLOOR}, "
        "and an aggregate over an empty set passes"
    )
    return found


def tracked_python_files(roots: Tuple[str, ...] = PYTHON_ROOTS) -> List[str]:
    """Return every tracked Python file of the named directories.

    **The reader asks git for the files and it walks no directory.** The agent harness
    places a worker worktree at `.claude/worktrees/agent-<id>`, and that worktree is a
    whole checkout, so a walk would read the files of every live worker. #473 records the
    measurement.

    Args:
        roots: The directories to read.

    Returns:
        One path for each file, relative to the repository root, sorted.

    Raises:
        subprocess.CalledProcessError: The read of git failed.
    """
    listed = subprocess.run(
        ["git", "ls-files", "-z", *[f"{root}/*.py" for root in roots]],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split("\0")
    return sorted(name for name in listed if name)


def python_files(roots: Tuple[str, ...] = PYTHON_ROOTS) -> List[str]:
    """Return the Python corpus a case reads.

    Args:
        roots: The directories to read. A case passes another set to measure the floor.

    Returns:
        One path for each tracked Python file of the directories, sorted.

    Raises:
        AssertionError: The corpus holds fewer files than `PYTHON_FLOOR`.
    """
    found = tracked_python_files(roots)
    assert len(found) >= PYTHON_FLOOR, (
        f"the corpus holds {len(found)} Python files, below the floor of {PYTHON_FLOOR}, "
        "and an aggregate over an empty set passes"
    )
    return found


MARKDOWN_DOCUMENTS = markdown_documents()
PYTHON_FILES = python_files()


def test_the_terms_table_rejects_the_ruled_word_for_the_statistics_thread() -> None:
    """The `## Terms` row of the statistics thread rejects the word the cases forbid."""
    assert RULED_WORD in rejected_words(), (
        f"the row of {CONTROLLED_TERM!r} rejects {rejected_words()}, and it names no "
        f"{RULED_WORD!r}, so every case here forbids a word the vocabulary admits"
    )


def test_the_reader_forbids_the_word_the_ruling_names() -> None:
    """The reader forbids one rejected word, and the row rejects two more.

    #441 rules on `reporter` alone. The module docstring names the two sentences that hold
    `timer`, and each one states a general mechanism rather than the statistics thread.
    """
    assert set(UNREAD_WORDS) < set(rejected_words()), (
        f"the row of {CONTROLLED_TERM!r} rejects {rejected_words()}, and the limit this "
        f"module records names {list(UNREAD_WORDS)}"
    )


@pytest.mark.parametrize("name", MARKDOWN_DOCUMENTS)
def test_no_document_names_the_statistics_thread_by_the_rejected_word(name: str) -> None:
    """No Markdown page names the statistics thread by the rejected word."""
    text = (REPO_ROOT / name).read_text(encoding="utf-8")
    offenders = rejected_uses(readable_prose(name, text), RULED_WORD)
    assert offenders == [], (
        f"{name} names {RULED_WORD!r} at {offenders}, and the `## Terms` row of "
        f"{CONTROLLED_TERM!r} rejects that word"
    )


@pytest.mark.parametrize("name", PYTHON_FILES)
def test_no_python_file_names_the_statistics_thread_by_the_rejected_word(name: str) -> None:
    """No comment and no docstring names the statistics thread by the rejected word."""
    prose = python_prose((REPO_ROOT / name).read_text(encoding="utf-8"))
    offenders = rejected_uses(without_code(prose), RULED_WORD)
    assert offenders == [], (
        f"{name} names {RULED_WORD!r} at {offenders}, and the `## Terms` row of "
        f"{CONTROLLED_TERM!r} rejects that word"
    )


def test_the_reader_reads_the_rejected_word_in_a_sentence() -> None:
    """The reader reads the rejected word where a sentence names it."""
    assert rejected_uses("The reporter writes one line.", RULED_WORD) == ["The reporter"]
    assert rejected_uses("Two reporters run.", RULED_WORD) == ["Two reporters"]


# The identifiers #441 rules that the package keeps. A case reads each one, so a reader
# that forbade a compound name would fail here rather than demand a breaking rename.
EXEMPT_IDENTIFIERS = (
    "StatisticsReporter",
    "report_statistics",
    "TheReporterWritesOneLinePerInterval",
    "TheReporterStopsCleanly",
    "run_reporter",
    "test_the_reporter_flushes_each_line",
)


@pytest.mark.parametrize("identifier", EXEMPT_IDENTIFIERS)
def test_the_reader_reads_no_part_of_an_exempt_identifier(identifier: str) -> None:
    """The reader reads no compound identifier that holds the rejected word."""
    sentence = f"The call {identifier} starts the statistics thread."
    assert rejected_uses(sentence, RULED_WORD) == [], f"the reader names {identifier}"


def test_the_reader_reads_no_code_span() -> None:
    """The reader reads no word inside a code span."""
    assert rejected_uses(without_code("Call `reporter.stop()` after the body."), RULED_WORD) == []


def test_the_reader_reads_a_line_below_a_line_that_holds_one_backtick() -> None:
    """The reader reads a sentence below a line that holds one unpaired backtick.

    A search over a whole page pairs a backtick of one line with a backtick far below it,
    and it then drops every word between them.
    """
    passage = "A line with one ` mark.\nAnother plain line.\nThe reporter writes a line.\n"
    assert rejected_uses(without_code(passage), RULED_WORD) == ["The reporter"]


def test_the_reader_reads_no_fenced_block() -> None:
    """The reader reads no word inside a fenced block."""
    passage = "A plain line.\n```\nreporter = build()\n```\nAnother plain line.\n"
    assert rejected_uses(without_code(passage), RULED_WORD) == []


def test_the_python_reader_reads_no_line_of_code() -> None:
    """The Python reader reads the comments and the docstrings, and no line of code.

    The reader keeps the marker of a comment, because it reads the text of the token.
    """
    source = "reporter = build()\n# The reporter writes a line.\n"
    assert rejected_uses(without_code(python_prose(source)), RULED_WORD) == ["# The reporter"]


def test_the_python_reader_reads_no_string_literal_that_is_no_docstring() -> None:
    """The Python reader reads no message of an assertion, which is the limit #441 records."""
    source = 'assert value, "the reporter thread did not end"\n'
    assert python_prose(source) == ""


def test_the_reader_reads_no_record_of_a_past_round() -> None:
    """`readable_prose` cuts the two records and the section that states the vocabulary."""
    assert readable_prose(RECORD_FILE, "Round 125. The reporter started.") == ""
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
    """Each corpus names the file of its own kind that held the rejected word."""
    assert name in MARKDOWN_DOCUMENTS or name in PYTHON_FILES, f"no corpus names {name}"


def test_the_python_corpus_reads_both_directories() -> None:
    """The Python corpus holds a file of the package and a file of the test suite."""
    roots = {name.split("/")[0] for name in PYTHON_FILES}
    assert roots == set(PYTHON_ROOTS), f"the corpus reads the directories {sorted(roots)}"


def test_the_floor_fails_a_corpus_that_names_no_file() -> None:
    """The floor fails a reader that names no Python file.

    **An aggregate over an empty set passes**, so a corpus that read nothing would report
    a green run over no file at all.
    """
    assert tracked_python_files(("docs",)) == [], "the docs directory holds a Python file"
    with pytest.raises(AssertionError, match="below the floor"):
        python_files(("docs",))
