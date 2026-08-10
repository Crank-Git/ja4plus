"""Tests that the sentence-length rule exempts the two records and reaches no other document.

Rule 1 of `.claude/rules/ste.md` holds a description sentence to 25 words. The user ruled
on 2026-08-10, on #457, that the record is exempt. A Changelog row records one round, and
this project quotes a dated record of a past measurement rather than rewriting it. A
rewrite of the 159 rows falsifies nothing they record. It does mean that the text a past
reader saw is not the text a future reader sees.

**The ruling names two records and it names no third.**

1. The entries of `CHANGELOG.md`.
2. The `## Changelog` table of `docs/specs/spec.md`.

**A blanket exemption is the defect these cases exist to catch.** A rule that exempts any
file whose name holds the word `changelog` reaches a file the ruling never read, and
`docs/CHANGELOG.md` is such a file. `exempt_records` therefore reads a blanket item as the
pattern it is, and `evaluate` reports every document the pattern reaches.

## What a case here reads

`evaluate` reads the exemption of `.claude/rules/ste.md` against the tracked document list
of git. It reports three states, and each one refuses the rule.

- The exemption names a record the ruling does not name, or it names one of the two
  nowhere.
- The exemption reaches a document outside the two records.
- The reader names fewer documents than `DOCUMENT_FLOOR`. **An aggregate over an empty set
  passes**, so a reader that names no document fails here rather than reporting a green
  result.

## What a case here does not read

**A case here measures no sentence of a document outside the two records.** The exemption
decides which document the limit covers, and this file holds that decision. A sweep that
measured every sentence of every page is a separate piece of work, and #457 orders none.

`over_limit_sentences` measures the two records, so a case proves that the exemption does
work: both records hold sentences past the limit today. Every other measurement here runs
on a document the case writes.

These cases read prose and the file list of git. They import nothing from `ja4plus` and
they produce no fingerprint.
"""

from fnmatch import fnmatch
from pathlib import Path
import re
import subprocess
from typing import List, NamedTuple, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

RULE_PATH = ".claude/rules/ste.md"
CHANGELOG_PATH = "CHANGELOG.md"
SPECIFICATION_PATH = "docs/specs/spec.md"

# The heading of the section that states the exemption, and the region each record names.
# `exempt_records` reads the list of that section alone, so a list of another section names
# no record.
EXEMPTION_HEADING = "## The one exemption"
CHANGELOG_TABLE = "## Changelog"
ENTRY_REGION = "entries"

# The limit of a description sentence, which rule 1 of the writing standard states.
DESCRIPTION_LIMIT = 25

# The count of documents the reader names at the least. The repository tracks 59 Markdown
# pages today, and the floor stands below that count so a new page needs no edit here.
DOCUMENT_FLOOR = 40

# The least count of sentences past the limit that each record holds. The two counts prove
# that the exemption does work, and a rewrite of the record is the one change that lowers
# them. #457 measured 190 in `CHANGELOG.md` and 786 in the specification table.
CHANGELOG_SENTENCE_FLOOR = 50
SPECIFICATION_SENTENCE_FLOOR = 50

# One document of each depth the corpus reaches, and one of each root it covers. A reader
# whose pathspec stops at a separator drops the deep pages, and a reader of one directory
# drops the root pages. A case reads this set rather than a count a writer transcribed.
ANCHOR_DOCUMENTS = (
    "README.md",
    CHANGELOG_PATH,
    RULE_PATH,
    "docs/usage.md",
    SPECIFICATION_PATH,
    "docs/specs/features/03-concurrency-safety.md",
)

# The git pathspec that names every tracked Markdown page. **In a default git pathspec `*`
# crosses `/`**, so this one term reaches every depth. **Never write `**` here**, because
# git reads `**` as one or more directories and it then drops every root page.
MARKDOWN_PATHSPEC = "*.md"


class Record(NamedTuple):
    """One record the exemption names, as its path and the region of it that is exempt."""

    path: str
    region: str


EXEMPT_RECORDS = (
    Record(CHANGELOG_PATH, ENTRY_REGION),
    Record(SPECIFICATION_PATH, CHANGELOG_TABLE),
)
EXEMPT_PATHS = frozenset(record.path for record in EXEMPT_RECORDS)

# A span of inline code, which carries every path and every heading a record names.
CODE_SPAN = re.compile(r"`([^`]+)`")

# The form of a path a record names. A code span of another shape is a heading or a word.
PATH_SPAN = re.compile(r"^[\w./-]+\.md$")

# The words that widen an item from one record to a class of files. An item that holds one
# of them claims the exemption for every file its code span matches, which is the blanket
# form the ruling of #457 bars.
BLANKET_WORD = re.compile(r"\b(?:any|every|each)\b", re.IGNORECASE)

# A fence opens and closes a code block. The sentence reader measures no line inside one,
# because a code block holds code and the writing standard rewrites no code.
FENCE = re.compile(r"^\s*(?:```|~~~)")

# The break between two sentences. A sentence ends with a period, a question mark or an
# exclamation mark, and white space follows it.
SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+")

# A token that carries a letter or a digit counts as one word. A bare dash and a bare
# bullet mark carry neither, so neither reaches the count.
WORD_TOKEN = re.compile(r"[A-Za-z0-9]")

# An entry of `CHANGELOG.md` opens the line with `- `, and its wrapped lines are indented.
ENTRY_OPENER = re.compile(r"^- ")


def _joined_items(body: str) -> List[str]:
    """Return every list item of one section body, with each wrapped item on one line.

    Args:
        body: The text of the section.

    Returns:
        One string for each item that opens with `- `, in file order.
    """
    items: List[str] = []
    for line in body.splitlines():
        if ENTRY_OPENER.match(line):
            items.append(line[2:].strip())
            continue
        if items and line.startswith(" ") and line.strip():
            items[-1] = f"{items[-1]} {line.strip()}"
    return items


def exemption_body(rule_text: str) -> str:
    """Return the body of the exemption section of the writing standard.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.

    Returns:
        The text below the exemption heading and above the next `## ` heading, or an empty
        string where the rule holds no such section.
    """
    start = rule_text.find(f"\n{EXEMPTION_HEADING}\n")
    if start == -1:
        return ""
    body = rule_text[start + len(EXEMPTION_HEADING) + 2 :]
    end = body.find("\n## ")
    return body if end == -1 else body[:end]


def _record_of(item: str) -> Record:
    """Return the record one list item of the exemption names.

    Args:
        item: The text of one item, on one line.

    Returns:
        The record. A blanket item yields the pattern it claims, and an item that names no
        path yields an empty path.
    """
    spans = CODE_SPAN.findall(item)
    headings = [span for span in spans if span.startswith("#")]
    region = headings[0] if headings else (ENTRY_REGION if ENTRY_REGION in item else "")
    # **Read the path before the blanket word.** An item that names a path names one
    # record, whatever else it says, and the item of `CHANGELOG.md` holds the word `each`
    # in the clause "which each record one round".
    paths = [span for span in spans if PATH_SPAN.match(span)]
    if paths:
        return Record(paths[0], region)
    if BLANKET_WORD.search(item):
        # A blanket item names a word rather than a path, so the record carries the
        # pattern that word matches. `evaluate` then reports every file it reaches.
        pattern = spans[0] if spans else item.strip()
        return Record(f"*{pattern}*", region)
    return Record("", region)


def exempt_records(rule_text: str) -> Tuple[Record, ...]:
    """Return every record the exemption of the writing standard names.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.

    Returns:
        One record for each item of the exemption list, in file order.
    """
    return tuple(_record_of(item) for item in _joined_items(exemption_body(rule_text)))


def reaches(record: Record, path: str) -> bool:
    """Return whether one record of the exemption covers one document.

    Args:
        record: The record the exemption names.
        path: The path of the document, relative to the repository root.

    Returns:
        True where the path matches the record. A literal path matches itself alone, and a
        blanket pattern matches every path of its class.
    """
    return fnmatch(path.lower(), record.path.lower())


def evaluate(rule_text: str, documents: Sequence[str]) -> Tuple[str, ...]:
    """Return every reason the exemption of the writing standard refuses the ruling of #457.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.
        documents: The path of every document, relative to the repository root.

    Returns:
        One reason for each state the reader finds, and an empty tuple where the exemption
        names the two records and reaches no other document.
    """
    failures: List[str] = []
    records = exempt_records(rule_text)
    if len(documents) < DOCUMENT_FLOOR:
        failures.append(
            f"the reader names {len(documents)} documents, and the floor is {DOCUMENT_FLOOR}"
        )
    extra = [record for record in records if record not in EXEMPT_RECORDS]
    if extra:
        failures.append(f"the ruling of #457 names none of these records: {extra}")
    absent = [record for record in EXEMPT_RECORDS if record not in records]
    if absent:
        failures.append(f"the exemption names none of these records: {absent}")
    reached = sorted(
        path
        for path in documents
        if path not in EXEMPT_PATHS and any(reaches(record, path) for record in records)
    )
    if reached:
        failures.append(f"the exemption reaches these documents outside the two records: {reached}")
    return tuple(failures)


def tracked_documents(pathspec: str = MARKDOWN_PATHSPEC) -> List[str]:
    """Return the path of every tracked Markdown page, relative to the repository root.

    The reader asks git for the tracked pages and it walks no directory. **The harness
    places a worker worktree at `.claude/worktrees/agent-<id>`, and that worktree is a
    whole checkout**, so a walk of `.claude/` reads the pages of every live worker. #473
    records that measurement.

    Args:
        pathspec: The git pathspec that names the pages.

    Returns:
        One path for each tracked page, sorted.

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


def read_document(path: str) -> str:
    """Return the text of one document of this repository.

    Args:
        path: The path of the document, relative to the repository root.

    Returns:
        The whole text of the document.
    """
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def _changelog_regions(text: str) -> Tuple[str, str]:
    """Return the entries of `CHANGELOG.md` and the prose outside them.

    An entry opens the line with `- ` and its wrapped lines are indented, so an indented
    line below an entry belongs to that entry.

    Args:
        text: The whole text of the file.

    Returns:
        The text of every entry, and the text of every other line.
    """
    entries: List[str] = []
    other: List[str] = []
    inside = False
    for line in text.splitlines():
        if ENTRY_OPENER.match(line):
            inside = True
        elif line.strip() and not line.startswith(" "):
            inside = False
        (entries if inside else other).append(line)
    return "\n".join(entries), "\n".join(other)


def _specification_regions(text: str) -> Tuple[str, str]:
    """Return the `## Changelog` table of `docs/specs/spec.md` and the prose outside it.

    Args:
        text: The whole text of the page.

    Returns:
        The text of the Changelog section, and the text of the rest of the page.
    """
    start = text.find(f"\n{CHANGELOG_TABLE}\n")
    if start == -1:
        return "", text
    tail = text[start + len(CHANGELOG_TABLE) + 2 :]
    end = tail.find("\n## ")
    if end == -1:
        return tail, text[:start]
    return tail[:end], text[:start] + tail[end:]


def regions(path: str, text: str) -> Tuple[str, str]:
    """Return the exempt region of one document and the region the limit covers.

    Args:
        path: The path of the document, relative to the repository root.
        text: The whole text of the document.

    Returns:
        The text the exemption covers, and the text the sentence-length rule covers. A
        document outside the two records yields an empty exempt region.
    """
    if path == CHANGELOG_PATH:
        return _changelog_regions(text)
    if path == SPECIFICATION_PATH:
        return _specification_regions(text)
    return "", text


def sentences(text: str) -> List[str]:
    """Return every sentence of one text, with the code blocks removed.

    The reader drops the emphasis marks first. This project opens a paragraph with a bold
    sentence, and the mark stands between the period and the space, so a reader that keeps
    the mark joins that sentence to the one below it and reports one long sentence.

    Args:
        text: The text to read.

    Returns:
        One string for each sentence, in file order.
    """
    text = text.replace("**", "")
    prose: List[str] = []
    fenced = False
    for line in text.splitlines():
        if FENCE.match(line):
            fenced = not fenced
            continue
        prose.append("" if fenced else line)
    found: List[str] = []
    for block in re.split(r"\n\s*\n", "\n".join(prose)):
        joined = " ".join(block.split())
        if joined:
            found.extend(part for part in SENTENCE_BREAK.split(joined) if part)
    return found


def word_count(sentence: str) -> int:
    """Return the count of words of one sentence.

    A span of inline code counts as one word, and so does a link, because the writing
    standard rewrites neither.

    Args:
        sentence: The text of one sentence.

    Returns:
        The count of tokens that carry a letter or a digit.
    """
    plain = CODE_SPAN.sub("code", sentence)
    plain = re.sub(r"https?://\S+", "link", plain)
    return len([token for token in plain.split() if WORD_TOKEN.search(token)])


def over_limit_sentences(text: str, limit: int = DESCRIPTION_LIMIT) -> List[str]:
    """Return every sentence of one text that passes the sentence-length limit.

    Args:
        text: The text to measure.
        limit: The word count a sentence may hold.

    Returns:
        One string for each sentence past the limit, in file order.
    """
    return [sentence for sentence in sentences(text) if word_count(sentence) > limit]


def limit_failures(path: str, text: str) -> List[str]:
    """Return every sentence of one document that the sentence-length rule refuses.

    Args:
        path: The path of the document, relative to the repository root.
        text: The whole text of the document.

    Returns:
        One string for each sentence past the limit outside the exempt region.
    """
    return over_limit_sentences(regions(path, text)[1])


LONG_SENTENCE = (
    "The reader of this document states one fact and it then states another fact and it "
    "then states a third fact, so the whole sentence carries far more than the limit of "
    "twenty-five words."
)

TWO_RECORD_RULE = (
    "# Writing standard\n\n"
    f"{EXEMPTION_HEADING}\n\n"
    f"- The entries of `{CHANGELOG_PATH}`, which each record one round.\n"
    f"- The `{CHANGELOG_TABLE}` table of `{SPECIFICATION_PATH}`, which holds one row for\n"
    "  each round.\n\n"
    "## The rules\n\n"
    "1. A description sentence is 25 words or fewer.\n"
)

THIRD_RECORD_ITEM = "- The entries of `docs/CHANGELOG.md`, which record the rounds of an epic.\n"

BLANKET_RULE = (
    "# Writing standard\n\n"
    f"{EXEMPTION_HEADING}\n\n"
    "- Any file whose name holds the word `changelog`.\n\n"
    "## The rules\n\n"
)


def test_the_writing_standard_states_the_exemption() -> None:
    """`.claude/rules/ste.md` holds a section that states the exemption."""
    assert exemption_body(read_document(RULE_PATH)).strip() != "", (
        f"{RULE_PATH} holds no {EXEMPTION_HEADING} section"
    )


def test_the_exemption_names_the_two_records_and_no_other() -> None:
    """The exemption of the writing standard names the two records of the ruling."""
    assert exempt_records(read_document(RULE_PATH)) == EXEMPT_RECORDS


def test_the_exemption_names_the_changelog_table_of_the_specification() -> None:
    """The exemption covers the `## Changelog` table of the specification and no other section."""
    records = exempt_records(read_document(RULE_PATH))
    named = [record for record in records if record.path == SPECIFICATION_PATH]
    assert named == [Record(SPECIFICATION_PATH, CHANGELOG_TABLE)]


def test_the_exemption_names_the_entries_of_the_changelog() -> None:
    """The exemption covers the entries of `CHANGELOG.md`."""
    records = exempt_records(read_document(RULE_PATH))
    named = [record for record in records if record.path == CHANGELOG_PATH]
    assert named == [Record(CHANGELOG_PATH, ENTRY_REGION)]


def test_the_reader_reads_no_list_item_of_another_section() -> None:
    """The reader names no record from a list that another section of the rule holds."""
    rule = TWO_RECORD_RULE + "- The entries of `docs/other.md`.\n"
    assert exempt_records(rule) == EXEMPT_RECORDS


def test_the_reader_reports_a_third_record_the_exemption_names() -> None:
    """The reader returns three records where the exemption names three."""
    records = exempt_records(TWO_RECORD_RULE.replace("## The rules", THIRD_RECORD_ITEM))
    assert [record.path for record in records] == [
        CHANGELOG_PATH,
        SPECIFICATION_PATH,
        "docs/CHANGELOG.md",
    ]


def test_the_reader_reads_a_blanket_exemption_as_the_pattern_it_claims() -> None:
    """The reader returns a pattern where an item exempts any file of a class."""
    assert [record.path for record in exempt_records(BLANKET_RULE)] == ["*changelog*"]


def test_this_repository_exempts_the_two_records_alone() -> None:
    """The exemption of this repository names the two records and reaches no other document."""
    failures = evaluate(read_document(RULE_PATH), tracked_documents())
    assert failures == (), f"the exemption fails this reading: {failures}"


def test_a_third_record_that_claims_the_exemption_fails() -> None:
    """A rule that exempts a third record fails, and the failure names that record."""
    rule = TWO_RECORD_RULE.replace("## The rules", THIRD_RECORD_ITEM)
    documents = sorted(tracked_documents() + ["docs/CHANGELOG.md"])
    failures = evaluate(rule, documents)
    assert failures != ()
    assert any("docs/CHANGELOG.md" in failure for failure in failures)


def test_a_blanket_exemption_that_reads_a_file_name_fails() -> None:
    """A rule that exempts any file whose name holds `changelog` fails."""
    documents = sorted(tracked_documents() + ["docs/CHANGELOG.md"])
    failures = evaluate(BLANKET_RULE, documents)
    assert failures != ()
    assert any("docs/CHANGELOG.md" in failure for failure in failures)


def test_an_exemption_that_names_one_record_fails() -> None:
    """A rule that exempts `CHANGELOG.md` alone fails, and the failure names the second record."""
    rule = TWO_RECORD_RULE.replace(
        f"- The `{CHANGELOG_TABLE}` table of `{SPECIFICATION_PATH}`, which holds one row for\n"
        "  each round.\n",
        "",
    )
    failures = evaluate(rule, tracked_documents())
    assert any(SPECIFICATION_PATH in failure for failure in failures)


def test_a_reader_that_names_no_document_fails() -> None:
    """A reading over an empty document set fails rather than passing."""
    failures = evaluate(read_document(RULE_PATH), [])
    assert any(str(DOCUMENT_FLOOR) in failure for failure in failures)


def test_the_document_set_names_a_page_of_each_depth_and_of_each_root() -> None:
    """The document set holds every anchor page, at each depth and under each root."""
    documents = set(tracked_documents())
    absent = sorted(name for name in ANCHOR_DOCUMENTS if name not in documents)
    assert absent == [], f"the reader names none of these pages: {absent}"


def test_the_entries_of_the_changelog_hold_sentences_past_the_limit() -> None:
    """The entries of `CHANGELOG.md` hold sentences past the limit, so the exemption does work."""
    entries = regions(CHANGELOG_PATH, read_document(CHANGELOG_PATH))[0]
    assert len(over_limit_sentences(entries)) >= CHANGELOG_SENTENCE_FLOOR


def test_the_changelog_table_of_the_specification_holds_sentences_past_the_limit() -> None:
    """The `## Changelog` table holds sentences past the limit, so the exemption does work."""
    table = regions(SPECIFICATION_PATH, read_document(SPECIFICATION_PATH))[0]
    assert len(over_limit_sentences(table)) >= SPECIFICATION_SENTENCE_FLOOR


def test_the_writing_standard_itself_holds_the_limit() -> None:
    """`.claude/rules/ste.md` holds no sentence past the limit, because no exemption covers it."""
    failures = limit_failures(RULE_PATH, read_document(RULE_PATH))
    assert failures == [], f"these sentences of {RULE_PATH} pass the limit: {failures}"


def test_a_document_outside_the_two_records_holds_the_limit() -> None:
    """A page outside the two records reports its sentence of more than 25 words."""
    assert limit_failures("docs/usage.md", LONG_SENTENCE) == [LONG_SENTENCE]


def test_a_file_whose_name_holds_changelog_holds_the_limit() -> None:
    """A page named `docs/CHANGELOG.md` reports its sentence of more than 25 words."""
    assert limit_failures("docs/CHANGELOG.md", LONG_SENTENCE) == [LONG_SENTENCE]


def test_the_specification_holds_the_limit_outside_the_changelog_table() -> None:
    """A sentence of the specification outside the `## Changelog` table reports its length."""
    page = f"## Goals\n\n{LONG_SENTENCE}\n\n{CHANGELOG_TABLE}\n\n| 1 | 2026-08-10 | A round. |\n"
    assert limit_failures(SPECIFICATION_PATH, page) == [LONG_SENTENCE]


def test_the_changelog_table_of_the_specification_reports_no_sentence() -> None:
    """A row of the `## Changelog` table reports no sentence, whatever its length."""
    page = (
        f"## Goals\n\nA short line.\n\n{CHANGELOG_TABLE}\n\n| 1 | 2026-08-10 | {LONG_SENTENCE} |\n"
    )
    assert limit_failures(SPECIFICATION_PATH, page) == []


def test_the_changelog_holds_the_limit_outside_an_entry() -> None:
    """A sentence of `CHANGELOG.md` outside an entry reports its length."""
    text = f"# Changelog\n\n{LONG_SENTENCE}\n\n- **A change** (#1). {LONG_SENTENCE}\n"
    assert limit_failures(CHANGELOG_PATH, text) == [LONG_SENTENCE]


def test_an_entry_of_the_changelog_reports_no_sentence() -> None:
    """An entry of `CHANGELOG.md` reports no sentence, whatever its length."""
    text = f"# Changelog\n\n- **A change** (#1). {LONG_SENTENCE}\n  It holds one more line.\n"
    assert limit_failures(CHANGELOG_PATH, text) == []


def test_the_reader_parts_a_bold_sentence_from_the_sentence_below_it() -> None:
    """A bold sentence and the sentence below it read as two sentences."""
    text = f"**A short warning stands here.** {LONG_SENTENCE}\n"
    assert over_limit_sentences(text) == [LONG_SENTENCE]


def test_the_reader_measures_no_line_of_a_code_block() -> None:
    """The sentence reader measures no line inside a fenced code block."""
    text = f"```\n{LONG_SENTENCE}\n```\n"
    assert over_limit_sentences(text) == []


def test_the_reader_reads_a_sentence_of_the_limit_as_no_failure() -> None:
    """A sentence of exactly 25 words passes, and a sentence of 26 words fails."""
    at_limit = " ".join(["word"] * (DESCRIPTION_LIMIT - 1)) + " end."
    past_limit = " ".join(["word"] * DESCRIPTION_LIMIT) + " end."
    assert over_limit_sentences(at_limit) == []
    assert over_limit_sentences(past_limit) == [past_limit]
