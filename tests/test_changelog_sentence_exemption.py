"""Tests that three rules exempt the two records and reach no other document.

Rule 1 of `.claude/rules/ste.md` holds a description sentence to 25 words. Rule 3 holds a
paragraph to six sentences. Rule 17 holds a word to the US spelling, and the maintainer
exempted the record from it on 2026-08-16, on #663. The user ruled on 2026-08-10, on #457
for rule 1 and on #502 for rule 3, that the record is exempt from both. A Changelog row
records one round, which is one topic, and the sentence count of that row follows from how
much the round measured. This project quotes a dated record of a past measurement rather
than rewriting it. A
rewrite of the rows falsifies nothing they record, and the text a past reader saw is then
not the text a future reader sees.

**The ruling names two records and it names no third.**

1. The entries of `CHANGELOG.md`.
2. The `## Changelog` table of `docs/specs/spec.md`.

**The exemption names three rules and it names no fourth.** The exemption states which
rules it covers and which rules reach both records, and `evaluate` holds the two statements
against the numbered rule list of the standard. A rule the standard states and the
exemption places nowhere fails a case here, so an eighteenth rule needs a reading before it
ships. #663 gave rule 17 that reading on 2026-08-16.

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
decides which document the limit covers, and this file holds that ruling. A sweep that
measured every sentence of every page is a separate piece of work, and #457 orders none.

`over_limit_sentences` and `over_limit_units` measure the two records, so a case proves
that each half of the exemption does work: both records hold sentences past the word limit
and paragraphs past the sentence limit today. Every other measurement here runs on a
document the case writes.

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
EXEMPTION_HEADING = "## The exemption"
RULES_HEADING = "## The rules"
CHANGELOG_TABLE = "## Changelog"
ENTRY_REGION = "entries"

# The limit of a description sentence, which rule 1 of the writing standard states.
DESCRIPTION_LIMIT = 25

# The limit of a paragraph, which rule 3 of the writing standard states.
PARAGRAPH_LIMIT = 6

# The number of each rule the exemption covers. Rule 1 holds the word count of a sentence
# and #457 exempted it. Rule 3 holds the sentence count of a paragraph and #502 exempted it.
# Rule 17 holds the spelling of a word and #663 exempted it.
SENTENCE_RULE = 1
PARAGRAPH_RULE = 3
SPELLING_RULE = 17
EXEMPT_RULES = (SENTENCE_RULE, PARAGRAPH_RULE, SPELLING_RULE)

# The count of numbered rules the standard states at the least. The standard states 17
# today. **An aggregate over an empty set passes**, so a reader that finds no numbered rule
# fails here rather than reporting that the exemption places every rule.
RULE_FLOOR = 17

# The count of documents the reader names at the least. The repository tracks 59 Markdown
# pages today, and the floor stands below that count so a new page needs no edit here.
DOCUMENT_FLOOR = 40

# The least count of sentences past the limit that each record holds. The two counts prove
# that the exemption does work, and a rewrite of the record is the one change that lowers
# them. #457 measured 191 in `CHANGELOG.md` and 787 in the specification table.
CHANGELOG_SENTENCE_FLOOR = 50
SPECIFICATION_SENTENCE_FLOOR = 50

# The least count of paragraphs past the sentence limit that each record holds. A read of
# 2026-08-10 reports 112 entries of `CHANGELOG.md` past six sentences, of 135, and 177 rows
# of the specification table past six sentences, of 189.
CHANGELOG_PARAGRAPH_FLOOR = 50
SPECIFICATION_PARAGRAPH_FLOOR = 50

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

# The opener of one item of a list, either a bullet or a number. **A list is not a
# paragraph**, so the paragraph reader parts one item from the next. The rule list of the
# standard holds 16 items under three headings, and a reader that joined them would report
# one paragraph of 16 sentences against a file that holds rule 3.
LIST_OPENER = re.compile(r"^\s*(?:[-*+]|\d+\.)\s")

# One numbered rule of the `## The rules` section, at the start of the line.
NUMBERED_RULE = re.compile(r"^(\d+)\.\s")

# One row of a Markdown table. The `## Changelog` table of the specification holds one row
# for each round, and the separator row carries no word.
TABLE_ROW = re.compile(r"^\s*\|")
TABLE_SEPARATOR = re.compile(r"^\s*\|[\s|:-]*$")

# A whole number, which names one rule where it stands in a sentence of the exemption.
RULE_NUMBER = re.compile(r"\b(\d+)\b")

# The two sentences of the exemption that place the rules. **A rewording that defeats a
# marker fails these cases**, because the reader then names no rule and the placement holds
# no rule the standard states.
COVERS_MARKER = "the exemption covers"
REACHES_MARKER = "reaches both records"


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


def section_body(text: str, heading: str) -> str:
    """Return the body of one section of a Markdown page.

    Args:
        text: The whole text of the page.
        heading: The heading line of the section, with its marks.

    Returns:
        The text below the heading and above the next `## ` heading, or an empty string
        where the page holds no such section.
    """
    start = text.find(f"\n{heading}\n")
    if start == -1:
        return ""
    body = text[start + len(heading) + 2 :]
    end = body.find("\n## ")
    return body if end == -1 else body[:end]


def exemption_body(rule_text: str) -> str:
    """Return the body of the exemption section of the writing standard.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.

    Returns:
        The text below the exemption heading and above the next `## ` heading, or an empty
        string where the rule holds no such section.
    """
    return section_body(rule_text, EXEMPTION_HEADING)


def standard_rules(rule_text: str) -> Tuple[int, ...]:
    """Return the number of every numbered rule the writing standard states.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.

    Returns:
        One number for each rule of the `## The rules` section, sorted and without a repeat.
    """
    found = {
        int(match.group(1))
        for line in section_body(rule_text, RULES_HEADING).splitlines()
        for match in [NUMBERED_RULE.match(line)]
        if match
    }
    return tuple(sorted(found))


def _placed_rules(rule_text: str, marker: str) -> Tuple[int, ...]:
    """Return the rule numbers of every sentence of the exemption that holds one marker.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.
        marker: The words that open the placement, in lower case.

    Returns:
        One number for each rule the marked sentences name, sorted and without a repeat.
    """
    found = {
        int(number)
        for sentence in sentences(exemption_body(rule_text))
        if marker in sentence.lower()
        for number in RULE_NUMBER.findall(sentence)
    }
    return tuple(sorted(found))


def exempt_rules(rule_text: str) -> Tuple[int, ...]:
    """Return the number of every rule the exemption covers.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.

    Returns:
        One number for each rule the exemption places under itself, sorted.
    """
    return _placed_rules(rule_text, COVERS_MARKER)


def rules_that_reach_the_records(rule_text: str) -> Tuple[int, ...]:
    """Return the number of every rule the exemption states that both records hold.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.

    Returns:
        One number for each rule the exemption places outside itself, sorted.
    """
    return _placed_rules(rule_text, REACHES_MARKER)


def _records_of(item: str) -> List[Record]:
    """Return every record one list item of the exemption names.

    **One item names as many records as it names paths.** A self-review of #457 drove the
    first form of this reader with the item
    "The entries of `CHANGELOG.md` and `docs/CHANGELOG.md`", which widens the exemption to
    a third document. That form returned the first path alone, so `evaluate` reported
    nothing and the widening passed.

    Args:
        item: The text of one item, on one line.

    Returns:
        One record for each path the item names. A blanket item yields one record that
        carries the pattern it claims, and an item that names neither yields one record
        with an empty path.
    """
    spans = CODE_SPAN.findall(item)
    headings = [span for span in spans if span.startswith("#")]
    region = headings[0] if headings else (ENTRY_REGION if ENTRY_REGION in item else "")
    # **Read the path before the blanket word.** An item that names a path names a record
    # of its own, whatever else it says, and the item of `CHANGELOG.md` holds the word
    # `each` in the clause "which each record one round".
    paths = [span for span in spans if PATH_SPAN.match(span)]
    if paths:
        return [Record(path, region) for path in paths]
    if BLANKET_WORD.search(item):
        # A blanket item names a word rather than a path, so the record carries the
        # pattern that word matches. `evaluate` then reports every file it reaches.
        pattern = spans[0] if spans else item.strip()
        return [Record(f"*{pattern}*", region)]
    return [Record("", region)]


def exempt_records(rule_text: str) -> Tuple[Record, ...]:
    """Return every record the exemption of the writing standard names.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.

    Returns:
        One record for each path the exemption list names, in file order.
    """
    records: List[Record] = []
    for item in _joined_items(exemption_body(rule_text)):
        records.extend(_records_of(item))
    return tuple(records)


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


def rule_failures(rule_text: str) -> List[str]:
    """Return every reason the rule placement of the exemption refuses the ruling of #502.

    The exemption places each numbered rule of the standard on one of two sides. It covers
    rule 1 and rule 3, and every other rule reaches both records. **A rule the exemption
    places nowhere fails here**, so a rule this project adds later needs a reading before it
    ships.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.

    Returns:
        One reason for each state the reader finds, and an empty list where the exemption
        places every rule of the standard on the side the ruling gives it.
    """
    failures: List[str] = []
    standard = standard_rules(rule_text)
    covered = exempt_rules(rule_text)
    reaching = rules_that_reach_the_records(rule_text)
    if len(standard) < RULE_FLOOR:
        failures.append(
            f"the reader names {len(standard)} numbered rules, and the floor is {RULE_FLOOR}"
        )
    if covered != EXEMPT_RULES:
        failures.append(
            f"the ruling exempts the rules {list(EXEMPT_RULES)}, "
            f"and the exemption covers {list(covered)}"
        )
    both = sorted(set(covered) & set(reaching))
    if both:
        failures.append(f"the exemption both covers these rules and states that they reach: {both}")
    unplaced = sorted(number for number in standard if number not in covered + reaching)
    if unplaced:
        failures.append(f"the exemption places these rules of the standard nowhere: {unplaced}")
    unknown = sorted(number for number in covered + reaching if number not in standard)
    if unknown:
        failures.append(
            f"the exemption places these rules, and the standard states none: {unknown}"
        )
    return failures


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
    failures.extend(rule_failures(rule_text))
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


def sentence_count(unit: str) -> int:
    """Return the count of sentences of one paragraph.

    Args:
        unit: The text of one paragraph, on one line or on several.

    Returns:
        The count of sentences the sentence reader finds.
    """
    return len(sentences(unit))


def paragraphs(text: str) -> List[str]:
    """Return every paragraph of one text, with the code blocks removed.

    A blank line parts one paragraph from the next, and each item of a list is a paragraph
    of its own. **A list is not a paragraph**, so a reader that joined the 16 rules of the
    standard would report one paragraph of 16 sentences.

    Args:
        text: The text to read.

    Returns:
        One string for each paragraph, in file order, with each paragraph on one line.
    """
    prose: List[str] = []
    fenced = False
    for line in text.splitlines():
        if FENCE.match(line):
            fenced = not fenced
            continue
        prose.append("" if fenced else line)
    found: List[str] = []
    for block in re.split(r"\n\s*\n", "\n".join(prose)):
        units: List[str] = []
        for line in block.splitlines():
            opener = LIST_OPENER.match(line)
            if opener:
                units.append(line[opener.end() :].strip())
            elif not units:
                units.append(line.strip())
            else:
                units[-1] = f"{units[-1]} {line.strip()}".strip()
        found.extend(" ".join(unit.split()) for unit in units if unit.strip())
    return found


def over_limit_units(units: Sequence[str], limit: int = PARAGRAPH_LIMIT) -> List[str]:
    """Return every paragraph of one sequence that passes the sentence limit.

    Args:
        units: One string for each paragraph.
        limit: The count of sentences a paragraph may hold.

    Returns:
        One string for each paragraph past the limit, in the order it was given.
    """
    return [unit for unit in units if sentence_count(unit) > limit]


def over_limit_paragraphs(text: str, limit: int = PARAGRAPH_LIMIT) -> List[str]:
    """Return every paragraph of one text that passes the sentence limit.

    Args:
        text: The text to measure.
        limit: The count of sentences a paragraph may hold.

    Returns:
        One string for each paragraph past the limit, in file order.
    """
    return over_limit_units(paragraphs(text), limit)


def record_units(path: str, text: str) -> List[str]:
    """Return every paragraph of the exempt region of one record.

    One entry of `CHANGELOG.md` is one paragraph, and one row of the `## Changelog` table
    of the specification is one paragraph. Each records one round, which is one topic.

    Args:
        path: The path of the document, relative to the repository root.
        text: The text of the exempt region of that document.

    Returns:
        One string for each paragraph of the region, in file order.
    """
    if path == CHANGELOG_PATH:
        return _joined_items(text)
    if path == SPECIFICATION_PATH:
        return [
            line.strip()
            for line in text.splitlines()
            if TABLE_ROW.match(line) and not TABLE_SEPARATOR.match(line)
        ]
    return paragraphs(text)


def uncovered_failures(rule_text: str, path: str, text: str) -> List[str]:
    """Return every measurement of the exempt region that a rule outside the exemption makes.

    **The exemption decides which rule the record answers to.** Where the exemption drops
    rule 1, the reader measures the word count of every sentence of the record. Where it
    drops rule 3, the reader measures the sentence count of every row and every entry.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.
        path: The path of the record, relative to the repository root.
        text: The whole text of the record.

    Returns:
        One string for each paragraph or sentence of the record that an uncovered rule
        refuses, and an empty list where the exemption covers both rules.
    """
    covered = exempt_rules(rule_text)
    region = regions(path, text)[0]
    failures: List[str] = []
    if SENTENCE_RULE not in covered:
        failures.extend(
            f"rule {SENTENCE_RULE} reaches {path}: {sentence}"
            for sentence in over_limit_sentences(region)
        )
    if PARAGRAPH_RULE not in covered:
        failures.extend(
            f"rule {PARAGRAPH_RULE} reaches {path}: {unit[:80]}"
            for unit in over_limit_units(record_units(path, region))
        )
    return failures


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

# The 17 numbered rules a fixture states, so that a fixture holds the rule floor and the
# placement reads against a whole standard.
FIXTURE_RULES = "".join(
    f"{number}. A rule of the standard.\n" for number in range(1, RULE_FLOOR + 1)
)

# The two sentences that place every rule. The shipped rule states the same two.
COVERED_SENTENCE = "**The exemption covers rule 1, rule 3 and rule 17.**\n"
REACHING_SENTENCE = (
    "**Every other rule reaches both records: rules 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,\n"
    "14, 15 and 16.**\n"
)

TWO_RECORD_RULE = (
    "# Writing standard\n\n"
    f"{EXEMPTION_HEADING}\n\n"
    f"- The entries of `{CHANGELOG_PATH}`, which each record one round.\n"
    f"- The `{CHANGELOG_TABLE}` table of `{SPECIFICATION_PATH}`, which holds one row for\n"
    "  each round.\n\n"
    f"{COVERED_SENTENCE}\n"
    f"{REACHING_SENTENCE}\n"
    f"{RULES_HEADING}\n\n"
    f"{FIXTURE_RULES}"
)

THIRD_RECORD_ITEM = "- The entries of `docs/CHANGELOG.md`, which record the rounds of an epic.\n"

THIRD_RECORD_RULE = TWO_RECORD_RULE.replace(
    COVERED_SENTENCE, f"{THIRD_RECORD_ITEM}\n{COVERED_SENTENCE}"
)

BLANKET_RULE = (
    "# Writing standard\n\n"
    f"{EXEMPTION_HEADING}\n\n"
    "- Any file whose name holds the word `changelog`.\n\n"
    f"{COVERED_SENTENCE}\n"
    f"{REACHING_SENTENCE}\n"
    f"{RULES_HEADING}\n\n"
    f"{FIXTURE_RULES}"
)

# A paragraph of seven sentences, which passes the limit rule 3 states.
LONG_PARAGRAPH = " ".join(f"The reader states fact {number}." for number in range(1, 8))


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
    records = exempt_records(THIRD_RECORD_RULE)
    assert [record.path for record in records] == [
        CHANGELOG_PATH,
        SPECIFICATION_PATH,
        "docs/CHANGELOG.md",
    ]


def test_the_reader_reports_both_paths_of_one_item() -> None:
    """An item that names two paths yields two records."""
    rule = TWO_RECORD_RULE.replace(
        f"- The entries of `{CHANGELOG_PATH}`, which each record one round.",
        f"- The entries of `{CHANGELOG_PATH}` and `docs/CHANGELOG.md`, which each record one round.",
    )
    assert [record.path for record in exempt_records(rule)] == [
        CHANGELOG_PATH,
        "docs/CHANGELOG.md",
        SPECIFICATION_PATH,
    ]


def test_a_second_path_of_one_item_that_claims_the_exemption_fails() -> None:
    """A record that shares an item with a named record fails, and the failure names it."""
    rule = TWO_RECORD_RULE.replace(
        f"- The entries of `{CHANGELOG_PATH}`, which each record one round.",
        f"- The entries of `{CHANGELOG_PATH}` and `docs/CHANGELOG.md`, which each record one round.",
    )
    documents = sorted(tracked_documents() + ["docs/CHANGELOG.md"])
    failures = evaluate(rule, documents)
    assert any("docs/CHANGELOG.md" in failure for failure in failures)


def test_the_reader_reads_a_blanket_exemption_as_the_pattern_it_claims() -> None:
    """The reader returns a pattern where an item exempts any file of a class."""
    assert [record.path for record in exempt_records(BLANKET_RULE)] == ["*changelog*"]


def test_this_repository_exempts_the_two_records_alone() -> None:
    """The exemption of this repository names the two records and reaches no other document."""
    failures = evaluate(read_document(RULE_PATH), tracked_documents())
    assert failures == (), f"the exemption fails this reading: {failures}"


def test_a_third_record_that_claims_the_exemption_fails() -> None:
    """A rule that exempts a third record fails, and the failure names that record."""
    documents = sorted(tracked_documents() + ["docs/CHANGELOG.md"])
    failures = evaluate(THIRD_RECORD_RULE, documents)
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


SHIPPED_COVERS = "The exemption covers rule 1, rule 3 and rule 17."
SHIPPED_REACHES_OPENER = "rules 2, 4,"


def mutated_rule(original: str, replacement: str) -> str:
    """Return the shipped writing standard with one span replaced.

    **A mutation that matches nothing proves nothing**, so this reader refuses one. A
    rewording of the shipped sentence therefore fails the case that calls it, and it does
    not leave the case reading an unmutated file.

    Args:
        original: The span the shipped rule holds today.
        replacement: The span the mutation writes in its place.

    Returns:
        The whole text of the rule, with the replacement applied.
    """
    rule = read_document(RULE_PATH)
    mutated = rule.replace(original, replacement)
    assert mutated != rule, f"{RULE_PATH} holds no span reading: {original}"
    return mutated


def test_the_exemption_covers_rule_one_and_rule_three() -> None:
    """The exemption of the writing standard covers rule 1 and rule 3, and no other rule."""
    assert exempt_rules(read_document(RULE_PATH)) == EXEMPT_RULES


def test_the_standard_states_sixteen_numbered_rules() -> None:
    """The `## The rules` section states 16 numbered rules, from 1 to 16."""
    assert standard_rules(read_document(RULE_PATH)) == tuple(range(1, RULE_FLOOR + 1))


def test_the_exemption_places_every_rule_of_the_standard() -> None:
    """The exemption places each numbered rule of the standard on one side and on one only."""
    failures = rule_failures(read_document(RULE_PATH))
    assert failures == [], f"the rule placement fails this reading: {failures}"


def test_every_rule_the_exemption_leaves_out_reaches_both_records() -> None:
    """The exemption states that the 14 rules outside it reach both records."""
    reaching = rules_that_reach_the_records(read_document(RULE_PATH))
    assert reaching == tuple(
        number for number in range(1, RULE_FLOOR + 1) if number not in EXEMPT_RULES
    )


def test_a_reader_that_names_no_rule_fails() -> None:
    """A reading over a standard that states no numbered rule fails rather than passing."""
    failures = rule_failures(f"# Writing standard\n\n{EXEMPTION_HEADING}\n\nNo rule stands here.\n")
    assert any(str(RULE_FLOOR) in failure for failure in failures)


def test_an_exemption_that_covers_a_rule_the_ruling_names_nowhere_fails() -> None:
    """A rule that exempts rule 2 as well fails, and the failure names the covered set."""
    rule = mutated_rule(SHIPPED_COVERS, "The exemption covers rule 1, rule 2, rule 3 and rule 17.")
    failures = rule_failures(rule)
    assert any("[1, 2, 3, 17]" in failure for failure in failures)


def test_an_exemption_that_places_a_rule_nowhere_fails() -> None:
    """A rule that names rule 2 on neither side fails, and the failure names rule 2."""
    rule = mutated_rule(SHIPPED_REACHES_OPENER, "rules 4,")
    failures = rule_failures(rule)
    assert any("places these rules of the standard nowhere: [2]" in failure for failure in failures)


def test_an_exemption_that_covers_a_rule_and_states_that_it_reaches_fails() -> None:
    """A rule that puts rule 2 on both sides fails, and the failure names rule 2."""
    rule = mutated_rule(SHIPPED_COVERS, "The exemption covers rule 1, rule 2, rule 3 and rule 17.")
    failures = rule_failures(rule)
    assert any(
        "both covers these rules and states that they reach: [2]" in failure for failure in failures
    )


def test_a_rule_placement_failure_reaches_the_whole_reading() -> None:
    """A placement the ruling refuses fails `evaluate`, beside the record readings."""
    rule = mutated_rule(SHIPPED_COVERS, "The exemption covers rule 1 and rule 17.")
    assert evaluate(rule, tracked_documents()) != ()


def test_the_entries_of_the_changelog_hold_paragraphs_past_the_limit() -> None:
    """The entries of `CHANGELOG.md` hold paragraphs past six sentences, so rule 3 needs it."""
    entries = regions(CHANGELOG_PATH, read_document(CHANGELOG_PATH))[0]
    over = over_limit_units(record_units(CHANGELOG_PATH, entries))
    assert len(over) >= CHANGELOG_PARAGRAPH_FLOOR


def test_the_changelog_table_of_the_specification_holds_paragraphs_past_the_limit() -> None:
    """The `## Changelog` table holds rows past six sentences, so rule 3 needs the exemption."""
    table = regions(SPECIFICATION_PATH, read_document(SPECIFICATION_PATH))[0]
    over = over_limit_units(record_units(SPECIFICATION_PATH, table))
    assert len(over) >= SPECIFICATION_PARAGRAPH_FLOOR


def test_the_shipped_exemption_measures_no_rule_against_the_changelog() -> None:
    """The shipped exemption covers both rules, so no rule reaches the entries of the record."""
    failures = uncovered_failures(
        read_document(RULE_PATH), CHANGELOG_PATH, read_document(CHANGELOG_PATH)
    )
    assert failures == [], (
        f"these paragraphs of {CHANGELOG_PATH} fail an uncovered rule: {failures}"
    )


def test_the_shipped_exemption_measures_no_rule_against_the_specification_table() -> None:
    """The shipped exemption covers both rules, so no rule reaches the `## Changelog` table."""
    failures = uncovered_failures(
        read_document(RULE_PATH), SPECIFICATION_PATH, read_document(SPECIFICATION_PATH)
    )
    assert failures == [], f"these rows of {SPECIFICATION_PATH} fail an uncovered rule: {failures}"


def test_an_exemption_that_drops_rule_three_reports_every_long_entry() -> None:
    """A rule that covers rule 1 alone reports the entries of `CHANGELOG.md` past six sentences."""
    rule = mutated_rule(SHIPPED_COVERS, "The exemption covers rule 1 and rule 17.")
    failures = uncovered_failures(rule, CHANGELOG_PATH, read_document(CHANGELOG_PATH))
    assert len(failures) >= CHANGELOG_PARAGRAPH_FLOOR
    assert all(failure.startswith(f"rule {PARAGRAPH_RULE} ") for failure in failures)


def test_an_exemption_that_drops_rule_three_reports_every_long_row() -> None:
    """A rule that covers rule 1 alone reports the rows of the `## Changelog` table."""
    rule = mutated_rule(SHIPPED_COVERS, "The exemption covers rule 1 and rule 17.")
    failures = uncovered_failures(rule, SPECIFICATION_PATH, read_document(SPECIFICATION_PATH))
    assert len(failures) >= SPECIFICATION_PARAGRAPH_FLOOR


def test_an_exemption_that_drops_rule_one_reports_every_long_sentence() -> None:
    """A rule that covers rule 3 alone reports the sentences of `CHANGELOG.md` past 25 words."""
    rule = mutated_rule(SHIPPED_COVERS, "The exemption covers rule 3 and rule 17.")
    failures = uncovered_failures(rule, CHANGELOG_PATH, read_document(CHANGELOG_PATH))
    assert len(failures) >= CHANGELOG_SENTENCE_FLOOR
    assert all(failure.startswith(f"rule {SENTENCE_RULE} ") for failure in failures)


def test_the_writing_standard_itself_holds_the_paragraph_limit() -> None:
    """`.claude/rules/ste.md` holds no paragraph past six sentences, because no exemption covers it."""
    failures = over_limit_paragraphs(read_document(RULE_PATH))
    assert failures == [], f"these paragraphs of {RULE_PATH} pass the limit: {failures}"


def test_a_document_outside_the_two_records_holds_the_paragraph_limit() -> None:
    """A page outside the two records reports its paragraph of seven sentences."""
    assert over_limit_paragraphs(LONG_PARAGRAPH) == [LONG_PARAGRAPH]


def test_the_paragraph_reader_parts_one_item_of_a_list_from_the_next() -> None:
    """Seven items of a list read as seven paragraphs, and none passes the limit."""
    listed = "\n".join(f"{number}. The reader states fact {number}." for number in range(1, 8))
    assert over_limit_paragraphs(listed) == []


def test_the_paragraph_reader_joins_the_wrapped_line_of_one_item() -> None:
    """A wrapped item reads as one paragraph, and its wrapped line opens no second one."""
    assert paragraphs("- The reader states one fact.\n  It states a second fact.\n") == [
        "The reader states one fact. It states a second fact."
    ]


def test_the_paragraph_reader_measures_no_line_of_a_code_block() -> None:
    """The paragraph reader measures no line inside a fenced code block."""
    assert over_limit_paragraphs(f"```\n{LONG_PARAGRAPH}\n```\n") == []


def test_the_paragraph_reader_reads_a_paragraph_of_the_limit_as_no_failure() -> None:
    """A paragraph of exactly six sentences passes, and a paragraph of seven fails."""
    at_limit = " ".join(f"The reader states fact {number}." for number in range(1, 7))
    assert over_limit_paragraphs(at_limit) == []
    assert over_limit_paragraphs(LONG_PARAGRAPH) == [LONG_PARAGRAPH]


def test_the_reader_reads_one_row_of_the_specification_table_as_one_paragraph() -> None:
    """Each row of the `## Changelog` table is one paragraph, and the separator row is none."""
    table = (
        f"| Round | Date | What changed |\n|---|---|---|\n| 1 | 2026-08-10 | {LONG_PARAGRAPH} |\n"
    )
    units = record_units(SPECIFICATION_PATH, table)
    assert len(units) == 2
    assert over_limit_units(units) == [f"| 1 | 2026-08-10 | {LONG_PARAGRAPH} |"]


def test_the_reader_reads_one_entry_of_the_changelog_as_one_paragraph() -> None:
    """Each entry of `CHANGELOG.md` is one paragraph, whatever count of lines it holds."""
    text = f"# Changelog\n\n- **A change** (#1). {LONG_PARAGRAPH}\n"
    units = record_units(CHANGELOG_PATH, regions(CHANGELOG_PATH, text)[0])
    assert len(units) == 1
    assert over_limit_units(units) == units
