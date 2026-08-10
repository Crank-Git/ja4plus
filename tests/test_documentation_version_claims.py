"""Tests that the documentation states no version claim the declaration contradicts.

`ja4plus/__init__.py:101` declares the version of this project, and `FR-release-1` puts
that number in one place. **A page that calls the declared version unreleased is stale on
the day the bump lands**, and #545 records the two pages that held such a sentence before
this round. These cases read the declaration and they hold the prose against it, so a
later bump fails here rather than leaving a reader with a false sentence.

## What a case reads

The corpus is `README.md`, every tracked Markdown page under `docs/` that stands outside
`docs/specs/`, and the preamble of `CHANGELOG.md`. That set is the documentation a reader
of the published package meets. `docs/specs/` holds the specification package, which
`mkdocs.yml` excludes from the site.

**A dated record of a past measurement is quoted, and it is never rewritten.**
`.claude/rules/ste.md` states the exemption for the entries of `CHANGELOG.md` and for the
`## Changelog` table of `docs/specs/spec.md`. `readable_prose` therefore cuts every
`CHANGELOG.md` entry, which starts at the first `### ` heading, and the corpus holds no
page of `docs/specs/`.

**The release heading of `CHANGELOG.md` is exempt, and #543 owns it.** `## [1.0.0] -
unreleased` carries the release date of the section, and the bump writes that date. A case
that read the heading would refuse the bump it exists to serve.

## Which versions a case checks

`checked_versions` returns the declared version of `ja4plus/__init__.py` and every version
`CHANGELOG.md` holds a release section for. **The declared version reaches the set through
the declaration and never through a literal**, so the set follows the bump.
`test_the_checked_versions_read_the_declaration` measures that.

The set reads `0.6.0` and `1.0.0` before #543 lands, because the declaration holds `0.6.0`
and `CHANGELOG.md` holds a section for each. It reads the same two after #543 lands,
because the declaration then holds `1.0.0`, which the changelog already names. A later
bump to a version the changelog also records adds that version to the set.

## The fence reader

**Warning: a line that opens and closes a code span with three backticks is no fence.**
`docs/specs/foxio/JA4X.md:235` holds such a line, and #533 measured what a naive reader
did with it: the reader took the line for a fence opener, shifted every fence pair below
it, and reported nine instances that no page holds. CommonMark states the rule this reader
follows. **An info string carries no backtick**, so a line that holds a second run of three
backticks opens no fence. `test_the_reader_reads_an_inline_code_span_as_no_fence` holds
the JA4X shape against it.

**The reader is no CommonMark parser, and three limits follow.** It reads a tilde fence as
prose, it accepts an indent of any depth before the backticks, and it reads a run of four
backticks and a run of three as one delimiter class. No page of the corpus holds any of
the three shapes, and a page that did would need a reading here first.

These cases read prose. They produce no fingerprint and they open no capture socket.
"""

import re
from pathlib import Path
from typing import Dict, List, Set

import ja4plus
from tests.test_documented_method_count import tracked_documents

REPO_ROOT = Path(__file__).resolve().parent.parent

# The git pathspec that names every tracked Markdown page. **In a default git pathspec `*`
# crosses `/`**, so this one term reaches every depth.
MARKDOWN_PATHSPEC = "*.md"

# The specification package. `mkdocs.yml` excludes it from the site, so no reader of the
# published package meets it.
SPECIFICATION_PREFIX = "docs/specs/"

# The file whose entries record one past round each. The reader keeps the preamble of this
# file and it cuts every entry.
RECORD_FILE = "CHANGELOG.md"

# The heading that opens the first entry of `CHANGELOG.md`. Every line from here down
# records a past measurement, which `.claude/rules/ste.md` exempts from a rewrite.
RECORD_ENTRY_HEADING = re.compile(r"^### ", re.MULTILINE)

# The release heading of `CHANGELOG.md`, in the Keep a Changelog form. #543 writes the date
# of the section at the bump, so no case here reads the line.
RELEASE_HEADING = re.compile(r"^## \[\d+\.\d+\.\d+\][^\n]*$", re.MULTILINE)

# A version number of the form the project declares.
VERSION = re.compile(r"\d+\.\d+\.\d+")

# The release section of `CHANGELOG.md`, whose bracket holds the version.
CHANGELOG_SECTION = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.MULTILINE)

# The words that call a version unreleased. A sentence that names a checked version and one
# of these words is the defect #545 removes.
UNRELEASED_WORDS = (
    "not released",
    "not yet released",
    "unreleased",
    "forthcoming",
    "upcoming",
    "will be released",
    "is not out",
)

# The end of one sentence. The reader splits the prose on it, so a version and an
# unreleased word reach one match only where one sentence holds both.
SENTENCE_END = re.compile(r"(?<=[.!?])\s+")

# The least count of pages the corpus holds. **An aggregate over an empty set passes**, so
# a reader that named no page would report a green result for every case here.
CORPUS_FLOOR = 20

# The pages that held a version claim before #545, and the two that carry the schema
# history and the interface. A case names each one, so a reader that stops reaching the
# corpus fails here rather than passes over nothing.
ANCHOR_FILES = (
    "README.md",
    "CHANGELOG.md",
    "docs/migration-0.6-to-1.0.md",
    "docs/output-schema.md",
    "docs/api_reference.md",
)

# The page that records the history of the output schema.
SCHEMA_PAGE = "docs/output-schema.md"

# The heading of the table that names the release of each schema version.
SCHEMA_HISTORY_HEADING = "## The history of the schema"


def is_fence_delimiter(line: str) -> bool:
    """Return True where the line opens or closes a fenced code block.

    A line that holds a second run of three backticks carries an info string with a
    backtick, which CommonMark forbids, so such a line is a code span and no fence.

    Args:
        line: One line of a Markdown page.

    Returns:
        True where the line is a fence delimiter.
    """
    stripped = line.lstrip()
    if not stripped.startswith("```"):
        return False
    return "```" not in stripped[3:]


def without_fenced_blocks(text: str) -> str:
    """Return the text with every line of a fenced code block replaced by an empty line.

    The reader keeps the line count, so a caller reports the line number of a match.

    Args:
        text: The whole text of one page.

    Returns:
        The text with no line of a fenced block.
    """
    kept: List[str] = []
    fenced = False
    for line in text.splitlines():
        if is_fence_delimiter(line):
            fenced = not fenced
            kept.append("")
            continue
        kept.append("" if fenced else line)
    return "\n".join(kept)


def readable_prose(name: str, text: str) -> str:
    """Return the prose of one page that a case reads.

    Args:
        name: The path of the page, relative to the repository root.
        text: The whole text of the page.

    Returns:
        The prose. `CHANGELOG.md` loses every entry and its release headings, and every
        page loses its fenced blocks and its backticks.
    """
    if name == RECORD_FILE:
        entry = RECORD_ENTRY_HEADING.search(text)
        if entry is not None:
            text = text[: entry.start()]
        text = RELEASE_HEADING.sub("", text)
    return without_fenced_blocks(text).replace("`", "")


def corpus() -> Dict[str, str]:
    """Return the prose of every page a case reads, keyed by path.

    Returns:
        One entry for each page, whose value is the prose `readable_prose` returns.

    Raises:
        AssertionError: The tracked page list is shorter than `CORPUS_FLOOR`.
        subprocess.CalledProcessError: The read of git failed.
    """
    found: Dict[str, str] = {}
    for path in tracked_documents(MARKDOWN_PATHSPEC):
        name = path.relative_to(REPO_ROOT).as_posix()
        if name.startswith(SPECIFICATION_PREFIX):
            continue
        if name != RECORD_FILE and name != "README.md" and not name.startswith("docs/"):
            continue
        found[name] = readable_prose(name, path.read_text(encoding="utf-8"))
    assert len(found) >= CORPUS_FLOOR, (
        f"the corpus holds {len(found)} pages, and a reader that holds fewer than "
        f"{CORPUS_FLOOR} passes every case here over an empty set"
    )
    return found


def changelog_versions() -> Set[str]:
    """Return every version `CHANGELOG.md` holds a release section for.

    Returns:
        One version for each section.
    """
    text = (REPO_ROOT / RECORD_FILE).read_text(encoding="utf-8")
    return set(CHANGELOG_SECTION.findall(text))


def checked_versions(declared: str = ja4plus.__version__) -> Set[str]:
    """Return every version a case reads the prose against.

    Args:
        declared: The version `ja4plus/__init__.py` declares. A case passes another
            version to prove that the set reads the declaration.

    Returns:
        The declared version, and every version `CHANGELOG.md` records.
    """
    return {declared} | changelog_versions()


def unreleased_claims(prose: str, versions: Set[str]) -> List[str]:
    """Return every sentence that names a checked version and calls it unreleased.

    Args:
        prose: The prose of one page, after `readable_prose` ran.
        versions: The versions to read for.

    Returns:
        One sentence for each claim, with its whitespace collapsed.
    """
    found: List[str] = []
    for sentence in SENTENCE_END.split(prose.replace("\n", " ")):
        lowered = sentence.lower()
        if not any(word in lowered for word in UNRELEASED_WORDS):
            continue
        if any(version in sentence for version in versions):
            found.append(" ".join(sentence.split()))
    return found


def test_no_page_calls_a_checked_version_unreleased() -> None:
    """No documentation page states that a checked version is unreleased."""
    versions = checked_versions()
    reported: List[str] = []
    for name, prose in corpus().items():
        for sentence in unreleased_claims(prose, versions):
            reported.append(f"{name}: {sentence}")
    assert reported == [], (
        "a page calls a version unreleased that ja4plus/__init__.py or CHANGELOG.md "
        f"records: {reported}"
    )


def test_the_rule_reports_a_page_that_calls_the_declared_version_unreleased() -> None:
    """The rule reports a sentence that calls the declared version unreleased."""
    declared = ja4plus.__version__
    prose = f"Version {declared} is not released yet."
    assert unreleased_claims(prose, checked_versions()) == [
        f"Version {declared} is not released yet."
    ]


def test_the_rule_reads_no_sentence_that_names_another_version() -> None:
    """The rule reports no sentence that calls a version outside the set unreleased."""
    prose = "Version 42.0.0 is not released yet."
    assert unreleased_claims(prose, checked_versions()) == []


def test_the_rule_reads_one_sentence_at_a_time() -> None:
    """The rule reports no version and no unreleased word that stand in two sentences."""
    declared = ja4plus.__version__
    prose = f"Version {declared} reads the packets. Version 42.0.0 is not released yet."
    assert unreleased_claims(prose, checked_versions()) == []


def test_the_checked_versions_read_the_declaration() -> None:
    """The version set reads `ja4plus/__init__.py` and never a literal version."""
    assert ja4plus.__version__ in checked_versions()
    assert "9.9.9" in checked_versions("9.9.9")
    assert "9.9.9" not in checked_versions()


def test_the_changelog_records_the_declared_version() -> None:
    """`CHANGELOG.md` holds a release section for the version the package declares."""
    assert ja4plus.__version__ in changelog_versions(), (
        f"CHANGELOG.md holds no section for the declared version {ja4plus.__version__}"
    )


def test_the_corpus_names_every_checked_version() -> None:
    """The prose of the corpus names each checked version at least once."""
    prose = " ".join(corpus().values())
    missing = sorted(version for version in checked_versions() if version not in prose)
    assert missing == [], (
        f"the corpus names none of these versions, so no case reads them: {missing}"
    )


def test_the_corpus_holds_each_anchor_file() -> None:
    """The corpus holds each page a case names."""
    found = corpus()
    missing = sorted(name for name in ANCHOR_FILES if name not in found)
    assert missing == [], f"the corpus reaches none of these pages: {missing}"


def test_the_reader_reads_no_fenced_block() -> None:
    """The reader reads no line inside a fenced code block."""
    page = "Before.\n```\nVersion 1.0.0 is not released yet.\n```\nAfter."
    assert "not released" not in without_fenced_blocks(page)
    assert "Before." in without_fenced_blocks(page)
    assert "After." in without_fenced_blocks(page)


def test_the_reader_reads_an_inline_code_span_as_no_fence() -> None:
    """The reader reads a line that opens and closes a code span as no fence.

    `docs/specs/foxio/JA4X.md:235` holds that shape, and #533 measured a reader that took
    it for a fence opener.
    """
    span = "```JA4X=2bab15409345_af684594efb4_000000000000```. The first two parts match."
    assert is_fence_delimiter(span) is False
    assert is_fence_delimiter("```") is True
    assert is_fence_delimiter("```bash") is True
    page = f"{span}\nVersion 1.0.0 is not released yet."
    assert "not released" in without_fenced_blocks(page)


def test_the_reader_cuts_every_changelog_entry() -> None:
    """The reader cuts each `CHANGELOG.md` entry, which records one past round."""
    prose = corpus()[RECORD_FILE]
    assert "Keep a Changelog" in prose
    assert "Round " not in prose


def test_the_reader_cuts_the_release_heading_of_the_changelog() -> None:
    """The reader cuts the release heading, whose date #543 writes at the bump."""
    prose = readable_prose(RECORD_FILE, "## [1.0.0] - unreleased\n\nThe release.\n")
    assert "unreleased" not in prose
    assert "The release." in prose


def test_the_schema_history_names_a_release_for_every_schema_version() -> None:
    """The schema history of `docs/output-schema.md` calls no release unreleased."""
    text = (REPO_ROOT / SCHEMA_PAGE).read_text(encoding="utf-8")
    start = text.index(SCHEMA_HISTORY_HEADING)
    rows = [
        line
        for line in text[start:].splitlines()
        if line.startswith("|") and not line.startswith("|---") and "Version" not in line
    ]
    assert rows, f"{SCHEMA_PAGE} holds no schema history row"
    for row in rows:
        release = row.split("|")[2].strip()
        assert VERSION.fullmatch(release), (
            f"{SCHEMA_PAGE} names the release {release!r} for a schema version, and a "
            "release is a version number"
        )
