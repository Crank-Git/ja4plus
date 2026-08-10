"""Tests that every document states the count of state tables one processor holds.

#453 found two documents that state a different count. `docs/api_reference.md` states
seventeen and `docs/specs/features/03-concurrency-safety.md` states sixteen, and the code
holds seventeen. **Two more numbers rest on that count**: the remembered-key count and the
memory those keys cost.

**A corrected number goes stale the next time a fingerprinter gains a table, and a reader
catches nothing.** Each case here therefore reads the count out of a live `Processor` and
compares each document against it. A case that restated seventeen would pass on a document
that contradicts the package.

## The three numbers, and how each one follows the one above it

`live_state_table_count` reads `Processor().stats()` and counts the `TableStats` entries.
That is the count of state tables.

`live_remembered_key_count` sums `max_entries` over the same entries. A state table
remembers the keys it evicted, and it bounds that memory at its own entry count, so the
sum is the count of remembered keys at the worst case.

`live_memory_figure` multiplies the key count by `BYTES_PER_KEY` and states the result in
MiB. #41 measured 187 bytes for one remembered key in an `OrderedDict`, and that reading
is the one both documents cite.

## What a case here does not read

**A dated record of a past measurement is quoted, not rewritten.** `CHANGELOG.md` records
one past round in every entry, and the `## Changelog` and `## Risks & open questions`
sections of `docs/specs/spec.md` each record a state of the project at the time of writing.
Round 85 records fifteen tables, 46400 keys and 8.3 MiB in its own words. `readable_text`
cuts all three places, so a correction here destroys no record.

**A count of the tables one fingerprinter holds is a different count, and it stands.** The
readers below match a claim about one processor, so a sentence that counts the two tables
of JA4L reports nothing.
"""

import re
from pathlib import Path
from typing import Dict, List

import pytest

from ja4plus import Processor
from tests.test_documented_method_count import documents, readable_text

REPO_ROOT = Path(__file__).resolve().parent.parent

# The bytes one remembered key costs in an `OrderedDict`. #41 measured the number with
# `tracemalloc`, and both documents that state the memory rest on it.
BYTES_PER_KEY = 187

# The bytes of one MiB. The documents state the memory in MiB, so the reader converts.
BYTES_PER_MIB = 1024 * 1024

# The count words a document may write for a table count. The range covers the counts this
# project has held and the two above them, so a new table still meets a reader.
COUNT_WORDS: Dict[int, str] = {
    6: "six",
    13: "thirteen",
    14: "fourteen",
    15: "fifteen",
    16: "sixteen",
    17: "seventeen",
    18: "eighteen",
    19: "nineteen",
    20: "twenty",
}

COUNT_PATTERN = "|".join(list(COUNT_WORDS.values()) + [str(number) for number in COUNT_WORDS])

# A claim about the count of state tables one processor holds. The first pattern reads a
# verb and then the count; the second reads the count as an adjective on the tables. Bold
# markers may sit around the count, because `docs/api_reference.md` writes one in bold.
TABLE_COUNT_PATTERNS = (
    re.compile(
        r"\b(?:holds?|covers?|reports?|reads?|walks?)\s+\*{0,2}(" + COUNT_PATTERN + r")\*{0,2}"
        r"\s+state tables\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bthe\s+\*{0,2}(" + COUNT_PATTERN + r")\*{0,2}\s+(?:state\s+)?tables\s+"
        r"(?:of one processor|hold)\b",
        re.IGNORECASE,
    ),
)

# A claim about the count of keys the state tables remember.
KEY_COUNT_PATTERN = re.compile(r"\b([0-9]{3,8})\s+remembered keys\b")

# A claim about the memory those keys cost. Both documents open the claim with the same
# four words, so the reader takes that opener and no other MiB figure of the page. The
# memory ceiling of #279 is a different number and it states a different sentence.
MEMORY_PATTERN = re.compile(r"\bthe memory costs\s+\*{0,2}([0-9]+\.[0-9]+)\s+MiB\b", re.IGNORECASE)

# The section of the feature file that records the bound of each state table.
BOUNDS_FILE = REPO_ROOT / "docs" / "specs" / "features" / "03-concurrency-safety.md"
BOUNDS_HEADING = "## State bounds the code holds today"

# The two rows of that table that describe no state table of a processor. The lookup client
# holds a cache that reads no packet, and `BaseFingerprinter.fingerprints` holds one result
# for each fingerprint rather than per-connection data.
NON_PROCESSOR_ROWS = ("JA4DBClient._cache", "BaseFingerprinter.fingerprints")

# The documents that state each number at the least. **An aggregate over an empty set
# passes**, so a reader that matched nothing would report a green run over no claim at all.
TABLE_COUNT_FLOOR = 2
KEY_COUNT_FLOOR = 2
MEMORY_FLOOR = 2

HTML_TAG = re.compile(r"<[^>]+>")


def _plain(text: str) -> str:
    """Return one line of text with no HTML tag and one space between words.

    A claim wraps across two lines in both documents, so a reader of single lines misses it.

    Args:
        text: The text of one document.

    Returns:
        The text as one line.
    """
    return " ".join(HTML_TAG.sub(" ", text).split())


def live_state_table_count() -> int:
    """Return the count of state tables one `Processor` holds.

    Returns:
        The count of `TableStats` entries `Processor.stats` reports.
    """
    return sum(len(report.tables) for report in Processor().stats().values())


def live_remembered_key_count() -> int:
    """Return the count of keys the state tables of one `Processor` remember at the worst case.

    Returns:
        The sum of `max_entries` over every table `Processor.stats` reports.
    """
    return sum(
        table.max_entries
        for report in Processor().stats().values()
        for table in report.tables.values()
    )


def live_memory_figure() -> str:
    """Return the memory the remembered keys cost, in MiB, to one decimal place.

    Returns:
        The figure a document states, as a string, so that a comparison reads no float.
    """
    return f"{live_remembered_key_count() * BYTES_PER_KEY / BYTES_PER_MIB:.1f}"


def stated_table_counts(text: str) -> List[str]:
    """Return every count of state tables the text states, in lowercase.

    Args:
        text: The text of one document.

    Returns:
        The count word or digit of each claim, in the order the text holds them, with no
        repetition.
    """
    found: List[str] = []
    line = _plain(text)
    for pattern in TABLE_COUNT_PATTERNS:
        for match in pattern.finditer(line):
            count = match.group(1).lower()
            if count not in found:
                found.append(count)
    return found


def stated_key_counts(text: str) -> List[str]:
    """Return every count of remembered keys the text states.

    Args:
        text: The text of one document.

    Returns:
        The digits of each claim, in the order the text holds them.
    """
    return [match.group(1) for match in KEY_COUNT_PATTERN.finditer(_plain(text))]


def stated_memory_figures(text: str) -> List[str]:
    """Return every memory figure the text states for the remembered keys.

    Args:
        text: The text of one document.

    Returns:
        The figure of each claim, in the order the text holds them.
    """
    return [match.group(1) for match in MEMORY_PATTERN.finditer(_plain(text))]


def bounds_table_rows() -> List[List[str]]:
    """Return the rows of the state-bound table of the feature file, as cell lists.

    Returns:
        One list of cells for each row that states a numeric maximum entry count and
        describes a state table of a processor.

    Raises:
        AssertionError: The feature file holds no section under `BOUNDS_HEADING`.
    """
    text = BOUNDS_FILE.read_text(encoding="utf-8")
    start = text.find(BOUNDS_HEADING)
    assert start != -1, f"{BOUNDS_FILE} holds no section {BOUNDS_HEADING!r}"
    end = text.find("\n## ", start + 1)
    section = text[start:] if end == -1 else text[start:end]
    rows: List[List[str]] = []
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2 or not cells[1].isdigit():
            continue
        if any(name in cells[0] for name in NON_PROCESSOR_ROWS):
            continue
        rows.append(cells)
    return rows


def _read(path: Path) -> str:
    """Return the readable text of one document.

    Args:
        path: The path of the document.

    Returns:
        The text with every recording section removed.
    """
    return readable_text(path, path.read_text(encoding="utf-8"))


def _name(path: Path) -> str:
    """Return the path of one document, relative to the repository root.

    Args:
        path: The absolute path.

    Returns:
        The relative path, as a string, which names the case.
    """
    return str(path.relative_to(REPO_ROOT))


DOCUMENTS = documents()
DOCUMENT_IDS = [_name(path) for path in DOCUMENTS]


def test_the_processor_holds_more_state_tables_than_the_reassemblers_alone() -> None:
    """The live count stands above the two `TCPStreamReassembler` instances.

    A reader that walked nothing would report zero, and every comparison below would then
    pass against a document that states any number.
    """
    assert live_state_table_count() > 2, "the walk of the processor found almost no state table"


def test_the_remembered_key_count_follows_the_bound_of_every_state_table() -> None:
    """The live key count stands above the count of state tables."""
    assert live_remembered_key_count() > live_state_table_count(), (
        "the sum of the entry bounds is no larger than the count of tables"
    )


def test_the_bounds_table_names_one_row_for_each_state_table_of_the_processor() -> None:
    """The state-bound table of the feature file holds one row for each live state table."""
    rows = bounds_table_rows()
    assert len(rows) == live_state_table_count(), (
        f"{_name(BOUNDS_FILE)} states the bound of {len(rows)} state tables, and one "
        f"processor holds {live_state_table_count()}: "
        f"{[row[0] for row in rows]}"
    )


def test_the_bounds_table_states_the_remembered_key_count_of_the_processor() -> None:
    """The maximum entry counts of the state-bound table sum to the live key count."""
    total = sum(int(row[1]) for row in bounds_table_rows())
    assert total == live_remembered_key_count(), (
        f"{_name(BOUNDS_FILE)} states entry bounds that sum to {total}, and one processor "
        f"bounds {live_remembered_key_count()} remembered keys"
    )


@pytest.mark.parametrize("path", DOCUMENTS, ids=DOCUMENT_IDS)
def test_every_document_states_the_count_of_state_tables_the_processor_holds(path: Path) -> None:
    """Every claim about the state-table count states the count of the processor."""
    count = live_state_table_count()
    allowed = {COUNT_WORDS[count], str(count)}
    stated = stated_table_counts(_read(path))
    wrong = [word for word in stated if word not in allowed]
    assert not wrong, (
        f"{_name(path)} states the state-table count as {wrong}, and one processor holds {count}"
    )


@pytest.mark.parametrize("path", DOCUMENTS, ids=DOCUMENT_IDS)
def test_every_document_states_the_remembered_key_count_the_processor_bounds(path: Path) -> None:
    """Every claim about the remembered-key count states the count of the processor."""
    keys = str(live_remembered_key_count())
    wrong = [count for count in stated_key_counts(_read(path)) if count != keys]
    assert not wrong, (
        f"{_name(path)} states {wrong} remembered keys, and one processor bounds {keys}"
    )


@pytest.mark.parametrize("path", DOCUMENTS, ids=DOCUMENT_IDS)
def test_every_document_states_the_memory_the_remembered_keys_cost(path: Path) -> None:
    """Every claim about the memory of the remembered keys states the computed figure."""
    figure = live_memory_figure()
    wrong = [found for found in stated_memory_figures(_read(path)) if found != figure]
    assert not wrong, (
        f"{_name(path)} states {wrong} MiB for the remembered keys, and "
        f"{live_remembered_key_count()} keys at {BYTES_PER_KEY} bytes cost {figure} MiB"
    )


def test_the_corpus_holds_documents_that_state_each_of_the_three_numbers() -> None:
    """The corpus holds a claim of each kind, above the floor each constant states."""
    texts = [_read(path) for path in DOCUMENTS]
    tables = [text for text in texts if stated_table_counts(text)]
    keys = [text for text in texts if stated_key_counts(text)]
    memory = [text for text in texts if stated_memory_figures(text)]
    assert len(tables) >= TABLE_COUNT_FLOOR, "the reader found almost no state-table count"
    assert len(keys) >= KEY_COUNT_FLOOR, "the reader found almost no remembered-key count"
    assert len(memory) >= MEMORY_FLOOR, "the reader found almost no memory figure"


TABLE_COUNT_SENTENCES = (
    "One processor holds **seventeen** state tables across the ten fingerprinters.",
    "One processor holds seventeen state tables: fifteen instances and two more.",
    "The report covers seventeen state tables, and not thirteen.",
    "The seventeen tables of one processor hold 57400 remembered keys.",
    "The seventeen tables hold 57400 remembered keys between them.",
    "`Processor.stats()` reports seventeen state tables across the fingerprinters.",
    "The processor now walks 17 state tables.",
)

OTHER_COUNTS = (
    "#39 moved thirteen tables, and it removed two companion tables.",
    "The count moved four times, from six in #179 to thirteen in #39 to fifteen in #41.",
    "The fifteen `BoundedStateTable` instances carry a maximum entry count.",
    "The entries of both JA4L tables rise together.",
)


@pytest.mark.parametrize("sentence", TABLE_COUNT_SENTENCES)
def test_the_table_count_reader_reads_each_wording_of_the_claim(sentence: str) -> None:
    """The reader takes the count out of every wording the two documents hold."""
    assert stated_table_counts(sentence) == ["seventeen"] or stated_table_counts(sentence) == [
        "17"
    ], f"the reader read {stated_table_counts(sentence)} from {sentence!r}"


@pytest.mark.parametrize("sentence", OTHER_COUNTS)
def test_the_table_count_reader_reads_no_count_of_another_thing(sentence: str) -> None:
    """The reader takes no count from a sentence that counts something other than the tables."""
    assert stated_table_counts(sentence) == [], (
        f"the reader read {stated_table_counts(sentence)} from {sentence!r}"
    )


def test_the_table_count_reader_reads_a_claim_that_two_lines_carry() -> None:
    """The reader takes a claim that a line break splits."""
    assert stated_table_counts(
        "The seventeen tables of one processor hold 57400\nremembered keys"
    ) == ["seventeen"]


def test_the_key_count_reader_reads_the_claim_and_no_other_number() -> None:
    """The reader takes the remembered-key count and no other number of the sentence."""
    assert stated_key_counts("The seventeen tables hold 57400 remembered keys, at 187 bytes.") == [
        "57400"
    ]


def test_the_memory_reader_reads_no_figure_of_the_memory_ceiling() -> None:
    """The reader takes no MiB figure that states the resident memory of a packet run."""
    assert stated_memory_figures("The highest of the four is 394.94 MiB, below the ceiling.") == []


def test_the_memory_reader_reads_the_cost_of_the_remembered_keys() -> None:
    """The reader takes the figure the remembered-key sentence states."""
    assert stated_memory_figures("so the memory costs 10.2 MiB at its worst") == ["10.2"]


def test_the_bounds_table_reader_reads_no_row_of_the_lookup_client() -> None:
    """The reader drops the two rows that describe no state table of a processor."""
    names = [row[0] for row in bounds_table_rows()]
    assert not [name for name in names if any(other in name for other in NON_PROCESSOR_ROWS)]
