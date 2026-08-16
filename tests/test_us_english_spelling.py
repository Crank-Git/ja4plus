"""Tests that the live prose of this repository holds the US spelling of every word.

The maintainer ruled US English on 2026-08-16, on #663. Rule 17 of `.claude/rules/ste.md`
states the ruling, and this module holds the corpus against it. The reason the maintainer
gave is that the documentation of this repository is largely agent-written, so a worker
that matches the surrounding spelling strengthens a convention no person chose.

**This module keeps no exemption list of its own.** It reads the corpus from the `paths`
list of the rule file, it reads the two exempt records from `## The exemption`, and it
reads every exempt span from `### The spellings rule 17 keeps`. A new record or a new
identifier therefore needs an edit of the rule file and no edit here.

**This module keeps the detection list, because detection is the rule and not the
exemption.** `BRITISH_SPANS` names one substring for each spelling class, and
`SUFFIX_SPELLINGS` names the classes that a suffix decides.

## What a case here does not read

**A word that ends with a stop word reaches no case.** `SUFFIX_STOPS` names the words that
end in `ise` and carry the US spelling already, such as `raise` and `promise`. A British
verb whose stem ends with one of them therefore passes, and the corpus holds no such word.

**`analyses` reaches no case**, because it is both the plural of `analysis` and the British
verb form. The plural is the reading this corpus uses.

**A word inside a code span reaches no case**, which bar 2 of the rule file states. A
writer who wants rule 17 to reach a word writes that word as prose.

**This file reaches no case either**, which bar 5 states. `BRITISH_SPANS` holds one British
spelling for each class it detects, and a sweep of this file would empty the detector. The
first sweep of #663 met that trap. It rewrote 89 words here, and it left a module that
detected the US spelling and reported it as British.

These cases read prose and the file list of git. They import nothing from `ja4plus` and
they produce no fingerprint.
"""

from fnmatch import fnmatch
from pathlib import Path
import re
import subprocess
from typing import Dict, List, NamedTuple, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

RULE_PATH = ".claude/rules/ste.md"

# The module that states the detection list, which bar 5 of the rule file keeps whole.
DETECTOR_PATH = "tests/test_us_english_spelling.py"

# The heading of each section this module reads. `## The exemption` names the two records,
# and the spelling section names every span a case or a caller reads by string.
EXEMPTION_HEADING = "## The exemption"
SPELLING_HEADING = "### The spellings rule 17 keeps"

# The heading of the exempt region of `docs/specs/spec.md`. The exemption names it, and the
# reader takes the name from the file rather than from this line.
CHANGELOG_TABLE_PATH = "docs/specs/spec.md"

# One substring for each spelling class, and the US form of that substring. A word that
# holds the substring holds the British spelling, and no US word of this corpus holds one.
BRITISH_SPANS: Tuple[Tuple[str, str], ...] = (
    ("behaviour", "behavior"),
    ("neighbour", "neighbor"),
    ("favour", "favor"),
    ("honour", "honor"),
    ("colour", "color"),
    ("rumour", "rumor"),
    ("armour", "armor"),
    ("labour", "labor"),
    ("harbour", "harbor"),
    ("endeavour", "endeavor"),
    ("flavour", "flavor"),
    ("humour", "humor"),
    ("odour", "odor"),
    ("savour", "savor"),
    ("splendour", "splendor"),
    ("valour", "valor"),
    ("vapour", "vapor"),
    ("vigour", "vigor"),
    ("parlour", "parlor"),
    ("saviour", "savior"),
    ("demeanour", "demeanor"),
    ("artefact", "artifact"),
    ("judgement", "judgment"),
    ("acknowledgement", "acknowledgment"),
    ("centre", "center"),
    ("metre", "meter"),
    ("litre", "liter"),
    ("fibre", "fiber"),
    ("theatre", "theater"),
    ("licence", "license"),
    ("defence", "defense"),
    ("offence", "offense"),
    ("pretence", "pretense"),
    ("practise", "practice"),
    ("enrolment", "enrollment"),
    ("instalment", "installment"),
    ("skilful", "skillful"),
    ("wilful", "willful"),
    ("labelled", "labeled"),
    ("labelling", "labeling"),
    ("modelled", "modeled"),
    ("modelling", "modeling"),
    ("cancelled", "canceled"),
    ("cancelling", "canceling"),
    ("travelled", "traveled"),
    ("travelling", "traveling"),
    ("signalled", "signaled"),
    ("signalling", "signaling"),
    ("fuelled", "fueled"),
    ("fuelling", "fueling"),
    ("marvellous", "marvelous"),
    ("counsellor", "counselor"),
    ("jewellery", "jewelry"),
    ("grey", "gray"),
    ("mould", "mold"),
    ("smoulder", "smolder"),
    ("plough", "plow"),
    ("storey", "story"),
    ("tyre", "tire"),
    ("kerb", "curb"),
    ("cheque", "check"),
    ("manoeuvre", "maneuver"),
    ("sulphur", "sulfur"),
    ("aluminium", "aluminum"),
)

# Two substrings whose US form needs a lookahead, because a US word holds the substring.
# `fulfill` holds `fulfil` and `programmer` holds `programme`.
GUARDED_SPANS: Tuple[Tuple[str, str, str], ...] = (
    ("fulfil", "fulfill", r"fulfil(?!l)"),
    ("programme", "program", r"programme(?!r)"),
)

# The suffix classes. A word that ends with one of these carries the British spelling,
# unless it ends with a stop word of `SUFFIX_STOPS`.
SUFFIX_SPELLINGS: Tuple[Tuple[str, str], ...] = (
    ("isation", "ization"),
    ("isations", "izations"),
    ("isable", "izable"),
    ("ising", "izing"),
    ("ised", "ized"),
    ("ises", "izes"),
    ("ise", "ize"),
    ("lysing", "lyzing"),
    ("lysed", "lyzed"),
    ("lyse", "lyze"),
)

# The words that end in `ise` and already carry the US spelling. A word that ends with one
# of them, or with an inflection of it, reaches no case. **The check reads the end of the
# word and not the whole word**, because an identifier joins several words into one token
# and `assertraises` is such a token.
SUFFIX_STOPS: Tuple[str, ...] = (
    "raise",
    "rise",
    "promise",
    "premise",
    "wise",
    "exercise",
    "advertise",
    "advise",
    "revise",
    "improvise",
    "disguise",
    "enterprise",
    "arise",
    "franchise",
    "surprise",
    "compromise",
    "precise",
    "concise",
    "merchandise",
    "comprise",
    "despise",
    "devise",
    "supervise",
    "paradise",
    "expertise",
    "treatise",
    "chastise",
    "apprise",
    "reprise",
    "bruise",
    "cruise",
    "guise",
    "poise",
    "noise",
    "praise",
    "appraise",
    "excise",
    "incise",
    "demise",
    "analyses",
)

# The count of documents the corpus holds at the least. **An aggregate over an empty set
# passes**, so a reader that names too few files fails here rather than reporting a clean
# corpus. The corpus holds 251 files today.
CORPUS_FLOOR = 150

# The count of exempt spans the rule file names at the least. A reader that parses no item
# would exempt nothing, and the sweep would then fail on every identifier it kept.
SPAN_FLOOR = 8

# A span of inline code. Bar 2 of the rule file reproduces every one of them verbatim.
CODE_SPAN = re.compile(r"`[^`\n]+`")

# A Markdown quotation, which bar 1 of the rule file reproduces verbatim.
QUOTATION = re.compile(r"^\s*>")

# The front matter of the rule file, which names every path the standard reaches.
FRONT_MATTER = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
FRONT_MATTER_PATH = re.compile(r'^\s*-\s*"([^"]+)"\s*$')

# One item of a Markdown list, and the wrapped lines that belong to it.
LIST_OPENER = re.compile(r"^- ")

# A span of inline code inside one list item. The exemption names a path this way, and the
# spelling list names the span first and the path second.
ITEM_SPAN = re.compile(r"`([^`]+)`")

# The form of a path one item of the exemption names.
PATH_SPAN = re.compile(r"^[\w./-]+\.md$")

# One word of the prose. A word holds letters alone, so a path breaks into its parts and an
# identifier that joins words with an underscore breaks the same way.
WORD = re.compile(r"[A-Za-z]+")


class Failure(NamedTuple):
    """One British spelling the corpus holds, with the place and the US form."""

    path: str
    line: int
    word: str
    us_form: str

    def __str__(self) -> str:
        """Return the failure as one line a reader can act on."""
        return f"{self.path}:{self.line}: {self.word} -> {self.us_form}"


class ExemptSpan(NamedTuple):
    """One span rule 17 keeps, and the git pathspec of the files that hold it."""

    span: str
    path: str


def read_file(path: str) -> str:
    """Return the whole text of one tracked file.

    Args:
        path: The path of the file, relative to the repository root.

    Returns:
        The text of the file.
    """
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def tracked_files() -> Tuple[str, ...]:
    """Return every file git tracks in this repository.

    Returns:
        One path for each tracked file, relative to the repository root.
    """
    listing = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return tuple(line for line in listing.stdout.splitlines() if line)


def section_body(text: str, heading: str) -> str:
    """Return the body of one section of a Markdown page.

    Args:
        text: The whole text of the page.
        heading: The heading line of the section, with its marks.

    Returns:
        The text below the heading and above the next heading of the same depth or higher,
        or an empty string where the page holds no such section.
    """
    start = text.find(f"\n{heading}\n")
    if start == -1:
        return ""
    body = text[start + len(heading) + 2 :]
    depth = len(heading) - len(heading.lstrip("#"))
    stop = re.compile(r"^#{1,%d} " % depth, re.MULTILINE)
    end = stop.search(body)
    return body if end is None else body[: end.start()]


def list_items(body: str) -> List[str]:
    """Return every item of one Markdown list, with each wrapped item on one line.

    Args:
        body: The text of the section that holds the list.

    Returns:
        One string for each item that opens with `- `, in file order.
    """
    items: List[str] = []
    for line in body.splitlines():
        if LIST_OPENER.match(line):
            items.append(line[2:].strip())
            continue
        if items and line.startswith(" ") and line.strip():
            items[-1] = f"{items[-1]} {line.strip()}"
    return items


def corpus_paths(rule_text: str) -> Tuple[str, ...]:
    """Return every git pathspec the front matter of the writing standard names.

    **A `*` of a git pathspec crosses a separator**, so this reader drops a `**` term and
    reads the rest as one crossing pattern.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.

    Returns:
        One pattern for each path the front matter lists.
    """
    matter = FRONT_MATTER.match(rule_text)
    if matter is None:
        return ()
    found = []
    for line in matter.group(1).splitlines():
        item = FRONT_MATTER_PATH.match(line)
        if item:
            found.append(item.group(1).replace("**/", ""))
    return tuple(found)


def corpus(rule_text: str, files: Tuple[str, ...]) -> Tuple[str, ...]:
    """Return every tracked file the writing standard reaches.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.
        files: Every path git tracks.

    Returns:
        One path for each file that matches a pattern of the front matter.
    """
    patterns = corpus_paths(rule_text)
    return tuple(path for path in files if any(fnmatch(path, term) for term in patterns))


def exempt_records(rule_text: str) -> Dict[str, str]:
    """Return the two records the exemption names, each with the region that is exempt.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.

    Returns:
        The path of each record, against the heading of its exempt region. An empty heading
        names the whole file.
    """
    records: Dict[str, str] = {}
    for item in list_items(section_body(rule_text, EXEMPTION_HEADING)):
        spans = ITEM_SPAN.findall(item)
        headings = [span for span in spans if span.startswith("#")]
        for span in spans:
            if PATH_SPAN.match(span):
                records[span] = headings[0] if headings else ""
    return records


def exempt_spans(rule_text: str) -> Tuple[ExemptSpan, ...]:
    """Return every span rule 17 keeps, with the git pathspec that holds it.

    **Each item names the span first and the path second.** A reader that took the third
    code span would read a reason rather than a path.

    Args:
        rule_text: The whole text of `.claude/rules/ste.md`.

    Returns:
        One entry for each item of the spelling list.
    """
    found: List[ExemptSpan] = []
    for item in list_items(section_body(rule_text, SPELLING_HEADING)):
        spans = ITEM_SPAN.findall(item)
        if len(spans) >= 2:
            found.append(ExemptSpan(spans[0], spans[1]))
    return tuple(found)


def _suffix_form(word: str) -> str:
    """Return the US form of one word a suffix class decides, or an empty string.

    Args:
        word: One word of the prose, in the case the file holds.

    Returns:
        The US form, or an empty string where no suffix class reaches the word.
    """
    lowered = word.lower()
    for stop in SUFFIX_STOPS:
        endings = (stop, f"{stop}s", f"{stop}d", f"{stop[:-1]}ing")
        if any(lowered.endswith(ending) for ending in endings):
            return ""
    for british, american in SUFFIX_SPELLINGS:
        if lowered.endswith(british):
            return f"{word[: len(word) - len(british)]}{american}"
    return ""


def us_form(word: str) -> str:
    """Return the US spelling of one word, or an empty string where the word holds it.

    Args:
        word: One word of the prose, in the case the file holds.

    Returns:
        The US form of the word, or an empty string where rule 17 reaches the word nowhere.
    """
    lowered = word.lower()
    for british, american in BRITISH_SPANS:
        if british in lowered:
            return re.sub(british, american, word, flags=re.IGNORECASE)
    for british, american, pattern in GUARDED_SPANS:
        if re.search(pattern, lowered):
            return re.sub(pattern, american, word, flags=re.IGNORECASE)
    return _suffix_form(word)


def _masked(line: str) -> str:
    """Return one line with every code span replaced by spaces.

    Bar 2 of the rule file reproduces a code span verbatim, so no case reads inside one.

    Args:
        line: One line of a file.

    Returns:
        The line, with the same length, and a space in place of every code-span character.
    """
    return CODE_SPAN.sub(lambda match: " " * len(match.group(0)), line)


def _exempt_at(path: str, line: str, start: int, end: int, spans: Tuple[ExemptSpan, ...]) -> bool:
    """Return whether one span of the rule file overlaps the word at one offset.

    **The reader takes an overlap and not a containment.** `BehaviourRules` stands inside
    the case name `TestTheBehaviourRulesNameOneCommand`, and a reader of the word start
    alone would report that name. **The reader ignores the case of a letter**, because
    `NEIGHBOUR_CLIENT` holds the span `neighbour` in upper case.

    Args:
        path: The path of the file, relative to the repository root.
        line: The whole line the word stands on.
        start: The offset of the first letter of the word.
        end: The offset past the last letter of the word.
        spans: Every span the rule file keeps.

    Returns:
        True where a span the file matches overlaps the word.
    """
    lowered = line.lower()
    for entry in spans:
        if not fnmatch(path, entry.path):
            continue
        span = entry.span.lower()
        offset = lowered.find(span)
        while offset != -1:
            if offset < end and start < offset + len(span):
                return True
            offset = lowered.find(span, offset + 1)
    return False


def _exempt_lines(path: str, text: str, records: Dict[str, str]) -> frozenset:
    """Return the line numbers of the exempt region of one record.

    Args:
        path: The path of the file, relative to the repository root.
        text: The whole text of the file.
        records: Every record the exemption names, against its region heading.

    Returns:
        The 1-based line numbers no case reads, and an empty set where the file is no
        record.
    """
    if path not in records:
        return frozenset()
    heading = records[path]
    lines = text.splitlines()
    if not heading:
        return frozenset(range(1, len(lines) + 1))
    depth = len(heading) - len(heading.lstrip("#"))
    inside = False
    exempt = set()
    for number, line in enumerate(lines, start=1):
        if line.strip() == heading:
            inside = True
            exempt.add(number)
            continue
        if inside and re.match(r"^#{1,%d} " % depth, line):
            inside = False
        if inside:
            exempt.add(number)
    return frozenset(exempt)


def failures(
    path: str, text: str, spans: Tuple[ExemptSpan, ...], records: Dict[str, str]
) -> List[Failure]:
    """Return every British spelling of one file that rule 17 refuses.

    Args:
        path: The path of the file, relative to the repository root.
        text: The whole text of the file.
        spans: Every span the rule file keeps.
        records: Every record the exemption names, against its region heading.

    Returns:
        One entry for each word that carries a British spelling rule 17 reaches.
    """
    if path == DETECTOR_PATH:
        return []
    skipped = _exempt_lines(path, text, records)
    found: List[Failure] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if number in skipped or QUOTATION.match(line):
            continue
        masked = _masked(line)
        for match in WORD.finditer(masked):
            american = us_form(match.group(0))
            if american and not _exempt_at(path, line, match.start(), match.end(), spans):
                found.append(Failure(path, number, match.group(0), american))
    return found


def corpus_failures() -> List[Failure]:
    """Return every British spelling the live prose of this repository holds.

    Returns:
        One entry for each word rule 17 refuses, over the whole corpus.
    """
    rule_text = read_file(RULE_PATH)
    spans = exempt_spans(rule_text)
    records = exempt_records(rule_text)
    found: List[Failure] = []
    for path in corpus(rule_text, tracked_files()):
        found.extend(failures(path, read_file(path), spans, records))
    return found


def test_the_live_prose_holds_the_us_spelling_of_every_word() -> None:
    """The corpus of the writing standard holds no British spelling rule 17 refuses."""
    found = corpus_failures()
    assert found == [], "these words hold a British spelling: " + "; ".join(
        str(failure) for failure in found[:40]
    )


def test_the_reader_names_the_corpus_of_the_writing_standard() -> None:
    """The reader names every file the front matter of the rule reaches, and it names many."""
    files = corpus(read_file(RULE_PATH), tracked_files())
    assert len(files) >= CORPUS_FLOOR, f"the reader names {len(files)} files"
    assert RULE_PATH in files
    assert "README.md" in files
    assert "docs/specs/spec.md" in files
    assert "docs/specs/spec.html" in files
    assert "ja4plus/cli.py" in files
    assert "tests/test_us_english_spelling.py" in files


def test_the_reader_takes_the_two_records_from_the_rule_file() -> None:
    """The reader reads the exempt records from `## The exemption` and from no list here."""
    records = exempt_records(read_file(RULE_PATH))
    assert records == {"CHANGELOG.md": "", CHANGELOG_TABLE_PATH: "## Changelog"}


def test_the_reader_takes_every_exempt_span_from_the_rule_file() -> None:
    """The reader reads the exempt spans from the spelling section and from no list here."""
    spans = exempt_spans(read_file(RULE_PATH))
    assert len(spans) >= SPAN_FLOOR, f"the reader names {len(spans)} spans"
    assert ExemptSpan("Behaviour rule", "*") in spans
    assert ExemptSpan("acknowledgement", "*") in spans


def test_the_rule_file_states_the_spelling_rule_under_the_word_heading() -> None:
    """Rule 17 stands under `### Words`, so a reader of the word rules finds it."""
    body = section_body(read_file(RULE_PATH), "### Words")
    assert "17." in body
    assert "US English spelling" in body


def test_the_rule_file_states_the_reason_the_maintainer_gave() -> None:
    """The exemption states why the maintainer ruled, so no later round re-derives it."""
    body = section_body(read_file(RULE_PATH), EXEMPTION_HEADING)
    assert "largely agent-written" in body
    assert "2026-08-16" in body


def test_the_rule_file_states_the_five_bars_of_the_sweep() -> None:
    """The spelling section states the quotation bar, the code-span bar and the three lists."""
    body = section_body(read_file(RULE_PATH), SPELLING_HEADING)
    assert "quotation" in body
    assert "code span" in body
    assert EXEMPTION_HEADING in body
    assert DETECTOR_PATH in body


def test_the_reader_reads_no_line_of_the_module_that_states_the_detection_list() -> None:
    """Bar 5 keeps this module, so a sweep never empties the list that detects a spelling."""
    assert failures(DETECTOR_PATH, "The behaviour stands.\n", (), {}) == []


def test_the_reader_keeps_a_span_that_stands_inside_a_longer_name() -> None:
    """A case name holds `BehaviourRules` as one word, and the reader keeps the whole name."""
    spans = (ExemptSpan("BehaviourRules", "tests/*.py"),)
    line = "class TestTheBehaviourRulesNameOneCommand:\n"
    assert failures("tests/test_made_up.py", line, spans, {}) == []


def test_the_reader_keeps_a_span_an_upper_case_name_holds() -> None:
    """A constant name holds `neighbour` in upper case, and the reader keeps that name."""
    spans = (ExemptSpan("neighbour", "tests/state_readers.py"),)
    assert failures("tests/state_readers.py", 'NEIGHBOUR_CLIENT = "1"\n', spans, {}) == []


def test_the_reader_reports_a_british_spelling_of_a_page_it_writes() -> None:
    """A page that holds `behaviour` outside every bar fails, so the reader refuses one."""
    found = failures("docs/made-up.md", "The processor states the behaviour.\n", (), {})
    assert [failure.word for failure in found] == ["behaviour"]
    assert found[0].us_form == "behavior"


def test_the_reader_reads_no_word_inside_a_code_span() -> None:
    """Bar 2 keeps a code span, so a British spelling inside backticks reaches no case."""
    assert failures("docs/made-up.md", "The name `behaviour_rules` reads it.\n", (), {}) == []


def test_the_reader_reads_no_word_of_a_quotation() -> None:
    """Bar 1 keeps a quotation, so a British spelling inside one reaches no case."""
    assert failures("docs/made-up.md", "> The reference keeps the behaviour.\n", (), {}) == []


def test_the_reader_reads_no_line_of_the_exempt_region_of_a_record() -> None:
    """Bar 3 keeps the two records, so the exempt region of one reaches no case."""
    page = "# Page\n\nThe behaviour stands.\n\n## Changelog\n\n| 1 | the behaviour |\n"
    found = failures("docs/specs/spec.md", page, (), {"docs/specs/spec.md": "## Changelog"})
    assert [failure.line for failure in found] == [3]


def test_the_reader_reads_no_line_of_a_record_that_names_no_region() -> None:
    """A record the exemption names with no heading exempts every line of the file."""
    assert failures("CHANGELOG.md", "The behaviour stands.\n", (), {"CHANGELOG.md": ""}) == []


def test_the_reader_keeps_a_span_the_rule_file_names_for_that_path() -> None:
    """Bar 4 keeps one span in one file, and it keeps that span in no other file."""
    spans = (ExemptSpan("Behaviour rules", "docs/specs/features/*.md"),)
    page = "The Behaviour rules state it.\n"
    assert failures("docs/specs/features/00-foundation.md", page, spans, {}) == []
    assert len(failures("docs/usage.md", page, spans, {})) == 1


def test_the_reader_reads_a_word_that_ends_with_a_stop_word_as_the_us_form() -> None:
    """A word that ends with `raise` or `promise` carries the US spelling already."""
    assert us_form("raises") == ""
    assert us_form("assertraises") == ""
    assert us_form("otherwise") == ""
    assert us_form("promising") == ""
    assert us_form("analyses") == ""


def test_the_reader_reads_the_suffix_classes_as_british() -> None:
    """A word that ends in `ise`, `isation` or `lyse` carries the British spelling."""
    assert us_form("recognise") == "recognize"
    assert us_form("normalisation") == "normalization"
    assert us_form("synchronised") == "synchronized"
    assert us_form("analyse") == "analyze"


def test_the_reader_keeps_the_us_word_that_holds_a_guarded_span() -> None:
    """`fulfill` holds `fulfil` and `programmer` holds `programme`, and both stay."""
    assert us_form("fulfil") == "fulfill"
    assert us_form("fulfill") == ""
    assert us_form("programme") == "program"
    assert us_form("programmer") == ""
