"""Tests that every document states the count of FoxIO methods this project implements.

#387 found documents that state ten. **The number is eleven.** `JA4LFingerprinter` writes
`JA4L-C=` for JA4L and `JA4L-S=` for JA4LS, so ten fingerprinter classes carry eleven
methods, and a count of classes read as a count of methods reads one short.

**A corrected number goes stale the next time the method set moves, and a reader catches
nothing.** Each case here therefore reads the count out of `ja4plus` and compares each
document against it. A case that restated eleven would pass on a document that
contradicts the package.

## The two readings, and why the file holds both

`stated_counts` reads a claim about the count this project implements, in any of three
word orders. It answers "does the document state the right number".

`class_counts_of_methods` reads the count of fingerprinter classes applied to the word
`method`. It answers "does the document call the class count a count of methods", which is
the sentence shape that produced #387. **The forbidden word is not the literal `ten`.** It
is the count of classes `__all__` names, so the case stops forbidding the word on the day
the two counts agree.

## What a case here does not read

**A dated record of a past measurement is quoted, not rewritten.** `CHANGELOG.md` records
one past round in every entry, and the `## Changelog` and `## Risks & open questions`
sections of `docs/specs/spec.md` each record a state of the project at the time of
writing. Round 136 records the superseded count in its own words, and round 139 records the
measurement. `readable_text` cuts those three, so a correction here destroys no record.

**A count of the ten things the processor drives is a different count, and it stands.**
`ProcessorStats.method` names one of ten, `ja4plus/processor.py` calls the field `method`,
and `docs/api_reference.md` counts them. The prose of this repair therefore counts values
and fingerprinters where it counted methods, matching the `FingerprintResult.type`
docstring that round 139 wrote.

**A case here reads the comments and the docstrings of every Python file under `tests/`,
and #450 widened the corpus to them.** `python_prose` extracts that prose before `_unquoted`
runs. **A docstring of one line sits inside quotation marks.** `_unquoted` therefore drops
the whole of it, and a search of the raw source reads nothing in it. Three of the ten places
#450 repaired hold that shape. A case fixture stays out of reach, because it is a string
literal and no docstring.

**The Python files under `ja4plus/` reach no case here.** They hold eight more places, and
#484 owns them. `ja4plus/watch.py` holds four that #450 repaired under the ruling on its
own issue thread.

## Where the document set comes from

**The reader asks git for the tracked Markdown pages, and it walks no directory.** The
agent harness places a worker worktree at `.claude/worktrees/agent-<id>`, and that worktree
is a whole checkout of the repository. A walk of `.claude/` therefore read the documents of
every live worker, and the collected case count measured the host rather than the commit.
#473 records the measurement, and `FR-documentation-16` states the rule.

These cases read prose and the public interface of `ja4plus`. They produce no fingerprint
and they open no capture socket.
"""

import ast
import inspect
import io
import re
import shutil
import subprocess
import tempfile
import tokenize
from pathlib import Path
from typing import Dict, FrozenSet, List, Tuple

import pytest

import ja4plus
from ja4plus import __all__ as PUBLIC_NAMES

from tests.test_documentation_image_count import FOXIO_METHODS
from tests.test_readme_contracts import COUNT_WORDS, DECLINED_METHOD

REPO_ROOT = Path(__file__).resolve().parent.parent

# The directory the agent harness gives a worker. A worktree there is a whole checkout of
# the repository, so a walk of `.claude/` reads the documents of every live worker.
WORKTREE_ROOT = REPO_ROOT / ".claude" / "worktrees"

# The name prefix of the directory one case writes below `.claude/worktrees/`. The prefix
# names the issue, so a reader who meets the directory after a killed run knows its owner.
WORKTREE_PREFIX = "issue-473-"

# The text of the page one case writes below `.claude/worktrees/`. The page states the
# superseded count, so a reader that names it turns two parametrized cases red.
WORKTREE_PAGE = "This project implements ten of the twelve FoxIO methods.\n"

# The git pathspec that names every tracked Markdown page of the repository. **In a
# default git pathspec `*` crosses `/`**, so this one term reaches every depth, and its
# plain reading equals what it matches. `.claude/rules/conformance.md` states the rule and
# `FR-pre-release-validation-16` records the reading that #436 repaired. **Never write
# `**` here**: git reads `**` as one or more directories, so it drops every root page.
MARKDOWN_PATHSPEC = "*.md"

# The least count of documents a reader may name. **An aggregate over an empty set
# passes**, so a pathspec that names nothing would report a green result for every case
# here. The floor turns that state into a failure where the corpus is read.
DOCUMENT_FLOOR = 1

# One document of each depth the corpus reaches, and one of each root it covers. **A
# pathspec whose `*` stops at a separator names one depth alone**, and a pathspec of one
# directory names one root alone. Either mistake drops a document of this set, so a case
# reads the set rather than a count a writer transcribed.
ANCHOR_DOCUMENTS = (
    "README.md",
    "CLAUDE.md",
    "docs/usage.md",
    "docs/specs/spec.md",
    "docs/specs/features/11-pre-release-validation.md",
    ".claude/rules/ste.md",
    "tests/fuzz/README.md",
    "docs/specs/spec.html",
    "mkdocs.yml",
)

# A pathspec that names a Markdown page of one depth of one directory. A case reads it to
# prove that `ANCHOR_DOCUMENTS` fails a reader which drops a depth or a root.
ONE_DEPTH_PATHSPEC = ":(glob)docs/*.md"

# The name prefix of a one-shot generator of the public interface. The rest of the name is
# the method it writes, in lowercase.
GENERATOR_PREFIX = "generate_"

# The name suffix of a fingerprinter class of the public interface.
CLASS_SUFFIX = "Fingerprinter"

# A generator that writes more than one FoxIO method, and the value prefix that names each
# method beyond the one its own name holds. FoxIO publishes JA4L and JA4LS as two methods
# and `generate_ja4l` writes both, so a count of generators reads one short. **That is the
# whole cause of #387.** A case reads the prefix out of the module source. A change that
# removes the emitter drops JA4LS from the count, and every document that states eleven
# then fails.
SHARED_METHODS: Dict[str, Dict[str, str]] = {"generate_ja4l": {"JA4LS": "JA4L-S="}}

# A line that returns a value. `emitter_lines` reads these lines alone.
#
# **Warning: a search of the whole module source passes on a module that emits nothing.**
# The docstring of `ja4plus/fingerprinters/ja4l.py:6` states the format `JA4L-S=` in prose,
# so a substring search over the module reports the prefix even where every emitter is
# gone. The first form of this reader did that, and it would have read eleven methods out
# of a package that writes ten.
RETURN_LINE = re.compile(r"^\s*return\b")

# The count words a document could state for this method set. The reader reads these alone,
# so a third party's count stays out of reach: `docs/specs/foxio/zeek.md` states that the
# Zeek package implements eight methods, and that sentence is true and is not about
# `ja4plus`.
COUNT_PATTERN = "|".join(
    [word for word in COUNT_WORDS.values()] + [str(number) for number in COUNT_WORDS]
)

# The verbs a document uses for the relation between this project and a method. **A reader
# that anchors on `implement` alone passes on "supports ten of them"**, and the review of
# #387 proved it against that sentence.
CLAIM_VERB = (
    r"implement(?:s|ed)?|support(?:s|ed)?|cover(?:s|ed)?"
    r"|build(?:s|t)?|ship(?:s|ped)?|provide(?:s|d)?"
)

# The noun a count of methods qualifies, with the words a document writes before it. **Two
# words of room reach an adjective that a rewording inserts**, because the phrase
# "ten distinct methods" states the same wrong count as "ten methods". Three words of room
# would reach "ten values carry eleven methods", which states the right count.
#
# **Warning: keep each quotation of this comment on one line.** `_unquoted` pairs the
# quotation marks of one line, so a quotation that spans two lines leaves one mark on each
# line and the words between them reach the reader.
METHOD_NOUN = r"(?:[\w'’]+\s+){0,2}(?:JA4\+?\s+|FoxIO\s+)?methods?"

# What follows a count of methods. **A count of another thing follows the same verb**, so
# "implemented ten fingerprinter classes" states a true fact and reaches no pattern here.
COUNT_TAIL = r"(?=\s*(?:of\s+(?:the\s+)?(?:twelve|12)|of\s+them|" + METHOD_NOUN + r"|[.,;:)]|$))"

# A claim about the count of methods this project implements. Each pattern captures the
# count alone, so a sentence that states the published count beside the implemented count
# yields the implemented count and not both. **A fixed sentence passes on a rewording**, so
# the set covers the word orders rather than the sentences the documents hold today.
IMPLEMENTED_COUNT_PATTERNS: Tuple["re.Pattern[str]", ...] = (
    # "implements eleven of them", "supports ten of the twelve", "implemented only ten."
    re.compile(
        r"\b(?:" + CLAIM_VERB + r")\s+(?:only\s+)?(" + COUNT_PATTERN + r")\b" + COUNT_TAIL,
        re.IGNORECASE,
    ),
    # "eleven of the twelve are implemented", "ten of twelve implemented"
    re.compile(
        r"\b("
        + COUNT_PATTERN
        + r")\s+of\s+(?:the\s+)?(?:twelve|12|them)\b[^.]*\b(?:"
        + CLAIM_VERB
        + r")",
        re.IGNORECASE,
    ),
    # "eleven implemented methods", "ten supported methods"
    re.compile(
        r"\b(" + COUNT_PATTERN + r")\s+(?:" + CLAIM_VERB + r")\s+" + METHOD_NOUN,
        re.IGNORECASE,
    ),
)


def class_count_pattern(word: str) -> "re.Pattern[str]":
    """Return the pattern that reads one count word applied to the word `method`.

    The pattern is built by concatenation and not by `str.format`, because `METHOD_NOUN`
    holds the quantifier `{0,2}` and `str.format` reads a brace as a field.

    Args:
        word: The count word of the fingerprinter classes.

    Returns:
        The compiled pattern.
    """
    return re.compile(r"\b" + re.escape(word) + r"\s+" + METHOD_NOUN + r"\b", re.IGNORECASE)


# A passage inside double quotation marks. `class_counts_of_methods` drops one before it
# reads, because a quotation reproduces the words of another document and the writing
# standard forbids a rewrite of it. `docs/specs/features/08-documentation.md` quotes the
# claim "all ten JA4+ methods" that the README carried, and that quotation is the record of
# the defect the epic corrects. **The limit is deliberate and it is a hole**: a document
# that states its own count inside quotation marks reaches no case here.
#
# **Warning: the reader drops a quoted passage one line at a time.** `docs/usage.md` holds
# a quotation mark inside a command, so a search over the whole page pairs one mark with
# another mark 40 lines away and drops every word between them. The first form of this
# reader did exactly that, and it read nothing at all on that page.
QUOTED_PASSAGE = re.compile(r"\"[^\"]*\"")

# The headings of the sections that record a state of the project at the time of writing.
# `readable_text` cuts each one out of `docs/specs/spec.md`.
RECORD_SECTIONS = ("## Risks & open questions", "## Changelog")

# The file that records one past round in every entry.
RECORD_FILE = "CHANGELOG.md"

# The count of lines that hold a number and its reason together. A reader who meets the
# count reads the reason without scrolling, and a bare number invites a recount of the
# classes.
REASON_WINDOW_LINES = 6

# An HTML tag, which the reader drops before it splits `docs/specs/spec.html` into
# sentences. A tag inside a sentence otherwise hides the words on each side of it.
HTML_TAG = re.compile(r"<[^>]+>")

# The end of a sentence. The reader binds a count to the claim of its own sentence, because
# a document states the published count in the sentence next to the implemented count.
SENTENCE_END = re.compile(r"(?<=[.!?])\s+")

# The node kinds that carry a docstring. `ast.get_docstring` accepts these four alone, and
# it raises a `TypeError` on any other node.
DOCUMENTED_NODES = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)


def emitter_lines(name: str) -> List[str]:
    """Return the lines of one generator's module that return a value.

    A docstring of the module states a value format in prose, so a search of the whole
    source reports a prefix that no code writes. The reader therefore reads the return
    lines alone.

    Args:
        name: The name of a generator of the public interface.

    Returns:
        Every line of the module that starts a return statement.
    """
    module = inspect.getmodule(getattr(ja4plus, name))
    assert module is not None, f"{name} belongs to no module"
    return [line for line in inspect.getsource(module).splitlines() if RETURN_LINE.match(line)]


def implemented_methods() -> FrozenSet[str]:
    """Return the FoxIO methods `ja4plus` implements, read out of the package.

    A generator of the public interface names its method, and `SHARED_METHODS` names the
    method a generator writes beside it. The reader confirms the extra method against a
    return line of the module, so a generator that stops writing the prefix drops the
    method.

    Returns:
        The method names, in the spelling `FOXIO_METHODS` holds.
    """
    found = set()
    for name in PUBLIC_NAMES:
        if not name.startswith(GENERATOR_PREFIX):
            continue
        found.add(name[len(GENERATOR_PREFIX) :].upper())
        emitters = emitter_lines(name)
        for method, prefix in SHARED_METHODS.get(name, {}).items():
            if any(prefix in line for line in emitters):
                found.add(method)
    return frozenset(found)


def fingerprinter_classes() -> FrozenSet[str]:
    """Return the fingerprinter classes the public interface names.

    Returns:
        Every name of `__all__` that ends in `Fingerprinter`.
    """
    return frozenset(name for name in PUBLIC_NAMES if name.endswith(CLASS_SUFFIX))


def _plain(text: str) -> str:
    """Return one line of text with no HTML tag and one space between words.

    Args:
        text: The text of one document.

    Returns:
        The text as one line.
    """
    return " ".join(HTML_TAG.sub(" ", text).split())


def _unquoted(text: str) -> str:
    """Return one line of text with every quoted passage of every line dropped.

    The reader drops a quotation one line at a time, because a search over the whole page
    pairs a quotation mark of one line with a quotation mark far below it.

    Args:
        text: The text of one document.

    Returns:
        The text as one line, with no HTML tag and no quoted passage.
    """
    lines = [QUOTED_PASSAGE.sub(" ", line) for line in HTML_TAG.sub(" ", text).splitlines()]
    return " ".join(" ".join(lines).split())


def stated_counts(text: str) -> List[str]:
    """Return every count of implemented methods the text states, in lowercase.

    Args:
        text: The text of one document, or one passage of it.

    Two patterns match one sentence where the claim carries two of the three word orders,
    so the reader returns each count once, in the order the text holds them.

    Returns:
        The count word or digit of each claim, in the order the text holds them.
    """
    found: List[str] = []
    for sentence in SENTENCE_END.split(_plain(text)):
        for pattern in IMPLEMENTED_COUNT_PATTERNS:
            for match in pattern.finditer(sentence):
                count = match.group(1).lower()
                if count not in found:
                    found.append(count)
    return found


def class_counts_of_methods(text: str, word: str) -> List[str]:
    """Return every place the text applies the class count to the word `method`.

    The reader drops a quoted passage first, so a quotation of another document's claim
    reports nothing.

    Args:
        text: The text of one document.
        word: The count word of the fingerprinter classes.

    Returns:
        The matching phrase of each place, in the order the text holds them.
    """
    return [match.group(0) for match in class_count_pattern(word).finditer(_unquoted(text))]


def readable_text(path: Path, text: str) -> str:
    """Return the text of one document with the sections that record a past state removed.

    Args:
        path: The path of the document.
        text: The whole text of the document.

    Returns:
        The text a case reads. `CHANGELOG.md` reads as an empty document, and
        `docs/specs/spec.md` loses the sections `RECORD_SECTIONS` names.
    """
    if path.name == RECORD_FILE:
        return ""
    if path.name != "spec.md":
        return text
    for heading in RECORD_SECTIONS:
        start = text.find(f"\n{heading}")
        if start == -1:
            continue
        end = text.find("\n## ", start + 1)
        text = text[:start] + (text[end:] if end != -1 else "")
    return text


def walked_documents() -> List[Path]:
    """Return the Markdown pages a walk of the four directories finds.

    This reader is the control of `test_the_reader_names_no_markdown_page_of_a_worktree`
    and no parametrized case reads it. A walk of `.claude/` reaches every document of
    every live worker worktree, which is the defect #473 records.

    Returns:
        Every Markdown page below `docs/`, `.claude/` and `tests/`, and every root page.
    """
    found = sorted((REPO_ROOT / "docs").rglob("*.md"))
    found += sorted((REPO_ROOT / ".claude").rglob("*.md"))
    found += sorted((REPO_ROOT / "tests").rglob("*.md"))
    found += sorted(REPO_ROOT.glob("*.md"))
    return found


def tracked_documents(pathspec: str = MARKDOWN_PATHSPEC) -> List[Path]:
    """Return every Markdown page the repository tracks, as an absolute path.

    Args:
        pathspec: The git pathspec that names the pages. A case passes another pathspec to
            measure the floor and the anchor set.

    Returns:
        One path for each tracked page, sorted.

    Raises:
        AssertionError: The pathspec names fewer pages than `DOCUMENT_FLOOR`.
        subprocess.CalledProcessError: The read of git failed.
    """
    listed = subprocess.run(
        ["git", "ls-files", "-z", pathspec],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split("\0")
    found = sorted(REPO_ROOT / name for name in listed if name)
    assert len(found) >= DOCUMENT_FLOOR, (
        f"the pathspec {pathspec!r} names {len(found)} documents, and a reader that names "
        f"fewer than {DOCUMENT_FLOOR} passes every case here over an empty set"
    )
    return found


def documents() -> List[Path]:
    """Return every prose document that could state a count of methods.

    The reader asks git for the tracked pages and it walks no directory. **The harness
    places a worker worktree at `.claude/worktrees/agent-<id>`, and that worktree is a
    whole checkout**, so a walk of `.claude/` reads the documents of every live worker and
    the count of collected cases then measures the host. #473 records the measurement, and
    `tests/mutation_sweep.py` already carries this correction for its module list.

    The corpus holds the Markdown pages under `tests/` as well, because `tests/fuzz/README.md`
    is prose and a count there goes as stale as a count under `docs/`. **It holds no Python
    file.** `python_sources` holds the Python corpus, because a Python file needs a reader
    that extracts its comments and its docstrings first.

    Returns:
        Every tracked Markdown page, the rendered `docs/specs/spec.html`, and `mkdocs.yml`,
        which carries the count in a comment.
    """
    found = tracked_documents()
    found.append(REPO_ROOT / "docs" / "specs" / "spec.html")
    found.append(REPO_ROOT / "mkdocs.yml")
    return [path for path in found if path.is_file()]


def python_prose(text: str) -> str:
    """Return the comments and the docstrings of one Python source, as one text.

    A string literal that is no docstring stays out. A case fixture holds the sentence it
    measures, and a fixture states no claim of this project. **A bare string below a class
    attribute stays out too**, because `ast.get_docstring` reads the first statement of a
    node alone. No file under `tests/` holds such a string today.

    Args:
        text: The whole source of one Python file.

    Returns:
        The text of every comment and of every docstring, joined by one line break.

    Raises:
        SyntaxError: The text parses as no Python module.
    """
    passages = [
        token.string
        for token in tokenize.generate_tokens(io.StringIO(text).readline)
        if token.type == tokenize.COMMENT
    ]
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, DOCUMENTED_NODES):
            document = ast.get_docstring(node)
            if document is not None:
                passages.append(document)
    return "\n".join(passages)


def python_sources() -> List[Path]:
    """Return every Python source a case reads for the class count.

    Returns:
        The Python files under `tests/`, sorted by path.
    """
    return sorted((REPO_ROOT / "tests").rglob("*.py"))


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

PYTHON_SOURCES = python_sources()
PYTHON_IDS = [_name(path) for path in PYTHON_SOURCES]

# The count of Python files the corpus holds at the least. **An aggregate over an empty set
# passes**, so a corpus that read nothing would report a green run over no file at all.
PYTHON_SOURCE_FLOOR = 120

# The documents that state a count of implemented methods today. The reader finds them, so
# a document that gains a count reaches the reason case without an edit here.
COUNTING_DOCUMENTS = [path for path in DOCUMENTS if stated_counts(_read(path))]
COUNTING_IDS = [_name(path) for path in COUNTING_DOCUMENTS]


def test_every_generator_of_the_public_interface_names_a_foxio_method() -> None:
    """Every method the reader derives from `__all__` is a method FoxIO publishes."""
    extra = sorted(implemented_methods() - set(FOXIO_METHODS))
    assert extra == [], f"the reader derives {extra}, which FoxIO does not publish"


def test_the_package_implements_every_foxio_method_but_the_declined_one() -> None:
    """The package implements every FoxIO method except the one it declines."""
    absent = sorted(set(FOXIO_METHODS) - implemented_methods())
    assert absent == [DECLINED_METHOD], (
        f"the package implements every method but {absent}, and it declines {DECLINED_METHOD} alone"
    )


def test_the_shared_generator_carries_the_second_method_of_its_module() -> None:
    """`generate_ja4l` carries JA4LS, because a return line writes the `JA4L-S=` prefix."""
    for name, methods in SHARED_METHODS.items():
        emitters = emitter_lines(name)
        for method, prefix in methods.items():
            assert any(prefix in line for line in emitters), (
                f"no return line of the module of {name} writes {prefix}, so it carries no {method}"
            )
            assert method in implemented_methods(), f"the reader misses {method}"


def test_the_emitter_reader_reads_no_prefix_that_a_docstring_alone_states() -> None:
    """The emitter reader reads a return line and not the prose of the module.

    `ja4plus/fingerprinters/ja4l.py:6` states the format `JA4L-S=` in its docstring, so a
    search of the whole source reports the prefix on a module whose emitters are all gone.
    """
    for name, methods in SHARED_METHODS.items():
        whole = inspect.getsource(inspect.getmodule(getattr(ja4plus, name)))
        for prefix in methods.values():
            emitters = [line for line in emitter_lines(name) if prefix in line]
            others = whole.count(prefix) - len(emitters)
            assert others > 0, (
                f"the module of {name} states {prefix} on a return line alone, so this case "
                "proves nothing and the reader needs another shape"
            )
            assert emitters, f"no return line of the module of {name} writes {prefix}"


def test_the_count_of_methods_is_above_the_count_of_fingerprinter_classes() -> None:
    """The package holds fewer fingerprinter classes than the methods they carry."""
    assert len(fingerprinter_classes()) < len(implemented_methods()), (
        "the two counts agree, so the case that forbids the class count reads nothing"
    )


@pytest.mark.parametrize("path", DOCUMENTS, ids=DOCUMENT_IDS)
def test_every_document_states_the_count_of_methods_the_package_implements(path: Path) -> None:
    """Every claim about the implemented method count states the count of the package."""
    word = COUNT_WORDS[len(implemented_methods())]
    stated = stated_counts(_read(path))
    wrong = sorted({count for count in stated if count != word})
    assert wrong == [], (
        f"{_name(path)} states {wrong} implemented methods, and the package implements "
        f"{len(implemented_methods())}, which reads {word}"
    )


@pytest.mark.parametrize("path", DOCUMENTS, ids=DOCUMENT_IDS)
def test_no_document_states_the_count_of_classes_as_a_count_of_methods(path: Path) -> None:
    """No document applies the count of fingerprinter classes to the word `method`."""
    word = COUNT_WORDS[len(fingerprinter_classes())]
    offenders = sorted(set(class_counts_of_methods(_read(path), word)))
    assert offenders == [], (
        f"{_name(path)} holds {offenders}, and {word} counts the fingerprinter classes "
        f"rather than the methods they carry"
    )


def test_the_python_corpus_holds_the_test_suite() -> None:
    """The Python corpus holds more files than the floor, and it holds this file."""
    assert len(PYTHON_SOURCES) >= PYTHON_SOURCE_FLOOR, (
        f"the corpus holds {len(PYTHON_SOURCES)} Python files, below the floor of "
        f"{PYTHON_SOURCE_FLOOR}, so a case over it proves little"
    )
    assert Path(__file__).resolve() in PYTHON_SOURCES, "the corpus misses this file"


def test_the_python_reader_reads_a_docstring_of_one_line() -> None:
    """The Python reader reads a docstring that sits on one line.

    **A docstring of one line sits inside quotation marks**, so `_unquoted` drops the whole
    of it. A search of the raw source therefore reads nothing in such a docstring. Three of
    the ten places #450 measured hold exactly that shape.
    """
    source = 'def f():\n    """It drops the state of all ten methods."""\n'
    assert class_counts_of_methods(source, "ten") == []
    assert class_counts_of_methods(python_prose(source), "ten") == ["ten methods"]


def test_the_python_reader_reads_a_comment() -> None:
    """The Python reader reads the text of a comment."""
    source = "# The loop reaches ten methods.\nvalue = 1\n"
    assert class_counts_of_methods(python_prose(source), "ten") == ["ten methods"]


def test_the_python_reader_reads_no_string_literal_that_is_no_docstring() -> None:
    """The Python reader reads no case fixture, because a fixture quotes another sentence."""
    source = 'SENTENCES = ("The package provides ten methods.",)\n'
    assert python_prose(source) == ""


@pytest.mark.parametrize("path", PYTHON_SOURCES, ids=PYTHON_IDS)
def test_no_python_file_states_the_count_of_classes_as_a_count_of_methods(path: Path) -> None:
    """No comment and no docstring applies the class count to the word `method`."""
    word = COUNT_WORDS[len(fingerprinter_classes())]
    prose = python_prose(path.read_text(encoding="utf-8"))
    offenders = sorted(set(class_counts_of_methods(prose, word)))
    assert offenders == [], (
        f"{_name(path)} holds {offenders}, and {word} counts the fingerprinter classes "
        f"rather than the methods they carry"
    )


@pytest.mark.parametrize("path", COUNTING_DOCUMENTS, ids=COUNTING_IDS)
def test_every_document_that_states_the_count_states_the_reason_beside_it(path: Path) -> None:
    """A document that states the count names JA4LS within `REASON_WINDOW_LINES` of it."""
    word = COUNT_WORDS[len(implemented_methods())]
    lines = _read(path).splitlines()
    for start in range(len(lines)):
        window = " ".join(lines[start : start + REASON_WINDOW_LINES])
        if re.search(rf"\b{word}\b", window, re.IGNORECASE) and "JA4LS" in window:
            return
    pytest.fail(
        f"{_name(path)} states {word} and names JA4LS nowhere within "
        f"{REASON_WINDOW_LINES} lines of it, so a reader recounts the classes"
    )


# The sentence #387 corrects, and every rewording of it the review of #387 proposed. **A
# reader of a fixed sentence passes on a rewording**, and the first form of this reader read
# nothing in the last five of these.
SUPERSEDED_SENTENCES = (
    "The project implements ten of the twelve, and does not implement JA4TScan.",
    "Ten of the twelve FoxIO methods are implemented here.",
    "The library ships ten implemented methods.",
    "This project supports ten of FoxIO's methods.",
    "The library covers ten of the FoxIO methods, and skips one.",
    "It has ten of twelve implemented.",
    "The package provides ten methods.",
    "This project implements ten distinct methods.",
)

# A sentence that states a true count of something other than a method. **The verb of a
# claim reaches a count of another thing**, so the reader needs the noun as well.
OTHER_COUNTS = (
    "It builds ten fingerprinters, and hands each packet to all of them.",
    "`ja4plus` implements ten fingerprinter classes, and they carry eleven methods.",
    "The processor implements ten distinct output fields.",
    "The Zeek package implements eight methods, and it outranks nothing.",
)


@pytest.mark.parametrize("sentence", SUPERSEDED_SENTENCES)
def test_the_reader_reads_the_superseded_count_of_every_wording(sentence: str) -> None:
    """The reader reads `ten` out of each wording of the superseded claim."""
    assert stated_counts(sentence) == ["ten"], f"the reader reads nothing in {sentence!r}"


def test_the_reader_reads_the_superseded_count_inside_a_paragraph_of_html() -> None:
    """The reader reads a claim that an HTML tag splits."""
    passage = "<li>FoxIO documents twelve and this <strong>project implements ten</strong>.</li>"
    assert stated_counts(passage) == ["ten"]


def test_the_reader_reads_no_count_of_the_methods_foxio_publishes() -> None:
    """The reader reads the implemented count alone from a sentence that states both."""
    sentence = "FoxIO publishes twelve JA4+ methods, and this project implements eleven of them."
    assert stated_counts(sentence) == ["eleven"]


@pytest.mark.parametrize("sentence", OTHER_COUNTS)
def test_the_reader_reads_no_count_of_a_thing_that_is_not_a_method(sentence: str) -> None:
    """The reader reads no count from a sentence that counts something else."""
    assert stated_counts(sentence) == [], f"the reader reads a count in {sentence!r}"


def test_the_class_count_reader_reads_the_word_beside_the_noun() -> None:
    """The class-count reader reads every shape of the count applied to `method`."""
    passage = (
        "One of the ten method names, lowercase. It runs all ten JA4+ methods. "
        "The report covers the ten methods. FoxIO names ten FoxIO methods."
    )
    assert class_counts_of_methods(passage, "ten") == [
        "ten method",
        "ten JA4+ methods",
        "ten methods",
        "ten FoxIO methods",
    ]


def test_the_class_count_reader_reads_no_quotation_of_another_document() -> None:
    """The class-count reader reads no claim that a quotation reproduces."""
    passage = 'The README said the project implements "all ten JA4+ methods".'
    assert class_counts_of_methods(passage, "ten") == []


def test_the_class_count_reader_reads_a_page_that_holds_a_quotation_mark_elsewhere() -> None:
    """The class-count reader reads a claim below a line that holds one quotation mark."""
    passage = "\n".join(
        [
            'Run `ja4plus live --filter "tcp port 443"` to read one port.',
            "A prose line that holds no mark at all.",
            "The eviction drops the state of all ten methods together.",
        ]
    )
    assert class_counts_of_methods(passage, "ten") == ["ten methods"]


def test_the_class_count_reader_reads_no_count_of_values_or_classes() -> None:
    """The class-count reader reads no sentence that counts values or classes."""
    passage = (
        "Ten values carry eleven methods. Ten fingerprinter classes carry eleven methods. "
        "The `--types` option accepts ten tokens."
    )
    assert class_counts_of_methods(passage, "ten") == []


# A heading of the top level of one Markdown page.
SECTION_HEADING = re.compile(r"^## .*$", re.MULTILINE)


def test_the_reader_reads_no_section_that_records_a_past_state() -> None:
    """`readable_text` cuts the recording sections of `docs/specs/spec.md`."""
    specification = REPO_ROOT / "docs" / "specs" / "spec.md"
    whole = specification.read_text(encoding="utf-8")
    readable = readable_text(specification, whole)
    for heading in RECORD_SECTIONS:
        assert heading in whole, f"the specification holds no {heading!r} section"
        assert heading not in readable, f"{heading!r} reaches a case that reads prose"
    assert "## Overview" in readable, "the reader cut the section that states the count"


def test_the_reader_cuts_the_two_recording_sections_and_no_other() -> None:
    """`readable_text` removes two sections of the specification and keeps every other.

    **The reader cuts one section, and the cut moves every index below it.** A reader that
    read the second heading before the first cut would remove the wrong span, and the case
    above passes on such a reader because both headings are absent either way.
    """
    specification = REPO_ROOT / "docs" / "specs" / "spec.md"
    whole = specification.read_text(encoding="utf-8")
    before = SECTION_HEADING.findall(whole)
    after = SECTION_HEADING.findall(readable_text(specification, whole))
    removed = [heading for heading in before if heading not in after]
    assert removed == list(RECORD_SECTIONS), f"the reader removed {removed}"
    assert "## Issue map" in after, "the reader swallowed the section below the Changelog"


@pytest.mark.parametrize("name", ANCHOR_DOCUMENTS)
def test_the_reader_names_every_anchor_document(name: str) -> None:
    """The reader names each document of `ANCHOR_DOCUMENTS`."""
    assert name in DOCUMENT_IDS, f"the reader misses {name}, which every case here reads"


def test_the_anchor_set_fails_a_reader_that_names_one_depth_of_one_directory() -> None:
    """A pathspec that names one depth of one directory misses an anchor document.

    The case above passes on a reader that drops a root, unless an anchor of another root
    is in the set. This case measures that power, so the anchor set proves what it states.
    """
    listed = {_name(path) for path in tracked_documents(ONE_DEPTH_PATHSPEC)}
    missing = [name for name in ANCHOR_DOCUMENTS if name not in listed]
    assert missing, (
        f"the pathspec {ONE_DEPTH_PATHSPEC} names every anchor document, so the anchor set "
        "measures no reader that drops a depth or a root"
    )


def test_the_reader_fails_where_the_pathspec_names_no_document() -> None:
    """The floor fails the reader that names no document."""
    with pytest.raises(AssertionError, match="names 0 documents"):
        tracked_documents("*.no-such-suffix")


def test_the_pathspec_reaches_every_depth_of_the_corpus() -> None:
    """The pathspec names a Markdown page of each of the four depths the corpus holds.

    A depth set separates the two readings of the pathspec, and a document count does not,
    because a count moves whenever the repository gains a page.
    """
    depths = {_name(path).count("/") for path in tracked_documents()}
    assert depths == {0, 1, 2, 3}, f"the pathspec reaches the depths {sorted(depths)}"


def test_the_reader_names_no_markdown_page_of_a_worktree() -> None:
    """The reader names no page of a worktree, where a walk of the directories names it.

    The case writes one page below `.claude/worktrees/`, and it removes the directory it
    created and no other. A live worker holds its own directory beside it.
    """
    WORKTREE_ROOT.mkdir(parents=True, exist_ok=True)
    created = Path(tempfile.mkdtemp(prefix=WORKTREE_PREFIX, dir=str(WORKTREE_ROOT)))
    try:
        page = created / "docs" / "copy.md"
        page.parent.mkdir(parents=True)
        page.write_text(WORKTREE_PAGE, encoding="utf-8")
        assert page in walked_documents(), (
            "a walk of the four directories misses the page, so this case proves nothing"
        )
        assert page not in documents(), f"{_name(page)} reaches a parametrized case"
    finally:
        shutil.rmtree(created)


def test_the_reader_reads_no_entry_of_the_changelog_file() -> None:
    """`readable_text` reads `CHANGELOG.md` as an empty document."""
    record = REPO_ROOT / RECORD_FILE
    assert record.is_file(), f"the repository holds no {RECORD_FILE}"
    assert readable_text(record, record.read_text(encoding="utf-8")) == ""
