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
docstring that round 139 wrote. Every case under `tests/` keeps its own wording, because
the criteria of #387 name the prose documents alone.

These cases read prose and the public interface of `ja4plus`. They produce no fingerprint
and they open no capture socket.
"""

import inspect
import re
from pathlib import Path
from typing import Dict, FrozenSet, List, Tuple

import pytest

import ja4plus
from ja4plus import __all__ as PUBLIC_NAMES

from tests.test_documentation_image_count import FOXIO_METHODS
from tests.test_readme_contracts import COUNT_WORDS, DECLINED_METHOD

REPO_ROOT = Path(__file__).resolve().parent.parent

# The name prefix of a one-shot generator of the public interface. The rest of the name is
# the method it writes, in lowercase.
GENERATOR_PREFIX = "generate_"

# The name suffix of a fingerprinter class of the public interface.
CLASS_SUFFIX = "Fingerprinter"

# A generator that writes more than one FoxIO method, and the value prefix that names each
# method beyond the one its own name holds. FoxIO publishes JA4L and JA4LS as two methods
# and `generate_ja4l` writes both, so a count of generators reads one short. **That is the
# whole cause of #387.** A case reads the prefix out of the module source, so removing the
# emitter drops JA4LS from the count and every document that states eleven then fails.
SHARED_METHODS: Dict[str, Dict[str, str]] = {"generate_ja4l": {"JA4LS": "JA4L-S="}}

# The count words a document could state for this method set. The reader reads these alone,
# so a third party's count stays out of reach: `docs/specs/foxio/zeek.md` states that the
# Zeek package implements eight methods, and that sentence is true and is not about
# `ja4plus`.
COUNT_PATTERN = "|".join(
    [word for word in COUNT_WORDS.values()] + [str(number) for number in COUNT_WORDS]
)

# A claim about the count of methods this project implements. Each pattern captures the
# count alone, so a sentence that states the published count beside the implemented count
# yields the implemented count and not both. **A fixed sentence passes on a rewording**, so
# the set covers the three word orders rather than the three sentences the documents hold.
IMPLEMENTED_COUNT_PATTERNS: Tuple["re.Pattern[str]", ...] = (
    # "implements eleven of them", "implements ten of the twelve", "implemented only ten"
    re.compile(r"\bimplement(?:s|ed)?\s+(?:only\s+)?(" + COUNT_PATTERN + r")\b", re.IGNORECASE),
    # "eleven of the twelve are implemented", "eleven of them this project implements"
    re.compile(
        r"\b(" + COUNT_PATTERN + r")\s+of\s+(?:the\s+twelve|them)\b[^.]*\bimplement",
        re.IGNORECASE,
    ),
    # "eleven implemented methods"
    re.compile(r"\b(" + COUNT_PATTERN + r")\s+implemented\s+method", re.IGNORECASE),
)

# The count of fingerprinter classes applied to the word `method`. `JA4+` and `FoxIO` reach
# the pattern because a document writes both between the count and the noun.
CLASS_COUNT_OF_METHODS = r"\b{word}\s+(?:JA4\+?\s+|FoxIO\s+)?methods?\b"

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


def implemented_methods() -> FrozenSet[str]:
    """Return the FoxIO methods `ja4plus` implements, read out of the package.

    A generator of the public interface names its method, and `SHARED_METHODS` names the
    method a generator writes beside it. The reader confirms the extra method against the
    value prefix in the module source, so a generator that stops writing the prefix drops
    the method.

    Returns:
        The method names, in the spelling `FOXIO_METHODS` holds.
    """
    found = set()
    for name in PUBLIC_NAMES:
        if not name.startswith(GENERATOR_PREFIX):
            continue
        generator = getattr(ja4plus, name)
        found.add(name[len(GENERATOR_PREFIX) :].upper())
        module = inspect.getmodule(generator)
        assert module is not None, f"{name} belongs to no module"
        source = inspect.getsource(module)
        for method, prefix in SHARED_METHODS.get(name, {}).items():
            if prefix in source:
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

    Args:
        text: The text of one document.
        word: The count word of the fingerprinter classes.

    Returns:
        The matching phrase of each place, in the order the text holds them.
    """
    pattern = re.compile(CLASS_COUNT_OF_METHODS.format(word=word), re.IGNORECASE)
    return [match.group(0) for match in pattern.finditer(_plain(text))]


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


def documents() -> List[Path]:
    """Return every prose document that could state a count of methods.

    Returns:
        The Markdown pages under `docs/` and `.claude/`, the root Markdown pages, the
        rendered `docs/specs/spec.html`, and `mkdocs.yml`, which carries the count in a
        comment.
    """
    found = sorted((REPO_ROOT / "docs").rglob("*.md"))
    found += sorted((REPO_ROOT / ".claude").rglob("*.md"))
    found += sorted(REPO_ROOT.glob("*.md"))
    found.append(REPO_ROOT / "docs" / "specs" / "spec.html")
    found.append(REPO_ROOT / "mkdocs.yml")
    return [path for path in found if path.is_file()]


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
        f"the package implements every method but {absent}, and it declines "
        f"{DECLINED_METHOD} alone"
    )


def test_the_shared_generator_carries_the_second_method_of_its_module() -> None:
    """`generate_ja4l` carries JA4LS, because its module writes the `JA4L-S=` prefix."""
    for name, methods in SHARED_METHODS.items():
        source = inspect.getsource(inspect.getmodule(getattr(ja4plus, name)))
        for method, prefix in methods.items():
            assert prefix in source, f"{name} writes no {prefix} and carries no {method}"
            assert method in implemented_methods(), f"the reader misses {method}"


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


# The sentence #387 corrects, and two rewordings of it. A reader of a fixed sentence passes
# on a rewording, so the cases below read all three.
SUPERSEDED_SENTENCES = (
    "The project implements ten of the twelve, and does not implement JA4TScan.",
    "Ten of the twelve FoxIO methods are implemented here.",
    "The library ships ten implemented methods.",
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


def test_the_reader_reads_no_count_of_fingerprinter_classes() -> None:
    """The reader reads no count from a sentence that counts fingerprinter classes."""
    sentence = "It builds ten fingerprinters, and hands each packet to all of them."
    assert stated_counts(sentence) == []


def test_the_reader_reads_no_count_a_third_party_states() -> None:
    """The reader reads no count from a sentence about another implementation."""
    sentence = "The Zeek package implements eight methods, and it outranks nothing."
    assert stated_counts(sentence) == []


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


def test_the_class_count_reader_reads_no_count_of_values_or_classes() -> None:
    """The class-count reader reads no sentence that counts values or classes."""
    passage = (
        "Ten values carry eleven methods. Ten fingerprinter classes carry eleven methods. "
        "The `--types` option accepts ten tokens."
    )
    assert class_counts_of_methods(passage, "ten") == []


def test_the_reader_reads_no_section_that_records_a_past_state() -> None:
    """`readable_text` cuts the recording sections of `docs/specs/spec.md`."""
    specification = REPO_ROOT / "docs" / "specs" / "spec.md"
    whole = specification.read_text(encoding="utf-8")
    readable = readable_text(specification, whole)
    for heading in RECORD_SECTIONS:
        assert heading in whole, f"the specification holds no {heading!r} section"
        assert heading not in readable, f"{heading!r} reaches a case that reads prose"
    assert "## Overview" in readable, "the reader cut the section that states the count"


def test_the_reader_reads_no_entry_of_the_changelog_file() -> None:
    """`readable_text` reads `CHANGELOG.md` as an empty document."""
    record = REPO_ROOT / RECORD_FILE
    assert record.is_file(), f"the repository holds no {RECORD_FILE}"
    assert readable_text(record, record.read_text(encoding="utf-8")) == ""
