"""Tests that every statement of the supported interpreter set names the same versions.

**Four records state which Python versions this project supports, and a change that
reaches three of them leaves a reader with a wrong page.** #575 measured the set on
2026-08-10.

1. `requires-python` of `pyproject.toml`, which states the floor a package index enforces.
2. The `Programming Language :: Python :: 3.x` classifiers of `pyproject.toml`.
3. The `python-version` matrix of `.github/workflows/test.yml`, which states what runs.
4. `FR-foundation-12` and `FR-foundation-13` of
   `docs/specs/features/00-foundation.md`, which state the requirement a reader builds to.

`target-version` of `[tool.ruff]` is a fifth statement of the floor. `ruff` reads it to
decide which syntax the lint rules accept, so a stale value accepts syntax no supported
interpreter runs.

## Why a case reads each record apart

**A reader that finds no interpreter reports agreement over an empty set.** #575 wrote
`test_every_reader_finds_an_interpreter` first for that reason. Each reader states a floor
of its own, so a pattern that stops matching fails a case rather than passing every
comparison below it.

## How to prove that these cases bite

`disagreements` takes the three statements as values, so a case drives it over text this
file holds. The section `The reader, driven in both directions` moves one statement alone
and requires a report. #575 also moved `requires-python` alone in the working tree, ran
this file, and restored the file. The run reported:

```
AssertionError: the records of the interpreter set part: ['pyproject.toml requires
>=3.10 and the matrix runs 3.9 through 3.13']
```

## What these cases cannot test

**A case here reads what the records state, and it runs no other interpreter.** It proves
no release installs on 3.10, and it proves no case of this suite passes there. The test
matrix takes that measurement.

These cases read prose and configuration. They import nothing from `ja4plus` and they
produce no fingerprint.
"""

from io import StringIO
from pathlib import Path
import re
import subprocess
import tokenize
from typing import List, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

PROJECT_FILE = REPO_ROOT / "pyproject.toml"

TEST_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "test.yml"

FOUNDATION_PAGE = REPO_ROOT / "docs" / "specs" / "features" / "00-foundation.md"

# One version, as `3.10`. A record states the minor line and never the patch level.
VERSION = Tuple[int, int]

# `requires-python` states the floor of the package, as `requires-python = ">=3.10"`.
REQUIRES_PYTHON = re.compile(r'^requires-python\s*=\s*">=(\d+)\.(\d+)"', re.MULTILINE)

# One interpreter classifier, as `"Programming Language :: Python :: 3.10",`. The bare
# `Programming Language :: Python :: 3` classifier names the major line and no minor one,
# so the pattern requires both numbers.
CLASSIFIER = re.compile(r'"Programming Language :: Python :: (\d+)\.(\d+)"')

# The matrix of the `test` job, as `python-version: ["3.10", "3.11", "3.12", "3.13"]`. The
# `include` block of that job adds the macOS entry, which a second pattern reads.
MATRIX_LINE = re.compile(r"^\s*python-version:\s*\[([^\]]*)\]\s*$", re.MULTILINE)

# One quoted version of a matrix list, as `"3.10"`.
QUOTED_VERSION = re.compile(r'"(\d+)\.(\d+)"')

# The macOS entry of the `include` block, which names one operating system and one version.
MACOS_ENTRY = re.compile(r'-\s*os:\s*macos-latest\s*\n\s*python-version:\s*"(\d+)\.(\d+)"')

# `target-version` of `[tool.ruff]`, as `target-version = "py310"`. `ruff` spells a version
# without the separator, so the pattern reads the major digit and the rest.
RUFF_TARGET = re.compile(r'^target-version\s*=\s*"py(\d)(\d+)"', re.MULTILINE)

# `FR-foundation-12` states the floor, as ``requires-python = ">=3.10"``.
FOUNDATION_FLOOR = re.compile(
    r"FR-foundation-12 — `pyproject\.toml` declares "
    r'`requires-python = ">=(\d+)\.(\d+)"`'
)

# `FR-foundation-13` states the range, as `The test matrix runs Python 3.10 through 3.13.`
FOUNDATION_RANGE = re.compile(
    r"FR-foundation-13 — The test matrix runs Python (\d+)\.(\d+) through (\d+)\.(\d+)\."
)

# The floor of each reader. A reader that stops matching returns fewer entries than this,
# and a comparison over an empty set reports agreement.
MINIMUM_CLASSIFIERS = 2

MINIMUM_MATRIX_VERSIONS = 2

# The git pathspec that names every tracked Python source of the package. **In a default
# git pathspec `*` crosses `/`**, so this one term reaches `ja4plus/utils/` as well.
PACKAGE_PATHSPEC = "ja4plus/*.py"

# The least count of package sources the corpus holds. **A sweep over an empty set passes**,
# so a read of git that returns nothing fails here rather than reports agreement. A read of
# 2026-08-10 reports 31 sources.
MINIMUM_PACKAGE_SOURCES = 20

# One interpreter a comment names, as `Python 3.9`. The pattern reads the lower-case form
# beside the upper-case one, because a sentence names the interpreter in either position.
COMMENT_INTERPRETER = re.compile(r"[Pp]ython (\d+)\.(\d+)")


def _versions(pattern: "re.Pattern[str]", text: str) -> List[VERSION]:
    """Return every version one pattern reads from one text, in the order it holds them.

    Args:
        pattern: A pattern whose first two groups are the major and the minor number.
        text: The record to read.

    Returns:
        One entry for each match.
    """
    return [(int(match.group(1)), int(match.group(2))) for match in pattern.finditer(text)]


def spell(version: VERSION) -> str:
    """Return one version in the form every record spells it.

    Args:
        version: The major and the minor number.

    Returns:
        The version, as `3.10`.
    """
    return f"{version[0]}.{version[1]}"


def floor_of(text: str) -> VERSION:
    """Return the package floor that one `pyproject.toml` text states.

    Args:
        text: The file text.

    Returns:
        The major and the minor number of `requires-python`.

    Raises:
        AssertionError: The text states no `requires-python` floor.
    """
    match = REQUIRES_PYTHON.search(text)
    assert match is not None, "the text states no `requires-python` floor"
    return (int(match.group(1)), int(match.group(2)))


def classifiers_of(text: str) -> List[VERSION]:
    """Return every interpreter one `pyproject.toml` text classifies as supported.

    Args:
        text: The file text.

    Returns:
        One entry for each `Programming Language :: Python :: 3.x` classifier.
    """
    return _versions(CLASSIFIER, text)


def matrix_of(text: str) -> List[VERSION]:
    """Return every interpreter the matrix of one workflow text runs on Linux.

    The `include` block adds the macOS entry, and `macos_of` reads that one.

    Args:
        text: The file text.

    Returns:
        One entry for each version of the first `python-version` list.

    Raises:
        AssertionError: The text holds no `python-version` list.
    """
    match = MATRIX_LINE.search(text)
    assert match is not None, "the text holds no `python-version` list"
    return _versions(QUOTED_VERSION, match.group(1))


def macos_of(text: str) -> VERSION:
    """Return the interpreter the macOS entry of one workflow text names.

    Args:
        text: The file text.

    Returns:
        The major and the minor number of the macOS entry.

    Raises:
        AssertionError: The text holds no macOS entry.
    """
    match = MACOS_ENTRY.search(text)
    assert match is not None, "the text holds no `macos-latest` entry"
    return (int(match.group(1)), int(match.group(2)))


def ruff_target_of(text: str) -> VERSION:
    """Return the interpreter `[tool.ruff]` of one `pyproject.toml` text targets.

    Args:
        text: The file text.

    Returns:
        The major and the minor number of `target-version`.

    Raises:
        AssertionError: The text states no `target-version`.
    """
    match = RUFF_TARGET.search(text)
    assert match is not None, "the text states no `target-version`"
    return (int(match.group(1)), int(match.group(2)))


def disagreements(floor: VERSION, matrix: List[VERSION], classifiers: List[VERSION]) -> List[str]:
    """Return every way the three statements of the interpreter set part.

    Args:
        floor: The `requires-python` floor.
        matrix: The interpreters the test matrix runs on Linux.
        classifiers: The interpreters the classifier list names.

    Returns:
        One line for each disagreement, which is empty where the three agree.
    """
    found: List[str] = []
    if not matrix:
        found.append("the matrix runs no interpreter")
        return found
    lowest = min(matrix)
    if floor != lowest:
        found.append(
            f"pyproject.toml requires >={spell(floor)} and the matrix runs "
            f"{spell(lowest)} through {spell(max(matrix))}"
        )
    unclassified = [version for version in sorted(matrix) if version not in classifiers]
    if unclassified:
        found.append(
            "the matrix runs these interpreters and no classifier names them: "
            f"{[spell(version) for version in unclassified]}"
        )
    unrun = [version for version in sorted(classifiers) if version not in matrix]
    if unrun:
        found.append(
            "the classifier list names these interpreters and the matrix runs none of "
            f"them: {[spell(version) for version in unrun]}"
        )
    return found


def _project_text() -> str:
    """Return the text of `pyproject.toml`.

    Returns:
        The file text.
    """
    return PROJECT_FILE.read_text(encoding="utf-8")


def _workflow_text() -> str:
    """Return the text of `.github/workflows/test.yml`.

    Returns:
        The file text.
    """
    return TEST_WORKFLOW.read_text(encoding="utf-8")


def package_sources(pathspec: str = PACKAGE_PATHSPEC) -> List[str]:
    """Return every tracked Python source of the package, relative to the repository root.

    **The reader asks git for the files and it walks no directory.** The agent harness
    places a worker worktree at `.claude/worktrees/agent-<id>`, and that worktree is a whole
    checkout. A walk would therefore read the sources of every live worker. #473 records the
    measurement.

    Args:
        pathspec: The git pathspec that names the sources. A case passes another pathspec to
            measure the floor.

    Returns:
        One path for each tracked source, sorted.

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


def comments_of(text: str) -> List[str]:
    """Return the text of every comment of one Python source.

    **The reader takes a comment and it takes no docstring.** A docstring of this package
    records a past measurement in some modules, and such a record names the interpreter it
    measured. A comment states the live reason instead.

    Args:
        text: The whole source of one Python file.

    Returns:
        One entry for each comment, in file order.

    Raises:
        tokenize.TokenError: The text tokenizes as no Python module.
    """
    return [
        token.string
        for token in tokenize.generate_tokens(StringIO(text).readline)
        if token.type == tokenize.COMMENT
    ]


def stale_comments(text: str, floor: VERSION) -> List[str]:
    """Return every comment of one source that names an interpreter below the floor.

    Args:
        text: The whole source of one Python file.
        floor: The lowest interpreter the package supports.

    Returns:
        One entry for each comment that names a dropped interpreter, which is empty where
        every comment names a supported one.
    """
    return [
        comment
        for comment in comments_of(text)
        for major, minor in COMMENT_INTERPRETER.findall(comment)
        if (int(major), int(minor)) < floor
    ]


# --- The floor of every reader ----------------------------------------------------------


def test_every_reader_finds_an_interpreter() -> None:
    """Each reader returns a version, so no case below compares two empty sets."""
    project = _project_text()
    workflow = _workflow_text()
    assert len(classifiers_of(project)) >= MINIMUM_CLASSIFIERS, (
        f"the classifier reader found {classifiers_of(project)}, and the floor is "
        f"{MINIMUM_CLASSIFIERS} entries"
    )
    assert len(matrix_of(workflow)) >= MINIMUM_MATRIX_VERSIONS, (
        f"the matrix reader found {matrix_of(workflow)}, and the floor is "
        f"{MINIMUM_MATRIX_VERSIONS} entries"
    )
    assert floor_of(project) >= (3, 0), "the floor reader found no major version"
    assert ruff_target_of(project) >= (3, 0), "the target reader found no major version"
    assert macos_of(workflow) >= (3, 0), "the macOS reader found no major version"


# --- The four records state one interpreter set -------------------------------------------


def test_the_three_configuration_records_state_one_interpreter_set() -> None:
    """`requires-python`, the matrix and the classifier list name the same interpreters."""
    found = disagreements(
        floor_of(_project_text()),
        matrix_of(_workflow_text()),
        classifiers_of(_project_text()),
    )
    assert found == [], f"the records of the interpreter set part: {found}"


def test_the_macos_entry_runs_an_interpreter_of_the_supported_set() -> None:
    """The macOS entry of the matrix names a version the classifier list holds."""
    workflow = _workflow_text()
    entry = macos_of(workflow)
    assert entry in matrix_of(workflow), (
        f"the macOS entry runs Python {spell(entry)}, and the Linux matrix runs "
        f"{[spell(version) for version in matrix_of(workflow)]}"
    )


def test_the_lint_target_names_the_floor_the_package_requires() -> None:
    """`target-version` of `[tool.ruff]` names the interpreter `requires-python` floors.

    `ruff` decides from this value which syntax a lint rule accepts. A stale value accepts
    syntax that the oldest supported interpreter refuses.
    """
    project = _project_text()
    assert ruff_target_of(project) == floor_of(project), (
        f"`[tool.ruff]` targets py{ruff_target_of(project)} and `requires-python` states "
        f">={spell(floor_of(project))}"
    )


def test_the_foundation_page_states_the_floor_the_package_declares() -> None:
    """`FR-foundation-12` states the `requires-python` value `pyproject.toml` holds."""
    page = FOUNDATION_PAGE.read_text(encoding="utf-8")
    match = FOUNDATION_FLOOR.search(page)
    assert match is not None, f"{FOUNDATION_PAGE} states no FR-foundation-12 floor"
    stated = (int(match.group(1)), int(match.group(2)))
    assert stated == floor_of(_project_text()), (
        f"FR-foundation-12 declares >={spell(stated)} and pyproject.toml declares "
        f">={spell(floor_of(_project_text()))}"
    )


def test_the_foundation_page_states_the_range_the_matrix_runs() -> None:
    """`FR-foundation-13` states the lowest and the highest interpreter of the matrix."""
    page = FOUNDATION_PAGE.read_text(encoding="utf-8")
    match = FOUNDATION_RANGE.search(page)
    assert match is not None, f"{FOUNDATION_PAGE} states no FR-foundation-13 range"
    stated = (
        (int(match.group(1)), int(match.group(2))),
        (int(match.group(3)), int(match.group(4))),
    )
    matrix = matrix_of(_workflow_text())
    assert stated == (min(matrix), max(matrix)), (
        f"FR-foundation-13 states {spell(stated[0])} through {spell(stated[1])} and the "
        f"matrix runs {spell(min(matrix))} through {spell(max(matrix))}"
    )


# --- The reader, driven in both directions ------------------------------------------------


AGREEING_SET = ((3, 10), [(3, 10), (3, 11)], [(3, 10), (3, 11)])


def test_the_reader_reports_no_disagreement_where_the_three_records_agree() -> None:
    """The reader returns an empty list where one interpreter set reaches all three."""
    assert disagreements(*AGREEING_SET) == []


def test_the_reader_reports_a_floor_that_the_matrix_leaves_behind() -> None:
    """A floor that moves alone reaches the reader, which is the change #575 made."""
    found = disagreements((3, 10), [(3, 9), (3, 10)], [(3, 9), (3, 10)])
    assert found != []
    assert "the matrix runs 3.9 through 3.10" in found[0]


def test_the_reader_reports_a_matrix_row_that_no_classifier_names() -> None:
    """A matrix that moves alone reaches the reader."""
    found = disagreements((3, 10), [(3, 10), (3, 11)], [(3, 10)])
    assert any("no classifier names them: ['3.11']" in line for line in found)


def test_the_reader_reports_a_classifier_that_the_matrix_never_runs() -> None:
    """A classifier list that moves alone reaches the reader."""
    found = disagreements((3, 10), [(3, 10)], [(3, 10), (3, 9)])
    assert any("the matrix runs none of them: ['3.9']" in line for line in found)


def test_the_reader_reports_a_matrix_that_runs_nothing() -> None:
    """An empty matrix reports a disagreement, and it reports no agreement."""
    assert disagreements((3, 10), [], []) == ["the matrix runs no interpreter"]


# --- The readers, driven over text this file holds ----------------------------------------


def test_the_floor_reader_reads_a_two_digit_minor_version() -> None:
    """The floor reader reads `3.10` as ten and never as one."""
    assert floor_of('requires-python = ">=3.10"\n') == (3, 10)


def test_the_floor_reader_fails_a_text_that_states_no_floor() -> None:
    """A text without `requires-python` fails the reader rather than returning a default."""
    with pytest.raises(AssertionError):
        floor_of('name = "ja4plus"\n')


def test_the_classifier_reader_passes_over_the_major_line_classifier() -> None:
    """`Programming Language :: Python :: 3` names no minor line, so the reader drops it."""
    text = (
        '    "Programming Language :: Python :: 3",\n'
        '    "Programming Language :: Python :: 3.10",\n'
    )
    assert classifiers_of(text) == [(3, 10)]


def test_the_matrix_reader_reads_the_first_list_of_the_workflow() -> None:
    """The reader returns every version of the `python-version` list, in file order."""
    text = '        python-version: ["3.10", "3.11", "3.12", "3.13"]\n'
    assert matrix_of(text) == [(3, 10), (3, 11), (3, 12), (3, 13)]


def test_the_matrix_reader_fails_a_workflow_that_holds_no_list() -> None:
    """A workflow without a `python-version` list fails the reader."""
    with pytest.raises(AssertionError):
        matrix_of("jobs:\n  test:\n")


def test_the_macos_reader_reads_the_entry_of_the_include_block() -> None:
    """The reader returns the version the macOS entry names and no matrix version."""
    text = (
        '        python-version: ["3.10", "3.13"]\n'
        "        include:\n"
        "          - os: macos-latest\n"
        '            python-version: "3.12"\n'
    )
    assert macos_of(text) == (3, 12)


def test_the_lint_target_reader_reads_a_two_digit_minor_version() -> None:
    """The reader reads `py310` as 3.10 and never as 3.1."""
    assert ruff_target_of('target-version = "py310"\n') == (3, 10)


# --- The comments of the package name a supported interpreter ---------------------------


def test_the_source_reader_finds_the_package() -> None:
    """The reader returns the sources of the package, so no sweep below reads nothing."""
    found = package_sources()
    assert len(found) >= MINIMUM_PACKAGE_SOURCES, (
        f"the corpus holds {len(found)} package sources, below the floor of "
        f"{MINIMUM_PACKAGE_SOURCES}, and a sweep over an empty set passes"
    )
    assert "ja4plus/__init__.py" in found, f"the corpus holds no package module: {found[:5]}"


def test_no_comment_of_the_package_names_an_interpreter_the_supported_set_dropped() -> None:
    """No comment under `ja4plus/` states a reason that a dropped interpreter carries.

    A comment states why the code is what it is. 28 sources named Python 3.9 as the reason
    `from __future__ import annotations` stands at the top of the module. #575 removed that
    interpreter from the supported set. **A comment that states a superseded reason is
    a defect**, because a reader takes it for the live reason. #578 repaired the 28 and this
    case holds the repair.

    The floor comes from `requires-python`, so a later drop fails this case and no repair
    leaves the prose of the package behind. The case reads a comment and no docstring.

    **The case reads each source as `utf-8-sig`.** `tokenize` reports a `TokenError` on a
    byte-order mark, so a source that carried one would error here rather than report the
    comments it holds. The self-review of #578 raised that reading.
    """
    floor = floor_of(_project_text())
    offenders = {
        name: stale
        for name in package_sources()
        for stale in [stale_comments((REPO_ROOT / name).read_text(encoding="utf-8-sig"), floor)]
        if stale
    }
    assert offenders == {}, f"these comments name a dropped interpreter: {offenders}"


def test_the_comment_reader_reads_a_comment_and_no_docstring() -> None:
    """A docstring that names a dropped interpreter reaches the reader nowhere."""
    text = '"""Python 3.9 measured this."""\n\nvalue = 1\n'
    assert comments_of(text) == []
    assert stale_comments(text, (3, 10)) == []


def test_the_comment_reader_reports_a_comment_that_names_a_dropped_interpreter() -> None:
    """The comment 28 sources held before #578 reaches the reader."""
    text = "# Python 3.9 is the floor, and it evaluates no annotation.\nvalue = 1\n"
    assert stale_comments(text, (3, 10)) == [
        "# Python 3.9 is the floor, and it evaluates no annotation."
    ]


def test_the_comment_reader_passes_over_a_supported_interpreter() -> None:
    """A comment that names the floor itself is no defect, so the reader does not report it."""
    text = "# Python 3.10 evaluates this annotation.\nvalue = 1\n"
    assert stale_comments(text, (3, 10)) == []


def test_the_comment_reader_reads_a_comment_that_stands_after_a_statement() -> None:
    """A trailing comment carries the same defect, so the reader reads the whole file."""
    text = "value = 1  # Python 3.8 needs this.\n"
    assert stale_comments(text, (3, 10)) == ["# Python 3.8 needs this."]


def test_the_comment_reader_reads_a_two_digit_minor_version() -> None:
    """The reader reads `3.10` as ten, so a comment naming the floor fails no case."""
    text = "# Python 3.10 is the floor.\n"
    assert stale_comments(text, (3, 10)) == []
    assert stale_comments(text, (3, 11)) == ["# Python 3.10 is the floor."]


def test_the_comment_reader_raises_on_a_text_that_tokenizes_as_no_python() -> None:
    """A text the tokenizer refuses raises, so no source passes the sweep unread."""
    with pytest.raises(tokenize.TokenError):
        comments_of("value = (1\n")


def test_the_source_reader_returns_nothing_for_a_pathspec_that_names_no_file() -> None:
    """A pathspec that matches nothing returns an empty list, which the floor case refuses."""
    assert package_sources("ja4plus/*.no-such-suffix") == []
