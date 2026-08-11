"""Tests that the `dev` extra states the shape a recorded ruling chose for every entry.

`FR-foundation-7` and `FR-foundation-8` name `ruff check` and `ruff format --check` as
gates of every pull request. Neither one names a version. `pyproject.toml` declared
`ruff>=0.6`, so `pip` resolved the newest release at the moment of each install, and the
gate read a different tool on two days.

**#297 measured the drift on this repository.** It recorded 58 `F401` findings, 28 files
and 82 `I001` findings against `ruff` 0.14.5, and 54, 27 and 76 against 0.16.2. Every
number differed on an unchanged tree. A gate whose result depends on the day it runs is a
comparison that measures something other than what it names. #378 records the defect and
the ruling.

**The file keeps its name and it now reads the whole extra.** #378 opened it for the lint
pin alone, and #446 widened it rather than opening a second reader over the same list.
`pyproject.toml`, `docs/specs/features/00-foundation.md` and `CHANGELOG.md` each name this
path, so a rename would move three records for no reading a reader gains.

## The two shapes #446 chose

**Four distributions carry an exact version.** `build`, `pytest`, `pytest-cov` and `ruff`
each move the result of a gate when a release changes a rule, and an exact pin makes that
move a commit that shows its own diff.

**`mypy` floats, and that is the opposite reading on purpose.** A pinned type checker
falls behind and holds back the checks a later release adds, so a real type defect
accumulates behind a passing gate. A floating formatter turns a green tree red, which is
noisy and safe. A frozen type checker keeps a red tree green, which is quiet and unsafe.
The user ruled the difference on 2026-08-10.

## What a case here reads

The pin is one entry of the `dev` extra, and `tests/dependency_entries.py` reads it.
**That module is the one reader of a dependency block, and #452 built it.** The reader of
#378 collected every double-quoted substring of the block, so a comment that quotes a
version read as an entry. A comment that quoted `"ruff==0.14.5"` would then have failed a
case here on the wording of a comment. #446 widened that hazard, because every entry now
carries a comment and four of those comments quote a version.

The self-review of #378 found the hazard, and #446 answered it with a second reader inside
this file. **Two readers of one block can disagree**, so #452 removed the second one.
`_dev_lines` and `_dev_entries` below call the shared module and parse nothing of their
own.

**The `dev` extra is the one place a tool reads a version from.** Every job of
`.github/workflows/test.yml` installs the extra, and no workflow names one of these
distributions with a version specifier of its own. #446 deleted the tracked
`requirements.txt`, which stated `pytest-cov>=3.0.0` against the `>=5.0` of
`pyproject.toml`, so one record now holds every version.

**Prose that quotes a pin reaches no case here.** `CHANGELOG.md` and `docs/specs/spec.md`
record the version each round chose, and no tool installs from a record. A case here reads
the files a tool resolves a dependency from, so the candidate set names them.

## What a case here cannot test

**A case here cannot test that a pinned version is the right one.** It holds each pin
against the installed tool and against the workflow set. A maintainer who bumps a number
holds the question of whether the new version reports a finding the old one did not.

**A case here cannot test that a pinned version installs on every interpreter of the test
matrix.** That read needs the package index, and this suite opens no network connection.
#446 took the measurement by hand and `docs/specs/spec.md` records it: `pytest` 9.1.1 and
`build` 1.5.0 each require Python 3.10, and the matrix ran the interpreter that #575
dropped. Each pin therefore named an older release until that round. #576 took the five
pins the drop released, and each entry now names the newest release this project measured.

These cases read prose and configuration. They import nothing from `ja4plus` and they
produce no fingerprint.
"""

from importlib import metadata
from pathlib import Path
import re

import pytest

from tests.dependency_entries import dependency_entries, dependency_lines

REPO_ROOT = Path(__file__).resolve().parent.parent

PYPROJECT = REPO_ROOT / "pyproject.toml"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# The distribution the lint gate runs. `FR-foundation-7` and `FR-foundation-8` name its
# two commands.
LINT_TOOL = "ruff"

# The distributions the `dev` extra pins to one exact version, `FR-foundation-8b` and
# `FR-foundation-8d`. A release of any one of them moves the result of a gate with no
# commit.
PINNED = ("build", "pytest", "pytest-cov", "twine", LINT_TOOL)

# The distributions the `dev` extra leaves floating, `FR-foundation-8e`. #446 records the
# reading that separates a type checker from the four above.
FLOATING = ("mypy",)

# The `dev` extra holds at least this many entries. **An aggregate over an empty set
# passes**, so a reader that collects too few entries fails here rather than reporting no
# offender. `dependency_entries` refuses a block of no entry, and this floor holds the
# count that the recorded rulings of #378 and #446 cover.
MINIMUM_DEV_ENTRIES = 6

# The line that opens the development extra of `pyproject.toml`.
DEV_EXTRA = "dev = ["

# The issue whose comment each entry cites, so a reader who asks why reaches the
# measurement. #378 chose the exact pin for `ruff` and #446 chose the shape of the rest.
SHAPE_ISSUE = {
    LINT_TOOL: "#378",
    "build": "#446",
    "mypy": "#446",
    "pytest": "#446",
    "pytest-cov": "#446",
    "twine": "#68",
}

# The second dependency record #446 deleted. It stated `pytest-cov>=3.0.0` against the
# `>=5.0` of `pyproject.toml`, and a contributor who installed from it got an environment
# the coverage gate cannot read.
DELETED_RECORD = "requirements.txt"

# The records that hold the history of this repository. Each one quotes the deleted file
# inside a row that states what an earlier round read, and no reader installs from a
# record.
HISTORY_FILES = ("CHANGELOG.md", "docs/specs/spec.md")

# A reader follows at least this many instruction files. The floor holds the same rule as
# `MINIMUM_DEV_ENTRIES`.
MINIMUM_INSTRUCTION_FILES = 10


def _exact_pin(distribution: str) -> re.Pattern[str]:
    """Return the pattern that matches an exact pin of one distribution.

    An exact pin reads as `ruff==0.16.2`. The version carries at least a major and a minor
    part, so `ruff==0` fails the pattern. The trailing group accepts a pre-release or a
    local version, as `0.17.0rc1` or `0.16.2+local`, because PEP 440 permits both and a pin
    that names one is still exact.

    Args:
        distribution: The distribution name, as `pytest-cov`.

    Returns:
        The compiled pattern. Group 1 holds the version.
    """
    return re.compile(rf"^{re.escape(distribution)}==(\d+\.\d+(?:\.\d+)*[A-Za-z0-9.+!-]*)$")


def _any_specifier(distribution: str) -> re.Pattern[str]:
    """Return the pattern that matches a version specifier of any shape.

    The pattern reads `ruff>=0.6`, `ruff>0.6`, `ruff===0.16.2` and `ruff[extra]==1.0`. A
    second file that carries one resolves a version of its own, which is the state the pin
    removes.

    **The one-character operators carry this pattern, and the first form omitted them.** It
    read `[=<>!~]=` and demanded a trailing `=`, so it missed `ruff>0.6`, which is the shape
    of the specifier the lint pin replaced. The optional extras group closes the second
    miss. The self-review of #378 found both.

    Args:
        distribution: The distribution name, as `pytest-cov`.

    Returns:
        The compiled pattern.
    """
    return re.compile(rf"\b{re.escape(distribution)}(?:\[[^\]]*\])?\s*(?:[=!~<>]=|===|[<>])\s*\d")


# The files a tool resolves a dependency from. `.github/workflows/` holds every job, and
# the four names below are the dependency files this project would carry if it used them.
# A name that matches no file reaches no case, so the set states the search rather than
# the state of the tree.
RESOLVED_FILES = (
    "requirements.txt",
    "requirements-dev.txt",
    "tox.ini",
    ".pre-commit-config.yaml",
)


def _dev_lines() -> list[str]:
    """Return every line inside the brackets of the `dev` extra of `pyproject.toml`.

    Returns:
        The stripped lines, comment lines included, in file order.

    Raises:
        AssertionError: `pyproject.toml` holds no `dev` extra, or the block is not closed.
    """
    return dependency_lines(PYPROJECT.read_text(encoding="utf-8"), DEV_EXTRA)


def _dev_entries() -> list[str]:
    """Return every dependency entry of the `dev` extra of `pyproject.toml`.

    A comment reaches no entry. The `dev` extra states the reason for every one of its
    entries in a comment, and a comment that quotes a version is prose rather than a
    dependency.

    Returns:
        The entries, without their quotes, in file order.

    Raises:
        AssertionError: `pyproject.toml` holds no `dev` extra, the block is not closed, or
            the extra holds no entry.
    """
    return dependency_entries(PYPROJECT.read_text(encoding="utf-8"), DEV_EXTRA)


def _distribution(entry: str) -> str:
    """Return the distribution name of one dependency entry.

    Args:
        entry: One entry of a dependency list, as `ruff==0.16.2` or `ruff[extra]>=1.0`.

    Returns:
        The name before the first extras bracket or version operator.
    """
    return re.split(r"[=<>!~\[;]", entry, maxsplit=1)[0].strip()


def _entry(distribution: str) -> str:
    """Return the `dev` entry that names one distribution.

    Args:
        distribution: The distribution name, as `pytest-cov`.

    Returns:
        The whole entry, as `ruff==0.16.2`.

    Raises:
        AssertionError: The extra names no such distribution, or it names it twice.
    """
    entries = [entry for entry in _dev_entries() if _distribution(entry) == distribution]
    assert len(entries) == 1, f"the dev extra names {distribution} {len(entries)} times: {entries}"
    return entries[0]


def _pinned_version(distribution: str) -> str:
    """Return the version the `dev` extra pins for one distribution.

    Args:
        distribution: The distribution name, as `pytest-cov`.

    Returns:
        The version after `==`.

    Raises:
        AssertionError: The entry states no exact version.
    """
    entry = _entry(distribution)
    match = _exact_pin(distribution).match(entry)
    assert match, f"the dev extra states no exact version for {distribution}: {entry!r}"
    return match.group(1)


def _comment(distribution: str) -> str:
    """Return the comment lines that stand above one entry inside the `dev` extra.

    The line has to name the distribution as its own. **A substring test reads the wrong
    entry**, and the self-review of #378 proved it: a decoy `ruff-lsp` entry above the pin,
    with a comment of its own, satisfied both comment cases while the pin carried no
    comment at all. `_distribution` compares the whole name instead.

    Args:
        distribution: The distribution name, as `pytest-cov`.

    Returns:
        The comment lines, joined by one space, without their `#` markers. An entry that
        carries no comment gives the empty string.

    Raises:
        AssertionError: `pyproject.toml` holds no `dev` extra.
    """
    comment: list[str] = []
    for line in _dev_lines():
        if line.startswith("#"):
            comment.append(line.lstrip("#").strip())
            continue
        if any(_distribution(found) == distribution for found in re.findall(r"\"([^\"]+)\"", line)):
            return " ".join(comment)
        comment = []
    return ""


def _instruction_files() -> list[Path]:
    """Return every tracked file that instructs a reader rather than records a round.

    A sentence in one of these files sends a contributor to a file. `CHANGELOG.md` and
    `docs/specs/spec.md` hold the history of this repository, so each one quotes a deleted
    path inside a record and neither one instructs anybody.

    Returns:
        The paths, in a fixed order.
    """
    history = {REPO_ROOT / name for name in HISTORY_FILES}
    candidates = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "CLAUDE.md",
        REPO_ROOT / "pyproject.toml",
        *sorted(WORKFLOWS.glob("*.yml")),
        *sorted(REPO_ROOT.glob("docs/**/*.md")),
    ]
    return [path for path in candidates if path.is_file() and path not in history]


@pytest.mark.parametrize("distribution", PINNED)
def test_the_dev_extra_pins_each_chosen_distribution_to_one_exact_version(
    distribution: str,
) -> None:
    """`pyproject.toml` states one exact version for each distribution #446 pinned.

    An exact pin makes a version change a commit that shows its own diff. #378 records the
    measurement that declined the floating pin and the compatible range, and #446 reads it
    across the rest of the extra.
    """
    assert _pinned_version(distribution) != ""


@pytest.mark.parametrize("distribution", PINNED + FLOATING)
def test_the_comment_beside_each_entry_cites_the_issue_that_chose_the_shape(
    distribution: str,
) -> None:
    """The comment beside each entry names its issue, so a reader reaches the measurement.

    The comment carries the one sentence that states why the shape was chosen. A reader
    who wants to bump the version needs the reason before the number.
    """
    comment = _comment(distribution)
    issue = SHAPE_ISSUE[distribution]
    assert issue in comment, (
        f"the comment beside the {distribution} entry omits {issue}: {comment!r}"
    )


@pytest.mark.parametrize("distribution", PINNED)
def test_each_pin_states_that_a_version_change_is_a_commit(distribution: str) -> None:
    """The comment beside each pin states that a version change is a deliberate commit."""
    comment = _comment(distribution)
    assert "commit" in comment, (
        f"the comment beside the {distribution} pin states no commit rule: {comment!r}"
    )


@pytest.mark.parametrize("distribution", FLOATING)
def test_the_dev_extra_leaves_the_type_checker_floating(distribution: str) -> None:
    """`pyproject.toml` states no exact version for the type checker.

    A pinned type checker holds back the checks a later release adds, so a real type
    defect accumulates behind a passing gate. The user ruled that trade on 2026-08-10.
    """
    entry = _entry(distribution)
    assert not _exact_pin(distribution).match(entry), (
        f"the dev extra pins {distribution} exactly, and #446 chose the floating shape: {entry!r}"
    )


@pytest.mark.parametrize("distribution", FLOATING)
def test_the_floating_entry_records_the_defect_a_pin_would_hide(distribution: str) -> None:
    """The comment beside the floating entry states what a pin would hide.

    A reader who meets one floating entry among four pins reads it as an omission. The
    comment states the reading instead, and a case holds the comment.
    """
    comment = _comment(distribution)
    assert "hides" in comment, (
        f"the comment beside the {distribution} entry states no hidden defect: {comment!r}"
    )


def test_the_decision_covers_every_entry_of_the_dev_extra() -> None:
    """Every entry of the `dev` extra carries a shape that a recorded ruling chose.

    A new entry that nobody ruled on reaches this case rather than the next install. The
    floor fails a reader that collected no entry, because an aggregate over an empty set
    passes and would report no offender.
    """
    entries = _dev_entries()
    assert len(entries) >= MINIMUM_DEV_ENTRIES, (
        f"the dev extra reader collected {len(entries)} entries: {entries}"
    )
    chosen = set(PINNED) | set(FLOATING)
    unchosen = sorted({_distribution(entry) for entry in entries} - chosen)
    assert unchosen == [], f"these dev entries carry no recorded shape: {unchosen}"


def test_no_pin_comment_names_an_interpreter_the_supported_set_dropped() -> None:
    """No comment of the extras table holds a pin back for an interpreter this project drops.

    A pin comment states why the version is what it is. Four comments named Python 3.9 as
    the reason a newer release could not land, and #575 removed that interpreter from the
    supported set. **A comment that states a superseded reason is a defect**, because a
    reader takes it for the live reason and declines the bump again. #576 repaired the
    four and this case holds the repair.

    The floor comes from `requires-python`, so a later drop fails this case rather than
    leaving the prose behind. The case reads the extras table alone. `[tool.mypy]` records
    a past measurement against Python 3.9, and that record is correct.
    """
    text = PYPROJECT.read_text(encoding="utf-8")
    floor_match = re.search(r'^requires-python = ">=(\d+)\.(\d+)"', text, re.MULTILINE)
    assert floor_match, "pyproject.toml states no requires-python floor"
    floor = (int(floor_match.group(1)), int(floor_match.group(2)))
    start = text.find("\n[project.optional-dependencies]\n")
    assert start != -1, "pyproject.toml holds no optional-dependencies table"
    end = text.find("\n[project.urls]", start)
    assert end != -1, "the optional-dependencies table reaches no following table"
    offenders = [
        line.strip()
        for line in text[start:end].splitlines()
        if line.lstrip().startswith("#")
        for major, minor in re.findall(r"Python (\d+)\.(\d+)", line)
        if (int(major), int(minor)) < floor
    ]
    assert offenders == [], f"these pin comments name a dropped interpreter: {offenders}"


@pytest.mark.parametrize("distribution", PINNED)
def test_no_workflow_resolves_a_version_of_its_own(distribution: str) -> None:
    """Every job installs each pinned tool from the `dev` extra and from no second place.

    Two places that state a version can disagree, and the job that installs the second
    one runs a tool the pin did not choose.
    """
    pattern = _any_specifier(distribution)
    offenders = sorted(
        str(path.relative_to(REPO_ROOT))
        for path in WORKFLOWS.glob("*.yml")
        if pattern.search(path.read_text(encoding="utf-8"))
    )
    assert offenders == [], (
        f"these workflows state a {distribution} version of their own: {offenders}"
    )


@pytest.mark.parametrize("distribution", PINNED)
def test_no_dependency_file_resolves_a_version_of_its_own(distribution: str) -> None:
    """No second dependency file of the repository states a version of a pinned tool."""
    pattern = _any_specifier(distribution)
    offenders = sorted(
        name
        for name in RESOLVED_FILES
        if (REPO_ROOT / name).is_file()
        and pattern.search((REPO_ROOT / name).read_text(encoding="utf-8"))
    )
    assert offenders == [], f"these files state a {distribution} version of their own: {offenders}"


@pytest.mark.parametrize("distribution", PINNED)
def test_the_installed_release_holds_the_pinned_version(distribution: str) -> None:
    """The release this environment holds equals the version the pin names.

    An environment that drifts from a pin runs a gate the repository did not choose, and
    the drift is silent. The case skips where the environment holds no such distribution,
    because the conformance job installs the extra and the reader of a skip sees the gap.
    """
    try:
        installed = metadata.version(distribution)
    except metadata.PackageNotFoundError:
        pytest.skip(f"this environment holds no {distribution}")
    assert installed == _pinned_version(distribution), (
        f"this environment holds {distribution} {installed} and pyproject.toml pins "
        f"{_pinned_version(distribution)}"
    )


def test_the_repository_holds_no_second_dependency_record() -> None:
    """The tracked `requirements.txt` no longer exists.

    That file stated `pytest-cov>=3.0.0` against the `>=5.0` of `pyproject.toml`, and
    nothing held the two in agreement. #446 deleted it, so one record states every version.
    """
    assert not (REPO_ROOT / DELETED_RECORD).is_file(), (
        f"{DELETED_RECORD} is a second dependency record, and #446 deleted it"
    )


def test_no_instruction_names_the_deleted_dependency_record() -> None:
    """No file that instructs a reader names the deleted `requirements.txt`.

    A deletion that leaves a document pointing at a deleted file is worse than the file.
    The floor fails a reader that collected too few candidates.
    """
    files = _instruction_files()
    assert len(files) >= MINIMUM_INSTRUCTION_FILES, (
        f"the instruction reader collected {len(files)} files"
    )
    offenders = sorted(
        str(path.relative_to(REPO_ROOT))
        for path in files
        if DELETED_RECORD in path.read_text(encoding="utf-8")
    )
    assert offenders == [], f"these files name {DELETED_RECORD}: {offenders}"
