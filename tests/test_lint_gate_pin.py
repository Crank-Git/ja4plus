"""Tests that the lint gate installs one `ruff` version, and that a commit chooses it.

`FR-foundation-7` and `FR-foundation-8` name `ruff check` and `ruff format --check` as
gates of every pull request. Neither one names a version. `pyproject.toml` declared
`ruff>=0.6`, so `pip` resolved the newest release at the moment of each install, and the
gate read a different tool on two days.

**#297 measured the drift on this repository.** It recorded 58 `F401` findings, 28 files
and 82 `I001` findings against `ruff` 0.14.5, and 54, 27 and 76 against 0.16.2. Every
number differed on an unchanged tree. A gate whose result depends on the day it runs is a
comparison that measures something other than what it names. #378 records the defect and
the decision.

## What a case here reads

The pin is one entry of the `dev` extra. `_dependency_block` of
`tests/test_documentation_site.py` parses a dependency list, and **this file declines it**.
That reader collects every double-quoted substring of the block. The `dev` extra carries
comment lines inside the list, and a comment that quotes a version therefore reads as an
entry. The reader already returns `not spec_validation` from the comment beside
`build>=1.0`. **A comment that quoted `"ruff==0.14.5"` would then fail a case here on the
wording of a comment**, which is a check a rewording defeats. `_dev_entries` below strips
the comment lines first.

The self-review of #378 found that hazard. `_dependency_block` stays correct where it is
used today, because the `docs` list and the runtime list carry no comment inside the
brackets.

**The `dev` extra is the one place a tool reads the version from.** Every job of
`.github/workflows/test.yml` installs the extra, and no workflow names `ruff` with a
version specifier of its own.

**Prose that quotes the pin reaches no case here.** `CHANGELOG.md` and
`docs/specs/spec.md` record the version this round chose, and no tool installs from a
record. A case here reads the files a tool resolves a dependency from, so the candidate set
names them.

## What a case here cannot test

**A case here cannot test that the pinned version is the right one.** It holds the pin
against the installed tool and against the workflow set. A maintainer who bumps the number
holds the question of whether the new version reports a finding the old one did not.

These cases read prose and configuration. They import nothing from `ja4plus` and they
produce no fingerprint.
"""

from importlib import metadata
from pathlib import Path
import re

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

PYPROJECT = REPO_ROOT / "pyproject.toml"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# The distribution the lint gate runs. `FR-foundation-7` and `FR-foundation-8` name its
# two commands.
LINT_TOOL = "ruff"

# The line that opens the development extra of `pyproject.toml`.
DEV_EXTRA = "dev = ["

# The issue that chose the exact pin over a compatible range and over the drift. The
# comment beside the pin cites it, so a reader who asks why reaches the measurement.
PIN_ISSUE = "#378"

# An exact pin, as `ruff==0.16.2`. The version carries at least a major and a minor part,
# so `ruff==0` fails the pattern. The trailing group accepts a pre-release or a local
# version, as `0.17.0rc1` or `0.16.2+local`, because PEP 440 permits both and a pin that
# names one is still exact.
EXACT_PIN = re.compile(rf"^{LINT_TOOL}==(\d+\.\d+(?:\.\d+)*[A-Za-z0-9.+!-]*)$")

# A version specifier of any shape, as `ruff>=0.6`, `ruff>0.6`, `ruff===0.16.2` or
# `ruff[extra]==1.0`. A second file that carries one resolves a version of its own, which
# is the state the pin removes.
# **The one-character operators carry this pattern, and the first form omitted them.** It
# read `[=<>!~]=` and demanded a trailing `=`, so it missed `ruff>0.6`, which is the shape
# of the specifier this pin replaced. The optional extras group closes the second miss.
# The self-review of #378 found both.
ANY_SPECIFIER = re.compile(rf"\b{LINT_TOOL}(?:\[[^\]]*\])?\s*(?:[=!~<>]=|===|[<>])\s*\d")

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
        AssertionError: `pyproject.toml` holds no `dev` extra, or the list is not closed.
    """
    text = PYPROJECT.read_text(encoding="utf-8")
    start = text.find(f"\n{DEV_EXTRA}\n")
    assert start != -1, f"pyproject.toml holds no {DEV_EXTRA!r} list"
    end = text.find("\n]", start)
    assert end != -1, f"the {DEV_EXTRA!r} list is not closed"
    return [line.strip() for line in text[start:end].splitlines()[2:]]


def _dev_entries() -> list[str]:
    """Return every dependency entry of the `dev` extra of `pyproject.toml`.

    A comment line reaches no entry. The `dev` extra states the reason for several of its
    entries in a comment, and a comment that quotes a version is prose rather than a
    dependency.

    Returns:
        The quoted entries, without their quotes, in file order.
    """
    return [
        found
        for line in _dev_lines()
        if not line.startswith("#")
        for found in re.findall(r"\"([^\"]+)\"", line)
    ]


def _distribution(entry: str) -> str:
    """Return the distribution name of one dependency entry.

    Args:
        entry: One entry of a dependency list, as `ruff==0.16.2` or `ruff[extra]>=1.0`.

    Returns:
        The name before the first extras bracket or version operator.
    """
    return re.split(r"[=<>!~\[;]", entry, maxsplit=1)[0].strip()


def _lint_entry() -> str:
    """Return the `dev` entry that names the lint tool.

    Returns:
        The whole entry, as `ruff==0.16.2`.

    Raises:
        AssertionError: The extra names no such distribution, or it names it twice.
    """
    entries = [entry for entry in _dev_entries() if _distribution(entry) == LINT_TOOL]
    assert len(entries) == 1, f"the dev extra names {LINT_TOOL} {len(entries)} times: {entries}"
    return entries[0]


def _pinned_version() -> str:
    """Return the version the `dev` extra pins for the lint tool.

    Returns:
        The version after `==`.

    Raises:
        AssertionError: The entry states no exact version.
    """
    entry = _lint_entry()
    match = EXACT_PIN.match(entry)
    assert match, f"the dev extra states no exact version for {LINT_TOOL}: {entry!r}"
    return match.group(1)


def _lint_comment() -> str:
    """Return the comment lines that stand above the lint entry inside the `dev` extra.

    The line has to name the lint tool as its distribution. **A substring test reads the
    wrong entry**, and the self-review of #378 proved it: a decoy `ruff-lsp` entry above the
    pin, with a comment of its own, satisfied both comment cases while the pin carried no
    comment at all. `_distribution` compares the whole name instead.

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
        if any(_distribution(found) == LINT_TOOL for found in re.findall(r"\"([^\"]+)\"", line)):
            return " ".join(comment)
        comment = []
    return ""


def test_the_dev_extra_pins_the_lint_tool_to_one_exact_version() -> None:
    """`pyproject.toml` states one exact `ruff` version for the lint gate.

    An exact pin makes a version change a commit that shows its own diff. #378 records
    the measurement that declined the floating pin and the compatible range.
    """
    assert _pinned_version() != ""


def test_the_pin_cites_the_issue_that_chose_the_shape() -> None:
    """The comment beside the pin names #378, so a reader reaches the measurement.

    The comment carries the one sentence that states why the shape was chosen. A reader
    who wants to bump the version needs the reason before the number.
    """
    comment = _lint_comment()
    assert PIN_ISSUE in comment, (
        f"the comment beside the {LINT_TOOL} pin omits {PIN_ISSUE}: {comment!r}"
    )


def test_the_pin_states_that_a_version_change_is_a_commit() -> None:
    """The comment beside the pin states that a version change is a deliberate commit."""
    comment = _lint_comment()
    assert "commit" in comment, (
        f"the comment beside the {LINT_TOOL} pin states no commit rule: {comment!r}"
    )


def test_no_workflow_resolves_a_lint_version_of_its_own() -> None:
    """Every job installs the lint tool from the `dev` extra and from no second place.

    Two places that state a version can disagree, and the job that installs the second
    one runs a tool the pin did not choose.
    """
    offenders = sorted(
        str(path.relative_to(REPO_ROOT))
        for path in WORKFLOWS.glob("*.yml")
        if ANY_SPECIFIER.search(path.read_text(encoding="utf-8"))
    )
    assert offenders == [], f"these workflows state a {LINT_TOOL} version of their own: {offenders}"


def test_no_dependency_file_resolves_a_lint_version_of_its_own() -> None:
    """No second dependency file of the repository states a `ruff` version."""
    offenders = sorted(
        name
        for name in RESOLVED_FILES
        if (REPO_ROOT / name).is_file()
        and ANY_SPECIFIER.search((REPO_ROOT / name).read_text(encoding="utf-8"))
    )
    assert offenders == [], f"these files state a {LINT_TOOL} version of their own: {offenders}"


def test_the_installed_lint_tool_holds_the_pinned_version() -> None:
    """The `ruff` release this environment holds equals the version the pin names.

    An environment that drifts from the pin runs a gate the repository did not choose, and
    the drift is silent. The case skips where the environment holds no `ruff`, because the
    conformance job installs the extra and the reader of a skip sees the gap.
    """
    try:
        installed = metadata.version(LINT_TOOL)
    except metadata.PackageNotFoundError:
        pytest.skip(f"this environment holds no {LINT_TOOL}")
    assert installed == _pinned_version(), (
        f"this environment holds {LINT_TOOL} {installed} and pyproject.toml pins "
        f"{_pinned_version()}"
    )
