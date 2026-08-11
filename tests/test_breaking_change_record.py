"""Tests that the record names every breaking change the package still carries.

`tests/test_changelog_round_agreement.py` compares `CHANGELOG.md` against
`docs/specs/spec.md`. **A comparison between two records finds no change that is absent
from both of them.** The move of the Python floor from 3.8 to 3.9 is such a change: it
shipped in commit `02ee772` under #76, neither file recorded it, and the two files
therefore agreed and were both wrong. #395 records the blind spot.

**These cases compare the record against the package instead.** The package states what
it removed and what it requires, so a change that no round records fails here. A reader
who raises the Python floor again, or who removes another module, meets this file before
a reader of the record meets the gap.

## Why the two floor cases read an unassigned record

**A member writes `TBD` in place of its round number, and the project manager assigns the
number at the batch gate.** #575 moved the Python floor and met the result: a reader that
demanded a number could not pass on the branch that made the move, and no later branch
makes it again. `FLOOR_ROUND` and `FLOOR_ROW` therefore accept `TBD` beside a number.

**An entry that records no round at all still fails.** `tests/test_specification_changelog.py`
requires the rounds 1 to the row count, each on one row, so a `TBD` reaches `dev` nowhere.
The module cases keep `CHANGELOG_ROUND`, because a removed module is no move of one batch.

The module census below reads the released version. `git ls-tree -r --name-only v0.6.0
ja4plus/` reports 26 tracked paths, and 25 of them are modules. `ja4plus/collector.py`
is the one module the census holds that the package no longer carries, and #191 removed
it.

These cases read prose and packaging metadata. They import nothing from `ja4plus` and
they produce no fingerprint.
"""

import importlib.util
from pathlib import Path
import re

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
PROJECT_FILE = REPO_ROOT / "pyproject.toml"

# The modules the version 0.6.0 release published. A reader reproduces this census with
# `git ls-tree -r --name-only v0.6.0 ja4plus/`, which also reports the mapping file.
RELEASED_MODULES = (
    "ja4plus",
    "ja4plus.cli",
    "ja4plus.collector",
    "ja4plus.fingerprinters",
    "ja4plus.fingerprinters.base",
    "ja4plus.fingerprinters.ja4",
    "ja4plus.fingerprinters.ja4d",
    "ja4plus.fingerprinters.ja4d6",
    "ja4plus.fingerprinters.ja4h",
    "ja4plus.fingerprinters.ja4l",
    "ja4plus.fingerprinters.ja4s",
    "ja4plus.fingerprinters.ja4ssh",
    "ja4plus.fingerprinters.ja4t",
    "ja4plus.fingerprinters.ja4ts",
    "ja4plus.fingerprinters.ja4x",
    "ja4plus.ja4db",
    "ja4plus.processor",
    "ja4plus.utils",
    "ja4plus.utils.http_utils",
    "ja4plus.utils.packet_utils",
    "ja4plus.utils.quic_utils",
    "ja4plus.utils.ssh_utils",
    "ja4plus.utils.tcp_stream",
    "ja4plus.utils.tls_utils",
    "ja4plus.utils.x509_utils",
)

# The census holds this many modules. A census that shrinks to nothing passes every case
# below, so the floor fails such a census.
RELEASED_MODULE_COUNT = 25

# A Changelog row of the specification opens with the round and the date, as
# `| 71 | 2026-08-08 | #191 landed and ... |`. The date parts a Changelog row from every
# other table of the page. An unassigned row carries the literal `TBD`, and it records no
# round yet, so the module cases read a numbered row alone.
SPECIFICATION_ROW = re.compile(r"^\|\s*(\d+)\s*\|\s*\d{4}-\d{2}-\d{2}\s*\|")

# The same row, plus the unassigned form the branch that moves the floor writes. The
# section above states why the two floor cases read it.
FLOOR_ROW = re.compile(r"^\|\s*(\d+|TBD)\s*\|\s*\d{4}-\d{2}-\d{2}\s*\|")

# The specification held this many numbered Changelog rows when #395 landed. A parser
# that reads nothing passes every case below, so the floor fails such a parser.
MINIMUM_SPECIFICATION_ROWS = 135

# `CHANGELOG.md` opens each section with a third-level heading, as `### Removed`.
CHANGELOG_HEADING = re.compile(r"^###\s+(.+?)\s*$")

# An entry names its round in a sentence of its own, as `Round 71.`. The file wraps at 90
# columns, so `Round` ends one line and the number opens the next on five entries.
# **`\s+` carries this pattern and a literal space breaks it.** #302 records the defect.
# The number must read as a number here, because `Round TBD.` records no round.
CHANGELOG_ROUND = re.compile(r"Round\s+`?(\d+)`?\.")

# The same sentence, plus the unassigned form. `Round TBD.` wraps at 90 columns as `Round`
# on one line and `  TBD.` on the next, so `\s+` carries this pattern too.
FLOOR_ROUND = re.compile(r"Round\s+`?(\d+|TBD)`?\.")

# `requires-python` states the Python floor of the package, as `requires-python = ">=3.9"`.
REQUIRES_PYTHON = re.compile(r'^requires-python\s*=\s*"([^"]+)"', re.MULTILINE)


def _changelog_entries_under(heading: str) -> list[str]:
    """Return every entry of `CHANGELOG.md` that sits under one third-level heading.

    Args:
        heading: The heading text, without the leading `###`, as `Removed`.

    Returns:
        One string for each entry, holding the whole entry text.
    """
    entries: list[str] = []
    current: str | None = None
    collected: list[str] = []
    for line in CHANGELOG.read_text(encoding="utf-8").splitlines():
        heading_match = CHANGELOG_HEADING.match(line)
        if heading_match:
            if collected:
                entries.append("\n".join(collected))
                collected = []
            current = heading_match.group(1)
            continue
        if current != heading:
            continue
        if line.startswith("- "):
            if collected:
                entries.append("\n".join(collected))
            collected = [line]
        elif collected:
            collected.append(line)
    if collected:
        entries.append("\n".join(collected))
    return entries


def _recorded_specification_rows() -> list[str]:
    """Return every Changelog row of the specification that records a round.

    A row of an unassigned round carries `TBD`, which the batch gate replaces with a
    number. The two floor cases read this list.

    Returns:
        One string for each row, holding the whole row text.

    Raises:
        AssertionError: The page holds fewer rows than the recorded floor.
    """
    rows = [
        line
        for line in SPECIFICATION.read_text(encoding="utf-8").splitlines()
        if FLOOR_ROW.match(line)
    ]
    assert len(rows) >= MINIMUM_SPECIFICATION_ROWS, (
        f"the parser read {len(rows)} recorded Changelog rows, "
        f"and the floor is {MINIMUM_SPECIFICATION_ROWS}"
    )
    return rows


def _numbered_specification_rows() -> list[str]:
    """Return every Changelog row of the specification that carries a round number.

    Returns:
        One string for each row, holding the whole row text.

    Raises:
        AssertionError: The page holds fewer numbered rows than the recorded floor.
    """
    rows = [
        line
        for line in SPECIFICATION.read_text(encoding="utf-8").splitlines()
        if SPECIFICATION_ROW.match(line)
    ]
    assert len(rows) >= MINIMUM_SPECIFICATION_ROWS, (
        f"the parser read {len(rows)} numbered Changelog rows, "
        f"and the floor is {MINIMUM_SPECIFICATION_ROWS}"
    )
    return rows


def _python_floor() -> str:
    """Return the Python floor that `pyproject.toml` states.

    Returns:
        The value of `requires-python`, as `>=3.9`.

    Raises:
        AssertionError: The file states no `requires-python` value.
    """
    match = REQUIRES_PYTHON.search(PROJECT_FILE.read_text(encoding="utf-8"))
    assert match, "pyproject.toml states no requires-python value"
    return match.group(1)


def test_the_census_holds_every_module_the_release_published() -> None:
    """The census of version 0.6.0 holds the module count that release carried.

    **This case compares two constants of this file and it reads no package.** It bars a
    census that shrinks to nothing, because an empty census passes every case below. A
    reader who changes both constants together defeats it, and
    `git ls-tree -r --name-only v0.6.0 ja4plus/` is the check on the census itself.
    """
    assert len(RELEASED_MODULES) == RELEASED_MODULE_COUNT, (
        f"the census holds {len(RELEASED_MODULES)} modules, and the count is "
        f"{RELEASED_MODULE_COUNT}"
    )


def test_a_removed_module_reaches_no_importer() -> None:
    """A module the census holds and the package drops raises no import today.

    **Every census name sits under the `ja4plus` package, which imports.**
    `importlib.util.find_spec` returns `None` for a missing module under a parent that
    imports, and it raises `ModuleNotFoundError` where the parent itself is missing. A
    census entry under a parent that does not exist therefore errors here.
    """
    absent = [name for name in RELEASED_MODULES if importlib.util.find_spec(name) is None]
    assert absent == ["ja4plus.collector"], (
        f"the package drops these modules of version 0.6.0: {absent}"
    )


def test_the_changelog_records_every_module_the_package_removed() -> None:
    """`CHANGELOG.md` records each removed module of version 0.6.0 under a round."""
    recorded = [
        entry
        for entry in _changelog_entries_under("Removed")
        if CHANGELOG_ROUND.search(entry) is not None
    ]
    unrecorded = [
        name
        for name in RELEASED_MODULES
        if importlib.util.find_spec(name) is None and not any(name in entry for entry in recorded)
    ]
    assert unrecorded == [], (
        f"CHANGELOG.md holds no numbered Removed entry for these modules: {unrecorded}"
    )


def test_the_specification_records_every_module_the_package_removed() -> None:
    """The Changelog table of `docs/specs/spec.md` records each removed module."""
    rows = _numbered_specification_rows()
    unrecorded = [
        name
        for name in RELEASED_MODULES
        if importlib.util.find_spec(name) is None and not any(name in row for row in rows)
    ]
    assert unrecorded == [], (
        f"the Changelog table holds no numbered row for these modules: {unrecorded}"
    )


def test_the_changelog_records_the_python_floor_the_package_states() -> None:
    """`CHANGELOG.md` names `requires-python` and its value under a round."""
    floor = _python_floor()
    recorded = [
        entry
        for entry in CHANGELOG.read_text(encoding="utf-8").split("\n- ")
        if "requires-python" in entry and floor in entry and FLOOR_ROUND.search(entry)
    ]
    assert recorded != [], (
        f"CHANGELOG.md holds no recorded entry that names requires-python and {floor}"
    )


def test_the_specification_records_the_python_floor_the_package_states() -> None:
    """The Changelog table of `docs/specs/spec.md` names `requires-python` and its value."""
    floor = _python_floor()
    recorded = [
        row for row in _recorded_specification_rows() if "requires-python" in row and floor in row
    ]
    assert recorded != [], (
        f"the Changelog table holds no recorded row that names requires-python and {floor}"
    )


def test_the_floor_reader_reads_no_entry_that_records_no_round_at_all() -> None:
    """An entry with no round sentence fails the reader, and an unassigned one passes."""
    assert FLOOR_ROUND.search("- **A change** (#3). It records no round.") is None
    assert FLOOR_ROUND.search("- **A change** (#3). Round\n  TBD.") is not None
    assert FLOOR_ROUND.search("- **A change** (#3). Round 42.") is not None


def test_the_floor_row_reader_reads_no_row_that_records_no_round_at_all() -> None:
    """A row with no round cell fails the reader, and an unassigned one passes."""
    assert FLOOR_ROW.match("| | 2026-08-10 | #3 landed. |") is None
    assert FLOOR_ROW.match("| TBD | 2026-08-10 | #3 landed. |") is not None
    assert FLOOR_ROW.match("| 42 | 2026-08-10 | #3 landed. |") is not None
