"""Read the built wheel against the two content requirements of the release.

`FR-release-10` requires the wheel to carry the mapping file and the `py.typed` marker.
`FR-release-11` requires it to carry no file under `tests/`, `examples/` or `docs/`. #69
owns both requirements, and `docs/specs/features/09-release.md` names this file.

**#455 already repaired the wheel, so these cases measure a state that holds today.** That
round moved the wheel from 96 entries and 3139637 bytes to 39 entries and 152780 bytes. A
read of 2026-08-10 reports 39 entries and 155900 bytes on this branch. The value of a case
here is therefore the direction it fails in, and the mutation cases below prove both
directions on a copy of the built wheel.

**This file adds three readings that `tests/test_installed_wheel.py` does not hold.**

1. The `py.typed` marker, which no case read in the wheel before this round.
2. The entry floor. **An aggregate over an empty set passes**, so a wheel that lists no
   entry meets every exclusion rule. `packaging_faults` reads the entry count first.
3. The proof that the reader fails on a wheel with the marker removed, and on a wheel with
   a file under an excluded tree added.

`tests/test_installed_wheel.py` keeps the readings it already holds: the mapping file, the
documentation tree, the assets tree, the top-level name and the payload of the whole wheel.
This file imports `build_artifacts` and `wheel_entry_names` from it, so one reader opens
the archive and one command builds it.

**Every case here carries the `installed_wheel` marker**, because a case here runs
`python -m build` and that command reaches the index. `tests/conftest.py` deselects the
marker from a run that does
not name it, and the `installed-wheel` job of `.github/workflows/test.yml` runs
`pytest tests/ -m installed_wheel`, which collects this file.

**A read of 2026-08-10 reports which mechanism ships each required entry.** The read cut
`[tool.setuptools.package-data]` to `ja4plus = ["data/*.csv"]`. It also cut the exclusion
list to `["examples", "assets", "assets.*"]`. The build still listed `ja4plus/py.typed`.
`include-package-data` is true by default, and the file finder of `setuptools-scm` reports
every tracked file, so a tracked file below the package ships whatever the package-data
list holds. That build listed 376 entries and 337 of them lay under the three excluded
trees. **The marker case therefore fails on an absent file and not on an absent list
entry.** The mutation cases below prove both directions on a copy of the built wheel.

**This module builds the wheel again rather than share the fixture of
`tests/test_installed_wheel.py`.** `pytest` registers a fixture on the module that defines
it, so a fixture two modules share lives in `tests/conftest.py`. That file carries the
deselection rule of the whole suite, and #69 moves no rule of another issue into it.
"""

from __future__ import annotations

import hashlib
import pathlib
import zipfile
from typing import Dict, Iterable, List, Sequence, Tuple

import pytest

from tests.test_installed_wheel import build_artifacts, wheel_entry_names

pytestmark = pytest.mark.installed_wheel

# The entries `FR-release-10` requires. The lookup reads the mapping file at run time, and
# a wheel without it produces a package that imports and then reports an empty database.
# PEP 561 reads the marker, and a wheel without it hides every annotation from `mypy`.
REQUIRED_ENTRIES: Tuple[str, ...] = (
    "ja4plus/data/ja4plus-mapping.csv",
    "ja4plus/py.typed",
)

# The trees `FR-release-11` names. `pyproject.toml` excludes each one in
# `[tool.setuptools.packages.find]`, and #455 records the two defaults that shipped `docs/`.
EXCLUDED_PREFIXES: Tuple[str, ...] = ("tests/", "examples/", "docs/")

# The floor on the entry count. **An assertion over an empty list passes**, so a build that
# writes an empty archive meets every exclusion rule above. A read of 2026-08-10 reports 39
# entries, and #455 reports the same number. The floor sits below that count, because a
# module this project adds later raises the count and never lowers it.
MINIMUM_ENTRY_COUNT = 30

# The entry the mutation cases add, under the first excluded tree. **The repository tracks
# no file of this name**, so a build that ships the whole tree cannot list it and the
# mutation stays a mutation.
INTRUDER_ENTRY = "tests/issue_69_intruder.txt"

# The entry count a failure message writes. A wheel that ships every tracked file lists 376
# entries, and a message that names all of them hides the sentence in front of it.
REPORTED_NAMES = 10


def sample(names: Sequence[str]) -> str:
    """Return the first names of one list, with the count of the rest.

    Args:
        names: The names to report, in the order the caller reads them.

    Returns:
        The text one failure message carries.
    """
    head = list(names[:REPORTED_NAMES])
    rest = len(names) - len(head)
    return f"{head} and {rest} more" if rest > 0 else f"{head}"


def packaging_faults(wheel: pathlib.Path) -> List[str]:
    """Return one sentence for every content requirement the wheel fails.

    Warning: read the entry count before the exclusion rules. A wheel that lists no entry
    carries no file under an excluded tree, so the exclusion rules alone pass on it.

    Args:
        wheel: The wheel to read.

    Returns:
        The faults, in the order this function reads them. An empty list reports a wheel
        that meets `FR-release-10` and `FR-release-11`.
    """
    names = wheel_entry_names(wheel)
    faults: List[str] = []
    if len(names) < MINIMUM_ENTRY_COUNT:
        faults.append(
            f"the wheel lists {len(names)} entries, and a wheel of this project lists "
            f"{MINIMUM_ENTRY_COUNT} or more"
        )
    missing = [entry for entry in REQUIRED_ENTRIES if entry not in names]
    if missing:
        faults.append(
            f"the wheel lists none of {missing}, and it lists {len(names)} entries: "
            f"{sample(sorted(names))}"
        )
    carried = sorted(name for name in names if name.startswith(EXCLUDED_PREFIXES))
    if carried:
        faults.append(
            f"the wheel carries {len(carried)} of its {len(names)} entries under "
            f"{list(EXCLUDED_PREFIXES)}, and it must carry none: {sample(carried)}"
        )
    return faults


def rewrite_wheel(
    source: pathlib.Path,
    destination: pathlib.Path,
    remove: Sequence[str] = (),
    add: Sequence[str] = (),
) -> pathlib.Path:
    """Return a copy of one wheel that drops named entries and adds named entries.

    The function writes a new archive and it edits no byte of the source, so the built
    wheel needs no restore after a mutation.

    Args:
        source: The wheel to copy.
        destination: The path of the copy. It must not exist.
        remove: The entry names the copy omits.
        add: The entry names the copy adds, each with an empty payload.

    Returns:
        The copy.

    Raises:
        AssertionError: The source lists an entry of `add`, or it lists no entry of
            `remove`.
    """
    names = wheel_entry_names(source)
    for entry in remove:
        assert entry in names, f"{source.name} lists no {entry}, so its removal changes nothing"
    for entry in add:
        assert entry not in names, f"{source.name} already lists {entry}"
    with zipfile.ZipFile(source) as archive, zipfile.ZipFile(destination, "w") as copy:
        for item in archive.infolist():
            if item.filename in remove:
                continue
            copy.writestr(item, archive.read(item.filename))
        for entry in add:
            copy.writestr(entry, b"")
    return destination


def digest_of(path: pathlib.Path) -> str:
    """Return the SHA-256 digest of one file, as hexadecimal text."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reported(faults: Iterable[str], text: str) -> bool:
    """Report whether one fault list holds a sentence that names the text."""
    return any(text in fault for fault in faults)


@pytest.fixture(scope="session")
def wheel(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """Build the wheel once for this module and return it."""
    artifacts: Dict[str, pathlib.Path] = build_artifacts(tmp_path_factory.mktemp("packaging"))
    return artifacts["wheel"]


def test_the_wheel_lists_the_mapping_file_and_the_type_marker(wheel: pathlib.Path) -> None:
    """`FR-release-10`. The wheel lists the mapping file and the `py.typed` marker.

    Both files fail silently at run time. A wheel without the mapping file reports an empty
    database, and a wheel without the marker hides the annotations from a caller who runs
    `mypy`. The build therefore reads both here.
    """
    names = wheel_entry_names(wheel)
    missing = [entry for entry in REQUIRED_ENTRIES if entry not in names]
    assert not missing, (
        f"the wheel lists none of {missing}, and it lists {len(names)} entries: "
        f"{sample(sorted(names))}"
    )


def test_the_wheel_lists_no_file_under_an_excluded_tree(wheel: pathlib.Path) -> None:
    """`FR-release-11`. The wheel lists no entry under `tests/`, `examples/` or `docs/`.

    A user who installs the wheel receives a library. The test suite, the examples and the
    design material are no part of it, and #455 measured 56 entries under `docs/` in the
    wheel of its base commit.

    Warning: this case reads the artifact and never the working tree. The state it measures
    lives in what the build includes.
    """
    names = wheel_entry_names(wheel)
    assert len(names) >= MINIMUM_ENTRY_COUNT, (
        f"the wheel lists {len(names)} entries, so this case reads no wheel that a user "
        f"could install"
    )
    carried = sorted(name for name in names if name.startswith(EXCLUDED_PREFIXES))
    assert not carried, (
        f"the wheel carries {len(carried)} of its {len(names)} entries under "
        f"{list(EXCLUDED_PREFIXES)}, and it must carry none: {sample(carried)}"
    )


def test_the_wheel_lists_at_least_the_minimum_entry_count(wheel: pathlib.Path) -> None:
    """The wheel lists enough entries to carry the package.

    **An aggregate over an empty set passes.** The exclusion case above reads an empty
    archive as correct, so this floor states the count a real wheel of this project holds.
    """
    names = wheel_entry_names(wheel)
    assert len(names) >= MINIMUM_ENTRY_COUNT, (
        f"the wheel lists {len(names)} entries, and a wheel of this project lists "
        f"{MINIMUM_ENTRY_COUNT} or more: {sample(sorted(names))}"
    )


def test_the_built_wheel_reports_no_packaging_fault(wheel: pathlib.Path) -> None:
    """The reader reports no fault against the wheel this repository builds today."""
    faults = packaging_faults(wheel)
    assert faults == [], f"the built wheel failed {len(faults)} requirements: {faults}"


def test_the_reader_refuses_a_wheel_that_lost_the_type_marker(
    wheel: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """The reader reports a fault where the wheel lists no `py.typed` marker.

    Such a wheel installs a package that imports, and `mypy` reads no annotation of it.

    **A build that drops the package-data entry still ships the marker**, which the module
    docstring records, so a checkout without the file produces this state. This case builds
    that state on a copy of the wheel instead.
    """
    marker = "ja4plus/py.typed"
    mutated = rewrite_wheel(wheel, tmp_path / "no-marker.whl", remove=[marker])
    faults = packaging_faults(mutated)
    assert reported(faults, marker), (
        f"the reader passed a wheel that lists no {marker}, and it reported {faults}"
    )


def test_the_reader_refuses_a_wheel_that_lost_the_mapping_file(
    wheel: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """The reader reports a fault where the wheel lists no mapping file.

    A lookup against such a package reports an empty database, and it raises nothing.
    """
    mapping = "ja4plus/data/ja4plus-mapping.csv"
    mutated = rewrite_wheel(wheel, tmp_path / "no-mapping.whl", remove=[mapping])
    faults = packaging_faults(mutated)
    assert reported(faults, mapping), (
        f"the reader passed a wheel that lists no {mapping}, and it reported {faults}"
    )


def test_the_reader_refuses_a_wheel_that_gained_a_file_under_an_excluded_tree(
    wheel: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """The reader reports a fault where the wheel gains one entry under `tests/`.

    An exclusion list that loses an entry produces this wheel. #455 measured that state on
    `docs/`, where 56 entries of 96 lay under the tree.
    """
    mutated = rewrite_wheel(wheel, tmp_path / "intruder.whl", add=[INTRUDER_ENTRY])
    faults = packaging_faults(mutated)
    assert reported(faults, INTRUDER_ENTRY), (
        f"the reader passed a wheel that lists {INTRUDER_ENTRY}, and it reported {faults}"
    )


def test_the_reader_refuses_a_wheel_that_lists_no_entry(tmp_path: pathlib.Path) -> None:
    """The reader reports a fault where the archive lists no entry.

    **A build that fails writes such an archive, and every exclusion rule passes on it.**
    This case is the one that proves the floor does work.
    """
    empty = tmp_path / "empty.whl"
    with zipfile.ZipFile(empty, "w"):
        pass
    faults = packaging_faults(empty)
    assert reported(faults, "lists 0 entries"), (
        f"the reader read an empty archive and reported {faults}"
    )


def test_the_mutation_leaves_the_built_wheel_unchanged(
    wheel: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """A mutation writes a copy, and the built wheel holds the bytes it held before.

    A case that edits the artifact of a session fixture moves every case that runs after
    it. `rewrite_wheel` therefore writes a new file, and this case measures that promise.
    """
    before = digest_of(wheel)
    rewrite_wheel(wheel, tmp_path / "copy.whl", remove=["ja4plus/py.typed"], add=[INTRUDER_ENTRY])
    assert digest_of(wheel) == before, f"a mutation changed {wheel}"
