"""The artefact of the settlement procedure, because no case watches a worker follow it.

`FR-pre-release-validation-23` read `A worker proves each mutation live in both directions
with inspect.getsource before it settles the candidate.` **That is a procedure a worker
follows, and no case observes a worker.** #419 found it and #414 settles it.

The settlement splits the requirement in two, because the two halves are not the same kind
of statement.

- **The procedure keeps no check.** `docs/specs/features/11-pre-release-validation.md`
  lists it among the statements it declares uncheckable, with its reason. A reader trusts
  the transcript in the pull request or repeats the run.
- **The artefact of the procedure keeps one.** A worker who followed the procedure leaves
  a settlement record whose every `repaired` verdict names a case, and the suite collects
  that case. A worker who settled a candidate with a case name it invented fails
  `test_the_suite_collects_every_case_a_repaired_verdict_names` here.

**The check reads a necessary condition and not a sufficient one.** A record that names a
collected case proves that the case exists. It does not prove that the worker ran the
mutation live in both directions, and nothing in this file claims that it does. The
condition this file adds is that the record cannot name a case the suite does not hold,
which is the failure a reader cannot otherwise see.

These cases read JSON records and prose. They import nothing from `ja4plus` and they
produce no fingerprint.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

SETTLEMENT_DIRECTORY = REPO_ROOT / "docs" / "mutation_settlements"

PRE_RELEASE_VALIDATION = REPO_ROOT / "docs" / "specs" / "features" / "11-pre-release-validation.md"

# The heading of the list the document uses for a statement it declares uncheckable. The
# count word opens the line, so the pattern reads the tail rather than the count.
UNCHECKABLE_HEADING = "statements here are not checkable"


def _records() -> list[tuple[Path, dict]]:
    """Return every settlement record of `docs/mutation_settlements/`, with its path.

    Returns:
        One pair for each `*.json` record: the path, and the object it holds.

    Raises:
        AssertionError: One file holds no JSON object. A reader needs the name of the
            broken file, and a traceback from a parser names the offset alone.
    """
    found: list[tuple[Path, dict]] = []
    for path in sorted(SETTLEMENT_DIRECTORY.glob("*.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as error:
            raise AssertionError(f"{path.name} holds no JSON object: {error}") from error
        found.append((path, record))
    return found


def _settlements(verdict: str) -> list[tuple[str, dict]]:
    """Return every settlement of one verdict, over every record.

    Args:
        verdict: `repaired` or `correct`.

    Returns:
        One pair for each settlement: the name of the record, and the settlement.
    """
    found: list[tuple[str, dict]] = []
    for path, record in _records():
        for settlement in record.get("settlements", []):
            if settlement.get("verdict") == verdict:
                found.append((path.name, settlement))
    return found


def test_the_settlement_directory_holds_a_record() -> None:
    """A directory that holds no record passes every case below with no work done.

    #412 reported the vacuous reading: the census printed `0 candidates over 0 test files`
    on an empty directory. This case is the floor the other cases stand on.
    """
    assert _records() != [], f"{SETTLEMENT_DIRECTORY} holds no settlement record"


def test_a_repaired_verdict_carries_a_case_name() -> None:
    """`FR-pre-release-validation-22` asks a `repaired` verdict for the name of the case."""
    unnamed = [
        f"{name}: {settlement.get('candidate')}"
        for name, settlement in _settlements("repaired")
        if not str(settlement.get("case", "")).strip()
    ]
    assert unnamed == [], f"these repaired verdicts name no case: {unnamed}"


def test_a_correct_verdict_carries_a_reason() -> None:
    """`FR-pre-release-validation-22` asks a `correct` verdict for the reason."""
    unstated = [
        f"{name}: {settlement.get('candidate')}"
        for name, settlement in _settlements("correct")
        if not str(settlement.get("reason", "")).strip()
    ]
    assert unstated == [], f"these correct verdicts state no reason: {unstated}"


def test_the_suite_collects_every_case_a_repaired_verdict_names() -> None:
    """A `repaired` verdict names a case the suite holds, and not a name a writer wrote.

    The collection reads the test files the records name and not the whole suite, because
    the whole suite costs 158 seconds on the host that measured it and this case needs the
    identifiers of six files.
    """
    repaired = _settlements("repaired")
    if not repaired:
        pytest.skip("no record holds a repaired verdict")

    named = {str(settlement["case"]) for _, settlement in repaired}
    files = sorted({case.split("::")[0] for case in named})
    for path in files:
        assert (REPO_ROOT / path).is_file(), f"a repaired verdict names the missing file {path}"

    finished = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *files],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert finished.returncode == 0, f"the collection failed:\n{finished.stdout}\n{finished.stderr}"
    # `--collect-only -q` writes one identifier for each line, then a summary. A
    # parametrized identifier may carry a space inside its brackets, so the filter reads
    # the leading character rather than the spaces.
    collected = {
        line.rstrip()
        for line in finished.stdout.splitlines()
        if "::" in line and not line[:1].isspace() and not line.startswith(("=", "-", "!"))
    }
    missing = sorted(case for case in named if case not in collected)
    assert missing == [], f"the suite collects no case of these repaired verdicts: {missing}"


def test_the_document_declares_the_settlement_procedure_uncheckable() -> None:
    """The document names the procedure among the statements it cannot check.

    A rule stated as a sentence a reader believes, among rules a check tests, with nothing
    marking the difference, is the defect this feature set exists to close.
    """
    text = PRE_RELEASE_VALIDATION.read_text(encoding="utf-8")
    assert UNCHECKABLE_HEADING in text, (
        f"{PRE_RELEASE_VALIDATION.name} holds no list of statements it declares uncheckable"
    )
    tail = text.split(UNCHECKABLE_HEADING, 1)[1]
    section = tail.split("\n## ", 1)[0]
    assert "inspect.getsource" in section, (
        f"{PRE_RELEASE_VALIDATION.name} declares no statement about the settlement "
        "procedure uncheckable, and no case observes a worker following one"
    )
