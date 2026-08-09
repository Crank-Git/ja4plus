"""Count the candidates one mutation sweep left open, and name who settles each one.

The sweep writes `mutation_sweep.json`. A candidate is one test case that no mutation of
that sweep makes fail, and a candidate needs a reader. This module counts the candidates
of each test file, and it reports which settlement record under `docs/mutation_settlements/`
claims each candidate.

**The census groups by test file and not by module.** `tests/mutation_sweep.py:593` builds
one flat candidate list over every module the sweep read, so no module owns a candidate.
The one grouping the report offers splits each identifier at `::`, at
`tests/mutation_sweep.py:396`.

**The census reads the JSON report and it opens no Markdown file.**
`docs/mutation_sweep.md` is one page. A count taken from its lines counts the page layout
and not the candidates. `FR-pre-release-validation-19` states the rule.

**The census reads the settlement directory and no shared file.** #412, #413 and #414 run
at the same time, and one shared table makes each of them conflict with the other two.
Each issue writes one file, and the census reads every file of the directory.

Run it from the repository root:

    python tests/mutation_census.py
"""

from __future__ import annotations

import collections
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent

# The sweep of #411 writes this report, and #412, #413 and #414 read it.
REPORT_PATH = REPO_ROOT / "mutation_sweep.json"

SETTLEMENT_DIRECTORY = REPO_ROOT / "docs" / "mutation_settlements"

# `FR-pre-release-validation-22` names two verdicts, and each one carries its own field.
VERDICT_FIELDS = {"repaired": "case", "correct": "reason"}


@dataclass
class Census:
    """The state of every candidate of one sweep."""

    commit: str
    counts: Dict[str, int]
    candidates: List[str]
    claimed_twice: Dict[str, List[str]]
    unclaimed: List[str]
    unknown: Dict[str, List[str]]
    faults: List[str]


def read_report(path: Path) -> Dict[str, object]:
    """Return the JSON report of one sweep.

    Args:
        path: The path of the report the sweep wrote.

    Returns:
        The report.

    Raises:
        FileNotFoundError: The path holds no file.
    """
    return json.loads(path.read_text())


def candidates(report: Dict[str, object]) -> List[str]:
    """Return every candidate identifier the report names, in order."""
    return list(report["candidates"])  # type: ignore[arg-type]


def counts_by_test_file(report: Dict[str, object]) -> Dict[str, int]:
    """Return the candidate count of each test file.

    Args:
        report: The JSON report of one sweep.

    Returns:
        The count of each test file, keyed by the part of the identifier before `::`.
    """
    counted: "collections.Counter[str]" = collections.Counter()
    for case in candidates(report):
        counted[case.split("::")[0]] += 1
    return dict(sorted(counted.items()))


def settlement_files(directory: Path) -> List[Path]:
    """Return every settlement record of the directory, in name order.

    A record carries the `.json` suffix. The census opens no Markdown file, so a page that
    describes the directory stays out of the result.
    """
    if not directory.is_dir():
        return []
    return sorted(directory.glob("*.json"))


def read_claims(directory: Path) -> Dict[str, List[str]]:
    """Return the settlement records that claim each candidate.

    Args:
        directory: The directory that holds one record for each module group.

    Returns:
        The record names that claim each candidate identifier, keyed by the identifier.
    """
    claims: Dict[str, List[str]] = {}
    for path in settlement_files(directory):
        record = json.loads(path.read_text())
        for settlement in record.get("settlements", []):
            claims.setdefault(str(settlement["candidate"]), []).append(path.name)
    return {case: sorted(names) for case, names in sorted(claims.items())}


def settlement_faults(directory: Path) -> List[str]:
    """Return one sentence for each settlement that states no complete verdict.

    `FR-pre-release-validation-22` asks each settlement for one verdict: `repaired` with
    the case name, or `correct` with the reason the mutation cannot reach the case.

    Args:
        directory: The directory that holds one record for each module group.

    Returns:
        One sentence for each settlement that breaks the requirement.
    """
    faults: List[str] = []
    for path in settlement_files(directory):
        record = json.loads(path.read_text())
        for settlement in record.get("settlements", []):
            case = settlement.get("candidate", "<no candidate>")
            verdict = settlement.get("verdict")
            field = VERDICT_FIELDS.get(str(verdict))
            if field is None:
                faults.append(
                    "{} states the verdict {!r} for {}, and the requirement names "
                    "repaired and correct.".format(path.name, verdict, case)
                )
            elif not settlement.get(field):
                faults.append(
                    "{} states the verdict {} for {}, and it names no {}.".format(
                        path.name, verdict, case, field
                    )
                )
    return faults


def census(report_path: Path, directory: Path) -> Census:
    """Return the state of every candidate of one sweep.

    Args:
        report_path: The path of the JSON report the sweep wrote.
        directory: The directory that holds one settlement record for each module group.

    Returns:
        The counts, and every candidate that no record claims or that two records claim.
    """
    report = read_report(report_path)
    found = candidates(report)
    claims = read_claims(directory)
    return Census(
        commit=str(report.get("commit", "")),
        counts=counts_by_test_file(report),
        candidates=found,
        claimed_twice={case: names for case, names in claims.items() if len(names) > 1},
        unclaimed=[case for case in found if case not in claims],
        unknown={case: names for case, names in claims.items() if case not in set(found)},
        faults=settlement_faults(directory),
    )


def main() -> int:
    found = census(REPORT_PATH, SETTLEMENT_DIRECTORY)
    print("commit {}".format(found.commit))
    print("{} candidates over {} test files".format(len(found.candidates), len(found.counts)))
    for path, count in found.counts.items():
        print("{}: {}".format(path, count))
    print("{} candidates no record claims".format(len(found.unclaimed)))
    print("{} candidates two records claim".format(len(found.claimed_twice)))
    print("{} settlements of a case the report names no candidate".format(len(found.unknown)))
    for sentence in found.faults:
        print(sentence)
    return 0


if __name__ == "__main__":
    sys.exit(main())
