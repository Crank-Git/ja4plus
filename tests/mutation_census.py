"""Count the candidates the mutation sweeps left open, and name who settles each one.

Each sweep writes one JSON report under `docs/mutation_reports/`. A candidate is one test
case that no mutation of that sweep makes fail, and a candidate needs a reader. This
module counts the candidates of each test file, and it reports which settlement record
under `docs/mutation_settlements/` claims each one.

**The census reads a directory of reports and not one report.** #411 measured the
whole-package sweep at 3545 mutations and 72.75 seconds for one suite run, which is 71.6
hours, and the project manager partitioned the sweep on 2026-08-09. #412, #413 and #414
each run one sweep over one module group and write one report.

**A candidate is keyed by the sweep that named it and by the case.** Two sweeps may name
the same case, and that is one candidate for each sweep and not a duplicate claim.

**The union of the per-module sweeps is larger than the candidate set of one whole-package
sweep.** A whole-package sweep names the cases that no mutation of any module kills. A
sweep of module X names the cases that no mutation of X kills, and a case that module Y
kills still reaches that list. **The union is the correct input for settlement, and a
reader who compares the two counts reads a regression that did not happen.**

**The census groups by test file and not by module.** `tests/mutation_sweep.py:593` builds
one flat candidate list over every module one sweep read, so no module owns a candidate.
The one grouping the report offers splits each identifier at `::`, at
`tests/mutation_sweep.py:396`.

**The census reads the JSON reports and it opens no Markdown file.** A Markdown report is
one page, and a count taken from its lines counts the page layout.
`FR-pre-release-validation-19` states the rule.

**The census reads both directories rather than one shared file.** #412, #413 and #414 run
at the same time, and one shared table makes each of them conflict with the other two.

Run it from the repository root:

    python tests/mutation_census.py
"""

from __future__ import annotations

import collections
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set

REPO_ROOT = Path(__file__).resolve().parent.parent

# #412, #413 and #414 write one report each. The stem of the file names the sweep.
REPORT_DIRECTORY = REPO_ROOT / "docs" / "mutation_reports"

SETTLEMENT_DIRECTORY = REPO_ROOT / "docs" / "mutation_settlements"

# `FR-pre-release-validation-22` names two verdicts, and each one carries its own field.
VERDICT_FIELDS = {"repaired": "case", "correct": "reason"}


@dataclass(frozen=True, order=True)
class Candidate:
    """One case that one sweep named a candidate."""

    sweep: str
    case: str

    @property
    def test_file(self) -> str:
        """Return the test file of the case, which is the part before `::`."""
        return self.case.split("::")[0]


@dataclass
class Census:
    """The state of every candidate of every sweep."""

    commits: Dict[str, str]
    counts: Dict[str, int]
    candidates: List[Candidate]
    claimed_twice: Dict[Candidate, List[str]]
    unclaimed: List[Candidate]
    unknown: Dict[Candidate, List[str]]
    faults: List[str]


def _json_files(directory: Path) -> List[Path]:
    """Return every JSON file of the directory, in name order.

    The census opens no Markdown file, so a page that describes the directory stays out of
    the result.
    """
    if not directory.is_dir():
        return []
    return sorted(directory.glob("*.json"))


def read_reports(directory: Path) -> Dict[str, Dict[str, object]]:
    """Return the report of each sweep, keyed by the stem of its file.

    Args:
        directory: The directory that holds one report for each sweep.

    Returns:
        The report of each sweep. A directory that holds no file gives an empty result.
    """
    return {path.stem: json.loads(path.read_text()) for path in _json_files(directory)}


def candidates(reports: Dict[str, Dict[str, object]]) -> List[Candidate]:
    """Return every candidate of every sweep, in sweep order and then in case order."""
    found: List[Candidate] = []
    for sweep in sorted(reports):
        for case in reports[sweep]["candidates"]:  # type: ignore[union-attr]
            found.append(Candidate(sweep, str(case)))
    return found


def modules_swept(reports: Dict[str, Dict[str, object]]) -> Set[str]:
    """Return every module the sweeps together read.

    `FR-pre-release-validation-16` asks that set to hold every tracked module of the
    package.
    """
    found: Set[str] = set()
    for report in reports.values():
        for entry in report["modules"]:  # type: ignore[union-attr]
            found.add(str(entry["module"]))
    return found


def counts_by_test_file(reports: Dict[str, Dict[str, object]]) -> Dict[str, int]:
    """Return the candidate count of each test file, over every sweep.

    A case two sweeps name counts twice, because each sweep names its own candidate and
    each one needs its own settlement.

    Args:
        reports: The report of each sweep, keyed by sweep.

    Returns:
        The count of each test file, keyed by the part of the identifier before `::`.
    """
    counted: "collections.Counter[str]" = collections.Counter()
    for candidate in candidates(reports):
        counted[candidate.test_file] += 1
    return dict(sorted(counted.items()))


def read_claims(directory: Path) -> Dict[Candidate, List[str]]:
    """Return the settlement records that claim each candidate.

    A record names the sweep it settles, and every settlement of that record belongs to
    that sweep.

    Args:
        directory: The directory that holds one record for each module group.

    Returns:
        The record names that claim each candidate, keyed by the candidate.
    """
    claims: Dict[Candidate, List[str]] = {}
    for path in _json_files(directory):
        record = json.loads(path.read_text())
        sweep = str(record.get("sweep", ""))
        for settlement in record.get("settlements", []):
            key = Candidate(sweep, str(settlement["candidate"]))
            claims.setdefault(key, []).append(path.name)
    return {key: sorted(names) for key, names in sorted(claims.items())}


def settlement_faults(directory: Path, sweeps: Set[str]) -> List[str]:
    """Return one sentence for each settlement record that breaks its own schema.

    `FR-pre-release-validation-22` asks each settlement for one verdict: `repaired` with
    the case name, or `correct` with the reason the mutation cannot reach the case. A
    record also names one sweep, and a record that names a sweep no report holds settles
    nothing a reader can find.

    Args:
        directory: The directory that holds one record for each module group.
        sweeps: The name of every sweep a report holds.

    Returns:
        One sentence for each fault.
    """
    faults: List[str] = []
    for path in _json_files(directory):
        record = json.loads(path.read_text())
        sweep = str(record.get("sweep", ""))
        if sweep not in sweeps:
            faults.append(
                "{} settles the sweep {!r}, and no report of the directory holds it.".format(
                    path.name, sweep
                )
            )
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


def census(report_directory: Path, settlement_directory: Path) -> Census:
    """Return the state of every candidate of every sweep.

    Args:
        report_directory: The directory that holds one JSON report for each sweep.
        settlement_directory: The directory that holds one settlement record for each
            module group.

    Returns:
        The counts, and every candidate that no record claims or that two records claim.
    """
    reports = read_reports(report_directory)
    found = candidates(reports)
    claims = read_claims(settlement_directory)
    # The membership test runs once for each claim, so the set is built once. The sweeps
    # together name more than a thousand candidates.
    named = set(found)
    return Census(
        commits={sweep: str(report.get("commit", "")) for sweep, report in sorted(reports.items())},
        counts=counts_by_test_file(reports),
        candidates=found,
        claimed_twice={key: names for key, names in claims.items() if len(names) > 1},
        unclaimed=[key for key in found if key not in claims],
        unknown={key: names for key, names in claims.items() if key not in named},
        faults=settlement_faults(settlement_directory, set(reports)),
    )


def main() -> int:
    found = census(REPORT_DIRECTORY, SETTLEMENT_DIRECTORY)
    for sweep, commit in found.commits.items():
        print("{} read commit {}".format(sweep, commit))
    print("{} candidates over {} test files".format(len(found.candidates), len(found.counts)))
    for path, count in found.counts.items():
        print("{}: {}".format(path, count))
    print("{} candidates no record claims".format(len(found.unclaimed)))
    print("{} candidates two records claim".format(len(found.claimed_twice)))
    print("{} settlements of a case no report names a candidate".format(len(found.unknown)))
    for sentence in found.faults:
        print(sentence)
    return 0


if __name__ == "__main__":
    sys.exit(main())
