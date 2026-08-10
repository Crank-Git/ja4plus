"""The skip gate reads the report of every matrix job, and a case that ran nowhere fails.

**A skip is not a pass, and a case that runs nowhere is not a case.** #438 measured that
shape. `tests/test_round_entry_existence.py` reported a skip on every job of the matrix
from the day it was written, because the runner made a clone of depth 1 and the case read
a merge base that clone did not hold. Every job stayed green and the case refused nothing.

**One job reads no such case, because one job reads one environment.** A macOS case that
skips on Linux is correct, and a Linux case that skips on macOS is correct. The defect is
a case that skips in every environment. The union of the six reports of the matrix is the
first reading that tells the two apart, so this gate runs after the matrix and reads all
six reports together.

**The reading is free of a new dependency.** `.github/workflows/test.yml` already writes
one JUnit report for each job of the matrix, with `pytest --junitxml`. A `testcase`
element with a `skipped` child names a case that job ran no assertion for. The `skip-gate`
job downloads the six artifacts and this file holds the condition.

**An allowlist entry is permitted and it names a reason.** A case that needs a capture
grant no runner holds is a legitimate entry. An entry that names no reason is the defect
#524 exists to remove, so the gate fails such an entry whatever the reports hold.

**The gate reads one download directory and never the checkout.** #473 measured a reader
that walked the repository root and picked up a worker worktree under `.claude/`, so its
corpus grew with the number of live workers. A read of the checkout would repeat that.

`.claude/rules/batch-gate.md` states the procedure. This file holds the condition, and
`tests/test_skip_gate.py` holds this file. It imports nothing from `ja4plus` and it
produces no fingerprint.

Read the gate against one download directory:

```bash
python -m tests.skip_gate --reports skip-reports
```
"""

from __future__ import annotations

import argparse
import json
import sys

# **The parser reads an artifact of the same workflow run and never a third-party file.**
# `xml.etree.ElementTree` resolves no external entity, and the entity-expansion attacks the
# Python documentation lists need a declaration this input never carries. #524 declined
# `defusedxml` on that reading, because the gate takes no new dependency.
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent

# The description the command line reports.
#
# **`python -OO` sets `__doc__` to None on every module.** A parser that read the module
# docstring here raised `AttributeError` under that interpreter, and it read no argument at
# all. `tests/test_parser_description.py` holds every parser of the repository against that
# run.
DESCRIPTION = (
    "The skip gate reads the report of every matrix job, and a case that ran nowhere fails."
)

# The allowlist the runner reads. Each entry names one case and the environment limit that
# stops it on every job.
ALLOWLIST_PATH = REPO_ROOT / "tests" / "universal_skips.json"

# `.github/workflows/test.yml` runs ubuntu with Python 3.9, 3.10, 3.11, 3.12 and 3.13, and
# macOS with 3.12. A union over fewer reports names fewer runs, so it can report a case as
# universal that another job ran. The gate therefore refuses a smaller report set rather
# than reading it.
MATRIX_JOB_COUNT = 6

# `pytest --junitxml` writes one `testcase` element for each case, and a `skipped` child
# where the case reported a skip.
CASE_ELEMENT = "testcase"

SKIPPED_ELEMENT = "skipped"

# **`pytest --junitxml` writes an expected failure as a `skipped` element too, and that
# element records a case that ran.** The element carries `type="pytest.xfail"` there and
# `type="pytest.skip"` for a real skip. A reader that ignored the type would report every
# registered FoxIO deviation as a case the suite runs nowhere. The first run of this gate
# measured it: 8 of the 19 cases it named were expected failures.
#
# **A type the reader does not know counts as a skip**, because an absence is not a pass.
XFAIL_TYPE = "pytest.xfail"


@dataclass(frozen=True)
class Report:
    """The skip report of one job of the matrix."""

    label: str
    cases: Mapping[str, bool]


@dataclass(frozen=True)
class Allowance:
    """One allowlist entry, as the tracked file states it."""

    case: str
    reason: str


def case_identifier(element: ElementTree.Element) -> str:
    """Return the identifier of one case, in the form `<classname>::<name>`.

    The provider runs one report for each job, so the identifier must read the same on
    every job. `classname` and `name` are the two attributes `pytest --junitxml` writes,
    and neither one carries the operating system or the interpreter version.

    Args:
        element: One `testcase` element.

    Returns:
        The identifier.

    Raises:
        ValueError: The element carries no `classname` or no `name`.
    """
    classname = element.get("classname")
    name = element.get("name")
    if not classname or not name:
        raise ValueError(
            f"a {CASE_ELEMENT} element carries no classname and name: {element.attrib}"
        )
    return f"{classname}::{name}"


def reports_a_skip(element: ElementTree.Element) -> bool:
    """Return True where one `testcase` element records a skip rather than a run.

    An expected failure carries a `skipped` element as well, and it records a case the job
    ran. `XFAIL_TYPE` names that shape, and every other `skipped` element reads as a skip.

    Args:
        element: One `testcase` element.

    Returns:
        True where the job ran no assertion of the case.
    """
    skipped = element.find(SKIPPED_ELEMENT)
    if skipped is None:
        return False
    return skipped.get("type") != XFAIL_TYPE


def read_report(path: Path) -> Report:
    """Return the skip state of every case one JUnit report holds.

    Args:
        path: The report file.

    Returns:
        The report, labelled by the directory the download wrote it into.

    Raises:
        ValueError: The file is no readable report, or it holds no case.
    """
    try:
        tree = ElementTree.parse(path)
    except ElementTree.ParseError as error:
        raise ValueError(f"{path} is no readable JUnit report: {error}") from error
    cases: Dict[str, bool] = {}
    for element in tree.getroot().iter(CASE_ELEMENT):
        cases[case_identifier(element)] = reports_a_skip(element)
    if not cases:
        raise ValueError(f"{path} holds no case, and a job that ran nothing is not a pass")
    return Report(label=path.parent.name, cases=cases)


def read_reports(directory: Path) -> List[Report]:
    """Return one report for each file the download wrote below one directory.

    The download writes one directory for each artifact. A pattern that matches one
    artifact extracts to the path itself, so the reader searches below the directory
    rather than one level down.

    Args:
        directory: The download target.

    Returns:
        The reports, ordered by file path.

    Raises:
        ValueError: The directory holds no report.
    """
    paths = sorted(path for path in directory.rglob("*.xml") if path.is_file())
    if not paths:
        raise ValueError(f"{directory} holds no report, and an absent report is not a passed job")
    return [read_report(path) for path in paths]


def universal_skips(reports: Sequence[Report]) -> List[str]:
    """Return every case that no report records as run.

    A case that one report leaves out counts as no run of that case. A job that does not
    collect a case runs no assertion for it, so an absence adds no pass.

    Args:
        reports: The reports of the matrix.

    Returns:
        The case identifiers, in sorted order.
    """
    seen = set()
    ran = set()
    for report in reports:
        for case, skipped in report.cases.items():
            seen.add(case)
            if not skipped:
                ran.add(case)
    return sorted(seen - ran)


def read_allowlist(path: Path = ALLOWLIST_PATH) -> List[Allowance]:
    """Return the entries of the allowlist, exactly as the file states them.

    The reader validates no reason. `gate_reasons` holds the reason rule, so a reasonless
    entry reaches the gate report rather than a parse failure.

    Args:
        path: The allowlist file.

    Returns:
        The entries, in file order.

    Raises:
        ValueError: The file is no JSON object with an `entries` list.
    """
    body = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(body, dict):
        raise ValueError(f"{path} holds no JSON object")
    entries = body.get("entries")
    if not isinstance(entries, list):
        raise ValueError(f"{path} holds no `entries` list")
    allowances: List[Allowance] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError(f"{path} holds an entry that is no object: {entry!r}")
        case = entry.get("case")
        if not isinstance(case, str) or not case:
            raise ValueError(f"{path} holds an entry that names no case: {entry!r}")
        reason = entry.get("reason")
        allowances.append(Allowance(case=case, reason=reason if isinstance(reason, str) else ""))
    return allowances


def counted(count: int, noun: str) -> str:
    """Return the count beside the noun, in the singular form or the plural form.

    The job summary is the census a reader reads, and `1 reports` or `6 report` costs that
    reader a second look at a line the gate exists to make plain.

    Args:
        count: The number of things.
        noun: The noun, in the singular form, whose plural form takes `s`.

    Returns:
        The count and the noun.
    """
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def gate_reasons(
    reports: Sequence[Report],
    allowances: Sequence[Allowance],
    minimum_reports: int = MATRIX_JOB_COUNT,
) -> List[str]:
    """Return every reason the gate holds against one set of reports.

    Args:
        reports: The reports of the matrix.
        allowances: The allowlist entries.
        minimum_reports: The number of reports the gate requires.

    Returns:
        The reasons. An empty list passes the gate.
    """
    reasons: List[str] = []
    if len(reports) < minimum_reports:
        reasons.append(
            f"the download holds {counted(len(reports), 'report')} of the "
            f"{minimum_reports} the matrix runs, and an absent report is not a passed job: "
            f"{[report.label for report in reports]}"
        )
    nameless = [entry.case for entry in allowances if not entry.reason.strip()]
    for case in nameless:
        reasons.append(
            f"{ALLOWLIST_PATH.name} allows {case} and names no reason, so the entry states "
            "no environment limit a reader can hold it against"
        )
    allowed = {entry.case for entry in allowances}
    for case in universal_skips(reports):
        if case in allowed:
            continue
        reasons.append(
            f"{case} skipped on every job of the matrix, so the suite ran it nowhere. "
            f"Repair the case, or record the environment limit in {ALLOWLIST_PATH.name}"
        )
    return reasons


def census_lines(reports: Sequence[Report], allowances: Sequence[Allowance]) -> List[str]:
    """Return the census of the reports, as one line for each universal skip.

    A verdict alone would leave the census to a log search. #524 states that the census is
    half of the deliverable, so the gate writes it on a pass and on a failure.

    Args:
        reports: The reports of the matrix.
        allowances: The allowlist entries.

    Returns:
        The lines, ready for the job summary.
    """
    reason_of = {entry.case: entry.reason for entry in allowances}
    cases = universal_skips(reports)
    lines = [
        f"The skip gate read {counted(len(reports), 'report')} and found "
        f"{counted(len(cases), 'case')} that ran on no job of the matrix."
    ]
    for case in cases:
        reason = reason_of.get(case)
        if reason is None:
            lines.append(f"- {case}: no allowlist entry")
        else:
            lines.append(f"- {case}: allowed, {reason}")
    return lines


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Read the gate and return the exit status.

    Args:
        argv: The command arguments, or None to read `sys.argv`.

    Returns:
        0 where the gate passes, and 1 where it holds a reason.
    """
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("--reports", required=True, type=Path, help="the download target")
    parser.add_argument("--allowlist", default=ALLOWLIST_PATH, type=Path, help="the allowlist")
    parser.add_argument(
        "--minimum-reports",
        default=MATRIX_JOB_COUNT,
        type=int,
        help="the number of reports the matrix runs",
    )
    arguments = parser.parse_args(argv)
    try:
        reports = read_reports(arguments.reports)
        allowances = read_allowlist(arguments.allowlist)
    except (OSError, ValueError) as error:
        print(f"The skip gate read nothing: {error}")
        return 1
    for line in census_lines(reports, allowances):
        print(line)
    reasons = gate_reasons(reports, allowances, minimum_reports=arguments.minimum_reports)
    for reason in reasons:
        print(f"::error::{reason}")
    return 1 if reasons else 0


if __name__ == "__main__":
    sys.exit(main())
