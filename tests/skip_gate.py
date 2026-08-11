"""The skip gate reads the report of every job that runs cases, and a case that ran nowhere fails.

**A skip is not a pass, and a case that runs nowhere is not a case.** #438 measured that
shape. `tests/test_round_entry_existence.py` reported a skip on every job of the matrix
from the day it was written, because the runner made a clone of depth 1 and the case read
a merge base that clone did not hold. Every job stayed green and the case refused nothing.

**One job reads no such case, because one job reads one environment.** A macOS case that
skips on Linux is correct, and a Linux case that skips on macOS is correct. The defect is
a case that skips in every environment. The union of the reports is the first reading that
tells the two apart, so this gate runs after every job that runs cases.

**The gate reads nine reports of five jobs, and #530 measured why the four outside the
matrix belong here.** The `test` job runs `pytest tests/ -m "not spec_validation"`, and
`tests/conftest.py` deselects the `installed_wheel` marker as well, so that job collects
4150 cases of the 6111 the suite holds. The `conformance` job holds the other 1918 and the
`installed-wheel` job holds the other 43. A read of 2026-08-10 reports that no report of
the `test` job holds any one of those 1961 cases, so a reader of the matrix alone reports a
clean corpus over 32 percent of the suite it cannot see.

**The `fuzz` job and the `samples` job add no case to that corpus, and the gate reads them
anyway.** The same read reports 127 cases of the `fuzz` job and 31 of the `samples` job,
and the `test` job holds every one of them. A gate bound to the jobs that one read finds
goes stale on the day a job changes its selection. This gate binds every job that runs
cases, and `tests/test_skip_gate.py` holds the workflow against that rule.

**A case one job alone selects reads one environment, and the gate says so.** The union
means `the suite ran this case nowhere`, and it means that over the jobs that select the
case rather than over nine reports. A conformance case therefore rests on one runner, and
the census names the report count of every case it lists. **A case no job selects at all
reaches no report**, so it is a different finding and this gate does not hold it.

**The reading is free of a new dependency.** `.github/workflows/test.yml` already writes
one JUnit report for each job that runs cases, with `pytest --junitxml`. A `testcase`
element with a `skipped` child names a case that job ran no assertion for. The `skip-gate`
job downloads the nine artifacts and this file holds the condition.

**An allowlist entry is permitted and it names a reason.** A case that needs a capture
grant no runner holds is a legitimate entry. An entry that names no reason is the defect
#524 exists to remove, so the gate fails such an entry whatever the reports hold.

**An entry names one case, or it names the prefix of a skip message.** A prefix entry
records one class of skip that the suite produces once for each parameter set of a cross
product. `not applicable:` is such a class: 143 parameter sets of
`tests/test_spec_validation.py` report it, because the vector holds no value for the method
and this project produces none. Those 143 sets belong to one function that ran 199 other
sets, so the function asserts and no repair of it is available. **A pass in place of the
skip would assert an equality over two empty sets**, which #524 put out of scope.

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
from dataclasses import dataclass, field
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
    "The skip gate reads the report of every job that runs cases, and a case that ran "
    "nowhere fails."
)

# The allowlist the runner reads. Each entry names one case and the environment limit that
# stops it on every job.
ALLOWLIST_PATH = REPO_ROOT / "tests" / "universal_skips.json"

# `.github/workflows/test.yml` runs ubuntu with Python 3.10, 3.11, 3.12 and 3.13, and macOS
# with 3.12. A union over fewer reports names fewer runs, so it can report a case as
# universal that another job ran. The gate therefore refuses a smaller report set rather
# than reading it. #575 dropped Python 3.9 and the count fell from 6.
MATRIX_JOB_COUNT = 5

# The four other jobs of `.github/workflows/test.yml` that run cases. Each one writes one
# JUnit report, so the download holds one report for each name here.
#
# **#530 measured the reach of each one on 2026-08-10.** `conformance` holds 1918 cases
# that no report of the `test` job holds, and `installed-wheel` holds 43 more. `fuzz` holds
# 127 and `samples` holds 31, and the `test` job holds every one of those 158.
CASE_JOBS_OUTSIDE_THE_MATRIX = ("conformance", "fuzz", "installed-wheel", "samples")

# The number of reports the download holds. An absent report is not a passed job, so the
# gate refuses a smaller set rather than reading it.
MINIMUM_REPORTS = MATRIX_JOB_COUNT + len(CASE_JOBS_OUTSIDE_THE_MATRIX)

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
    """The skip report of one job that runs cases."""

    label: str
    cases: Mapping[str, bool]
    # The reason each skipped case states. A prefix entry of the allowlist reads this map,
    # so a class of skip reaches the gate without one entry for each parameter set.
    messages: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Allowance:
    """One allowlist entry, as the tracked file states it.

    An entry names one case, or it names the prefix of a skip message. A prefix entry
    covers a class of skip that one cross product produces once for each parameter set.
    """

    case: str = ""
    reason: str = ""
    message_prefix: str = ""

    def label(self) -> str:
        """Return the text that names this entry in a gate reason.

        Returns:
            The case identifier, or the skip message prefix.
        """
        return self.case or f"the skip message prefix {self.message_prefix!r}"


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


def skip_message(element: ElementTree.Element) -> str:
    """Return the reason one `testcase` element states for its skip.

    `pytest --junitxml` writes the reason into the `message` attribute of the `skipped`
    child. A skip that states no reason reads as an empty message, which matches no prefix
    entry of the allowlist.

    Args:
        element: One `testcase` element.

    Returns:
        The reason, or an empty string where the element states none.
    """
    skipped = element.find(SKIPPED_ELEMENT)
    if skipped is None:
        return ""
    return skipped.get("message") or ""


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
    messages: Dict[str, str] = {}
    for element in tree.getroot().iter(CASE_ELEMENT):
        identifier = case_identifier(element)
        cases[identifier] = reports_a_skip(element)
        if cases[identifier]:
            messages[identifier] = skip_message(element)
    if not cases:
        raise ValueError(f"{path} holds no case, and a job that ran nothing is not a pass")
    return Report(label=path.parent.name, cases=cases, messages=messages)


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

    An entry names one case under `case`, or one class of skip under
    `skip_message_prefix`. The reader validates no reason. `gate_reasons` holds the reason
    rule, so a reasonless entry reaches the gate report rather than a parse failure.

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
        prefix = entry.get("skip_message_prefix")
        case = case if isinstance(case, str) else ""
        prefix = prefix if isinstance(prefix, str) else ""
        if not case and not prefix:
            raise ValueError(
                f"{path} holds an entry that names no case and no skip message prefix: {entry!r}"
            )
        reason = entry.get("reason")
        allowances.append(
            Allowance(
                case=case,
                reason=reason if isinstance(reason, str) else "",
                message_prefix=prefix,
            )
        )
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


def holders(reports: Sequence[Report], case: str) -> List[str]:
    """Return the label of every report that holds one case.

    The count is the job scope of that case. A case the whole matrix collects rests on six
    environments, and a case one job alone selects rests on one. #530 declined a job field
    on an allowlist entry because this reading derives the same scope from the reports.

    Args:
        reports: The reports of the download.
        case: The case identifier.

    Returns:
        The labels, in report order.
    """
    return [report.label for report in reports if case in report.cases]


def covering_prefix(
    reports: Sequence[Report], case: str, allowances: Sequence[Allowance]
) -> Optional[Allowance]:
    """Return the prefix entry that covers one universal skip, or None.

    An entry covers the case where every report that records a skip of it states a message
    that starts with the prefix. A report that states another message therefore takes the
    case back out of the class, so one class entry hides no second reason.

    Args:
        reports: The reports of the download.
        case: The case identifier.
        allowances: The allowlist entries.

    Returns:
        The first entry that covers the case, or None.
    """
    messages = [
        report.messages.get(case, "") for report in reports if report.cases.get(case, False)
    ]
    if not messages:
        return None
    for entry in allowances:
        if not entry.message_prefix:
            continue
        if all(message.startswith(entry.message_prefix) for message in messages):
            return entry
    return None


def gate_reasons(
    reports: Sequence[Report],
    allowances: Sequence[Allowance],
    minimum_reports: int = MINIMUM_REPORTS,
) -> List[str]:
    """Return every reason the gate holds against one set of reports.

    Args:
        reports: The reports of the download.
        allowances: The allowlist entries.
        minimum_reports: The number of reports the gate requires.

    Returns:
        The reasons. An empty list passes the gate.
    """
    reasons: List[str] = []
    if len(reports) < minimum_reports:
        reasons.append(
            f"the download holds {counted(len(reports), 'report')} of the "
            f"{minimum_reports} the workflow runs, and an absent report is not a passed "
            f"job: {[report.label for report in reports]}"
        )
    for entry in allowances:
        if entry.reason.strip():
            continue
        reasons.append(
            f"{ALLOWLIST_PATH.name} allows {entry.label()} and names no reason, so the "
            "entry states no environment limit a reader can hold it against"
        )
    allowed = {entry.case for entry in allowances if entry.case}
    for case in universal_skips(reports):
        if case in allowed:
            continue
        if covering_prefix(reports, case, allowances) is not None:
            continue
        scope = counted(len(holders(reports, case)), "report")
        reasons.append(
            f"{case} skipped on every job that selects it, so the suite ran it nowhere. "
            f"The download holds {scope} of it. Repair the case, or record the "
            f"environment limit in {ALLOWLIST_PATH.name}"
        )
    return reasons


def census_lines(reports: Sequence[Report], allowances: Sequence[Allowance]) -> List[str]:
    """Return the census of the reports, as one line for each universal skip.

    A verdict alone would leave the census to a log search. #524 states that the census is
    half of the deliverable, so the gate writes it on a pass and on a failure.

    **The census names the corpus size, because that number is the reach of the reader.**
    #530 measured the reach on 2026-08-10: the six reports of the matrix held 4150 cases
    and the ten reports held 6111. A reader of this line sees at once which jobs reached
    the gate.

    **A prefix entry reports its count and never its cases.** The `not applicable:` class
    holds 143 cases, and 143 near-identical lines would bury every case-level line under
    them.

    Args:
        reports: The reports of the download.
        allowances: The allowlist entries.

    Returns:
        The lines, ready for the job summary.
    """
    reason_of = {entry.case: entry.reason for entry in allowances if entry.case}
    cases = universal_skips(reports)
    corpus = {case for report in reports for case in report.cases}
    lines = [
        f"The skip gate read {counted(len(reports), 'report')} that hold "
        f"{counted(len(corpus), 'case')} between them, and found "
        f"{counted(len(cases), 'case')} that ran on no job."
    ]
    covered: Dict[str, List[str]] = {}
    for case in cases:
        entry = covering_prefix(reports, case, allowances)
        if entry is not None:
            covered.setdefault(entry.message_prefix, []).append(case)
            continue
        scope = f"held by {', '.join(holders(reports, case))}"
        reason = reason_of.get(case)
        if reason is None:
            lines.append(f"- {case}: no allowlist entry, {scope}")
        else:
            lines.append(f"- {case}: allowed, {scope}, {reason}")
    for prefix, group in sorted(covered.items()):
        lines.append(
            f"- {counted(len(group), 'case')}: allowed by the skip message prefix {prefix!r}"
        )
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
        default=MINIMUM_REPORTS,
        type=int,
        help="the number of reports the workflow runs",
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
