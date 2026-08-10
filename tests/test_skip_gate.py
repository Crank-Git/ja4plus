"""The cases of `tests/skip_gate.py`.

#524 built the gate and #438 is the measurement behind it.
`tests/test_round_entry_existence.py` reported a skip on every job of the matrix, and a
reader of a green run took that for a pass. This file holds the condition that refuses
such a case.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

import pytest

from tests.skip_gate import (
    ALLOWLIST_PATH,
    MATRIX_JOB_COUNT,
    Allowance,
    Report,
    census_lines,
    gate_reasons,
    main,
    read_allowlist,
    read_report,
    read_reports,
    universal_skips,
)

# A case every job runs. It keeps a report from holding no case at all, which the reader
# refuses, so a fixture can leave one case out of one job on purpose.
ANCHOR = "tests.test_anchor::test_the_job_ran_something"

JOB_LABELS = [f"test-results-ubuntu-latest-py3.{minor}" for minor in range(9, 14)] + [
    "test-results-macos-latest-py3.12"
]

CaseMap = Mapping[str, Optional[str]]
JobMap = Mapping[str, CaseMap]


def junit_report(cases: CaseMap) -> str:
    """Return the text of one JUnit report.

    Args:
        cases: The identifier of each case against its skip reason, or None where the
            job ran that case.

    Returns:
        The report text, in the shape `pytest --junitxml` writes.
    """
    lines = ['<?xml version="1.0" encoding="utf-8"?>', "<testsuites>", "  <testsuite>"]
    for identifier, reason in cases.items():
        classname, name = identifier.rsplit("::", 1)
        inner = "" if reason is None else f'<skipped type="pytest.skip">{reason}</skipped>'
        lines.append(f'    <testcase classname="{classname}" name="{name}">{inner}</testcase>')
    lines += ["  </testsuite>", "</testsuites>", ""]
    return "\n".join(lines)


def write_reports(directory: Path, jobs: JobMap) -> Path:
    """Write one JUnit report for each named job, in the layout the download produces.

    Args:
        directory: The download target.
        jobs: The label of each job against its case map.

    Returns:
        The download target.
    """
    for label, cases in jobs.items():
        folder = directory / label
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "test-results.xml").write_text(junit_report(cases), encoding="utf-8")
    return directory


def six_jobs(cases: CaseMap) -> Dict[str, Dict[str, Optional[str]]]:
    """Return the same case map under the six labels of the matrix.

    Args:
        cases: The case map every job reports. The anchor case joins it.

    Returns:
        A map of six job labels against that case map.
    """
    jobs: Dict[str, Dict[str, Optional[str]]] = {}
    for label in JOB_LABELS:
        entry: Dict[str, Optional[str]] = {ANCHOR: None}
        entry.update(cases)
        jobs[label] = entry
    return jobs


def allowance(case: str, reason: str) -> Allowance:
    """Return one allowlist entry.

    Args:
        case: The case identifier.
        reason: The environment limit that stops the case on every job.

    Returns:
        The entry.
    """
    return Allowance(case=case, reason=reason)


def reasons_for(
    tmp_path: Path,
    jobs: JobMap,
    allowances: Sequence[Allowance] = (),
    minimum: int = MATRIX_JOB_COUNT,
) -> List[str]:
    """Return every reason the gate holds against one set of reports.

    Args:
        tmp_path: The download target.
        jobs: The label of each job against its case map.
        allowances: The allowlist entries.
        minimum: The number of reports the gate requires.

    Returns:
        The reasons, in the order the gate produces them.
    """
    write_reports(tmp_path, jobs)
    return gate_reasons(read_reports(tmp_path), allowances, minimum_reports=minimum)


# --- The reader -------------------------------------------------------------------------


def test_the_reader_marks_a_case_the_job_skipped(tmp_path: Path) -> None:
    """A `skipped` child of a `testcase` element reports that the job ran no assertion."""
    path = tmp_path / "test-results.xml"
    path.write_text(junit_report({"tests.test_a.TestB::test_c": "no grant"}), encoding="utf-8")
    assert read_report(path).cases == {"tests.test_a.TestB::test_c": True}


def test_the_reader_marks_a_case_the_job_ran(tmp_path: Path) -> None:
    """A `testcase` element with no `skipped` child reports that the job ran the case."""
    path = tmp_path / "test-results.xml"
    path.write_text(junit_report({"tests.test_a::test_c": None}), encoding="utf-8")
    assert read_report(path).cases == {"tests.test_a::test_c": False}


def test_the_reader_labels_a_report_by_its_directory(tmp_path: Path) -> None:
    """The download writes one directory for each artifact, and that name names the job."""
    write_reports(tmp_path, {"test-results-macos-latest-py3.12": {ANCHOR: None}})
    assert [report.label for report in read_reports(tmp_path)] == [
        "test-results-macos-latest-py3.12"
    ]


def test_the_reader_finds_a_report_the_download_left_at_the_top(tmp_path: Path) -> None:
    """A pattern that matches one artifact extracts to the path and makes no directory."""
    (tmp_path / "test-results.xml").write_text(junit_report({ANCHOR: None}), encoding="utf-8")
    assert len(read_reports(tmp_path)) == 1


def test_the_reader_refuses_a_report_that_holds_no_case(tmp_path: Path) -> None:
    """An empty report reads as a job that ran nothing, and an absence is not a pass."""
    path = tmp_path / "test-results.xml"
    path.write_text('<?xml version="1.0"?>\n<testsuites><testsuite/></testsuites>\n', "utf-8")
    with pytest.raises(ValueError):
        read_report(path)


def test_the_reader_refuses_a_directory_that_holds_no_report(tmp_path: Path) -> None:
    """A download that wrote nothing must fail the gate rather than report an empty union."""
    with pytest.raises(ValueError):
        read_reports(tmp_path)


# --- The condition ----------------------------------------------------------------------


def test_a_case_that_every_job_skipped_reads_as_a_universal_skip(tmp_path: Path) -> None:
    """This is the shape #438 measured, and the gate exists to name it."""
    write_reports(tmp_path, six_jobs({"tests.test_a::test_c": "this clone holds no parent"}))
    assert universal_skips(read_reports(tmp_path)) == ["tests.test_a::test_c"]


def test_a_case_that_one_job_ran_reads_as_no_universal_skip(tmp_path: Path) -> None:
    """A macOS case that skips on Linux runs somewhere, so the gate passes it."""
    jobs = six_jobs({"tests.test_a::test_c": "the /dev/bpf devices are macOS"})
    jobs["test-results-macos-latest-py3.12"]["tests.test_a::test_c"] = None
    write_reports(tmp_path, jobs)
    assert universal_skips(read_reports(tmp_path)) == []


def test_a_case_that_one_job_alone_holds_and_skips_reads_as_a_universal_skip(
    tmp_path: Path,
) -> None:
    """A case the other jobs never collect still ran nowhere, so an absence adds no pass."""
    jobs = six_jobs({})
    jobs["test-results-macos-latest-py3.12"]["tests.test_a::test_c"] = "a limit"
    write_reports(tmp_path, jobs)
    assert universal_skips(read_reports(tmp_path)) == ["tests.test_a::test_c"]


# --- The gate ---------------------------------------------------------------------------


def test_the_gate_fails_a_case_that_skips_in_every_job(tmp_path: Path) -> None:
    """The failing case of #524: a case that runs nowhere refuses the merge."""
    reasons = reasons_for(tmp_path, six_jobs({"tests.test_a::test_c": "a limit"}))
    assert len(reasons) == 1
    assert "tests.test_a::test_c" in reasons[0]


def test_the_gate_passes_the_same_case_under_an_allowlist_entry(tmp_path: Path) -> None:
    """A capture grant no runner holds is a legitimate entry, and #524 states it."""
    reasons = reasons_for(
        tmp_path,
        six_jobs({"tests.test_a::test_c": "a limit"}),
        [allowance("tests.test_a::test_c", "no runner grants the capture privilege")],
    )
    assert reasons == []


def test_the_gate_fails_an_allowlist_entry_that_names_no_reason(tmp_path: Path) -> None:
    """An entry with no reason is the defect #524 exists to remove."""
    reasons = reasons_for(
        tmp_path,
        six_jobs({"tests.test_a::test_c": "a limit"}),
        [allowance("tests.test_a::test_c", "   ")],
    )
    assert len(reasons) == 1
    assert "names no reason" in reasons[0]


def test_the_gate_fails_a_reasonless_entry_whose_case_runs_somewhere(tmp_path: Path) -> None:
    """The reason rule reads the entry alone, so no report state hides such an entry."""
    reasons = reasons_for(
        tmp_path,
        six_jobs({"tests.test_a::test_c": None}),
        [allowance("tests.test_a::test_c", "")],
    )
    assert len(reasons) == 1
    assert "names no reason" in reasons[0]


def test_the_gate_fails_a_report_set_smaller_than_the_matrix(tmp_path: Path) -> None:
    """An absent report is not a passed job, and a smaller union proves fewer runs."""
    reasons = reasons_for(tmp_path, {"test-results-ubuntu-latest-py3.9": {ANCHOR: None}})
    assert len(reasons) == 1
    assert "1 report" in reasons[0]


def test_the_gate_passes_the_suite_that_runs_every_case(tmp_path: Path) -> None:
    """A green direction that nothing proves is a gate that may pass always."""
    assert reasons_for(tmp_path, six_jobs({"tests.test_a::test_c": None})) == []


# --- The allowlist ------------------------------------------------------------------------


def test_the_allowlist_reader_holds_the_case_and_the_reason(tmp_path: Path) -> None:
    """The gate reads a JSON object with an `entries` list."""
    path = tmp_path / "universal_skips.json"
    path.write_text(
        json.dumps({"entries": [{"case": "tests.test_a::test_c", "reason": "a limit"}]}),
        encoding="utf-8",
    )
    assert read_allowlist(path) == [Allowance(case="tests.test_a::test_c", reason="a limit")]


def test_the_allowlist_reader_keeps_a_missing_reason(tmp_path: Path) -> None:
    """The reader reports the entry as it stands, and the gate holds the reason rule."""
    path = tmp_path / "universal_skips.json"
    path.write_text(json.dumps({"entries": [{"case": "tests.test_a::test_c"}]}), encoding="utf-8")
    assert read_allowlist(path) == [Allowance(case="tests.test_a::test_c", reason="")]


def test_the_tracked_allowlist_names_a_reason_on_every_entry() -> None:
    """The tracked file is the one the runner reads, so a case holds it here too."""
    nameless = [entry.case for entry in read_allowlist(ALLOWLIST_PATH) if not entry.reason.strip()]
    assert nameless == [], f"{ALLOWLIST_PATH.name} holds an entry that names no reason: {nameless}"


# --- The census ---------------------------------------------------------------------------


def test_the_census_names_every_universal_skip(tmp_path: Path) -> None:
    """A gate that printed a verdict alone would leave the census to a log search."""
    write_reports(tmp_path, six_jobs({"tests.test_a::test_c": "a limit"}))
    lines = census_lines(read_reports(tmp_path), [allowance("tests.test_a::test_c", "a limit")])
    assert any("tests.test_a::test_c" in line for line in lines)


# --- The command ---------------------------------------------------------------------------


def test_the_command_exits_one_on_a_universal_skip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The job reads the exit status, so a red gate must exit non-zero."""
    reports = write_reports(tmp_path / "reports", six_jobs({"tests.test_a::test_c": "a limit"}))
    allowlist = tmp_path / "empty.json"
    allowlist.write_text(json.dumps({"entries": []}), encoding="utf-8")
    status = main(["--reports", str(reports), "--allowlist", str(allowlist)])
    assert status == 1
    assert "tests.test_a::test_c" in capsys.readouterr().out


def test_the_command_exits_zero_where_every_case_runs(tmp_path: Path) -> None:
    """A gate that never exits zero blocks every merge and reads as broken."""
    reports = write_reports(tmp_path / "reports", six_jobs({"tests.test_a::test_c": None}))
    allowlist = tmp_path / "empty.json"
    allowlist.write_text(json.dumps({"entries": []}), encoding="utf-8")
    assert main(["--reports", str(reports), "--allowlist", str(allowlist)]) == 0


def test_the_reader_holds_no_case_of_a_worker_worktree(tmp_path: Path) -> None:
    """#473 measured a reader that walked the checkout and picked up a worker worktree.

    The gate reads the reports of one download directory and never the checkout, so the
    case list does not grow with the number of live workers.
    """
    hidden = tmp_path / ".claude" / "worktrees" / "agent-1"
    hidden.mkdir(parents=True)
    (hidden / "test-results.xml").write_text(
        junit_report({"tests.test_other::test_c": None}), encoding="utf-8"
    )
    write_reports(tmp_path / "reports", six_jobs({"tests.test_a::test_c": None}))
    reports = read_reports(tmp_path / "reports")
    assert all("tests.test_other::test_c" not in report.cases for report in reports)


def test_the_report_type_is_frozen() -> None:
    """A reader that changed one report would move the union under the next reader."""
    report = Report(label="a", cases={"tests.test_a::test_c": True})
    with pytest.raises(Exception):
        report.label = "b"  # type: ignore[misc]
