"""The cases of `tests/skip_gate.py`.

#524 built the gate and #438 is the measurement behind it.
`tests/test_round_entry_existence.py` reported a skip on every job of the matrix, and a
reader of a green run took that for a pass. This file holds the condition that refuses
such a case.

#530 widened the reach of the gate from the matrix jobs to the reports of the five jobs
that run cases. The section `The reach` holds `.github/workflows/test.yml` against
that rule.
"""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

import pytest

from tests.skip_gate import (
    ALLOWLIST_PATH,
    CASE_JOBS_OUTSIDE_THE_MATRIX,
    MATRIX_JOB_COUNT,
    MINIMUM_REPORTS,
    Allowance,
    Report,
    census_lines,
    counted,
    covering_prefix,
    gate_reasons,
    holders,
    main,
    read_allowlist,
    read_report,
    read_reports,
    universal_skips,
)

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "test.yml"

# The job that holds the gate. It runs no case of its own.
GATE_JOB = "skip-gate"

# A case every job runs. It keeps a report from holding no case at all, which the reader
# refuses, so a fixture can leave one case out of one job on purpose.
ANCHOR = "tests.test_anchor::test_the_job_ran_something"

JOB_LABELS = [f"test-results-ubuntu-latest-py3.{minor}" for minor in range(10, 14)] + [
    "test-results-macos-latest-py3.12"
]

# The artifact name of each job outside the matrix, as `.github/workflows/test.yml` writes
# it. The download labels each report by the directory it extracts into.
OTHER_JOB_LABELS = [
    "conformance-results",
    "fuzz-results",
    "installed-wheel-results",
    "sample-results",
]

CaseMap = Mapping[str, Optional[str]]
JobMap = Mapping[str, CaseMap]


def junit_report(cases: CaseMap) -> str:
    """Return the text of one JUnit report.

    `pytest --junitxml` writes the reason into the `message` attribute of the `skipped`
    element, and a prefix entry of the allowlist reads that attribute.

    Args:
        cases: The identifier of each case against its skip reason, or None where the
            job ran that case.

    Returns:
        The report text, in the shape `pytest --junitxml` writes.
    """
    lines = ['<?xml version="1.0" encoding="utf-8"?>', "<testsuites>", "  <testsuite>"]
    for identifier, reason in cases.items():
        classname, name = identifier.rsplit("::", 1)
        inner = (
            ""
            if reason is None
            else f'<skipped type="pytest.skip" message="{reason}">{reason}</skipped>'
        )
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


def matrix_jobs(cases: CaseMap) -> Dict[str, Dict[str, Optional[str]]]:
    """Return the same case map under every label of the matrix.

    Args:
        cases: The case map every job reports. The anchor case joins it.

    Returns:
        A map of every job label of the matrix against that case map.
    """
    jobs: Dict[str, Dict[str, Optional[str]]] = {}
    for label in JOB_LABELS:
        entry: Dict[str, Optional[str]] = {ANCHOR: None}
        entry.update(cases)
        jobs[label] = entry
    return jobs


def every_job(
    matrix_cases: CaseMap, other_cases: Optional[JobMap] = None
) -> Dict[str, Dict[str, Optional[str]]]:
    """Return the nine reports the download holds on a whole run.

    Args:
        matrix_cases: The case map every job of the matrix reports.
        other_cases: The case map of each job outside the matrix, by artifact name. A job
            the map leaves out reports the anchor case alone.

    Returns:
        A map of nine report labels against their case maps.
    """
    jobs = matrix_jobs(matrix_cases)
    for label in OTHER_JOB_LABELS:
        entry: Dict[str, Optional[str]] = {ANCHOR: None}
        entry.update((other_cases or {}).get(label, {}))
        jobs[label] = entry
    return jobs


def allowance(case: str, reason: str, message_prefix: str = "") -> Allowance:
    """Return one allowlist entry.

    Args:
        case: The case identifier, or an empty string on a prefix entry.
        reason: The environment limit that stops the case on every job.
        message_prefix: The prefix of the skip message the entry covers.

    Returns:
        The entry.
    """
    return Allowance(case=case, reason=reason, message_prefix=message_prefix)


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


def test_the_reader_reads_a_failed_case_as_a_run(tmp_path: Path) -> None:
    """A case that failed carries a `failure` element, and the job ran every assertion."""
    path = tmp_path / "test-results.xml"
    path.write_text(
        '<?xml version="1.0"?><testsuites><testsuite>'
        '<testcase classname="tests.test_a" name="test_c">'
        '<failure message="assert 1 == 2"/>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )
    assert read_report(path).cases == {"tests.test_a::test_c": False}


def test_the_reader_reads_a_case_that_raised_at_setup_as_a_run(tmp_path: Path) -> None:
    """A case whose fixture raised carries an `error` element, and it reported a state."""
    path = tmp_path / "test-results.xml"
    path.write_text(
        '<?xml version="1.0"?><testsuites><testsuite>'
        '<testcase classname="tests.test_a" name="test_c">'
        '<error message="fixture raised"/>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )
    assert read_report(path).cases == {"tests.test_a::test_c": False}


def test_the_reader_reads_an_expected_failure_as_a_run(tmp_path: Path) -> None:
    """An `xfail` carries a `skipped` element and it records a case the job ran.

    The first run of this gate named 8 expected failures among 19 cases, and every one of
    them is a registered FoxIO deviation that the suite runs on every job.
    """
    path = tmp_path / "test-results.xml"
    path.write_text(
        '<?xml version="1.0"?><testsuites><testsuite>'
        '<testcase classname="tests.test_a" name="test_c">'
        '<skipped type="pytest.xfail" message="issue #129"/>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )
    assert read_report(path).cases == {"tests.test_a::test_c": False}


def test_the_reader_reads_a_skip_type_it_does_not_know_as_a_skip(tmp_path: Path) -> None:
    """An absence is not a pass, so an unknown type reads as the state that fails."""
    path = tmp_path / "test-results.xml"
    path.write_text(
        '<?xml version="1.0"?><testsuites><testsuite>'
        '<testcase classname="tests.test_a" name="test_c">'
        '<skipped type="pytest.something_new"/>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )
    assert read_report(path).cases == {"tests.test_a::test_c": True}


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
    write_reports(tmp_path, matrix_jobs({"tests.test_a::test_c": "this clone holds no parent"}))
    assert universal_skips(read_reports(tmp_path)) == ["tests.test_a::test_c"]


def test_a_case_that_one_job_ran_reads_as_no_universal_skip(tmp_path: Path) -> None:
    """A macOS case that skips on Linux runs somewhere, so the gate passes it."""
    jobs = matrix_jobs({"tests.test_a::test_c": "the /dev/bpf devices are macOS"})
    jobs["test-results-macos-latest-py3.12"]["tests.test_a::test_c"] = None
    write_reports(tmp_path, jobs)
    assert universal_skips(read_reports(tmp_path)) == []


def test_a_case_that_one_job_alone_holds_and_skips_reads_as_a_universal_skip(
    tmp_path: Path,
) -> None:
    """A case the other jobs never collect still ran nowhere, so an absence adds no pass."""
    jobs = matrix_jobs({})
    jobs["test-results-macos-latest-py3.12"]["tests.test_a::test_c"] = "a limit"
    write_reports(tmp_path, jobs)
    assert universal_skips(read_reports(tmp_path)) == ["tests.test_a::test_c"]


# --- The gate ---------------------------------------------------------------------------


def test_the_gate_fails_a_case_that_skips_in_every_job(tmp_path: Path) -> None:
    """The failing case of #524: a case that runs nowhere refuses the merge."""
    reasons = reasons_for(tmp_path, matrix_jobs({"tests.test_a::test_c": "a limit"}))
    assert len(reasons) == 1
    assert "tests.test_a::test_c" in reasons[0]


def test_the_gate_passes_the_same_case_under_an_allowlist_entry(tmp_path: Path) -> None:
    """A capture grant no runner holds is a legitimate entry, and #524 states it."""
    reasons = reasons_for(
        tmp_path,
        matrix_jobs({"tests.test_a::test_c": "a limit"}),
        [allowance("tests.test_a::test_c", "no runner grants the capture privilege")],
    )
    assert reasons == []


def test_the_gate_fails_an_allowlist_entry_that_names_no_reason(tmp_path: Path) -> None:
    """An entry with no reason is the defect #524 exists to remove."""
    reasons = reasons_for(
        tmp_path,
        matrix_jobs({"tests.test_a::test_c": "a limit"}),
        [allowance("tests.test_a::test_c", "   ")],
    )
    assert len(reasons) == 1
    assert "names no reason" in reasons[0]


def test_the_gate_fails_a_reasonless_entry_whose_case_runs_somewhere(tmp_path: Path) -> None:
    """The reason rule reads the entry alone, so no report state hides such an entry."""
    reasons = reasons_for(
        tmp_path,
        matrix_jobs({"tests.test_a::test_c": None}),
        [allowance("tests.test_a::test_c", "")],
    )
    assert len(reasons) == 1
    assert "names no reason" in reasons[0]


def test_the_gate_fails_a_report_set_smaller_than_the_matrix(tmp_path: Path) -> None:
    """An absent report is not a passed job, and a smaller union proves fewer runs."""
    reasons = reasons_for(tmp_path, {"test-results-ubuntu-latest-py3.10": {ANCHOR: None}})
    assert len(reasons) == 1
    assert "1 report" in reasons[0]


def test_the_gate_passes_the_suite_that_runs_every_case(tmp_path: Path) -> None:
    """A green direction that nothing proves is a gate that may pass always."""
    assert reasons_for(tmp_path, matrix_jobs({"tests.test_a::test_c": None})) == []


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
    write_reports(tmp_path, matrix_jobs({"tests.test_a::test_c": "a limit"}))
    lines = census_lines(read_reports(tmp_path), [allowance("tests.test_a::test_c", "a limit")])
    assert any("tests.test_a::test_c" in line for line in lines)


# --- The command ---------------------------------------------------------------------------


def test_the_command_exits_one_on_a_universal_skip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The job reads the exit status, so a red gate must exit non-zero."""
    reports = write_reports(tmp_path / "reports", every_job({"tests.test_a::test_c": "a limit"}))
    allowlist = tmp_path / "empty.json"
    allowlist.write_text(json.dumps({"entries": []}), encoding="utf-8")
    status = main(["--reports", str(reports), "--allowlist", str(allowlist)])
    assert status == 1
    assert "tests.test_a::test_c" in capsys.readouterr().out


def test_the_command_exits_zero_where_every_case_runs(tmp_path: Path) -> None:
    """A gate that never exits zero blocks every merge and reads as broken."""
    reports = write_reports(tmp_path / "reports", every_job({"tests.test_a::test_c": None}))
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
    write_reports(tmp_path / "reports", matrix_jobs({"tests.test_a::test_c": None}))
    reports = read_reports(tmp_path / "reports")
    assert all("tests.test_other::test_c" not in report.cases for report in reports)


def test_the_census_names_a_count_in_the_form_that_matches_it() -> None:
    """`1 reports` and `6 report` each cost a reader of the job summary a second look."""
    assert counted(1, "report") == "1 report"
    assert counted(6, "report") == "6 reports"
    assert counted(0, "case") == "0 cases"


def test_the_report_type_is_frozen() -> None:
    """A reader that changed one report would move the union under the next reader."""
    report = Report(label="a", cases={"tests.test_a::test_c": True})
    with pytest.raises(Exception):
        report.label = "b"  # type: ignore[misc]


# --- The reach ----------------------------------------------------------------------------


def workflow_jobs() -> Dict[str, str]:
    """Return the text block of each top-level job of `.github/workflows/test.yml`.

    A job name sits at two spaces of indent below `jobs:`, and every key of a job sits at
    four or more. The reader takes no YAML parser, because no test dependency of this
    project holds one and `tests/test_installed_wheel_selection.py` reads the same file as
    text.

    Returns:
        The block of each job, by job name.
    """
    body = WORKFLOW_PATH.read_text(encoding="utf-8").split("\njobs:\n", 1)[1]
    blocks: Dict[str, str] = {}
    name = ""
    lines: List[str] = []
    for line in body.splitlines():
        match = re.match(r"^  ([A-Za-z][\w-]*):\s*$", line)
        if match:
            if name:
                blocks[name] = "\n".join(lines)
            name, lines = match.group(1), []
        elif name:
            lines.append(line)
    if name:
        blocks[name] = "\n".join(lines)
    return blocks


def commands_of(block: str) -> str:
    """Return the block with every comment line removed.

    A comment names a command that the job does not run. The `skip-gate` block names
    `pytest tests/ -m "not spec_validation"` in prose, and a reader of the raw block would
    read that job as a job that runs cases.

    Args:
        block: The text block of one job.

    Returns:
        The lines that carry no comment.
    """
    return "\n".join(line for line in block.splitlines() if not line.lstrip().startswith("#"))


def case_jobs() -> Dict[str, str]:
    """Return the block of every job of the workflow that runs cases.

    **Warning: this reader finds a job that names `pytest` in a command, and it finds no
    other job.** A job that ran cases through another program would reach no case below,
    and every count here would stay green while that job reached the gate nowhere.
    `test_the_skip_gate_job_depends_on_every_job_that_uploads_a_report` reads the same
    workflow from the artifact side, so a job that writes a report reaches the gate
    whatever command it runs.

    Returns:
        The block of each job whose steps run `pytest`, by job name.
    """
    return {
        name: block for name, block in workflow_jobs().items() if "pytest" in commands_of(block)
    }


def report_jobs() -> Dict[str, str]:
    """Return the block of every job of the workflow that uploads a report.

    Returns:
        The block of each job whose steps upload an artifact, by job name.
    """
    return {
        name: block
        for name, block in workflow_jobs().items()
        if "upload-artifact" in commands_of(block)
    }


def test_the_workflow_reader_finds_the_jobs_the_file_holds() -> None:
    """A reader that found nothing passes every case below on an empty set."""
    names = set(workflow_jobs())
    assert {"lint", "test", GATE_JOB, "fuzz", "samples", "installed-wheel", "conformance"} <= names


def test_every_job_that_runs_cases_writes_one_report() -> None:
    """The gate reads reports, so a job that writes none reaches it nowhere."""
    for name, block in case_jobs().items():
        assert "--junitxml=" in block, f"the {name} job runs cases and writes no JUnit report"
        assert "upload-artifact" in block, f"the {name} job writes a report and uploads none"


def test_the_skip_gate_job_depends_on_every_job_that_runs_cases() -> None:
    """A job the gate does not wait for reaches the download with no report.

    This is the reading #530 exists to build. The `test` job collects 4150 cases of the
    6111 the suite holds, and a gate behind that job alone reports a clean corpus over the
    1961 it cannot see.
    """
    block = workflow_jobs()[GATE_JOB]
    match = re.search(r"^    needs: \[([^\]]*)\]$", block, re.M)
    assert match is not None, f"the {GATE_JOB} job states no needs list"
    named = {name.strip() for name in match.group(1).split(",")}
    assert named == set(case_jobs()), f"the {GATE_JOB} job waits for {named}"


def test_the_skip_gate_job_depends_on_every_job_that_uploads_a_report() -> None:
    """The reader of `case_jobs` finds a `pytest` command, and this one finds an artifact.

    A job that ran cases through another program would reach `case_jobs` nowhere, and every
    count that rests on that reader would stay green. This case reads the artifact instead,
    which is the thing the gate consumes.
    """
    block = workflow_jobs()[GATE_JOB]
    match = re.search(r"^    needs: \[([^\]]*)\]$", block, re.M)
    assert match is not None, f"the {GATE_JOB} job states no needs list"
    named = {name.strip() for name in match.group(1).split(",")}
    assert set(report_jobs()) <= named, f"the {GATE_JOB} job waits for {named}"


def test_the_gate_requires_one_report_for_each_job_that_runs_cases() -> None:
    """An absent report is not a passed job, so the count follows the workflow."""
    outside = sorted(set(case_jobs()) - {"test"})
    assert outside == sorted(CASE_JOBS_OUTSIDE_THE_MATRIX)
    assert MINIMUM_REPORTS == MATRIX_JOB_COUNT + len(outside)


def test_the_download_pattern_matches_the_artifact_name_of_every_job() -> None:
    """A report the pattern misses never reaches the gate, and the gate then reads less."""
    block = workflow_jobs()[GATE_JOB]
    pattern = re.search(r'^          pattern: "?([^"\n]+)"?$', block, re.M)
    assert pattern is not None, f"the {GATE_JOB} job states no download pattern"
    names = []
    for job_block in case_jobs().values():
        names += re.findall(r"upload-artifact@[^\n]*\n\s*with:\n\s*name: (\S+)", job_block)
    assert len(names) == len(case_jobs()), f"the reader found the artifact names {names}"
    for name in names:
        assert fnmatch.fnmatch(name, pattern.group(1)), f"{pattern.group(1)} misses {name}"


def test_a_case_that_one_job_outside_the_matrix_holds_and_skips_fails_the_gate(
    tmp_path: Path,
) -> None:
    """This is the case the matrix-report reader of #524 accepted and this reader refuses.

    The `conformance` job runs `pytest tests/ -m spec_validation`, and every other job
    deselects that marker. A spec_validation case that skips there therefore ran nowhere,
    and no report of the `test` job holds it at all.
    """
    conformance = {"conformance-results": {"tests.test_spec_validation::test_c": "no vector"}}
    reasons = reasons_for(tmp_path, every_job({}, conformance), minimum=MINIMUM_REPORTS)
    assert len(reasons) == 1
    assert "tests.test_spec_validation::test_c" in reasons[0]


def test_the_matrix_report_reader_accepts_the_same_case(tmp_path: Path) -> None:
    """The reader of #524 downloaded `test-results-*` alone, so that case reached it never."""
    reasons = reasons_for(tmp_path, matrix_jobs({}), minimum=MATRIX_JOB_COUNT)
    assert reasons == []


# --- The job scope of an entry --------------------------------------------------------------


def test_the_reader_names_every_report_that_holds_one_case(tmp_path: Path) -> None:
    """#530 declined a job field on an entry because the reports state the same scope."""
    conformance = {"conformance-results": {"tests.test_spec_validation::test_c": "no vector"}}
    reports = read_reports(write_reports(tmp_path, every_job({}, conformance)))
    assert holders(reports, "tests.test_spec_validation::test_c") == ["conformance-results"]
    assert len(holders(reports, ANCHOR)) == MINIMUM_REPORTS


def test_the_census_names_the_scope_of_a_case_it_lists(tmp_path: Path) -> None:
    """An entry that covers a matrix case says more than one that covers a one-job case."""
    conformance = {"conformance-results": {"tests.test_spec_validation::test_c": "no vector"}}
    write_reports(tmp_path, every_job({}, conformance))
    lines = census_lines(read_reports(tmp_path), [])
    listed = [line for line in lines if "tests.test_spec_validation::test_c" in line]
    assert len(listed) == 1
    assert "held by conformance-results" in listed[0]


# --- The class of skip one message states -----------------------------------------------------

# The class `tests/test_spec_validation.py` produces once for each cell of a cross product
# that holds no data. #530 measured 143 such cases on 2026-08-10, all of one function that
# ran 199 other parameter sets.
NOT_APPLICABLE = "not applicable:"


def test_the_gate_passes_a_universal_skip_under_a_prefix_entry(tmp_path: Path) -> None:
    """One entry covers a class, so 143 parameter sets need no 143 entries."""
    conformance = {
        "conformance-results": {
            "tests.test_spec_validation::test_c[a]": "not applicable: a holds no JA4 value",
            "tests.test_spec_validation::test_c[b]": "not applicable: b holds no JA4S value",
        }
    }
    reasons = reasons_for(
        tmp_path,
        every_job({}, conformance),
        [allowance("", "the cell holds no data on either side", NOT_APPLICABLE)],
        minimum=MINIMUM_REPORTS,
    )
    assert reasons == []


def test_a_prefix_entry_covers_no_case_whose_message_differs_on_one_report(
    tmp_path: Path,
) -> None:
    """A second reason on one job must reach the gate, so one class hides no other."""
    jobs = every_job({"tests.test_a::test_c": "not applicable: the vector holds no value"})
    jobs["test-results-macos-latest-py3.12"]["tests.test_a::test_c"] = "no /dev/bpf device"
    reasons = reasons_for(
        tmp_path,
        jobs,
        [allowance("", "the cell holds no data on either side", NOT_APPLICABLE)],
        minimum=MINIMUM_REPORTS,
    )
    assert len(reasons) == 1
    assert "tests.test_a::test_c" in reasons[0]


def test_a_prefix_entry_reads_the_start_of_the_message_and_never_the_middle(
    tmp_path: Path,
) -> None:
    """A prefix that matched anywhere would cover a case whose reason merely quotes it."""
    conformance = {
        "conformance-results": {"tests.test_a::test_c": "the runner states not applicable: nothing"}
    }
    reasons = reasons_for(
        tmp_path,
        every_job({}, conformance),
        [allowance("", "the cell holds no data on either side", NOT_APPLICABLE)],
        minimum=MINIMUM_REPORTS,
    )
    assert len(reasons) == 1


def test_the_gate_fails_a_prefix_entry_that_names_no_reason(tmp_path: Path) -> None:
    """The reason rule reads every entry, and a prefix entry covers the most cases."""
    reasons = reasons_for(
        tmp_path, every_job({}), [allowance("", "  ", NOT_APPLICABLE)], minimum=MINIMUM_REPORTS
    )
    assert len(reasons) == 1
    assert "names no reason" in reasons[0]
    assert NOT_APPLICABLE in reasons[0]


def test_the_prefix_reader_finds_no_entry_for_a_case_that_every_job_ran(
    tmp_path: Path,
) -> None:
    """A case with no skip message matches no prefix, so the reader states None."""
    reports = read_reports(write_reports(tmp_path, every_job({"tests.test_a::test_c": None})))
    entry = allowance("", "a reason", NOT_APPLICABLE)
    assert covering_prefix(reports, "tests.test_a::test_c", [entry]) is None


def test_the_allowlist_reader_holds_a_skip_message_prefix(tmp_path: Path) -> None:
    """The tracked file states a class entry under `skip_message_prefix`."""
    path = tmp_path / "universal_skips.json"
    path.write_text(
        json.dumps({"entries": [{"skip_message_prefix": NOT_APPLICABLE, "reason": "a reason"}]}),
        encoding="utf-8",
    )
    assert read_allowlist(path) == [
        Allowance(case="", reason="a reason", message_prefix=NOT_APPLICABLE)
    ]


def test_the_allowlist_reader_refuses_an_entry_that_names_neither(tmp_path: Path) -> None:
    """An entry that names no case and no prefix covers everything or nothing."""
    path = tmp_path / "universal_skips.json"
    path.write_text(json.dumps({"entries": [{"reason": "a reason"}]}), encoding="utf-8")
    with pytest.raises(ValueError):
        read_allowlist(path)


def test_the_tracked_allowlist_covers_the_not_applicable_class() -> None:
    """#530 records the ruling that a `not applicable` cell is no case that runs nowhere.

    The 143 cases belong to one function that ran 199 other parameter sets, so the function
    asserts. A pass in place of the skip would assert an equality over two empty sets, which
    #524 put out of scope.
    """
    prefixes = [entry.message_prefix for entry in read_allowlist(ALLOWLIST_PATH)]
    assert NOT_APPLICABLE in prefixes


def test_the_census_groups_the_cases_a_prefix_entry_covers(tmp_path: Path) -> None:
    """143 near-identical lines would bury every case-level line of the census."""
    conformance = {
        "conformance-results": {
            "tests.test_spec_validation::test_c[a]": "not applicable: a holds no JA4 value",
            "tests.test_spec_validation::test_c[b]": "not applicable: b holds no JA4S value",
        }
    }
    write_reports(tmp_path, every_job({}, conformance))
    entry = allowance("", "the cell holds no data on either side", NOT_APPLICABLE)
    lines = census_lines(read_reports(tmp_path), [entry])
    assert any("2 cases" in line and NOT_APPLICABLE in line for line in lines)
    assert not any("test_c[a]" in line for line in lines)


def test_the_census_names_the_corpus_the_reports_hold(tmp_path: Path) -> None:
    """The corpus size is the reach of the reader, and a reader of the matrix saw less."""
    write_reports(tmp_path, every_job({"tests.test_a::test_c": None}))
    lines = census_lines(read_reports(tmp_path), [])
    assert "2 cases between them" in lines[0]
