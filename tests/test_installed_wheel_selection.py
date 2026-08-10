"""Hold the deselection rule of the `installed_wheel` marker against three commands.

`tests/conftest.py` states the rule, and the `installed-wheel` job of
`.github/workflows/test.yml` is the only runner of the marker.

**A rule that nobody checks removes the wheel cases from the gate in silence.** A rename
of the marker, a lost `conftest.py`, or a `-m` expression that stops naming the marker
each produce a green gate that builds no wheel. That shape is the fault this project
records sixteen times, and #408 exists because of it. These cases therefore run the
selection itself and read the counts.

Every case here runs `--collect-only`, so no case builds a wheel and no case creates a
clean environment. These cases carry no marker, so the default gate runs them.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
from typing import List

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
WHEEL_TESTS = REPOSITORY_ROOT / "tests" / "test_installed_wheel.py"

# The case count of `tests/test_installed_wheel.py` on 2026-08-10. A reader that finds
# nothing passes every count case on zero, so the cases below hold this floor. Four issues
# wrote the cases.
#
#   1. #408 wrote seven cases against the wheel.
#   2. #409 added nine against the source distribution.
#   3. #455 added seven that read the entry list, the metadata and the member list.
#   4. #67 added one that reads the version the build resolved into the wheel metadata.
EXPECTED_CASE_COUNT = 24


def _collect(arguments: List[str]) -> str:
    """Return the output of one `--collect-only` run of the wheel test file.

    Args:
        arguments: The arguments after the file name, such as the `-m` expression.

    Returns:
        The standard output and the standard error of the run, joined.
    """
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", str(WHEEL_TESTS), "--collect-only", "-q", *arguments],
        cwd=str(REPOSITORY_ROOT),
        capture_output=True,
        text=True,
    )
    return completed.stdout + completed.stderr


def _count(output: str, word: str) -> int:
    """Return the count that the summary line states for one word.

    Args:
        output: The output of a `pytest` run.
        word: The summary word, such as `deselected` or `tests collected`.

    Returns:
        The count, or zero where the summary states none.
    """
    match = re.search(rf"(\d+)\s+{re.escape(word)}", output)
    return int(match.group(1)) if match else 0


def test_the_marker_runs_where_the_expression_names_it() -> None:
    """`pytest -m installed_wheel` collects every case of the wheel test file."""
    output = _collect(["-m", "installed_wheel"])
    collected = _count(output, "tests collected")
    assert collected == EXPECTED_CASE_COUNT, (
        f"-m installed_wheel collected {collected} cases, and the file holds "
        f"{EXPECTED_CASE_COUNT}: {output}"
    )


def test_the_gate_command_deselects_the_marker() -> None:
    """The unit gate deselects every case of the wheel test file.

    `pytest tests/ -m "not spec_validation"` is the command the gate runs, and it builds
    no wheel.
    """
    output = _collect(["-m", "not spec_validation"])
    assert _count(output, "deselected") == EXPECTED_CASE_COUNT, (
        f'-m "not spec_validation" deselected no case, and it must deselect '
        f"{EXPECTED_CASE_COUNT}: {output}"
    )
    assert _count(output, "tests collected") == 0, (
        f'-m "not spec_validation" collected a wheel case, and it must collect none: {output}'
    )


def test_a_run_with_no_expression_deselects_the_marker() -> None:
    """A run that names no `-m` expression deselects every case of the wheel test file."""
    output = _collect([])
    assert _count(output, "deselected") == EXPECTED_CASE_COUNT, (
        f"a run with no -m expression deselected no case, and it must deselect "
        f"{EXPECTED_CASE_COUNT}: {output}"
    )


def test_the_conftest_names_the_marker_the_workflow_job_runs() -> None:
    """The deselected marker and the marker of the `installed-wheel` job are one name.

    A rename that reaches one file and not the other leaves a job that runs nothing.
    """
    from tests.conftest import DESELECTED_MARKER

    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
    assert f"-m {DESELECTED_MARKER}" in workflow, (
        f"no job of .github/workflows/test.yml runs -m {DESELECTED_MARKER}"
    )
