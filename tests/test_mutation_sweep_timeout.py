"""Tests that one mutation cannot hang a sweep.

`tests/mutation_sweep.py` runs the suite once for each mutation, and it ran that suite with
no time limit. One mutation of `ja4plus/utils/ssh_utils.py` turns `while position <
len(payload)` into `while position <= len(payload)`, and the loop then never ends. The
suite run never returns, so the sweep stops for good and the checkpoint records nothing.
#412 met that mutation three times.

The sweep now accepts a time limit. A run that passes the limit records the status
`timeout`, and the sweep continues with the next mutation. **A mutation that times out is
not a survivor.** A survivor is the signal this project reads, and a run that never
finished measured nothing.

The limit is off by default, so a sweep that names no limit behaves as it did before.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

from tests import mutation_sweep


def write_suite(root: Path, body: str) -> None:
    """Write one test file under `tests/` of the named root."""
    (root / "tests").mkdir(parents=True, exist_ok=True)
    (root / "tests" / "test_one.py").write_text(textwrap.dedent(body))


class TestTheTimeLimitOfOneSuiteRun:
    def test_a_run_that_passes_the_limit_reports_no_return_code(self, tmp_path) -> None:
        write_suite(
            tmp_path,
            """
            import time


            def test_a_case_that_never_ends() -> None:
                time.sleep(30)
            """,
        )
        failures, code = mutation_sweep.run_suite(
            tmp_path, sys.executable, [], ["tests/"], timeout=2
        )
        assert code is None
        assert failures == set()

    def test_a_run_under_the_limit_reports_its_return_code(self, tmp_path) -> None:
        write_suite(
            tmp_path,
            """
            def test_a_case_that_passes() -> None:
                assert True
            """,
        )
        failures, code = mutation_sweep.run_suite(
            tmp_path, sys.executable, [], ["tests/"], timeout=120
        )
        assert code == 0
        assert failures == set()

    def test_a_run_that_names_no_limit_reports_its_return_code(self, tmp_path) -> None:
        write_suite(
            tmp_path,
            """
            def test_a_case_that_passes() -> None:
                assert True
            """,
        )
        failures, code = mutation_sweep.run_suite(tmp_path, sys.executable, [], ["tests/"])
        assert code == 0


class TestTheOptionThatCarriesTheLimit:
    def test_the_sweep_names_no_limit_by_default(self) -> None:
        assert mutation_sweep.parse_arguments([]).timeout == 0

    def test_the_option_reads_a_second_count(self) -> None:
        assert mutation_sweep.parse_arguments(["--timeout", "90"]).timeout == 90


class TestTheStatusOfAMutationThatTimesOut:
    def test_the_status_names_the_timeout_and_not_a_survivor(self) -> None:
        mutation = mutation_sweep.Mutation(
            module="ja4plus/utils/ssh_utils.py",
            kind="compare",
            line=284,
            before="<",
            after="<=",
            start=0,
            end=1,
        )
        mutation.status = mutation_sweep.TIMEOUT
        assert mutation_sweep.TIMEOUT == "timeout"
        assert mutation.record()["status"] == "timeout"
        assert mutation.status != "survived"
