"""Tests that the sweep report names the commit the sweep read.

`.claude/rules/conformance.md` states that a checkpoint belongs to one commit, because
the checkpoint keys each result on the position of the expression in the file. A report
that names no commit therefore states no way to check that its results belong to the code
a reader holds. `FR-pre-release-validation-17` states the requirement, and
`FR-pre-release-validation-18` asks a reader to prove that the commit is an ancestor of
the head of the branch. Neither check runs against a report that carries no commit.

#411 records the finding. The committed report of 2026-08-07 states a `Date` and no
commit.

These cases read no packet and they produce no fingerprint.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from tests import mutation_sweep

REPO_ROOT = Path(__file__).resolve().parent.parent


def one_report(commit: str) -> dict:
    """Return the smallest report that `markdown_report` renders."""
    return {
        "generated": "2026-08-09T00:00:00",
        "commit": commit,
        "seed": 0,
        "max_per_module": 0,
        "tests": ["tests/"],
        "cases_collected": 2,
        "baseline_failures": [],
        "seconds": 1.0,
        "modules": [{"module": "ja4plus/types.py", "mutations": []}],
        "candidates": ["tests/test_one.py::test_a"],
    }


class TestTheCommitTheSweepReads:
    def test_the_reader_returns_the_head_commit_of_the_repository(self) -> None:
        expected = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        assert mutation_sweep.head_commit(REPO_ROOT) == expected

    def test_the_reader_returns_a_full_forty_character_commit(self) -> None:
        found = mutation_sweep.head_commit(REPO_ROOT)
        assert len(found) == 40
        assert set(found) <= set("0123456789abcdef")


class TestTheMarkdownReport:
    def test_the_page_states_the_commit_the_sweep_read(self) -> None:
        page = mutation_sweep.markdown_report(one_report("a" * 40))
        assert "| Commit | `{}` |".format("a" * 40) in page

    def test_the_commit_row_follows_the_date_row(self) -> None:
        lines = mutation_sweep.markdown_report(one_report("b" * 40)).splitlines()
        date = next(index for index, line in enumerate(lines) if line.startswith("| Date |"))
        assert lines[date + 1].startswith("| Commit |")
