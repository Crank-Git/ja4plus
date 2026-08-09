"""Tests that the census reads the sweep report and names every open candidate.

The sweep names a candidate: one test case that no mutation of one sweep makes fail. #206
asks for a count that cannot silently become zero, and the census produces it.
`FR-pre-release-validation-19` and `FR-pre-release-validation-20` state the requirement.

**The census groups by test file and not by module.** `tests/mutation_sweep.py:593` builds
one flat candidate list over every module the sweep read, so no module owns a candidate.
The one grouping the report offers splits each identifier at `::`.

**The census reads the JSON report and it opens no Markdown file.**
`docs/mutation_sweep.md` is one page, and a count taken from its lines counts the page
layout. One case below patches the file readers and proves the rule.

These cases build their own report and their own settlement directory. They read no
packet and they produce no fingerprint.
"""

from __future__ import annotations

import builtins
import json
from pathlib import Path

from tests import mutation_census


def write_report(directory: Path, candidates: list[str]) -> Path:
    """Write one report that holds the named candidates and return its path."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "mutation_sweep.json"
    path.write_text(
        json.dumps(
            {
                "generated": "2026-08-09T00:00:00",
                "commit": "c" * 40,
                "seed": 0,
                "max_per_module": 0,
                "tests": ["tests/"],
                "cases_collected": 10,
                "baseline_failures": [],
                "seconds": 1.0,
                "modules": [{"module": "ja4plus/types.py", "mutations": []}],
                "candidates": candidates,
            }
        )
    )
    return path


def write_settlement(directory: Path, name: str, settlements: list[dict]) -> Path:
    """Write one settlement record and return its path."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "{}.json".format(name)
    path.write_text(
        json.dumps({"issue": 412, "modules": ["ja4plus/types.py"], "settlements": settlements})
    )
    return path


def repaired(candidate: str) -> dict:
    return {"candidate": candidate, "verdict": "repaired", "case": candidate + "_guard"}


def correct(candidate: str) -> dict:
    return {"candidate": candidate, "verdict": "correct", "reason": "The mutation is equivalent."}


class TestTheCandidateCountOfEachTestFile:
    def test_the_census_counts_the_candidates_of_each_test_file(self, tmp_path) -> None:
        report = write_report(
            tmp_path,
            [
                "tests/test_one.py::test_a",
                "tests/test_one.py::TestB::test_c",
                "tests/test_two.py::test_d",
            ],
        )
        counts = mutation_census.counts_by_test_file(mutation_census.read_report(report))
        assert counts == {"tests/test_one.py": 2, "tests/test_two.py": 1}

    def test_one_more_candidate_of_one_file_raises_that_count_by_one(self, tmp_path) -> None:
        before = write_report(tmp_path / "before", ["tests/test_one.py::test_a"])
        after = write_report(tmp_path / "after", ["tests/test_one.py::test_a", "x.py::test_b"])
        first = mutation_census.counts_by_test_file(mutation_census.read_report(before))
        second = mutation_census.counts_by_test_file(mutation_census.read_report(after))
        assert first != second
        assert second["x.py"] == 1

    def test_the_census_names_a_count_that_falls_to_zero(self, tmp_path) -> None:
        report = write_report(tmp_path, [])
        assert mutation_census.counts_by_test_file(mutation_census.read_report(report)) == {}

    def test_a_parametrized_identifier_groups_under_its_test_file(self, tmp_path) -> None:
        report = write_report(tmp_path, ["tests/test_one.py::test_a[README.md:74]"])
        counts = mutation_census.counts_by_test_file(mutation_census.read_report(report))
        assert counts == {"tests/test_one.py": 1}


class TestTheSettlementDirectory:
    def test_the_census_reads_every_settlement_file_of_the_directory(self, tmp_path) -> None:
        directory = tmp_path / "settlements"
        write_settlement(directory, "412-utils", [repaired("tests/test_one.py::test_a")])
        write_settlement(directory, "413-fingerprinters", [correct("tests/test_two.py::test_b")])
        claims = mutation_census.read_claims(directory)
        assert claims == {
            "tests/test_one.py::test_a": ["412-utils.json"],
            "tests/test_two.py::test_b": ["413-fingerprinters.json"],
        }

    def test_a_directory_that_holds_no_file_produces_no_claim(self, tmp_path) -> None:
        assert mutation_census.read_claims(tmp_path / "absent") == {}

    def test_the_census_reads_no_file_of_another_suffix(self, tmp_path) -> None:
        directory = tmp_path / "settlements"
        directory.mkdir()
        (directory / "README.md").write_text("tests/test_one.py::test_a\n")
        assert mutation_census.read_claims(directory) == {}


class TestTheClaimOfEveryCandidate:
    def test_a_candidate_two_settlement_files_claim_is_named(self, tmp_path) -> None:
        directory = tmp_path / "settlements"
        write_settlement(directory, "412-utils", [repaired("tests/test_one.py::test_a")])
        write_settlement(directory, "413-fingerprinters", [correct("tests/test_one.py::test_a")])
        report = write_report(tmp_path, ["tests/test_one.py::test_a"])
        found = mutation_census.census(report, directory)
        assert found.claimed_twice == {
            "tests/test_one.py::test_a": ["412-utils.json", "413-fingerprinters.json"]
        }
        assert found.unclaimed == []

    def test_a_candidate_no_settlement_file_claims_is_named(self, tmp_path) -> None:
        directory = tmp_path / "settlements"
        write_settlement(directory, "412-utils", [repaired("tests/test_one.py::test_a")])
        report = write_report(tmp_path, ["tests/test_one.py::test_a", "tests/test_two.py::test_b"])
        found = mutation_census.census(report, directory)
        assert found.unclaimed == ["tests/test_two.py::test_b"]
        assert found.claimed_twice == {}

    def test_a_settlement_of_a_case_the_report_names_no_candidate_is_named(self, tmp_path) -> None:
        directory = tmp_path / "settlements"
        write_settlement(directory, "412-utils", [repaired("tests/test_gone.py::test_a")])
        report = write_report(tmp_path, ["tests/test_one.py::test_a"])
        found = mutation_census.census(report, directory)
        assert found.unknown == {"tests/test_gone.py::test_a": ["412-utils.json"]}

    def test_a_census_that_settles_every_candidate_once_names_nothing(self, tmp_path) -> None:
        directory = tmp_path / "settlements"
        write_settlement(
            directory,
            "412-utils",
            [repaired("tests/test_one.py::test_a"), correct("tests/test_two.py::test_b")],
        )
        report = write_report(tmp_path, ["tests/test_one.py::test_a", "tests/test_two.py::test_b"])
        found = mutation_census.census(report, directory)
        assert found.unclaimed == []
        assert found.claimed_twice == {}
        assert found.unknown == {}
        assert found.faults == []


class TestTheVerdictOfEverySettlement:
    def test_a_repaired_verdict_that_names_no_case_is_a_fault(self, tmp_path) -> None:
        directory = tmp_path / "settlements"
        write_settlement(directory, "412-utils", [{"candidate": "a.py::b", "verdict": "repaired"}])
        faults = mutation_census.settlement_faults(directory)
        assert len(faults) == 1
        assert "412-utils.json" in faults[0]
        assert "a.py::b" in faults[0]

    def test_a_correct_verdict_that_names_no_reason_is_a_fault(self, tmp_path) -> None:
        directory = tmp_path / "settlements"
        write_settlement(directory, "412-utils", [{"candidate": "a.py::b", "verdict": "correct"}])
        assert len(mutation_census.settlement_faults(directory)) == 1

    def test_a_verdict_the_requirement_does_not_name_is_a_fault(self, tmp_path) -> None:
        directory = tmp_path / "settlements"
        write_settlement(
            directory, "412-utils", [{"candidate": "a.py::b", "verdict": "skipped", "case": "c"}]
        )
        assert len(mutation_census.settlement_faults(directory)) == 1

    def test_two_sound_verdicts_produce_no_fault(self, tmp_path) -> None:
        directory = tmp_path / "settlements"
        write_settlement(directory, "412-utils", [repaired("a.py::b"), correct("c.py::d")])
        assert mutation_census.settlement_faults(directory) == []


class TestTheCensusOpensNoMarkdownFile:
    def test_no_reader_of_the_census_opens_a_markdown_file(self, tmp_path, monkeypatch) -> None:
        directory = tmp_path / "settlements"
        write_settlement(directory, "412-utils", [repaired("tests/test_one.py::test_a")])
        report = write_report(tmp_path, ["tests/test_one.py::test_a"])
        (tmp_path / "mutation_sweep.md").write_text("| Candidates | 1 |\n")

        opened: list[str] = []
        real_open = builtins.open
        real_read_text = Path.read_text

        def record_open(file, *args, **kwargs):
            opened.append(str(file))
            return real_open(file, *args, **kwargs)

        def record_read_text(self, *args, **kwargs):
            opened.append(str(self))
            return real_read_text(self, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", record_open)
        monkeypatch.setattr(Path, "read_text", record_read_text)
        mutation_census.census(report, directory)
        monkeypatch.undo()

        assert opened != []
        assert [path for path in opened if path.endswith(".md")] == []

    def test_the_census_states_the_commit_the_report_names(self, tmp_path) -> None:
        directory = tmp_path / "settlements"
        report = write_report(tmp_path, [])
        assert mutation_census.census(report, directory).commit == "c" * 40
