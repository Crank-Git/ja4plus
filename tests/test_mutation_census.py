"""Tests that the census reads every sweep report and names every open candidate.

The sweep names a candidate: one test case that no mutation of one sweep makes fail. #206
asks for a count that cannot silently become zero, and the census produces it.
`FR-pre-release-validation-19` and `FR-pre-release-validation-20` state the requirement.

**The census reads a directory of reports and not one report.** The project manager
partitioned the sweep on 2026-08-09, after #411 measured the whole-package run at 71.6
hours. #412, #413 and #414 each run one sweep and write one report.

**A candidate is keyed by the sweep that named it and by the case.** Two sweeps may name
the same case, and that is one candidate for each sweep and not a duplicate claim. The
union of the per-module sweeps is therefore larger than the candidate set of one
whole-package sweep, and the union is the set this project settles.

**The census groups by test file and not by module.** `tests/mutation_sweep.py:593` builds
one flat candidate list over every module one sweep read, so no module owns a candidate.

**The census reads the JSON reports and it opens no Markdown file.** A count taken from
the lines of a Markdown page counts the page layout. One case below patches the file
readers and proves the rule.

These cases build their own reports and their own settlement directory. They read no
packet and they produce no fingerprint.
"""

from __future__ import annotations

import builtins
import json
from pathlib import Path

import pytest

from tests import mutation_census


def write_report(directory: Path, name: str, modules: list, candidates: list) -> Path:
    """Write one sweep report under the named stem and return its path."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "{}.json".format(name)
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
                "modules": [{"module": module, "mutations": []} for module in modules],
                "candidates": candidates,
            }
        )
    )
    return path


def write_settlement(directory: Path, name: str, sweep: str, settlements: list) -> Path:
    """Write one settlement record for one sweep and return its path."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "{}.json".format(name)
    path.write_text(
        json.dumps(
            {
                "issue": 412,
                "sweep": sweep,
                "modules": ["ja4plus/types.py"],
                "settlements": settlements,
            }
        )
    )
    return path


def repaired(candidate: str) -> dict:
    return {"candidate": candidate, "verdict": "repaired", "case": candidate + "_guard"}


def correct(candidate: str) -> dict:
    return {"candidate": candidate, "verdict": "correct", "reason": "The mutation is equivalent."}


@pytest.fixture
def reports(tmp_path) -> Path:
    return tmp_path / "reports"


@pytest.fixture
def settlements(tmp_path) -> Path:
    return tmp_path / "settlements"


class TestTheUnionOfEverySweep:
    def test_the_census_reads_every_report_of_the_directory(self, reports) -> None:
        write_report(reports, "412-utils", ["ja4plus/utils/tls_utils.py"], ["a.py::test_x"])
        write_report(reports, "413-fingerprinters", ["ja4plus/fingerprinters/ja4.py"], ["b.py::y"])
        found = mutation_census.read_reports(reports)
        assert sorted(found) == ["412-utils", "413-fingerprinters"]

    def test_one_case_two_sweeps_name_produces_one_candidate_for_each_sweep(self, reports) -> None:
        write_report(reports, "412-utils", ["ja4plus/utils/tls_utils.py"], ["a.py::test_x"])
        write_report(reports, "413-fingerprinters", ["ja4plus/fingerprinters/ja4.py"], ["a.py::x"])
        write_report(reports, "414-interface", ["ja4plus/cli.py"], ["a.py::test_x"])
        found = mutation_census.candidates(mutation_census.read_reports(reports))
        named = [item for item in found if item.case == "a.py::test_x"]
        assert len(named) == 2
        assert sorted(item.sweep for item in named) == ["412-utils", "414-interface"]

    def test_a_directory_that_holds_no_report_produces_no_candidate(self, tmp_path) -> None:
        assert mutation_census.read_reports(tmp_path / "absent") == {}

    def test_the_census_reads_no_file_of_another_suffix(self, reports) -> None:
        reports.mkdir(parents=True)
        (reports / "README.md").write_text("| Candidates | 976 |\n")
        assert mutation_census.read_reports(reports) == {}

    def test_the_swept_modules_are_the_union_of_every_report(self, reports) -> None:
        write_report(reports, "412-utils", ["ja4plus/utils/tls_utils.py"], [])
        write_report(reports, "413-fingerprinters", ["ja4plus/fingerprinters/ja4.py"], [])
        found = mutation_census.modules_swept(mutation_census.read_reports(reports))
        assert found == {"ja4plus/utils/tls_utils.py", "ja4plus/fingerprinters/ja4.py"}


class TestTheCandidateCountOfEachTestFile:
    def test_the_census_counts_the_candidates_of_each_test_file(self, reports) -> None:
        write_report(
            reports,
            "412-utils",
            ["ja4plus/utils/tls_utils.py"],
            [
                "tests/test_one.py::test_a",
                "tests/test_one.py::TestB::test_c",
                "tests/t2.py::test_d",
            ],
        )
        counts = mutation_census.counts_by_test_file(mutation_census.read_reports(reports))
        assert counts == {"tests/t2.py": 1, "tests/test_one.py": 2}

    def test_one_more_candidate_of_one_file_raises_that_count_by_one(self, reports) -> None:
        write_report(reports, "412-utils", ["ja4plus/types.py"], ["tests/test_one.py::test_a"])
        first = mutation_census.counts_by_test_file(mutation_census.read_reports(reports))
        write_report(
            reports,
            "412-utils",
            ["ja4plus/types.py"],
            ["tests/test_one.py::test_a", "tests/test_one.py::test_b"],
        )
        second = mutation_census.counts_by_test_file(mutation_census.read_reports(reports))
        assert first == {"tests/test_one.py": 1}
        assert second == {"tests/test_one.py": 2}

    def test_one_case_two_sweeps_name_counts_twice(self, reports) -> None:
        write_report(reports, "412-utils", ["ja4plus/utils/tls_utils.py"], ["tests/t.py::test_a"])
        write_report(reports, "414-interface", ["ja4plus/cli.py"], ["tests/t.py::test_a"])
        counts = mutation_census.counts_by_test_file(mutation_census.read_reports(reports))
        assert counts == {"tests/t.py": 2}

    def test_the_census_names_a_count_that_falls_to_zero(self, reports) -> None:
        write_report(reports, "412-utils", ["ja4plus/types.py"], [])
        assert mutation_census.counts_by_test_file(mutation_census.read_reports(reports)) == {}

    def test_a_parametrized_identifier_groups_under_its_test_file(self, reports) -> None:
        write_report(
            reports, "412-utils", ["ja4plus/types.py"], ["tests/test_one.py::test_a[README.md:74]"]
        )
        counts = mutation_census.counts_by_test_file(mutation_census.read_reports(reports))
        assert counts == {"tests/test_one.py": 1}


class TestTheSettlementDirectory:
    def test_the_census_reads_every_settlement_file_of_the_directory(self, settlements) -> None:
        write_settlement(settlements, "412-utils", "412-utils", [repaired("tests/t1.py::test_a")])
        write_settlement(settlements, "413-fp", "413-fp", [correct("tests/t2.py::test_b")])
        claims = mutation_census.read_claims(settlements)
        assert claims == {
            mutation_census.Candidate("412-utils", "tests/t1.py::test_a"): ["412-utils.json"],
            mutation_census.Candidate("413-fp", "tests/t2.py::test_b"): ["413-fp.json"],
        }

    def test_a_directory_that_holds_no_file_produces_no_claim(self, tmp_path) -> None:
        assert mutation_census.read_claims(tmp_path / "absent") == {}

    def test_the_census_reads_no_file_of_another_suffix(self, settlements) -> None:
        settlements.mkdir(parents=True)
        (settlements / "README.md").write_text("tests/test_one.py::test_a\n")
        assert mutation_census.read_claims(settlements) == {}


class TestTheClaimOfEveryCandidate:
    def test_a_candidate_two_settlement_records_claim_is_named(self, reports, settlements) -> None:
        write_report(reports, "412-utils", ["ja4plus/types.py"], ["tests/t.py::test_a"])
        write_settlement(settlements, "412-utils", "412-utils", [repaired("tests/t.py::test_a")])
        write_settlement(settlements, "412-again", "412-utils", [correct("tests/t.py::test_a")])
        found = mutation_census.census(reports, settlements)
        key = mutation_census.Candidate("412-utils", "tests/t.py::test_a")
        assert found.claimed_twice == {key: ["412-again.json", "412-utils.json"]}
        assert found.unclaimed == []

    def test_one_case_two_sweeps_name_needs_one_claim_for_each_sweep(
        self, reports, settlements
    ) -> None:
        write_report(reports, "412-utils", ["ja4plus/utils/tls_utils.py"], ["tests/t.py::test_a"])
        write_report(reports, "414-interface", ["ja4plus/cli.py"], ["tests/t.py::test_a"])
        write_settlement(settlements, "412-utils", "412-utils", [repaired("tests/t.py::test_a")])
        found = mutation_census.census(reports, settlements)
        assert found.claimed_twice == {}
        assert found.unclaimed == [mutation_census.Candidate("414-interface", "tests/t.py::test_a")]

    def test_a_candidate_no_settlement_record_claims_is_named(self, reports, settlements) -> None:
        write_report(
            reports,
            "412-utils",
            ["ja4plus/types.py"],
            ["tests/t1.py::test_a", "tests/t2.py::test_b"],
        )
        write_settlement(settlements, "412-utils", "412-utils", [repaired("tests/t1.py::test_a")])
        found = mutation_census.census(reports, settlements)
        assert found.unclaimed == [mutation_census.Candidate("412-utils", "tests/t2.py::test_b")]
        assert found.claimed_twice == {}

    def test_a_settlement_of_a_case_no_report_names_a_candidate_is_named(
        self, reports, settlements
    ) -> None:
        write_report(reports, "412-utils", ["ja4plus/types.py"], ["tests/t1.py::test_a"])
        write_settlement(settlements, "412-utils", "412-utils", [repaired("tests/gone.py::test_a")])
        found = mutation_census.census(reports, settlements)
        assert found.unknown == {
            mutation_census.Candidate("412-utils", "tests/gone.py::test_a"): ["412-utils.json"]
        }

    def test_a_census_that_settles_every_candidate_once_names_nothing(
        self, reports, settlements
    ) -> None:
        write_report(
            reports,
            "412-utils",
            ["ja4plus/types.py"],
            ["tests/t1.py::test_a", "tests/t2.py::test_b"],
        )
        write_settlement(
            settlements,
            "412-utils",
            "412-utils",
            [repaired("tests/t1.py::test_a"), correct("tests/t2.py::test_b")],
        )
        found = mutation_census.census(reports, settlements)
        assert found.unclaimed == []
        assert found.claimed_twice == {}
        assert found.unknown == {}
        assert found.faults == []


class TestARecordThatBreaksItsOwnSchema:
    """A broken record reaches the fault list. It raises nothing.

    The census reads files three issues write at the same time. **A reader who runs the
    census against a half-written record needs the name of the broken file**, and a
    traceback from inside a dictionary lookup names the key alone.
    """

    def test_a_report_that_holds_no_candidates_key_is_a_fault(self, reports, settlements) -> None:
        reports.mkdir(parents=True)
        (reports / "412-utils.json").write_text(json.dumps({"commit": "c" * 40, "modules": []}))
        found = mutation_census.census(reports, settlements)
        assert found.candidates == []
        assert len(found.faults) == 1
        assert "candidates" in found.faults[0]
        assert "412-utils" in found.faults[0]

    def test_a_report_that_holds_no_modules_key_is_a_fault(self, reports, settlements) -> None:
        reports.mkdir(parents=True)
        (reports / "412-utils.json").write_text(json.dumps({"commit": "c" * 40, "candidates": []}))
        found = mutation_census.census(reports, settlements)
        assert len(found.faults) == 1
        assert "modules" in found.faults[0]

    def test_a_settlement_that_names_no_candidate_is_a_fault(self, reports, settlements) -> None:
        write_report(reports, "412-utils", ["ja4plus/types.py"], [])
        write_settlement(settlements, "412-utils", "412-utils", [{"verdict": "correct"}])
        found = mutation_census.census(reports, settlements)
        assert found.unknown == {}
        assert any("names no candidate" in sentence for sentence in found.faults)

    def test_a_broken_report_raises_nothing(self, reports, settlements) -> None:
        reports.mkdir(parents=True)
        (reports / "412-utils.json").write_text(json.dumps({}))
        write_settlement(settlements, "412-utils", "412-utils", [{"verdict": "repaired"}])
        found = mutation_census.census(reports, settlements)
        assert found.counts == {}
        # The report holds none of the three keys, and the settlement names no candidate.
        assert len(found.faults) == 4


class TestTheVerdictOfEverySettlement:
    def test_a_repaired_verdict_that_names_no_case_is_a_fault(self, reports, settlements) -> None:
        write_report(reports, "412-utils", ["ja4plus/types.py"], [])
        write_settlement(
            settlements, "412-utils", "412-utils", [{"candidate": "a.py::b", "verdict": "repaired"}]
        )
        faults = mutation_census.settlement_faults(settlements, {"412-utils"})
        assert len(faults) == 1
        assert "412-utils.json" in faults[0]
        assert "a.py::b" in faults[0]

    def test_a_correct_verdict_that_names_no_reason_is_a_fault(self, settlements) -> None:
        write_settlement(
            settlements, "412-utils", "412-utils", [{"candidate": "a.py::b", "verdict": "correct"}]
        )
        assert len(mutation_census.settlement_faults(settlements, {"412-utils"})) == 1

    def test_a_verdict_the_requirement_does_not_name_is_a_fault(self, settlements) -> None:
        write_settlement(
            settlements,
            "412-utils",
            "412-utils",
            [{"candidate": "a.py::b", "verdict": "skipped", "case": "c"}],
        )
        assert len(mutation_census.settlement_faults(settlements, {"412-utils"})) == 1

    def test_a_record_that_names_a_sweep_no_report_holds_is_a_fault(self, settlements) -> None:
        write_settlement(settlements, "412-utils", "412-gone", [repaired("a.py::b")])
        faults = mutation_census.settlement_faults(settlements, {"412-utils"})
        assert len(faults) == 1
        assert "412-gone" in faults[0]

    def test_two_sound_verdicts_produce_no_fault(self, settlements) -> None:
        write_settlement(
            settlements, "412-utils", "412-utils", [repaired("a.py::b"), correct("c.py::d")]
        )
        assert mutation_census.settlement_faults(settlements, {"412-utils"}) == []


class TestTheCensusOpensNoMarkdownFile:
    def test_no_reader_of_the_census_opens_a_markdown_file(
        self, reports, settlements, monkeypatch
    ) -> None:
        write_report(reports, "412-utils", ["ja4plus/types.py"], ["tests/t.py::test_a"])
        write_settlement(settlements, "412-utils", "412-utils", [repaired("tests/t.py::test_a")])
        (reports / "412-utils.md").write_text("| Candidates | 1 |\n")

        opened = []
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
        mutation_census.census(reports, settlements)
        monkeypatch.undo()

        assert opened != []
        assert [path for path in opened if path.endswith(".md")] == []

    def test_the_census_states_the_commit_of_each_sweep(self, reports, settlements) -> None:
        write_report(reports, "412-utils", ["ja4plus/types.py"], [])
        assert mutation_census.census(reports, settlements).commits == {"412-utils": "c" * 40}
