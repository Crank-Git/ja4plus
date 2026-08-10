"""Run the Zeek baseline comparison script end to end and check what it prints.

`docs/specs/foxio/zeek.md` cites readings that `tests/compare_zeek_baselines.py`
produced, so the script is evidence-producing tooling. No gate ran it, and #49 broke it
by removing the composite `source` field that its reader read. These cases run the
script over a committed capture, so the next change to the output schema breaks a case
instead of breaking the script in silence.

`TestTheReaderOfTheOutputLines` and `TestTheEndToEndRun` write a baseline in the Zeek TSV
form and state the fingerprints they expect, which measures the reader, the connection key
and the comparison. Those cases measure no FoxIO value.

`TestTheCommittedBaselinesRunAsAGate` measures the FoxIO values. #515 committed the seven
baselines under `tests/foxio_vectors/zeek_expected/`, so the whole comparison now runs with
no external checkout. The class states the three counts that
`docs/specs/foxio/zeek.md` records for the run of #327, so a fingerprint that moves against
the Zeek package fails a case here rather than waiting for the next manual run.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests import compare_zeek_baselines
from tests.compare_zeek_baselines import READS_SCHEMA_VERSION, ja4plus_readings

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "tests" / "compare_zeek_baselines.py"
CAPTURE = REPO_ROOT / "tests" / "foxio_vectors" / "dhcp.pcapng"

# The two connections of `dhcp.pcapng` and the JA4D fingerprints this project emits for
# each one, in the order the command-line program writes them.
CLIENT_CONNECTION = ("0.0.0.0:68", "255.255.255.255:67")
SERVER_CONNECTION = ("192.168.0.10:68", "192.168.0.1:67")
CLIENT_FINGERPRINTS = ["disco0000in_61-55_1-3-6-42", "reqst0000in_61-54-55_1-3-6-42"]
SERVER_FINGERPRINTS = ["offer0000nn_1-58-59-51-54_00", "dpack0000nn_58-59-51-54-1_00"]

ZEEK_FIELDS = ["ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "ja4d"]

# The counts the whole comparison reads against the committed baselines. #327 measured the
# same three numbers on 2026-08-08 against a `FoxIO-LLC/ja4` checkout at the pinned commit,
# and `docs/specs/foxio/zeek.md` records that run. A count that moves names the method and
# the connection through the row cases below.
COMPARED_ROWS = 98
DIFFERING_ROWS = 35

# The JA4TS reading, which #515 owns. Nine of the ten values match, and the tenth is the
# proven `DLT_NULL` defect of the Zeek script.
JA4TS_ROWS = 10
JA4TS_MATCHING_ROWS = 9


def write_baseline(reference: Path, fingerprints: list[str]) -> None:
    """Write one Zeek JA4D baseline for `dhcp.pcapng` under a reference checkout.

    Args:
        reference: The directory that stands in for a `FoxIO-LLC/ja4` checkout.
        fingerprints: The four JA4D values the baseline states, in the order of
            `CLIENT_FINGERPRINTS` followed by `SERVER_FINGERPRINTS`.
    """
    directory = reference / "zeek" / "tests" / "Traces" / "Scripts.ja4-dhcp"
    directory.mkdir(parents=True)
    rows = [
        ("0.0.0.0", "68", "255.255.255.255", "67", fingerprints[0]),
        ("0.0.0.0", "68", "255.255.255.255", "67", fingerprints[1]),
        ("192.168.0.1", "67", "192.168.0.10", "68", fingerprints[2]),
        ("192.168.0.1", "67", "192.168.0.10", "68", fingerprints[3]),
    ]
    lines = ["#separator \\x09", "#fields\t" + "\t".join(ZEEK_FIELDS)]
    lines += ["\t".join(("1102274184.317453",) + row) for row in rows]
    (directory / "ja4d.log").write_text("\n".join(lines) + "\n")


def run_script(reference: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Return the finished run of the comparison script.

    Args:
        reference: The directory that stands in for a `FoxIO-LLC/ja4` checkout, or None.
            None runs the script against the committed baselines.

    Returns:
        The finished process, with its output captured.
    """
    command = [sys.executable, str(SCRIPT)]
    if reference is not None:
        command.append(str(reference))
    return subprocess.run(command, capture_output=True, text=True, cwd=REPO_ROOT)


def comparison_rows(output: str) -> list[list[str]]:
    """Return one list of cell values for each comparison row the report holds.

    Args:
        output: The whole report the script printed.

    Returns:
        One list per data row, holding the connection, the method, the Zeek value, the
        ja4plus value and the verdict. The header row and the separator row are dropped.
    """
    rows = []
    for line in output.splitlines():
        if not line.startswith("| "):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if cells[0] == "Connection":
            continue
        rows.append(cells)
    return rows


class TestTheReaderOfTheOutputLines:
    def test_the_reader_keys_a_fingerprint_by_the_four_endpoint_fields(self):
        readings = ja4plus_readings(CAPTURE)
        assert readings[CLIENT_CONNECTION]["ja4d"] == CLIENT_FINGERPRINTS
        assert readings[SERVER_CONNECTION]["ja4d"] == SERVER_FINGERPRINTS

    def test_the_reader_rejects_an_output_line_above_the_schema_version_it_reads(self, monkeypatch):
        line = {
            "schema_version": READS_SCHEMA_VERSION + 1,
            "type": "ja4d",
            "fingerprint": CLIENT_FINGERPRINTS[0],
            "src_ip": "0.0.0.0",
            "src_port": 68,
            "dst_ip": "255.255.255.255",
            "dst_port": 67,
        }

        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(args, 0, json.dumps(line) + "\n", "")

        monkeypatch.setattr(compare_zeek_baselines.subprocess, "run", fake_run)
        with pytest.raises(ValueError, match="schema version"):
            ja4plus_readings(CAPTURE)


class TestTheEndToEndRun:
    def test_the_script_reports_no_difference_when_the_baseline_agrees(self, tmp_path):
        write_baseline(tmp_path, CLIENT_FINGERPRINTS + SERVER_FINGERPRINTS)
        run = run_script(tmp_path)
        assert run.returncode == 0, run.stderr
        assert (
            f"| {CLIENT_CONNECTION[0]} / {CLIENT_CONNECTION[1]} | ja4d | "
            f"`{','.join(CLIENT_FINGERPRINTS)}` | `{','.join(CLIENT_FINGERPRINTS)}` | yes |"
        ) in run.stdout
        assert (
            f"| {SERVER_CONNECTION[0]} / {SERVER_CONNECTION[1]} | ja4d | "
            f"`{','.join(SERVER_FINGERPRINTS)}` | `{','.join(SERVER_FINGERPRINTS)}` | yes |"
        ) in run.stdout
        assert "Connection-and-method pairs that differ: 0" in run.stdout

    def test_the_script_counts_a_difference_when_the_baseline_disagrees(self, tmp_path):
        write_baseline(
            tmp_path,
            ["dpack0000nn_58-59-51-54-1_00"] + CLIENT_FINGERPRINTS[1:] + SERVER_FINGERPRINTS,
        )
        run = run_script(tmp_path)
        assert run.returncode == 0, run.stderr
        assert "| NO |" in run.stdout
        assert "Connection-and-method pairs that differ: 1" in run.stdout


@pytest.fixture(scope="module")
def committed_report() -> list[list[str]]:
    """Return the comparison rows the script prints against the committed baselines."""
    run = run_script()
    assert run.returncode == 0, run.stderr
    return comparison_rows(run.stdout)


@pytest.mark.spec_validation
class TestTheCommittedBaselinesRunAsAGate:
    """Measure the whole Zeek comparison against the committed baselines.

    `docs/specs/foxio/zeek.md` records the run of #327, and every count below comes from
    that record. The comparison ran by hand until #515, so a fingerprint that moved
    against the Zeek package reached no gate.
    """

    def test_the_comparison_reads_every_baseline_and_every_capture(self, committed_report):
        """The report holds one row for each connection and method the two both produce."""
        assert len(committed_report) == COMPARED_ROWS

    def test_the_comparison_holds_the_difference_count_the_reading_records(self, committed_report):
        """The count of differing rows equals the count #327 measured."""
        differing = [row for row in committed_report if row[4] == "NO"]
        assert len(differing) == DIFFERING_ROWS, "\n".join(
            "{} {} zeek={} ja4plus={}".format(row[0], row[1], row[2], row[3]) for row in differing
        )

    def test_the_comparison_holds_the_match_count_the_reading_records(self, committed_report):
        """The count of matching rows equals the count #327 measured."""
        matching = [row for row in committed_report if row[4] == "yes"]
        assert len(matching) == COMPARED_ROWS - DIFFERING_ROWS

    def test_the_baselines_hold_ten_ja4ts_rows(self, committed_report):
        """The three `conn.log` baselines carry ten JA4TS connections."""
        assert len([row for row in committed_report if row[1] == "ja4ts"]) == JA4TS_ROWS

    def test_nine_of_the_ten_ja4ts_rows_match(self, committed_report):
        """JA4TS agrees with the FoxIO Zeek package on nine of its ten connections."""
        rows = [row for row in committed_report if row[1] == "ja4ts"]
        matching = [row for row in rows if row[4] == "yes"]
        assert len(matching) == JA4TS_MATCHING_ROWS, "\n".join(
            "{} zeek={} ja4plus={}".format(row[0], row[2], row[3]) for row in rows
        )
