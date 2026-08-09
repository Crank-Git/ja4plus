"""Run the Zeek baseline comparison script end to end and check what it prints.

`docs/specs/foxio/zeek.md` cites readings that `tests/compare_zeek_baselines.py`
produced, so the script is evidence-producing tooling. No gate ran it, and #49 broke it
by removing the composite `source` field that its reader read. These cases run the
script over a committed capture, so the next change to the output schema breaks a case
instead of breaking the script in silence.

This repository holds no Zeek baseline. Each case therefore writes a baseline in the
Zeek TSV form and states the fingerprints it expects, which measures the reader, the
connection key and the comparison. It measures no FoxIO value.
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


def run_script(reference: Path) -> subprocess.CompletedProcess[str]:
    """Return the finished run of the comparison script against one reference."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(reference)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


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
