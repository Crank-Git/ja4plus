"""Run every script of `examples/`.

FR-documentation-6 states the requirement. #63 states the defect: a script nobody runs
is prose that reads as evidence, and this project has recorded seventeen instances of a
comparison that never happened reading as a comparison that passed.

Every script runs in a subprocess, against a committed capture. No script reaches an
interface and no script reaches the network.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
from typing import Dict, List, Tuple

import pytest

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
EXAMPLES = REPOSITORY_ROOT / "examples"
VECTORS = REPOSITORY_ROOT / "tests" / "foxio_vectors"

# The capture every script reads. It carries a TLS handshake and an HTTP response, so
# several methods produce a value from it.
CAPTURE_VECTOR = "https3-301-get.pcap"
CAPTURE_NAME = "capture.pcap"

# The command line each script runs under. A script that carries several modes names one
# line for each mode, because a mode nobody runs is a mode nobody tests.
#
# Warning: never remove an entry to make this file pass. Every script of `examples/`
# names at least one line here, and `test_the_table_names_every_example_script` fails
# where one does not.
EXAMPLE_COMMANDS: Dict[str, List[Tuple[str, List[str]]]] = {
    "demo_fingerprints.py": [("the built-in demonstration", [])],
    "pcap_analysis.py": [("a capture file", [CAPTURE_NAME])],
    "threat_detection.py": [("a capture file", [CAPTURE_NAME])],
    "tcpdump_workflows.py": [
        ("the analyze mode", ["analyze", CAPTURE_NAME]),
        ("the filter recipes", ["filters"]),
    ],
    "live_traffic_fingerprinting.py": [("the capture-file mode", ["--pcap", CAPTURE_NAME])],
}

# `examples/` held this many scripts on 2026-08-09, and the table above names this many
# command lines. A reader that finds nothing passes every case on an empty list, so the
# floor fails such a reader.
MINIMUM_SCRIPTS = 5
MINIMUM_COMMANDS = 6


def _script_names() -> List[str]:
    """Return the file name of every script of `examples/`, in sorted order."""
    return sorted(path.name for path in EXAMPLES.glob("*.py"))


def test_the_reader_finds_at_least_the_measured_count_of_scripts() -> None:
    """`examples/` holds no fewer scripts than the count measured on 2026-08-09."""
    found = _script_names()
    assert len(found) >= MINIMUM_SCRIPTS, (
        f"the reader found {len(found)} scripts, and the floor is {MINIMUM_SCRIPTS}: {found}"
    )


def test_the_table_holds_at_least_the_measured_count_of_command_lines() -> None:
    """The table names no fewer command lines than the count measured on 2026-08-09."""
    total = sum(len(lines) for lines in EXAMPLE_COMMANDS.values())
    assert total >= MINIMUM_COMMANDS, (
        f"the table names {total} command lines, and the floor is {MINIMUM_COMMANDS}"
    )


def test_the_table_names_every_example_script() -> None:
    """`EXAMPLE_COMMANDS` names every script of `examples/`, and no other file.

    A new script fails this case until somebody records how to run it. A script nobody
    records is a script nobody runs.
    """
    assert set(_script_names()) == set(EXAMPLE_COMMANDS)


@pytest.fixture(scope="module")
def example_workspace(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """Return a directory that holds the capture the scripts read."""
    workspace = tmp_path_factory.mktemp("examples")
    shutil.copyfile(VECTORS / CAPTURE_VECTOR, workspace / CAPTURE_NAME)
    return workspace


_CASES = [
    (script, description, arguments)
    for script, lines in sorted(EXAMPLE_COMMANDS.items())
    for description, arguments in lines
]


@pytest.mark.parametrize(
    "script,description,arguments", _CASES, ids=[f"{s}-{d}" for s, d, _ in _CASES]
)
def test_the_example_script_runs(
    script: str,
    description: str,
    arguments: List[str],
    example_workspace: pathlib.Path,
) -> None:
    """The script runs against a committed capture and ends with the status zero."""
    # The environment of the run carries `HOME` and the rest, because `scapy` reads the
    # home directory at import time.
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, str(EXAMPLES / script), *arguments],
        cwd=str(example_workspace),
        capture_output=True,
        text=True,
        timeout=300,
        env=environment,
    )
    assert completed.returncode == 0, (
        f"{script} under {description} ended with the status {completed.returncode}\n"
        f"{completed.stdout}\n{completed.stderr}"
    )
    assert completed.stdout.strip(), f"{script} under {description} wrote no output"
