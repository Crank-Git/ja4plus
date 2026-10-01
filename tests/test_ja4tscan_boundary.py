"""Hold the boundary between the passive package and the scanner.

The maintainer ruled on 2026-09-30, in #775, that nothing in `Processor` or a passive
fingerprinter can send a packet. `docs/specs/features/12-active-scan.md` states the
boundary as FR-active-scan-4, FR-active-scan-5, FR-active-scan-6 and FR-active-scan-7.
Each case reads the source of `ja4plus/`, or imports it in a fresh interpreter, so a new
module reaches every case with no edit here.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.dependency_entries import dependency_entries

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = REPO_ROOT / "ja4plus"
SCAN_PACKAGE = PACKAGE / "scan"
PYPROJECT = REPO_ROOT / "pyproject.toml"

MODULES = sorted(PACKAGE.rglob("*.py"))
OUTSIDE = [path for path in MODULES if SCAN_PACKAGE not in path.parents]
INSIDE = [path for path in MODULES if SCAN_PACKAGE in path.parents]


def _name(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


# A dotted name inside a string reaches `importlib.import_module` as well as an import
# statement does, so the case reads both.
SCAN_MODULE = re.compile(r"ja4plus\.scan(\.\w+)*")


def scan_references(path: Path) -> list[str]:
    """Return every import of `ja4plus.scan`, and every string that names one of its modules."""
    found = []
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            found += [alias.name for alias in node.names if SCAN_MODULE.fullmatch(alias.name)]
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if SCAN_MODULE.fullmatch(module):
                found.append(module)
            elif module == "ja4plus" or (node.level and module == ""):
                found += [f"ja4plus.{alias.name}" for alias in node.names if alias.name == "scan"]
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if SCAN_MODULE.fullmatch(node.value):
                found.append(node.value)
    return found


def test_the_reader_finds_every_form_of_a_scan_import(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        "import ja4plus.scan\n"
        "from ja4plus.scan.link import LinkNetwork\n"
        "from ja4plus import scan\n"
        "import importlib\n"
        "importlib.import_module('ja4plus.scan.command')\n"
        "text = 'the scanner of `ja4plus.scan` is apart'\n",
        encoding="utf-8",
    )
    assert scan_references(source) == [
        "ja4plus.scan",
        "ja4plus.scan.link",
        "ja4plus.scan",
        "ja4plus.scan.command",
    ]


@pytest.mark.parametrize("path", OUTSIDE, ids=_name)
def test_no_module_outside_the_scan_package_imports_it(path):
    assert scan_references(path) == [], f"{_name(path)} reaches ja4plus.scan"


def test_the_case_reads_every_module_of_the_package():
    assert len(OUTSIDE) >= 30
    assert {path.name for path in INSIDE} >= {"__init__.py", "link.py", "scanner.py"}


def _loaded_scan_modules(statement: str) -> list[str]:
    """Run the statement in a fresh interpreter, and return each scan module it loaded."""
    probe = f"{statement}\nimport sys\nprint(sorted(m for m in sys.modules if m.startswith('ja4plus.scan')))"
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, cwd=REPO_ROOT, check=True
    )
    return ast.literal_eval(result.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize(
    "statement",
    [
        "import ja4plus",
        "import ja4plus.processor",
        "import ja4plus.cli",
        "import ja4plus.watch",
        "from ja4plus.fingerprinters import *",
    ],
)
def test_the_passive_path_loads_no_module_of_the_scanner(statement):
    assert _loaded_scan_modules(statement) == []


def test_the_probe_of_loaded_modules_sees_a_scan_import():
    assert "ja4plus.scan.link" in _loaded_scan_modules("import ja4plus.scan.link")


# The `scapy` names that put a packet on the wire, or open a socket that can.
SEND_NAMES = frozenset(
    {
        "send",
        "sendp",
        "sendpfast",
        "sr",
        "sr1",
        "srp",
        "srp1",
        "srloop",
        "srploop",
        "L2socket",
        "L3socket",
        "getmacbyip",
        "arping",
    }
)


def send_names(path: Path) -> list[str]:
    """Return each `scapy` name of the module that sends a packet."""
    found = []
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("scapy"):
            found += [alias.name for alias in node.names if alias.name in SEND_NAMES]
        elif isinstance(node, ast.Attribute) and node.attr in SEND_NAMES:
            if isinstance(node.value, ast.Name) and node.value.id in ("conf", "scapy"):
                found.append(node.attr)
    return found


@pytest.mark.parametrize("path", OUTSIDE, ids=_name)
def test_no_module_outside_the_scan_package_holds_a_send_function(path):
    assert send_names(path) == [], f"{_name(path)} can send a packet"


def test_the_send_reader_finds_the_send_functions_of_the_link_module():
    assert set(send_names(SCAN_PACKAGE / "link.py")) == {"L2socket", "getmacbyip"}


# The calls that run a command of the host.
COMMAND_CALLS = frozenset(
    {
        ("os", "system"),
        ("os", "popen"),
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "check_call"),
        ("subprocess", "check_output"),
        ("subprocess", "Popen"),
    }
)
FIREWALL_WORDS = ("iptables", "pfctl", "nft")


def firewall_commands(path: Path) -> list[str]:
    """Return each call of the module that runs a host command naming a firewall tool."""
    found = []
    for node in ast.walk(_tree(path)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        owner = node.func.value
        if not isinstance(owner, ast.Name) or (owner.id, node.func.attr) not in COMMAND_CALLS:
            continue
        text = ast.unparse(node)
        found += [word for word in FIREWALL_WORDS if word in text]
    return found


def test_the_firewall_reader_finds_a_command_that_names_iptables(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        "import os, subprocess\nos.system('iptables -A INPUT -j DROP')\n"
        "subprocess.run(['pfctl', '-f', 'rules'])\n",
        encoding="utf-8",
    )
    assert firewall_commands(source) == ["iptables", "pfctl"]


@pytest.mark.parametrize("path", MODULES, ids=_name)
def test_no_module_runs_a_firewall_command(path):
    assert firewall_commands(path) == [], f"{_name(path)} changes firewall state"


@pytest.mark.parametrize("path", INSIDE, ids=_name)
def test_the_scan_package_runs_no_host_command(path):
    names = {
        alias.name
        for node in ast.walk(_tree(path))
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    modules = {node.module for node in ast.walk(_tree(path)) if isinstance(node, ast.ImportFrom)}
    assert "subprocess" not in names | modules
    assert "os" not in names


def _distribution(entry: str) -> str:
    """Return the distribution name of one requirement, lowercase."""
    return re.split(r"[<>=!~;\[ ]", entry, maxsplit=1)[0].strip().lower()


def test_the_scan_extra_names_every_dependency_the_core_install_lacks():
    text = PYPROJECT.read_text(encoding="utf-8")
    core = {_distribution(entry) for entry in dependency_entries(text, "dependencies = [")}
    if re.search(r"^scan = \[\]$", text, re.MULTILINE):
        extra: set[str] = set()
    else:
        extra = {_distribution(entry) for entry in dependency_entries(text, "scan = [")}
    imported = set()
    for path in INSIDE:
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                imported.add(node.module.split(".")[0])
    third_party = imported - set(sys.stdlib_module_names) - {"ja4plus", "__future__"}
    assert third_party, "the reader found no third-party import in ja4plus/scan/"
    assert third_party <= core | extra, f"{sorted(third_party - core - extra)} is in no list"


def test_pyproject_declares_the_scan_extra_and_the_command_entry_point():
    text = PYPROJECT.read_text(encoding="utf-8")
    assert re.search(r"^scan = \[", text, re.MULTILINE)
    assert '[project.entry-points."ja4plus.commands"]' in text
    assert 'scan = "ja4plus.scan.command:run"' in text
