"""Fingerprint a capture from the wheel, installed into a clean environment.

`FR-pre-release-validation-1` to `FR-pre-release-validation-7` state the requirements.
#68 and #69 read the contents of the wheel. No case before this one installed the wheel
and then produced a fingerprint.

**A run that resolves the working copy proves nothing.** Every job of
`.github/workflows/test.yml` installs with `pip install -e ".[dev]"`, which puts the
source tree on the import path. A case that imports `ja4plus` therefore measures the
checkout. Every command here runs with the working directory set to the temporary
directory, and `test_the_import_check_fails_for_the_source_tree` proves the check
discriminates.

**The control case is not optional.** Without it the byte-for-byte comparison passes on
any wheel that imports. `test_the_lookup_reports_an_empty_database_without_the_mapping_file`
removes the mapping file and reads the same probe again.

**Every case here carries the `installed_wheel` marker, and `tests/conftest.py` deselects
that marker from a run that does not name it.** The `installed-wheel` job of
`.github/workflows/test.yml` is the only runner of the marker, and the `conformance` job
holds the same relation to `spec_validation`. The build and the install cost about 23 s,
and `pip` reaches the index for the dependency list, so the unit gate carries neither.
`tests/test_installed_wheel_selection.py` holds that rule against three commands.

#68 owns `.github/workflows/publish.yml`. **#68 imports this file rather than writing
the check again**, so `build_artifacts`, `create_clean_environment` and
`package_file_of` stay public.

#409 installs the source distribution. The build, the environment creation and the
comparison each take the artifact as a parameter, so #409 passes another artifact to the
same three functions.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.installed_wheel

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = REPOSITORY_ROOT / "tests" / "foxio_vectors"
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "test.yml"

# The capture the three paths read. `tls12.pcap` carries one TLS handshake, so the run
# produces a JA4 fingerprint and the output holds one line.
CAPTURE_VECTOR = "tls12.pcap"

# The name the job carries in `.github/workflows/test.yml`, and the marker that job runs.
JOB_NAME = "installed-wheel"
MARKER = "installed_wheel"

# One fingerprint that `ja4plus/data/ja4plus-mapping.csv` names. The control case reads
# this value before it removes the mapping file and after it, so a hit and a miss
# separate the two states.
MAPPED_FINGERPRINT = "t13i181000_85036bcba153_d41ae481755e"

# The probe that exercises the public interface. It imports `ja4plus`, builds a
# `Processor`, reads the capture with `scapy`, and writes one line for each fingerprint
# it collects. The order of the lines is the order the processor produced them.
PROCESSOR_PROBE = '''\
"""Write one line for every fingerprint the processor reads from the capture."""

import sys

from scapy.all import rdpcap

from ja4plus.processor import Processor

processor = Processor()
for packet in rdpcap(sys.argv[1]):
    for result in processor.process_packet(packet):
        sys.stdout.write("%s %s\\n" % (result.type, result.fingerprint))
'''

# The probe the control case reads. It writes the entry count of the mapping the lookup
# holds, and it writes whether the lookup answers for one named fingerprint.
LOOKUP_PROBE = '''\
"""Write the entry count of the mapping, and the answer for one named fingerprint."""

import sys

from ja4plus.ja4db import JA4DBClient, load_mapping_file

mapping, source, path = load_mapping_file()
answered = JA4DBClient().lookup(sys.argv[1]) is not None
sys.stdout.write("%d %s\\n" % (len(mapping), answered))
'''


@dataclasses.dataclass(frozen=True)
class CleanEnvironment:
    """One virtual environment that holds the installed package.

    Attributes:
        root: The directory `python -m venv` created.
        python: The interpreter of the environment.
        script: The `ja4plus` console script of the environment.
        site_packages: The `purelib` directory the interpreter reports.
        pip_output: The standard output of the `pip install` run, kept for #409.
    """

    root: pathlib.Path
    python: pathlib.Path
    script: pathlib.Path
    site_packages: pathlib.Path
    pip_output: str


def _binary_directory(root: pathlib.Path) -> pathlib.Path:
    """Return the directory that holds the interpreter of one virtual environment.

    `venv` writes `bin` on POSIX and `Scripts` on Windows.

    Verified against: https://docs.python.org/3/library/venv.html (retrieved 2026-08-09).
    """
    return root / ("Scripts" if os.name == "nt" else "bin")


def build_artifacts(destination: pathlib.Path) -> dict[str, pathlib.Path]:
    """Return the artifacts that `python -m build` writes for this project.

    `build` writes the source distribution from the source tree, and it writes the wheel
    from that source distribution. `--outdir` names the directory, because the default
    `{srcdir}/dist` writes into the checkout.

    Verified against: https://build.pypa.io/en/stable/reference/cli.html
    (retrieved 2026-08-09).

    Args:
        destination: The directory `build` writes both artifacts into.

    Returns:
        The `wheel` path and the `sdist` path.

    Raises:
        AssertionError: `build` wrote no wheel, or it wrote no source distribution.
    """
    subprocess.run(
        [sys.executable, "-m", "build", "--outdir", str(destination), str(REPOSITORY_ROOT)],
        check=True,
        capture_output=True,
        text=True,
        env=_scrubbed_environment(),
    )
    wheels = sorted(destination.glob("*.whl"))
    sdists = sorted(destination.glob("*.tar.gz"))
    assert len(wheels) == 1, f"build wrote {len(wheels)} wheels into {destination}"
    assert len(sdists) == 1, f"build wrote {len(sdists)} source distributions into {destination}"
    return {"wheel": wheels[0], "sdist": sdists[0]}


def create_clean_environment(
    root: pathlib.Path,
    artifact: pathlib.Path,
    pip_arguments: tuple[str, ...] = (),
) -> CleanEnvironment:
    """Return one clean environment that holds the artifact.

    The environment installs no development extra, so `pip` reads the dependency list the
    artifact ships. `pip install <path>` installs the local file and resolves that list
    from the index.

    Verified against: https://pip.pypa.io/en/stable/cli/pip_install/ and
    https://docs.python.org/3/library/venv.html (retrieved 2026-08-09).

    Args:
        root: The directory `python -m venv` creates. It must not exist.
        artifact: The wheel or the source distribution to install.
        pip_arguments: Further arguments for `pip install`. #409 passes
            `--no-binary ja4plus` here.

    Returns:
        The environment.

    Raises:
        subprocess.CalledProcessError: `venv` failed, or `pip install` failed.
    """
    variables = _scrubbed_environment()
    subprocess.run(
        [sys.executable, "-m", "venv", str(root)],
        check=True,
        capture_output=True,
        text=True,
        env=variables,
    )
    python = _binary_directory(root) / "python"
    install = subprocess.run(
        [str(python), "-m", "pip", "install", *pip_arguments, str(artifact)],
        check=True,
        capture_output=True,
        text=True,
        env=variables,
    )
    site_packages = subprocess.run(
        [str(python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        check=True,
        capture_output=True,
        text=True,
        env=variables,
    ).stdout.strip()
    environment = CleanEnvironment(
        root=root,
        python=python,
        script=_binary_directory(root) / "ja4plus",
        site_packages=pathlib.Path(site_packages),
        pip_output=install.stdout,
    )
    # **`pip` reports success when it installs the dependencies alone.** It reads the
    # requirement as satisfied where the package already imports, and it then writes no
    # `ja4plus` into `site-packages`. This check names that state where it happens, rather
    # than leaving a later case to report a missing file.
    package_directory = environment.site_packages / "ja4plus"
    assert package_directory.is_dir(), (
        f"pip wrote no {package_directory}, and it reported: {install.stdout}"
    )
    return environment


def _scrubbed_environment() -> dict[str, str]:
    """Return the ambient environment without the two variables that break the isolation.

    **`PYTHONPATH` names a directory that every interpreter reads before `site-packages`.**
    A shell that points it at this checkout breaks this file in two ways, and a
    measurement of 2026-08-09 proved both.

    1. `pip install <wheel>` reads the requirement as satisfied, because the package
       already imports. It then installs the dependencies, it installs no `ja4plus`, and
       it reports `Successfully installed` with `ja4plus` absent from the list.
    2. A probe of the clean environment imports the source tree, so a comparison holds
       the checkout against itself.

    `PYTHONNOUSERSITE` bars the per-user directory for the same reason. Every other
    variable stays, because `pip` reads the index settings and the proxy settings of the
    host to resolve the dependency list.
    """
    variables = dict(os.environ)
    variables.pop("PYTHONPATH", None)
    variables["PYTHONNOUSERSITE"] = "1"
    return variables


def _run_environment() -> dict[str, str]:
    """Return the environment every probe runs under.

    The lookup prefers the cached mapping file over the bundled one. A cached file on the
    host therefore changes the result of the control case. `HOME` and `XDG_CACHE_HOME`
    name a directory that holds no cached file. That directory removes the difference
    from both sides of every comparison.
    """
    variables = _scrubbed_environment()
    variables.pop("JA4PLUS_DB_LOOKUP", None)
    variables["PYTHONDONTWRITEBYTECODE"] = "1"
    return variables


def run_probe(
    python: pathlib.Path,
    arguments: list[str],
    working_directory: pathlib.Path,
    cache_home: pathlib.Path,
) -> bytes:
    """Return the standard output of one probe run.

    Standard error carries a deprecation warning that `scapy` writes at import time, and
    the two environments hold two dependency sets. The comparison therefore reads
    standard output alone.

    Args:
        python: The interpreter that runs the probe.
        arguments: The arguments after the interpreter.
        working_directory: The directory the run starts in. The repository root puts the
            source tree on the import path, so a clean run names another directory.
        cache_home: The directory that holds `HOME` and `XDG_CACHE_HOME` for this run.

    Returns:
        The standard output, as bytes.

    Raises:
        AssertionError: The run reported a non-zero status.
    """
    variables = _run_environment()
    variables["HOME"] = str(cache_home)
    variables["XDG_CACHE_HOME"] = str(cache_home)
    completed = subprocess.run(
        [str(python), *arguments],
        cwd=str(working_directory),
        capture_output=True,
        env=variables,
    )
    assert completed.returncode == 0, (
        f"{python} {' '.join(arguments)} reported status {completed.returncode}: "
        f"{completed.stderr.decode('utf-8', 'replace')}"
    )
    return completed.stdout


def package_file_of(python: pathlib.Path, working_directory: pathlib.Path) -> str:
    """Return the `ja4plus.__file__` value that one interpreter reports.

    Args:
        python: The interpreter that imports the package.
        working_directory: The directory the run starts in. The interpreter puts this
            directory at the front of `sys.path`, so it decides which copy wins.

    Returns:
        The path of `ja4plus/__init__.py`, as the interpreter resolved it.
    """
    completed = subprocess.run(
        [str(python), "-c", "import ja4plus; print(ja4plus.__file__)"],
        cwd=str(working_directory),
        capture_output=True,
        text=True,
        env=_run_environment(),
    )
    assert completed.returncode == 0, f"the import reported status {completed.returncode}"
    return completed.stdout.strip()


def resolves_outside_the_repository(
    package_file: str,
    site_packages: pathlib.Path,
    repository_root: pathlib.Path = REPOSITORY_ROOT,
) -> bool:
    """Report whether one `ja4plus.__file__` value names the installed package.

    `FR-pre-release-validation-4` states the requirement. The value must lie below the
    `site-packages` directory of the clean environment, and it must hold no part of the
    repository root. macOS resolves `/tmp` through a symbolic link, so each path passes
    through `os.path.realpath` first.

    Args:
        package_file: The `ja4plus.__file__` value one interpreter reported.
        site_packages: The `purelib` directory of the clean environment.
        repository_root: The checkout this suite runs from.

    Returns:
        True when the value names the installed package, False otherwise.
    """
    package = os.path.realpath(package_file)
    installed = os.path.realpath(str(site_packages))
    checkout = os.path.realpath(str(repository_root))
    below_site_packages = os.path.commonpath([package, installed]) == installed
    holds_no_checkout = os.path.commonpath([package, checkout]) != checkout
    return below_site_packages and holds_no_checkout


def declared_version() -> str:
    """Return the version that the `[project]` block of `pyproject.toml` declares.

    Python 3.9 carries no `tomllib`, and the test matrix holds 3.9, so this reader
    matches the line rather than parsing the file.

    Returns:
        The version string.

    Raises:
        AssertionError: The file holds no top-level `version` line.
    """
    text = (REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', text, re.MULTILINE)
    assert match is not None, "pyproject.toml holds no top-level version line"
    return match.group(1)


@pytest.fixture(scope="session")
def artifacts(tmp_path_factory: pytest.TempPathFactory) -> dict[str, pathlib.Path]:
    """Build the wheel and the source distribution once for the whole session."""
    return build_artifacts(tmp_path_factory.mktemp("dist"))


@pytest.fixture(scope="session")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """Return the directory every probe runs in, holding a copy of the capture.

    The repository root is not on the import path of a run that starts here.
    """
    directory = tmp_path_factory.mktemp("workspace")
    shutil.copyfile(VECTORS / CAPTURE_VECTOR, directory / CAPTURE_VECTOR)
    (directory / "processor_probe.py").write_text(PROCESSOR_PROBE, encoding="utf-8")
    (directory / "lookup_probe.py").write_text(LOOKUP_PROBE, encoding="utf-8")
    (directory / "cache").mkdir()
    return directory


@pytest.fixture(scope="session")
def wheel_environment(
    artifacts: dict[str, pathlib.Path],
    tmp_path_factory: pytest.TempPathFactory,
) -> CleanEnvironment:
    """Install the wheel into one clean environment for the whole session."""
    return create_clean_environment(
        tmp_path_factory.mktemp("wheel-env") / "env", artifacts["wheel"]
    )


@pytest.fixture(scope="session")
def control_environment(
    artifacts: dict[str, pathlib.Path],
    tmp_path_factory: pytest.TempPathFactory,
) -> CleanEnvironment:
    """Install the wheel into a second environment that the control case damages.

    The control case removes the mapping file, so it needs an environment that no other
    case reads.
    """
    return create_clean_environment(
        tmp_path_factory.mktemp("control-env") / "env", artifacts["wheel"]
    )


def test_the_clean_environment_imports_ja4plus_from_its_own_site_packages(
    wheel_environment: CleanEnvironment, workspace: pathlib.Path
) -> None:
    """`FR-pre-release-validation-4`. The clean environment resolves the installed copy."""
    package_file = package_file_of(wheel_environment.python, workspace)
    assert resolves_outside_the_repository(package_file, wheel_environment.site_packages), (
        f"the clean environment imported {package_file}, which is not below "
        f"{wheel_environment.site_packages}"
    )


def test_the_import_check_fails_for_the_source_tree(
    wheel_environment: CleanEnvironment,
) -> None:
    """The check that names the installed copy rejects the source tree.

    Warning: never remove this case. The assertion above passes on any value that lies
    below `site-packages`, and a check that cannot fail measures nothing. This case reads
    the `ja4plus.__file__` of the interpreter that runs the suite, which the editable
    install resolves to the checkout, and it asserts that the same predicate reports
    False.
    """
    source_tree_file = package_file_of(pathlib.Path(sys.executable), REPOSITORY_ROOT)
    assert os.path.commonpath(
        [os.path.realpath(source_tree_file), os.path.realpath(str(REPOSITORY_ROOT))]
    ) == os.path.realpath(str(REPOSITORY_ROOT)), (
        f"the suite runs against {source_tree_file}, which is outside the checkout, so "
        "this case cannot prove the check discriminates"
    )
    assert not resolves_outside_the_repository(source_tree_file, wheel_environment.site_packages), (
        f"the check accepted {source_tree_file}, which lies inside the repository root"
    )


def test_the_clean_environment_reports_the_version_of_pyproject(
    wheel_environment: CleanEnvironment, workspace: pathlib.Path
) -> None:
    """The console script of the clean environment writes the declared version."""
    written = run_probe(wheel_environment.script, ["--version"], workspace, workspace / "cache")
    assert written.decode("utf-8").strip() == f"ja4plus {declared_version()}"


def test_the_analyze_output_of_the_clean_environment_equals_the_source_tree(
    wheel_environment: CleanEnvironment, workspace: pathlib.Path
) -> None:
    """`FR-pre-release-validation-3` and `FR-pre-release-validation-5`.

    Both runs call `ja4plus.cli:main` on one copy of the capture, and the two outputs are
    equal byte for byte.
    """
    # Both runs name the same copy of the capture by an absolute path, because the two
    # working directories differ. The output holds no path, so the two lines stay equal.
    arguments = [
        "-m",
        "ja4plus.cli",
        "analyze",
        str(workspace / CAPTURE_VECTOR),
        "--format",
        "json",
    ]
    installed = run_probe(wheel_environment.python, arguments, workspace, workspace / "cache")
    source_tree = run_probe(
        pathlib.Path(sys.executable), arguments, REPOSITORY_ROOT, workspace / "cache"
    )
    assert installed, "the clean environment wrote no output line"
    assert installed == source_tree


def test_the_imported_processor_produces_the_same_fingerprint_list(
    wheel_environment: CleanEnvironment, workspace: pathlib.Path
) -> None:
    """`FR-pre-release-validation-2` and `FR-pre-release-validation-5`.

    The probe imports `ja4plus`, builds a `Processor`, and writes one line for each
    fingerprint. The two lists hold the same lines in the same order.
    """
    arguments = [str(workspace / "processor_probe.py"), str(workspace / CAPTURE_VECTOR)]
    installed = run_probe(wheel_environment.python, arguments, workspace, workspace / "cache")
    source_tree = run_probe(
        pathlib.Path(sys.executable), arguments, REPOSITORY_ROOT, workspace / "cache"
    )
    assert installed.splitlines(), "the clean environment collected no fingerprint"
    assert installed.splitlines() == source_tree.splitlines()


def test_the_lookup_reports_an_empty_database_without_the_mapping_file(
    control_environment: CleanEnvironment, workspace: pathlib.Path
) -> None:
    """`FR-pre-release-validation-6`. The control case proves the comparison can fail.

    The probe reads the entry count of the mapping and the answer for one named
    fingerprint. It runs before the removal and after it, so a passing wheel and a broken
    wheel produce two different lines.
    """
    arguments = [str(workspace / "lookup_probe.py"), MAPPED_FINGERPRINT]
    # This case damages its environment, so it reads a cache directory that no other case
    # reads. A shared directory would carry a mapping file from one environment to the
    # other as soon as a probe writes one.
    cache_home = control_environment.root.parent / "cache"
    cache_home.mkdir(exist_ok=True)
    before = run_probe(control_environment.python, arguments, workspace, cache_home).decode("utf-8")
    count, answered = before.split()
    assert int(count) > 0, "the installed wheel holds no mapping entry before the removal"
    assert answered == "True", f"the installed wheel holds no entry for {MAPPED_FINGERPRINT}"

    mapping_file = control_environment.site_packages / "ja4plus" / "data" / "ja4plus-mapping.csv"
    assert mapping_file.is_file(), f"the wheel shipped no {mapping_file}"
    mapping_file.unlink()

    after = run_probe(control_environment.python, arguments, workspace, cache_home).decode("utf-8")
    assert after.split() == ["0", "False"], (
        f"the lookup reported {after.strip()!r} without the mapping file, and an empty "
        "database reports '0 False'"
    )


def _job_block(name: str) -> list[str]:
    """Return the lines of one job of `.github/workflows/test.yml`.

    A job starts at a line of two spaces, the name and a colon. It ends at the next such
    line. The reader matches the text, because no gate installs a YAML parser.

    Args:
        name: The job name.

    Returns:
        The lines of the job, without the header line. The list is empty when the file
        holds no job of that name.
    """
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    header = re.compile(r"^  (\S+):\s*$")
    block: list[str] = []
    collecting = False
    for line in lines:
        match = header.match(line)
        if match:
            if collecting:
                break
            collecting = match.group(1) == name
            continue
        if collecting:
            block.append(line)
    return block


def test_the_workflow_holds_a_job_that_runs_the_installed_wheel_marker() -> None:
    """`FR-pre-release-validation-7`. One job names this marker.

    The job names the check, so a failure is visible without a log search. The `fuzz` job
    and the `samples` job of the same file state the same reason.
    """
    block = _job_block(JOB_NAME)
    assert block, f".github/workflows/test.yml holds no job named {JOB_NAME}"
    text = "\n".join(block)
    assert f"-m {MARKER}" in text, f"the {JOB_NAME} job runs no command with -m {MARKER}"
