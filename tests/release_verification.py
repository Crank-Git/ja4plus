"""Build the release and verify it in a clean environment, before the publish.

`.github/workflows/publish.yml` runs this module in one step, in front of the step that
uploads to PyPI. `FR-release-4` to `FR-release-9` state the checks, and a publish to PyPI
cannot be undone, so each one runs before the upload and never after it.

The check runs five commands in this order.

1. `python -m build` writes the source distribution and the wheel. `FR-release-4`.
2. `twine check` reads both files. `FR-release-9`.
3. `pip install <the wheel>` fills a clean environment. `FR-release-5`.
4. The console script of that environment writes the version. `FR-release-6`.
5. The conformance suite of the checkout runs against that installation. `FR-release-7`.

**The conformance suite lives under `tests/`, and #455 removed `tests/` from the wheel.**
The suite therefore comes from the checkout and the package comes from the environment.
**A run that starts in the repository root reads the source tree.** `python -m` puts the
working directory on `sys.path`. `pytest` inserts the parent of the `tests` package there
as well. Both paths name the checkout, and both hold `ja4plus/`. `verification_root` copies
the suite to a directory that holds no package source. The check then reads
`ja4plus.__file__` from that directory before it runs one case.

**This module rewrites no part of the repair #408 built.** `build_artifacts`,
`create_clean_environment`, `package_file_of` and `run_probe` of
`tests/test_installed_wheel.py` scrub `PYTHONPATH`, set `PYTHONNOUSERSITE`, and assert
that `pip` wrote the package into `site-packages`. `pip install` reports
`Successfully installed` while it installs the dependencies alone, whenever the package
already imports, so that assertion is what establishes the install. This module imports
those functions and adds the steps around them.

`tests/test_publish_workflow.py` holds every case against this module and against the
workflow.
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Sequence

from tests.dependency_entries import dependency_entries

# `_run_environment` carries the repair of #408, and a copy of it here would be a second
# record of one rule. The other four names are public, and the module docstring of
# `tests/test_installed_wheel.py` states that they stay public for this module.
from tests.test_installed_wheel import (
    REPOSITORY_ROOT,
    CleanEnvironment,
    _run_environment,
    build_artifacts,
    create_clean_environment,
    declared_version,
    package_file_of,
    run_probe,
)

# The command `.github/workflows/publish.yml` states. A case holds the workflow against
# this text, so the workflow cannot name an entry point no case runs.
CHECK_COMMAND = "python -m tests.release_verification"

# The marker of the conformance suite. `CLAUDE.md` states the command that names it.
CONFORMANCE_MARKER = "spec_validation"

# The line that opens the development extra of `pyproject.toml`, and the distribution the
# check installs from it. The clean environment holds the shipped dependency list, which
# carries no test runner.
DEV_EXTRA = "dev = ["
TEST_RUNNER = "pytest"

# The names `verification_root` copies out of the checkout. `pyproject.toml` comes too,
# because it registers the markers of the suite and it makes the copy the `pytest` root.
COPIED_NAMES = ("tests", "pyproject.toml")

# The package directory of the checkout. The verification root holds no directory of this
# name, and that absence is what sends `import ja4plus` to `site-packages`.
PACKAGE_DIRECTORY = "ja4plus"

# The words a `pytest` summary line writes for a case that did not pass. `passing_summary`
# refuses a summary that holds one of them. The leading space keeps the reader off the word
# `xfailed`, which names a registered deviation and not a failure.
FAILURE_WORDS = (" failed", " error")


@dataclasses.dataclass(frozen=True)
class ReleaseCheck:
    """The result of one release check.

    Attributes:
        wheel: The built wheel.
        sdist: The built source distribution.
        twine_output: The output of `twine check` over both files.
        python: The interpreter of the clean environment.
        site_packages: The `purelib` directory of the clean environment.
        version_line: The line the installed console script wrote.
        package_file: The `ja4plus.__file__` the verification root resolves.
        root: The verification root, which holds the suite and no package source.
        collected_in_the_checkout: The conformance cases the checkout collects.
        collected: The conformance cases the clean environment collects.
        conformance_output: The output of the conformance run.
        conformance_summary: The summary line of that run, which names a passed count above
            zero and no failure.
    """

    wheel: pathlib.Path
    sdist: pathlib.Path
    twine_output: str
    python: pathlib.Path
    site_packages: pathlib.Path
    version_line: str
    package_file: str
    root: pathlib.Path
    collected_in_the_checkout: List[str]
    collected: List[str]
    conformance_output: str
    conformance_summary: str


def runner_requirement(text: str) -> str:
    """Return the `pytest` entry that the `dev` extra of `pyproject.toml` states.

    The clean environment installs the shipped dependency list, which holds no test
    runner. The check adds the entry of the `dev` extra, so one record states the version
    and the release check runs the runner every gate runs.

    Args:
        text: The whole text of `pyproject.toml`.

    Returns:
        The entry, as `pytest==8.4.2`.

    Raises:
        RuntimeError: The extra holds no `pytest` entry, or it holds more than one.
    """
    entries = [
        entry
        for entry in dependency_entries(text, DEV_EXTRA)
        if entry.split("=")[0].split("[")[0].split(";")[0].strip() == TEST_RUNNER
    ]
    if len(entries) != 1:
        raise RuntimeError(f"the {DEV_EXTRA!r} block states {len(entries)} {TEST_RUNNER} entries")
    return entries[0]


def verification_root(destination: pathlib.Path) -> pathlib.Path:
    """Return one directory that holds the test suite and no package source.

    Warning: run every conformance command in this directory and never in the checkout.
    `python -m` puts the working directory on `sys.path`, and `pytest` inserts the parent
    of the `tests` package there as well. In the checkout both paths hold `ja4plus/`, so
    the run measures the working copy rather than the installed wheel.

    Args:
        destination: The directory this function creates. It must not exist.

    Returns:
        The directory.

    Raises:
        RuntimeError: The checkout holds none of the copied names, or the copy holds a
            package directory.
    """
    destination.mkdir(parents=True)
    for name in COPIED_NAMES:
        source = REPOSITORY_ROOT / name
        if not source.exists():
            raise RuntimeError(f"the checkout holds no {name}")
        if source.is_dir():
            shutil.copytree(
                source, destination / name, ignore=shutil.ignore_patterns("__pycache__")
            )
        else:
            shutil.copy2(source, destination / name)
    if (destination / PACKAGE_DIRECTORY).exists():
        raise RuntimeError(f"{destination} holds {PACKAGE_DIRECTORY}, so an import reads it")
    return destination


def twine_check(python: pathlib.Path, artifacts: Sequence[pathlib.Path]) -> str:
    """Return the output of `twine check` over the built files.

    `FR-release-9` states this command. **`twine check` over no file reports no failure**,
    so the caller holds the file count against the `PASSED` count.

    Verified against: https://twine.readthedocs.io/en/stable/#twine-check
    (retrieved 2026-08-10).

    Args:
        python: The interpreter that holds `twine`.
        artifacts: The built files to read.

    Returns:
        The standard output and the standard error of the run, joined.

    Raises:
        RuntimeError: The list is empty, or `twine check` reported a non-zero status.
    """
    if not artifacts:
        raise RuntimeError("twine check reads no file, and a run over no file reports no failure")
    completed = subprocess.run(
        [str(python), "-m", "twine", "check", *[str(path) for path in artifacts]],
        capture_output=True,
        text=True,
        env=_run_environment(),
    )
    output = completed.stdout + completed.stderr
    if completed.returncode != 0:
        raise RuntimeError(f"twine check reported status {completed.returncode}: {output}")
    return output


def collected_cases(python: pathlib.Path, root: pathlib.Path, targets: Sequence[str]) -> List[str]:
    """Return the conformance cases that one interpreter collects.

    Args:
        python: The interpreter that runs `pytest`.
        root: The directory the run starts in.
        targets: The paths `pytest` reads, relative to the root.

    Returns:
        The case identifiers, sorted.

    Raises:
        RuntimeError: The collection reported a non-zero status.
    """
    completed = subprocess.run(
        [
            str(python),
            "-m",
            "pytest",
            *targets,
            "-m",
            CONFORMANCE_MARKER,
            "--collect-only",
            "-q",
        ],
        cwd=str(root),
        capture_output=True,
        text=True,
        env=_run_environment(),
    )
    output = completed.stdout + completed.stderr
    if completed.returncode != 0:
        raise RuntimeError(
            f"the collection in {root} reported status {completed.returncode}: {output}"
        )
    return sorted(line.strip() for line in completed.stdout.splitlines() if "::" in line)


def conformance_files(cases: Sequence[str]) -> List[str]:
    """Return the file of each collected case, without a repeat.

    The file list comes from the collection of the checkout, so a new conformance file
    reaches the clean environment without an edit here.

    Args:
        cases: The case identifiers, as `tests/test_spec_validation.py::test_one`.

    Returns:
        The file paths, sorted.
    """
    return sorted({case.split("::")[0] for case in cases})


def compare_collections(checkout: Sequence[str], clean: Sequence[str]) -> None:
    """Refuse a clean environment whose case list differs from the checkout.

    **An aggregate over an empty set passes.** A run of zero cases reports zero failures,
    so the floor stands here and not in the summary line of the run.

    Args:
        checkout: The cases the checkout collects.
        clean: The cases the clean environment collects.

    Raises:
        RuntimeError: The checkout collected no case, or the two lists differ.
    """
    if not checkout:
        raise RuntimeError(f"the checkout collected no case of the {CONFORMANCE_MARKER} marker")
    missing = sorted(set(checkout) - set(clean))
    extra = sorted(set(clean) - set(checkout))
    if missing or extra:
        raise RuntimeError(
            f"the clean environment collected {len(clean)} cases against {len(checkout)} in "
            f"the checkout. It missed {missing[:5]} and it added {extra[:5]}"
        )


def install_test_runner(environment: CleanEnvironment, requirement: str) -> None:
    """Add the test runner to one clean environment.

    The wheel install runs first and it reads the shipped dependency list alone, so the
    runner reaches the environment after the check measured that list.

    Args:
        environment: The environment the wheel install created.
        requirement: The entry the `dev` extra states, as `pytest==8.4.2`.

    Raises:
        subprocess.CalledProcessError: The install failed.
    """
    subprocess.run(
        [str(environment.python), "-m", "pip", "install", requirement],
        check=True,
        capture_output=True,
        text=True,
        env=_run_environment(),
    )


def passing_summary(output: str) -> str:
    """Return the summary line of a conformance run that passed cases.

    **A status of zero is not a passing run.** `pytest` reports a run whose every case
    skipped as a success. A vector tree the copy missed produces that state, and the
    release then ships against a suite that measured nothing. This reader holds the passed
    count above zero, and it refuses a summary that names a failure.

    Args:
        output: The output of the conformance run.

    Returns:
        The summary line.

    Raises:
        RuntimeError: The output holds no summary line, the run passed no case, or the
            summary names a failure.
    """
    lines = [line for line in output.strip().splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("the conformance run wrote no output")
    summary = lines[-1]
    for word in FAILURE_WORDS:
        if word in summary:
            raise RuntimeError(f"the conformance run reported {summary!r}")
    match = re.search(r"(\d+) passed", summary)
    if match is None:
        raise RuntimeError(f"the conformance run wrote no passed count: {summary!r}")
    if int(match.group(1)) == 0:
        raise RuntimeError(f"the conformance run passed no case: {summary!r}")
    return summary


def run_conformance(
    python: pathlib.Path, root: pathlib.Path, targets: Sequence[str], cache_home: pathlib.Path
) -> str:
    """Return the output of the conformance run against the installed package.

    Args:
        python: The interpreter of the clean environment.
        root: The verification root, which holds no package source.
        targets: The conformance files, relative to the root.
        cache_home: The directory that holds `HOME` and `XDG_CACHE_HOME` for the run.

    Returns:
        The standard output and the standard error of the run, joined.

    Raises:
        RuntimeError: The run reported a non-zero status.
    """
    variables = _run_environment()
    variables["HOME"] = str(cache_home)
    variables["XDG_CACHE_HOME"] = str(cache_home)
    completed = subprocess.run(
        [str(python), "-m", "pytest", *targets, "-m", CONFORMANCE_MARKER, "-q"],
        cwd=str(root),
        capture_output=True,
        text=True,
        env=variables,
    )
    output = completed.stdout + completed.stderr
    if completed.returncode != 0:
        raise RuntimeError(
            f"the conformance suite reported status {completed.returncode} against the "
            f"installed package: {output}"
        )
    return output


def verify(work: pathlib.Path, dist: pathlib.Path) -> ReleaseCheck:
    """Return the result of the whole release check.

    Args:
        work: The directory the check writes the environment and the copied suite into.
        dist: The directory `build` writes both artifacts into.

    Returns:
        The result of each step.

    Raises:
        RuntimeError: One step refused the release.
        AssertionError: `build` wrote no wheel, `pip` wrote no package, or a probe
            reported a non-zero status.
    """
    dist.mkdir(parents=True, exist_ok=True)
    artifacts: Dict[str, pathlib.Path] = build_artifacts(dist)
    twine_output = twine_check(
        pathlib.Path(sys.executable), [artifacts["sdist"], artifacts["wheel"]]
    )

    environment = create_clean_environment(work / "venv", artifacts["wheel"])
    install_test_runner(environment, runner_requirement(_pyproject_text()))

    root = verification_root(work / "root")
    cache_home = work / "cache"
    cache_home.mkdir(exist_ok=True)

    version_line = run_probe(environment.script, ["--version"], root, cache_home).decode("utf-8")
    version_line = version_line.strip()
    expected = f"ja4plus {declared_version()}"
    if version_line != expected:
        raise RuntimeError(f"the installed console script wrote {version_line!r} for {expected!r}")

    package_file = package_file_of(environment.python, root)
    if not package_file.startswith(str(environment.site_packages)):
        raise RuntimeError(
            f"the verification root imported {package_file}, which is not below "
            f"{environment.site_packages}"
        )

    in_the_checkout = collected_cases(pathlib.Path(sys.executable), REPOSITORY_ROOT, ["tests"])
    targets = conformance_files(in_the_checkout)
    collected = collected_cases(environment.python, root, targets)
    compare_collections(in_the_checkout, collected)
    conformance_output = run_conformance(environment.python, root, targets, cache_home)

    return ReleaseCheck(
        wheel=artifacts["wheel"],
        sdist=artifacts["sdist"],
        twine_output=twine_output,
        python=environment.python,
        site_packages=environment.site_packages,
        version_line=version_line,
        package_file=package_file,
        root=root,
        collected_in_the_checkout=in_the_checkout,
        collected=collected,
        conformance_output=conformance_output,
        conformance_summary=passing_summary(conformance_output),
    )


def _pyproject_text() -> str:
    """Return the whole text of `pyproject.toml`."""
    return (REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Report whether the built release passes every check the publish workflow needs.

    Args:
        argv: The command line, or None to read `sys.argv`.

    Returns:
        0 where every check passed. 1 otherwise, and every other state refuses the
        publish.
    """
    parser = argparse.ArgumentParser(
        prog=CHECK_COMMAND,
        description="Build the release and verify it in a clean environment.",
    )
    parser.add_argument(
        "--dist",
        default="dist",
        help="The directory the build writes the wheel and the source distribution into.",
    )
    parser.add_argument(
        "--work",
        default=None,
        help="The directory the check writes the clean environment into.",
    )
    options = parser.parse_args(argv)
    work = pathlib.Path(options.work) if options.work else pathlib.Path(tempfile.mkdtemp())

    try:
        check = verify(work, pathlib.Path(options.dist))
    except (AssertionError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"release check: REFUSED. {error}", file=sys.stderr)
        return 1

    print(f"release check: built {check.wheel.name} and {check.sdist.name}.")
    print(f"release check: twine check reported PASSED {check.twine_output.count('PASSED')} times.")
    print(f"release check: the clean environment holds {check.package_file}.")
    print(f"release check: the console script wrote {check.version_line!r}.")
    print(f"release check: the conformance suite ran {len(check.collected)} cases.")
    print(f"release check: {check.conformance_summary}")
    print("release check: PASSED. The release is ready to publish.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
