"""Hold the publish workflow and its release check against `FR-release-4` to `FR-release-9`.

`.github/workflows/publish.yml` uploads to PyPI on a published release, and a publish to
PyPI cannot be undone. Every check therefore runs before the publish step and never after
it.

**A workflow step that never runs cannot fail.** No case here starts the publish workflow,
because a run of it would publish. The cases split the claim in two instead.

1. The steps of the workflow, read as text. The publish step is the last step, the check
   step runs before it, and no step continues after a failure.
2. The check itself, run here. `tests/release_verification.py` holds every command the
   check step runs, and the cases below call that module rather than read it.

**The conformance suite lives under `tests/`, and #455 removed `tests/` from the wheel.**
`FR-release-7` therefore means one thing alone: install the wheel into a clean
environment, then run the suite of the checkout against that installed package. **A run
that starts in the repository root proves nothing about the wheel**, because `python -m`
puts the working directory on `sys.path` and `pytest` inserts the parent of the `tests`
package there as well. Both paths name the checkout, so `import ja4plus` reads the source
tree. `test_the_repository_root_resolves_the_source_tree` measures that state, so the
positive case beside it cannot pass on a mechanism that measures nothing.

Every case that builds an artifact carries the `installed_wheel` marker, and
`tests/conftest.py` deselects that marker from a run that does not name it. The
`installed-wheel` job of `.github/workflows/test.yml` runs the marker over `tests/`, so it
runs this file too.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
from typing import Dict, List

import pytest

from tests.release_verification import (
    CHECK_COMMAND,
    CONFORMANCE_MARKER,
    PACKAGE_DIRECTORY,
    ReleaseCheck,
    compare_collections,
    runner_requirement,
    twine_check,
    verification_root,
    verify,
)
from tests.test_installed_wheel import REPOSITORY_ROOT, declared_version, package_file_of

WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "publish.yml"
PYPROJECT = REPOSITORY_ROOT / "pyproject.toml"

# The step of the publish job that uploads to PyPI. It is the last step, so every check
# stands in front of it.
PUBLISH_ACTION = "pypa/gh-action-pypi-publish@"

# The event the workflow accepts, and the permission trusted publishing needs.
#
# Verified against: https://docs.pypi.org/trusted-publishers/ (retrieved 2026-08-10).
RELEASE_TRIGGER = ("on:", "  release:", "    types: [published]")
TRUSTED_PUBLISHER_PERMISSION = "id-token: write"

# The two keys that let a job continue past a failed step. `FR-release-8` publishes only
# where every check passed, so no step of this workflow carries either one.
CONTINUATION_KEYS = ("continue-on-error", "if: always()")

# A step of the publish job starts at six spaces, a dash and a space. The reader matches
# the text, because no gate of this repository installs a YAML parser.
STEP_LINE = re.compile(r"^      - (\S.*)$")

# The action reference of one step, without its version comment. Each one pins a commit,
# so a moved tag reaches no run of this workflow.
ACTION_REFERENCE = re.compile(r"uses:\s+(\S+)")
PINNED_COMMIT = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def _steps() -> List[str]:
    """Return the steps of the publish job, in file order.

    Returns:
        One string for each step, holding every line of that step.
    """
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    steps: List[List[str]] = []
    for line in lines:
        if STEP_LINE.match(line):
            steps.append([line])
        elif steps and line.startswith("        "):
            steps[-1].append(line)
        elif steps and line.strip() == "":
            steps[-1].append(line)
    return ["\n".join(step) for step in steps]


def test_the_publish_workflow_runs_on_a_published_release() -> None:
    """The workflow accepts the published-release event and no second event.

    A second trigger would publish outside a release, and a publish to PyPI cannot be
    undone.
    """
    text = WORKFLOW.read_text(encoding="utf-8")
    for line in RELEASE_TRIGGER:
        assert f"\n{line}\n" in text, f"{WORKFLOW.name} holds no line {line!r}"
    assert "workflow_dispatch" not in text, f"{WORKFLOW.name} accepts a second trigger"
    assert "\n  push:\n" not in text, f"{WORKFLOW.name} accepts a push event"


def test_the_publish_workflow_declares_the_trusted_publisher_permission() -> None:
    """The workflow keeps the permission that trusted publishing needs.

    Trusted publishing stores no token, so a removed permission moves this project back to
    a stored credential.
    """
    text = WORKFLOW.read_text(encoding="utf-8")
    assert TRUSTED_PUBLISHER_PERMISSION in text, (
        f"{WORKFLOW.name} declares no {TRUSTED_PUBLISHER_PERMISSION}"
    )


def test_the_publish_workflow_runs_the_release_check_before_the_publish() -> None:
    """`FR-release-8`. The check step stands in front of the publish step.

    GitHub stops a job at the first step that fails, so a check in front of the publish
    step refuses the upload. A check behind it would read an artifact PyPI already holds.
    """
    steps = _steps()
    assert len(steps) >= 2, f"{WORKFLOW.name} holds {len(steps)} steps"
    checks = [index for index, step in enumerate(steps) if CHECK_COMMAND in step]
    publishes = [index for index, step in enumerate(steps) if PUBLISH_ACTION in step]
    assert len(checks) == 1, f"{WORKFLOW.name} runs {CHECK_COMMAND!r} in {len(checks)} steps"
    assert len(publishes) == 1, f"{WORKFLOW.name} holds {len(publishes)} publish steps"
    assert checks[0] < publishes[0], (
        f"{WORKFLOW.name} runs the check at step {checks[0]} and publishes at step "
        f"{publishes[0]}, so it publishes before it checks"
    )
    assert publishes[0] == len(steps) - 1, (
        f"the publish step is step {publishes[0]} of {len(steps)}, and it must be the last"
    )


def test_the_publish_workflow_holds_no_step_that_runs_after_a_failure() -> None:
    """`FR-release-8`. No step of the workflow continues past a failed step.

    `continue-on-error` and `if: always()` each let a later step run where an earlier one
    failed. Either one would carry a failed check to the publish step.
    """
    for key in CONTINUATION_KEYS:
        offenders = [step.splitlines()[0].strip() for step in _steps() if key in step]
        assert offenders == [], f"these steps of {WORKFLOW.name} carry {key}: {offenders}"


def test_every_action_of_the_publish_workflow_pins_a_commit() -> None:
    """Each action of the workflow names a 40-character commit and not a tag.

    A tag moves. An action that publishes to PyPI reads the credential of this project, so
    the reference names the commit a reader reviewed.
    """
    references = ACTION_REFERENCE.findall(WORKFLOW.read_text(encoding="utf-8"))
    assert references, f"{WORKFLOW.name} names no action"
    unpinned = sorted(name for name in references if not PINNED_COMMIT.match(name))
    assert unpinned == [], f"these actions of {WORKFLOW.name} pin no commit: {unpinned}"


def test_the_publish_workflow_states_no_version_of_the_check_it_runs() -> None:
    """The workflow installs the development extra, which states every tool version.

    Two places that state a version can disagree, and the job then runs a tool that no pin
    chose. `tests/test_lint_gate_pin.py` holds the same rule for each pinned tool.
    """
    text = WORKFLOW.read_text(encoding="utf-8")
    assert 'pip install -e ".[dev]"' in text, (
        f"{WORKFLOW.name} installs no development extra, so it resolves its own versions"
    )


def test_the_release_check_names_the_test_runner_of_the_development_extra() -> None:
    """The check installs the `pytest` entry that `pyproject.toml` states.

    The clean environment holds the shipped dependency list and no test runner, so the
    check adds one. It adds the entry of the `dev` extra, so one record states the version.
    """
    requirement = runner_requirement(PYPROJECT.read_text(encoding="utf-8"))
    assert requirement.startswith("pytest=="), (
        f"the dev extra states the test runner as {requirement!r}, and the check installs "
        "an exact pin"
    )


def test_the_release_check_refuses_a_conformance_run_that_collected_nothing() -> None:
    """An empty collection fails the check rather than passes it.

    **An aggregate over an empty set passes.** A run of zero cases reports zero failures,
    so the floor stands here rather than in the summary line.
    """
    with pytest.raises(RuntimeError, match="collected no case"):
        compare_collections([], [])


def test_the_release_check_refuses_a_clean_environment_that_dropped_a_case() -> None:
    """A clean environment that collects fewer cases than the checkout fails the check."""
    checkout = [
        "tests/test_spec_validation.py::test_one",
        "tests/test_spec_validation.py::test_two",
    ]
    with pytest.raises(RuntimeError, match="test_two"):
        compare_collections(checkout, checkout[:1])


@pytest.fixture(scope="session")
def release_check(tmp_path_factory: pytest.TempPathFactory) -> ReleaseCheck:
    """Run the whole release check once for this file.

    The check builds both artifacts, reads them with `twine`, installs the wheel into a
    clean environment and runs the conformance suite against that installation. Each case
    below reads one result of that run.
    """
    work = tmp_path_factory.mktemp("release-check")
    return verify(work, work / "dist")


@pytest.mark.installed_wheel
def test_the_release_check_builds_a_source_distribution_and_a_wheel(
    release_check: ReleaseCheck,
) -> None:
    """`FR-release-4`. The check writes one source distribution and one wheel."""
    assert release_check.wheel.suffix == ".whl", f"the check built {release_check.wheel}"
    assert release_check.sdist.name.endswith(".tar.gz"), f"the check built {release_check.sdist}"
    assert release_check.wheel.stat().st_size > 0, "the check built an empty wheel"
    assert release_check.sdist.stat().st_size > 0, "the check built an empty source distribution"


@pytest.mark.installed_wheel
def test_the_release_check_reports_passed_for_both_built_files(
    release_check: ReleaseCheck,
) -> None:
    """`FR-release-9`. `twine check` reports `PASSED` for the wheel and for the source
    distribution.

    A count of two stands here, because `twine check` over no file reports no failure.
    """
    passed = release_check.twine_output.count("PASSED")
    assert passed == 2, (
        f"twine check reported PASSED {passed} times over two files: {release_check.twine_output}"
    )


@pytest.mark.installed_wheel
def test_the_release_check_refuses_a_built_file_that_twine_rejects(
    release_check: ReleaseCheck, tmp_path: pathlib.Path
) -> None:
    """The check fails on a damaged wheel, so the case above cannot pass on a broken file.

    The damaged file carries the name of a wheel and holds no archive. `twine check` reads
    it, reports a non-zero status, and the check raises.
    """
    damaged = tmp_path / release_check.wheel.name
    damaged.write_text("this file is no wheel", encoding="utf-8")
    with pytest.raises(RuntimeError, match="twine check"):
        twine_check(pathlib.Path(sys.executable), [damaged])


@pytest.mark.installed_wheel
def test_the_clean_environment_of_the_release_check_runs_the_console_script(
    release_check: ReleaseCheck,
) -> None:
    """`FR-release-6`. The console script of the installation writes the declared version."""
    assert release_check.version_line == f"ja4plus {declared_version()}", (
        f"the installed console script wrote {release_check.version_line!r}"
    )


@pytest.mark.installed_wheel
def test_the_conformance_run_resolves_the_installed_package(
    release_check: ReleaseCheck,
) -> None:
    """`FR-release-5` and `FR-release-7`. The conformance run imports the installed copy.

    The check reads `ja4plus.__file__` from the directory the suite runs in. A value below
    the `site-packages` directory of the clean environment names the wheel under test.
    """
    assert release_check.package_file.startswith(str(release_check.site_packages)), (
        f"the conformance run imported {release_check.package_file}, which is not below "
        f"{release_check.site_packages}"
    )


@pytest.mark.installed_wheel
def test_the_repository_root_resolves_the_source_tree(release_check: ReleaseCheck) -> None:
    """The same probe reads the checkout when it starts in the repository root.

    Warning: never remove this case. It proves the verification root is load-bearing. The
    case above passes on any path below `site-packages`, and a check that cannot fail
    measures nothing.
    """
    from_the_checkout = package_file_of(release_check.python, REPOSITORY_ROOT)
    assert from_the_checkout.startswith(str(REPOSITORY_ROOT)), (
        f"the clean environment imported {from_the_checkout} from the repository root, so "
        "this case cannot prove the verification root discriminates"
    )
    assert not from_the_checkout.startswith(str(release_check.site_packages)), (
        f"{from_the_checkout} lies below {release_check.site_packages}"
    )


@pytest.mark.installed_wheel
def test_the_verification_root_holds_no_package_source(tmp_path: pathlib.Path) -> None:
    """The directory the suite runs in holds the test suite and no package source.

    `pytest` inserts the parent of the `tests` package into `sys.path`. That parent is the
    repository root in the checkout, and it holds `ja4plus/`.
    """
    root = verification_root(tmp_path / "root")
    assert (root / "tests").is_dir(), f"{root} holds no test suite"
    assert not (root / PACKAGE_DIRECTORY).exists(), (
        f"{root} holds {PACKAGE_DIRECTORY}, so an import there reads the source tree"
    )


@pytest.mark.installed_wheel
def test_the_conformance_run_reads_every_case_the_checkout_collects(
    release_check: ReleaseCheck,
) -> None:
    """`FR-release-7`. The clean environment collects the case list of the checkout.

    A file the run dropped would leave a green result over a smaller suite, and nothing in
    the summary line would report it.
    """
    assert release_check.collected, "the conformance run collected no case"
    assert release_check.collected == release_check.collected_in_the_checkout


@pytest.mark.installed_wheel
def test_the_conformance_run_reports_no_failure(release_check: ReleaseCheck) -> None:
    """`FR-release-7`. The conformance suite passes against the installed package.

    The summary line states the counts. The passed count stands above zero, because a run
    that collected nothing reports no failure either.
    """
    summary = release_check.conformance_output.strip().splitlines()[-1]
    assert " failed" not in summary and " error" not in summary, (
        f"the conformance run against the installed package reported {summary!r}"
    )
    match = re.search(r"(\d+) passed", summary)
    assert match is not None, f"the conformance run wrote no passed count: {summary!r}"
    assert int(match.group(1)) > 0, f"the conformance run passed no case: {summary!r}"


@pytest.mark.installed_wheel
def test_the_conformance_run_selects_the_marker_of_the_conformance_suite(
    release_check: ReleaseCheck,
) -> None:
    """The check runs the marker that `CLAUDE.md` names for the conformance suite."""
    assert CONFORMANCE_MARKER == "spec_validation"
    assert release_check.collected, "the conformance run collected no case"


def test_the_installed_wheel_job_runs_the_marker_over_the_whole_suite() -> None:
    """The job that runs the marker reads every file that carries it.

    A command that names one file runs no case this file adds, and a case nobody runs is a
    check nobody has.
    """
    text = (REPOSITORY_ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
    assert "pytest tests/ -m installed_wheel" in text, (
        "no job of .github/workflows/test.yml runs the installed_wheel marker over tests/"
    )


def test_the_check_module_runs_from_the_command_the_workflow_states() -> None:
    """The command the workflow states starts the module the cases above run.

    A workflow that names another entry point would run code no case here measures.
    """
    completed = subprocess.run(
        [sys.executable, "-m", "tests.release_verification", "--help"],
        cwd=str(REPOSITORY_ROOT),
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, f"the check module refused --help: {completed.stderr}"
    assert CHECK_COMMAND.startswith("python -m tests.release_verification"), (
        f"the workflow command is {CHECK_COMMAND!r}"
    )


def test_the_release_feature_records_the_publish_check() -> None:
    """`docs/specs/features/09-release.md` names the check the publish workflow runs."""
    page = (REPOSITORY_ROOT / "docs" / "specs" / "features" / "09-release.md").read_text(
        encoding="utf-8"
    )
    assert "tests/release_verification.py" in page, (
        "the release feature document names no publish check"
    )


def test_the_release_skill_verifies_the_wheel_outside_the_checkout() -> None:
    """`.claude/skills/release/SKILL.md` runs the conformance suite outside the checkout.

    The manual procedure holds the same trap as the workflow. A `pytest` run that starts
    in the repository root reads the source tree, so the released package gets no check.
    """
    skill = (REPOSITORY_ROOT / ".claude" / "skills" / "release" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    assert "python -m tests.release_verification" in skill, (
        "the release skill states a verification that does not name the release check"
    )


def _named_paths() -> Dict[str, pathlib.Path]:
    """Return the files this issue adds, keyed by the name a reader cites."""
    return {
        "check": REPOSITORY_ROOT / "tests" / "release_verification.py",
        "cases": REPOSITORY_ROOT / "tests" / "test_publish_workflow.py",
        "workflow": WORKFLOW,
    }


def test_every_file_of_the_publish_check_is_present() -> None:
    """The three files of this check are present, so no case above reads a missing path."""
    missing = sorted(name for name, path in _named_paths().items() if not path.is_file())
    assert missing == [], f"these files of the publish check are missing: {missing}"
