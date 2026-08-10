"""Hold the release-body reader against `FR-release-14`.

`FR-release-14` asks the GitHub release body to hold the changelog section of that
version. `tests/release_body.py` builds that body, and the publish workflow writes it to
the release before it publishes.

**A workflow step that never runs cannot fail.** No case here creates a release and no
case calls the provider. The cases split the claim in two, as
`tests/test_publish_workflow.py` does.

1. The step order of the workflow, read as text. `tests/test_publish_workflow.py` holds
   that reading.
2. The reader itself, run here against real changelog text and against damaged text.

**The provider refuses a body of more than 125000 characters**, and the version 1.0.0
section of `CHANGELOG.md` is longer than that. `tests/release_body.py` therefore reports a
fault rather than writes a body the provider rejects, and
`test_the_reader_refuses_the_version_1_0_0_section_of_this_repository` measures the state
of this repository today.

Verified against https://docs.github.com/en/rest/releases/releases (retrieved 2026-08-10),
which states the `body` field of a release, and against the reports of the 422 answer the
field returns: https://github.com/cli/cli/issues/7705 (retrieved 2026-08-10).
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

from tests.release_body import (
    BODY_LIMIT,
    body_fault,
    changelog_section,
    release_body,
)
from tests.test_installed_wheel import REPOSITORY_ROOT

CHANGELOG = REPOSITORY_ROOT / "CHANGELOG.md"
PACKAGE = REPOSITORY_ROOT / "ja4plus" / "__init__.py"

# A changelog of two sections, which every reader case below reads.
SAMPLE = """# Changelog

## [1.0.0] - unreleased

The first line of the new section.

### Added

- One entry.

## [0.6.0] - 2026-05

The line of the old section.
"""


def test_the_reader_returns_the_section_of_the_named_version() -> None:
    """The reader returns one section, from its heading to the next version heading."""
    section = changelog_section(SAMPLE, "1.0.0")
    assert section.startswith("## [1.0.0]"), f"the reader returned {section[:40]!r}"
    assert "One entry." in section, "the reader dropped a line of the section"
    assert "the old section" not in section, "the reader ran into the next section"


def test_the_reader_returns_the_last_section_of_the_file() -> None:
    """The reader reads the section that no later heading follows.

    A reader that needs a following heading returns nothing for the oldest version.
    """
    section = changelog_section(SAMPLE, "0.6.0")
    assert section.strip().endswith("The line of the old section."), (
        f"the reader returned {section!r}"
    )


def test_the_reader_refuses_a_version_the_changelog_does_not_hold() -> None:
    """`FR-release-14`. A version with no section fails the reader.

    The release then carries no body rather than an empty one, and the workflow stops in
    front of the publish step.
    """
    with pytest.raises(RuntimeError, match=r"holds no `## \[9\.9\.9\]` section"):
        changelog_section(SAMPLE, "9.9.9")


def test_the_reader_refuses_a_section_that_holds_no_line() -> None:
    """A heading with nothing below it fails the reader.

    **A section of one heading passes a search for that heading.** The floor stands here,
    so an empty section reaches no release body.
    """
    with pytest.raises(RuntimeError, match="holds no line"):
        changelog_section("# Changelog\n\n## [1.0.0]\n\n## [0.6.0] - 2026-05\n\nOld.\n", "1.0.0")


def test_the_reader_matches_the_whole_version_and_not_a_prefix() -> None:
    """A version that is the prefix of another version reads its own section.

    `1.0` is the prefix of `1.0.0`, and a reader that matched a prefix would return the
    wrong section.
    """
    text = SAMPLE.replace("## [0.6.0] - 2026-05", "## [1.0.0-rc1] - 2026-04")
    with pytest.raises(RuntimeError, match=r"holds no `## \[1\.0\]` section"):
        changelog_section(text, "1.0")


def test_the_body_reader_accepts_a_section_below_the_limit() -> None:
    """A body of fewer characters than the limit carries no fault."""
    assert body_fault("## [1.0.0]\n\nOne line.\n") is None


def test_the_body_reader_refuses_a_body_above_the_provider_limit() -> None:
    """`FR-release-14`. A body of more characters than the limit carries a fault.

    The provider answers `422` and names the limit, so the workflow reads the length here
    and it stops in front of the publish step.
    """
    fault = body_fault("x" * (BODY_LIMIT + 1))
    assert fault is not None, f"a body of {BODY_LIMIT + 1} characters reported no fault"
    assert str(BODY_LIMIT) in fault, f"the fault names no limit: {fault}"
    assert str(BODY_LIMIT + 1) in fault, f"the fault names no measured length: {fault}"


def test_the_body_reader_accepts_a_body_of_exactly_the_limit() -> None:
    """The limit is the longest body the provider accepts, so the reader accepts it.

    An off-by-one here refuses a release the provider would take.
    """
    assert body_fault("x" * BODY_LIMIT) is None


def test_the_body_reader_names_the_limit_the_provider_states() -> None:
    """The reader holds the character count the provider documents."""
    assert BODY_LIMIT == 125000


def test_the_body_reader_refuses_a_body_that_holds_no_word() -> None:
    """A body of whitespace carries a fault.

    **A length check passes on a blank body.** The floor stands beside the limit.
    """
    fault = body_fault("   \n\n  \n")
    assert fault is not None, "a blank body reported no fault"
    assert "no text" in fault, f"the fault of a blank body reads {fault!r}"


def test_the_release_body_reader_returns_the_section_of_the_declared_version() -> None:
    """The reader takes the version from the package and the text from the changelog.

    `ja4plus/__init__.py` is the one version declaration, so no argument states a version.
    """
    body = release_body(SAMPLE, '__version__ = "1.0.0"\n')
    assert body.startswith("## [1.0.0]"), f"the reader returned {body[:40]!r}"


def test_the_release_body_reader_refuses_a_package_that_declares_no_version() -> None:
    """A package text with no `__version__` fails the reader."""
    with pytest.raises(RuntimeError, match="declares no"):
        release_body(SAMPLE, "# no version here\n")


def test_the_release_body_reader_refuses_a_section_above_the_limit() -> None:
    """The two floors run in one call, so the caller reads one failure.

    A section the provider would refuse fails the reader rather than reaches the release.
    """
    long_text = SAMPLE.replace("- One entry.", "- " + "x" * (BODY_LIMIT + 1))
    with pytest.raises(RuntimeError, match=str(BODY_LIMIT)):
        release_body(long_text, '__version__ = "1.0.0"\n')


def test_the_reader_returns_the_version_1_0_0_section_of_this_repository() -> None:
    """The reader reads the real changelog and it returns the section a release would hold.

    A case over sample text alone proves the reader and not the file it reads.
    """
    section = changelog_section(CHANGELOG.read_text(encoding="utf-8"), "1.0.0")
    assert section.startswith("## [1.0.0]"), f"the reader returned {section[:40]!r}"
    assert len(section) > 1000, f"the version 1.0.0 section holds {len(section)} characters"


def test_the_reader_refuses_the_version_1_0_0_section_of_this_repository() -> None:
    """**The version 1.0.0 section is longer than the provider accepts, and this is a
    measurement of today.**

    A read of 2026-08-10 reports 242778 characters against a limit of 125000. The reader
    therefore reports a fault, the publish workflow stops in front of the publish step, and
    no release carries a body the provider refuses.

    Warning: this case fails on the day the section falls below the limit. Read the
    `### The release body of version 1.0.0` section of
    `docs/specs/features/09-release.md` before you change it.
    """
    section = changelog_section(CHANGELOG.read_text(encoding="utf-8"), "1.0.0")
    fault = body_fault(section)
    assert fault is not None, (
        f"the version 1.0.0 section holds {len(section)} characters, which is below the "
        f"limit of {BODY_LIMIT}, so this repository no longer measures the state this case "
        "records"
    )
    assert str(len(section)) in fault, f"the fault names no measured length: {fault}"


def test_the_module_runs_from_the_command_the_workflow_states(tmp_path: pathlib.Path) -> None:
    """The command the workflow states starts the module the cases above call.

    A workflow that named another entry point would run code no case here measures.
    """
    completed = subprocess.run(
        [sys.executable, "-m", "tests.release_body", "--help"],
        cwd=str(REPOSITORY_ROOT),
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, f"the module refused --help: {completed.stderr}"


def test_the_module_writes_the_body_to_the_named_file(tmp_path: pathlib.Path) -> None:
    """The module writes the section to the output path the caller names."""
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(SAMPLE, encoding="utf-8")
    package = tmp_path / "__init__.py"
    package.write_text('__version__ = "1.0.0"\n', encoding="utf-8")
    output = tmp_path / "body.md"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "tests.release_body",
            "--changelog",
            str(changelog),
            "--package",
            str(package),
            "--output",
            str(output),
        ],
        cwd=str(REPOSITORY_ROOT),
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, (
        f"the module exited {completed.returncode}: {completed.stderr}"
    )
    assert output.read_text(encoding="utf-8").startswith("## [1.0.0]"), (
        f"the module wrote {output.read_text(encoding='utf-8')[:40]!r}"
    )


def test_the_module_reports_a_fault_and_writes_no_file(tmp_path: pathlib.Path) -> None:
    """A changelog with no section for the version exits non-zero and writes nothing.

    **A step that writes a file and then reports a failure leaves a body a later step
    reads.** The module therefore writes the file after the two floors pass.
    """
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(SAMPLE, encoding="utf-8")
    package = tmp_path / "__init__.py"
    package.write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    output = tmp_path / "body.md"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "tests.release_body",
            "--changelog",
            str(changelog),
            "--package",
            str(package),
            "--output",
            str(output),
        ],
        cwd=str(REPOSITORY_ROOT),
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0, "the module accepted a version the changelog omits"
    assert "9.9.9" in completed.stderr, f"the module named no version: {completed.stderr}"
    assert not output.exists(), f"the module wrote {output} although it reported a fault"


def test_the_release_feature_records_the_release_body() -> None:
    """`docs/specs/features/09-release.md` names the reader the publish workflow runs."""
    page = (REPOSITORY_ROOT / "docs" / "specs" / "features" / "09-release.md").read_text(
        encoding="utf-8"
    )
    assert "tests/release_body.py" in page, "the release feature document names no body reader"


def test_the_release_skill_builds_the_release_body_with_the_reader() -> None:
    """`.claude/skills/release/SKILL.md` builds the body with the module and not by hand.

    A second reader of the same file can disagree with the first one. The manual procedure
    and the workflow therefore run one command.
    """
    skill = (REPOSITORY_ROOT / ".claude" / "skills" / "release" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    assert "python -m tests.release_body" in skill, (
        "the release skill builds the release body from a reader of its own"
    )
