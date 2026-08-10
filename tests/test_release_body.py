"""Hold the release-body reader against `FR-release-14`.

`FR-release-14` asks the GitHub release body to hold the summary and the breaking-change
tables of the changelog section for that version, and to link `CHANGELOG.md` at the tag for
the rest. `tests/release_body.py` builds that body, and the publish workflow writes it to
the release before it publishes.

**A workflow step that never runs cannot fail.** No case here creates a release and no
case calls the provider. The cases split the claim in two, as
`tests/test_publish_workflow.py` does.

1. The step order of the workflow, read as text. `tests/test_publish_workflow.py` holds
   that reading.
2. The reader itself, run here against real changelog text and against damaged text.

**The provider refuses a body of more than 125000 characters**, and the version 1.0.0
section of `CHANGELOG.md` is 242778 characters. The user ruled on 2026-08-10 that the body
holds a named part and a link, and `tests/release_body.py` truncates nothing.
`test_the_whole_version_1_0_0_section_stands_above_the_provider_limit` records the reason
for the named part, and
`test_the_release_body_of_this_repository_stands_below_the_provider_limit` measures the
body a release of this repository carries.

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
    DESCRIPTION,
    REPOSITORY_URL,
    absolute_links,
    body_fault,
    changelog_link,
    changelog_section,
    link_targets,
    named_part,
    release_body,
    relative_link_targets,
)
from tests.test_installed_wheel import REPOSITORY_ROOT

CHANGELOG = REPOSITORY_ROOT / "CHANGELOG.md"
PACKAGE = REPOSITORY_ROOT / "ja4plus" / "__init__.py"

# A changelog of two sections, which every reader case below reads. The new section holds
# the shape of `CHANGELOG.md`: a summary, the breaking-change tables, and the entry list.
SAMPLE = """# Changelog

## [1.0.0] - unreleased

The first line of the new section.

### The breaking changes

#### The interface changes

| Change | Record |
|---|---|
| One interface change. | Round 1, #1 |

#### The fingerprints that move

| Change | Record |
|---|---|
| One fingerprint change. | Round 2, #2 |

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


def test_the_named_part_holds_the_summary_and_both_breaking_change_tables() -> None:
    """The named part runs from the version heading to the end of the second table.

    **A `####` heading of a table carries one more mark than a part heading**, so a reader
    that stopped at the first `###` heading below the tables keeps both of them.
    """
    part = named_part(changelog_section(SAMPLE, "1.0.0"))
    assert part.startswith("## [1.0.0]"), f"the reader returned {part[:40]!r}"
    assert "The first line of the new section." in part, "the named part drops the summary"
    assert "One interface change." in part, "the named part drops the interface table"
    assert "One fingerprint change." in part, "the named part drops the fingerprint table"


def test_the_named_part_holds_no_entry_of_the_entry_list() -> None:
    """**The entry list is the part that does not fit**, so the named part holds none of it.

    The user ruled on 2026-08-10 that a link carries the entry list.
    """
    part = named_part(changelog_section(SAMPLE, "1.0.0"))
    assert "### Added" not in part, "the named part reaches the entry list"
    assert "One entry." not in part, "the named part holds an entry of the entry list"


def test_the_named_part_reader_passes_over_the_heading_named_inside_a_paragraph() -> None:
    """A summary that names the heading in prose does not end the named part.

    **A substring match would end the part above the tables it exists to carry**, so the
    reader matches a whole heading line.
    """
    text = SAMPLE.replace(
        "The first line of the new section.",
        "The `### The breaking changes` heading below holds the two tables.",
    )
    part = named_part(changelog_section(text, "1.0.0"))
    assert "One interface change." in part, "the reader ended the part above the tables"
    assert "One fingerprint change." in part, "the reader ended the part above the tables"
    assert "One entry." not in part, "the named part reaches the entry list"


def test_the_named_part_reader_passes_over_the_heading_quoted_in_a_code_block() -> None:
    """A code block that quotes the heading does not end the named part.

    **A line anchor alone does not close this case**, because a line inside a code block
    opens a line of the file like any other. The reader tracks the code fence instead.
    """
    quoted = "```\n### The breaking changes\n```\n\nThe first line of the new section."
    text = SAMPLE.replace("The first line of the new section.", quoted)
    part = named_part(changelog_section(text, "1.0.0"))
    assert "One interface change." in part, "the reader ended the part above the tables"
    assert "One fingerprint change." in part, "the reader ended the part above the tables"
    assert "One entry." not in part, "the named part reaches the entry list"


def test_the_named_part_of_a_section_with_no_breaking_change_is_the_whole_section() -> None:
    """A section that names no breaking change reaches the body in whole.

    The reader sets nothing aside there, so no link is needed and no line is lost.
    `body_fault` still holds the whole part against the limit. The `## [0.6.0]` section of
    `CHANGELOG.md` is such a section, and version 0.6.0 is the released version.
    """
    section = "## [0.9.0] - 2026-01\n\nThe summary alone.\n\n### Added\n\n- One entry.\n"
    assert named_part(section) == section.strip(), "the reader set a part aside"


def test_the_link_names_the_changelog_at_the_tag_of_the_release() -> None:
    """The link reads `CHANGELOG.md` as the release shipped it.

    A link to the default branch moves under the reader after the next merge, so the link
    names the tag.
    """
    link = changelog_link("1.0.0")
    assert "/blob/v1.0.0/CHANGELOG.md" in link, f"the link reads {link!r}"
    assert REPOSITORY_URL in link, f"the link names no repository: {link!r}"


def test_the_reader_writes_an_absolute_url_for_a_link_to_a_path_of_the_repository() -> None:
    """A link to a path of the repository names the repository and the tag.

    The stored body carries no base, so a reader outside the release page resolves a
    relative path against nothing.
    """
    text = "[`docs/migration-0.6-to-1.0.md`](docs/migration-0.6-to-1.0.md) states the form.\n"
    written = absolute_links(text, "v1.0.0")
    assert f"({REPOSITORY_URL}/blob/v1.0.0/docs/migration-0.6-to-1.0.md)" in written, (
        f"the reader wrote {written!r}"
    )


def test_the_reader_writes_an_absolute_url_for_a_link_from_the_repository_root() -> None:
    """A target that opens with one slash reads from the repository root.

    GitHub states that a link which opens with a slash is relative to the repository root,
    so the reader joins the tag and never a second slash.
    """
    written = absolute_links("[the file](/docs/index.md) is there.\n", "v1.0.0")
    assert f"({REPOSITORY_URL}/blob/v1.0.0/docs/index.md)" in written, (
        f"the reader wrote {written!r}"
    )


def test_the_reader_keeps_an_anchor_of_the_same_body() -> None:
    """An anchor stays an anchor, because the body holds the heading it names.

    The body of version 1.0.0 names `#the-fingerprints-that-move`, and the release page
    holds that heading. An absolute URL there would carry a reader out of the page.
    """
    text = "Read [The fingerprints that move](#the-fingerprints-that-move) first.\n"
    assert absolute_links(text, "v1.0.0") == text, (
        f"the reader moved an anchor: {absolute_links(text, 'v1.0.0')!r}"
    )


def test_the_reader_keeps_a_link_that_is_already_absolute() -> None:
    """A target that names a scheme reaches the reader unchanged.

    `changelog_link` writes such a target, so a reader that joined the tag to it would
    write the repository address twice.
    """
    text = f"Read [`CHANGELOG.md`]({REPOSITORY_URL}/blob/v1.0.0/CHANGELOG.md) for the rest.\n"
    assert absolute_links(text, "v1.0.0") == text, (
        f"the reader moved an absolute link: {absolute_links(text, 'v1.0.0')!r}"
    )


def test_the_reader_rewrites_no_link_inside_a_code_block() -> None:
    """A code block quotes text, so the reader writes no URL into one.

    A rewrite inside a code block changes an example a reader copies. `breaking_heading_end`
    reads the same fence for the same reason.
    """
    text = "```markdown\n[the file](docs/index.md)\n```\n"
    assert absolute_links(text, "v1.0.0") == text, (
        f"the reader wrote into a code block: {absolute_links(text, 'v1.0.0')!r}"
    )


def test_the_relative_link_reader_names_the_target_of_a_text_that_holds_one() -> None:
    """The fault reader finds a relative target, so a clean report states a clean body.

    **An aggregate over an empty set passes.** This case is the floor under
    `test_the_release_body_of_this_repository_holds_no_relative_link`.
    """
    targets = relative_link_targets("[the file](docs/index.md) and [a heading](#one).\n")
    assert targets == ["docs/index.md"], f"the fault reader returned {targets}"


def test_the_release_body_of_this_repository_holds_no_relative_link() -> None:
    """**The body a release of this repository carries names every link absolutely.**

    The published body of version 1.0.0 held one relative target at line 9, and #566
    measured it. The stored body carries no base, so `gh release view` and the REST API
    each return a target that resolves against nothing.

    Warning: read the floor below before you read a clean report. A body that holds no
    link at all reports no relative target either.
    """
    body = release_body(CHANGELOG.read_text(encoding="utf-8"), '__version__ = "1.0.0"\n')
    links = link_targets(body)
    assert len(links) >= 2, f"the release body holds {len(links)} links, so this case reads none"
    targets = relative_link_targets(body)
    assert targets == [], f"the release body holds the relative targets {targets}"


def test_the_record_keeps_the_relative_link_that_the_release_body_rewrites() -> None:
    """`CHANGELOG.md` keeps its relative links, because a reader of the repository follows
    one.

    The release page is a different page. The reader rewrites the copy it builds, and it
    edits no line of the record.
    """
    record = CHANGELOG.read_text(encoding="utf-8")
    assert "](docs/migration-0.6-to-1.0.md)" in record, (
        "`CHANGELOG.md` lost the relative link that #566 keeps there"
    )


def test_the_release_body_reader_returns_the_named_part_and_the_link() -> None:
    """The reader takes the version from the package and the text from the changelog.

    `ja4plus/__init__.py` is the one version declaration, so no argument states a version.
    """
    body = release_body(SAMPLE, '__version__ = "1.0.0"\n')
    assert body.startswith("## [1.0.0]"), f"the reader returned {body[:40]!r}"
    assert "One interface change." in body, "the body drops the interface table"
    assert "One entry." not in body, "the body holds an entry of the entry list"
    assert "/blob/v1.0.0/CHANGELOG.md" in body, "the body carries no link to the changelog"


def test_the_release_body_reader_refuses_a_package_that_declares_no_version() -> None:
    """A package text with no `__version__` fails the reader."""
    with pytest.raises(RuntimeError, match="declares no"):
        release_body(SAMPLE, "# no version here\n")


def test_the_release_body_reader_refuses_a_named_part_above_the_limit() -> None:
    """The two floors run in one call, so the caller reads one failure.

    **The reader truncates nothing.** A named part that grows past the limit fails the
    reader rather than reaches the release.
    """
    long_text = SAMPLE.replace("The first line of the new section.", "x" * (BODY_LIMIT + 1))
    with pytest.raises(RuntimeError, match=str(BODY_LIMIT)):
        release_body(long_text, '__version__ = "1.0.0"\n')


def test_the_reader_returns_the_version_1_0_0_section_of_this_repository() -> None:
    """The reader reads the real changelog and it returns the section a release would hold.

    A case over sample text alone proves the reader and not the file it reads.
    """
    section = changelog_section(CHANGELOG.read_text(encoding="utf-8"), "1.0.0")
    assert section.startswith("## [1.0.0]"), f"the reader returned {section[:40]!r}"
    assert len(section) > 1000, f"the version 1.0.0 section holds {len(section)} characters"


def test_the_whole_version_1_0_0_section_stands_above_the_provider_limit() -> None:
    """**The whole section is longer than the provider accepts, and this is the reason for
    the named part.**

    A read of 2026-08-10 reports 242778 characters against a limit of 125000. This case
    records why the body holds a named part, and it fails on the day that reason ends.

    Warning: this case fails where the section falls below the limit. Read the
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


def test_the_release_body_of_this_repository_stands_below_the_provider_limit() -> None:
    """**The body a release of this repository carries fits the provider.**

    `FR-release-14` holds where the reader returns a body the provider accepts. A case over
    sample text alone proves the reader and not the file it reads, so this case reads
    `CHANGELOG.md` as it stands.

    **The package declares version 0.6.0 today, and this case states version 1.0.0.** The
    release of version 1.0.0 is the release this measurement covers, and
    `test_the_release_body_reader_returns_the_named_part_and_the_link` holds the reader to
    the one version declaration.
    """
    body = release_body(CHANGELOG.read_text(encoding="utf-8"), '__version__ = "1.0.0"\n')
    assert body_fault(body) is None, (
        f"the release body holds {len(body)} characters against a limit of {BODY_LIMIT}"
    )
    assert "### The breaking changes" in body, "the release body holds no breaking change"
    assert "/CHANGELOG.md" in body, "the release body carries no link to the changelog"


def test_the_module_runs_from_the_command_the_workflow_states() -> None:
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


def test_the_module_runs_where_the_interpreter_strips_every_docstring() -> None:
    """The module states its own description, so a stripped docstring starts it too.

    **`python -OO` sets `__doc__` to None on every module.** A parser that read the module
    docstring for its description then raised `AttributeError` before it read one argument,
    and the publish step would report that name and not the release body.
    """
    completed = subprocess.run(
        [sys.executable, "-OO", "-m", "tests.release_body", "--help"],
        cwd=str(REPOSITORY_ROOT),
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, f"the module refused --help under -OO: {completed.stderr}"
    assert DESCRIPTION in completed.stdout, (
        f"the module named no description under -OO: {completed.stdout}"
    )


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
