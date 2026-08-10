"""Check the release skill against the repository it tells a maintainer to release.

`.claude/skills/release/SKILL.md` is the procedure a maintainer follows to publish to
PyPI. **A skill file carried no case until #512, and that is why a wrong step survived two
rounds.** Step 1 named `pyproject.toml` as the one version declaration and said that
`ja4plus/__init__.py` read the value with `importlib.metadata`. #67 reversed both, and step
2 read the version with `tomllib` out of the file that declares none. A maintainer who
followed step 1 edited a file that declares no version, so the release shipped the old
number.

**Every case here reads the repository, and no case reads a copy of the skill text.** The
file the skill names as the version source is the file that declares `__version__`, the
line it names is the line that holds the assignment, and the command it names runs. A case
that compared the skill against a second copy of the same words would pass on the day both
copies go wrong together.

Four groups of cases hold the file.

1. The source cases read the file and the line that step 1 names, and they hold both
   against `tests/version_gate.py` and against `git ls-files`.
2. The command case runs the version check of step 2 in a subprocess, and it requires the
   version that `ja4plus/__init__.py` declares in the output.
3. The rule cases require the two facts a bump needs: the plain string assignment, and the
   matching `## [<version>]` section of `CHANGELOG.md`.
4. The discrimination cases prove that the readers fail on the superseded text of #67.

These cases read prose and run one subprocess. They import nothing from `ja4plus` and they
produce no fingerprint.
"""

from __future__ import annotations

import re
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Optional, Tuple

import pytest

from tests.version_gate import PACKAGE_DECLARATION, declaration_files, package_version

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

SKILL = REPOSITORY_ROOT / ".claude" / "skills" / "release" / "SKILL.md"

# The sentence of step 1 that names the one version declaration and the line that holds it.
# The reader takes both out of the prose, so a step that names another file or another line
# reaches the repository check below rather than a second copy of the same words.
VERSION_SOURCE = re.compile(r"The\s+version\s+lives\s+in\s+`([^`]+)`\s+at\s+line\s+(\d+)")

# The rule that keeps the declaration readable from the syntax tree. #67 measured that a
# computed value makes a build import the package and every dependency it loads.
#
# **Each pattern of this file joins its words with `\s+`.** The file wraps at 90 columns, so
# a pattern that held a literal space matches no sentence that wraps between two of its
# words, and a later rewrap would break the case for no reason a reader could see.
SYNTAX_TREE_RULE = re.compile(
    r"`setuptools`\s+reads\s+the\s+value\s+from\s+the\s+syntax\s+tree", re.IGNORECASE
)

# The rule that puts the changelog section in the bump. `tests/release_body.py` reads that
# section, so a bump without one fails the release rather than the commit.
CHANGELOG_RULE = re.compile(r"matching\s+`##\s+\[<version>\]`\s+section\s+of\s+`CHANGELOG\.md`")

# The fenced `bash` block of step 2, which holds the version check a maintainer runs. The
# reader takes the whole block, so the case runs the text the page shows.
VERSION_CHECK_BLOCK = re.compile(
    r"2\. Confirm the version and the changelog agree\.\s*\n\s*```bash\n(.*?)```",
    re.DOTALL,
)

# The line the version check writes on success. The case reads the declared version into
# this form, so a check that printed a constant would fail it.
# #543 added the release date and the classifier to the check, and the line names both.
VERSION_CHECK_REPORT = "version {version} has a dated changelog section and the right classifier"

# The text of step 1 before #512, quoted from the file rather than rewritten. The
# discrimination cases read it, so the defect cannot come back unmeasured.
SUPERSEDED_STEP_1 = (
    "1. Set the version. It lives in `pyproject.toml` only. `ja4plus/__init__.py` reads it\n"
    "   with `importlib.metadata.version`.\n"
)


def skill_text() -> str:
    """Return the text of the release skill.

    Returns:
        The whole file, decoded as UTF-8.
    """
    return SKILL.read_text(encoding="utf-8")


def version_source(text: str) -> Optional[Tuple[str, int]]:
    """Return the file and the line that the release skill names as the version source.

    Args:
        text: The text of `.claude/skills/release/SKILL.md`.

    Returns:
        The tracked path and the line number, or None where the skill names neither.
    """
    match = VERSION_SOURCE.search(text)
    if match is None:
        return None
    return match.group(1), int(match.group(2))


def version_source_disagreement(text: str, repository_root: Path) -> Optional[str]:
    """Return the reason the named version source is not the version declaration.

    The reader opens the file the skill names and reads the line the skill names. It
    compares neither against a second copy of the prose.

    Args:
        text: The text of `.claude/skills/release/SKILL.md`.
        repository_root: The root of the checkout to read.

    Returns:
        One sentence that states the disagreement, or None where the two agree.
    """
    source = version_source(text)
    if source is None:
        return "the release skill names no version source and no line"
    path, line_number = source
    target = repository_root / path
    if not target.is_file():
        return f"the release skill names `{path}`, and the repository holds no such file"
    lines = target.read_text(encoding="utf-8").splitlines()
    if line_number > len(lines):
        return f"the release skill names line {line_number} of `{path}`, which holds {len(lines)} lines"
    declared = lines[line_number - 1]
    if PACKAGE_DECLARATION.match(declared) is None:
        return f"line {line_number} of `{path}` reads {declared!r} and declares no `__version__`"
    return None


def test_the_release_skill_names_the_file_and_the_line_that_declare_the_version() -> None:
    assert version_source_disagreement(skill_text(), REPOSITORY_ROOT) is None


def test_the_release_skill_names_the_one_declaration_that_git_reports() -> None:
    source = version_source(skill_text())
    assert source is not None, "the release skill names no version source"
    assert declaration_files(REPOSITORY_ROOT) == [source[0]]


def test_the_version_check_of_the_release_skill_reports_the_declared_version() -> None:
    match = VERSION_CHECK_BLOCK.search(skill_text())
    assert match is not None, "step 2 of the release skill holds no `bash` block"
    # The block carries the indent of the numbered step. A heredoc ends on a line that
    # holds the delimiter alone, so the runner removes that indent before it runs the text.
    command = textwrap.dedent(match.group(1)).replace("python -", f"{sys.executable} -", 1)
    result = subprocess.run(
        ["bash", "-c", command],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"the version check exited {result.returncode}: {result.stderr}"
    declared = package_version((REPOSITORY_ROOT / "ja4plus" / "__init__.py").read_text())
    assert declared is not None, "`ja4plus/__init__.py` declares no `__version__`"
    assert VERSION_CHECK_REPORT.format(version=declared) in result.stdout


def test_the_release_skill_keeps_the_plain_string_assignment() -> None:
    assert SYNTAX_TREE_RULE.search(skill_text()) is not None


def test_the_release_skill_puts_the_changelog_section_in_the_bump() -> None:
    assert CHANGELOG_RULE.search(skill_text()) is not None


def test_the_release_skill_reads_the_version_through_the_version_gate() -> None:
    match = VERSION_CHECK_BLOCK.search(skill_text())
    assert match is not None, "step 2 of the release skill holds no `bash` block"
    assert "version_gate" in match.group(1)
    assert "tomllib" not in match.group(1)


def test_the_reader_names_pyproject_toml_nowhere_in_the_current_skill() -> None:
    source = version_source(skill_text())
    assert source is not None, "the release skill names no version source"
    assert source[0] != "pyproject.toml"


def test_the_reader_reports_the_superseded_step_1() -> None:
    reason = version_source_disagreement(SUPERSEDED_STEP_1, REPOSITORY_ROOT)
    assert reason == "the release skill names no version source and no line"


def test_the_reader_reports_a_step_that_names_pyproject_toml() -> None:
    mutation = "The version lives in `pyproject.toml` at line 20, and a bump edits that line alone."
    reason = version_source_disagreement(mutation, REPOSITORY_ROOT)
    assert reason is not None
    assert "declares no `__version__`" in reason


def test_the_reader_reports_a_step_that_names_the_wrong_line() -> None:
    source = version_source(skill_text())
    assert source is not None, "the release skill names no version source"
    mutation = f"The version lives in `{source[0]}` at line {source[1] + 1}"
    reason = version_source_disagreement(mutation, REPOSITORY_ROOT)
    assert reason is not None
    assert "declares no `__version__`" in reason


def test_the_reader_reports_a_file_the_repository_holds_nowhere() -> None:
    mutation = "The version lives in `ja4plus/version.py` at line 1"
    reason = version_source_disagreement(mutation, REPOSITORY_ROOT)
    assert (
        reason
        == "the release skill names `ja4plus/version.py`, and the repository holds no such file"
    )


@pytest.mark.parametrize(
    "pattern, name",
    [
        (SYNTAX_TREE_RULE, "SYNTAX_TREE_RULE"),
        (CHANGELOG_RULE, "CHANGELOG_RULE"),
        (VERSION_SOURCE, "VERSION_SOURCE"),
        (VERSION_CHECK_BLOCK, "VERSION_CHECK_BLOCK"),
    ],
)
def test_each_reader_of_the_release_skill_finds_nothing_in_the_superseded_step_1(
    pattern: "re.Pattern[str]", name: str
) -> None:
    assert pattern.search(SUPERSEDED_STEP_1) is None, name
