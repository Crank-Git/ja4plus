"""Tests that one sweep reads every module of the package.

`FR-pre-release-validation-16` asks the sweeps to apply every mutation of every module,
and `FR-pre-release-validation-16a` asks a case to fail when the module list moves. A
module the sweep never reads is a module no mutation measures, and nothing else in this
repository reports that omission.

**Never write `git ls-files 'ja4plus/**/*.py'`.** Git reads `**` in a pathspec as one or
more directories, so that pattern lists 24 files where the package holds 31, and it drops
every module of the top directory of the package. `ja4plus/processor.py` and
`ja4plus/cli.py` are two of the seven it drops. #411 measured the difference, and
`FR-pre-release-validation-16` carried the defective pattern until then.

The glob of a rule file is a different thing. `.claude/rules/ste.md` and
`.claude/rules/external-apis.md` hold `ja4plus/**/*.py` in their front matter, that glob
follows the gitignore rules, and it matches every module. Do not repair those.

**A count that is right proves no rule that is right.** `FR-pre-release-validation-16`
named `git ls-files 'ja4plus/*.py' 'ja4plus/*/*.py'` until #436. That pair lists all 31
modules, and the first term alone lists all 31 too, because `*` crosses `/` in a default
git pathspec. The second term therefore added nothing, and a reader who reasoned from the
pair read a separator rule that git does not hold. #411 and #414 each met that reading.
The cases of `TestThePathspecTheRequirementStates` read the pathspec out of the
requirement, so the text of the requirement is what they measure.

These cases read no packet and they produce no fingerprint.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path
from typing import List, Set

from tests import mutation_sweep

REPO_ROOT = Path(__file__).resolve().parent.parent

REQUIREMENT_FILE = REPO_ROOT / "docs" / "specs" / "features" / "11-pre-release-validation.md"

# The requirement states its pathspec as one `git ls-files` command with quoted terms.
# The case runs what the document states, so a document that states a different pathspec
# than the sweep reads fails here rather than misleading the next reader.
# The pattern reads `\s` between the terms, because the feature document wraps its lines
# and `FR-pre-release-validation-16a` already holds a command that wraps inside its
# backticks. A pattern that reads one space alone finds nothing after such a wrap.
LS_FILES_COMMAND = re.compile(r"`(git ls-files\s+(?:'[^']*'\s*)+)`")

SEPARATOR_RULE = "`*` crosses `/`"


def tracked_modules() -> Set[str]:
    """Return every tracked Python file of the package, whatever its depth."""
    listed = subprocess.run(
        ["git", "ls-files", "ja4plus"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    return {path for path in listed if path.endswith(".py")}


def listed_by(patterns: list) -> Set[str]:
    """Return every tracked file the named pathspecs list."""
    listed = subprocess.run(
        ["git", "ls-files", *patterns],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    return {path for path in listed if path}


def requirement_text(identifier: str) -> str:
    """Return the one paragraph of the feature document that states the requirement.

    Args:
        identifier: The requirement identifier, for example
            `FR-pre-release-validation-16`.

    Returns:
        The text of the paragraph, with no trailing separator.

    Raises:
        AssertionError: The document holds no paragraph for the identifier.
    """
    blocks = REQUIREMENT_FILE.read_text(encoding="utf-8").split("\n\n")
    opening = "{} —".format(identifier)
    found = [block for block in blocks if block.startswith(opening)]
    assert len(found) == 1, "{} opens {} paragraphs of {}".format(
        identifier, len(found), REQUIREMENT_FILE.name
    )
    return found[0]


def stated_pathspec(identifier: str) -> List[str]:
    """Return the pathspec terms of the `git ls-files` command the requirement states.

    Args:
        identifier: The requirement identifier that holds the command.

    Returns:
        One term for each quoted argument, in the order the document writes them.

    Raises:
        AssertionError: The requirement states no `git ls-files` command, or it states
            more than one.
    """
    text = requirement_text(identifier)
    found = LS_FILES_COMMAND.findall(text)
    assert len(found) == 1, "{} states {} `git ls-files` commands".format(identifier, len(found))
    terms = shlex.split(found[0])[2:]
    # A pathspec of no term lists the whole repository, and every set comparison below
    # would then measure something the requirement never stated.
    assert terms, "{} states a `git ls-files` command of no pathspec".format(identifier)
    return terms


def swept_modules() -> Set[str]:
    """Return every module the sweep reads under its default patterns."""
    paths = mutation_sweep.module_paths(REPO_ROOT, mutation_sweep.DEFAULT_MODULE_PATTERNS)
    return {path.relative_to(REPO_ROOT).as_posix() for path in paths}


class TestTheModuleListOfOneSweep:
    def test_the_sweep_reads_every_tracked_module_of_the_package(self) -> None:
        assert swept_modules() == tracked_modules()

    def test_the_default_patterns_list_every_tracked_module_of_the_package(self) -> None:
        assert listed_by(list(mutation_sweep.DEFAULT_MODULE_PATTERNS)) == tracked_modules()

    def test_the_default_patterns_reach_the_depth_of_every_tracked_module(self) -> None:
        # `DEFAULT_MODULE_PATTERNS` reaches `Path.glob`, where `*` stops at `/`. A git
        # pathspec reads the same string differently, so the sweep needs the two patterns
        # that `FR-pre-release-validation-16` needs one term for.
        # `ja4plus/*.py` reaches depth 1 and `ja4plus/*/*.py` reaches depth 2. A module
        # below depth 2 needs a third pattern, and the two cases above would then fail
        # with no reader knowing which pattern to add.
        assert len(mutation_sweep.DEFAULT_MODULE_PATTERNS) == 2
        assert {path.count("/") for path in tracked_modules()} == {1, 2}


class TestThePathspecTheRequirementStates:
    """These cases read `FR-pre-release-validation-16` and they run what it states.

    A reader copies the pathspec of a requirement and applies its rule elsewhere. Three
    defects of one epic came from a pathspec whose plain reading missed what git matches,
    so these cases bind the text and not a count a writer transcribed.
    """

    def test_the_stated_pathspec_lists_the_module_set_the_sweep_reads(self) -> None:
        listed = listed_by(stated_pathspec("FR-pre-release-validation-16"))
        # An empty set equals no module set the sweep reads, and the floor states that
        # rather than resting on the comparison alone.
        assert listed, "the stated pathspec lists no file"
        assert listed == swept_modules()

    def test_the_stated_pathspec_reaches_every_depth_of_the_package(self) -> None:
        # A pathspec whose `*` stops at a separator lists one depth alone. The depth set
        # is the property that separates the two readings, and a module count is not,
        # because a count moves whenever the package gains a module.
        listed = listed_by(stated_pathspec("FR-pre-release-validation-16"))
        assert listed == tracked_modules()
        assert {path.count("/") for path in listed} == {1, 2}

    def test_every_term_of_the_stated_pathspec_lists_a_file_no_other_term_lists(
        self,
    ) -> None:
        # A redundant term reports the right count for the wrong reason. The pair
        # `'ja4plus/*.py' 'ja4plus/*/*.py'` listed all 31 modules while its first term
        # alone listed all 31, and two later readers took the second term for proof that
        # `*` stops at a separator.
        terms = stated_pathspec("FR-pre-release-validation-16")
        for position, term in enumerate(terms):
            others = terms[:position] + terms[position + 1 :]
            added = listed_by([term]) - listed_by(others) if others else listed_by([term])
            assert added, "the term {} lists no file the other terms miss".format(term)

    def test_the_requirement_states_that_a_star_crosses_a_separator(self) -> None:
        assert SEPARATOR_RULE in requirement_text("FR-pre-release-validation-16")


class TestThePathspecThatDropsSevenModules:
    """These two cases measure git and they do not measure the sweep.

    They record why `DEFAULT_MODULE_PATTERNS` holds two patterns rather than the one
    pattern `FR-pre-release-validation-16` carried. A reader who meets the `**` form in
    another repository reads the measurement here instead of the claim.
    """

    def test_the_double_star_pathspec_lists_no_module_of_the_top_directory(self) -> None:
        below = {path for path in tracked_modules() if path.count("/") > 1}
        assert listed_by(["ja4plus/**/*.py"]) == below

    def test_the_double_star_pathspec_drops_the_processor_and_the_command_line_program(
        self,
    ) -> None:
        dropped = swept_modules() - listed_by(["ja4plus/**/*.py"])
        assert "ja4plus/processor.py" in dropped
        assert "ja4plus/cli.py" in dropped
        assert len(dropped) == 7
