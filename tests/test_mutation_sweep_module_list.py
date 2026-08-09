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

These cases read no packet and they produce no fingerprint.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Set

from tests import mutation_sweep

REPO_ROOT = Path(__file__).resolve().parent.parent


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


def swept_modules() -> Set[str]:
    """Return every module the sweep reads under its default patterns."""
    paths = mutation_sweep.module_paths(REPO_ROOT, mutation_sweep.DEFAULT_MODULE_PATTERNS)
    return {path.relative_to(REPO_ROOT).as_posix() for path in paths}


class TestTheModuleListOfOneSweep:
    def test_the_sweep_reads_every_tracked_module_of_the_package(self) -> None:
        assert swept_modules() == tracked_modules()

    def test_the_default_patterns_list_every_tracked_module_of_the_package(self) -> None:
        assert listed_by(list(mutation_sweep.DEFAULT_MODULE_PATTERNS)) == tracked_modules()

    def test_the_package_holds_more_than_one_directory_of_modules(self) -> None:
        depths = {path.count("/") for path in tracked_modules()}
        assert depths == {1, 2}


class TestThePathspecThatDropsSevenModules:
    def test_the_double_star_pathspec_lists_no_module_of_the_top_directory(self) -> None:
        below = {path for path in tracked_modules() if path.count("/") > 1}
        assert listed_by(["ja4plus/**/*.py"]) == below

    def test_the_double_star_pathspec_drops_the_processor_and_the_command_line_program(
        self,
    ) -> None:
        dropped = tracked_modules() - listed_by(["ja4plus/**/*.py"])
        assert "ja4plus/processor.py" in dropped
        assert "ja4plus/cli.py" in dropped
        assert len(dropped) == 7
