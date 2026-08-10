"""Name the test file that reads the values one module body builds.

`.claude/rules/conformance.md` states the cover procedure of one sweep. Step 2 of that
procedure subtracts the lines the import runs, because every test file that imports
`ja4plus` runs every module-level statement. A mutation of a module body therefore keeps
no reader, and the cost rule of step 3 then holds the cheapest test file.

This module reads the value rather than the line. It takes the names a module body binds
and the identifier strings those statements build, and it ranks the test files by the
count of those tokens each file names in its own source.

Run it directly to read the ranked list of one module.

    python -m tests.mutation_cover ja4plus/__init__.py

These functions read no packet and they produce no fingerprint.
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

# `git ls-files 'tests/**/test_*.py'` reads `**` as one or more directories, so it drops
# every file of the top directory of the suite. #411 measured that failure against the
# module patterns of `tests/mutation_sweep.py`, and these two patterns hold the same
# repair.
DEFAULT_TEST_PATTERNS = ("tests/test_*.py", "tests/*/test_*.py")

SECTION = "## How to scope one sweep: the minimal cover"

# A cost the rule states is a measurement of one run, so the prover asks for a number.
SECONDS = re.compile(r"\d+(?:\.\d+)?\s+seconds")


def body_tokens(path: Path) -> List[str]:
    """Return the tokens one module body builds.

    Args:
        path: The module to read.

    Returns:
        Every name a module-level assignment binds, and every identifier string those
        statements hold, in sorted order. The list is empty when the module body binds
        no name.

    Raises:
        SyntaxError: The file holds no parsable Python source.
    """
    tree = ast.parse(path.read_text())
    found = set()
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                found.add(target.id)
        for inner in ast.walk(node):
            # A mutation of `__all__` changes one entry string, so the entry is the value
            # a reader reads. A string that is no identifier names no value of the code.
            if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
                if inner.value.isidentifier():
                    found.add(inner.value)
    return sorted(found)


def test_files(root: Path, patterns: Sequence[str] = DEFAULT_TEST_PATTERNS) -> List[str]:
    """Return every tracked test file of the repository, as a path below the root."""
    listed = subprocess.run(
        ["git", "ls-files", *patterns],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    return [path for path in listed if path]


def body_readers(
    root: Path, module: Path, patterns: Sequence[str] = DEFAULT_TEST_PATTERNS
) -> List[Tuple[str, int]]:
    """Return each test file that names a token of the module body, and its count.

    Args:
        root: The repository root.
        module: The module to read, absolute or below the root.
        patterns: The pathspecs that list the test files.

    Returns:
        One pair for each test file that names one token or more, greatest count first
        and then path order. The list is empty when no test file names a token.
    """
    path = module if module.is_absolute() else root / module
    tokens = body_tokens(path)
    if not tokens:
        return []
    word = {token: re.compile(r"\b" + re.escape(token) + r"\b") for token in tokens}
    ranked = []
    for name in test_files(root, patterns):
        source = (root / name).read_text(errors="ignore")
        count = sum(1 for token in tokens if word[token].search(source))
        if count:
            ranked.append((name, count))
    ranked.sort(key=lambda pair: (-pair[1], pair[0]))
    return ranked


def body_reader(
    root: Path, module: Path, patterns: Sequence[str] = DEFAULT_TEST_PATTERNS
) -> Optional[str]:
    """Return the test file that names the most tokens of the module body.

    Args:
        root: The repository root.
        module: The module to read, absolute or below the root.
        patterns: The pathspecs that list the test files.

    Returns:
        The path of that file below the root, or None when no test file names a token.
        Path order breaks a tie, so two runs of one commit return one answer.
    """
    ranked = body_readers(root, module, patterns)
    return ranked[0][0] if ranked else None


def _section(text: str) -> str:
    """Return the cover section of the rule file, or the empty string."""
    if SECTION not in text:
        return ""
    rest = text.split(SECTION, 1)[1]
    return rest.split("\n## ", 1)[0]


def states_the_body_reader_rule(text: str) -> bool:
    """Report whether the cover section gives a module body its own reader.

    Args:
        text: The whole text of `.claude/rules/conformance.md`.

    Returns:
        True when the section names this module and names the line class it covers. The
        check reads no wording beyond those two anchors, so a writer rewords the step and
        the check still holds.
    """
    section = _section(text)
    return "tests/mutation_cover.py" in section and "module body" in section


def states_the_reader_cost(text: str) -> bool:
    """Report whether the cover section states a measured cost for the reader.

    Args:
        text: The whole text of `.claude/rules/conformance.md`.

    Returns:
        True when one line of the section names the reader of `ja4plus/__init__.py` and a
        second count. An estimate carries no second count, so it fails this check.
    """
    for line in _section(text).splitlines():
        if "tests/test_public_interface.py" in line and SECONDS.search(line):
            return True
    return False


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("module", help="The module to read, below the repository root.")
    parser.add_argument(
        "--top", type=int, default=5, help="The count of readers to print. 0 prints every one."
    )
    options = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    ranked = body_readers(root, Path(options.module))
    if not ranked:
        print("No test file names a token of {}.".format(options.module))
        return 1
    shown = ranked if options.top == 0 else ranked[: options.top]
    print("{} tokens in the module body.".format(len(body_tokens(root / options.module))))
    for name, count in shown:
        print("{:4d}  {}".format(count, name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
