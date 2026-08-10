"""Read every fenced block of the documentation, and state the disposition of each one.

`tests/test_documentation_samples.py` runs the blocks this module reports. The module
stays separate from the cases, so a case can measure the reader itself. #302 shipped a
reader whose own floor came from its own defect, and a reader nothing measures repeats
that.

FR-documentation-4 covers the README and FR-documentation-5 covers `docs/`.
"""

from __future__ import annotations

import dataclasses
import pathlib
import re
from typing import Dict, List, Optional

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent

# A fence opens with three or more backticks or tildes, and CommonMark permits three
# leading spaces. The reader matches that grammar rather than the literal string
# "```python", because a reader that matches one literal form skips every other form.
_FENCE = re.compile(r"^(?P<indent> {0,3})(?P<ticks>`{3,}|~{3,})[ \t]*(?P<info>[^`\n]*)$")

# The marker sits above the opening fence. An explicit marker beats a heuristic: a
# heuristic reclassifies a sample the day somebody edits it, and it reports no change.
#
# The reader passes over a blank line between the marker and the fence. A reader that
# read one line alone would drop the marker the day somebody tidies the file, and the
# block would then run with no reason recorded.
_MARKER = re.compile(r"^<!--\s*sample:\s*(?P<body>.+?)\s*-->$")

# A fence inside a blockquote reaches neither reader, so a case bars the form.
BLOCKQUOTE_FENCE = re.compile(r"^ {0,3}>[ >]*(?:`{3,}|~{3,})")

EXCLUDED_DIRECTORY = "docs/specs"

# `docs/specs/` holds the design of the project and the transcription of the FoxIO
# material. `.claude/rules/ste.md` forbids a rewrite of text copied from FoxIO, and a
# runnable sample needs a rewrite, so no block of that directory runs. The census below
# still counts every one of them, because a skip nobody counts is the defect #63 removes.
EXCLUDED_DIRECTORY_REASON = (
    "docs/specs holds the specification package and the verbatim FoxIO transcription"
)

# The two languages this harness executes. A block in any other language, and a block
# with no info string, is output or data rather than a code sample.
RUNNABLE_LANGUAGES = ("python", "bash")


@dataclasses.dataclass(frozen=True)
class FencedBlock:
    """One fenced block of one Markdown file."""

    path: str
    line: int
    info: str
    body: str
    marker: Optional[str]

    @property
    def language(self) -> str:
        """Return the first word of the info string, or an empty string."""
        return self.info.split()[0].lower() if self.info.split() else ""

    @property
    def name(self) -> str:
        """Return the identifier a case reports for this block."""
        return f"{self.path}:{self.line}"


@dataclasses.dataclass(frozen=True)
class Disposition:
    """What the harness does with one fenced block, and why."""

    action: str  # "run", "raises", "skip" or "output"
    reason: str
    expected_error: Optional[str] = None


def read_fenced_blocks(path: pathlib.Path, relative_to: pathlib.Path) -> List[FencedBlock]:
    """Return every fenced block of one Markdown file, in file order.

    Args:
        path: The Markdown file to read.
        relative_to: The directory the reported path is relative to.

    Returns:
        One `FencedBlock` for each fenced block, with its marker where it carries one.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    blocks: List[FencedBlock] = []
    index = 0
    while index < len(lines):
        opening = _FENCE.match(lines[index])
        if opening is None:
            index += 1
            continue
        fence = opening.group("ticks")
        above = index - 1
        while above >= 0 and not lines[above].strip():
            above -= 1
        marker_match = _MARKER.match(lines[above].strip()) if above >= 0 else None
        body_start = index + 1
        end = body_start
        while end < len(lines):
            closing = _FENCE.match(lines[end])
            if (
                closing is not None
                and closing.group("ticks")[0] == fence[0]
                and len(closing.group("ticks")) >= len(fence)
                and not closing.group("info").strip()
            ):
                break
            end += 1
        blocks.append(
            FencedBlock(
                path=path.relative_to(relative_to).as_posix(),
                line=index + 1,
                info=opening.group("info").strip(),
                body="\n".join(lines[body_start:end]),
                marker=marker_match.group("body") if marker_match else None,
            )
        )
        index = end + 1
    return blocks


def documentation_files(root: pathlib.Path = REPOSITORY_ROOT) -> List[pathlib.Path]:
    """Return every Markdown file of the README and of `docs/`, in sorted order."""
    files = [root / "README.md"]
    files.extend(sorted((root / "docs").rglob("*.md")))
    return files


def user_documentation_files(root: pathlib.Path = REPOSITORY_ROOT) -> List[str]:
    """Return every Markdown file of the user documentation, in sorted order.

    The filesystem is the one record of which pages exist, so this function reads it
    rather than a list somebody maintains beside it. #64 added five pages under
    `docs/reference/` one sub-merge after this harness landed, and a hand-written list
    had already gone stale.

    Args:
        root: The repository root.

    Returns:
        The path of each page, relative to the root, with `docs/specs/` left out.
    """
    return [
        path.relative_to(root).as_posix()
        for path in documentation_files(root)
        if not path.relative_to(root).as_posix().startswith(EXCLUDED_DIRECTORY + "/")
    ]


def all_blocks(root: pathlib.Path = REPOSITORY_ROOT) -> List[FencedBlock]:
    """Return every fenced block of the README and of `docs/`, in file order."""
    blocks: List[FencedBlock] = []
    for path in documentation_files(root):
        blocks.extend(read_fenced_blocks(path, root))
    return blocks


def disposition(block: FencedBlock) -> Disposition:
    """Return what the harness does with one fenced block, and the reason.

    Args:
        block: The fenced block to classify.

    Returns:
        A `Disposition`. The action is `run`, `raises`, `skip` or `output`.
    """
    if block.path.startswith(EXCLUDED_DIRECTORY + "/"):
        return Disposition("skip", EXCLUDED_DIRECTORY_REASON)
    if block.language not in RUNNABLE_LANGUAGES:
        return Disposition("output", f"the info string is {block.info!r}")
    if block.marker is None:
        return Disposition("run", "the block declares a language this harness runs")
    if block.marker.startswith("skip "):
        return Disposition("skip", block.marker[len("skip ") :].strip())
    if block.marker.startswith("raises "):
        rest = block.marker[len("raises ") :].strip().split(maxsplit=1)
        return Disposition("raises", rest[1] if len(rest) > 1 else "", rest[0])
    raise ValueError(f"{block.name}: the marker {block.marker!r} names no known action")


def census(root: pathlib.Path = REPOSITORY_ROOT) -> Dict[str, int]:
    """Return the count of fenced blocks the reader found, by action."""
    counts: Dict[str, int] = {"run": 0, "raises": 0, "skip": 0, "output": 0}
    for block in all_blocks(root):
        counts[disposition(block).action] += 1
    return counts
