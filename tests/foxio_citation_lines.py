"""Read every line citation of the transcription pages that names a file this repository owns.

**A `file:line` citation of a repository-owned file goes stale on every change above the
cited line, and nothing reported it before this reader.** #668 measured 282 citations over
the ten pages and found ten wrong. The maintainer ruled on 2026-08-15 that the pins of
those pages stand, so this reader never repairs a citation to a working-tree line.

## The two classes

A citation stands in one of two classes, and the section it stands in decides the class.
The file it names decides nothing.

| The citation stands | This reader reads it against |
|---|---|
| under a pin declaration | the commit that declaration names |
| under no pin declaration | the working tree |

**A pin declaration is a sentence that opens with `The comparison below reads`**, names one
or more paths under `ja4plus/`, and names one commit as ``at commit `<commit>` ``. It
governs every citation of those paths from its own line to the next declaration or to the
next `## ` heading, whichever comes first.

**A table cell that names its own commit overrides the declaration above it.** The cell is
the nearer statement, so it wins. `docs/specs/foxio/JA4H.md` carries one such cell, for R19.

## What this reader checks

**The file holds the cited line at the read the citation declares.** That condition needs
no table a person keeps, and #668 measured that it fails exactly the ten wrong citations
and passes the 272 correct ones.

**The cited lines hold a statement.** #668 read the line count alone, so a citation of a
blank line passed. A blank line names nothing, and a line that holds a comment alone names
nothing either. #690 measured five such citations on `docs/implementation_notes.md` and 27
on the pages of `docs/specs/foxio/`.

**Warning: a citation of a comment line is not always wrong**, because a page may cite the
comment that states a reason. `tests/citation_line_allowlist.json` holds every citation of
the second class that stood before this condition, and #709 reads each one.

## The pages this reader holds

**#668 globbed `docs/specs/foxio/` alone, and `docs/implementation_notes.md` drifted
outside it.** `PAGES` names both, so a citation of either one reaches this reader.

**Warning: this reader reads no FoxIO citation.** `tests/test_ja4t_citation_lines.py` reads
those at the FoxIO pin, against a recorded source line. The two readers answer different
questions, and a reader that merged them would be wrong in both directions.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

PAGE_DIRECTORY = REPO_ROOT / "docs" / "specs" / "foxio"

# The pages this reader holds outside `PAGE_DIRECTORY`. No reader read this page before
# #690. A review lens of #600 found the one falsified citation that round produced.
OUTSIDE_PAGES = (REPO_ROOT / "docs" / "implementation_notes.md",)

# The record of every citation that names no statement and stood before this condition.
# #709 reads each entry and removes this file.
ALLOWLIST = REPO_ROOT / "tests" / "citation_line_allowlist.json"

# A citation names a path and one line, or a path and a line range. A range citation states
# its first line and its last line, and both must exist.
CITATION = re.compile(r"`([A-Za-z0-9_./-]+\.py):(\d+)(?:-(\d+))?`")

# The opener of a pin declaration. A page that states a pin any other way declares none, so
# every citation under it reads the working tree.
DECLARATION_OPENER = "The comparison below reads"

# The commit a declaration or a cell names.
PIN = re.compile(r"at commit `([0-9a-f]{7,40})`")

# A subject path of a declaration. A declaration names the whole path, so a reader needs no
# guess about which file a later shorthand means.
SUBJECT = re.compile(r"`(ja4plus/[A-Za-z0-9_./-]+\.py)`")

# The directories of the FoxIO checkout. A citation under one of them names no file this
# repository owns, whatever a basename of this repository matches.
FOXIO_PREFIXES = ("python/", "rust/", "wireshark/", "zeek/", "epan/", "technical_details/")

# The reference the workflow writes for a pin, because the clone of the runner holds depth 1
# and reaches no pin on its own. `.github/workflows/test.yml` fetches each one.
PIN_REFERENCE = "refs/ja4plus/citation-pin-{pin}"


@dataclass(frozen=True)
class Citation:
    """One line citation of one page, with the read its section declares."""

    page: str
    page_line: int
    written: str
    path: str
    first: int
    last: int
    pin: str | None

    @property
    def read_against(self) -> str:
        return f"commit {self.pin}" if self.pin else "the working tree"


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )


def tracked_python_files() -> list[str]:
    """Return every Python file the index of this repository holds."""
    return sorted(_git("ls-files", "*.py").stdout.split())


def _basename_index(paths: list[str]) -> dict[str, str]:
    """Return the one tracked path of each basename exactly one tracked path holds."""
    seen: dict[str, list[str]] = {}
    for path in paths:
        seen.setdefault(Path(path).name, []).append(path)
    return {name: found[0] for name, found in seen.items() if len(found) == 1}


def resolve_path(written: str, tracked: list[str], by_basename: dict[str, str]) -> str | None:
    """Return the tracked path a citation names, or None where this repository owns none.

    Args:
        written: The path as the page writes it, whole or as a basename.
        tracked: Every tracked Python file.
        by_basename: The basenames exactly one tracked path holds.

    Returns:
        The tracked path, or None for a FoxIO path and for a path no tracked file matches.
    """
    if written.startswith(FOXIO_PREFIXES):
        return None
    if written in tracked:
        return written
    return by_basename.get(written)


def _declaration_blocks(lines: list[str]) -> list[tuple[int, list[str], str | None]]:
    """Return each pin declaration of a page, as its line index, subjects and commit."""
    blocks: list[tuple[int, list[str], str | None]] = []
    for index, line in enumerate(lines):
        if DECLARATION_OPENER not in line:
            continue
        end = index
        while end < len(lines) and lines[end].strip():
            end += 1
        text = "\n".join(lines[index:end])
        found = PIN.search(text)
        blocks.append((index, SUBJECT.findall(text), found.group(1) if found else None))
    return blocks


def _cell_of(line: str, position: int) -> str:
    """Return the table cell of one line that holds the given position.

    **An override reaches the cell that carries the citation, and it reaches no other
    cell.** A row of the comparison tables holds four cells, and the Reading cell of one row
    names a FoxIO commit while the citation cell names none. A reader of the whole line
    would take that FoxIO commit for the pin of the citation.

    Args:
        line: One line of a page.
        position: The offset of the citation inside that line.

    Returns:
        The text between the pipe characters that surround the position. A line that holds
        no pipe character is one cell, so the whole line comes back.
    """
    start = line.rfind("|", 0, position) + 1
    end = line.find("|", position)
    return line[start:] if end == -1 else line[start:end]


def _section_start(lines: list[str], index: int) -> int:
    """Return the line index of the `## ` heading that holds the given line."""
    for candidate in range(index, -1, -1):
        if lines[candidate].startswith("## "):
            return candidate
    return 0


def pages() -> list[Path]:
    """Return every page this reader holds, in one order."""
    return sorted(PAGE_DIRECTORY.glob("*.md")) + [page for page in OUTSIDE_PAGES if page.is_file()]


def allowlist() -> list[dict[str, object]]:
    """Return every recorded citation that names no statement, or nothing where #709 lands."""
    if not ALLOWLIST.is_file():
        return []
    entries: list[dict[str, object]] = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    return entries


def _allowed() -> set[tuple[str, str]]:
    """Return the page and the written form of each recorded citation."""
    return {(str(entry["page"]), str(entry["citation"])) for entry in allowlist()}


def all_citations() -> list[Citation]:
    """Return every repository-owned citation of every page, in page order."""
    found: list[Citation] = []
    for page in pages():
        found.extend(read_text(page.name, page.read_text(encoding="utf-8")))
    return found


def page_declarations(name: str) -> list[tuple[int, list[str], str | None]]:
    """Return each pin declaration of one page, as its line index, subjects and commit."""
    for page in pages():
        if page.name == name:
            return _declaration_blocks(page.read_text(encoding="utf-8").splitlines())
    raise AssertionError(f"this reader holds no page named {name}")


def declared_pins() -> list[str]:
    """Return every commit the pages name, sorted and without a repeat."""
    return sorted({citation.pin for citation in all_citations() if citation.pin})


def _blob(pin: str | None, path: str) -> list[str] | None:
    """Return the lines of one file at one read, or None where the read fails."""
    if pin is None:
        whole = REPO_ROOT / path
        return whole.read_text(encoding="utf-8").splitlines() if whole.exists() else None
    for revision in (pin, PIN_REFERENCE.format(pin=pin)):
        result = _git("show", f"{revision}:{path}")
        if result.returncode == 0:
            return result.stdout.splitlines()
    return None


def read_text(name: str, text: str) -> list[Citation]:
    """Return every repository-owned citation of one page held in memory.

    Args:
        name: The name the result reports for the page.
        text: The whole page.

    Returns:
        The citations, read by the same rule as a page on disk. A reversal case calls this.
    """
    tracked = tracked_python_files()
    lines = text.splitlines()
    blocks = _declaration_blocks(lines)
    by_basename = _basename_index(tracked)
    found: list[Citation] = []
    for index, line in enumerate(lines):
        for match in CITATION.finditer(line):
            path = resolve_path(match.group(1), tracked, by_basename)
            if path is None:
                continue
            first = int(match.group(2))
            last = int(match.group(3)) if match.group(3) else first
            cell = PIN.search(_cell_of(line, match.start()))
            pin = cell.group(1) if cell else None
            if pin is None:
                section = _section_start(lines, index)
                for start, subjects, commit in blocks:
                    if section <= start <= index and path in subjects:
                        pin = commit
            found.append(Citation(name, index + 1, match.group(0), path, first, last, pin))
    return found


def names_a_statement(lines: list[str]) -> bool:
    """Return True where one line of the range holds something other than a comment.

    Args:
        lines: The cited lines, as the file holds them.

    Returns:
        False where every line is blank or holds a comment alone. A docstring line and a
        closing bracket each belong to a statement, so both return True.
    """
    return any(
        stripped and not stripped.startswith("#") for stripped in (line.strip() for line in lines)
    )


def wrong_citations(
    citations: list[Citation] | None = None, allow: bool = True
) -> list[tuple[Citation, str]]:
    """Return every citation the file does not hold at the read the citation declares.

    Args:
        citations: The citations to read. Every page this reader holds by default.
        allow: True to pass a citation `tests/citation_line_allowlist.json` records. One
            case reads the corpus with False, so a stale entry fails there.

    Returns:
        Each wrong citation, with one sentence that states what the read found.
    """
    wrong: list[tuple[Citation, str]] = []
    blobs: dict[tuple[str | None, str], list[str] | None] = {}
    allowed = _allowed() if allow else set()
    for citation in all_citations() if citations is None else citations:
        key = (citation.pin, citation.path)
        if key not in blobs:
            blobs[key] = _blob(citation.pin, citation.path)
        source = blobs[key]
        if source is None:
            wrong.append(
                (citation, f"no reader reached {citation.path} at {citation.read_against}")
            )
            continue
        if citation.last > len(source):
            wrong.append(
                (
                    citation,
                    f"{citation.path} holds {len(source)} lines at {citation.read_against}",
                )
            )
            continue
        if names_a_statement(source[citation.first - 1 : citation.last]):
            continue
        if (citation.page, citation.written) in allowed:
            continue
        wrong.append(
            (
                citation,
                f"the lines hold no statement at {citation.read_against}, because each one "
                "is blank or holds a comment alone",
            )
        )
    return wrong


def census() -> str:
    """Return one table row for each page, with the count of each class it holds."""
    citations = all_citations()
    wrong = {(bad.page, bad.page_line, bad.written) for bad, _ in wrong_citations()}
    rows = ["| Page | Pinned | Unpinned | Total | Wrong |", "|---|---|---|---|---|"]
    for name in [page.name for page in pages()]:
        held = [citation for citation in citations if citation.page == name]
        pinned = sum(1 for citation in held if citation.pin)
        bad = sum(
            1 for citation in held if (citation.page, citation.page_line, citation.written) in wrong
        )
        rows.append(f"| `{name}` | {pinned} | {len(held) - pinned} | {len(held)} | {bad} |")
    rows.append(
        f"| **Total** | {sum(1 for c in citations if c.pin)} "
        f"| {sum(1 for c in citations if not c.pin)} | {len(citations)} | {len(wrong)} |"
    )
    return "\n".join(rows)


def main() -> int:
    """Print the census and return 1 where any citation is wrong."""
    print(census())
    wrong = wrong_citations()
    for citation, reason in wrong:
        print(f"{citation.page}:{citation.page_line}: {citation.written} — {reason}")
    return 1 if wrong else 0


if __name__ == "__main__":
    raise SystemExit(main())
