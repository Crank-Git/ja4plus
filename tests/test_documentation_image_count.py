"""Tests that the documentation states the FoxIO image count the inventory measures.

`docs/specs/foxio/README.md` holds the inventory of `technical_details/` at the pinned
commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`. The directory holds twelve files:
three text files and nine images. One method of twelve holds a complete text
specification, and that method is JA4.

#195 corrected four files and left three that kept the superseded count. #211 corrects
the three and adds these cases, so that a later reader finds the contradiction here
rather than in a review.

These cases read prose. They import nothing from `ja4plus` and they produce no
fingerprint.
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# The count the inventory supersedes. `docs/specs/spec.md` records the superseded premise
# in Changelog round 49 with different words, so that history survives this case.
SUPERSEDED_COUNT = "seven of the twelve"

# `technical_details/README.md` lists these twelve methods at the pinned commit.
FOXIO_METHODS = (
    "JA4",
    "JA4S",
    "JA4H",
    "JA4L",
    "JA4LS",
    "JA4X",
    "JA4SSH",
    "JA4T",
    "JA4TS",
    "JA4TScan",
    "JA4D",
    "JA4D6",
)

CONFORMANCE_FEATURE = REPO_ROOT / "docs" / "specs" / "features" / "01-spec-conformance.md"


def _documentation_files() -> list[Path]:
    """Return every prose file that may state the FoxIO image count.

    Returns:
        The Markdown pages under `docs/` and `.claude/rules/`, the rendered
        `docs/specs/spec.html`, `CLAUDE.md` and `README.md`.
    """
    files = sorted((REPO_ROOT / "docs").rglob("*.md"))
    files += sorted((REPO_ROOT / ".claude" / "rules").glob("*.md"))
    files.append(REPO_ROOT / "docs" / "specs" / "spec.html")
    files.append(REPO_ROOT / "CLAUDE.md")
    files.append(REPO_ROOT / "README.md")
    return [path for path in files if path.is_file()]


def _section(text: str, heading: str) -> str:
    """Return the body of one Markdown section, up to the next heading of any level.

    Args:
        text: The whole page.
        heading: The heading line, including its `#` characters.

    Returns:
        The text after the heading and before the next line that starts with `#`.

    Raises:
        AssertionError: The page holds no line equal to the heading.
    """
    # A paragraph quotes a heading, so a search of the whole page reaches the quotation
    # first and returns the wrong body. Match the heading as a whole line instead.
    page = text.splitlines()
    starts = [number for number, line in enumerate(page) if line.strip() == heading]
    assert starts, f"the page holds no {heading!r} heading"
    assert len(starts) == 1, f"the page holds {len(starts)} {heading!r} headings"
    lines: list[str] = []
    for line in page[starts[0] + 1 :]:
        if line.startswith("#"):
            break
        lines.append(line)
    return "\n".join(lines)


def _first_table(section: str) -> list[str]:
    """Return the rows of the first Markdown table of one section.

    A section holds more than one table, so a case that reads every row of the section
    passes on a name another table carries.

    Args:
        section: The body of one section.

    Returns:
        The lines of the first table, header row first.

    Raises:
        AssertionError: The section holds no table.
    """
    rows: list[str] = []
    for line in section.splitlines():
        if line.startswith("|"):
            rows.append(line)
        elif rows:
            break
    assert rows, "the section holds no table"
    return rows


def _bullet(section: str, subject: str) -> list[str]:
    """Return every line of the one bullet that opens with the subject.

    A bullet wraps over several lines, so a case that reads one line misses the rest.

    Args:
        section: The body of one section.
        subject: The word the bullet opens with.

    Returns:
        The lines of the bullet, or an empty list when the section holds no such bullet.
    """
    lines: list[str] = []
    for line in section.splitlines():
        if line.startswith(f"- {subject}"):
            lines.append(line)
        # The next bullet and a blank line each end this bullet. A search that stops on
        # the next bullet alone swallows the prose that follows the last bullet.
        elif lines and (line.startswith("- ") or not line.strip()):
            break
        elif lines:
            lines.append(line)
    return lines


def test_no_documentation_file_states_the_superseded_image_count() -> None:
    """No page states that FoxIO publishes seven of the twelve methods as an image."""
    offenders = []
    for path in _documentation_files():
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            if SUPERSEDED_COUNT in line.lower():
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}")
    assert offenders == [], (
        f"these lines state the superseded count {SUPERSEDED_COUNT!r}: {offenders}"
    )


@pytest.mark.parametrize("method", FOXIO_METHODS)
def test_the_conformance_interface_table_names_every_foxio_method(method: str) -> None:
    """The `Interfaces` table of the conformance feature names all twelve methods."""
    interfaces = _section(CONFORMANCE_FEATURE.read_text(encoding="utf-8"), "## Interfaces")
    names = {
        cell.strip().strip("`")
        for row in _first_table(interfaces)
        for cell in row.split("|")[1].split(",")
    }
    assert method in names, f"the table names no row for {method}"


def test_the_conformance_feature_states_the_ja4tscan_decline() -> None:
    """The `Out of scope` section records the JA4TScan decline, not an open question."""
    out_of_scope = _section(CONFORMANCE_FEATURE.read_text(encoding="utf-8"), "## Out of scope")
    ja4tscan = _bullet(out_of_scope, "JA4TScan")
    assert ja4tscan, "the section names no JA4TScan bullet"
    text = "\n".join(ja4tscan)
    assert "open question" not in text, "the bullet still calls JA4TScan an open question"
    assert "#197" in text, "the bullet cites no issue for the decline"
