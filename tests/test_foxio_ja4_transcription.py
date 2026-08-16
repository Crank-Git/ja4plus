"""The transcription page of JA4, held against the records it repeats.

**A transcription page states facts that four other records already hold, and nothing
compared them before this file.** `docs/specs/foxio/README.md` holds the inventory of the
FoxIO material, `docs/specs/spec.md` holds the divergence register, the vector set holds
the values, and the page repeats all three. A page that drifts from any one of them reads
as evidence and is not.

**JA4 is the one method of the twelve that carries a complete text specification.** The
page therefore transcribes two files rather than one, and the cases below hold the
provenance of each one against the inventory.

**Warning: these cases read no FoxIO file.** This repository holds no copy of
`technical_details/JA4.md`, so the inventory of `docs/specs/foxio/README.md` is the
recorded reading, and `tests/foxio_citation_lines.py` reads the citations that name a file
this repository owns.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

PAGE = REPO_ROOT / "docs" / "specs" / "foxio" / "JA4.md"

INVENTORY = REPO_ROOT / "docs" / "specs" / "foxio" / "README.md"

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

PINNED_COMMIT = "27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8"

# The image draws this string, and its own caption states that part b holds the sorted
# cipher list. The sorted list hashes to `8daaf6152771`, so the drawn value pairs the
# unsorted part b with the sorted part c.
IMAGE_EXAMPLE = "t13d1516h2_acb858a92679_e5627efa2ab1"

# The four values the text specification states for one client hello.
SPECIFICATION_EXAMPLE = {
    "JA4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
    "JA4_o": "t13d1516h2_acb858a92679_18f69afefd3d",
}


def page_text() -> str:
    """Return the whole transcription page."""
    return PAGE.read_text(encoding="utf-8")


def inventory_row(name: str) -> str:
    """Return the inventory row of one file of the FoxIO material.

    Args:
        name: The file name, as the inventory writes it.

    Returns:
        The one row that names the file.
    """
    rows = [
        line
        for line in INVENTORY.read_text(encoding="utf-8").splitlines()
        if line.startswith(f"| `{name}` |")
    ]
    assert len(rows) == 1, f"the inventory holds {len(rows)} rows for {name}"
    return rows[0]


def inventory_hash(name: str) -> str:
    """Return the SHA-256 the inventory records for one file of the FoxIO material."""
    found = re.search(r"`([0-9a-f]{64})`", inventory_row(name))
    assert found is not None, f"the inventory row of {name} states no SHA-256"
    return found.group(1)


def vector_values(method: str) -> list[str]:
    """Return every value one method holds in the FoxIO expected-output files.

    Args:
        method: The method name, without the occurrence counter.

    Returns:
        One string for each value, over every `*.json` file of the vector set.
    """
    found: list[str] = []
    for path in sorted(VECTORS.glob("*.json")):
        for stream in json.loads(path.read_text(encoding="utf-8")):
            for key, value in stream.items():
                if key.split(".")[0] == method:
                    found.append(str(value))
    return found


def rule_section(rule: str) -> str:
    """Return the text of one rule section of the page.

    Args:
        rule: The rule name, as the heading writes it, such as `R13`.

    Returns:
        Every line from the heading of that rule to the next heading.
    """
    lines = page_text().splitlines()
    opener = [index for index, line in enumerate(lines) if line.startswith(f"### {rule} — ")]
    assert len(opener) == 1, f"the page holds {len(opener)} headings for {rule}"
    start = opener[0]
    end = start + 1
    while end < len(lines) and not lines[end].startswith("#"):
        end += 1
    return "\n".join(lines[start:end])


def test_the_directory_holds_a_transcription_page_for_ja4() -> None:
    """A reader who searches the transcription directory for a JA4 rule finds a page."""
    assert PAGE.is_file(), "docs/specs/foxio/JA4.md holds the JA4 transcription"


def test_the_page_states_the_pinned_commit_it_reads_the_material_at() -> None:
    """A transcription that names no commit records no read."""
    assert PINNED_COMMIT in page_text()


def test_the_page_states_the_hash_the_inventory_records_for_each_file() -> None:
    """The page and the inventory read one commit, so they state one hash for each file."""
    text = page_text()
    for name in ("JA4.png", "JA4.md"):
        assert inventory_hash(name) in text, (
            f"the page must state the SHA-256 the inventory records for {name}"
        )


def test_the_page_states_that_ja4_is_the_one_method_with_a_text_specification() -> None:
    """A reader who stops at the image reads no rule the text alone states."""
    text = page_text()
    assert "technical_details/JA4.md" in text
    assert "JA4H.md" in text, "the page names the second text file the inventory holds"


def test_the_inventory_holds_three_text_files_and_the_page_names_the_third() -> None:
    """The inventory decides which methods hold a live text specification."""
    rows = [
        line
        for line in INVENTORY.read_text(encoding="utf-8").splitlines()
        if line.startswith("| `") and line.rstrip().endswith("Text |")
    ]
    named = [re.findall(r"`([^`]+)`", row)[0] for row in rows]
    assert named == ["README.md", "JA4.md", "JA4H.md"], (
        "the inventory records the text files of the FoxIO material, and the page reports "
        f"the same set. It holds {named}"
    )


def test_the_page_records_the_two_sentinel_lines_of_the_text_specification() -> None:
    """#653 rests the JA4 half of the sentinel ruling on these two lines."""
    text = page_text()
    assert "technical_details/JA4.md:121" in text
    assert "technical_details/JA4.md:176" in text


def test_the_page_and_the_register_agree_on_the_sentinel_value() -> None:
    """Two records state one rule, so a reader who finds one finds the other.

    **A read of the whole page proves nothing here**, because the register names the
    sentinel for three methods. This case reads the rule section of the page instead.
    """
    rule = rule_section("R13")
    assert "000000000000" in rule
    for line in ("technical_details/JA4.md:121", "technical_details/JA4.md:176"):
        assert line in rule
    register = SPECIFICATION.read_text(encoding="utf-8")
    assert "000000000000" in register
    assert "technical_details/JA4.md" in register


def test_the_page_states_the_worked_example_the_text_specification_holds() -> None:
    """The example is the one value a reader can compare against another tool."""
    text = page_text()
    for value in SPECIFICATION_EXAMPLE.values():
        assert value in text


def test_the_vector_set_reproduces_the_worked_example_of_the_specification() -> None:
    """A transcribed example that no vector holds proves nothing about this project."""
    assert SPECIFICATION_EXAMPLE["JA4"] in vector_values("JA4")
    assert SPECIFICATION_EXAMPLE["JA4_o"] in vector_values("JA4_o")


def test_no_expected_output_file_holds_the_string_the_image_draws() -> None:
    """The image pairs the unsorted part b with the sorted part c, and no tool writes it.

    **A negative assertion over an empty corpus passes for the wrong reason**, so this case
    states the floor first. A read of 2026-08-15 returned 167 JA4 values.
    """
    hashed = vector_values("JA4")
    original = vector_values("JA4_o")
    assert len(hashed) > 100, f"the vector set holds {len(hashed)} JA4 values"
    assert len(original) > 100, f"the vector set holds {len(original)} JA4_o values"
    assert IMAGE_EXAMPLE not in hashed
    assert IMAGE_EXAMPLE not in original


def test_the_page_records_the_string_the_image_draws() -> None:
    """A reader who compares the image against a value needs this finding first."""
    assert IMAGE_EXAMPLE in page_text()


def test_the_transcription_table_of_the_inventory_names_the_page() -> None:
    """The inventory lists every transcription, so a reader reaches this one from it."""
    assert "`docs/specs/foxio/JA4.md`" in INVENTORY.read_text(encoding="utf-8")
