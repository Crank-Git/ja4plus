"""Tests that the README states the method coverage and the two contracts correctly.

#62 carries four requirements of `docs/specs/features/08-documentation.md`.

- FR-documentation-1 — The README states which FoxIO methods the project implements
  and which it does not.
- FR-documentation-2 — The README states the concurrency contract.
- FR-documentation-3 — The README states the memory bounds and their defaults.
- FR-documentation-14 — The documentation states that FoxIO owns the JA4+ standard
  and that this project is an independent implementation.

**A README claim goes stale the moment the code moves, and a reader catches nothing.**
Each case here therefore reads the number out of the code and compares the README
against it. A case that restated the number would pass on a README that contradicts
`ja4plus/`.

These cases read prose. They produce no fingerprint and they open no capture socket.
"""

import re
from pathlib import Path

import pytest

from ja4plus import __all__ as PUBLIC_NAMES
from ja4plus.utils.state_table import DEFAULT_MAX_CONNECTION_AGE, DEFAULT_MAX_CONNECTIONS
from ja4plus.watch import DEFAULT_CONNECTION_TIMEOUT
from ja4plus.watch import DEFAULT_MAX_CONNECTIONS as MONITOR_MAX_CONNECTIONS

from tests.test_documentation_image_count import FOXIO_METHODS
from tests.test_memory_bounds import MEMORY_CEILING_MIB

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"

# The heading of the method table. FR-documentation-1 rests on this one table.
METHOD_HEADING = "## Methods"

# The heading of the table that states the default of each bound.
BOUNDS_HEADING = "#### The default bounds"

# The heading of the paragraph that states whether threads may share one processor.
CONCURRENCY_HEADING = "#### The concurrency contract"

# The one method FoxIO publishes that this project declines. `docs/specs/spec.md`
# § Non-goals holds the decision and #197 holds the reading.
DECLINED_METHOD = "JA4TScan"

# The claim #62 removes. The project implements eleven of the twelve FoxIO methods, so a
# claim of full coverage is false whatever count it names and whatever words it uses.
# **A fixed list of three phrasings passes on the fourth phrasing**, and the first form of
# this case held such a list, so these patterns match the shape of the claim instead.
COVERAGE_CLAIMS = (
    re.compile(r"\ball\s+(?:\w+\s+){0,2}ja4\+?\s+methods\b", re.IGNORECASE),
    re.compile(r"\bevery\s+(?:\w+\s+){0,2}ja4\+?\s+method\b", re.IGNORECASE),
    re.compile(r"\bfull\s+(?:method\s+)?coverage\b", re.IGNORECASE),
    re.compile(r"\bimplements\s+all\b", re.IGNORECASE),
)

# The count word the README writes for each count of implemented methods. A case compares
# the word the prose states against the rows the table marks, so the two cannot drift.
COUNT_WORDS = {
    9: "nine",
    10: "ten",
    11: "eleven",
    12: "twelve",
}

# The one sentence that answers FR-documentation-14 for a reader of the first screen. A
# substring search over the whole page passes on a footnote, and #62 needs the claim where
# a reader meets the project.
OWNER_SENTENCE = "FoxIO owns the JA4+ standard"
INDEPENDENCE_SENTENCE = "This library is an independent implementation of that standard."

# The lines of the README that a reader sees before the first heading.
INTRODUCTION_LINES = 20

# The heading of the section that states the license of this project and of each method.
LICENSE_HEADING = "## License"

# The name of the license FoxIO applies to every method but one. The reader finds the
# paragraph by this name, so a rewording of the surrounding prose defeats no case here.
LICENSE_NAME = "FoxIO License 1.1"

# The one method FoxIO publishes under BSD-3-Clause. The license list of the README names
# the methods that carry `LICENSE_NAME`, so it names every other implemented method and
# not this one.
BSD_METHOD = "JA4"

# The FoxIO document that names each method the FoxIO License 1.1 covers, and the commit
# this project reads it at. `docs/specs/foxio/README.md` pins the same commit.
LICENSE_SOURCE = "License%20FAQ.md"
LICENSE_SOURCE_COMMIT = "27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8"

# One JA4+ method name. **The trailing boundary is what stops `JA4L` from matching inside
# `JA4LS`**, so a reader that searched for each name as a substring would report `JA4L` on a
# paragraph that names `JA4LS` alone.
METHOD_NAME = re.compile(r"\bJA4[A-Za-z0-9]*\b")

# The characters Markdown emphasis writes around a name. **An underscore is a word
# character, so `__JA4S__` hides `JA4S` from the boundary of `METHOD_NAME`.** The first form
# of this reader lost `JA4S` for that reason, so the reader removes these first.
EMPHASIS = "_*"

# One imported fingerprinter of the `All Fingerprinters` block. The name must open a line
# of the import statement, because a name inside a comment imports nothing.
IMPORTED_FINGERPRINTER = re.compile(r"^\s+(JA4\w*Fingerprinter)\s*,", re.MULTILINE)


def _readme() -> str:
    """Return the whole README.

    Returns:
        The text of `README.md`.
    """
    return README.read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    """Return the body of one Markdown section, up to the next heading of any level.

    Args:
        text: The whole page.
        heading: The heading line, including its `#` characters.

    Returns:
        The text after the heading and before the next line that starts with `#`.

    Raises:
        AssertionError: The page holds no line equal to the heading, or more than one.
    """
    page = text.splitlines()
    starts = [number for number, line in enumerate(page) if line.strip() == heading]
    assert starts, f"the README holds no {heading!r} heading"
    assert len(starts) == 1, f"the README holds {len(starts)} {heading!r} headings"
    lines: list[str] = []
    for line in page[starts[0] + 1 :]:
        if line.startswith("#"):
            break
        lines.append(line)
    return "\n".join(lines)


def _table_rows(section: str) -> list[list[str]]:
    """Return the data rows of the first Markdown table of one section.

    A section holds more than one table, so a reader of every row of the section reads
    a row of the wrong table.

    Args:
        section: The body of one section.

    Returns:
        One list of stripped cells for each data row. The header row and the alignment
        row are absent.

    Raises:
        AssertionError: The section holds no table.
    """
    lines: list[str] = []
    for line in section.splitlines():
        if line.startswith("|"):
            lines.append(line)
        elif lines:
            break
    assert lines, "the section holds no table"
    rows = [[cell.strip() for cell in line.strip("|").split("|")] for line in lines]
    # Row 0 is the header and row 1 is the alignment row that Markdown requires.
    return rows[2:]


def _method_rows() -> dict[str, list[str]]:
    """Return one row of the README method table for each method name.

    Returns:
        The cells of each data row, keyed by the method name of its first cell.
    """
    rows = _table_rows(_section(_readme(), METHOD_HEADING))
    return {row[0].strip("`"): row for row in rows}


def _implemented_cell(row: list[str]) -> str:
    """Return the `Implemented` cell of one row of the method table.

    Args:
        row: The cells of one data row.

    Returns:
        The text of the last cell.
    """
    return row[-1]


def _bounds() -> dict[str, str]:
    """Return the default of each bound the README states.

    Returns:
        The stated default, keyed by the name of the bound.
    """
    rows = _table_rows(_section(_readme(), BOUNDS_HEADING))
    return {row[0]: row[1] for row in rows}


@pytest.mark.parametrize("method", FOXIO_METHODS)
def test_the_readme_method_table_names_every_foxio_method(method: str) -> None:
    """The README method table holds one row for each of the twelve FoxIO methods."""
    assert method in _method_rows(), f"the method table holds no row for {method}"


def test_the_readme_method_table_names_only_methods_foxio_publishes() -> None:
    """The README method table names the twelve FoxIO methods and no other name."""
    extra = sorted(set(_method_rows()) - set(FOXIO_METHODS))
    assert extra == [], f"the method table names {extra}, which FoxIO does not publish"


def test_the_readme_method_table_marks_ja4tscan_as_not_implemented() -> None:
    """The README marks JA4TScan as the one FoxIO method this project does not build."""
    row = _method_rows()[DECLINED_METHOD]
    assert _implemented_cell(row) == "No", (
        f"the {DECLINED_METHOD} row states {_implemented_cell(row)!r}, and it must state 'No'"
    )


@pytest.mark.parametrize("method", [name for name in FOXIO_METHODS if name != DECLINED_METHOD])
def test_the_readme_method_table_marks_every_other_method_implemented(method: str) -> None:
    """The README marks the eleven methods this project builds as implemented."""
    row = _method_rows()[method]
    assert _implemented_cell(row) == "Yes", (
        f"the {method} row states {_implemented_cell(row)!r}, and it must state 'Yes'"
    )


def test_the_readme_claims_no_full_foxio_method_coverage() -> None:
    """The README claims coverage of no complete set of JA4+ methods."""
    offenders = []
    for pattern in COVERAGE_CLAIMS:
        offenders += [match.group(0) for match in pattern.finditer(_readme())]
    assert offenders == [], f"the README still claims {offenders}"


def test_the_readme_states_the_count_of_methods_its_own_table_marks() -> None:
    """The README prose states the count of methods its method table marks `Yes`."""
    implemented = [row for row in _method_rows().values() if _implemented_cell(row) == "Yes"]
    word = COUNT_WORDS[len(implemented)]
    assert f"implements {word} of them" in _readme(), (
        f"the table marks {len(implemented)} methods implemented, and the prose "
        f"states no 'implements {word} of them'"
    )


def test_the_readme_states_the_count_of_methods_foxio_publishes() -> None:
    """The README prose states the count of methods the FoxIO tuple holds."""
    word = COUNT_WORDS[len(FOXIO_METHODS)]
    assert f"FoxIO publishes {word} JA4+ methods" in _readme(), (
        f"FoxIO publishes {len(FOXIO_METHODS)} methods, and the prose states another count"
    )


def test_the_readme_import_block_imports_every_exported_fingerprinter() -> None:
    """The README `All Fingerprinters` block imports each fingerprinter `__all__` holds."""
    exported = {name for name in PUBLIC_NAMES if name.endswith("Fingerprinter")}
    text = _readme()
    start = text.index("### All Fingerprinters")
    opening = text.index("```python", start)
    block = text[opening : text.index("```", opening + 1)]
    # A name inside a comment imports nothing, so read the import lines and not the block.
    imported = set(IMPORTED_FINGERPRINTER.findall(block))
    assert imported == exported, (
        f"the block imports no {sorted(exported - imported)} and imports an unexported "
        f"{sorted(imported - exported)}"
    )


def test_the_readme_states_the_default_maximum_entry_count_of_a_state_table() -> None:
    """The README states the maximum entry count `ja4plus/utils/state_table.py` sets."""
    stated = _bounds()["The maximum entry count of one state table"]
    assert stated == f"{DEFAULT_MAX_CONNECTIONS} entries", (
        f"the README states {stated!r} against a default of {DEFAULT_MAX_CONNECTIONS}"
    )


def test_the_readme_states_the_default_maximum_age_of_a_state_table() -> None:
    """The README states the maximum age `ja4plus/utils/state_table.py` sets."""
    stated = _bounds()["The maximum age of one entry of a state table"]
    assert stated == f"{DEFAULT_MAX_CONNECTION_AGE} seconds", (
        f"the README states {stated!r} against a default of {DEFAULT_MAX_CONNECTION_AGE}"
    )


def test_the_readme_states_the_default_maximum_connection_count_of_the_monitor() -> None:
    """The README states the connection count `ja4plus/watch.py` sets."""
    stated = _bounds()["The maximum count of connections the monitor holds"]
    assert stated == f"{MONITOR_MAX_CONNECTIONS} connections", (
        f"the README states {stated!r} against a default of {MONITOR_MAX_CONNECTIONS}"
    )


def test_the_readme_states_the_default_maximum_connection_age_of_the_monitor() -> None:
    """The README states the connection age `ja4plus/watch.py` sets."""
    stated = _bounds()["The maximum age of one connection of the monitor"]
    assert stated == f"{int(DEFAULT_CONNECTION_TIMEOUT)} seconds", (
        f"the README states {stated!r} against a default of {DEFAULT_CONNECTION_TIMEOUT}"
    )


def test_the_readme_states_the_memory_ceiling_the_suite_measures_against() -> None:
    """The README states the ceiling `tests/test_memory_bounds.py` measures against."""
    assert f"**{int(MEMORY_CEILING_MIB)} MiB**" in _readme(), (
        f"the README states no ceiling of {int(MEMORY_CEILING_MIB)} MiB"
    )


def test_the_readme_states_whether_threads_may_share_one_processor() -> None:
    """The README concurrency paragraph states that threads may share one processor."""
    paragraph = _section(_readme(), CONCURRENCY_HEADING)
    assert "Several threads may share one `Processor()`" in paragraph, (
        "the concurrency contract states no answer for a shared processor"
    )


def _introduction() -> str:
    """Return the first lines of the README, with each run of whitespace as one space.

    The page wraps at 90 columns, so a sentence spans two lines and a search for it fails
    against the raw text.

    Returns:
        The text a reader meets before the badges and the first heading.
    """
    head = "\n".join(_readme().splitlines()[:INTRODUCTION_LINES])
    return " ".join(head.split())


def test_the_readme_names_foxio_as_the_owner_of_the_standard() -> None:
    """The README introduction states that FoxIO owns the JA4+ standard."""
    assert OWNER_SENTENCE in _introduction(), (
        f"the first {INTRODUCTION_LINES} lines name no owner of the JA4+ standard"
    )


def test_the_readme_names_this_project_an_independent_implementation() -> None:
    """The README introduction states that this project is an independent implementation."""
    assert INDEPENDENCE_SENTENCE in _introduction(), (
        f"the first {INTRODUCTION_LINES} lines hold no {INDEPENDENCE_SENTENCE!r}"
    )


def _license_paragraph() -> str:
    """Return the paragraph of the README that names the FoxIO License 1.1.

    The reader normalizes the whitespace, so it finds a sentence whether the paragraph
    occupies one line or wraps over several.

    Returns:
        The paragraph, with each run of whitespace written as one space.

    Raises:
        AssertionError: The license section holds no paragraph that names the license, or
            it holds more than one.
    """
    section = _section(_readme(), LICENSE_HEADING)
    found = [block for block in section.split("\n\n") if LICENSE_NAME in block]
    assert found, f"the {LICENSE_HEADING!r} section holds no paragraph that names {LICENSE_NAME}"
    assert len(found) == 1, (
        f"the {LICENSE_HEADING!r} section holds {len(found)} paragraphs that name "
        f"{LICENSE_NAME}, and a reader cannot tell which one states the list"
    )
    return " ".join(found[0].split())


def _licensed_methods() -> set[str]:
    """Return the methods the README license paragraph names under the FoxIO License 1.1.

    The reader parses the names out of the paragraph. **A reader that searched for each
    expected name instead would report a name the paragraph never holds**, because `JA4L`
    is a substring of `JA4LS`.

    Returns:
        Every method name of the paragraph, without the BSD-3-Clause method.
    """
    plain = _license_paragraph()
    for character in EMPHASIS:
        plain = plain.replace(character, " ")
    return {name for name in METHOD_NAME.findall(plain) if name != BSD_METHOD}


def _methods_under_the_foxio_license() -> set[str]:
    """Return the implemented methods that FoxIO does not publish under BSD-3-Clause.

    The count of these methods is not the count of methods this project implements. The
    implemented set holds `BSD_METHOD` as well, and
    `tests/test_documented_method_count.py` measures that larger set against `ja4plus/`.

    Returns:
        The methods the README method table marks implemented, without `BSD_METHOD`.

    Raises:
        AssertionError: The method table marks no method implemented.
    """
    implemented = {
        method for method, row in _method_rows().items() if _implemented_cell(row) == "Yes"
    }
    expected = implemented - {BSD_METHOD}
    # **An aggregate over an empty set passes.** A table that marked nothing implemented
    # would make the set case agree with a paragraph that names nothing, so the floor
    # states that the comparison read something.
    assert expected, "the README method table marks no method implemented beside JA4"
    return expected


def test_the_readme_license_paragraph_names_every_method_the_foxio_license_covers() -> None:
    """The README license list names each implemented method that carries FoxIO License 1.1."""
    expected = _methods_under_the_foxio_license()
    named = _licensed_methods()
    assert named == expected, (
        f"the license paragraph names no {sorted(expected - named)} and names "
        f"{sorted(named - expected)}, which the method table does not mark implemented"
    )


def test_the_readme_license_paragraph_cites_the_foxio_document_it_follows() -> None:
    """The README license list cites the FoxIO document and the commit this project read."""
    paragraph = _license_paragraph()
    assert LICENSE_SOURCE in paragraph, (
        f"the license paragraph cites no {LICENSE_SOURCE}, so a reader cannot check the list"
    )
    assert LICENSE_SOURCE_COMMIT in paragraph, (
        f"the license paragraph names no commit {LICENSE_SOURCE_COMMIT}"
    )
