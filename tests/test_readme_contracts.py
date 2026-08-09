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

# The claim #62 removes. The project implements eleven of the twelve FoxIO methods, so
# a claim of full coverage is false whatever count it names.
COVERAGE_CLAIMS = ("all ten ja4+ methods", "all twelve ja4+ methods", "all ja4+ methods")


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


def test_the_readme_method_table_names_no_method_foxio_does_not_publish() -> None:
    """The README method table names no method outside the twelve FoxIO publishes."""
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
    """The README claims no coverage of every JA4+ method."""
    offenders = []
    text = _readme().lower()
    for claim in COVERAGE_CLAIMS:
        if claim in text:
            offenders.append(claim)
    assert offenders == [], f"the README still claims {offenders}"


def test_the_readme_import_block_names_every_exported_fingerprinter() -> None:
    """The README `All Fingerprinters` block names each fingerprinter `__all__` holds."""
    exported = {name for name in PUBLIC_NAMES if name.endswith("Fingerprinter")}
    text = _readme()
    start = text.index("### All Fingerprinters")
    block = text[start : text.index("```", text.index("```python", start) + 1)]
    named = {name for name in exported if name in block}
    assert named == exported, f"the block names no import for {sorted(exported - named)}"


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


def test_the_readme_names_foxio_as_the_owner_of_the_standard() -> None:
    """The README states that FoxIO owns the JA4+ standard."""
    assert "FoxIO owns the JA4+ standard" in _readme(), (
        "the README names no owner of the JA4+ standard"
    )


def test_the_readme_names_this_project_an_independent_implementation() -> None:
    """The README states that this project is an independent implementation."""
    assert "independent implementation" in _readme(), (
        "the README does not call this project an independent implementation"
    )
