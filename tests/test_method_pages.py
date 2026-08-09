"""Tests that the method pages of the documentation site agree with the code.

#65 carries three requirements of `docs/specs/features/08-documentation.md`.

- FR-documentation-10 — The documentation site carries a page per method.
- FR-documentation-11 — The documentation site carries the output schema.
- FR-documentation-12 — The documentation site carries a migration page for the move
  from version 0.6.0 to version 1.0.0.

**A method page states an output format, a field list and a hash rule, and every one of
the three goes stale the moment the code moves.** Each case here therefore reads the
value out of `ja4plus/` and compares the page against it. A case that restated the value
would pass on a page that contradicts the package.

`tests/test_readme_contracts.py` holds the same shape for `README.md`, and #62 landed it.

**The example table of each page is the strongest case of the file.** It names a capture
and a value, and `test_the_example_of_each_method_page_comes_from_the_capture_it_names`
reads the capture, runs the processor and compares. A wrong digit in a page fails it.

These cases read prose and committed captures. They open no capture socket and they
reach no network.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path
from typing import Any

import pytest

import ja4plus
from ja4plus import __all__ as PUBLIC_NAMES
from ja4plus.cli import VALID_TYPES

from tests.test_documentation_image_count import FOXIO_METHODS

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
METHODS_DIR = DOCS_DIR / "methods"
CONFIGURATION = REPO_ROOT / "mkdocs.yml"
FOXIO_INVENTORY = DOCS_DIR / "specs" / "foxio" / "README.md"
SCHEMA_PAGE = DOCS_DIR / "output-schema.md"
MIGRATION_PAGE = DOCS_DIR / "migration-0.6-to-1.0.md"

# The one FoxIO method this project declines. `docs/specs/spec.md` § Non-goals holds the
# decision and #197 holds the reading. It reaches no method page, and
# `docs/methods/index.md` states the decline.
DECLINED_METHOD = "JA4TScan"

# The eleven methods a page describes. Ten fingerprinter classes carry them, because
# `JA4LFingerprinter` writes both `JA4L-C=` and `JA4L-S=`. #387 records the counting
# error that reads the ten classes as ten methods.
IMPLEMENTED_METHODS = tuple(name for name in FOXIO_METHODS if name != DECLINED_METHOD)

# Nine cases parametrize over the tuple above, and pytest reads it at collection time. A
# tuple that shrank would collect fewer cases rather than fail one, which reads as a green
# run. This check runs at import and it names the shrink.
assert len(IMPLEMENTED_METHODS) == 11, (
    f"the case file parametrizes over {len(IMPLEMENTED_METHODS)} methods, and this "
    f"project implements eleven"
)
assert DECLINED_METHOD in FOXIO_METHODS, (
    f"{DECLINED_METHOD} left FOXIO_METHODS, so the tuple above declines nothing"
)

# The heading of the table that holds the machine-read facts of one page.
FACTS_HEADING = "## The facts"

# The heading of the table that names one capture and the value it produces.
EXAMPLE_HEADING = "## An example"

# The header row each table carries. `_table_rows` reads the first table of a section, so
# a stray table above the intended one would be read instead. The header names which
# table the caller means, and `_table_rows` refuses any other.
FACTS_HEADER = ["Item", "Value"]
EXAMPLE_HEADER = ["Capture", "Value"]
INDEX_HEADER = ["Method", "Protocol", "Page", "Implemented"]
RAW_FORMS_HEADER = ["Method", "`raw`", "`raw_original_order`"]
MIGRATION_HEADER = [
    "Change",
    "The version 0.6.0 form",
    "The version 1.0.0 form",
    "Why",
    "Record",
]

# The two values the `raw` rows accept. A page states one of them, and a case compares it
# against what the fingerprinter writes into the field.
RAW_PRESENT = "A value"
RAW_ABSENT = "Always `null`"

# The value the hash rows accept for a method that hashes no part.
NO_HASH = "None. The method hashes no part."

# The hash rule of a method that hashes a part. The count comes out of the module.
HASH_RULE = "SHA-256, truncated to {} characters"

# The truncation the module applies, as `hexdigest()[:12]`. A module that hashes a part of
# its fingerprint holds one or more of these, and every one of them holds the same count.
HEXDIGEST_TRUNCATION = re.compile(r"hexdigest\(\)\[:(\d+)\]")

# A row of the inventory table of `docs/specs/foxio/README.md`, as
# `| `JA4.md` | 9153 | ... |`. The inventory names the twelve files of
# `technical_details/` at the pinned commit.
INVENTORY_FILE = re.compile(r"^\|\s*`([A-Za-z0-9_.]+)`\s*\|\s*\d+\s*\|", re.MULTILINE)

# The floor that guards the parser. A parser that reads no page passes every case on an
# empty list, and the project has met that defect. #64 records the same floor for the
# link checker.
MINIMUM_PAGES = 11

# The count of breaking changes the record held when #65 landed. It grows and it never
# falls, because a released breaking change stays breaking.
MINIMUM_BREAKING_CHANGES = 11


def _page(method: str) -> Path:
    """Return the documentation page of one method.

    Args:
        method: The FoxIO method name, as `JA4LS`.

    Returns:
        The path of the page, whether or not the file exists.
    """
    return METHODS_DIR / f"{method.lower()}.md"


def _section(text: str, heading: str) -> str:
    """Return the body of one Markdown section, up to the next heading of any level.

    A paragraph quotes a heading, so a search of the whole page reaches the quotation
    first and returns the wrong body. This function matches the heading as a whole line.

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
    assert starts, f"the page holds no {heading!r} heading"
    assert len(starts) == 1, f"the page holds {len(starts)} {heading!r} headings"
    lines: list[str] = []
    for line in page[starts[0] + 1 :]:
        if line.startswith("#"):
            break
        lines.append(line)
    return "\n".join(lines)


def _table_rows(section: str, header: list[str]) -> list[list[str]]:
    """Return the data rows of the first Markdown table of one section.

    **This function reads the first table of the section and never the intended one.**
    A stray table placed above it would be read instead, with no diagnostic, so every
    caller states the header it expects and this function compares it.

    Args:
        section: The body of one section.
        header: The cells of the header row the caller expects.

    Returns:
        One list of stripped cells for each data row. The header row and the alignment
        row are absent.

    Raises:
        AssertionError: The section holds no table, or the table carries another header.
    """
    lines: list[str] = []
    for line in section.splitlines():
        if line.startswith("|"):
            lines.append(line)
        elif lines:
            break
    assert lines, "the section holds no table"
    rows = [[cell.strip() for cell in line.strip("|").split("|")] for line in lines]
    assert rows[0] == header, f"the first table of the section carries the header {rows[0]}"
    # Row 0 names the columns and row 1 is the alignment row that Markdown requires.
    return rows[2:]


def _facts(method: str) -> dict[str, str]:
    """Return the fact table of one method page, keyed by the `Item` cell.

    Args:
        method: The FoxIO method name.

    Returns:
        The `Value` cell of each row, keyed by the `Item` cell.

    Raises:
        AssertionError: The page does not exist, or it holds no fact table.
    """
    page = _page(method)
    assert page.is_file(), f"{page.relative_to(REPO_ROOT)} does not exist"
    rows = _table_rows(_section(page.read_text(encoding="utf-8"), FACTS_HEADING), FACTS_HEADER)
    return {row[0]: row[1] for row in rows}


def _fact_cell(method: str, item: str) -> str:
    """Return one fact of one method page, exactly as the cell writes it.

    Args:
        method: The FoxIO method name.
        item: The text of the `Item` cell.

    Returns:
        The `Value` cell, with every backtick it holds.

    Raises:
        AssertionError: The fact table holds no such row.
    """
    facts = _facts(method)
    assert item in facts, f"{_page(method).name} states no {item!r} row, and holds {sorted(facts)}"
    return facts[item]


def _fact(method: str, item: str) -> str:
    """Return one fact of one method page, without its backticks.

    Args:
        method: The FoxIO method name.
        item: The text of the `Item` cell.

    Returns:
        The `Value` cell, stripped of the backticks that mark code.

    Raises:
        AssertionError: The fact table holds no such row.
    """
    return _fact_cell(method, item).strip("`")


def _examples(method: str) -> list[tuple[str, str]]:
    """Return the capture and the value of each row of the example table.

    Args:
        method: The FoxIO method name.

    Returns:
        One pair for each row: the repository-relative capture path, and the value.

    Raises:
        AssertionError: The page holds no example table.
    """
    text = _page(method).read_text(encoding="utf-8")
    rows = _table_rows(_section(text, EXAMPLE_HEADING), EXAMPLE_HEADER)
    return [(row[0].strip("`"), row[1].strip("`")) for row in rows]


def _module_of(method: str) -> Any:
    """Return the module that holds the fingerprinter of one method.

    Args:
        method: The FoxIO method name.

    Returns:
        The imported module the page's fingerprinter class comes from.
    """
    fingerprinter = getattr(ja4plus, _fact(method, "The fingerprinter class"))
    return importlib.import_module(fingerprinter.__module__)


def _inventory_files() -> set[str]:
    """Return the file names the FoxIO inventory records.

    `docs/specs/foxio/README.md` holds the inventory of `technical_details/` at the
    pinned commit, with a SHA-256 for each file.

    Returns:
        The twelve file names of the inventory table.

    Raises:
        AssertionError: The inventory holds fewer rows than the pinned commit carries.
    """
    names = set(INVENTORY_FILE.findall(FOXIO_INVENTORY.read_text(encoding="utf-8")))
    assert len(names) >= 12, f"the inventory names {sorted(names)}, and the floor is twelve"
    return names


def _run(capture: str) -> list[Any]:
    """Return every record one committed capture produces.

    Args:
        capture: The repository-relative path of the capture.

    Returns:
        Every `FingerprintResult` of `process_packet`, then every record of
        `close_open_windows`. The second call returns a dict and not a result, so a
        reader of the list checks the shape.

    Raises:
        AssertionError: The capture produces no fingerprint.
    """
    from scapy.utils import rdpcap

    from ja4plus import Processor

    processor = Processor()
    produced: list[Any] = []
    for packet in rdpcap(str(REPO_ROOT / capture)):
        produced += processor.process_packet(packet)
    produced += list(processor.close_open_windows())
    assert produced, f"{capture} produced no fingerprint"
    return produced


def _pairs(capture: str) -> list[tuple[str, str]]:
    """Return the method and the fingerprint of every record one capture produces.

    Args:
        capture: The repository-relative path of the capture.

    Returns:
        One pair for each record: the `type` value and the fingerprint string.
    """
    return [
        (
            record["type"] if isinstance(record, dict) else record.type,
            record["fingerprint"] if isinstance(record, dict) else record.fingerprint,
        )
        for record in _cached_run(capture)
    ]


def _result_for(capture: str, value: str) -> Any:
    """Return the typed result one capture produced for one fingerprint.

    A dict of `close_open_windows` carries no raw field, so this function reads a
    `FingerprintResult` alone.

    Args:
        capture: The repository-relative path of the capture.
        value: The fingerprint string the page states.

    Returns:
        The first `FingerprintResult` whose fingerprint equals the value.

    Raises:
        AssertionError: The capture produced no such result.
    """
    matches = [
        record
        for record in _cached_run(capture)
        if not isinstance(record, dict) and record.fingerprint == value
    ]
    assert matches, f"{capture} produced no result whose fingerprint is {value!r}"
    return matches[0]


_RUNS: dict[str, list[Any]] = {}


def _cached_run(capture: str) -> list[Any]:
    """Return the fingerprints of one capture, and read each capture once.

    Args:
        capture: The repository-relative path of the capture.

    Returns:
        The pairs `_run` produced for that capture.
    """
    if capture not in _RUNS:
        _RUNS[capture] = _run(capture)
    return _RUNS[capture]


def test_the_documentation_holds_one_page_for_each_implemented_method() -> None:
    """`FR-documentation-10`. `docs/methods/` holds one page per implemented method."""
    assert METHODS_DIR.is_dir(), "docs/methods/ does not exist"
    pages = {path.stem for path in METHODS_DIR.glob("*.md")} - {"index"}
    wanted = {method.lower() for method in IMPLEMENTED_METHODS}
    assert len(wanted) >= MINIMUM_PAGES, f"the case reads {len(wanted)} methods"
    assert pages == wanted, (
        f"docs/methods/ holds no page for {sorted(wanted - pages)} and holds an "
        f"unexpected {sorted(pages - wanted)}"
    )


def test_the_documentation_holds_no_page_for_the_declined_method() -> None:
    """The site serves no method page for JA4TScan, which this project does not build."""
    assert not _page(DECLINED_METHOD).exists(), (
        f"{_page(DECLINED_METHOD).name} exists, and this project builds no {DECLINED_METHOD}"
    )


@pytest.mark.parametrize("method", IMPLEMENTED_METHODS)
def test_the_navigation_names_the_page_of_each_method(method: str) -> None:
    """A page outside the `nav` of `mkdocs.yml` is a page no reader reaches."""
    entry = f"methods/{method.lower()}.md"
    assert entry in CONFIGURATION.read_text(encoding="utf-8"), (
        f"the nav of mkdocs.yml names no {entry}"
    )


@pytest.mark.parametrize("method", IMPLEMENTED_METHODS)
def test_each_method_page_names_a_types_token_the_command_accepts(method: str) -> None:
    """The `--types` token of each page is one `ja4plus/cli.py` accepts."""
    token = _fact(method, "The `--types` token")
    assert token in VALID_TYPES, (
        f"{method} states the token {token!r}, and VALID_TYPES holds it not"
    )


@pytest.mark.parametrize("token", VALID_TYPES)
def test_each_types_token_reaches_a_method_page(token: str) -> None:
    """Every token `ja4plus/cli.py` accepts is described by a page.

    `ja4l` reaches two pages, because `JA4LFingerprinter` writes two methods.
    """
    claimed = {
        method for method in IMPLEMENTED_METHODS if _fact(method, "The `--types` token") == token
    }
    assert claimed, f"no method page describes the token {token!r}"


@pytest.mark.parametrize("method", IMPLEMENTED_METHODS)
def test_each_method_page_names_a_fingerprinter_the_package_exports(method: str) -> None:
    """The class each page names is in `ja4plus.__all__`, so a reader may import it."""
    name = _fact(method, "The fingerprinter class")
    assert name in PUBLIC_NAMES, f"{method} names {name!r}, and `__all__` holds it not"
    assert hasattr(ja4plus, name), f"`ja4plus` holds no attribute {name!r}"


@pytest.mark.parametrize("method", IMPLEMENTED_METHODS)
def test_each_method_page_names_a_one_shot_function_the_package_exports(method: str) -> None:
    """The one-shot function each page names is in `ja4plus.__all__` and it is callable."""
    name = _fact(method, "The one-shot function")
    assert name in PUBLIC_NAMES, f"{method} names {name!r}, and `__all__` holds it not"
    assert callable(getattr(ja4plus, name)), f"`ja4plus.{name}` is not callable"


@pytest.mark.parametrize("method", IMPLEMENTED_METHODS)
def test_each_method_page_states_the_hash_rule_its_module_holds(method: str) -> None:
    """The hash rule of each page is the truncation its own module applies.

    A module that hashes a part of its fingerprint writes `hexdigest()[:12]`. This case
    reads that count out of the source, so a change from 12 to any other count fails
    here rather than reaching a reader.
    """
    source = Path(_module_of(method).__file__).read_text(encoding="utf-8")
    counts = {int(found) for found in HEXDIGEST_TRUNCATION.findall(source)}
    assert len(counts) <= 1, f"{method} hashes with {sorted(counts)} different truncations"
    expected = HASH_RULE.format(counts.pop()) if counts else NO_HASH
    assert _fact(method, "The hash rule") == expected, (
        f"{method} states {_fact(method, 'The hash rule')!r} against the module's {expected!r}"
    )


@pytest.mark.parametrize("method", IMPLEMENTED_METHODS)
def test_each_method_page_cites_a_foxio_file_the_inventory_records(method: str) -> None:
    """Every method page cites its FoxIO source, and the inventory holds that file.

    `docs/specs/foxio/README.md` records the twelve files of `technical_details/` at the
    pinned commit, with a byte count and a SHA-256 for each one.
    """
    inventory = _inventory_files()
    cited = [name.strip().strip("`") for name in _fact(method, "The FoxIO source").split(",")]
    unknown = [name for name in cited if Path(name).name not in inventory]
    assert cited, f"{method} cites no FoxIO source"
    assert unknown == [], f"{method} cites {unknown}, and the FoxIO inventory records none of them"


@pytest.mark.parametrize("method", IMPLEMENTED_METHODS)
def test_each_method_page_states_the_raw_fields_the_method_writes(method: str) -> None:
    """The two raw rows of each page agree with the fields the method fills.

    `docs/output-schema.md` states the same two facts for the output line, and
    `test_the_raw_forms_table_of_the_schema_page_states_what_the_writer_writes` reads
    that page against the same result.
    """
    capture, value = _examples(method)[0]
    result = _result_for(capture, value)
    for field, item in (
        ("raw", "The `raw` field"),
        ("raw_original_order", "The `raw_original_order` field"),
    ):
        written = getattr(result, field) is not None
        stated = _fact_cell(method, item)
        expected = RAW_PRESENT if written else RAW_ABSENT
        assert stated == expected, (
            f"{method} states {stated!r} for `{field}`, and the result carries "
            f"{getattr(result, field)!r}"
        )


@pytest.mark.parametrize("method", IMPLEMENTED_METHODS)
def test_the_example_of_each_method_page_comes_from_the_capture_it_names(method: str) -> None:
    """Every example value of a method page is one its named capture produces.

    **This case is the one that catches a wrong digit.** It reads the capture, runs the
    processor and compares the value, so no example on a page is a value a person typed.
    """
    examples = _examples(method)
    assert examples, f"{method} holds no example"
    token = _fact(method, "The `--types` token")
    for capture, value in examples:
        produced = {
            fingerprint
            for fingerprint_type, fingerprint in _pairs(capture)
            if fingerprint_type == token
        }
        # A capture that emits nothing for the token would make the comparison below
        # vacuous, so this case names that state rather than pass through it.
        assert produced, f"{capture} emitted no {token} fingerprint"
        assert value in produced, (
            f"{method} states the example {value!r}, and {capture} produced {sorted(produced)}"
        )


def test_the_index_of_the_methods_states_the_decline_of_the_one_method_not_built() -> None:
    """`docs/methods/index.md` records the JA4TScan decline, so a reader finds the reason."""
    index = METHODS_DIR / "index.md"
    assert index.is_file(), "docs/methods/index.md does not exist"
    text = index.read_text(encoding="utf-8")
    assert DECLINED_METHOD in text, f"the index names no {DECLINED_METHOD}"
    assert "#197" in text, "the index cites no issue for the decline"


@pytest.mark.parametrize("method", FOXIO_METHODS)
def test_the_index_of_the_methods_names_every_foxio_method(method: str) -> None:
    """The index table holds one row for each of the twelve methods FoxIO publishes."""
    rows = _table_rows(
        _section((METHODS_DIR / "index.md").read_text(encoding="utf-8"), "## The methods"),
        INDEX_HEADER,
    )
    names = {row[0].strip("`") for row in rows}
    assert method in names, f"the index table holds no row for {method}, and holds {sorted(names)}"


def test_the_index_of_the_methods_links_the_page_of_every_implemented_method() -> None:
    """Each row of the index table links the page of the method it names."""
    text = (METHODS_DIR / "index.md").read_text(encoding="utf-8")
    missing = [method for method in IMPLEMENTED_METHODS if f"({method.lower()}.md)" not in text]
    assert missing == [], f"the index links no page for {missing}"


def test_the_site_serves_the_output_schema_page() -> None:
    """`FR-documentation-11`. The schema page exists and the nav names it."""
    assert SCHEMA_PAGE.is_file(), "docs/output-schema.md does not exist"
    assert "output-schema.md" in CONFIGURATION.read_text(encoding="utf-8"), (
        "the nav of mkdocs.yml names no output-schema.md"
    )


@pytest.mark.parametrize("method", IMPLEMENTED_METHODS)
def test_the_output_schema_page_links_the_page_of_every_method(method: str) -> None:
    """The schema page reaches the page that describes the method of each output line."""
    text = SCHEMA_PAGE.read_text(encoding="utf-8")
    assert f"methods/{method.lower()}.md" in text, (
        f"docs/output-schema.md links no page for {method}"
    )


@pytest.mark.parametrize("token", VALID_TYPES)
def test_the_raw_forms_table_of_the_schema_page_states_what_the_writer_writes(token: str) -> None:
    """The `## The raw forms` table of the schema page agrees with the output.

    The table was prose that no case read. It states, for each of the ten output types,
    whether the line carries a `raw` value and a `raw_original_order` value. This case
    runs the captures the method pages name and compares.
    """
    rows = _table_rows(
        _section(SCHEMA_PAGE.read_text(encoding="utf-8"), "## The raw forms"), RAW_FORMS_HEADER
    )
    stated: dict[str, tuple[str, str]] = {}
    for row in rows:
        for name in row[0].split(","):
            stated[name.strip().strip("`")] = (row[1], row[2])
    assert set(stated) == set(VALID_TYPES), (
        f"the raw-forms table names {sorted(stated)} against the ten of VALID_TYPES"
    )
    assert token in stated, f"the raw-forms table holds no row for {token}"

    # Run the capture the method page of this token names, and read the result itself.
    # A comparison against the method page alone would compare two documents.
    method = next(
        name for name in IMPLEMENTED_METHODS if _fact(name, "The `--types` token") == token
    )
    capture, value = _examples(method)[0]
    result = _result_for(capture, value)
    for field, cell in zip(("raw", "raw_original_order"), stated[token]):
        written = getattr(result, field) is not None
        assert written == (cell != "`null`"), (
            f"the schema page states {cell!r} for the `{field}` of {token}, and the "
            f"result of {capture} carries {getattr(result, field)!r}"
        )


def test_the_site_serves_the_migration_page() -> None:
    """`FR-documentation-12`. The migration page exists and the nav names it."""
    assert MIGRATION_PAGE.is_file(), "docs/migration-0.6-to-1.0.md does not exist"
    assert "migration-0.6-to-1.0.md" in CONFIGURATION.read_text(encoding="utf-8"), (
        "the nav of mkdocs.yml names no migration-0.6-to-1.0.md"
    )


def test_the_migration_page_states_the_released_version_it_moves_from() -> None:
    """The migration page names the version `ja4plus/__init__.py` publishes today.

    Version 0.6.0 is the released version, and `__version__` holds it. A release raises
    that constant, and this case then names the page as the thing to change.
    """
    assert f"version {ja4plus.__version__}" in MIGRATION_PAGE.read_text(encoding="utf-8"), (
        f"the migration page names no `version {ja4plus.__version__}`, which `__version__` holds"
    )


def _migration_changes() -> list[list[str]]:
    """Return the rows of the breaking-change table of the migration page.

    Returns:
        One list of cells for each breaking change.

    Raises:
        AssertionError: The table holds fewer rows than the record carries. **An empty
            table passes every check that reads it**, so the floor guards the two cases
            below.
    """
    text = MIGRATION_PAGE.read_text(encoding="utf-8")
    rows = _table_rows(_section(text, "## The breaking changes"), MIGRATION_HEADER)
    assert len(rows) >= MINIMUM_BREAKING_CHANGES, (
        f"the page lists {len(rows)} breaking changes, and the floor is {MINIMUM_BREAKING_CHANGES}"
    )
    return rows


def test_the_migration_page_states_an_old_form_and_a_new_form_for_each_change() -> None:
    """`docs/specs/features/08-documentation.md` asks for the old form, the new form and
    the reason of each breaking change."""
    empty = [row[0] for row in _migration_changes() if not all(cell for cell in row[:4])]
    assert empty == [], f"these breaking changes state no old form, new form or reason: {empty}"


def test_every_breaking_change_of_the_migration_page_cites_an_issue() -> None:
    """Each breaking change names the issue that made it, so a reader reaches the record."""
    uncited = [row[0] for row in _migration_changes() if not re.search(r"#\d+", row[-1])]
    assert uncited == [], f"these breaking changes cite no issue: {uncited}"


def test_the_migration_page_states_that_the_collector_module_is_removed() -> None:
    """`ja4plus.collector` is gone, and the page must say so.

    The module of version 0.6.0 no longer exists, so `import ja4plus.collector` raises.
    This case reads the package rather than the prose.
    """
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("ja4plus.collector")
    assert "ja4plus.collector" in MIGRATION_PAGE.read_text(encoding="utf-8"), (
        "the package holds no `ja4plus.collector`, and the migration page names it not"
    )


def test_the_migration_page_states_the_python_floor_the_project_requires() -> None:
    """The page states the `requires-python` floor `pyproject.toml` sets.

    The move from Python 3.8 to Python 3.9 is a breaking change, and #65 found that no
    Changelog round records it.
    """
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    found = re.search(r'requires-python\s*=\s*"[><=]*(\d+\.\d+)"', pyproject)
    assert found, "pyproject.toml states no `requires-python` floor"
    assert f"Python {found.group(1)}" in MIGRATION_PAGE.read_text(encoding="utf-8"), (
        f"the migration page states no `Python {found.group(1)}`, which pyproject.toml requires"
    )


def test_the_concurrency_page_states_whether_threads_may_share_one_processor() -> None:
    """The concurrency page answers the question the README answers, in the same words."""
    page = DOCS_DIR / "concurrency.md"
    assert page.is_file(), "docs/concurrency.md does not exist"
    sentence = "Several threads may share one `Processor()`"
    assert sentence in page.read_text(encoding="utf-8"), (
        f"the concurrency page holds no {sentence!r}"
    )


def test_the_concurrency_page_states_the_default_bounds_the_code_sets() -> None:
    """The concurrency page states the two defaults `ja4plus/utils/state_table.py` sets."""
    from ja4plus.utils.state_table import DEFAULT_MAX_CONNECTION_AGE, DEFAULT_MAX_CONNECTIONS

    text = (DOCS_DIR / "concurrency.md").read_text(encoding="utf-8")
    for stated in (f"{DEFAULT_MAX_CONNECTIONS} entries", f"{DEFAULT_MAX_CONNECTION_AGE} seconds"):
        assert stated in text, f"the concurrency page states no {stated!r}"
