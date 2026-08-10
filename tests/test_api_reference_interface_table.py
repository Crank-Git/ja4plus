"""Tests that the interface table of the API reference names every published name.

`docs/api_reference.md:5` frames the page as the interface this project promises, and
version 1.0.0 published that interface. A name a module exports in `__all__`, and the
page names nowhere in a table, is a promise the reader cannot find.

**These cases read the `__all__` of every module rather than three known rows.** #562
records the reason. A review found `packet_statistics_drops`, `PACKET_STATISTICS` and
`SOL_PACKET` outside the table, and a repair of those three rows stops no fourth name.
#70 measured that shape twice: round 191 repaired one site and round 197 wrote the same
defect into a new file.

## The module set these cases take

**A published module is a tracked module under `ja4plus/` that states `__all__`.** The
reader takes that set and it takes no other. `__all__` is the statement a module makes
about its own public names, and `docs/api_reference.md:5` promises exactly such names.

**Warning: never take the module set from the headings of the page.** The page holds a
`### ja4plus.<module>` heading for five of the six published modules, so a reader keyed on
those headings reads no name of the sixth. `ja4plus.output` is that module, and it states
seven names. A reader that covers less than the page claims is the shape #530, #524, #438
and #70 each recorded.

## What counts as the table

The page holds two table shapes, and the reader reads both.

- `| Class/Function | Description |` puts the name in the first cell.
- `| Group | Names |` puts the 25 top-level names in the second cell, one row for each
  group.

The reader therefore reads every code span of a table row, and it reads no code span
outside a table. **Prose is not the table.** `docs/api_reference.md` names
`packet_statistics_drops` in a paragraph today. #562 records that reading, and the review
of round 206 rests on it.

These cases read no packet and they produce no fingerprint.
"""

from __future__ import annotations

import ast
import pathlib
import re
import subprocess
from typing import Dict, List, Sequence, Set

import pytest

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent

API_REFERENCE = REPOSITORY_ROOT / "docs" / "api_reference.md"

# A published module is a tracked module of this package. The reader reads no test tool
# and no build script, because neither one carries the promise of the page.
PACKAGE_DIRECTORY = "ja4plus/"

# A Markdown code span. The page writes every name it documents as one.
CODE_SPAN = re.compile(r"`([^`]+)`")

# The pipe that bounds one cell of a table row. **A backslash escapes a pipe inside a code
# span.** The result table writes `str \| None`, so a split on every pipe cuts that cell in
# two.
CELL_BOUNDARY = re.compile(r"(?<!\\)\|")

# The floors below refuse a reader that finds nothing. Each number stands under the count
# of a read of 2026-08-10, so a name a later round removes fails no case here.
MODULE_FLOOR = 6
PUBLISHED_NAME_FLOOR = 60
TABLE_NAME_FLOOR = 100


def documented_name(span: str) -> str:
    """Return the bare name one code span of a table row documents.

    The page writes a name in three forms. `Monitor(processor, report)` carries the
    signature, `.process_packet(packet)` carries a leading dot, and `Monitor.stats` carries
    the owner. Each form documents one name, so the reader removes the signature, the dot
    and the attribute.

    Args:
        span: The text inside one pair of backticks.

    Returns:
        The name, or the empty string where the span carries none.
    """
    name = span.split("(")[0].strip().lstrip(".")
    return name.split(".")[0]


def is_separator_row(line: str) -> bool:
    """Return True where the line separates the header of a table from its body.

    Args:
        line: One line of a Markdown page.

    Returns:
        True where the line holds pipes, dashes, colons and spaces alone.
    """
    stripped = line.strip()
    if not stripped.startswith("|"):
        return False
    return set(stripped) <= set("|-: ")


def is_name_cell(cell: str) -> bool:
    """Return True where one cell of a table row states names and nothing else.

    **A name cell holds code spans, commas and spaces alone.** A description cell states
    a sentence, and a name inside such a sentence documents the row it stands in rather
    than itself. `| `.stats()` | Return one `ProcessorStats` for each ... |` is that shape.
    The self-review of #562 measured it, and the page named `ProcessorStats` in no cell of
    its own.

    Args:
        cell: The text of one cell, without the pipes that bound it.

    Returns:
        True where the cell holds one code span at least, and no other text.
    """
    if not CODE_SPAN.search(cell):
        return False
    return not set(CODE_SPAN.sub("", cell).strip()) - set(", ")


def table_names(text: str) -> Set[str]:
    """Return every name the name cells of one Markdown document state.

    A table row starts with a pipe. The reader reads the name cells of such a row, and it
    reads no other line, so a name that reaches the prose alone reaches no result here.

    **A header row documents no name, so the reader drops it.** A separator row follows
    every header row, and `| Field of `ProcessorStats` | Description |` is such a header.

    Args:
        text: The whole text of one Markdown document.

    Returns:
        The bare name of every code span of every name cell of every body row.
    """
    names: Set[str] = set()
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line.strip().startswith("|"):
            continue
        if is_separator_row(line):
            continue
        if index + 1 < len(lines) and is_separator_row(lines[index + 1]):
            continue
        for cell in CELL_BOUNDARY.split(line.strip())[1:-1]:
            if not is_name_cell(cell):
                continue
            for span in CODE_SPAN.findall(cell):
                name = documented_name(span)
                if name:
                    names.add(name)
    return names


def public_names(source: str, path: str) -> List[str]:
    """Return the names one module states in its own `__all__`.

    The reader reads the assignments of the module body, so an `__all__` a function builds
    reaches no result. It reads the syntax tree and never the text, because a text match
    reads one quote style alone.

    Args:
        source: The text of one Python file.
        path: The repository path the failure message names.

    Returns:
        The names of `__all__`, or an empty list where the module states none.

    Raises:
        SyntaxError: The source is not Python.
        ValueError: `__all__` holds an entry that is no string.
    """
    names: List[str] = []
    for node in ast.parse(source).body:
        targets: Sequence[ast.expr]
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            value = node.value
        else:
            continue
        if not any(isinstance(one, ast.Name) and one.id == "__all__" for one in targets):
            continue
        if not isinstance(value, (ast.List, ast.Tuple)):
            raise ValueError(f"{path} states an __all__ that is no list and no tuple")
        for element in value.elts:
            if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
                raise ValueError(f"{path} states an __all__ entry that is no string")
            names.append(element.value)
    return names


def tracked_package_files() -> List[str]:
    """Return every tracked Python file of the package.

    The reader takes the file list from `git ls-files`. **Never walk the checkout with
    `rglob`.** #473 records the reason. The harness places a worker worktree under
    `.claude/`, so a walk grows its corpus with the number of live workers.
    """
    listed = subprocess.run(
        ["git", "ls-files"],
        cwd=str(REPOSITORY_ROOT),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    return [path for path in listed if path.startswith(PACKAGE_DIRECTORY) and path.endswith(".py")]


def module_name(path: str) -> str:
    """Return the import name of one repository path."""
    stem = path[: -len(".py")].replace("/", ".")
    suffix = ".__init__"
    if stem.endswith(suffix):
        stem = stem[: -len(suffix)]
    return stem


def published_modules() -> Dict[str, List[str]]:
    """Return the public names of every published module, keyed by import name."""
    modules: Dict[str, List[str]] = {}
    for path in tracked_package_files():
        names = public_names((REPOSITORY_ROOT / path).read_text(encoding="utf-8"), path)
        if names:
            modules[module_name(path)] = names
    return modules


def undocumented_names(text: str) -> List[str]:
    """Return every published name the table rows of one document name nowhere.

    Args:
        text: The whole text of the API reference.

    Returns:
        One `<module>.<name>` entry for each name outside the table, in module order.
    """
    documented = table_names(text)
    missing: List[str] = []
    for module, names in sorted(published_modules().items()):
        missing.extend(f"{module}.{name}" for name in names if name not in documented)
    return missing


# --- The reader of the table --------------------------------------------------------------


def test_the_reader_finds_a_name_in_the_first_cell_of_a_row() -> None:
    """A `| Class/Function | Description |` row states the name first."""
    row = "| `available_interfaces()` | Return the name of every interface the host holds |"
    assert "available_interfaces" in table_names(row)


def test_the_reader_finds_a_name_in_the_names_cell_of_a_group_row() -> None:
    """A `| Group | Names |` row states the names second, and the page holds five of them."""
    row = "| Certificate helpers | `compute_ja4x_from_der`, `compute_ja4x_from_pem` |"
    assert table_names(row) == {"compute_ja4x_from_der", "compute_ja4x_from_pem"}


def test_the_reader_removes_the_signature_of_a_documented_call() -> None:
    """The page writes the parameters beside the name, and the name is what a caller imports."""
    row = "| `Monitor(processor, report, ...)` | The monitor loop |"
    assert table_names(row) == {"Monitor"}


def test_the_reader_removes_the_leading_dot_of_a_method_row() -> None:
    """The processor section writes a method as `.process_packet(packet)`."""
    row = "| `.process_packet(packet)` | Run every fingerprinter on one packet |"
    assert table_names(row) == {"process_packet"}


def test_the_reader_reads_the_owner_of_an_attribute_row() -> None:
    """`Monitor.stats` documents `Monitor`, which is the name `__all__` states."""
    row = "| `Monitor.stats` | The counts the statistics line reports |"
    assert table_names(row) == {"Monitor"}


def test_the_reader_reads_no_name_of_a_description_cell() -> None:
    """A name inside a sentence documents the row it stands in, and never itself.

    The self-review of #562 found `ProcessorStats` under this shape. The page named it in
    the description of `.stats()` and in one table header, and it gave the class no cell of
    its own. A reader of the whole row reported that page as complete.
    """
    row = "| `.stats()` | Return one `ProcessorStats` for each of the ten fingerprinters |"
    assert table_names(row) == {"stats"}


def test_the_reader_reads_no_name_of_a_table_header() -> None:
    """`| Field of `ProcessorStats` | Description |` heads a table, and it documents no name."""
    table = "| Field of `ProcessorStats` | Description |\n|---|---|\n| `method` | The name |\n"
    assert table_names(table) == {"method"}


def test_the_reader_reads_no_name_of_a_prose_line() -> None:
    """**Prose is not the table.** #562 rests on this reading."""
    prose = "On Linux it holds a whole number, which `packet_statistics_drops` reads.\n"
    assert table_names(prose) == set()


def test_the_reader_reads_no_name_of_a_fenced_code_block() -> None:
    """A sample states how to call a name, and it documents none."""
    sample = "```python\nimport ja4plus\n\nja4plus.__all__\n```\n"
    assert table_names(sample) == set()


def test_the_reader_reads_a_separator_row_as_no_name() -> None:
    """A separator row carries no code span, so it adds nothing."""
    assert table_names("|----------------|-------------|") == set()


def test_the_reader_reads_a_row_that_escapes_a_pipe_inside_a_code_span() -> None:
    """The result table writes `str \\| None`, and the row still states its field name."""
    row = "| `raw` | `str \\| None` | The raw form, when the method defines one. |"
    assert "raw" in table_names(row)


# --- The reader of `__all__` --------------------------------------------------------------


def test_the_public_name_reader_finds_a_list() -> None:
    """Five of the six published modules state `__all__` as a list."""
    assert public_names('__all__ = ["Monitor", "StopRequest"]\n', "sample.py") == [
        "Monitor",
        "StopRequest",
    ]


def test_the_public_name_reader_finds_a_tuple() -> None:
    """A tuple states the same promise, so the reader reads it too."""
    assert public_names('__all__ = ("Monitor",)\n', "sample.py") == ["Monitor"]


def test_the_public_name_reader_finds_an_annotated_assignment() -> None:
    """A module that annotates `__all__` states the same promise."""
    source = 'from typing import List\n__all__: List[str] = ["Monitor"]\n'
    assert public_names(source, "sample.py") == ["Monitor"]


def test_the_public_name_reader_reads_no_all_that_a_function_builds() -> None:
    """The reader reads the module body, so a local name reaches no promise."""
    source = 'def build():\n    __all__ = ["Hidden"]\n    return __all__\n'
    assert public_names(source, "sample.py") == []


def test_the_public_name_reader_reads_a_module_that_states_no_all() -> None:
    """Most modules of the package state none, and each one is correct."""
    assert public_names("VALUE = 1\n", "sample.py") == []


def test_the_public_name_reader_refuses_an_all_it_cannot_read() -> None:
    """A reader that returns nothing here reports a clean table over a whole module."""
    with pytest.raises(ValueError):
        public_names("__all__ = names\n", "sample.py")
    with pytest.raises(ValueError):
        public_names("__all__ = [VALUE]\n", "sample.py")


# --- The floor ------------------------------------------------------------------------------


def test_the_reader_finds_the_published_modules() -> None:
    """A reader that finds no module reports a clean table that it never read.

    This case is the floor of the corpus case below. A pathspec that lists nothing, or a
    parse that reads no `__all__`, passes that case for the wrong reason and fails this one.
    """
    modules = published_modules()
    assert len(modules) >= MODULE_FLOOR, f"the reader found {len(modules)} published modules"
    assert "ja4plus" in modules
    assert "ja4plus.watch" in modules
    assert "ja4plus.output" in modules


def test_the_reader_finds_the_published_names() -> None:
    """A module set that holds an empty name list passes the corpus case and fails this one."""
    count = sum(len(names) for names in published_modules().values())
    assert count >= PUBLISHED_NAME_FLOOR, f"the reader found {count} published names"


def test_the_reader_finds_the_names_of_the_interface_table() -> None:
    """A reader that finds no table row reports every name as missing, or none.

    A document the reader cannot open, and a row pattern that matches nothing, both reach
    this case. The corpus case below then measures the table it read.
    """
    names = table_names(API_REFERENCE.read_text(encoding="utf-8"))
    assert len(names) >= TABLE_NAME_FLOOR, f"the reader found {len(names)} documented names"


def test_the_top_level_module_states_the_name_count_the_page_promises() -> None:
    """`docs/api_reference.md:12` names 25 promised names, and the module states them."""
    assert len(published_modules()["ja4plus"]) == 25


# --- The corpus -----------------------------------------------------------------------------


def test_the_interface_table_names_every_published_name() -> None:
    """Every name a published module exports reaches a table row of the API reference.

    A name outside the table is a promise version 1.0.0 made and the page does not state.
    Add the row rather than remove the name, because `__all__` carries the promise until
    version 2.0.0.
    """
    missing = undocumented_names(API_REFERENCE.read_text(encoding="utf-8"))
    assert missing == [], f"the interface table names none of these: {missing}"


def test_the_corpus_case_fails_a_table_that_drops_one_row() -> None:
    """The corpus case bites, so a removed row reports the name it carried.

    The mutation runs over the text in memory and it writes no file, so
    `docs/api_reference.md` holds the row this case removes. The second reading restores
    the whole text and reports no missing name.
    """
    text = API_REFERENCE.read_text(encoding="utf-8")
    kept = [line for line in text.splitlines() if "`SOL_PACKET`" not in line]
    mutated = "\n".join(kept) + "\n"
    assert mutated != text, "the interface table holds no row that names `SOL_PACKET`"
    assert undocumented_names(mutated) == ["ja4plus.watch.SOL_PACKET"]
    assert undocumented_names(text) == []
