"""The one reader of a dependency list of `pyproject.toml`.

A dependency list of `pyproject.toml` holds one entry for each distribution, and this
project writes a comment above each entry that a decision chose. **A reader that collects
every double-quoted substring of the block returns a comment fragment as an entry.** #452
records that defect. The `dev` extra carries the command `pytest tests/ -m "not
spec_validation"` inside one comment, and the earlier reader returned `not spec_validation`
as an entry of the extra.

**A reader that is correct only because of what its callers happen to read is the defect.**
The two callers of #378 read the runtime list and the `docs` extra, and neither block
carries a comment inside its brackets. Every caller now reads one reader, and that reader
meets the comment.

## Why this module reads lines and not TOML

**`tomllib` reaches the standard library at Python 3.11, and `pyproject.toml` states
`requires-python = ">=3.9"`.** `FR-foundation-13` runs the test matrix from Python 3.9, so
a case that imports `tomllib` fails two jobs of that matrix. The `dev` extra names no
`tomli`, so no third-party reader is present either. This module therefore reads the block
as lines, and it drops a comment the way TOML drops one.

## Two rules a caller reads

**A comment starts at a `#` that stands outside a string.** A comment line and a comment
after an entry both reach that rule, so one scan removes both.

**A block that holds no entry raises.** An aggregate over an empty set passes, so a reader
that parses nothing would report a clean block to every caller. `dependency_entries` fails
there instead.

`tests/test_dependency_entries.py` holds the cases against this module.
"""

import re

# A double-quoted string of one line, without its quotes. TOML calls it a basic string, and
# every entry of `pyproject.toml` takes that form.
QUOTED = re.compile(r"\"([^\"]+)\"")


def _without_comment(line: str) -> str:
    """Return one line of a dependency block, without the comment it carries.

    A `#` inside a string is text, and a `#` outside one opens a comment. The reader tracks
    the quote character to part the two, so a comment line and a comment after an entry
    read the same way.

    Args:
        line: One line inside the brackets of a dependency list.

    Returns:
        The text in front of the comment. A comment line gives the empty string.
    """
    inside = False
    for index, character in enumerate(line):
        if character == '"':
            inside = not inside
        elif character == "#" and not inside:
            return line[:index]
    return line


def dependency_lines(text: str, opener: str) -> list[str]:
    """Return every line inside the brackets of one dependency list of `pyproject.toml`.

    Args:
        text: The whole file.
        opener: The line that opens the list, as `dependencies = [`.

    Returns:
        The stripped lines, comment lines included, in file order.

    Raises:
        AssertionError: The file holds no such list, or the list is not closed.
    """
    start = text.find(f"\n{opener}\n")
    assert start != -1, f"pyproject.toml holds no {opener!r} list"
    end = text.find("\n]", start)
    assert end != -1, f"the {opener!r} list is not closed"
    return [line.strip() for line in text[start:end].splitlines()[2:]]


def dependency_entries(text: str, opener: str) -> list[str]:
    """Return the entries of one dependency list of `pyproject.toml`.

    A comment reaches no entry. This project states the reason for an entry in a comment
    above it, and a comment that quotes a version or a command is prose.

    Args:
        text: The whole file.
        opener: The line that opens the list, as `dependencies = [`.

    Returns:
        The entries, without their quotes, in file order.

    Raises:
        AssertionError: The file holds no such list, the list is not closed, or the block
            holds no entry.
    """
    entries = [
        found
        for line in dependency_lines(text, opener)
        for found in QUOTED.findall(_without_comment(line))
    ]
    assert entries, f"the {opener!r} list holds no entry"
    return entries
