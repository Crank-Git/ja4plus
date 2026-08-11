r"""The one reader of a dependency block of `pyproject.toml`.

A dependency block holds one entry for each distribution. This project writes a comment
above each entry that a ruling chose. **A reader that collects every quoted substring of
the block returns a comment fragment as an entry.** #452 records that defect. The `dev`
extra carries the command `pytest tests/ -m "not spec_validation"` inside one comment. The
earlier reader returned `not spec_validation` as an entry of that extra.

**A reader that is correct only because of what its callers happen to read is the defect.**
The two callers of #378 read the runtime block and the `docs` extra. Neither block carries
a comment inside its brackets. Every caller now reads one reader, and that reader meets the
comment.

## Why this module reads lines and no TOML

**`tomllib` reaches the standard library at Python 3.11.** `pyproject.toml` states
`requires-python = ">=3.9"`, and `FR-foundation-13` runs the test matrix from Python 3.9.
A case that imports `tomllib` therefore fails two jobs of that matrix. The `dev` extra
names no `tomli`, so no third-party reader is present either. This module reads the block
as lines, and it drops a comment the way TOML drops one.

## Three rules a caller reads

**A comment starts at a `#` that stands outside a string.** A comment line and a comment
after an entry both reach that rule, so one scan removes both.

**The reader holds a basic string and a literal string.** TOML writes the first form in
double quotes and the second form in single quotes. A reader of one form alone drops an
entry of the other form and reports no offender.

**A block that holds no entry raises.** An aggregate over an empty set passes, so a reader
that parses nothing would report a clean block to every caller. `dependency_entries` fails
there instead.

## One shape the reader declines

**The reader reads no escape sequence, and a line that holds one raises.** TOML writes a
quote inside a basic string as `\"`, and the reader closes the string at that quote. The
rest of the line then reads as one open string, and `_without_comment` fails there. **A
silent half of an entry is the worse result.** The reader refuses the line rather than
returns `foo\` for the entry `"foo\"bar"`. No requirement of PEP 508 holds a quote. An
environment marker that quotes its value reaches no such failure, because the reader holds
the quote that opened the string.

`tests/test_dependency_entries.py` holds the cases against this module.
"""

import re

# A quoted string of one line, without its quotes. TOML holds two such forms: a basic
# string in double quotes, and a literal string in single quotes. **The reader holds both**,
# because a reader that holds one form drops an entry of the other form and reports no
# offender. Group 2 holds the text, and the back reference closes the string on the quote
# that opened it.
QUOTED = re.compile(r"([\"'])(.+?)\1")

# The two characters that open a string of TOML.
QUOTES = "\"'"


def _without_comment(line: str) -> str:
    """Return one line of a dependency block, without the comment it carries.

    A `#` inside a string is text, and a `#` outside one opens a comment. The reader holds
    the quote that opened the string, so a comment line and a comment after an entry read
    the same way, and an apostrophe of an environment marker closes no basic string.

    Args:
        line: One line inside the brackets of a dependency block.

    Returns:
        The text in front of the comment. A comment line gives the empty string.

    Raises:
        AssertionError: The line ends inside a string. An escape sequence produces that
            state, and the reader reads none.
    """
    quote = ""
    for index, character in enumerate(line):
        if quote:
            if character == quote:
                quote = ""
        elif character in QUOTES:
            quote = character
        elif character == "#":
            return line[:index]
    assert not quote, f"this line of a dependency block holds an open string: {line!r}"
    return line


def dependency_lines(text: str, opener: str) -> list[str]:
    """Return every line inside the brackets of one dependency block of `pyproject.toml`.

    Args:
        text: The whole file.
        opener: The line that opens the block, as `dependencies = [`.

    Returns:
        The stripped lines, comment lines included, in file order.

    Raises:
        AssertionError: The file holds no such block, or the block is not closed.
    """
    start = text.find(f"\n{opener}\n")
    assert start != -1, f"pyproject.toml holds no {opener!r} block"
    end = text.find("\n]", start)
    assert end != -1, f"the {opener!r} block is not closed"
    return [line.strip() for line in text[start:end].splitlines()[2:]]


def dependency_entries(text: str, opener: str) -> list[str]:
    """Return the entries of one dependency block of `pyproject.toml`.

    A comment reaches no entry. This project states the reason for an entry in a comment
    above it, and a comment that quotes a version or a command is prose.

    Args:
        text: The whole file.
        opener: The line that opens the block, as `dependencies = [`.

    Returns:
        The entries, without their quotes, in file order.

    Raises:
        AssertionError: The file holds no such block, the block is not closed, or the
            block holds no entry.
    """
    entries = [
        found
        for line in dependency_lines(text, opener)
        for _, found in QUOTED.findall(_without_comment(line))
    ]
    assert entries, f"the {opener!r} block holds no entry"
    return entries
