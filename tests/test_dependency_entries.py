"""Tests that the shared reader reads dependency entries and never every quoted substring.

`tests/dependency_entries.py` holds the one reader of a dependency block of
`pyproject.toml`. #452 records the defect it repairs. The earlier reader collected every
double-quoted substring of the block, so a comment inside the block read as an entry.

**A case here writes the block it reads.** The blocks of `pyproject.toml` hold the shapes
this project writes today. A case that reads those blocks alone proves the reader against
those shapes and no other. `tests/test_documentation_site.py` holds the real blocks by
name, and the cases here hold four shapes a later writer could add.

1. A comment that stands after an entry.
2. A `#` inside an entry.
3. An entry that a literal string holds.
4. A block that holds no entry.

**Each case reads the reader in both directions.** A case that reads the absence of a
comment fragment passes against a reader that returns an empty list. Every case below
therefore names the entries it expects.

These cases read text. They import nothing from `ja4plus` and they produce no fingerprint.
"""

import pytest

from tests.dependency_entries import dependency_entries, dependency_lines


def _block(body: str) -> str:
    """Return a `pyproject.toml` fragment that holds one dependency block.

    Args:
        body: The lines inside the brackets, without the opener and without the closer.

    Returns:
        The fragment, opened by a line the reader finds and closed by `]`.
    """
    return f"[project]\ndev = [\n{body}\n]\nname = 'ja4plus'\n"


def test_the_reader_drops_a_comment_line_of_a_block() -> None:
    """A comment line above an entry reaches no entry.

    The `dev` extra of `pyproject.toml` states one comment above every entry, and one of
    them quotes a command. #452 measured `not spec_validation` as an entry of that extra.
    """
    text = _block(
        '    # The suite runs `pytest tests/ -m "not spec_validation"`.\n    "pytest==8.4.2",'
    )
    assert dependency_entries(text, "dev = [") == ["pytest==8.4.2"]


def test_the_reader_drops_a_comment_that_stands_after_an_entry() -> None:
    """A comment on the line of an entry reaches no second entry.

    TOML opens a comment at a `#` that stands outside a string, and the position of that
    `#` on the line changes nothing.
    """
    text = _block('    "ruff==0.16.2",  # #378 declined the range "ruff>=0.6".')
    assert dependency_entries(text, "dev = [") == ["ruff==0.16.2"]


def test_the_reader_holds_an_entry_that_carries_a_number_sign() -> None:
    """A `#` inside an entry is text, and the reader returns the whole entry.

    A URL of a direct reference carries a fragment marker, as
    `ja4plus @ https://example.invalid/ja4plus.whl#sha256=00`. A reader that cuts the line
    at the first `#` returns half of such an entry.
    """
    text = _block('    "ja4plus @ https://example.invalid/ja4plus.whl#sha256=00",')
    assert dependency_entries(text, "dev = [") == [
        "ja4plus @ https://example.invalid/ja4plus.whl#sha256=00"
    ]


def test_the_reader_returns_an_entry_that_a_literal_string_holds() -> None:
    """TOML holds a literal string in single quotes, and that entry is a dependency.

    **A reader of the double-quoted form alone drops such an entry and reports no
    offender.** The self-review of #452 found the hole.
    """
    text = _block("    'ruff==0.16.2',\n    \"mypy>=1.11\",")
    assert dependency_entries(text, "dev = [") == ["ruff==0.16.2", "mypy>=1.11"]


def test_the_reader_holds_an_entry_whose_marker_quotes_a_version() -> None:
    """An environment marker quotes its value, and the entry holds that quote.

    A basic string holds an apostrophe, and the reader holds the quote that opened the
    string, so the apostrophe closes nothing.
    """
    text = _block("    \"tomli; python_version < '3.11'\",")
    assert dependency_entries(text, "dev = [") == ["tomli; python_version < '3.11'"]


def test_the_reader_refuses_a_line_that_holds_an_escaped_quote() -> None:
    """A line the reader cannot read fails rather than returns half of an entry.

    The reader reads no escape sequence. It closes the string at the escaped quote, so the
    rest of the line reads as one open string, and a silent `foo\\` entry is the worse
    result.
    """
    with pytest.raises(AssertionError, match="open string"):
        dependency_entries(_block('    "foo\\"bar",'), "dev = [")


def test_the_reader_returns_every_entry_of_a_block_in_file_order() -> None:
    """The reader drops no entry and it holds the order of the file.

    A repair that returns an empty list passes a case that reads the absence of a comment
    fragment. This case therefore names all three entries.
    """
    text = _block('    "pytest==8.4.2",\n    # Why.\n    "ruff==0.16.2",\n    "mypy>=1.11",')
    assert dependency_entries(text, "dev = [") == ["pytest==8.4.2", "ruff==0.16.2", "mypy>=1.11"]


def test_the_reader_refuses_a_block_that_holds_no_entry() -> None:
    """A block of comments alone fails rather than reports a clean block.

    **An aggregate over an empty set passes.** A caller that reads an empty list finds no
    offender, so the reader raises here and no caller carries the floor.
    """
    text = _block("    # Every entry moved to the runtime block.")
    with pytest.raises(AssertionError, match="holds no entry"):
        dependency_entries(text, "dev = [")


def test_the_reader_refuses_a_file_that_holds_no_such_block() -> None:
    """A reader of a renamed block fails rather than returns nothing."""
    with pytest.raises(AssertionError, match="holds no"):
        dependency_entries(_block('    "pytest==8.4.2",'), "docs = [")


def test_the_reader_refuses_a_block_that_is_not_closed() -> None:
    """A truncated file fails rather than reads to the end of the text."""
    with pytest.raises(AssertionError, match="is not closed"):
        dependency_entries('[project]\ndev = [\n    "pytest==8.4.2",\n', "dev = [")


def test_the_line_reader_holds_the_comment_lines_the_entry_reader_drops() -> None:
    """`dependency_lines` returns every line, because a caller reads the comments.

    `tests/test_lint_gate_pin.py` reads the comment above one entry, so the two readers
    stand beside each other and neither one replaces the other.
    """
    text = _block('    # Why.\n    "pytest==8.4.2",')
    assert dependency_lines(text, "dev = [") == ["# Why.", '"pytest==8.4.2",']
