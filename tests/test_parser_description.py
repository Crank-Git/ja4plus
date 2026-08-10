"""Tests that no module reads its own docstring for the description of a parser.

**`python -OO` sets `__doc__` to None on every module.** A parser that reads
`__doc__.splitlines()[0]` for its description then raises `AttributeError` before it reads
one argument. A parser that passes `__doc__` itself raises nothing, and it reports no
description at all under that interpreter.

**#70 repaired one site at `tests/release_body.py:139` and the same line reached
`tests/skip_gate.py:333` two rounds later.** A repair of the known sites stops no new one.
These cases read every tracked module instead, so the next site fails here on the round
that writes it.

The reader takes the file list from `git ls-files`. **Never walk the checkout with
`rglob`.** #473 records the reason. The harness places a worker worktree under `.claude/`,
so a walk of the checkout grows its corpus with the number of live workers.

These cases read no packet and they produce no fingerprint.
"""

from __future__ import annotations

import ast
import pathlib
import subprocess
import sys
from typing import List, NamedTuple, Optional

import pytest

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent

# The call names that build a parser. `ArgumentParser` builds the top parser and
# `add_parser` builds a subcommand parser, and each one accepts `description`.
PARSER_CALLS = frozenset({"ArgumentParser", "add_parser"})

# `ArgumentParser(prog, usage, description, ...)` takes the description third, so a caller
# reaches it with no keyword at all. `add_parser(name, **kwargs)` takes one positional
# argument, so this position reads the top parser alone.
POSITIONAL_DESCRIPTION = 2


class ParserCall(NamedTuple):
    """One parser call of one file.

    Attributes:
        path: The repository path of the file that holds the call.
        line: The line of the call.
        reads_module_docstring: True where the description reads `__doc__`.
    """

    path: str
    line: int
    reads_module_docstring: bool


def _called_name(func: ast.expr) -> str:
    """Return the attribute or name the call reads, or the empty string."""
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _reads_module_docstring(value: ast.expr) -> bool:
    """Return True where the expression reads the name `__doc__`.

    The reader reports every expression that names `__doc__`, and it reads no control
    flow. `description=__doc__ or "Read the run."` raises nothing under `-OO`, and this
    reader still reports it. **A module states its description**, and a fallback beside
    `__doc__` states that description twice.
    """
    return any(isinstance(node, ast.Name) and node.id == "__doc__" for node in ast.walk(value))


def parser_calls(source: str, path: str) -> List[ParserCall]:
    """Return every parser call the source holds.

    Args:
        source: The text of one Python file.
        path: The repository path the records report.

    Returns:
        One record for each `ArgumentParser` call and each `add_parser` call.

    Raises:
        SyntaxError: The source is not Python.
    """
    tree = ast.parse(source)
    calls: List[ParserCall] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _called_name(node.func) not in PARSER_CALLS:
            continue
        description: Optional[ast.expr] = None
        if _called_name(node.func) == "ArgumentParser" and len(node.args) > POSITIONAL_DESCRIPTION:
            description = node.args[POSITIONAL_DESCRIPTION]
        for keyword in node.keywords:
            if keyword.arg == "description":
                description = keyword.value
        reads = description is not None and _reads_module_docstring(description)
        calls.append(ParserCall(path=path, line=node.lineno, reads_module_docstring=reads))
    return calls


def _is_main_name(node: ast.expr) -> bool:
    """Return True where the expression is the name `__name__`."""
    return isinstance(node, ast.Name) and node.id == "__name__"


def _is_main_string(node: ast.expr) -> bool:
    """Return True where the expression is the string `__main__`."""
    return isinstance(node, ast.Constant) and node.value == "__main__"


def holds_main_guard(source: str) -> bool:
    """Return True where the source compares `__name__` against `__main__`.

    The reader reads the syntax tree rather than the text. A text match reads one quote
    style and one operand order, so a guard that writes either one differently reaches no
    run case and the suite reports a corpus it never read.

    Args:
        source: The text of one Python file.

    Returns:
        True where one comparison of the file holds both operands.

    Raises:
        SyntaxError: The source is not Python.
    """
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left, *node.comparators]
        if any(_is_main_name(one) for one in operands) and any(
            _is_main_string(one) for one in operands
        ):
            return True
    return False


def tracked_python_files() -> List[str]:
    """Return every tracked Python file of the repository."""
    listed = subprocess.run(
        ["git", "ls-files"],
        cwd=str(REPOSITORY_ROOT),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    return [path for path in listed if path.endswith(".py")]


def tracked_parser_calls() -> List[ParserCall]:
    """Return every parser call of every tracked Python file."""
    calls: List[ParserCall] = []
    for path in tracked_python_files():
        source = (REPOSITORY_ROOT / path).read_text(encoding="utf-8")
        calls.extend(parser_calls(source, path))
    return calls


def tool_modules() -> List[str]:
    """Return the module name of every tracked test tool that a caller runs as a program."""
    names: List[str] = []
    for path in tracked_python_files():
        if not path.startswith("tests/"):
            continue
        source = (REPOSITORY_ROOT / path).read_text(encoding="utf-8")
        if not parser_calls(source, path):
            continue
        if not holds_main_guard(source):
            continue
        names.append(path[: -len(".py")].replace("/", "."))
    return names


def _help_output(module: str, optimize: bool, cwd: pathlib.Path) -> subprocess.CompletedProcess:
    """Return the completed run of `--help` for the named module."""
    command = [sys.executable]
    if optimize:
        command.append("-OO")
    command.extend(["-m", module, "--help"])
    return subprocess.run(command, cwd=str(cwd), capture_output=True, text=True)


def _normalized(text: str) -> str:
    """Return the text with every run of whitespace as one space.

    argparse wraps the description to the terminal width, and the width of a captured run
    is not the width of a terminal. The comparison reads the words and never the wrap.
    """
    return " ".join(text.split())


# --- The reader, in both directions -----------------------------------------------------


def test_the_reader_finds_a_parser_that_splits_the_module_docstring() -> None:
    """A description that splits `__doc__` is the form that raises under `-OO`."""
    source = "import argparse\nargparse.ArgumentParser(description=__doc__.splitlines()[0])\n"
    calls = parser_calls(source, "sample.py")
    assert [call.reads_module_docstring for call in calls] == [True]
    assert calls[0].line == 2


def test_the_reader_finds_a_parser_that_passes_the_module_docstring() -> None:
    """A description that passes `__doc__` raises nothing, and `-OO` still removes it."""
    source = "import argparse\nargparse.ArgumentParser(description=__doc__)\n"
    calls = parser_calls(source, "sample.py")
    assert [call.reads_module_docstring for call in calls] == [True]


def test_the_reader_finds_a_subcommand_parser_that_reads_the_module_docstring() -> None:
    """`add_parser` accepts the same keyword, so the reader reads that call too."""
    source = "subparsers.add_parser('run', description=__doc__)\n"
    calls = parser_calls(source, "sample.py")
    assert [call.reads_module_docstring for call in calls] == [True]


def test_the_reader_passes_a_parser_that_states_its_own_description() -> None:
    """A description the module states survives an interpreter that strips every docstring."""
    source = "import argparse\nargparse.ArgumentParser(description='Measure the run.')\n"
    calls = parser_calls(source, "sample.py")
    assert [call.reads_module_docstring for call in calls] == [False]


def test_the_reader_finds_a_parser_that_takes_the_module_docstring_in_the_third_position() -> None:
    """`ArgumentParser` takes the description third, so a caller reaches it with no keyword."""
    source = "import argparse\nargparse.ArgumentParser('tool', None, __doc__)\n"
    calls = parser_calls(source, "sample.py")
    assert [call.reads_module_docstring for call in calls] == [True]


def test_the_reader_reads_the_keyword_above_the_third_position() -> None:
    """A caller that writes both forms reaches the keyword, which is what Python binds."""
    source = "import argparse\nargparse.ArgumentParser('tool', None, description='Run it.')\n"
    calls = parser_calls(source, "sample.py")
    assert [call.reads_module_docstring for call in calls] == [False]


def test_the_reader_reports_a_fallback_beside_the_module_docstring() -> None:
    """A fallback raises nothing, and the reader still reports it.

    The docstring of `_reads_module_docstring` states the reason. A module states one
    description, and this form states that description twice.
    """
    source = "import argparse\nargparse.ArgumentParser(description=__doc__ or 'Run it.')\n"
    calls = parser_calls(source, "sample.py")
    assert [call.reads_module_docstring for call in calls] == [True]


def test_the_tool_reader_reads_a_main_guard_whatever_its_quotes_and_order() -> None:
    """A guard that writes another quote style, or the other operand order, still reads."""
    assert holds_main_guard("if __name__ == '__main__':\n    pass\n")
    assert holds_main_guard('if "__main__" == __name__:\n    pass\n')
    assert holds_main_guard('if __name__=="__main__":\n    pass\n')


def test_the_tool_reader_reads_no_guard_where_the_file_holds_none() -> None:
    """A file that names one operand alone holds no guard."""
    assert not holds_main_guard('print("__main__")\n')
    assert not holds_main_guard("print(__name__)\n")


def test_the_reader_passes_a_call_that_is_no_parser() -> None:
    """The reader reads a parser call alone, so another call that names `__doc__` passes."""
    source = "print(description=__doc__)\n"
    assert parser_calls(source, "sample.py") == []


# --- The corpus -------------------------------------------------------------------------


def test_the_tracked_corpus_holds_an_argument_parser() -> None:
    """A reader that finds no parser reports a clean corpus that it never read.

    This case is the floor of the case below. A pathspec that lists nothing, or a walk that
    reaches no file, passes the corpus case for the wrong reason and fails this one.
    """
    calls = tracked_parser_calls()
    assert len(calls) >= 5, f"the reader found {len(calls)} parser calls in the tracked corpus"


def test_no_tracked_module_reads_the_module_docstring_for_a_parser_description() -> None:
    """Every parser of the repository states a description that `-OO` does not remove."""
    guilty = [
        f"{call.path}:{call.line}" for call in tracked_parser_calls() if call.reads_module_docstring
    ]
    assert guilty == [], f"these parser descriptions read the module docstring: {guilty}"


def test_the_tracked_corpus_holds_a_tool_module() -> None:
    """A reader that finds no tool module runs no program, so the run case proves nothing."""
    modules = tool_modules()
    assert len(modules) >= 5, f"the reader found {len(modules)} tool modules"


@pytest.mark.parametrize("module", tool_modules())
def test_the_tool_reports_the_same_help_where_the_interpreter_strips_every_docstring(
    module: str,
) -> None:
    """The `--help` of a tool reads the same under `-OO` as it reads under a plain run.

    The comparison covers both failure modes at once. A description that splits `__doc__`
    raises, so the run exits non-zero. A description that passes `__doc__` exits 0 and
    reports no description, so the two outputs differ.
    """
    plain = _help_output(module, optimize=False, cwd=REPOSITORY_ROOT)
    stripped = _help_output(module, optimize=True, cwd=REPOSITORY_ROOT)
    assert plain.returncode == 0, f"{module} refused --help: {plain.stderr}"
    assert stripped.returncode == 0, f"{module} refused --help under -OO: {stripped.stderr}"
    assert _normalized(stripped.stdout) == _normalized(plain.stdout), (
        f"{module} reports a different --help under -OO"
    )


def test_the_help_comparison_fails_a_module_that_reads_the_module_docstring(
    tmp_path: pathlib.Path,
) -> None:
    """The comparison above bites, so a module that reads `__doc__` reports two outputs."""
    tool = tmp_path / "docstring_tool.py"
    tool.write_text(
        '"""State the description of this tool."""\n'
        "\n"
        "import argparse\n"
        "\n"
        "argparse.ArgumentParser(description=__doc__).parse_args()\n",
        encoding="utf-8",
    )
    plain = _help_output("docstring_tool", optimize=False, cwd=tmp_path)
    stripped = _help_output("docstring_tool", optimize=True, cwd=tmp_path)
    assert plain.returncode == 0, plain.stderr
    assert stripped.returncode == 0, stripped.stderr
    assert "State the description of this tool." in _normalized(plain.stdout)
    assert _normalized(stripped.stdout) != _normalized(plain.stdout)
