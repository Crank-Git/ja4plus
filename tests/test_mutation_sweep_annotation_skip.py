"""Tests that the sweep builds no mutation inside a type annotation.

`tests/mutation_sweep.py` builds one mutation for each `BinOp` node whose operator sits in
`BINOP_SWAP`, and `ast.BitOr` is one of them. A type annotation written `str | None` holds
a `BitOr`, so the sweep changed it to `str & None`.

**28 of the 31 modules of `ja4plus/` carry `from __future__ import annotations`.** Python
then holds each annotation as a string. It evaluates none of them, so a changed annotation
reaches no run-time value. No case can fail for such a mutation, and the sweep spends one
suite run on it.

#413 swept `ja4plus/fingerprinters/` whole. 94 of the 675 surviving mutations sit inside a
type annotation, and all 94 survived. `_annotation_nodes` removes them, in the shape
`_docstring_nodes` and `_logging_argument_nodes` already set.

The cases below prove the reader in both directions. A node it names builds no mutation,
and a `BitOr` outside an annotation still builds one.

These cases read Python source with `ast`. They import nothing from `ja4plus` and they
produce no fingerprint.
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path
from typing import List

from tests import mutation_sweep
from tests.mutation_sweep import Mutation

# The module every case reads. It holds the three annotation positions the reader covers,
# and one `BitOr` outside every annotation.
SOURCE = textwrap.dedent(
    '''\
    from __future__ import annotations


    def f(a: str | None) -> int | None:
        """Return the width of the value."""
        x: str | None = None
        width = 4 | 1
        return width
    '''
)

# The `BitOr` count of `SOURCE`. Three sit inside an annotation and one sits outside every
# annotation. A reader that names nothing passes an aggregate over an empty set, so each
# case below reads this floor first.
BIT_OR_COUNT = 4

ANNOTATION_LINE_ARGUMENT = 4
ANNOTATION_LINE_RETURN = 4
ANNOTATION_LINE_ASSIGNMENT = 6
PLAIN_LINE = 7


def write_module(root: Path) -> Path:
    """Write `SOURCE` under the named root and return the path.

    Args:
        root: The directory the module is written to.

    Returns:
        The path of the written module.
    """
    path = root / "module.py"
    path.write_text(SOURCE)
    return path


def bit_or_nodes(tree: ast.AST) -> List[ast.BinOp]:
    """Return every `BinOp` node of the tree whose operator is `ast.BitOr`."""
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr)
    ]


def binop_mutations(root: Path) -> List[Mutation]:
    """Return every `binop` mutation the sweep builds for the module under the named root."""
    path = write_module(root)
    return [item for item in mutation_sweep.generate_mutations(path, root) if item.kind == "binop"]


class TestTheReaderThatNamesAnAnnotation:
    def test_the_module_holds_four_bit_or_nodes(self) -> None:
        """The floor: the reader answers over a source that holds four `BitOr` nodes."""
        assert len(bit_or_nodes(ast.parse(SOURCE))) == BIT_OR_COUNT

    def test_the_reader_names_the_argument_annotation(self) -> None:
        """The reader names the `BitOr` of `a: str | None`."""
        tree = ast.parse(SOURCE)
        found = mutation_sweep._annotation_nodes(tree)
        function = tree.body[1]
        assert isinstance(function, ast.FunctionDef)
        annotation = function.args.args[0].annotation
        assert annotation is not None
        assert id(annotation) in found

    def test_the_reader_names_the_return_annotation(self) -> None:
        """The reader names the `BitOr` of `-> int | None`."""
        tree = ast.parse(SOURCE)
        found = mutation_sweep._annotation_nodes(tree)
        function = tree.body[1]
        assert isinstance(function, ast.FunctionDef)
        assert function.returns is not None
        assert id(function.returns) in found

    def test_the_reader_names_the_assignment_annotation(self) -> None:
        """The reader names the `BitOr` of `x: str | None = None`."""
        tree = ast.parse(SOURCE)
        found = mutation_sweep._annotation_nodes(tree)
        function = tree.body[1]
        assert isinstance(function, ast.FunctionDef)
        assignment = function.body[1]
        assert isinstance(assignment, ast.AnnAssign)
        assert id(assignment.annotation) in found

    def test_the_reader_names_no_node_outside_an_annotation(self) -> None:
        """The reader names no node of `width = 4 | 1`."""
        tree = ast.parse(SOURCE)
        found = mutation_sweep._annotation_nodes(tree)
        outside = [node for node in bit_or_nodes(tree) if node.lineno == PLAIN_LINE]
        assert len(outside) == 1
        assert id(outside[0]) not in found

    def test_the_reader_names_nothing_in_a_module_that_holds_no_annotation(self) -> None:
        """The reader names nothing where the module carries no annotation."""
        assert mutation_sweep._annotation_nodes(ast.parse("width = 4 | 1\n")) == set()


class TestTheConstantOfAnAnnotation:
    def test_the_sweep_builds_no_mutation_of_a_constant_inside_an_annotation(
        self, tmp_path: Path
    ) -> None:
        """The sweep builds no `bool` mutation of the `False` of `Literal[False]`.

        `ja4plus/fingerprinters/base.py:43` holds `-> Literal[False]:`. That constant
        reaches no run-time value either, so the reader removes it beside the `BitOr`
        mutations. It raises the count this issue removes from 94 to 95.
        """
        path = tmp_path / "module.py"
        path.write_text(
            textwrap.dedent(
                """\
                from __future__ import annotations

                from typing import Literal


                def f() -> Literal[False]:
                    return False
                """
            )
        )
        found = mutation_sweep.generate_mutations(path, tmp_path)
        assert [item.line for item in found if item.kind == "bool"] == [7]


class TestTheMutationsTheSweepBuilds:
    def test_the_sweep_builds_no_mutation_of_an_annotation(self, tmp_path: Path) -> None:
        """The sweep builds no `binop` mutation on the three annotation lines."""
        lines = {item.line for item in binop_mutations(tmp_path)}
        assert ANNOTATION_LINE_ARGUMENT not in lines
        assert ANNOTATION_LINE_RETURN not in lines
        assert ANNOTATION_LINE_ASSIGNMENT not in lines

    def test_the_sweep_builds_one_mutation_outside_an_annotation(self, tmp_path: Path) -> None:
        """The sweep builds the `binop` mutation of `width = 4 | 1`."""
        found = binop_mutations(tmp_path)
        assert len(found) == 1
        assert found[0].line == PLAIN_LINE
        assert found[0].before == "|"
        assert found[0].after == "&"
