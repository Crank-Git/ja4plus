"""Ask of every test case: would this fail if the code were wrong?

The sweep changes one expression in one module under `ja4plus/`, runs the suite, and
records which cases fail. The change is a measurement, and the sweep reverts it. A case
that fails for no mutation measures nothing that the mutations reach, and the report
names it a candidate.

Coverage answers a different question. Coverage reports which line runs. This sweep
reports whether a line that runs is measured.

Run it from the repository root:

    python tests/mutation_sweep.py --max-per-module 10 --report reports/sweep.json

The sweep restores every file it changes. It also checks the worktree before it starts,
so a mutation never lands on top of an uncommitted edit.
"""

from __future__ import annotations

import argparse
import ast
import collections
import json
import random
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

# A mutant that breaks the import of a module fails the whole suite. Such a run reports
# no test as measured, so the sweep records it and drops it from the kill sets.
UNUSABLE_KILL_RATIO = 0.9

COMPARE_SWAP = {
    "==": "!=",
    "!=": "==",
    "<=": "<",
    "<": "<=",
    ">=": ">",
    ">": ">=",
    "is not": "is",
    "is": "is not",
    "not in": "in",
    "in": "not in",
}

COMPARE_TOKEN = re.compile(r"not\s+in|is\s+not|==|!=|<=|>=|<|>|\bin\b|\bis\b")

BINOP_SWAP = {
    ast.Add: ("+", "-"),
    ast.Sub: ("-", "+"),
    ast.Mult: ("*", "+"),
    ast.LShift: ("<<", ">>"),
    ast.RShift: (">>", "<<"),
    ast.BitAnd: ("&", "|"),
    ast.BitOr: ("|", "&"),
}


@dataclass
class Mutation:
    """One reversible change to one expression."""

    module: str
    kind: str
    line: int
    before: str
    after: str
    start: int
    end: int
    killed: List[str] = field(default_factory=list)
    status: str = "pending"

    def describe(self) -> str:
        return "{}:{} {} {!r} -> {!r}".format(
            self.module, self.line, self.kind, self.before, self.after
        )

    def record(self) -> Dict[str, object]:
        return {
            "module": self.module,
            "kind": self.kind,
            "line": self.line,
            "before": self.before,
            "after": self.after,
            "status": self.status,
            "killed_count": len(self.killed),
            "killed_sample": sorted(self.killed)[:5],
        }


def _line_starts(source: str) -> List[int]:
    starts = [0]
    for index, char in enumerate(source):
        if char == "\n":
            starts.append(index + 1)
    return starts


def _offset(starts: Sequence[int], line: int, col: int) -> int:
    return starts[line - 1] + col


def _docstring_nodes(tree: ast.AST) -> Set[int]:
    """Return the id of every string node that serves as a docstring."""
    found: Set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", [])
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            if isinstance(body[0].value.value, str):
                found.add(id(body[0].value))
    return found


def _logging_argument_nodes(tree: ast.AST) -> Set[int]:
    """Return the id of every node that a logger call carries.

    A log message reaches no assertion, so a mutation of one measures nothing. The sweep
    spends its runs elsewhere.
    """
    found: Set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        if not isinstance(target, ast.Attribute):
            continue
        owner = target.value
        name = owner.id if isinstance(owner, ast.Name) else getattr(owner, "attr", "")
        if "log" not in str(name).lower():
            continue
        for argument in ast.walk(node):
            found.add(id(argument))
    return found


def _span_swap(
    source: str,
    start: int,
    end: int,
    pattern: "re.Pattern[str]",
    swap: Dict[str, str],
) -> Optional[Tuple[int, int, str, str]]:
    """Find the operator token between two expressions and return its replacement."""
    window = source[start:end]
    match = pattern.search(window)
    if match is None:
        return None
    token = " ".join(match.group(0).split())
    replacement = swap.get(token)
    if replacement is None:
        return None
    return start + match.start(), start + match.end(), token, replacement


def generate_mutations(path: Path, root: Path) -> List[Mutation]:
    """Return every mutation the sweep can apply to one module."""
    source = path.read_text()
    tree = ast.parse(source)
    starts = _line_starts(source)
    skip = _docstring_nodes(tree) | _logging_argument_nodes(tree)
    name = path.relative_to(root).as_posix()
    mutations: List[Mutation] = []

    def add(kind: str, start: int, end: int, after: str) -> None:
        line = source.count("\n", 0, start) + 1
        mutations.append(
            Mutation(
                module=name,
                kind=kind,
                line=line,
                before=source[start:end],
                after=after,
                start=start,
                end=end,
            )
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            left: ast.expr = node.left
            for index, operator in enumerate(node.ops):
                right = node.comparators[index]
                if left.end_lineno is None or left.end_col_offset is None:
                    continue
                found = _span_swap(
                    source,
                    _offset(starts, left.end_lineno, left.end_col_offset),
                    _offset(starts, right.lineno, right.col_offset),
                    COMPARE_TOKEN,
                    COMPARE_SWAP,
                )
                left = right
                if found is not None:
                    add("compare", found[0], found[1], found[3])
        elif isinstance(node, ast.BoolOp):
            swap = {"and": "or", "or": "and"}
            pattern = re.compile(r"\band\b|\bor\b")
            for index in range(len(node.values) - 1):
                first, second = node.values[index], node.values[index + 1]
                if first.end_lineno is None or first.end_col_offset is None:
                    continue
                found = _span_swap(
                    source,
                    _offset(starts, first.end_lineno, first.end_col_offset),
                    _offset(starts, second.lineno, second.col_offset),
                    pattern,
                    swap,
                )
                if found is not None:
                    add("boolop", found[0], found[1], found[3])
        elif isinstance(node, ast.BinOp) and type(node.op) in BINOP_SWAP:
            token, replacement = BINOP_SWAP[type(node.op)]
            if node.left.end_lineno is None or node.left.end_col_offset is None:
                continue
            found = _span_swap(
                source,
                _offset(starts, node.left.end_lineno, node.left.end_col_offset),
                _offset(starts, node.right.lineno, node.right.col_offset),
                re.compile(re.escape(token)),
                {token: replacement},
            )
            if found is not None:
                add("binop", found[0], found[1], found[3])
        elif isinstance(node, ast.Constant) and id(node) not in skip:
            if node.end_lineno is None or node.end_col_offset is None:
                continue
            start = _offset(starts, node.lineno, node.col_offset)
            end = _offset(starts, node.end_lineno, node.end_col_offset)
            value = node.value
            if isinstance(value, bool):
                add("bool", start, end, "False" if value else "True")
            elif isinstance(value, int):
                add("number", start, end, repr(value + 1))
            elif isinstance(value, float):
                add("number", start, end, repr(value + 1.0))
            elif isinstance(value, str) and source[start : start + 1] in "'\"":
                add("string", start, end, repr(value + "_mutated"))
            elif isinstance(value, bytes) and source[start : start + 1] == "b":
                add("bytes", start, end, repr(value + b"\x00"))

    mutations.sort(key=lambda item: (item.start, item.kind))
    return mutations


def sample(mutations: List[Mutation], limit: int, seed: int) -> List[Mutation]:
    """Return at most `limit` mutations, chosen the same way on every run."""
    if limit <= 0 or len(mutations) <= limit:
        return mutations
    chosen = random.Random(seed).sample(range(len(mutations)), limit)
    return [mutations[index] for index in sorted(chosen)]


# pytest prints a failing subtest as `SUBFAILED(hop_count=23) tests/...`, and it prints
# no `FAILED` line for the case that holds it. A pattern that reads `FAILED` alone counts
# a case with subtests as measured by nothing.
FAILURE_LINE = re.compile(r"^(?:FAILED|ERROR|SUBFAIL\w*(?:\([^)]*\))?)\s+(\S+)")


def run_suite(
    root: Path, python: str, pytest_args: Sequence[str], tests: Sequence[str] = ("tests/",)
) -> Tuple[Set[str], int]:
    """Run the suite once and return the failing case names and the exit code."""
    command = [
        python,
        "-m",
        "pytest",
        *tests,
        "-q",
        "--tb=no",
        "-rfE",
        "-p",
        "no:cacheprovider",
    ]
    command.extend(pytest_args)
    finished = subprocess.run(
        command, cwd=str(root), capture_output=True, text=True, check=False
    )
    failures: Set[str] = set()
    for line in finished.stdout.splitlines():
        match = FAILURE_LINE.match(line)
        if match is not None:
            failures.add(match.group(1))
    return failures, finished.returncode


def collect_cases(root: Path, python: str, tests: Sequence[str] = ("tests/",)) -> Set[str]:
    """Return the name of every case the suite collects."""
    finished = subprocess.run(
        [python, "-m", "pytest", *tests, "-q", "--collect-only", "-p", "no:cacheprovider"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    cases = set()
    for line in finished.stdout.splitlines():
        if "::" in line and not line.startswith(" "):
            cases.add(line.strip())
    return cases


def module_paths(root: Path, patterns: Sequence[str]) -> List[Path]:
    paths: List[Path] = []
    for pattern in patterns:
        paths.extend(sorted(root.glob(pattern)))
    return [path for path in paths if path.is_file()]


def markdown_report(report: Dict[str, object]) -> str:
    """Return the report as a page a reader can follow."""
    modules = report["modules"]
    candidates = report["candidates"]
    lines = [
        "# The mutation sweep",
        "",
        "`tests/mutation_sweep.py` writes this page. Never edit it by hand.",
        "",
        "The sweep asks of every case: would this fail if the code were wrong? It changes",
        "one expression in one module, runs the suite, and records which cases fail.",
        "A case that no mutation makes fail is a candidate, and a candidate needs a reader.",
        "A case may be correct and the mutation wrong.",
        "",
        "| Field | Value |",
        "|---|---|",
        "| Date | {} |".format(report["generated"]),
        "| Cases collected | {} |".format(report["cases_collected"]),
        "| Mutations per module | {} |".format(report["max_per_module"] or "every one"),
        "| Sampling seed | {} |".format(report["seed"]),
        "| Tests | `{}` |".format(" ".join(report["tests"])),  # type: ignore[arg-type]
        "| Seconds | {} |".format(report["seconds"]),
        "| Candidates | {} |".format(len(candidates)),  # type: ignore[arg-type]
        "",
        "## What the sweep applied to each module",
        "",
        "| Module | Mutations | Killed | Survived | Unusable |",
        "|---|---|---|---|---|",
    ]
    for entry in modules:  # type: ignore[union-attr]
        found = entry["mutations"]
        counts = collections.Counter(item["status"] for item in found)
        lines.append(
            "| `{}` | {} | {} | {} | {} |".format(
                entry["module"],
                len(found),
                counts["killed"],
                counts["survived"],
                counts["unusable"],
            )
        )
    lines.extend(["", "## Every mutation", ""])
    for entry in modules:  # type: ignore[union-attr]
        lines.extend(
            [
                "### `{}`".format(entry["module"]),
                "",
                "| Line | Kind | Before | After | Result | Cases killed |",
                "|---|---|---|---|---|---|",
            ]
        )
        if not entry["mutations"]:
            lines.append("| — | — | — | — | the module holds no expression to change | 0 |")
        for item in entry["mutations"]:
            lines.append(
                "| {} | {} | `{}` | `{}` | {} | {} |".format(
                    item["line"],
                    item["kind"],
                    item["before"].replace("|", "\\|"),
                    item["after"].replace("|", "\\|"),
                    item["status"],
                    item["killed_count"],
                )
            )
        lines.append("")
    lines.extend(["## Every candidate", ""])
    grouped: Dict[str, List[str]] = {}
    for case in candidates:  # type: ignore[union-attr]
        grouped.setdefault(case.split("::")[0], []).append(case)
    for path in sorted(grouped):
        lines.append("### `{}` — {} candidates".format(path, len(grouped[path])))
        lines.append("")
        for case in grouped[path]:
            lines.append("- `{}`".format(case))
        lines.append("")
    return "\n".join(lines) + "\n"


def parse_arguments(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--module",
        action="append",
        default=None,
        help="A glob below the repository root. It repeats. It defaults to every module.",
    )
    parser.add_argument(
        "--max-per-module",
        type=int,
        default=10,
        help="The mutation count per module. 0 applies every mutation.",
    )
    parser.add_argument("--seed", type=int, default=0, help="The sampling seed.")
    parser.add_argument(
        "--report", default="mutation_sweep.json", help="The path the report is written to."
    )
    parser.add_argument(
        "--python", default=sys.executable, help="The interpreter that runs the suite."
    )
    parser.add_argument(
        "--pytest-arg",
        action="append",
        default=[],
        help="One more argument for every suite run. It repeats.",
    )
    parser.add_argument(
        "--markdown",
        default=None,
        help="The path a readable form of the report is written to.",
    )
    parser.add_argument(
        "--tests",
        action="append",
        default=None,
        help="The path pytest runs. It repeats. Name one test file to confirm a candidate "
        "of that file.",
    )
    parser.add_argument(
        "--checkpoint",
        default="mutation_sweep_checkpoint.jsonl",
        help="The path that holds one result for each mutation. A later run reads it and "
        "runs only the mutations it does not hold.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report the mutation count per module and run no suite.",
    )
    return parser.parse_args(argv)


def checkpoint_key(mutation: Mutation) -> str:
    return "{}|{}|{}|{}".format(mutation.module, mutation.start, mutation.kind, mutation.after)


def read_checkpoint(path: Path) -> Dict[str, Dict[str, object]]:
    """Return the result of every mutation an earlier run finished."""
    if not path.exists():
        return {}
    done: Dict[str, Dict[str, object]] = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        done[str(record["key"])] = record
    return done


def main(argv: Optional[Sequence[str]] = None) -> int:
    options = parse_arguments(argv)
    root = Path(__file__).resolve().parent.parent
    tests = options.tests or ["tests/"]
    patterns = options.module or ["ja4plus/*.py", "ja4plus/*/*.py"]
    paths = module_paths(root, patterns)
    if not paths:
        print("no module matches {}".format(patterns), file=sys.stderr)
        return 2

    plan: List[Tuple[Path, List[Mutation]]] = []
    for path in paths:
        found = generate_mutations(path, root)
        plan.append((path, sample(found, options.max_per_module, options.seed)))

    if options.dry_run:
        for path, chosen in plan:
            print("{}: {} mutations".format(path.relative_to(root).as_posix(), len(chosen)))
        print("total {} runs".format(sum(len(chosen) for _, chosen in plan)))
        return 0

    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--", "ja4plus"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if dirty:
        print("ja4plus/ carries uncommitted changes. Commit or stash them.", file=sys.stderr)
        return 2

    # A stop signal must reach the `finally` that restores the module, so the handler
    # raises instead of ending the process.
    def stop(number, frame):
        raise SystemExit("the sweep received signal {}".format(number))

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)

    started = time.time()
    checkpoint = Path(options.checkpoint)
    done = read_checkpoint(checkpoint)
    if done:
        print("checkpoint: {} mutations already measured".format(len(done)))

    baseline_key = "|baseline|"
    if baseline_key in done:
        baseline = set(done[baseline_key]["failures"])  # type: ignore[arg-type]
        cases = set(done[baseline_key]["cases"])  # type: ignore[arg-type]
    else:
        baseline, _ = run_suite(root, options.python, options.pytest_arg, tests)
        cases = collect_cases(root, options.python, tests)
        with checkpoint.open("a") as handle:
            handle.write(
                json.dumps(
                    {"key": baseline_key, "failures": sorted(baseline), "cases": sorted(cases)}
                )
                + "\n"
            )
    print("baseline: {} cases collected, {} failing".format(len(cases), len(baseline)))

    killers: Dict[str, Set[str]] = {}
    total = sum(len(chosen) for _, chosen in plan)
    index = 0

    for path, chosen in plan:
        original = path.read_text()
        try:
            for mutation in chosen:
                index += 1
                key = checkpoint_key(mutation)
                if key in done:
                    mutation.status = str(done[key]["status"])
                    mutation.killed = list(done[key]["killed"])  # type: ignore[arg-type]
                else:
                    path.write_text(
                        original[: mutation.start] + mutation.after + original[mutation.end :]
                    )
                    failures, _ = run_suite(
                        root, options.python, options.pytest_arg, tests
                    )
                    killed = failures - baseline
                    mutation.killed = sorted(killed)
                    if len(killed) >= UNUSABLE_KILL_RATIO * max(len(cases), 1):
                        mutation.status = "unusable"
                    elif killed:
                        mutation.status = "killed"
                    else:
                        mutation.status = "survived"
                    with checkpoint.open("a") as handle:
                        handle.write(
                            json.dumps(
                                {
                                    "key": key,
                                    "status": mutation.status,
                                    "killed": mutation.killed,
                                }
                            )
                            + "\n"
                        )
                    print(
                        "[{}/{}] {} -> {} ({})".format(
                            index, total, mutation.describe(), mutation.status, len(killed)
                        ),
                        flush=True,
                    )
                if mutation.status != "unusable":
                    for case in mutation.killed:
                        killers.setdefault(case, set()).add(mutation.module)
        finally:
            path.write_text(original)

    candidates = sorted(case for case in cases if case not in killers and case not in baseline)
    report = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "seed": options.seed,
        "max_per_module": options.max_per_module,
        "tests": tests,
        "cases_collected": len(cases),
        "baseline_failures": sorted(baseline),
        "seconds": round(time.time() - started, 1),
        "modules": [
            {
                "module": path.relative_to(root).as_posix(),
                "mutations": [mutation.record() for mutation in chosen],
            }
            for path, chosen in plan
        ],
        "candidates": candidates,
    }
    Path(options.report).write_text(json.dumps(report, indent=2) + "\n")
    if options.markdown:
        Path(options.markdown).write_text(markdown_report(report))
        print("markdown report at {}".format(options.markdown))
    print(
        "{} mutations applied, {} candidate cases, report at {}".format(
            total, len(candidates), options.report
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
