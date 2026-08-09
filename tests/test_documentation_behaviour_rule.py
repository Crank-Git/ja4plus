"""Check that every documentation-test command the specification names collects cases.

#393 states the defect. The Behaviour rules of `docs/specs/features/08-documentation.md`
named `pytest --doctest-glob="*.md" README.md docs/`, and that command collects nothing
and exits with the status 5. `--doctest-glob` collects an interactive session, written as
`>>>` lines above the expected output, and every code sample of this project is a fenced
code block. The two forms share nothing, so the rule named no check at all, and a reader
of the feature file believed the rule covered the samples.

`docs/specs/spec.md` named the same command in its Testing strategy table, so the defect
lived in two files. #63 built `tests/test_documentation_samples.py` and stopped at the
rule rather than editing the specification inside a feature diff.

Four groups of cases guard the amendment.

1. The command cases run every `pytest` command the two records name, and require each one
   to collect at least one case.
2. The floor case requires the Behaviour rules to name one such command. An aggregate
   over an empty set passes, so a rule somebody deletes would satisfy group 1 alone.
3. The discrimination cases prove the measurement fails where it must. The doctest command
   collects nothing today, and the counter reads zero for a file that holds no case.
4. The reader cases prove three failures of the prose reader. It fails on an absent
   sentence, on a repeated sentence, and on the text the rules held before this round.

These cases read prose and run pytest collection in a subprocess. They import nothing
from `ja4plus` and they produce no fingerprint.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

FEATURE_PAGE = REPOSITORY_ROOT / "docs" / "specs" / "features" / "08-documentation.md"
SPECIFICATION = REPOSITORY_ROOT / "docs" / "specs" / "spec.md"

# The sentence of the Behaviour rules that names the command for FR-documentation-4 and
# FR-documentation-5. The reader takes the command out of the backticks, so a case runs the
# text a reader of the page runs.
SAMPLE_COMMAND = re.compile(r"`(pytest [^`]+)` runs every code sample of the README and of")

# The sentence of the Behaviour rules that names the command for FR-documentation-6.
SCRIPT_COMMAND = re.compile(r"`(pytest [^`]+)` runs every script of")

# The Documentation row of the Testing strategy table of `docs/specs/spec.md`. The row
# named the doctest command until #393, and a case reads it so that the second copy of the
# defect cannot come back alone.
STRATEGY_ROW = re.compile(
    r"\| Documentation \| Every code sample in the README and in `docs/`\. \| `(pytest [^`]+)` \|"
)

# The reason that records why this project keeps the fenced form. #393 states the
# requirement: a later reader will otherwise propose the doctest form again.
#
# The reason takes two clauses, and a reader that took the first alone would accept a
# sentence that reverses the claim. A sentence holding "collects an interactive session"
# and no consequence states what the option does and refuses nothing.
REFUSAL_REASON = re.compile(
    r"`--doctest-glob` option collects an interactive session", re.IGNORECASE
)
REFUSAL_CONSEQUENCE = re.compile(r"that option collects nothing here", re.IGNORECASE)

# Every backticked span of the Behaviour rules that opens a pytest command. Group 1 reads
# the whole command, so a rewording that keeps the command reaches the command cases.
PYTEST_SPAN = re.compile(r"`(pytest\s[^`]+)`")

# The summary line of a pytest collection run. `--collect-only -q` writes one node
# identifier per line and then this line. The reader parses the count and never greps it,
# because a page that holds the words `0 tests collected` would match a substring search.
COLLECTED_SUMMARY = re.compile(r"^(\d+) tests? collected", re.MULTILINE)

# pytest exits with this status when a command collects no case at all. The doctest command
# of the old rule exits with it.
EXIT_NO_TESTS_COLLECTED = 5


def flatten(path: Path) -> str:
    """Return the text of one page with every run of whitespace as one space.

    The Behaviour rules wrap at 90 columns, so a sentence spans two lines. A reader that
    matched a line would miss every wrapped sentence, which is the parser fault that #302
    recorded.

    Args:
        path: The Markdown file to read.

    Returns:
        The whole text of the page on one line.
    """
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


def behaviour_rules(path: Path) -> str:
    """Return the Behaviour rules section of one feature page, flattened.

    Args:
        path: The feature page to read.

    Returns:
        The text between the `## Behaviour rules` heading and the next heading of the same
        level, with every run of whitespace as one space.

    Raises:
        ValueError: The page holds no `## Behaviour rules` heading.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    opening = None
    for number, line in enumerate(lines):
        if line.strip() == "## Behaviour rules":
            opening = number + 1
            break
    if opening is None:
        raise ValueError(f"{path.name} holds no '## Behaviour rules' heading")
    closing = len(lines)
    for number in range(opening, len(lines)):
        if lines[number].startswith("## "):
            closing = number
            break
    return re.sub(r"\s+", " ", " ".join(lines[opening:closing]))


def stated_command(document: str, pattern: re.Pattern[str], subject: str) -> str:
    """Return the one command a document states for one subject.

    Args:
        document: The flattened text to read.
        pattern: The sentence pattern, whose first group reads the command.
        subject: The name of the subject, for the failure message.

    Returns:
        The verbatim command the sentence names.

    Raises:
        ValueError: The document states the command for that subject on no sentence, or on
            more than one sentence.
    """
    matches = pattern.findall(document)
    if len(matches) != 1:
        raise ValueError(
            f"the document names the command for {subject} on {len(matches)} sentences, "
            "and it names it on one"
        )
    return matches[0]


def collect(command: str) -> Tuple[int, int]:
    """Return the case count and the exit status of one pytest command under collection.

    The command runs with `--collect-only`, so it collects the cases and runs none of them.
    A collection run of the whole documentation harness costs under one second.

    Args:
        command: A command line that opens with the word `pytest`.

    Returns:
        The count of cases the run collected, then the exit status of the run.

    Raises:
        ValueError: The command does not open with the word `pytest`.
    """
    arguments = shlex.split(command)
    if not arguments or arguments[0] != "pytest":
        raise ValueError(f"the command {command!r} does not open with the word 'pytest'")
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    # `PYTEST_ADDOPTS` of the parent environment would reach this run and change the summary
    # line, so a coverage option or an xdist option would break the parse for a reason that
    # has nothing to do with the rule under test.
    environment.pop("PYTEST_ADDOPTS", None)
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"]
        + arguments[1:],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        env=environment,
    )
    if completed.returncode == EXIT_NO_TESTS_COLLECTED:
        return 0, completed.returncode
    summary = COLLECTED_SUMMARY.search(completed.stdout)
    if summary is None:
        # A usage error exits 4 and writes the diagnostic to standard error, so a message
        # that carried standard output alone would name no reason.
        raise AssertionError(
            f"the collection run of {command!r} wrote no summary line. "
            f"Its exit status is {completed.returncode}, its standard output is:\n"
            f"{completed.stdout}\nand its standard error is:\n{completed.stderr}"
        )
    return int(summary.group(1)), completed.returncode


def stated_pytest_commands(document: str) -> List[str]:
    """Return every pytest command a flattened document names inside backticks.

    Args:
        document: The flattened text to read.

    Returns:
        One command for each backticked span that opens with the word `pytest`, in the
        order the document holds them.
    """
    return PYTEST_SPAN.findall(document)


class TestTheCommandsTheRecordsName:
    """Check that every pytest command the two records name collects at least one case.

    #393 states the requirement: every rule that names a command names one that runs
    today. A command that collects nothing exits with the status 5, which is the state the
    doctest command of the old rule reached.
    """

    def test_the_behaviour_rules_name_a_sample_command_that_collects_cases(self) -> None:
        command = stated_command(behaviour_rules(FEATURE_PAGE), SAMPLE_COMMAND, "the code samples")
        count, status = collect(command)
        assert status != EXIT_NO_TESTS_COLLECTED, f"{command!r} collected nothing"
        assert count > 0, f"{command!r} collected {count} cases"

    def test_the_behaviour_rules_name_a_script_command_that_collects_cases(self) -> None:
        command = stated_command(
            behaviour_rules(FEATURE_PAGE), SCRIPT_COMMAND, "the example scripts"
        )
        count, status = collect(command)
        assert status != EXIT_NO_TESTS_COLLECTED, f"{command!r} collected nothing"
        assert count > 0, f"{command!r} collected {count} cases"

    def test_the_testing_strategy_table_names_a_command_that_collects_cases(self) -> None:
        """The Documentation row of `docs/specs/spec.md` names an instrument that runs.

        The row held the doctest command too, so the amendment repairs one defect in two
        files. A case reads the row, so the second copy cannot return alone.
        """
        command = stated_command(flatten(SPECIFICATION), STRATEGY_ROW, "the Documentation layer")
        count, status = collect(command)
        assert status != EXIT_NO_TESTS_COLLECTED, f"{command!r} collected nothing"
        assert count > 0, f"{command!r} collected {count} cases"

    def test_every_pytest_command_the_behaviour_rules_name_collects_cases(self) -> None:
        """Every backticked pytest command of the Behaviour rules collects at least one case.

        The three cases above read three named sentences, and a fourth rule could name a
        fourth command. This case reads them all, so a new rule that names a dead command
        fails here whatever sentence carries it.
        """
        empty = [
            command
            for command in stated_pytest_commands(behaviour_rules(FEATURE_PAGE))
            if collect(command)[0] == 0
        ]
        assert empty == [], (
            f"the Behaviour rules name these commands, and each collects nothing: {empty}"
        )


class TestTheBehaviourRulesNameOneCommand:
    """Check that the Behaviour rules name at least one pytest command.

    `test_every_pytest_command_the_behaviour_rules_name_collects_cases` reads an aggregate,
    and an aggregate over an empty set passes. A rule somebody deletes would satisfy it in
    silence. This floor fails that change set.
    """

    def test_the_behaviour_rules_name_at_least_one_pytest_command(self) -> None:
        commands = stated_pytest_commands(behaviour_rules(FEATURE_PAGE))
        assert len(commands) >= 2, (
            f"the Behaviour rules name {len(commands)} pytest commands, and the floor is 2: "
            f"{commands}"
        )


class TestTheRulesRecordWhyTheFencedFormStays:
    """Check that the Behaviour rules record why this project keeps the fenced form.

    #393 requires the reason in the rule and not the command alone. A later reader will
    otherwise propose the doctest form again, and a rewrite of 44 fenced samples would buy
    no coverage the harness already provides.

    The reason takes two clauses, and each case below reads both. A reader of the first
    clause alone would accept a sentence that reverses the claim, because the words
    `collects an interactive session` state what the option does and refuse nothing.
    """

    def test_the_behaviour_rules_state_that_the_doctest_option_reads_a_session(self) -> None:
        rules = behaviour_rules(FEATURE_PAGE)
        assert REFUSAL_REASON.search(rules) is not None, (
            "the Behaviour rules state no reading of the `--doctest-glob` option"
        )

    def test_the_behaviour_rules_state_that_the_doctest_option_collects_nothing_here(
        self,
    ) -> None:
        rules = behaviour_rules(FEATURE_PAGE)
        assert REFUSAL_CONSEQUENCE.search(rules) is not None, (
            "the Behaviour rules state no consequence for the `--doctest-glob` option"
        )

    def test_the_reader_of_the_reason_rejects_a_document_that_states_it_nowhere(self) -> None:
        """The reader reports an absent reason, so a deletion fails rather than passes."""
        document = "A code sample is tested by `pytest --doctest-glob`."
        assert REFUSAL_REASON.search(document) is None
        assert REFUSAL_CONSEQUENCE.search(document) is None

    def test_the_reader_of_the_reason_rejects_a_sentence_that_states_no_consequence(
        self,
    ) -> None:
        """The reader rejects a sentence that reads the option and refuses nothing.

        A reader of the first clause alone would accept this text, and the text records no
        reason to keep the fenced form.
        """
        document = (
            "The `--doctest-glob` option collects an interactive session, and this project uses it."
        )
        assert REFUSAL_REASON.search(document) is not None
        assert REFUSAL_CONSEQUENCE.search(document) is None


class TestTheMeasurementDiscriminates:
    """Check that the collection measurement fails where it must.

    A check that reports the same result for the right command and the wrong one is no
    check. These cases prove both directions of `collect`.
    """

    def test_the_doctest_command_of_the_old_rule_collects_nothing(self) -> None:
        """The command the old rule named collects no case and exits with the status 5.

        This is the measurement #393 records, and it is the reason the amendment exists. A
        day this case fails is a day the documentation grew a doctest session, and the
        rules then need a reading rather than a floor.
        """
        count, status = collect('pytest --doctest-glob="*.md" README.md docs/')
        assert count == 0
        assert status == EXIT_NO_TESTS_COLLECTED

    def test_the_measurement_reads_zero_for_a_path_that_holds_no_case(self, tmp_path: Path) -> None:
        """The counter reads zero for a file that holds no case.

        A counter that reported a positive count for every command would pass the
        instrument cases on any text at all.
        """
        empty = tmp_path / "test_nothing_at_all.py"
        empty.write_text("", encoding="utf-8")
        count, status = collect(f"pytest {shlex.quote(str(empty))}")
        assert count == 0
        assert status == EXIT_NO_TESTS_COLLECTED

    def test_the_measurement_reads_the_cases_one_known_file_holds(self) -> None:
        """The counter reads a positive count for a file that holds cases."""
        count, status = collect("pytest tests/test_examples.py")
        assert count > 0
        assert status != EXIT_NO_TESTS_COLLECTED

    def test_the_measurement_rejects_a_command_that_names_another_program(self) -> None:
        with pytest.raises(ValueError, match="does not open with the word 'pytest'"):
            collect("mkdocs build --strict")


class TestTheReaderOfTheRule:
    """Check that the prose reader fails on an absent, a repeated and a stale sentence.

    #380 proved the same four directions on the precedence exception. A reader that
    returned a default for an absent sentence would report green on a page that names no
    instrument.
    """

    def test_the_reader_reads_the_sample_command_a_sentence_states(self) -> None:
        document = (
            "- `pytest tests/test_documentation_samples.py` runs every code sample of the "
            "README and of `docs/`."
        )
        assert (
            stated_command(document, SAMPLE_COMMAND, "the code samples")
            == "pytest tests/test_documentation_samples.py"
        )

    def test_the_reader_reads_the_script_command_a_sentence_states(self) -> None:
        document = "- `pytest tests/test_examples.py` runs every script of `examples/`."
        assert (
            stated_command(document, SCRIPT_COMMAND, "the example scripts")
            == "pytest tests/test_examples.py"
        )

    def test_the_reader_rejects_a_document_that_states_the_command_nowhere(self) -> None:
        with pytest.raises(ValueError, match="on 0 sentences"):
            stated_command("The samples run in continuous integration.", SAMPLE_COMMAND, "x")

    def test_the_reader_rejects_the_text_the_rules_held_before_this_round(self) -> None:
        """The reader rejects the sentence #393 replaced.

        The check fails on the wrong text as well as on no text. `pytest --doctest-glob`
        names the option and no path, so the sentence states no instrument a reader runs.
        """
        document = (
            "- A code sample is tested by `pytest --doctest-glob`. A sample that cannot run "
            "in continuous integration, because it needs a capture interface, is marked and "
            "excluded, and the marker names the reason."
        )
        with pytest.raises(ValueError, match="on 0 sentences"):
            stated_command(document, SAMPLE_COMMAND, "the code samples")

    def test_the_reader_rejects_a_document_that_states_the_command_twice(self) -> None:
        document = (
            "`pytest a.py` runs every code sample of the README and of `docs/`. "
            "`pytest b.py` runs every code sample of the README and of `docs/`."
        )
        with pytest.raises(ValueError, match="on 2 sentences"):
            stated_command(document, SAMPLE_COMMAND, "the code samples")

    def test_the_section_reader_rejects_a_page_that_holds_no_behaviour_rules(
        self, tmp_path: Path
    ) -> None:
        page = tmp_path / "99-nothing.md"
        page.write_text("## Purpose\n\nA page with no rules.\n", encoding="utf-8")
        with pytest.raises(ValueError, match="holds no '## Behaviour rules' heading"):
            behaviour_rules(page)

    def test_the_section_reader_stops_at_the_next_heading(self, tmp_path: Path) -> None:
        """The section reader returns the rules alone, and no later section.

        A reader that ran to the end of the file would find the Acceptance criteria too,
        and a command named there would satisfy a case about the Behaviour rules.
        """
        page = tmp_path / "99-two-sections.md"
        page.write_text(
            "## Behaviour rules\n\n- `pytest inside.py` runs.\n\n"
            "## Acceptance criteria\n\n- `pytest outside.py` passes.\n",
            encoding="utf-8",
        )
        assert stated_pytest_commands(behaviour_rules(page)) == ["pytest inside.py"]
