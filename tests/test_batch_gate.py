"""The batch gate fails on an absent run, and it names the cause #459 measured.

**An absent run is not a failed run, and a reader takes it for a pass.** `gh pr checks`
writes "no checks reported" where the pull-request event created nothing, and that line
refuses nothing. The failure this file stops is a batch merged in the belief that the
provider ran the suite.

Every case here reads a payload this file holds, or a file of this repository. No case
reaches the network. No case imports `ja4plus` and no case produces a fingerprint.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.batch_gate import (
    DOCUMENTATION_WORKFLOW,
    REQUIRED_WORKFLOW_PATHS,
    SKIP_KEYWORDS,
    TESTS_WORKFLOW,
    gate_reasons,
    read_runs,
    skip_keywords,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

BATCH_GATE_RULE = REPO_ROOT / ".claude" / "rules" / "batch-gate.md"

REPOSITORY_GUIDE = REPO_ROOT / "CLAUDE.md"

LOOP_CONFIGURATION = REPO_ROOT / ".issue-flow.json"

# The head commit of pull request #444. #459 measured that this commit created no run.
# The sentence that states the commit carries no keyword holds the keyword, and GitHub
# reads the keyword anywhere in the message. This text is evidence, so it stays verbatim.
HEAD_MESSAGE_444 = (
    "chore(changelog): assign rounds 157 to 159 for batch #437\n"
    "\n"
    "This commit carries no `[skip ci]`, so it is the head that starts the full run\n"
    "on the batch pull request.\n"
)

# The head commit of pull request #458, which #459 measured the same way.
HEAD_MESSAGE_458 = (
    "chore(changelog): assign rounds 160 to 163 for batch #445\n"
    "\n"
    "This commit carries no `[skip ci]`, so it is the head that starts the full run\n"
    "on the batch pull request.\n"
)

# The head commit of the epic pull request that did create its runs. It is the control.
CONTROL_MESSAGE = (
    "docs(changelog): assign rounds 145 to 155 for Epic 11\n"
    "\n"
    "Rounds 1 to 155 are contiguous with no gap and no duplicate.\n"
)

HEAD = "b593de5f273fa6ecc62ff5d4ef796953014c899e"

OTHER_HEAD = "2a589ca440a0642fc38df169c4efeb269e3259ac"


def _run(
    path: str = TESTS_WORKFLOW,
    status: str = "completed",
    conclusion: str | None = "success",
    head_sha: str = HEAD,
    created_at: str = "2026-08-09T23:37:51Z",
    name: str = "Tests",
    event: str = "pull_request",
) -> dict:
    """Return one workflow-run object in the shape the provider publishes.

    Args:
        path: The workflow file the run belongs to.
        status: `completed`, `in_progress` or `queued`.
        conclusion: `success`, `failure`, `cancelled`, or None while the run is not
            terminal.
        head_sha: The commit the run read.
        created_at: The creation time, which orders two runs of one workflow.
        name: The display name of the run.
        event: The event that started the run.

    Returns:
        A dictionary with the field names of `GET /repos/{owner}/{repo}/actions/runs`.
    """
    return {
        "path": path,
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "head_sha": head_sha,
        "created_at": created_at,
        "event": event,
    }


def _trigger_block(path: str) -> str:
    """Return the `on:` block of one workflow file, and never a comment above it.

    The header comment of each workflow discusses a pull request in prose, so a search for
    the word alone would read the comment. The block opens at a line that holds `on:` and
    nothing else, and it ends at the first line that starts in column one after it.

    Args:
        path: The workflow file, relative to the repository root.

    Returns:
        The lines of the `on:` block, joined by newlines.

    Raises:
        AssertionError: The file holds no such line, or it holds more than one. A reader
            that guessed here would test a region it did not find, and that case would pass
            on a claim nobody read.
    """
    lines = (REPO_ROOT / path).read_text(encoding="utf-8").splitlines()
    opens = [number for number, line in enumerate(lines) if line.rstrip() == "on:"]
    assert len(opens) == 1, f"{path} holds {len(opens)} lines that read exactly `on:`"
    block: list[str] = []
    for line in lines[opens[0] + 1 :]:
        if line and not line.startswith((" ", "\t", "#")):
            break
        block.append(line)
    return "\n".join(block)


def _pull_request_trigger(path: str) -> str:
    """Return the `pull_request:` trigger of one workflow file.

    Args:
        path: The workflow file, relative to the repository root.

    Returns:
        The lines of the trigger, from `pull_request:` to the next key of the same indent.

    Raises:
        AssertionError: The block holds no `pull_request:` key, or the region the reader
            took holds no `branches:` key. The second check proves the reader found the
            trigger and not a neighboring region.
    """
    block = _trigger_block(path)
    assert "  pull_request:" in block, f"{path} accepts no pull-request event"
    tail = block.split("  pull_request:", 1)[1].splitlines()
    trigger: list[str] = []
    for line in tail:
        if line.startswith("  ") and not line.startswith("    "):
            break
        trigger.append(line)
    joined = "\n".join(trigger)
    assert "branches:" in joined, (
        f"the pull-request trigger this reader took from {path} holds no `branches:` key, so "
        "it read the wrong region and the case that reads it would prove nothing"
    )
    return joined


def _payload(*runs: dict) -> dict:
    """Return a provider response that holds the runs.

    Args:
        runs: The run objects the response carries.

    Returns:
        The response object, with the `workflow_runs` key the provider writes.
    """
    return {"total_count": len(runs), "workflow_runs": list(runs)}


class TestTheKeywordReader:
    """The reader finds every skip keyword the head commit message holds."""

    def test_the_reader_finds_the_keyword_in_a_sentence_that_denies_it(self) -> None:
        """This is the cause #459 measured on pull request #444 and pull request #458.

        The sentence claims the commit carries no keyword, and the claim holds the
        keyword. GitHub matches the text and never the intent.
        """
        assert skip_keywords(HEAD_MESSAGE_444) == ["[skip ci]"]
        assert skip_keywords(HEAD_MESSAGE_458) == ["[skip ci]"]

    def test_the_reader_finds_no_keyword_in_the_control_message(self) -> None:
        """The epic head that created its runs holds no keyword.

        The control matters: a reader that reported a keyword on every message would
        explain both observations and predict nothing.
        """
        assert skip_keywords(CONTROL_MESSAGE) == []

    def test_the_reader_reads_the_body_and_not_the_subject_alone(self) -> None:
        """GitHub reads the whole head commit message, so a body keyword skips the run."""
        assert skip_keywords("feat: add a reader\n\nA body line holds [skip ci].\n") == [
            "[skip ci]"
        ]

    def test_the_reader_finds_every_documented_keyword(self) -> None:
        """Five keywords skip a run, and a reader that knew one would miss four."""
        for keyword in SKIP_KEYWORDS:
            assert skip_keywords(f"chore: a commit\n\n{keyword}\n") == [keyword], keyword

    def test_the_reader_ignores_the_case_of_the_keyword(self) -> None:
        """A reader that matched one case would report an absence it cannot prove.

        The provider documentation states no case rule. The reader therefore reports the
        wider set, because this reader diagnoses a failure and it decides no verdict.
        """
        assert skip_keywords("chore: a commit\n\n[SKIP CI]\n") == ["[skip ci]"]

    def test_the_reader_reports_each_keyword_once(self) -> None:
        """A message that repeats one keyword names one cause."""
        assert skip_keywords("[skip ci] and again [skip ci]") == ["[skip ci]"]

    def test_the_reader_finds_nothing_in_an_empty_message(self) -> None:
        """An empty message holds no keyword, and the reader raises nothing."""
        assert skip_keywords("") == []


class TestTheRunReader:
    """The reader takes the fields of the provider response."""

    def test_the_reader_takes_every_field_of_a_run(self) -> None:
        """The field names come from the documented response of the provider."""
        runs = read_runs(_payload(_run()))
        assert len(runs) == 1
        assert runs[0].workflow_path == TESTS_WORKFLOW
        assert runs[0].workflow_name == "Tests"
        assert runs[0].status == "completed"
        assert runs[0].conclusion == "success"
        assert runs[0].head_sha == HEAD
        assert runs[0].event == "pull_request"

    def test_the_reader_reads_a_run_that_holds_no_conclusion(self) -> None:
        """The provider writes a null conclusion while a run is not terminal."""
        runs = read_runs(_payload(_run(status="in_progress", conclusion=None)))
        assert runs[0].conclusion == ""

    def test_the_reader_reads_a_response_that_holds_no_run(self) -> None:
        """An absent run is the state this file exists for, so the reader returns a list."""
        assert read_runs(_payload()) == []

    def test_the_reader_reads_a_response_that_holds_no_run_key(self) -> None:
        """A response shape the reader does not expect reads as no run, and never as a pass."""
        assert read_runs({}) == []


class TestTheGateVerdict:
    """The gate passes only on a terminal successful run of the head commit."""

    def test_a_terminal_successful_run_passes_the_gate(self) -> None:
        """This is the one state that permits a batch merge."""
        assert gate_reasons(HEAD, read_runs(_payload(_run()))) == []

    def test_an_absent_run_fails_the_gate(self) -> None:
        """#459 is this state. `gh pr checks` reads it as "no checks reported"."""
        reasons = gate_reasons(HEAD, read_runs(_payload()))
        assert reasons != []
        assert any(TESTS_WORKFLOW in reason for reason in reasons)
        assert any(HEAD in reason for reason in reasons)

    def test_a_run_of_another_commit_fails_the_gate(self) -> None:
        """A green run of the previous head proves nothing about this head.

        The provider filters by `head_sha`, and this case holds the rule where a caller
        passes an unfiltered list.
        """
        reasons = gate_reasons(HEAD, read_runs(_payload(_run(head_sha=OTHER_HEAD))))
        assert reasons != []

    def test_a_run_in_progress_fails_the_gate(self) -> None:
        """A run that has not finished reports no result, so the gate refuses the merge."""
        runs = read_runs(_payload(_run(status="in_progress", conclusion=None)))
        reasons = gate_reasons(HEAD, runs)
        assert reasons != []
        assert any("in_progress" in reason for reason in reasons)

    def test_a_queued_run_fails_the_gate(self) -> None:
        """A queued run is not a terminal run."""
        reasons = gate_reasons(HEAD, read_runs(_payload(_run(status="queued", conclusion=None))))
        assert reasons != []

    @pytest.mark.parametrize("conclusion", ["failure", "cancelled", "timed_out", "action_required"])
    def test_a_run_that_did_not_succeed_fails_the_gate(self, conclusion: str) -> None:
        """Only `success` passes, so a new provider conclusion fails rather than passes.

        Args:
            conclusion: A terminal conclusion the provider writes that is not `success`.
        """
        reasons = gate_reasons(HEAD, read_runs(_payload(_run(conclusion=conclusion))))
        assert reasons != []
        assert any(conclusion in reason for reason in reasons)

    def test_a_skipped_run_fails_the_gate(self) -> None:
        """A skipped run is the shape a skip keyword produces where it produces a run.

        `success` is the one conclusion that proves the suite ran, and `skipped` proves
        the opposite while it still reads as a terminal run.
        """
        reasons = gate_reasons(HEAD, read_runs(_payload(_run(conclusion="skipped"))))
        assert reasons != []

    def test_the_newest_run_of_one_workflow_decides(self) -> None:
        """A re-run that succeeded after a failure passes, because a person read the fix."""
        runs = read_runs(
            _payload(
                _run(conclusion="failure", created_at="2026-08-09T23:00:00Z"),
                _run(conclusion="success", created_at="2026-08-09T23:30:00Z"),
            )
        )
        assert gate_reasons(HEAD, runs) == []

    def test_a_failure_after_a_success_fails_the_gate(self) -> None:
        """The rule reads the newest run in both directions, and not the best run."""
        runs = read_runs(
            _payload(
                _run(conclusion="success", created_at="2026-08-09T23:00:00Z"),
                _run(conclusion="failure", created_at="2026-08-09T23:30:00Z"),
            )
        )
        assert gate_reasons(HEAD, runs) != []

    def test_a_red_run_of_an_unrequired_workflow_fails_the_gate(self) -> None:
        """`Documentation` runs on a path filter, so the gate requires no run of it.

        A run that exists and failed is a different statement from an absent run, and the
        gate refuses the merge on it.
        """
        runs = read_runs(
            _payload(
                _run(),
                _run(path=DOCUMENTATION_WORKFLOW, name="Documentation", conclusion="failure"),
            )
        )
        reasons = gate_reasons(HEAD, runs)
        assert reasons != []
        assert any(DOCUMENTATION_WORKFLOW in reason for reason in reasons)

    def test_an_absent_run_of_an_unrequired_workflow_passes_the_gate(self) -> None:
        """`Documentation` reads a path filter, so a batch that touches no such path runs it
        never."""
        assert gate_reasons(HEAD, read_runs(_payload(_run()))) == []

    def test_an_empty_required_set_fails_the_gate(self) -> None:
        """**An aggregate over an empty set passes**, so the floor is a case of its own.

        A required set emptied by an edit would make the gate pass on every input, which
        is the failure this whole file exists to stop.
        """
        assert gate_reasons(HEAD, read_runs(_payload()), required=()) != []

    def test_an_unknown_head_commit_fails_the_gate(self) -> None:
        """A caller that read no head commit cannot compare a run against it."""
        assert gate_reasons("", read_runs(_payload())) != []

    def test_two_runs_of_one_time_break_the_tie_toward_a_refusal(self) -> None:
        """A push event and a pull-request event can reach one commit at one second.

        `max` returns the first of several equal keys, so the order of the response would
        otherwise decide the verdict. A gate that reported a green run on an ordering
        accident is the failure this whole file stops, so the tie refuses the merge.
        """
        red = _run(conclusion="failure", created_at="2026-08-09T23:37:51Z")
        green = _run(conclusion="success", created_at="2026-08-09T23:37:51Z")
        assert gate_reasons(HEAD, read_runs(_payload(red, green))) != []
        assert gate_reasons(HEAD, read_runs(_payload(green, red))) != []

    def test_an_older_red_run_moves_no_verdict(self) -> None:
        """The tie rule reaches one creation time alone, and it is no rule about every run."""
        runs = read_runs(
            _payload(
                _run(conclusion="failure", created_at="2026-08-09T22:00:00Z"),
                _run(conclusion="success", created_at="2026-08-09T23:00:00Z"),
            )
        )
        assert gate_reasons(HEAD, runs) == []

    def test_the_upper_form_of_a_commit_identifier_reads_the_same_run(self) -> None:
        """The provider writes the lower form, and the upper form must match no absence.

        A caller that passed the upper form would otherwise read an absent run for a
        commit that holds a green one, which sends a reader after a cause that is not there.
        """
        assert gate_reasons(HEAD.upper(), read_runs(_payload(_run()))) == []

    def test_a_head_commit_that_is_no_commit_identifier_fails_the_gate(self) -> None:
        """An abbreviated identifier fails, because the provider writes the full form.

        A comparison of `b593de5` against `b593de5f27...` matches nothing, and it would
        report an absent run for every head.
        """
        assert gate_reasons("b593de5", read_runs(_payload(_run()))) != []


class TestTheGateNamesTheCause:
    """A failure on an absent run names the keyword that explains it."""

    def test_the_gate_names_the_keyword_when_no_run_exists(self) -> None:
        """A reader of the failure reaches the cause without a second investigation."""
        reasons = gate_reasons(HEAD, read_runs(_payload()), head_message=HEAD_MESSAGE_458)
        assert any("[skip ci]" in reason for reason in reasons)
        assert any("#459" in reason for reason in reasons)

    def test_the_gate_names_no_keyword_when_a_run_exists_and_failed(self) -> None:
        """A red run has a cause in its log, and the keyword explains an absence alone."""
        reasons = gate_reasons(
            HEAD,
            read_runs(_payload(_run(conclusion="failure"))),
            head_message=HEAD_MESSAGE_458,
        )
        assert reasons != []
        assert not any("[skip ci]" in reason for reason in reasons)

    def test_the_gate_states_no_cause_where_the_message_holds_no_keyword(self) -> None:
        """An absent run with a clean head message is the state #85 recorded."""
        reasons = gate_reasons(HEAD, read_runs(_payload()), head_message=CONTROL_MESSAGE)
        assert reasons != []
        assert not any("[skip ci]" in reason for reason in reasons)


class TestTheWorkflowFilesHoldTheClaimsTheGateMakes:
    """The required set rests on two readings of `.github/workflows/`, and both are read."""

    def test_every_required_workflow_file_exists(self) -> None:
        """A required path that names no file would fail every gate for the wrong reason."""
        for path in REQUIRED_WORKFLOW_PATHS:
            assert (REPO_ROOT / path).is_file(), f"{path} names no file"

    def test_the_required_workflow_reads_no_path_filter(self) -> None:
        """`Tests` runs on every pull request into `dev`, which is why the gate requires it.

        A `paths` filter added to that trigger would make the run conditional, and the
        gate would then demand a run the provider never creates.
        """
        trigger = _pull_request_trigger(TESTS_WORKFLOW)
        assert "paths:" not in trigger, (
            f"{TESTS_WORKFLOW} filters its pull-request trigger by path, so the gate can no "
            "longer require a run of it"
        )

    def test_the_unrequired_workflow_reads_a_path_filter(self) -> None:
        """`Documentation` runs on a path filter, which is the reason the gate requires none."""
        trigger = _pull_request_trigger(DOCUMENTATION_WORKFLOW)
        assert "paths:" in trigger, (
            f"{DOCUMENTATION_WORKFLOW} filters no pull-request trigger by path, so the gate "
            "may require a run of it"
        )

    def test_the_workflow_comment_states_the_measured_cause(self) -> None:
        """The comment named a throttle it never measured, and #459 measured a keyword.

        The comment of #85 read that a throttled webhook path creates no run. That is a
        guess, and a reader who took it looked for a provider fault rather than the head
        commit message.
        """
        text = (REPO_ROOT / TESTS_WORKFLOW).read_text(encoding="utf-8")
        header = text.split("\non:\n", 1)[0]
        assert header != text, f"{TESTS_WORKFLOW} holds no line that reads exactly `on:`"
        assert "#459" in header, f"{TESTS_WORKFLOW} records no cause for an absent run"
        assert "skip ci" in header, (
            f"{TESTS_WORKFLOW} names no skip keyword, so a reader of an absent run reaches no cause"
        )


class TestTheProcedureReachesTheLoop:
    """A procedure that lives in a closed issue is a procedure nobody runs."""

    def test_the_rule_file_exists(self) -> None:
        """`.claude/rules/` is a directory the loop reads before it works."""
        assert BATCH_GATE_RULE.is_file(), f"{BATCH_GATE_RULE} holds no procedure"

    def test_the_rule_names_the_command_that_reads_the_gate(self) -> None:
        """A procedure that states no command leaves a reader to invent one."""
        text = BATCH_GATE_RULE.read_text(encoding="utf-8")
        assert "python -m tests.batch_gate" in text, (
            f"{BATCH_GATE_RULE.name} names no command, so the condition it describes runs never"
        )

    def test_the_rule_states_the_cause_and_the_two_measurements(self) -> None:
        """A rule that stated the remedy alone would lose the evidence behind it."""
        text = BATCH_GATE_RULE.read_text(encoding="utf-8")
        for fact in ["#459", "#444", "#458", "skip ci"]:
            assert fact in text, f"{BATCH_GATE_RULE.name} states no {fact}"

    def test_the_rule_names_every_job_of_the_required_workflow(self) -> None:
        """The branch-protection list must reach every job, or it guards a subset in silence.

        A job added to `.github/workflows/test.yml` publishes a check that the required
        list does not hold, and a merge then passes while that job is red. The first form
        of this rule named `test` as a check, and the provider publishes one check for each
        matrix combination instead, so a required `test` would have matched nothing.
        """
        workflow = (REPO_ROOT / TESTS_WORKFLOW).read_text(encoding="utf-8")
        body = workflow.split("\njobs:", 1)[1]
        # A job key opens a line with two spaces and it ends with a colon. A step key of a
        # job sits deeper, so the indent tells the two apart.
        jobs = [
            line.strip().rstrip(":")
            for line in body.splitlines()
            if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":")
        ]
        assert len(jobs) >= 6, f"{TESTS_WORKFLOW} reports {len(jobs)} jobs, which reads too few"
        text = BATCH_GATE_RULE.read_text(encoding="utf-8")
        missing = [job for job in jobs if job not in text]
        assert missing == [], (
            f"{BATCH_GATE_RULE.name} names no required check for these jobs of "
            f"{TESTS_WORKFLOW}: {missing}"
        )

    def test_the_rule_bars_the_keyword_from_a_head_commit_message(self) -> None:
        """The cause repeats where nothing bars the sentence that produced it."""
        text = BATCH_GATE_RULE.read_text(encoding="utf-8")
        assert "commit message" in text, (
            f"{BATCH_GATE_RULE.name} states no rule about a commit message, so the cause "
            "#459 measured repeats"
        )

    def test_the_repository_guide_names_the_rule(self) -> None:
        """`CLAUDE.md` loads on every session, and it is the path to every other rule."""
        text = REPOSITORY_GUIDE.read_text(encoding="utf-8")
        assert ".claude/rules/batch-gate.md" in text, (
            "CLAUDE.md names no batch-gate rule, so a reader of that file reaches no procedure"
        )

    def test_the_loop_configuration_names_the_rule(self) -> None:
        """The configuration held the false claim that a batch pull request starts a run.

        That sentence is the belief that turns an absence into a pass, so the file now
        names the rule instead of asserting the behavior.
        """
        notes = " ".join(json.loads(LOOP_CONFIGURATION.read_text(encoding="utf-8"))["notes"])
        assert ".claude/rules/batch-gate.md" in notes, (
            f"{LOOP_CONFIGURATION.name} names no batch-gate rule"
        )


class TestTheCommand:
    """The command exits non-zero on every state that is not a proven green run."""

    def _invoke(self, tmp_path: Path, payload: dict, message: str) -> subprocess.CompletedProcess:
        """Run the command against a payload on disk, so no case reaches the network.

        Args:
            tmp_path: The directory the fixture files go in.
            payload: The provider response the command reads.
            message: The head commit message the command reads.

        Returns:
            The finished process, with its output captured.
        """
        runs_file = tmp_path / "runs.json"
        runs_file.write_text(json.dumps(payload), encoding="utf-8")
        message_file = tmp_path / "message.txt"
        message_file.write_text(message, encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "tests.batch_gate",
                "--head-sha",
                HEAD,
                "--runs-file",
                str(runs_file),
                "--message-file",
                str(message_file),
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )

    def test_the_command_exits_zero_on_a_terminal_successful_run(self, tmp_path: Path) -> None:
        """The one green state, and the only one that permits a batch merge.

        Args:
            tmp_path: The fixture directory `pytest` provides.
        """
        finished = self._invoke(tmp_path, _payload(_run()), CONTROL_MESSAGE)
        assert finished.returncode == 0, finished.stdout + finished.stderr

    def test_the_command_exits_nonzero_on_an_absent_run(self, tmp_path: Path) -> None:
        """The state #459 measured, and the reason this command exists.

        Args:
            tmp_path: The fixture directory `pytest` provides.
        """
        finished = self._invoke(tmp_path, _payload(), HEAD_MESSAGE_458)
        assert finished.returncode != 0
        assert "[skip ci]" in finished.stdout + finished.stderr

    def test_the_command_exits_nonzero_on_a_red_run(self, tmp_path: Path) -> None:
        """A red run refuses the merge as plainly as an absent run.

        Args:
            tmp_path: The fixture directory `pytest` provides.
        """
        finished = self._invoke(tmp_path, _payload(_run(conclusion="failure")), CONTROL_MESSAGE)
        assert finished.returncode != 0
