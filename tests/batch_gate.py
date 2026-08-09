"""The batch gate reads a terminal run of the head commit, and an absence fails.

**An absent run is not a failed run.** `gh pr checks` writes "no checks reported" where
the pull-request event created nothing, and that line refuses no merge. #459 records the
failure: a batch merged in the belief that the provider ran the suite. Every member
commit carries a skip keyword by design, so the batch pull request is the first run of a
member's cases on Linux.

**The cause #459 measured is the head commit message.** Pull request #444 and pull
request #458 each created no run from the pull-request event. Both head commit messages
hold the literal keyword `[skip ci]`, inside the sentence
`This commit carries no `[skip ci]`, so it is the head that starts the full run`. GitHub
matches the text and never the intent. The two control heads `ec697c0e` and `b21604ce`
hold no keyword, and both created their runs. A manual run on each failing ref started
every job and all passed, which proves the provider refused neither the repository nor
the workflow.

Verified against
https://docs.github.com/en/actions/how-tos/manage-workflow-runs/skip-workflow-runs
(retrieved 2026-08-09), which states that a keyword anywhere in the head commit message
of a pull request creates no run for a push event or a pull-request event. The run reader
uses `GET /repos/{owner}/{repo}/actions/runs`, verified against
https://docs.github.com/en/rest/actions/workflow-runs (API version 2022-11-28, retrieved
2026-08-09), which documents the `head_sha` parameter and the `path`, `status`,
`conclusion`, `head_sha`, `event` and `created_at` fields.

`.claude/rules/batch-gate.md` states the procedure. This file holds the condition, and
`tests/test_batch_gate.py` holds this file. It imports nothing from `ja4plus` and it
produces no fingerprint.

Read the gate against one pull request:

```bash
python -m tests.batch_gate --pr 460
```
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent

# The repository the gate reads. `.issue-flow.json` holds the same pair, and a gate that
# read a second repository would report a green run of somebody else's code.
REPOSITORY = "Crank-Git/ja4plus"

TESTS_WORKFLOW = ".github/workflows/test.yml"

DOCUMENTATION_WORKFLOW = ".github/workflows/docs-build.yml"

# `Tests` accepts every pull request into `dev` and it filters no path, so the provider
# creates a run of it for every batch pull request. `Documentation` filters four paths, so
# a batch that touches none of them creates no run of it and an absence proves nothing.
# `tests/test_batch_gate.py` reads both trigger blocks, so a new path filter on `Tests`
# fails a case rather than making this gate demand a run nobody creates.
REQUIRED_WORKFLOW_PATHS = (TESTS_WORKFLOW,)

# The keywords the provider documentation lists. A reader that knew one would miss four.
SKIP_KEYWORDS = (
    "[skip ci]",
    "[ci skip]",
    "[no ci]",
    "[skip actions]",
    "[actions skip]",
)

# The provider writes a full 40-character identifier, so a comparison against an
# abbreviated form matches nothing and reports an absent run for every head.
COMMIT_IDENTIFIER = re.compile(r"^[0-9a-f]{40}$")

# `success` is the one conclusion that proves the suite ran and passed. `skipped` is the
# shape a skip keyword produces where it produces a run at all, and it reads as terminal.
PASSING_CONCLUSION = "success"

TERMINAL_STATUS = "completed"


@dataclass(frozen=True)
class WorkflowRun:
    """One workflow run of the provider, reduced to the fields the gate reads."""

    workflow_path: str
    workflow_name: str
    status: str
    conclusion: str
    head_sha: str
    event: str
    created_at: str


def skip_keywords(message: str) -> list[str]:
    """Return every skip keyword the commit message holds, with no duplicate.

    The reader ignores the case of the keyword. The provider documentation states no case
    rule, so the reader reports the wider set. It decides no verdict: it explains an
    absent run, and `gate_reasons` reads the run list for the verdict itself.

    Args:
        message: A whole commit message, subject and body.

    Returns:
        The keywords the message holds, in the order `SKIP_KEYWORDS` lists them.
    """
    folded = message.lower()
    return [keyword for keyword in SKIP_KEYWORDS if keyword in folded]


def read_runs(payload: object) -> list[WorkflowRun]:
    """Return every workflow run of one provider response.

    A response shape the reader does not expect produces no run. That reads as an absent
    run, which fails the gate, and never as a pass.

    Args:
        payload: The object `GET /repos/{owner}/{repo}/actions/runs` returned.

    Returns:
        One `WorkflowRun` for each entry of `workflow_runs`.
    """
    if not isinstance(payload, dict):
        return []
    entries = payload.get("workflow_runs")
    if not isinstance(entries, list):
        return []
    runs: list[WorkflowRun] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        runs.append(
            WorkflowRun(
                workflow_path=str(entry.get("path") or ""),
                workflow_name=str(entry.get("name") or ""),
                status=str(entry.get("status") or ""),
                # The provider writes a null conclusion while a run is not terminal.
                conclusion=str(entry.get("conclusion") or ""),
                head_sha=str(entry.get("head_sha") or ""),
                event=str(entry.get("event") or ""),
                created_at=str(entry.get("created_at") or ""),
            )
        )
    return runs


def _newest(runs: Iterable[WorkflowRun]) -> WorkflowRun:
    """Return the run a person reads on the pull request, which is the newest one.

    Args:
        runs: Two or more runs of one workflow at one head commit.

    Returns:
        The run with the latest creation time. The provider writes an RFC 3339 time in
        UTC, so a string comparison orders it.
    """
    return max(runs, key=lambda run: run.created_at)


def gate_reasons(
    head_sha: str,
    runs: Sequence[WorkflowRun],
    head_message: str = "",
    required: Sequence[str] = REQUIRED_WORKFLOW_PATHS,
) -> list[str]:
    """Return every reason the batch gate refuses a merge, and an empty list on a pass.

    Two rules decide. Every required workflow holds a terminal successful run at the head
    commit. Every workflow that ran at the head commit concluded `success`. The second
    rule reaches `Documentation`, which the gate requires no run of, so a red run of it
    still refuses the merge.

    Args:
        head_sha: The full 40-character head commit of the pull request.
        runs: The runs the provider holds. A run of another commit is discarded here.
        head_message: The head commit message. The reader names a skip keyword of it
            where a required run is absent, because that keyword is the cause #459
            measured.
        required: The workflow files that must hold a green run.

    Returns:
        One sentence for each reason, or an empty list where the gate passes.
    """
    reasons: list[str] = []

    if not COMMIT_IDENTIFIER.match(head_sha):
        # A caller that read no head commit, or an abbreviated one, can compare nothing.
        return [
            f"the head commit {head_sha!r} is no 40-character commit identifier, so the "
            "gate compared no run against it"
        ]

    if not required:
        # An aggregate over an empty set passes, so an emptied required set would make
        # this gate pass on every input. That is the failure the whole file stops.
        reasons.append(
            "the required workflow set is empty, so this gate would pass on an absent run"
        )

    at_head = [run for run in runs if run.head_sha == head_sha]

    grouped: dict[str, list[WorkflowRun]] = {}
    for run in at_head:
        grouped.setdefault(run.workflow_path, []).append(run)

    for path in required:
        if path not in grouped:
            reasons.append(
                f"no run of {path} exists for the head commit {head_sha}, and an absent "
                "run is no passed run"
            )

    for path in sorted(grouped):
        newest = _newest(grouped[path])
        if newest.status != TERMINAL_STATUS:
            reasons.append(
                f"the newest run of {path} at {head_sha} reads the status "
                f"{newest.status!r}, so it is no terminal run"
            )
        elif newest.conclusion != PASSING_CONCLUSION:
            reasons.append(
                f"the newest run of {path} at {head_sha} concluded "
                f"{newest.conclusion!r} and not {PASSING_CONCLUSION!r}"
            )

    absent = [reason for reason in reasons if reason.startswith("no run of")]
    if absent:
        found = skip_keywords(head_message)
        if found:
            reasons.append(
                f"the head commit message holds {', '.join(found)}, which is the cause "
                "#459 measured: the provider reads the keyword anywhere in the message "
                "and it creates no run"
            )

    return reasons


def _gh(*arguments: str) -> str:
    """Return the standard output of one `gh` command.

    Args:
        arguments: The command line, with no leading `gh`.

    Returns:
        The standard output.

    Raises:
        RuntimeError: The command exited non-zero. The message names the command and the
            standard error, because a permission failure and an absent pull request need
            different answers and a bare status tells them apart never.
    """
    finished = subprocess.run(
        ["gh", *arguments], capture_output=True, text=True, check=False, cwd=str(REPO_ROOT)
    )
    if finished.returncode != 0:
        raise RuntimeError(
            f"`gh {' '.join(arguments)}` exited {finished.returncode}: {finished.stderr.strip()}"
        )
    return finished.stdout


def read_pull_request(number: int, repository: str = REPOSITORY) -> tuple[str, str]:
    """Return the head commit and the head commit message of one pull request.

    Args:
        number: The pull-request number.
        repository: The `owner/repo` pair.

    Returns:
        The full head commit identifier, and the whole head commit message.

    Raises:
        RuntimeError: A `gh` command failed, or the response held no head commit.
    """
    view = json.loads(_gh("pr", "view", str(number), "--repo", repository, "--json", "headRefOid"))
    head_sha = str(view.get("headRefOid") or "")
    if not head_sha:
        raise RuntimeError(f"pull request #{number} of {repository} reports no head commit")
    commit = json.loads(_gh("api", f"repos/{repository}/commits/{head_sha}"))
    message = str(commit.get("commit", {}).get("message") or "")
    return head_sha, message


def read_provider_runs(head_sha: str, repository: str = REPOSITORY) -> list[WorkflowRun]:
    """Return every run the provider holds for one head commit.

    Args:
        head_sha: The full head commit identifier.
        repository: The `owner/repo` pair.

    Returns:
        The runs the provider reports. An empty list is the state #459 measured.

    Raises:
        RuntimeError: The `gh api` command failed.
    """
    payload = _gh("api", f"repos/{repository}/actions/runs?head_sha={head_sha}&per_page=100")
    return read_runs(json.loads(payload))


def main(argv: Sequence[str] | None = None) -> int:
    """Report whether the batch gate ran green on one pull request.

    Args:
        argv: The command line, or None to read `sys.argv`.

    Returns:
        0 where every required workflow holds a terminal successful run at the head
        commit and every other run of that commit concluded `success`. 1 otherwise, and
        every other state is a state that refuses a batch merge.
    """
    parser = argparse.ArgumentParser(
        prog="python -m tests.batch_gate",
        description="Refuse a batch merge while no terminal run exists for the head commit.",
    )
    parser.add_argument(
        "--pr",
        type=int,
        help="Read the head commit and the runs of this pull request from the provider.",
    )
    parser.add_argument("--repo", default=REPOSITORY, help="The `owner/repo` pair to read.")
    parser.add_argument("--head-sha", help="Read this head commit rather than a pull request.")
    parser.add_argument(
        "--runs-file", help="Read the provider response from this file rather than the network."
    )
    parser.add_argument(
        "--message-file",
        help="Read the head commit message from this file rather than the network.",
    )
    options = parser.parse_args(argv)

    head_sha = options.head_sha or ""
    message = ""

    if options.pr is not None:
        try:
            head_sha, message = read_pull_request(options.pr, options.repo)
        except RuntimeError as error:
            # A read that failed proves no green run, so the gate refuses the merge.
            print(f"batch gate: REFUSED. {error}", file=sys.stderr)
            return 1

    if options.message_file:
        message = Path(options.message_file).read_text(encoding="utf-8")

    if options.runs_file:
        runs = read_runs(json.loads(Path(options.runs_file).read_text(encoding="utf-8")))
    else:
        try:
            runs = read_provider_runs(head_sha, options.repo)
        except RuntimeError as error:
            print(f"batch gate: REFUSED. {error}", file=sys.stderr)
            return 1

    reasons = gate_reasons(head_sha, runs, head_message=message)
    if reasons:
        print(f"batch gate: REFUSED for the head commit {head_sha}.", file=sys.stderr)
        for reason in reasons:
            print(f"  - {reason}", file=sys.stderr)
        print(
            "  Start a run by hand, then read this gate again: "
            f"gh workflow run Tests --repo {options.repo} --ref <branch>",
            file=sys.stderr,
        )
        return 1

    for path in sorted({run.workflow_path for run in runs if run.head_sha == head_sha}):
        print(f"batch gate: {path} concluded success at {head_sha}.")
    print(f"batch gate: PASSED for the head commit {head_sha}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
