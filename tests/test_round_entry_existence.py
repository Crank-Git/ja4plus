"""Tests that a change set which edits a tracked file also records a Changelog round.

`tests/test_changelog_round_agreement.py` holds `CHANGELOG.md` and `docs/specs/spec.md`
**against each other**. Each of its three cases reads one file and compares it against the
other, so **two absent records agree and every case passes**. The invariant those cases
hold is agreement, and the invariant this file holds is existence.

#412 proved the gap. Commit `46aa502` carried eleven sweeps, two repairs and a new test
file, it added no `CHANGELOG.md` entry and no `Changelog` row, and the whole unit gate was
green. The project manager read the diff at the merge gate and caught it. That is not a
check.

## The reference point

A case here reads the change set of the branch, so it needs a commit to read the change
set against. **The reference point is the merge base of `HEAD` and the integration
branch**, which `reference_commit` reads with `git merge-base`. `REFERENCE_BRANCHES` names
the candidates in order, and the branch model of `CLAUDE.md` names `dev` as the
integration branch. The merge base is a condition on the commit graph. It reads no local
configuration, so a checkout that carries the ref reaches the same commit as every other
checkout of the same branch.

The change set holds two readings that `changed_paths` joins.

- `git diff --name-only <reference>` reports every tracked file the branch changed,
  including a change the branch has not committed yet.
- `git ls-files --others --exclude-standard` reports every new file that no rule ignores.
  A commit tracks such a file, and #412 shipped exactly one of them.

## The reference point on the runner

**A shallow clone holds no merge base, so the runner names the reference commit instead.**
The `actions/checkout` step of `.github/workflows/test.yml` makes a clone of depth 1. That
clone carries no `origin/dev` ref and no history behind the checked-out commit, so
`git merge-base` fails on it. The `test` job therefore fetches the base commit of the pull
request at depth 1 and writes it into the `ROUND_ENTRY_REFERENCE` environment variable.
`environment_reference` reads that variable and `reference_commit` prefers it over the
merge base.

**`git diff` and `git show` read a commit that no history connects to `HEAD`, and
`git merge-base` does not.** A diff compares two trees, so it needs the two commits and
nothing between them. #438 measured the pair on a clone of depth 1: the diff and the
show each answered, and `git merge-base` exited 1. That measurement is why the runner
names a commit rather than deepens the clone.

**A pull-request event carries the base commit, so the runner fetches one commit.** #438
measured the cost against the repository on 2026-08-10. A clone of depth 1 holds 14844 KB.
The extra fetch of one commit raises it to 15452 KB, which is 608 KB. `fetch-depth: 0`
raises it to 18728 KB, which is 3884 KB, and that cost rises with every commit the project
makes.

**A manual run carries no pull request, and #541 measured what that cost.** The variable
stayed empty, and `git merge-base` found no `origin/dev` ref in the clone of depth 1. This
case then skipped on all six jobs of the matrix. The `skip-gate` job failed every manual
run, which is the recovery path `.claude/rules/batch-gate.md` names.

**A case that a given event does not select is no finding of that event.** The `test` job
now names a reference commit wherever the event carries no pull request. It reads the merge
base of `GITHUB_SHA` and `dev` from the provider, because the clone holds no history for
`git merge-base` to read.

**A push reaches that step too, and a push to `master` needs it.** `actions/checkout`
writes the one remote-tracking ref the event names. A push to `dev` therefore holds
`origin/dev` and `git merge-base` answers, and a push to `master` holds `origin/master`
alone and it answers nothing. A promotion to `master` is a push of the second kind.

**Where the change set cannot be read, a case here skips and the reason names the state.**
`evaluate` returns the skip
reason and the failure as two separate fields, so a case reports which one it met.

## The two recorded change sets

**A scratch repository proves the reading against a change set the case wrote.** A recorded
commit proves it against a change set the project made. Two commits carry that proof, and
`recorded_change_set` reads each one against its parent.

- `DEFECT_COMMIT` is the commit #412 shipped. It carried eleven sweeps, two repairs and a
  new test file, it recorded no round, and the whole unit gate passed it.
- `CONTROL_COMMIT` is the commit #429 shipped. It added this file, it recorded one round,
  and the reading passes it.

**The clone of depth 1 holds neither commit, so the `test` job fetches both at depth 2.**
A fetch of depth 2 carries the commit and its parent, which is the pair the reading needs.
#528 measured the cost on 2026-08-10, after `git gc --prune=now` on each read. The clone
of depth 1 holds 14884 KB, the defect fetch raises it to 14912 KB, and the control fetch
raises it to 14916 KB. The two refspecs therefore cost 32 KB together.

**Warning: one command carries both refspecs, and two commands fail.** Each fetch of a
shallow clone reads `.git/shallow`, and it refuses to finish where that file moved since
the read. #528 wrote two commands, and each one rewrote that file. #586 measured the
failure on run https://github.com/Crank-Git/ja4plus/actions/runs/31452971377, where the
first fetch wrote `refs/ja4plus/recorded-defect` and the second reported
`fatal: shallow file has changed since we read it`. `RECORDED_FETCH` holds the one command
that replaces the pair.

**Two tags hold the two commits, and a branch sweep must keep both.** `DEFECT_TAG` and
`CONTROL_TAG` name them. A commit that a workflow fetches is a commit some reference must
hold, and a sweep of 2026-08-10 left `DEFECT_COMMIT` reachable from no branch. **The
workflow fetches the identifier and never the tag**, because a tag moves and an identifier
does not.

**#528 measured that the fetch of an abbreviated name fails, so each constant holds the
whole identifier.** The workflow names the same two identifiers, and
`test_the_test_job_fetches_the_two_recorded_change_sets` holds the workflow against the
constants. A repository that holds neither commit skips the two cases, and the `skip-gate`
job of `.github/workflows/test.yml` fails a run where that skip reaches every job.

## What a case here cannot test

**A case here tests that an entry exists. It cannot test that the entry is true.** Prose
that names the wrong issue, or that states a change the branch did not make, passes every
case in this file. A reader of the merge gate holds that question.

Three more limits, each stated rather than implied.

- The count reads the whole branch, so a change set that merges another branch inherits
  the entry of that branch. An integration branch whose members each recorded a round
  therefore satisfies a member that recorded none.
- The count rises by one where an edit to the prose of an entry makes the parser match a
  round sentence that it read before as prose.
- `RoundRecord` counts an unassigned entry and a numbered entry alike, so a case here
  reads no round number. The project manager assigns the number at the batch gate on one
  batch, and hands the number to the worker on another. A case that demanded `TBD` would
  fail on the second, and `tests/test_changelog_round_agreement.py` holds the number
  itself against the specification row.

These cases read prose and the commit graph. They import nothing from `ja4plus` and they
produce no fingerprint.
"""

import os
from pathlib import Path
import re
import subprocess
from typing import List, Mapping, NamedTuple, Optional, Sequence

import pytest

from tests.test_changelog_round_agreement import CHANGELOG_ROUND, SPECIFICATION_ROW_NUMBER

REPO_ROOT = Path(__file__).resolve().parent.parent

# The two documents that record a round. A change set that edits these alone records a
# round by definition, so neither path demands one.
CHANGELOG_PATH = "CHANGELOG.md"
SPECIFICATION_PATH = "docs/specs/spec.md"
EXEMPT_RECORDS = (CHANGELOG_PATH, SPECIFICATION_PATH)
EXEMPT_PATHS = frozenset(EXEMPT_RECORDS)

# The refs that name the integration branch, in the order `reference_commit` reads them.
# A worktree of this project carries `origin/dev`. A clone that fetched no remote ref
# carries the local `dev` alone, and a shallow clone carries neither.
REFERENCE_BRANCHES = ("origin/dev", "dev")

# The environment variable that names the reference commit. The `test` job of
# `.github/workflows/test.yml` writes the base commit of the pull request into it, because
# a clone of depth 1 holds no merge base for `git merge-base` to report.
REFERENCE_ENVIRONMENT_VARIABLE = "ROUND_ENTRY_REFERENCE"

# The workflow whose `test` job runs this case on the runner.
WORKFLOW_PATH = ".github/workflows/test.yml"

# The base-branch filter of that workflow. `master` and `dev` accept the batch pull request
# and the promotion, and the two patterns accept a member pull request. #438 measured that
# a filter of `[master, dev]` alone creates no run for a member pull request, so this case
# reaches the `test` job on a batch pull request alone and passes there by construction.
WORKFLOW_BASE_FILTER = 'branches: [master, dev, "batch/**", "epic/**"]'

# The rule file that states which pull request creates a run.
BATCH_GATE_RULE_PATH = ".claude/rules/batch-gate.md"

# The step that names the reference commit where the event carries no pull request.
NO_PULL_REQUEST_STEP = "Resolve the reference commit of a run that carries no pull request"

# The `if` condition of that step. The step above it reads the base commit of a pull
# request, so the two conditions together cover every event the workflow accepts.
#
# **A manual run and a push to `master` each reach this condition.** `actions/checkout`
# writes the one remote-tracking ref the event names, so neither one holds `origin/dev` for
# `git merge-base` to read. A promotion to `master` is a push of that kind.
NO_PULL_REQUEST_CONDITION = "if: github.event_name != 'pull_request'"

# The read that names the merge base of the checked-out commit and the integration branch.
# A clone of depth 1 holds no history behind that commit, so `git merge-base` answers
# nothing and the provider answers in its place.
#
# **The basehead form is `BASE...HEAD` and the response holds `merge_base_commit`.**
# Verified against
# https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28 (retrieved
# 2026-08-10).
MERGE_BASE_READ = (
    'gh api "repos/$GITHUB_REPOSITORY/compare/dev...$GITHUB_SHA" --jq .merge_base_commit.sha'
)

# A git command that reads one ref or one index answers in well under a second. The limit
# bars a hung command from stopping the whole gate.
GIT_TIMEOUT_SECONDS = 60

# The commit #412 shipped. It carried eleven sweeps, two repairs and a new test file, and
# it recorded no round. A case reads it to prove the reading against a real change set,
# because a scratch repository proves the reading against a change set the case wrote.
#
# **The constant holds the whole identifier, because the runner fetches this commit by
# name.** #528 measured `git fetch --depth=2 origin "+46aa502:refs/ja4plus/abbrev"` on a
# clone of depth 1, and git answered `fatal: couldn't find remote ref 46aa502`.
DEFECT_COMMIT = "46aa502ca47f3c29f3c5ece15e4e78500e2f59c5"

# The commit #429 shipped, which added this file. It changed one file outside the two
# records and it recorded one round, so the reading passes it. **A green reading of one
# commit proves nothing on its own**, and this commit is the second direction that #528
# put on the runner beside `DEFECT_COMMIT`.
CONTROL_COMMIT = "f140a5c318dfbe443b38b8f1a6a7df7d6b098cf0"

# The refs the fetch of the runner writes. A commit that no ref reaches is unreachable, so
# `git gc` removes it. #438 measured the ref form and #528 measured it again on these two.
DEFECT_REF = "refs/ja4plus/recorded-defect"

CONTROL_REF = "refs/ja4plus/recorded-control"

# The tags that hold the two recorded commits at the provider. A commit that a workflow
# fetches is a commit some reference must hold, and a branch sweep of 2026-08-10 left
# `DEFECT_COMMIT` reachable from no branch. The project manager created both tags that day.
DEFECT_TAG = "record/412-defect"

CONTROL_TAG = "record/429-control"

# The one command that carries the two recorded change sets to the runner. **Each fetch of
# a shallow clone rewrites `.git/shallow`, and #586 measured the failure of a second
# write.** One command names both refspecs and writes that file once.
RECORDED_FETCH = (
    f'git fetch --depth=2 origin "+$DEFECT_SHA:{DEFECT_REF}" "+$CONTROL_SHA:{CONTROL_REF}"'
)

# The step that runs `RECORDED_FETCH`.
RECORDED_FETCH_STEP = "Fetch the two recorded change sets"

# The step that carries the pins of `docs/specs/foxio/` to the runner. #668 added it, and
# `tests/foxio_citation_lines.py` reads the reference it writes.
CITATION_PIN_STEP = "Fetch the commits the transcription pages pin"

# Every step of the `test` job that runs `git fetch`. The first two carry an `if` condition
# and no event selects both, so the job runs three of these four steps.
#
# **A step that runs one fetch writes `.git/shallow` once, so it needs no repair.**
# `test_a_fetch_step_of_the_test_job_runs_one_git_fetch_command` holds each of the four
# against that count, and `test_the_workflow_holds_no_fetch_step_this_list_omits` refuses a
# fifth fetch that reaches no case here.
FETCH_STEPS = (
    "Fetch the base commit of the pull request",
    NO_PULL_REQUEST_STEP,
    RECORDED_FETCH_STEP,
    CITATION_PIN_STEP,
)

# The opener of a step of a job of the workflow. A step of `.github/workflows/test.yml`
# starts at column 6, so the next line at that column starts the next step.
STEP_OPENER = "      - "

# The indentation of a key that stands above a step. A job name sits at column 2 and a key
# of a job sits at column 4, so a line this pattern matches ends the step above it.
#
# **A step reader that watched for `STEP_OPENER` alone would read past the last step of a
# job**, and it would take the keys of the next job into that step. The self-review of #586
# raised that reading, and no call of `step_block` met it.
BLOCK_CLOSER = re.compile(r"^ {0,5}\S")

# A line that runs `git fetch`. The pattern anchors at the start of the line, so a comment
# that names the command matches nothing and a reader counts a command alone.
#
# **The pattern reads three forms, because a narrower one would miss a fetch and report
# agreement.** A block scalar writes `git fetch`, a one-line `run` key writes
# `run: git fetch`, and an option between the program and the subcommand writes
# `git -C <path> fetch`. The self-review of #586 raised the second form and the third.
COMMAND_FETCH = re.compile(r"^\s*(?:run:\s+)?git\s+(?:\S+\s+)*?fetch\b")

# The count of paths a failure names. A sweep changes 30 files, and a message that names
# all of them buries the count that follows it.
NAMED_PATH_LIMIT = 3


def step_block(workflow: str, name: str) -> str:
    """Return the text of one step of the workflow, from its name to the next step.

    Args:
        workflow: The text of `.github/workflows/test.yml`.
        name: The value of the `name` key of the step.

    Returns:
        The lines of that step, including the line that names it.

    Raises:
        AssertionError: The workflow holds no step of that name.
    """
    lines = workflow.splitlines(keepends=True)
    opener = f"{STEP_OPENER}name: {name}"
    for index, line in enumerate(lines):
        if line.rstrip("\n") != opener:
            continue
        end = len(lines)
        for later in range(index + 1, len(lines)):
            if lines[later].startswith(STEP_OPENER) or BLOCK_CLOSER.match(lines[later]):
                end = later
                break
        return "".join(lines[index:end])
    raise AssertionError(f"the workflow holds no step named {name}")


def fetch_count(text: str) -> int:
    """Return the count of `git fetch` commands one block of the workflow runs.

    Args:
        text: The text of one step, or the text of the whole workflow.

    Returns:
        The count of lines that run `git fetch`. A comment that names the command counts
        nowhere, because `COMMAND_FETCH` anchors at the start of the line.
    """
    return sum(1 for line in text.splitlines() if COMMAND_FETCH.match(line))


class RoundRecord(NamedTuple):
    """The count of round entries that each of the two documents holds."""

    entries: int
    rows: int


class Verdict(NamedTuple):
    """The result of one evaluation, as the skip reason and the failure reason."""

    skip_reason: Optional[str]
    failure: Optional[str]


def _git(repository: Path, *arguments: str) -> Optional[str]:
    """Return the standard output of one git command.

    Args:
        repository: The root of the repository the command reads.
        arguments: The git arguments, without the program name.

    Returns:
        The standard output, or None where git is absent, where the command fails, or
        where it passes the time limit.
    """
    try:
        finished = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if finished.returncode != 0:
        return None
    return finished.stdout


def environment_reference(environment: Mapping[str, str] = os.environ) -> str:
    """Return the commit the environment names for the change set to read against.

    Args:
        environment: The environment to read.

    Returns:
        The name the `ROUND_ENTRY_REFERENCE` variable holds, or an empty string where the
        environment holds no such variable.
    """
    return environment.get(REFERENCE_ENVIRONMENT_VARIABLE, "").strip()


def named_commit(repository: Path, name: str) -> Optional[str]:
    """Return the commit one name states.

    Args:
        repository: The root of the repository.
        name: The name of a commit, or an empty string where the caller names none. The
            reader drops the space around the name, because a caller other than
            `environment_reference` reaches this function too.

    Returns:
        The full commit identifier, or None where the name is empty and None where the
        repository holds no such commit.
    """
    name = name.strip()
    if not name:
        return None
    output = _git(repository, "rev-parse", "--verify", f"{name}^{{commit}}")
    if output is None or not output.strip():
        return None
    return output.strip()


def reference_commit(
    repository: Path,
    reference_branches: Sequence[str] = REFERENCE_BRANCHES,
    named: str = "",
) -> Optional[str]:
    """Return the commit the change set reads against.

    A named commit outranks the merge base, because the runner holds a clone of depth 1
    and `git merge-base` fails on such a clone. A name the repository cannot read reads
    as no name, so a stale value of the environment leaves the local gate as it is.

    Args:
        repository: The root of the repository.
        reference_branches: The refs that name the integration branch, in read order.
        named: The name of a commit, or an empty string where the caller names none.

    Returns:
        The named commit, then the merge base of `HEAD` and the first ref the repository
        holds, or None where it holds neither.
    """
    commit = named_commit(repository, named)
    if commit is not None:
        return commit
    for branch in reference_branches:
        output = _git(repository, "merge-base", branch, "HEAD")
        if output is not None and output.strip():
            return output.strip()
    return None


def changed_paths(repository: Path, reference: str) -> Optional[List[str]]:
    """Return every path the branch changed since the reference commit.

    Args:
        repository: The root of the repository.
        reference: The commit the change set reads against.

    Returns:
        The tracked paths the branch changed, followed by the new paths no rule ignores,
        or None where git answers neither question.
    """
    tracked = _git(repository, "diff", "--name-only", reference)
    if tracked is None:
        return None
    new = _git(repository, "ls-files", "--others", "--exclude-standard")
    if new is None:
        return None
    return [line for line in (tracked + new).splitlines() if line]


def document_at(repository: Path, reference: str, path: str) -> str:
    """Return the text of one document at the reference commit.

    A commit that carries no such document reads as an empty document. That reading makes
    every entry of the working tree a new entry, so it reports no failure that the
    document does not hold.

    Args:
        repository: The root of the repository.
        reference: The commit the change set reads against.
        path: The path of the document, relative to the repository root.

    Returns:
        The text of the document, or an empty string.
    """
    return _git(repository, "show", f"{reference}:{path}") or ""


def document_now(repository: Path, path: str) -> str:
    """Return the text of one document in the working tree.

    Args:
        repository: The root of the repository.
        path: The path of the document, relative to the repository root.

    Returns:
        The text of the document, or an empty string where the working tree holds none.
    """
    document = repository / path
    if not document.is_file():
        return ""
    return document.read_text(encoding="utf-8")


def read_record(changelog_text: str, specification_text: str) -> RoundRecord:
    """Return the count of round entries of the two documents.

    `CHANGELOG_ROUND` and `SPECIFICATION_ROW_NUMBER` carry the two patterns, and
    `tests/test_changelog_round_agreement.py` owns them. One parser reads both files, so
    the two modules cannot disagree about what a round entry is.

    Args:
        changelog_text: The text of `CHANGELOG.md`.
        specification_text: The text of `docs/specs/spec.md`.

    Returns:
        The count of `CHANGELOG.md` entries that name a round, and the count of
        `docs/specs/spec.md` Changelog rows.
    """
    entries = 0
    # An entry opens the line with `- `, which is the split `_changelog_entries` uses.
    for entry in re.split(r"\n(?=- )", changelog_text):
        if CHANGELOG_ROUND.search(entry):
            entries += 1
    rows = 0
    for line in specification_text.splitlines():
        if SPECIFICATION_ROW_NUMBER.match(line):
            rows += 1
    return RoundRecord(entries=entries, rows=rows)


def missing_round_entry(
    paths: Sequence[str], base: RoundRecord, head: RoundRecord
) -> Optional[str]:
    """Return the reason a change set records no round.

    Args:
        paths: Every path the change set holds.
        base: The counts of the two documents at the reference commit.
        head: The counts of the two documents in the working tree.

    Returns:
        The reason, or None where the change set records a round or edits no other file.
    """
    subjects = sorted(set(paths) - EXEMPT_PATHS)
    if not subjects:
        return None
    named = ", ".join(subjects[:NAMED_PATH_LIMIT])
    if len(subjects) > NAMED_PATH_LIMIT:
        named = f"{named} and {len(subjects) - NAMED_PATH_LIMIT} more"
    if head.entries <= base.entries:
        return (
            f"the change set holds these paths outside the two records: {named}. "
            f"{CHANGELOG_PATH} holds {head.entries} round entries against {base.entries} "
            "at the reference commit"
        )
    if head.rows <= base.rows:
        return (
            f"the change set holds these paths outside the two records: {named}. "
            f"{SPECIFICATION_PATH} holds {head.rows} Changelog rows against {base.rows} "
            "at the reference commit"
        )
    return None


def evaluate(
    repository: Path = REPO_ROOT,
    reference_branches: Sequence[str] = REFERENCE_BRANCHES,
    named: str = "",
) -> Verdict:
    """Return the verdict on the change set of one repository.

    Args:
        repository: The root of the repository.
        reference_branches: The refs that name the integration branch, in read order.
        named: The name of the reference commit, or an empty string where the caller
            names none. `environment_reference` reads the name the runner writes.

    Returns:
        A verdict that carries a skip reason where the change set cannot be read, and a
        failure reason where the change set records no round.
    """
    reference = reference_commit(repository, reference_branches, named)
    if reference is None:
        return Verdict(
            f"{REFERENCE_ENVIRONMENT_VARIABLE} names no commit this repository holds, and "
            f"git reports no merge base between HEAD and any of {list(reference_branches)}",
            None,
        )
    paths = changed_paths(repository, reference)
    if paths is None:
        return Verdict(f"git reports no change set against {reference}", None)
    base = read_record(
        document_at(repository, reference, CHANGELOG_PATH),
        document_at(repository, reference, SPECIFICATION_PATH),
    )
    head = read_record(
        document_now(repository, CHANGELOG_PATH),
        document_now(repository, SPECIFICATION_PATH),
    )
    return Verdict(None, missing_round_entry(paths, base, head))


def recorded_change_set(repository: Path, commit: str) -> Verdict:
    """Return the verdict the reading gives one recorded commit.

    The reader compares the commit against its parent, so it needs the two commits and
    nothing between them. A clone of depth 2 over the commit holds that pair.

    Args:
        repository: The root of the repository.
        commit: The whole identifier of the commit to read.

    Returns:
        A verdict that carries a skip reason where the repository holds no such pair, and
        the reading of the change set otherwise.
    """
    parent = named_commit(repository, f"{commit}^")
    if parent is None:
        return Verdict(f"this clone holds no parent of commit {commit}", None)
    changed = _git(repository, "diff", "--name-only", parent, commit)
    if changed is None:
        return Verdict(f"git reports no change set of commit {commit}", None)
    base = read_record(
        document_at(repository, parent, CHANGELOG_PATH),
        document_at(repository, parent, SPECIFICATION_PATH),
    )
    head = read_record(
        document_at(repository, commit, CHANGELOG_PATH),
        document_at(repository, commit, SPECIFICATION_PATH),
    )
    return Verdict(None, missing_round_entry(changed.splitlines(), base, head))


BASE_CHANGELOG = "# Changelog\n\n- **A first change** (#1). Round 1.\n"
BASE_SPECIFICATION = (
    "## Changelog\n\n| Round | Date | What changed |\n|---|---|---|\n"
    "| 1 | 2026-08-09 | #1 landed. |\n"
)
UNASSIGNED_ENTRY = "- **A second change** (#2). Round TBD.\n"
UNASSIGNED_ROW = "| TBD | 2026-08-09 | #2 landed. |\n"
NUMBERED_ENTRY = "- **A second change** (#2). Round 2.\n"
NUMBERED_ROW = "| 2 | 2026-08-09 | #2 landed. |\n"


def _run(repository: Path, *arguments: str) -> None:
    """Run one git command against a scratch repository and raise where it fails.

    A scratch repository is not the repository under test, so a failure here is a defect
    of the case rather than a finding.

    Args:
        repository: The root of the scratch repository.
        arguments: The git arguments, without the program name.

    Raises:
        subprocess.CalledProcessError: The command failed.
    """
    subprocess.run(
        # A hook or a signature of the person who runs the gate reaches no scratch
        # repository, because either one fails a case for a reason the case does not test.
        ["git", "-C", str(repository), "-c", "commit.gpgsign=false", *arguments],
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=True,
    )


def _write(repository: Path, path: str, text: str) -> None:
    """Write one file of a scratch repository.

    Args:
        repository: The root of the scratch repository.
        path: The path of the file, relative to the root.
        text: The text to write.
    """
    document = repository / path
    document.parent.mkdir(parents=True, exist_ok=True)
    document.write_text(text, encoding="utf-8")


def _commit(repository: Path, message: str) -> None:
    """Commit every change of a scratch repository under a fixed author.

    The author reaches the command and not the configuration of the person who runs the
    gate, because a machine that configures no author fails `git commit`.

    Args:
        repository: The root of the scratch repository.
        message: The commit message.
    """
    _run(repository, "add", "-A")
    _run(
        repository,
        "-c",
        "user.email=case@example.com",
        "-c",
        "user.name=Case",
        "commit",
        "--no-verify",
        "-m",
        message,
    )


def _scratch_repository(root: Path, initial_branch: str = "dev") -> Path:
    """Return a repository that holds the two records on one commit and a second branch.

    Args:
        root: The directory to make the repository in.
        initial_branch: The name of the first branch, which the case reads as the
            integration branch.

    Returns:
        The root of the repository, on a branch named `work`.
    """
    subprocess.run(
        ["git", "init", "-b", initial_branch, str(root)],
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=True,
    )
    _write(root, CHANGELOG_PATH, BASE_CHANGELOG)
    _write(root, SPECIFICATION_PATH, BASE_SPECIFICATION)
    _write(root, "ja4plus/cli.py", "VALUE = 1\n")
    # The first commit carries the ignore rule, so the rule reaches the `work` branch
    # without a change set of its own.
    _write(root, ".gitignore", ".venv/\n")
    _commit(root, "the first commit")
    _run(root, "checkout", "-b", "work")
    return root


def _record_a_round(
    repository: Path, entry: str = UNASSIGNED_ENTRY, row: str = UNASSIGNED_ROW
) -> None:
    """Add one round entry to each record of a scratch repository.

    Args:
        repository: The root of the scratch repository.
        entry: The `CHANGELOG.md` entry to append.
        row: The `docs/specs/spec.md` Changelog row to append.
    """
    _write(repository, CHANGELOG_PATH, BASE_CHANGELOG + entry)
    _write(repository, SPECIFICATION_PATH, BASE_SPECIFICATION + row)


def test_the_change_set_of_this_branch_records_a_round() -> None:
    """The branch of this repository records a round for the files it changes."""
    verdict = evaluate(named=environment_reference())
    if verdict.skip_reason is not None:
        pytest.skip(verdict.skip_reason)
    assert verdict.failure is None, verdict.failure


def test_the_reading_fails_the_change_set_of_the_defect() -> None:
    """The reading fails the defect commit, which changed six files and recorded no round."""
    verdict = recorded_change_set(REPO_ROOT, DEFECT_COMMIT)
    if verdict.skip_reason is not None:
        pytest.skip(verdict.skip_reason)
    assert verdict.failure is not None
    assert CHANGELOG_PATH in verdict.failure


def test_the_reading_passes_the_change_set_that_records_a_round() -> None:
    """The reading passes the control commit, which changed one file and recorded one round."""
    verdict = recorded_change_set(REPO_ROOT, CONTROL_COMMIT)
    if verdict.skip_reason is not None:
        pytest.skip(verdict.skip_reason)
    assert verdict.failure is None, verdict.failure


def test_a_change_set_that_edits_code_and_records_no_round_fails(tmp_path: Path) -> None:
    """A change set that edits a tracked file and adds no round entry fails."""
    repository = _scratch_repository(tmp_path / "red")
    _write(repository, "ja4plus/cli.py", "VALUE = 2\n")
    verdict = evaluate(repository, ("dev",))
    assert verdict.skip_reason is None
    assert verdict.failure is not None
    assert "ja4plus/cli.py" in verdict.failure
    assert CHANGELOG_PATH in verdict.failure


def test_a_change_set_that_records_an_unassigned_round_passes(tmp_path: Path) -> None:
    """A change set that edits a tracked file and adds one unassigned entry passes."""
    repository = _scratch_repository(tmp_path / "green")
    _write(repository, "ja4plus/cli.py", "VALUE = 2\n")
    _record_a_round(repository)
    verdict = evaluate(repository, ("dev",))
    assert verdict.skip_reason is None
    assert verdict.failure is None, verdict.failure


def test_a_change_set_that_records_a_numbered_round_passes(tmp_path: Path) -> None:
    """A change set that adds a numbered entry to each record passes."""
    repository = _scratch_repository(tmp_path / "numbered")
    _write(repository, "ja4plus/cli.py", "VALUE = 2\n")
    _record_a_round(repository, NUMBERED_ENTRY, NUMBERED_ROW)
    verdict = evaluate(repository, ("dev",))
    assert verdict.skip_reason is None
    assert verdict.failure is None, verdict.failure


@pytest.mark.parametrize("edited", [(CHANGELOG_PATH,), (SPECIFICATION_PATH,), EXEMPT_RECORDS])
def test_a_change_set_of_the_records_alone_passes(tmp_path: Path, edited: Sequence[str]) -> None:
    """A change set that edits `CHANGELOG.md` or `docs/specs/spec.md` alone passes."""
    repository = _scratch_repository(tmp_path / "-".join(edited).replace("/", "-"))
    # The round assignment of the project manager edits a record and adds no entry, so the
    # text of the edit adds no round sentence and no Changelog row.
    for path in edited:
        _write(repository, path, document_now(repository, path) + "\nA line the edit adds.\n")
    verdict = evaluate(repository, ("dev",))
    assert verdict.skip_reason is None
    assert verdict.failure is None, verdict.failure


def test_an_entry_that_reaches_one_record_alone_fails(tmp_path: Path) -> None:
    """A change set that adds an entry to `CHANGELOG.md` and no row to the specification fails."""
    repository = _scratch_repository(tmp_path / "orphan")
    _write(repository, "ja4plus/cli.py", "VALUE = 2\n")
    _write(repository, CHANGELOG_PATH, BASE_CHANGELOG + UNASSIGNED_ENTRY)
    verdict = evaluate(repository, ("dev",))
    assert verdict.skip_reason is None
    assert verdict.failure is not None
    assert SPECIFICATION_PATH in verdict.failure


def test_a_new_file_that_no_commit_holds_reaches_the_change_set(tmp_path: Path) -> None:
    """A change set whose only new file is untracked and records no round fails."""
    repository = _scratch_repository(tmp_path / "untracked")
    _write(repository, "tests/test_new_case.py", "def test_a_case() -> None:\n    assert True\n")
    verdict = evaluate(repository, ("dev",))
    assert verdict.skip_reason is None
    assert verdict.failure is not None
    assert "tests/test_new_case.py" in verdict.failure


def test_a_file_an_ignore_rule_covers_reaches_no_change_set(tmp_path: Path) -> None:
    """A change set whose only new file matches `.gitignore` records no round and passes."""
    repository = _scratch_repository(tmp_path / "ignored")
    _write(repository, ".venv/marker.txt", "a file of the environment\n")
    verdict = evaluate(repository, ("dev",))
    assert verdict.skip_reason is None
    assert verdict.failure is None, verdict.failure


def test_a_commit_that_edits_code_and_records_no_round_fails(tmp_path: Path) -> None:
    """A committed change to a tracked file that adds no round entry fails."""
    repository = _scratch_repository(tmp_path / "committed")
    _write(repository, "ja4plus/cli.py", "VALUE = 2\n")
    _commit(repository, "the second commit")
    verdict = evaluate(repository, ("dev",))
    assert verdict.skip_reason is None
    assert verdict.failure is not None
    assert "ja4plus/cli.py" in verdict.failure


def test_a_commit_that_records_a_round_passes(tmp_path: Path) -> None:
    """A committed change to a tracked file that adds one round entry passes."""
    repository = _scratch_repository(tmp_path / "committed-green")
    _write(repository, "ja4plus/cli.py", "VALUE = 2\n")
    _record_a_round(repository)
    _commit(repository, "the second commit")
    verdict = evaluate(repository, ("dev",))
    assert verdict.skip_reason is None
    assert verdict.failure is None, verdict.failure


def test_a_repository_that_holds_no_reference_branch_skips(tmp_path: Path) -> None:
    """A repository that holds no integration branch produces a skip reason."""
    repository = _scratch_repository(tmp_path / "shallow", initial_branch="release")
    _write(repository, "ja4plus/cli.py", "VALUE = 2\n")
    verdict = evaluate(repository, ("origin/dev", "dev"))
    assert verdict.skip_reason is not None
    assert "origin/dev" in verdict.skip_reason
    assert verdict.failure is None


def test_a_directory_that_holds_no_repository_skips(tmp_path: Path) -> None:
    """A directory that git cannot read produces a skip reason and no failure."""
    plain = tmp_path / "plain"
    plain.mkdir()
    verdict = evaluate(plain, ("dev",))
    assert verdict.skip_reason is not None
    assert verdict.failure is None


def test_the_reader_counts_a_round_sentence_that_wraps() -> None:
    """The reader counts an entry whose round sentence wraps to the next line."""
    wrapped = "- **A change** (#3). Round\n  TBD.\n"
    assert read_record(BASE_CHANGELOG + wrapped, BASE_SPECIFICATION).entries == 2


def _unrelated_head(repository: Path) -> str:
    """Return the first commit and leave `HEAD` on a branch that shares no history with it.

    A clone of depth 1 holds the base commit and the head commit with no history between
    them, and `git merge-base` fails on that pair. An orphan branch reproduces that state
    inside a scratch repository, so a case reads the runner state without a network.

    Args:
        repository: The root of the scratch repository.

    Returns:
        The commit the scratch repository started from.
    """
    base = _git(repository, "rev-parse", "HEAD")
    assert base is not None
    _run(repository, "checkout", "--orphan", "shallow")
    return base.strip()


def test_the_environment_names_the_reference_commit() -> None:
    """The reader returns the commit that `ROUND_ENTRY_REFERENCE` names."""
    environment = {REFERENCE_ENVIRONMENT_VARIABLE: "  864b70d  "}
    assert environment_reference(environment) == "864b70d"


def test_an_environment_that_holds_no_variable_names_no_commit() -> None:
    """The reader returns an empty name where the environment holds no variable."""
    assert environment_reference({}) == ""


def test_a_named_commit_outranks_the_merge_base(tmp_path: Path) -> None:
    """The reference reads the named commit where the repository also holds a merge base."""
    repository = _scratch_repository(tmp_path / "named")
    _write(repository, "ja4plus/cli.py", "VALUE = 2\n")
    _commit(repository, "the second commit")
    head = _git(repository, "rev-parse", "HEAD")
    assert head is not None
    merge_base = reference_commit(repository, ("dev",))
    assert merge_base is not None and merge_base != head.strip()
    assert reference_commit(repository, ("dev",), named="HEAD") == head.strip()


def test_a_named_commit_reads_through_the_space_around_the_name(tmp_path: Path) -> None:
    """The reader resolves a name that carries a space at each end."""
    repository = _scratch_repository(tmp_path / "spaced")
    head = _git(repository, "rev-parse", "HEAD")
    assert head is not None
    assert named_commit(repository, "  HEAD  ") == head.strip()


def test_a_named_commit_reads_a_change_set_that_no_merge_base_reaches(tmp_path: Path) -> None:
    """A change set against a commit no history connects to `HEAD` fails without a round."""
    repository = _scratch_repository(tmp_path / "shallow-red")
    base = _unrelated_head(repository)
    _write(repository, "ja4plus/cli.py", "VALUE = 2\n")
    _commit(repository, "the head of the shallow clone")
    # The runner state: git reports no merge base, and the case must still read the diff.
    assert reference_commit(repository, ("origin/dev", "dev")) is None
    verdict = evaluate(repository, ("origin/dev", "dev"), named=base)
    assert verdict.skip_reason is None
    assert verdict.failure is not None
    assert "ja4plus/cli.py" in verdict.failure


def test_a_named_commit_passes_a_change_set_that_records_a_round(tmp_path: Path) -> None:
    """A change set against an unconnected commit passes where it records one round."""
    repository = _scratch_repository(tmp_path / "shallow-green")
    base = _unrelated_head(repository)
    _write(repository, "ja4plus/cli.py", "VALUE = 2\n")
    _record_a_round(repository)
    _commit(repository, "the head of the shallow clone")
    verdict = evaluate(repository, ("origin/dev", "dev"), named=base)
    assert verdict.skip_reason is None
    assert verdict.failure is None, verdict.failure


def test_a_name_the_repository_cannot_read_reads_the_merge_base(tmp_path: Path) -> None:
    """A name that states no commit of the repository leaves the merge base as the reference."""
    repository = _scratch_repository(tmp_path / "unreadable")
    _write(repository, "ja4plus/cli.py", "VALUE = 2\n")
    verdict = evaluate(repository, ("dev",), named="0" * 40)
    assert verdict.skip_reason is None
    assert verdict.failure is not None
    assert "ja4plus/cli.py" in verdict.failure


def test_a_repository_that_holds_neither_reference_names_both_in_the_skip(tmp_path: Path) -> None:
    """A skip reason names the environment variable and the refs it read."""
    repository = _scratch_repository(tmp_path / "neither", initial_branch="release")
    _write(repository, "ja4plus/cli.py", "VALUE = 2\n")
    verdict = evaluate(repository, ("origin/dev", "dev"), named="0" * 40)
    assert verdict.skip_reason is not None
    assert REFERENCE_ENVIRONMENT_VARIABLE in verdict.skip_reason
    assert "origin/dev" in verdict.skip_reason


def test_the_test_job_fetches_the_base_commit_of_a_pull_request() -> None:
    """The `test` job of the workflow fetches the base commit of the pull request."""
    workflow = (REPO_ROOT / WORKFLOW_PATH).read_text(encoding="utf-8")
    assert "BASE_SHA: ${{ github.event.pull_request.base.sha }}" in workflow
    assert 'git fetch --depth=1 origin "+$BASE_SHA:refs/ja4plus/round-entry-base"' in workflow


def test_the_test_job_fetches_the_two_recorded_change_sets() -> None:
    """The `test` job fetches each recorded commit and its parent into a ref."""
    workflow = (REPO_ROOT / WORKFLOW_PATH).read_text(encoding="utf-8")
    assert f"DEFECT_SHA: {DEFECT_COMMIT}" in workflow
    assert f"CONTROL_SHA: {CONTROL_COMMIT}" in workflow
    assert RECORDED_FETCH in workflow


@pytest.mark.parametrize("step", FETCH_STEPS)
def test_a_fetch_step_of_the_test_job_runs_one_git_fetch_command(step: str) -> None:
    """Each step of the `test` job that fetches runs one `git fetch` command."""
    workflow = (REPO_ROOT / WORKFLOW_PATH).read_text(encoding="utf-8")
    assert fetch_count(step_block(workflow, step)) == 1


def test_the_workflow_holds_no_fetch_step_this_list_omits() -> None:
    """`FETCH_STEPS` names every step of the workflow that runs `git fetch`."""
    workflow = (REPO_ROOT / WORKFLOW_PATH).read_text(encoding="utf-8")
    named = sum(fetch_count(step_block(workflow, step)) for step in FETCH_STEPS)
    assert fetch_count(workflow) == named


def test_the_recorded_fetch_step_names_the_tag_that_holds_each_commit() -> None:
    """The step that fetches the two recorded change sets names both tags."""
    block = step_block((REPO_ROOT / WORKFLOW_PATH).read_text(encoding="utf-8"), RECORDED_FETCH_STEP)
    assert DEFECT_TAG in block
    assert CONTROL_TAG in block


def test_the_step_reader_returns_the_lines_of_one_step() -> None:
    """The step reader stops at the next step and it keeps the line that names the step."""
    workflow = (
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - name: The first step\n"
        "        run: git fetch --depth=1 origin main\n"
        "      - name: The second step\n"
        "        run: echo done\n"
    )
    block = step_block(workflow, "The first step")
    assert block == "      - name: The first step\n        run: git fetch --depth=1 origin main\n"


def test_the_step_reader_refuses_a_name_the_workflow_does_not_hold() -> None:
    """The step reader raises where the workflow holds no step of that name."""
    with pytest.raises(AssertionError):
        step_block("      - name: The one step\n", "Another step")


def test_the_step_reader_stops_at_the_last_step_of_a_job() -> None:
    """The step reader stops at the key of the next job and it reads no line of that job."""
    workflow = (
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - name: The last step\n"
        "        run: echo done\n"
        "\n"
        "  lint:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: The first step of the next job\n"
        "        run: git fetch --depth=1 origin main\n"
    )
    block = step_block(workflow, "The last step")
    assert block == "      - name: The last step\n        run: echo done\n\n"
    assert fetch_count(block) == 0


def test_the_fetch_reader_counts_a_command_a_one_line_run_key_holds() -> None:
    """The fetch reader counts a fetch that a one-line `run` key holds."""
    assert fetch_count('        run: git fetch --depth=1 origin "+$BASE_SHA:refs/x"\n') == 1


def test_the_fetch_reader_counts_a_command_that_names_another_repository() -> None:
    """The fetch reader counts a fetch that carries an option before the subcommand."""
    assert fetch_count("          git -C /tmp/clone fetch --depth=2 origin main\n") == 1


def test_the_fetch_reader_counts_no_git_command_other_than_a_fetch() -> None:
    """The fetch reader counts no git command that runs another subcommand."""
    assert fetch_count("          git rev-parse --verify HEAD\n          git diff --stat\n") == 0


def test_the_fetch_reader_counts_no_comment_that_names_the_command() -> None:
    """The fetch reader counts a command and it counts no comment that names one."""
    block = "        # A bare git fetch origin <sha> writes FETCH_HEAD.\n        run: |\n"
    assert fetch_count(block) == 0


def test_the_fetch_reader_counts_one_command_that_carries_two_refspecs() -> None:
    """The fetch reader counts one command where that command names two refspecs."""
    assert fetch_count(f"          {RECORDED_FETCH}\n") == 1


def test_the_workflow_accepts_a_pull_request_into_an_integration_branch() -> None:
    """The base-branch filter of the workflow names the two integration-branch patterns."""
    workflow = (REPO_ROOT / WORKFLOW_PATH).read_text(encoding="utf-8")
    assert WORKFLOW_BASE_FILTER in workflow


def test_the_batch_gate_rule_records_the_widened_filter() -> None:
    """The batch-gate rule states which pull request creates a run, and it cites #438."""
    rule = (REPO_ROOT / BATCH_GATE_RULE_PATH).read_text(encoding="utf-8")
    assert "batch/**" in rule
    assert "epic/**" in rule
    assert "#438" in rule


def test_the_test_job_writes_the_reference_variable() -> None:
    """The fetch step writes the base commit into `ROUND_ENTRY_REFERENCE`."""
    workflow = (REPO_ROOT / WORKFLOW_PATH).read_text(encoding="utf-8")
    assert f'{REFERENCE_ENVIRONMENT_VARIABLE}=$BASE_SHA" >> "$GITHUB_ENV"' in workflow


def test_the_test_job_resolves_the_reference_commit_of_a_manual_run() -> None:
    """The `test` job reads the merge base from the provider where no pull request runs."""
    workflow = (REPO_ROOT / WORKFLOW_PATH).read_text(encoding="utf-8")
    assert NO_PULL_REQUEST_STEP in workflow
    assert NO_PULL_REQUEST_CONDITION in workflow
    assert MERGE_BASE_READ in workflow
    assert 'git fetch --depth=1 origin "+$MERGE_BASE:refs/ja4plus/round-entry-base"' in workflow
    assert f'{REFERENCE_ENVIRONMENT_VARIABLE}=$MERGE_BASE" >> "$GITHUB_ENV"' in workflow


def test_the_batch_gate_rule_states_the_reference_commit_of_a_manual_run() -> None:
    """The batch-gate rule states which commit a manual run reads the change set against."""
    rule = (REPO_ROOT / BATCH_GATE_RULE_PATH).read_text(encoding="utf-8")
    assert "merge_base_commit" in rule
    assert "#541" in rule


def test_the_batch_gate_rule_records_the_one_fetch_of_the_recorded_change_sets() -> None:
    """The batch-gate rule states the shallow-file failure and names the two tags."""
    rule = (REPO_ROOT / BATCH_GATE_RULE_PATH).read_text(encoding="utf-8")
    assert "fatal: shallow file has changed since we read it" in rule
    assert "#586" in rule
    assert DEFECT_TAG in rule
    assert CONTROL_TAG in rule


def test_the_reader_counts_no_round_a_quotation_holds() -> None:
    """The reader counts no entry whose prose quotes a round and states none of its own."""
    quotation = "- **A change** (#3) reports that eight entries read `Round TBD` and it stops.\n"
    assert read_record(BASE_CHANGELOG + quotation, BASE_SPECIFICATION).entries == 1
