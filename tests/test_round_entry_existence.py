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

**Where the change set cannot be read, a case here skips and the reason names the state.**
A shallow clone carries no `origin/dev` ref, and the `actions/checkout` step of
`.github/workflows/test.yml` makes such a clone. A case therefore skips on the runner and
runs on the gate of a worker, whose worktree carries the ref. `evaluate` returns the skip
reason and the failure as two separate fields, so a case reports which one it met.

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

from pathlib import Path
import re
import subprocess
from typing import List, NamedTuple, Optional, Sequence

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

# A git command that reads one ref or one index answers in well under a second. The limit
# bars a hung command from stopping the whole gate.
GIT_TIMEOUT_SECONDS = 60

# The commit #412 shipped. It carried eleven sweeps, two repairs and a new test file, and
# it recorded no round. A case reads it to prove the reading against a real change set,
# because a scratch repository proves the reading against a change set the case wrote.
DEFECT_COMMIT = "46aa502"

# The count of paths a failure names. A sweep changes 30 files, and a message that names
# all of them buries the count that follows it.
NAMED_PATH_LIMIT = 3


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


def reference_commit(
    repository: Path, reference_branches: Sequence[str] = REFERENCE_BRANCHES
) -> Optional[str]:
    """Return the commit the change set reads against.

    Args:
        repository: The root of the repository.
        reference_branches: The refs that name the integration branch, in read order.

    Returns:
        The merge base of `HEAD` and the first ref the repository holds, or None where it
        holds none of them.
    """
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
    repository: Path = REPO_ROOT, reference_branches: Sequence[str] = REFERENCE_BRANCHES
) -> Verdict:
    """Return the verdict on the change set of one repository.

    Args:
        repository: The root of the repository.
        reference_branches: The refs that name the integration branch, in read order.

    Returns:
        A verdict that carries a skip reason where the change set cannot be read, and a
        failure reason where the change set records no round.
    """
    reference = reference_commit(repository, reference_branches)
    if reference is None:
        return Verdict(
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
    verdict = evaluate()
    if verdict.skip_reason is not None:
        pytest.skip(verdict.skip_reason)
    assert verdict.failure is None, verdict.failure


def test_the_reading_fails_the_change_set_of_the_defect() -> None:
    """The reading fails commit `46aa502`, which changed six files and recorded no round."""
    parent = _git(REPO_ROOT, "rev-parse", f"{DEFECT_COMMIT}^")
    if parent is None:
        pytest.skip(f"this clone holds no parent of commit {DEFECT_COMMIT}")
    reference = parent.strip()
    changed = _git(REPO_ROOT, "diff", "--name-only", reference, DEFECT_COMMIT)
    if changed is None:
        pytest.skip(f"git reports no change set of commit {DEFECT_COMMIT}")
    base = read_record(
        document_at(REPO_ROOT, reference, CHANGELOG_PATH),
        document_at(REPO_ROOT, reference, SPECIFICATION_PATH),
    )
    head = read_record(
        document_at(REPO_ROOT, DEFECT_COMMIT, CHANGELOG_PATH),
        document_at(REPO_ROOT, DEFECT_COMMIT, SPECIFICATION_PATH),
    )
    failure = missing_round_entry(changed.splitlines(), base, head)
    assert failure is not None
    assert CHANGELOG_PATH in failure


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


def test_the_reader_counts_no_round_a_quotation_holds() -> None:
    """The reader counts no entry whose prose quotes a round and states none of its own."""
    quotation = "- **A change** (#3) reports that eight entries read `Round TBD` and it stops.\n"
    assert read_record(BASE_CHANGELOG + quotation, BASE_SPECIFICATION).entries == 1
