# The batch gate

**An absent run is not a passed run.** The batch pull request stays the only run of a
member's cases on Linux, because every member commit ends with a skip keyword by design and
#459 measured that such a commit creates no run. `gh pr checks` writes "no checks reported"
where the pull-request event created nothing. That line refuses no merge, so a reader takes
an absence for a pass and merges an ungated batch. #459 records the failure and this file
states the procedure.

## Which pull request creates a run

**Two conditions stand between a pull request and a run, and each one alone stops it.** A
skip keyword in the head commit message is the first, which the section below states. The
base-branch filter of the workflow is the second, and this section states that one.

```yaml
on:
  pull_request:
    branches: [master, dev, "batch/**", "epic/**"]
```

**The `branches` filter of a `pull_request` event matches the base branch and never the
head branch.** GitHub states that the filter runs a workflow "only on pull requests that
target specific branches". Verified against
https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
(retrieved 2026-08-10).

**#438 measured what the older filter of `[master, dev]` cost, and that measurement is the
reason the user widened it on 2026-08-10.** That filter accepted the batch pull request and
the promotion, and it accepted no member pull request, so a pull request into an
integration branch created no run at all. Pull request #519 carried a keyword-free head
into `batch/510-dry-run-and-gates` and the provider held no run for it.

**A check that reaches the batch pull request alone can pass by construction.**
`tests/test_round_entry_existence.py` fails a change set that edits a tracked file and
records no round. A batch pull request reads its change set against the tip of `dev`, and
every member of a batch has already recorded a round, so that check finds an entry whatever
one member did. **The member pull request is the change set the check exists to refuse, and
the older filter kept it away from the job.** Read a new check against this shape before
you trust it.

**The widened filter costs no run that the batch model saved.** A member commit ends with
the keyword, so a member pull request still creates no run. Under the widened filter, a
keyword-free head is the one head that starts a run. A member branch carries such a head
only where a worker writes one on purpose.

**Warning: `master` and `dev` stay in the list.** The batch pull request and the promotion
each target one of them, and they are the runs the merge gate reads.

**A pull request that conflicts with its base creates no run at all, and that is a third
condition.** The workflow runs against the merge commit of the pull request, and the
provider builds no merge commit for a conflicting pull request. #524 measured it three
times on 2026-08-10, on the proof pull request #526. Each time
`gh pr view <number> --json mergeable` read `CONFLICTING`, and
`gh api "repos/Crank-Git/ja4plus/actions/runs?head_sha=<head>"` read `total_count` 0 for a
keyword-free head. **Take the base branch again, and the same head then starts a run.**

```bash
gh pr view <number> --repo Crank-Git/ja4plus --json mergeable,mergeStateStatus
```

**Warning: read that command before you read an absent run as a passed run.** An
integration branch moves under every live member, so this state arrives without a push of
your own.

## A case that skips on every job fails the run

**A skip is not a pass, and a case that runs nowhere is not a case.** #438 measured that
shape. `tests/test_round_entry_existence.py` reported a skip on every job of the matrix
from the day it was written, and every job stayed green while the case refused nothing.

**One job reads no such case, because one job reads one environment.** A macOS case that
skips on Linux is correct, and a Linux case that skips on macOS is correct. The union of
the reports is the first reading that tells a correct skip from a case the suite runs
nowhere.

The `skip-gate` job of `.github/workflows/test.yml` holds that reading. It depends on every
job of the file that runs cases, it downloads the report of each one, and it fails a case
that every report records as skipped. `tests/skip_gate.py` holds the condition and
`tests/test_skip_gate.py` holds that file. Read the same condition by hand:

```bash
python -m tests.skip_gate --reports <download directory>
```

**Warning: add an entry to `tests/universal_skips.json` only where a runner can never hold
the condition the case needs.** A capture grant is such a condition. Every entry names a
reason, and the gate fails an entry that names none.

### The gate reads ten reports, and #530 measured what the six missed

**Warning: a reader that covers part of the suite reports a clean corpus over the part it
cannot see.** #524 bound the gate to the six reports of the `test` job. That job runs
`pytest tests/ -m "not spec_validation"`, and `tests/conftest.py` deselects the
`installed_wheel` marker as well. A read of 2026-08-10 measured each job of the workflow.

| Job | Cases | Cases no report of `test` holds | Skips |
|---|---|---|---|
| `test` | 4150 | 0 | 7 |
| `conformance` | 1918 | 1918 | 143 |
| `installed-wheel` | 43 | 43 | 0 |
| `fuzz` | 127 | 0 | 0 |
| `samples` | 31 | 0 | 0 |

**The suite holds 6111 cases and the six reports held 4150 of them.** The gate therefore
reported a clean corpus over 1961 cases, which is 32 percent of the suite. The `skip-gate`
job waits for all five jobs and it downloads ten reports.

**The `fuzz` job and the `samples` job added no case at that read, and the gate reads them
anyway.** A gate bound to the jobs that one read finds goes stale on the day a job changes
its selection. `tests/test_skip_gate.py` reads `.github/workflows/test.yml` instead: every job
that runs `pytest` writes a report, the download pattern matches the artifact name of every
one of them, and the `needs` list of `skip-gate` names all of them.

**The verdict reads over the jobs that select the case, and over no other job.** A case the
whole matrix collects rests on six environments. A conformance case rests on one, because
the `conformance` job is the one job that selects the `spec_validation` marker. The census
names the report that holds each case it lists, so a reader takes that scope from the run
rather than from a field somebody keeps by hand. **#530 declined a job field on an allowlist
entry on that reading.**

**A case that no job selects at all reaches no report, and this gate holds no such case.**
That is a different finding, and `.claude/rules/batch-gate.md` records it here so that no
reader takes a green gate for a statement about it.

### One entry covers one class of skip

**An entry names one case under `case`, or one class of skip under `skip_message_prefix`.**
The conformance suite parametrizes one case over each vector and each method. A cell where
the vector holds no value and this project produces none reports the message below, and 143
cells reported it on 2026-08-10.

```
not applicable: CVE-2018-6794.pcap holds no JA4SSH value and ja4plus produces none
```

**All 143 belong to one function that ran 199 other parameter sets**, so that function
asserts and no case runs nowhere. A pass in place of the skip would assert an equality over
two empty sets, which #524 put out of scope. `tests/universal_skips.json` therefore holds
one prefix entry in place of 143 case entries.

**Warning: a prefix entry covers a case only where every report that skips it states that
same prefix.** A second reason on one job takes the case back out of the class and the gate
names it. The census reports the count each prefix entry covers, and it names none of those
cases one by one.

**An entry that records an open finding names the issue that removes it.** The census of
#524 found two cases that run on no job while no limit of the runner explains either one.
#528 and #529 hold them. Such an entry states the finding, and it goes out with the repair.

**Warning: `skip-gate` is a twelfth check, and the required list below holds eleven names.**
A red `skip-gate` fails the run, so the batch gate refuses the merge on the run conclusion.
The branch protection rule of `dev` reaches this check once the user adds the name to it,
and that change is the user's alone. #524 records the state.

## Read the gate before every batch merge

**Warning: read this gate before you merge a batch pull request, and never after.**

```bash
python -m tests.batch_gate --pr <number>
```

The command exits 0 on one state alone. Every required workflow holds a terminal
successful run at the head commit of the pull request, and every other run of that commit
concluded `success`. The command exits 1 on every other state, and each of these states
refuses the merge.

- The provider holds no run for the head commit.
- A run of the head commit has not finished.
- A run of the head commit concluded anything other than `success`.
- The read of the provider failed.

`tests/batch_gate.py` holds the condition and `tests/test_batch_gate.py` holds the cases
against it. `.github/workflows/test.yml` is the required workflow, because it accepts
every pull request into `dev` and it filters no path. `.github/workflows/docs-build.yml`
filters four paths, so the gate requires no run of it and a red run of it still refuses
the merge.

## Assign every round number at the batch gate

**Warning: assign a round number at the batch gate, and never at a sub-merge.** A
sub-merge is the merge of one member branch into the integration branch. The project
manager assigns the numbers of a whole batch in one pass, immediately before the batch
pull request. `dev` holds a fixed row count at that moment, so the pass reads one
sequence that no other writer moves.

A member writes the literal `TBD` in place of its round number. The `TBD` reaches two
records, and it stays in both through every sub-merge.

1. The entry of `CHANGELOG.md`, as `Round TBD.`.
2. The Changelog row of `docs/specs/spec.md`, as `| TBD | 2026-08-10 | ... |`.

`tests/test_changelog_round_agreement.py` holds the two records against each other, so an
assignment that covers one file alone fails a case. An integration branch carries one
`TBD` for each member that has not reached the gate, and every one of them is correct.

**The round sequence is global to the repository, and a sub-merge is an event of one
batch.** Two live integration branches therefore assign from one sequence at once, and
neither branch reads the rows of the other until that other branch merges. #482 measured
the result on 2026-08-10, at the sub-merge gate of #456.

```
AssertionError: the Changelog holds 169 rows and its highest round is 173
assert 169 == 173
```

**A project manager who assigns 168 and 169 on the second branch writes two rows numbered
168 and two numbered 169.** That state merges cleanly, and the rule above removes it
rather than reports it.

**Warning: a wrong pairing survives the row-count rule, so read the contiguity case
instead.** `row count == highest round` reads a table that carries 168 twice and 170
nowhere as correct. The count and the maximum both still read right under the wrong
pairing.
`tests/test_specification_changelog.py::test_the_changelog_assigns_every_round_from_one_to_the_row_count`
requires the rounds 1 to the row count, each on one row, and
`test_the_row_count_rule_passes_on_a_table_that_repeats_a_round` holds the measurement of
the older rule.

**One integration branch at a time also removes the race, and this project declines that
order.** It costs the concurrency the batch model exists to provide. #482 records the
decline.

## Never write a skip keyword in a head commit message

**Warning: a skip keyword anywhere in a commit message creates no run for that commit.**

GitHub reads five keywords: `[skip ci]`, `[ci skip]`, `[no ci]`, `[skip actions]` and
`[actions skip]`. It matches the text of the whole message, subject and body. It reads no
intent, so a sentence that states a commit carries no keyword carries one.

**That sentence is the cause #459 measured.** The head commit of pull request #444 and the
head commit of pull request #458 each held this line.

```
This commit carries no `[skip ci]`, so it is the head that starts the full run
on the batch pull request.
```

Neither pull request created a run from the pull-request event. Two control heads,
`ec697c0e` and `b21604ce`, held no keyword and both created their runs. A manual run on
each failing ref started every job and all passed.

Three rules follow.

1. A member commit ends with the keyword, and it names the keyword nowhere else.
2. An integration-branch commit names the keyword nowhere at all.
3. Where prose must discuss the keyword, put that prose in a file and never in a commit
   message.

Verified against
https://docs.github.com/en/actions/how-tos/manage-workflow-runs/skip-workflow-runs
(retrieved 2026-08-09).

## Start a run by hand where the gate refuses

`workflow_dispatch` starts a run through the provider interface rather than the webhook
path, so it runs where a push event and a pull-request event created nothing.

```bash
gh workflow run Tests --repo Crank-Git/ja4plus --ref <branch>
gh run list --repo Crank-Git/ja4plus --branch <branch> --json event,status,conclusion,headSha
```

Read the gate again after the run finishes. **Warning: a manual run reads the branch head
and not the merge result**, so it proves the branch and it does not prove the merge.

## The provider refuses an ungated merge

**`dev` carries a required status check, and the provider refuses a contributor merge that
no successful run of every required context covers.** `enforce_admins` reads `false`, so
the rule binds no repository administrator and an administrator merge reaches `dev` with no
run. The subsection below holds that reading. A read of 2026-08-10 reports the state. #468
turned the rule on and #480 re-took the measurement.

| Read | Result |
|---|---|
| `gh api repos/Crank-Git/ja4plus/branches/dev/protection` | `200`, eleven required contexts |
| `gh api repos/Crank-Git/ja4plus/rulesets` | `[]` |

Each of the eleven contexts carries `app_id` 15368, and the provider holds that number
under `required_status_checks.checks[]`. `required_status_checks.contexts` holds the names
alone, so a reader of that list reads no application at all. No context reads `build` and
none reads the bare `test`. The ruleset list stays empty, so the branch protection rule is the
one place the provider holds this condition.

**A read of 2026-08-09 returned a different result, and this record supersedes it.** That
read reported no protection, and #459 wrote the section around it. The sentence below is
the superseded wording, quoted rather than rewritten.

> **A required status check refuses the merge inside the provider, and this repository
> holds none.** A read of 2026-08-09 reports the state.

| Read | 2026-08-09, superseded | 2026-08-10 |
|---|---|---|
| `gh api repos/Crank-Git/ja4plus/branches/dev/protection` | `404`, `Branch not protected` | `200`, eleven required contexts |
| `gh api repos/Crank-Git/ja4plus/rulesets` | `[]` | `[]` |

**Read the local gate before every batch merge, because the provider rule stands beside it
and replaces it nowhere.** `python -m tests.batch_gate --pr <number>` reads the same
condition, and it reads it before the merge rather than at it. The section above states
that procedure.

### Two limits the same call returned

**`enforce_admins` reads `false`.** The rule binds a contributor, and it binds no
repository administrator. A merge an administrator makes therefore passes the provider
with no run at all, so the local gate stays the procedure for every merge.

**`strict` reads `false`.** A branch merges where it is behind `dev`, and it takes `dev`
again for no other reason. **That reading suits the batch model.** `strict: true` would
demand that every integration branch take `dev` again after another batch lands, and the
new head would then carry no run, so the run that proved the batch would not be a run of
the head.

The token carries the `repo` scope and each read returned a determinate answer, so every
result above is a measurement and not a limit. **A change to branch protection changes the
repository configuration, so the user makes it and no agent makes it.** These four steps
read the rule at the provider, and they change nothing.

1. Open `https://github.com/Crank-Git/ja4plus/settings/branches`.
2. Open the branch protection rule for `dev`.
3. Read `Require status checks to pass before merging`, which is on.
4. Read the eleven check names of the list below against the rule.

**Warning: a check name is not a job name.** The `test` job of
`.github/workflows/test.yml` runs a matrix, so the provider publishes one check for each
combination. A required check named `test` matches nothing. These are the eleven names the
read of 2026-08-10 reports, and a read of commit `b593de5` reported the same names.

```
lint
test (ubuntu-latest, 3.9)
test (ubuntu-latest, 3.10)
test (ubuntu-latest, 3.11)
test (ubuntu-latest, 3.12)
test (ubuntu-latest, 3.13)
test (macos-latest, 3.12)
fuzz
samples
installed-wheel
conformance
```

**Warning: leave the `build` check out of the required list.** It belongs to
`.github/workflows/docs-build.yml`, which filters four paths. A batch that touches none of
those paths creates no run of it, so a required `build` would block every such batch. The
read of 2026-08-10 reports no `build` context, and this warning follows that read.

A required check that never reports blocks the merge, which is the condition this file
otherwise reads by hand.

`tests/test_batch_gate_protection_rule.py` reads this section against
`gh api repos/Crank-Git/ja4plus/branches/dev/protection`, so a change at the provider
fails a case here rather than leaving a reader with a stale rule. One case reads
`required_status_checks.checks[]` and requires `app_id` 15368 on each of the eleven
contexts, so a context of another application fails that case. **Where the call cannot be
made, every live case skips and it does not pass.**

## What this file does not cover

**A gate that reads a green run proves the run and not the code.** A run of the branch
head is not a run of the merge result. A member whose cases never ran on Linux reaches the
batch gate unproven, and `.issue-flow.json` records that history.
