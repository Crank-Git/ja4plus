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

**A check that reaches the batch pull request alone can pass by construction.** Read a new
check against that shape before you trust it. #438 measured it on 2026-08-10, and the
paragraph below records that reading. The sentences are quoted rather than rewritten.

> `tests/test_round_entry_existence.py` fails a change set that edits a tracked file and
> records no round. A batch pull request reads its change set against the tip of `dev`, and
> every member of a batch has already recorded a round, so that check finds an entry whatever
> one member did. **The member pull request is the change set the check exists to refuse, and
> the older filter kept it away from the job.**

**#727 superseded the example on 2026-08-15, and it left the shape standing.** That issue
moved the round mandate from the change set to the batch pull request, so a member pull
request records no round and this check refuses none.
`## A round is a batch, and the batch pull request records it` below states the model.

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

### The gate reads every report, and #530 measured what the matrix missed

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
job waits for all five jobs and it downloads nine reports.

**The `fuzz` job and the `samples` job added no case at that read, and the gate reads them
anyway.** A gate bound to the jobs that one read finds goes stale on the day a job changes
its selection. `tests/test_skip_gate.py` reads `.github/workflows/test.yml` instead, and it
holds three rules.

1. Every job that runs `pytest` writes one JUnit report and uploads it.
2. The download pattern of `skip-gate` matches the artifact name of every one of them.
3. The `needs` list of `skip-gate` names every one of them.

**The verdict reads over the jobs that select the case, and over no other job.** A case the
whole matrix collects rests on six environments. A conformance case rests on one, because
the `conformance` job is the one job that selects the `spec_validation` marker. The census
names the report that holds each case it lists. A reader therefore takes that scope from
the run, and never from a field that somebody keeps by hand. **#530 declined a job field on
an allowlist entry on that reading.**

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
**#528 and #529 each made that removal on 2026-08-10**, and the allowlist held no open
finding after the second one. Every entry it kept names a limit of the runner.

**A checkout that reads one commit is such a repair, and it costs 32 KB.**
`tests/test_round_entry_existence.py` reads two recorded commits, each against its parent,
and the clone of depth 1 held neither pair. The `test` job fetches each one at depth 2,
into `refs/ja4plus/recorded-defect` and `refs/ja4plus/recorded-control`. **Read a universal
skip against the checkout before you read it as a limit of the runner.**

**Warning: write one `git fetch` in a step, and never two.** Each fetch of a shallow clone
reads `.git/shallow`, and it refuses to finish where that file moved since the read. #586
measured the failure on run
https://github.com/Crank-Git/ja4plus/actions/runs/31452971377, a push of `master` at
`2129964`, job `test (ubuntu-latest, 3.13)`.

```
* [new ref]  46aa502ca47f3c29f3c5ece15e4e78500e2f59c5 -> refs/ja4plus/recorded-defect
fatal: shallow file has changed since we read it
```

**The first fetch succeeded and the second one failed.** #528 wrote two commands in the step
`Fetch the two recorded change sets`, and each one rewrote the shallow file. **One command
that names both refspecs writes that file once**, and #586 took that repair.

```bash
git fetch --depth=2 origin "+$DEFECT_SHA:refs/ja4plus/recorded-defect" "+$CONTROL_SHA:refs/ja4plus/recorded-control"
```

**Read a repair of this kind on a clone of depth 1 before you read it on the runner.** A
clone outside every worktree proves the command and it costs no run. #586 measured the one
command that way: it reported `* [new ref]` twice, it exited 0, `git rev-parse` read the
parent of each commit, and the shallow file carried one line before the command and three
after it. **A read of 2026-08-10 puts the cost at 40 KB**, and a garbage collection ran
before each of the two readings.

**A failure of that step skips both recorded cases, and the `skip-gate` job then reports
nothing at all, because it never runs.** The step fails the job, the job fails the run, and
`needs` holds `skip-gate` behind it.

**Three steps of the `test` job fetch, and the other two each run one command already.**
`Fetch the base commit of the pull request` and `Resolve the reference commit of a run that
carries no pull request` carry opposite `if` conditions. One event therefore reaches one of
those two steps, and neither one needs this repair.
`tests/test_round_entry_existence.py::test_a_fetch_step_of_the_test_job_runs_one_git_fetch_command`
holds all three steps at one command each, and
`test_the_workflow_holds_no_fetch_step_this_list_omits` refuses a fourth fetch that no case
reads.

**Two tags hold the commits that step fetches, and a branch sweep must keep both.**
`record/412-defect` holds `46aa502ca47f3c29f3c5ece15e4e78500e2f59c5` and
`record/429-control` holds `f140a5c318dfbe443b38b8f1a6a7df7d6b098cf0`. The project manager
created them on 2026-08-10, after a sweep left the first commit reachable from no branch.
**That reachability caused no measured failure**, and #586 records that the project manager
stated it as the cause before reading the error. The tags stand on their own reading: a
commit a workflow fetches is a commit some reference must hold. **The step fetches the
identifier and never the tag**, because a tag moves and an identifier does not.

**An install step is such a repair too, and #529 made it.** `pymdownx` reaches a job through
the `docs` extra, and every job installed the `dev` extra alone. The `test` job installs the
`docs` extra on the `ubuntu-latest` job with Python 3.13, so one job of the five runs the
documentation slug case. **Read a universal skip against the installed extras as well.**

**Warning: `skip-gate` is a required check, and the required list below holds its name.**
A red `skip-gate` fails the run, so the batch gate refuses the merge on the run conclusion.
The user added `skip-gate` to the branch protection rule of `dev` on 2026-08-10, and that
change is the user's alone. #546 records the read that measured it. #524 records the
earlier state, where the rule held eleven names and this check stood outside them.

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

## A round is a batch, and the batch pull request records it

**Warning: record one round on the batch pull request, and none on a member pull
request.** #727 moved the mandate on 2026-08-15. The project manager writes the entry and
the row at the batch gate, immediately before the batch pull request, and it assigns the
number in the same pass. `dev` holds a fixed row count at that moment, so the pass reads
one sequence that no other writer moves.

The round reaches two records, and one number covers both.

1. The entry of `CHANGELOG.md`, as `Round 262.`.
2. The Changelog row of `docs/specs/spec.md`, as `| 262 | 2026-08-15 | ... |`.

`tests/test_changelog_round_agreement.py` holds the two records against each other, so an
assignment that covers one file alone fails a case.

**#727 measured what the older model cost.** One issue recorded one round, so
`tests/test_round_entry_existence.py` failed every change set that edited a tracked file
and recorded no round. Each member therefore wrote the two most contended files of the
repository, and each member then conflicted with every other member on them. A read of
2026-08-15 covered the last 300 commits of `master`. 192 of them touch
`docs/specs/spec.md` and 186 touch `CHANGELOG.md`, against 56 that touch a file under
`ja4plus/`.

**Warning: the 261 rounds already recorded stay exactly as they are.** They record past
measurements and `.claude/rules/ste.md` bars a rewrite of such a record. The new model
begins at the next round this project assigns.

### Which change set the mandate reads

`tests/test_round_entry_existence.py` reads the branch the change set belongs to, and
`records_a_round` holds the condition. A branch whose name opens with `batch/` or `epic/`
records a round. Every other branch records none, and the reading refuses no round it
finds on one.

**The two prefixes match the two patterns of the base-branch filter above.** One model
therefore names an integration branch in the filter and in the mandate.

**The `test` job names that branch in `ROUND_ENTRY_BRANCH`, because a run of a pull request
checks out a detached merge commit.** `git rev-parse --abbrev-ref HEAD` then answers the
literal `HEAD` and names no branch, so the case would skip on every job and `skip-gate`
would fail the run. The step `Name the branch the change set belongs to` reads
`github.head_ref` first and `github.ref_name` second, which names the head branch on every
event the workflow accepts.

### One guard still takes a record from a member

**Warning: the routine `TBD` sweep goes out with the older model, and one exception keeps
the form.** A member that writes no round record leaves nothing to assign later, so the
sweep covers no member of a routine batch.

**`tests/test_breaking_change_record.py` requires a record from the member that trips it.**
It requires that `CHANGELOG.md` and `docs/specs/spec.md` each record the Python floor the
package states. #575 moved that floor and met the result: a reader that demanded a number
could not pass on the branch that made the move. Such a member writes `Round TBD.` and the
matching row, and the project manager assigns the number at the batch gate.

**#395 records why that guard stands.** A comparison between two records finds no change
that is absent from both of them, and the move of the floor from 3.8 to 3.9 was such a
change. #727 therefore kept the guard, and it kept the `TBD` form the guard reads.

### The race the older model measured

**The round sequence is global to the repository, and a sub-merge is an event of one
batch.** Two live integration branches therefore assigned from one sequence at once, and
neither branch read the rows of the other until that other branch merged. #482 measured
the result on 2026-08-10, at the sub-merge gate of #456.

```
AssertionError: the Changelog holds 169 rows and its highest round is 173
assert 169 == 173
```

**#727 removes that race for every routine member.** One batch writes one round at its own
gate, and the project manager runs one gate at a time, so no second writer moves the
sequence between the read and the write.

**Warning: a wrong pairing survives the row-count rule, so read the contiguity case
instead.** `row count == highest round` reads a table that carries 168 twice and 170
nowhere as correct. The count and the maximum both still read right under the wrong
pairing.
`tests/test_specification_changelog.py::test_the_changelog_assigns_every_round_from_one_to_the_row_count`
requires the rounds 1 to the row count, each on one row, and
`test_the_row_count_rule_passes_on_a_table_that_repeats_a_round` holds the measurement of
the older rule. **That case stays.** It caught the duplicate rounds of #482, and it is
cheap under the new model.

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

### A manual run names its own reference commit

**Warning: a manual run carries no pull request, so a case that reads the base commit of
one runs nowhere.** #541 measured that state on 2026-08-10. Run
https://github.com/Crank-Git/ja4plus/actions/runs/31421263768 reads `event=workflow_dispatch`
and `conclusion=failure`, its `skip-gate` job reads `failure`, and every other job of that
run reads `success`.
`tests.test_round_entry_existence::test_the_change_set_of_this_branch_records_a_round`
skipped on all six jobs of the matrix. `ROUND_ENTRY_REFERENCE` stayed empty, and the clone
of depth 1 holds no `origin/dev` ref for `git merge-base` to read. **The recovery path of
the section above therefore produced a red run on every branch.** A reader could not tell a
real failure from that one.

**The gate is right about what it measures and wrong about what it concludes.** A case that
a given event does not select is no finding of that event. #541 took the reading that makes
the case run on every event, and it declined the two readings that excuse the skip on one.

- The first reading runs the `skip-gate` job nowhere on a manual event. It leaves the
  manual run with no skip gate at all, which is the reading a recovery path can least
  afford.
- The second reading accepts the skip where the run carries no pull request. It leaves the
  case unrun on the one path a reader reaches for where every other path failed.
- The third reading names a reference commit the manual run holds. It costs one read of the
  provider and one fetch of one commit, and #541 took it.

The `test` job holds the step `Resolve the reference commit of a run that carries no pull
request`. It reads the merge base of `GITHUB_SHA` and `dev` from the provider, fetches that
one commit at depth 1, and writes it into `ROUND_ENTRY_REFERENCE`.

```bash
MERGE_BASE=$(gh api "repos/$GITHUB_REPOSITORY/compare/dev...$GITHUB_SHA" --jq .merge_base_commit.sha)
```

**The provider reads the merge base, because the clone of depth 1 holds no history.** The
basehead form is `BASE...HEAD` and the response holds `merge_base_commit`. Verified against
https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28 (retrieved
2026-08-10). The read names `dev`, which is the first ref the local gate reads. The runner
and a checkout therefore read the change set against the same commit.

**Warning: a push to `master` carries the same defect, so the condition names the pull
request and never the manual event.** `actions/checkout` writes the one remote-tracking ref
the event names. A push to `dev` therefore holds `origin/dev`, `git merge-base` answers,
and the push run of `dev` at `31cca24` concluded `success` on `skip-gate`. **A push to
`master` holds `origin/master` alone**, so `git merge-base` answers nothing and the case
would skip on every job. **A promotion of `dev` to `master` is a push of that second
kind**, and a condition of `github.event_name == 'workflow_dispatch'` would leave the
release run red. The step therefore reads `github.event_name != 'pull_request'`, and the
two `if` conditions of the `test` job cover every event the workflow accepts. The
self-review of #541 raised this reading, and no push run of `master` has measured it since
round 197 added the `skip-gate` job.

## The provider refuses an ungated merge

**`dev` carries a required status check, and the provider refuses a contributor merge that
no successful run of every required context covers.** `enforce_admins` reads `false`, so
the rule binds no repository administrator and an administrator merge reaches `dev` with no
run. The subsection below holds that reading. #468 turned the rule on. #480 took the first
measurement and #546 re-took it. **#575 dropped the Python 3.9 job of the matrix on
2026-08-10, so the rule requires eleven contexts and the user removes the twelfth at the
provider.** The table states the reading each call returns once the user makes that change.

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

| Read | 2026-08-09, #459, superseded | 2026-08-10, #480, superseded |
|---|---|---|
| `gh api repos/Crank-Git/ja4plus/branches/dev/protection` | `404`, `Branch not protected` | `200`, eleven required contexts |
| `gh api repos/Crank-Git/ja4plus/rulesets` | `[]` | `[]` |

**The read of 2026-08-10 that #480 took reported eleven required contexts, and this record
supersedes it.** The user added `skip-gate` to the branch protection rule of `dev` on the
same date, between the two reads. The sentence below is the superseded wording, quoted
rather than rewritten.

> Each of the eleven contexts carries `app_id` 15368, and the provider holds that number
> under `required_status_checks.checks[]`.

| Read | 2026-08-10, #480, superseded | 2026-08-10, #546 |
|---|---|---|
| `gh api repos/Crank-Git/ja4plus/branches/dev/protection` | `200`, eleven required contexts | `200`, twelve required contexts |
| `gh api repos/Crank-Git/ja4plus/rulesets` | `[]` | `[]` |

**The read of 2026-08-10 that #546 took reported twelve required contexts, and this record
supersedes it.** #575 dropped Python 3.9 from the test matrix, so no job publishes
`test (ubuntu-latest, 3.9)` and that context never reports again. **The user removes the
context at the provider, and no agent removes it.** The sentence below is the superseded
wording, quoted rather than rewritten.

> Each of the twelve contexts carries `app_id` 15368, and the provider holds that number
> under `required_status_checks.checks[]`.

| Read | 2026-08-10, #546, superseded | The rule after #575 |
|---|---|---|
| `gh api repos/Crank-Git/ja4plus/branches/dev/protection` | `200`, twelve required contexts | `200`, eleven required contexts |
| `gh api repos/Crank-Git/ja4plus/rulesets` | `[]` | `[]` |

**Warning: two reads of 2026-08-10 stand in this section, so read the issue beside the
date.** #480 took the first and #546 took the second. Every live sentence of this section
states the rule that #575 leaves.

**Warning: two cases of `tests/test_batch_gate_protection_rule.py` fail between the merge
of #575 and the change at the provider.** `test_the_provider_requires_the_contexts_the_rule_file_lists`
and `test_the_provider_carries_the_stated_application_on_every_context` read the provider
against this list. That failure is correct, and it clears when the user removes the
context.

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
combination. A required check named `test` matches nothing. These are the eleven names this
rule requires after #575. The record above holds the twelve names of the #546 read.

```
lint
test (ubuntu-latest, 3.10)
test (ubuntu-latest, 3.11)
test (ubuntu-latest, 3.12)
test (ubuntu-latest, 3.13)
test (macos-latest, 3.12)
fuzz
samples
installed-wheel
conformance
skip-gate
```

**`skip-gate` is the eleventh name.** Round 201 built the job that publishes it. The job
downloads the report of every job that runs cases. It fails a case that every one of those
reports records as skipped. `## A case that skips on every job fails the run` above holds
the whole condition. **A red `skip-gate` refuses the merge on the same rule as a red
`lint`.**

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
