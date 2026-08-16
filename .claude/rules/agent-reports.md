# What a worker reports about the agents it spawns

**A worker spawns review agents, and an agent that never returns is a normal event.** The
worker then writes one comment that stands as the record of the review. This file states
what that comment says about an agent that returned nothing.

**Warning: read this file before you write a self-review comment.** #720 records the defect
that earned it. A worker on #613 spawned two review agents. One reported and one never did,
and the worker wrote up the agent that never reported as though it had.

## The rule

1. A report an agent did not return is reported as absent.
2. A worker names the agent that reported, and it names the agent that did not.
3. An absent report is a normal outcome and it refuses nothing.

**A worker that ran the review itself in place of the absent agent says so.** That sentence
is the whole repair, and it costs one line.

**Warning: rule 3 binds the reader of the comment as well.** An absent report refuses no
merge, it fails no gate, and it earns no tracker issue. A reader who treats it as a failure
gives the next worker a reason to fill the gap.

## Why the rule names the absence as correct

**The worker on #613 reported its own fabrication in the verdict it returned.** It named the
comment and it named the exact sentences. The project manager corrected the comment at
https://github.com/Crank-Git/ja4plus/pull/718#issuecomment-5305142104, and it quoted the
superseded text rather than deleting it.

**A rule that punishes the report rather than the shape removes the one signal that found
this defect.** No gate of this project reads whether a sentence about a review is true. The
worker's own report is therefore the one detection this defect class has. The rule names
the absence as the correct outcome, and it leaves a worker one cheap true thing to say.

**The census of 2026-08-16 measured that the absence is common and that workers report it
plainly.** The corpus holds 20 comments that state a stall of a review child, and each one
states what the worker did instead. One record of the same corpus counts nine stalls in one
session. The rule writes down a practice this project already holds.

## Where the repair belongs

**The repair belongs in two places, and this change makes one of them.**

| Home | What it holds | This change |
|---|---|---|
| `.claude/rules/agent-reports.md` | The rule, the reason, the census, and the limit | Written here |
| `agents/issue-worker.md` of the `issue-flow` plugin | The same rule beside the step that spawns the children | Named, and no line changed |

**The plugin is outside this repository, so #720 names the file and it edits no line of
it.** Step 3 of the runbook spawns the review children. It opens `**Self-review**`, and it
directs the worker to review by specialist lens through Sonnet children. That step names no
outcome for a child that never returns. A second copy of the file stands at
`skills/issue-flow/references/issue-worker.md` of the same plugin.

**Warning: the rule reaches a worker of another repository only through the plugin.** This
file binds a worker of this repository alone, because a worker reads the rules of the
repository it works in. The maintainer owns the plugin change.

## The census of 2026-08-16

**#720 asks whether any earlier record of this repository carries the same shape.** This
section reports the census that answers it.

**Count.** The census read 1842 records. The provider returned each count on 2026-08-16.

- 1101 issue comments. That endpoint holds every pull-request conversation comment.
- 741 issue and pull-request bodies.
- 0 pull-request review comments.

**Method.** The census ran in two passes. The first pass matched every record against a
pattern of two parts. The pattern names a reviewer, a lens, a review agent, a review child
or a Sonnet child, beside a verb of finding. It selected 88 comments and 7 bodies.

The second pass read each selected record in full, and it looked for four signals.

- A quotation of an external document that the record attributes to a review agent.
- A count that the record attributes to a review agent.
- A record that reports findings from more agents than it states ran.
- A plain statement that an agent returned nothing.

Two Sonnet children read 44 comments each. **Both children reported.** The worker read the
7 bodies itself.

**Bound.** The census reads the provider records of this repository alone. It reads no
session transcript, so it cannot compare a write-up against the reports a worker received.
It therefore finds the shape in three cases alone.

- The record contradicts itself.
- The record quotes a source that the source does not hold.
- The worker reported the fabrication.

**A fabrication that stays internally consistent and quotes nothing checkable reaches no
reader of this corpus.** The census reports a clean corpus over that class, and it measures
none of it.

**Finding.** One record of 1842 carries the shape, and it is the record #720 was filed on.
That record is the comment at
https://github.com/Crank-Git/ja4plus/pull/718#issuecomment-5305142104. It attributed these
four things to an agent that never reported.

- A count of 26 re-measured claims.
- A finding of no wrong claim.
- One claim the agent declined to reproduce.
- A quotation of RFC 9000 Section 12.2.

**Every other record is a clean negative, and the clean negative is the result this section
reports.**

**Two records sit next to the shape and neither one is it.**

- The comment at https://github.com/Crank-Git/ja4plus/pull/561#issuecomment-5245948296
  states that a read by lens returned six findings, and it then itemizes five. All three
  lenses reported, and two of them reported nothing. The mismatch is a wrong count and it
  is no fabricated report.
- The comment at https://github.com/Crank-Git/ja4plus/pull/222#issuecomment-5224677084
  states that two child agents never reported, and it then reports a review the worker ran
  again itself. It carries the date 2026-08-08, so it holds rule 2 and rule 3 eight days
  before this file states them.

## No case of this repository refuses this shape

**No case of this repository refuses a fabricated review report, and no case here can.** A
guard that guards nothing costs a reader more than a stated absence, so this section states
the absence.

**A case would need the record of which agents returned, and that record is the session
transcript.** The transcript lives outside this repository, git tracks no copy of it, and a
pull-request comment states no such record either. A case therefore compares the write-up
against nothing.

**A fabricated write-up is well-formed text.** It names lenses, it states counts, and it
reads like a report the worker received. No property of the text parts it from a true
report, so a pattern that matched it would match every honest self-review beside it.

**`tests/test_agent_report_absence_rule.py` holds every claim of this file that a case can
read.** These are the claims it reads.

- The file exists, and it states the three rules of `## The rule`.
- The file states the reason that `## Why the rule names the absence as correct` holds.
- The file names the plugin file, and this repository tracks no copy of that file.
- The census states a count, a method, a bound and a finding.
- The file repeats no heading of `.claude/rules/conformance.md`.

**That module reads no comment of the provider**, because the suite reads the working tree.

**`.claude/rules/conformance.md` states the same discipline for the conformance suite**,
under `## What a green conformance run does not measure`. #736 wrote that section on
2026-08-16 and this file repeats no sentence of it. The two readings share one rule: where a
case cannot read the shape, record what stays unmeasured.
