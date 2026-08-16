---
paths:
  - "ja4plus/fingerprinters/**/*.py"
  - "ja4plus/utils/**/*.py"
  - "tests/test_spec_validation.py"
---

# Conformance rules for a fingerprinter

A fingerprint exists so that one tool's output can be compared against another tool's
output. A fingerprint that does not match the FoxIO reference is worse than no
fingerprint, because it looks usable and is not.

## The authority rule

**The specification decides intent and schema. The vectors decide the exact bytes where
intent runs out. A provable reference defect is declined and recorded.**

Read the rule in three parts.

1. The FoxIO specification under `technical_details/` states what a method measures and
   what its output looks like. Start there, and never build a method from a vector alone.
2. Where the specification leaves a byte open, the expected-output files decide. That is
   the only case the vector settles.
3. Where the reference implementation produces a value by accident, this project declines
   it under the two shapes below, and records the decline.

The user stated the rule on 2026-08-08. `docs/specs/foxio/README.md` holds the inventory
of the specification material and the transcription procedure.

## Before you change a fingerprinter

1. Run `pytest tests/ -m spec_validation` and record the result.
2. Find the FoxIO material for the method under
   `https://github.com/FoxIO-LLC/ja4/tree/main/technical_details`.
3. Find the expected value in `tests/foxio_vectors/<capture>.json`.
4. Write the failing test first. The test names the vector and the expected value.
5. Change the code.
6. Run the conformance suite again. No vector that passed before may fail now.

**Never change a fingerprint without a vector, or a test derived from the FoxIO
material, that proves the change is correct.** A change that no test covers is a guess
that reaches a user as an identifier they will compare against something else.

## Reading the expected output

An expected-output file is a JSON array. Each element describes one stream. A key is a
method name plus an occurrence counter.

```json
{
  "stream": 0,
  "src": "172.16.225.48",
  "dst": "54.160.114.75",
  "srcport": "57377",
  "dstport": "22",
  "JA4SSH.1": "c36s36_c76s124_c0s0"
}
```

`JA4SSH.1` is the first JA4SSH fingerprint on that stream. `JA4SSH.2` is the second. A
method that emits more fingerprints than the reference is a defect, and so is one that
emits fewer.

## What a green conformance run does not measure

**Warning: a green conformance run states nothing about the frame that carries a value.**
The suite compares one value for each stream, and it never compares the packet that
produced it. #736 measured the limit on 2026-08-16 and this section records it.

**#606 moved seven values from one frame to another, and the suite discriminated none of
them.** That issue moved the QUIC `JA4L-S` emission from the packet that fills point `B`
to the packet that fills point `D`. #736 restored the point `B` emission and ran the suite
again. The three counts held at 1676 passed, 142 skipped and 138 xfailed under the change
and under the restored defect. These are the seven moves.

| Capture | The move |
|---|---|
| `chrome-cloudflare-quic-with-secrets.pcapng` | 49 to 52 |
| `ssh2.pcapng` | 1140 to 1147 |
| `tls3.pcapng` | 144 to 147 |
| `tls3.pcapng` | 149 to 153 |
| `tls3.pcapng` | 155 to 162 |
| `tls3.pcapng` | 159 to 167 |
| `tls3.pcapng` | 303 to 312 |

### One of the four reference sources states a frame

**The conformance value comparison reads the one source that frames nothing.** A per-frame
comparison is possible only where a source states the frame, and #736 read all four.

| Source | States a frame | Values |
|---|---|---|
| FoxIO Python expected output, `tests/foxio_vectors/*.json` | No | 1203 |
| FoxIO Rust snapshots, `tests/foxio_vectors/rust_expected/*.snap` | No | 460 |
| Zeek baselines, `tests/foxio_vectors/zeek_expected/` | No | 7 baselines |
| FoxIO Wireshark dissector, `tests/foxio_vectors/wireshark_expected/*.json` | Yes, `frame.number` | 724 |

**The first three key a value on the stream or on the connection.** A Zeek baseline names
`orig_pkts` and `resp_pkts`, and each one counts the packets of a connection rather than
names one of them. **The dissector frames every value it writes**, and #736 measured 724
framed values and none unframed across 26 files.

**The conformance suite builds all 1203 of its value cases from the first source.** No case
of the suite can read a frame, because the source it reads states none.

### Why the suite compares no frame

**The suite compares the FoxIO Python reference, and the dissector holds a different value
set.** A per-frame comparison reads a new source. It therefore adds no discrimination to
any case the suite runs today.

**#736 measured what that comparison would report on 2026-08-16.** The measurement ran the
`Processor` over each of the 26 captures this project holds, it numbered each packet, and
it read the 445 dissector values of a hashed form against the result. **Warning: the three
counts below are one measurement, and no case holds them.** Take them again before you
build on them.

| Reading | Values |
|---|---|
| The value agrees and the frame agrees | 206 |
| The value agrees and the frame differs | 136 |
| This project produces no such value | 103 |

**The 136 frame disagreements are values this project already produces correctly.** Each
one would enter `tests/foxio_deviations.json` as a new entry. Each entry would record a
difference this project has already ruled.

**The TCP `JA4L` and `JA4LS` values hold 70 of the 136.** The dissector writes each one on
a later frame than this project, and none of the 70 is a QUIC value. **A comparison whose
largest class is a recorded divergence measures the register and not the code.**

**The frame is an artifact of one dissector, and the value is what the standard defines.**
Two FoxIO implementations produce the same value on different packets, and neither one is
wrong. This project therefore declines the per-frame comparison in the conformance suite.

### Where the frame is measured instead

**A frame this project rules on gets a case of its own.**
`tests/test_ja4l_quic_point_d_emission.py` holds the frame of every QUIC `JA4L` value
against `frame.number` of the dissector, and it runs in the unit suite. #736 restored the
point `B` emission and measured 8 failures in that module, against 0 in the conformance
suite.

**Warning: leave that module in the unit suite, and never move it to the conformance
suite.** The `test` job runs the unit suite on five environments. `.github/workflows/test.yml:86-91`
holds that matrix: `ubuntu-latest` on Python 3.10, 3.11, 3.12 and 3.13, and `macos-latest`
on Python 3.12. The `conformance` job runs the conformance suite on one environment. A move
would therefore take four readings away from the one frame guard this project holds. #736
declined the move on that reading.

**Warning: the count of five is the matrix after #575, and an older record states six.**
That issue dropped Python 3.9 on 2026-08-10. `.claude/rules/batch-gate.md` records a
measurement of that date over six jobs, and that record stays exactly as it is. Read the
workflow for the present count, and never a record of a past measurement.

**Warning: read a frame ruling against the unit suite, and never against the conformance
counts.** `tests/test_conformance_frame_discrimination.py` holds this whole reading. A
source that starts to state a frame therefore fails a case there, and it leaves no reader
with a stale rule.

## When the FoxIO reference holds a defect

The FoxIO reference decides behavior. It does not decide behavior that the reference
itself produces by accident.

**A defect is proven, never asserted.** Instrument the FoxIO implementation at the pinned
commit, or measure the vector directly, and put the command and its output in the issue.
A reading of the source alone is not proof.

**`ja4plus` declines a proven defect when reproducing it would do either of these.**

1. Make a fingerprint depend on something other than the connection: the composition of
   the capture, the order the capture is read, or the position of the connection in the
   file.
2. Make `ja4plus` emit a fingerprint that describes no traffic.

A fingerprint exists so that one tool's output can be compared against another tool's
output. A value that changes with the file it was read from cannot be compared, and a
value that describes nothing cannot be read.

**A declined defect is recorded, never hidden.** Open an issue that states the mechanism
and the evidence, close it as a documented divergence, and point every affected register
entry at it. The cost goes in the issue: how many cases stay unmatched, and in which
direction.

**A defect outside those two shapes is a question for the user.** Do not extend this rule
by analogy.

Decided on 2026-08-07. #96, #97 and #105 are the first three.

## What a delegated session may rule

**The user delegates a session to a project manager, and this section states what that
delegation permits.** The user granted two delegations, and both hold today. A question
that fails both belongs to the user.

| Delegation | Date | What it reaches | Where the delegation lives |
|---|---|---|---|
| The narrow delegation | 2026-08-12 | A schema violation. | `Crank-Git/ja4plus-go#246`, and #597 here |
| The recording delegation | 2026-08-15 | A reading this project already holds. | The ruling comments of #595, #607, #608 and #613 |

**A ruling lands in this repository and in the port together, or in neither.**
`.claude/rules/parity.md` of `Crank-Git/ja4plus-go` states that rule, and
`.claude/rules/rulings.md` of that repository holds the port half of the narrow
delegation.

### The narrow delegation of 2026-08-12

**A schema violation has one right answer, and a reference split has none.** That sentence
is the boundary. The project manager rules a schema violation under this delegation. It
rules no reference split, and it rules no other question.

**A delegated ruling is a ruling, and never a reading.** A reading concludes what one
source states. A delegated ruling settles what this project does where a published FoxIO
value contradicts a published FoxIO rule. No source settles that question, because FoxIO
publishes both of them.

A project manager makes a delegated ruling only where every one of these is true.

1. A published FoxIO rule states the answer. The rule reaches the material under
   `technical_details/`, the transcription of it under `docs/specs/foxio/<METHOD>.md`, or
   a FoxIO reference implementation.
2. Every FoxIO implementation enforces that rule. One implementation that departs makes
   the question a reference split, and this delegation bars a reference split.
3. A recorded measurement proves the violation, and each citation names a file and a line.
   `## When the FoxIO reference holds a defect` above states that a defect is proven and
   never asserted.
4. The record of the ruling carries a provisional marker, and it names the issue.
5. The record names a reversal path, so the user reverses the ruling with one action.

**A question that fails one condition leaves this delegation.** The project manager reads
it against the recording delegation below.

### The recording delegation of 2026-08-15

**The user granted a second delegation on 2026-08-15.** Four ruling comments each state it
in these words: #595, #607, #608 and #613. This file quotes them, and it rewrites no word
of the delegation.

**Warning: never open a line of this file with an issue number.** The section reader of
`tests/test_ported_pattern_cost.py` reads a line that opens with `#` as a heading, and it
then stops at that line. A paragraph below such a line reaches no case.

> The maintainer granted a delegated session this carve-out on 2026-08-15: a delegated
> session may rule where the decision preserves the present behaviour, moves no
> fingerprint, and records an existing reading as a divergence register row. A decision
> that moves a value, that forks from `ja4plus-go`, or that changes the scope of the
> project stays with the maintainer.

**The delegation states three limits, and a permitted question meets every one of them.**

- The ruling keeps the present behavior of this project.
- The ruling moves no fingerprint value.
- The ruling writes one row of the divergence register.

**A ruling that moves a value stays with the user.** A ruling that parts this project from
the port stays with the user. A ruling that changes the scope of this project stays with
the user.

**The project manager ruled each of the four issues under this delegation on 2026-08-15,
and no line of a fingerprinter moved.** #595 records the JA4L eviction of the QUIC path, #607 records the
JA4H emission frame, #608 records the JA4SSH packet selection, and #613 records the one
QUIC packet each datagram fills point C from.

### How the two delegations relate

**The two delegations reach different questions, and neither one repeals the other.**

- The narrow delegation settles what this project does, and it can move a fingerprint
  value. It therefore bars a reference split: a wrong answer there makes this project
  answer differently from a FoxIO implementation on the same bytes.
- The recording delegation records what this project already does, and it moves no
  fingerprint value. A reference split therefore reaches it. #595 and #613 are each such a
  question, and each ruling of 2026-08-15 left every line of the fingerprinter as it
  stood.
- **A reference split is never delegable as a schema violation.** Condition 2 of the
  narrow delegation bars it, and no reading of the evidence removes that bar.
- **Every delegated ruling is provisional under both delegations**, and each one names a
  reversal path.

**A question that fails both delegations belongs to the user.** The project manager labels
that issue `status:needs-feedback`. It records the reading it holds. It builds nothing that
depends on the answer.

**The user confirms a delegated ruling, or reverses it.** A delegated ruling that the user
has not confirmed stays provisional. A later reader reads a provisional ruling as
unconfirmed, and never as settled.

### The worked example both repositories share

`Crank-Git/ja4plus-go#223` is the first delegated ruling, and the user confirmed it on
2026-08-12. A published FoxIO value contradicts a rule that four implementations enforce.
`zeek/ja4ssh/main.zeek:63`, `wireshark/source/packet-ja4.c:400`, `rust/ja4/src/ssh.rs:284`
and `python/ja4ssh.py:51` each state that the JA4SSH mode is `0` when the side sent no SSH
packet. `python/test/testdata/ssh-scp-1050.pcap.json` holds `c112s1460_c0s200_c36s0`,
which pairs a client mode of `112` with a client packet count of `0`.

**This project already reads the mode of the window alone**, and #96 holds that rule. The
narrow delegation therefore moved no fingerprint here, and it moved no exported name.

## When the FoxIO material is ambiguous

Eleven of the twelve methods are published as an image. Only JA4 holds a complete text
specification. Read the image before you call it ambiguous. An image nobody read settles
nothing, and it permits no fallback.

1. Read the image at the pinned commit.
2. Read the transcription under `docs/specs/foxio/<METHOD>.md`.
3. If the image does not settle the question, the expected-output file decides.
4. Record the reading in `docs/implementation_notes.md`, with the vector that supports
   it.
5. Never guess from the method name or from another implementation.

## State rules

- Every state table has a maximum entry count and a maximum age. A state table survives
  across packets.
- A structure that one packet or one request builds and releases is not a state table,
  and it holds neither bound. The cookie list of one HTTP request is such a structure,
  and #175 records the ruling.
- The boundary removes no bound from a state table. The six unbounded state tables that
  #179 records keep their bound.
- Eviction uses the packet timestamp when the packet carries one. A capture file replays
  faster than real time, and a wall clock would evict state the capture still needs.
- No fingerprinter holds a reference to a packet object after `process_packet` returns.
- A stateful fingerprinter implements `cleanup_connection` and normalizes the 5-tuple to
  its own key format.
- A fingerprinter catches the parse errors it expects. It does not catch bare
  `Exception`.

## Ask whether a case can fail

A comparison that is never made reads as a comparison that passes. The project has found
twelve of them, and a worker who worked on something else found every one.

Coverage answers a different question. Coverage reports which line runs. This question
asks whether a line that runs is measured. #172 built a sweep that asks it.

`tests/mutation_sweep.py` changes one expression in one module under `ja4plus/`, runs the
suite, and records which cases fail. The change is a measurement, and the sweep reverts
it. A case that no mutation makes fail is a candidate.

**Warning: the sweep writes to a module file. Commit or stash your work first.** The
sweep refuses to start when `ja4plus/` holds an uncommitted change, and it restores every
file it changes. A stop signal reaches the restore, and `SIGKILL` does not. If a killed
sweep leaves a change behind, the next sweep refuses to start; run
`git checkout -- ja4plus/` to drop it.

**A checkpoint belongs to one commit.** It keys each result on the position of the
expression in the file, so a code change moves the key. Delete the checkpoint file when
the code changes.

Run the sweep from the repository root:

```bash
python tests/mutation_sweep.py --max-per-module 12 --report mutation_sweep.json
python tests/mutation_sweep.py --dry-run --max-per-module 0     # count the mutations
python tests/mutation_sweep.py --module "ja4plus/utils/tls_utils.py" --max-per-module 0
```

**Warning: measure the run before you start it.** One run of the whole suite took about
17 seconds when #172 built the sweep. #411 measured 72.75 seconds on 2026-08-09, over
4325 collected cases, and no single case dominates that time. The cost of a sweep is the
mutation count times the cost of one suite run, so a suite that grows raises every sweep.
Read the mutation count with `--dry-run --max-per-module 0`, multiply it by a measured
suite run, and state the product before the sweep starts. **Never estimate either
number.**

#411 measured 3545 mutations over 31 modules, so one whole-package sweep costs 71.6 hours
on one host. **A checkpoint makes such a run resumable, and it removes no work.**

**Sweep one module group at a time, and scope the suite to the test files that read it.**
`tests/mutation_sweep.py:482` runs the whole suite for each mutation when `--tests` names
nothing, and the 72.75 seconds above is the cost of that whole suite. A scoped sweep runs a
small suite for each mutation, and it names a candidate set that belongs to that module
group by construction. The project manager partitioned the sweep on 2026-08-09 for both
reasons.

```bash
python tests/mutation_sweep.py --max-per-module 0 \
  --module "ja4plus/utils/tls_utils.py" --tests tests/test_tls_utils.py \
  --report docs/mutation_reports/412-utils.json
```

The report holds four parts.

- `commit` names the commit the sweep read, from `git rev-parse HEAD` at the start of the
  run. A checkpoint belongs to one commit, and `FR-pre-release-validation-17` asks the
  report to state it. #411 added the field.
- `modules` names every module, and every mutation the sweep applied to it. A mutation
  records the line, the text before, the text after, and the count of the cases it killed.
- A mutation whose status is `survived` killed no case. A mutation whose status is
  `unusable` failed the whole suite, because it broke an import, and the sweep drops it. A
  mutation whose status is `timeout` passed the time limit of one suite run.
- `candidates` names every case that no mutation killed.

**Warning: one mutation can turn a loop bound into a loop that never ends.** The sweep then
never returns, and the checkpoint records nothing. `ja4plus/utils/ssh_utils.py:284` holds
such a bound: the sweep reads `while position < len(payload)` as
`while position <= len(payload)`, and `SSHMessageTracker.process_payload` then loops with
no progress. **Name `--timeout` to bound one suite run.** #412 met the hang three times
before it added the option. The limit is off by default, so a sweep that names no
`--timeout` behaves as it did before.

```bash
python tests/mutation_sweep.py --max-per-module 0 --timeout 90 \
  --module "ja4plus/utils/ssh_utils.py" --tests tests/test_ja4ssh_deep.py
```

## How to scope one sweep: the minimal cover

**Scope each module to the smallest test-file set that still runs every mutation line of
that module.** The user ruled on 2026-08-09, after #412 measured the rule "name every test
file that reads the module" at **32.18 hours** over 1420 mutations. The minimal cover
measures **0.52 hours** for the same 1420 mutations.

Build the cover from a measurement and not from a file name.

1. Run each test file on its own under `--cov=ja4plus --cov-report=json`, and record the
   executed line set of the module.
2. Subtract the lines the import runs. Every test file that imports `ja4plus` runs every
   module-level constant, so a cover built on import reach names every file.
3. Take the test files that run a mutation line, greatest lines for each second first,
   until the set runs every reachable mutation line.
4. Run `python -m tests.mutation_cover <module>`. Put the body reader it names in the
   cover.

**Step 2 leaves every mutation of the module body without a case that reads it.** Step 4
names the body reader by the value and never by the cost. `tests/mutation_cover.py` reads
the names the module body binds and the identifier strings those statements build. It then
names the test file whose own source holds the most of those tokens. A file that reads the
value kills a mutation of the value, and the cheapest file reads no value at all.

**#433 measured the repair on `ja4plus/__init__.py`, at commit `00a0c42`, over all 32
mutations of the module.** The cost rule alone builds the cover `tests/test_parity.py`. That
sweep costs 43.2 seconds, it reads 1 killed and 31 survived, and all 25 entries of `__all__`
survive it. Step 4 adds the reader `tests/test_public_interface.py`, and one sweep against
that file alone costs 39.9 seconds. The repaired cover reads 26 killed and 6 survived in
48.0 seconds, and no entry of `__all__` survives it.

**State this fourth limit beside the three below.** The body reader kills a mutation of the
value it reads. It kills no other mutation of the module body. The three survivors of the
module body above are `__version__`, `__author__` and `__license__`, which
`tests/test_public_interface.py` names and never compares against a value.

**State these three limits wherever the result is read.**

- **Every mutation keeps a reader**, so a mutation that no case kills is still found. The
  surviving-mutation signal is preserved.
- **The cover is conservative in the safe direction.** A test file the cover drops might
  have killed a mutation, so the cover can report a survivor that a wider run would have
  killed. **It over-reports survivors and it does not under-report them.**
- **The candidate set shrinks**, because fewer cases are evaluated. A case the cover drops
  stays unmeasured against that module, and the record names that rather than implying the
  module is fully measured.

**Record the cover of each module in the settlement record**, so a later reader widens it
without deriving the cover again. `docs/mutation_settlements/412-utils.json` holds the
first one, under the `scope` key.

**Warning: `git ls-files 'ja4plus/**/*.py'` lists 24 files and the package holds 31.** Git
reads `**` in a pathspec as one or more directories, so the pattern matches no file of the
top directory of the package. It omits `ja4plus/cli.py` and `ja4plus/processor.py` among
seven. Write `git ls-files 'ja4plus/*.py'` to list every module. **In a default git
pathspec, `*` crosses `/`**, so that one term reaches every depth. Only `:(glob)` magic
stops `*` at a separator, and `git ls-files ':(glob)ja4plus/*.py'` lists 7 files.

**Read `DEFAULT_MODULE_PATTERNS` of `tests/mutation_sweep.py` under the other rule.** It
reaches `Path.glob`, where `*` stops at `/`, so the sweep holds the pair `ja4plus/*.py`
and `ja4plus/*/*.py`. `tests/test_mutation_sweep_module_list.py` fails when the pathspec,
the pair and the tracked files stop agreeing, so no writer reintroduces the `**` form in
silence. #436 records the reading, and #411 and #414 each met the earlier one.
**The front matter of `.claude/rules/ste.md` and of
`.claude/rules/external-apis.md` holds `ja4plus/**/*.py`, that glob follows the gitignore
rules, and it matches every module. Do not repair those.**

## How to read the census

`tests/mutation_census.py` reads every `*.json` report of `docs/mutation_reports/` and
counts the candidates of each test file. **It opens no Markdown file**, because a Markdown
report is one page and a count taken from its lines counts the page layout.

**The census groups by test file and not by module.** `tests/mutation_sweep.py:593` builds
one flat candidate list over every module one sweep read, so no module owns a candidate. A
sweep of one module names a candidate set that belongs to that module by construction, and
that is the sweep each module group runs.

**Warning: the union of the per-module sweeps is larger than the candidate set of one
whole-package sweep.** A reader who compares the two counts reads a regression that did not
happen. A whole-package sweep names the cases that no mutation of any module kills. A sweep
of module X names the cases that no mutation of X kills, and a case that module Y kills
still reaches that list. **The union is the correct input for settlement**, because a case
module Y kills is still unmeasured against module X.

**A candidate is keyed by the sweep that named it and by the case.** Two sweeps may name
the same case, and that is one candidate for each sweep and not a duplicate claim. Each one
needs its own settlement.

The census reads every `*.json` record of `docs/mutation_settlements/`, so three issues
settle three module groups at the same time and no file is shared. Each record names the
sweep it settles, and it holds this shape.

```json
{
  "issue": 412,
  "sweep": "412-utils",
  "modules": ["ja4plus/utils/tls_utils.py"],
  "settlements": [
    {"candidate": "tests/test_a.py::test_b", "verdict": "repaired", "case": "tests/test_a.py::test_c"},
    {"candidate": "tests/test_a.py::test_d", "verdict": "correct", "reason": "The mutation is equivalent."}
  ]
}
```

The `sweep` field names the stem of the report file under `docs/mutation_reports/`, so
`412-utils` settles `docs/mutation_reports/412-utils.json`.

`FR-pre-release-validation-22` states the two verdicts. A `repaired` verdict names the
case, and a `correct` verdict states the reason the mutation cannot reach the case.

The census names each of these.

1. Every candidate that two records claim.
2. Every candidate that no record claims.
3. Every settlement of a case no report names a candidate.
4. Every record that names a sweep no report holds.
5. Every report or record that holds no key its schema states.

**A broken file reaches that list, and it raises nothing.** Three issues write these
directories at the same time, so the census meets a half-written record. A reader needs the
name of the broken file, and a traceback from a dictionary lookup names the key alone.

Read a candidate this way.

1. Read the case first. A case may be correct and the mutation wrong.
2. If the mutations reach no code the case names, sweep that module whole with
   `--max-per-module 0`, and read the report again.
3. If the case cannot fail, repair it. Apply by hand the mutation that exposed it, run
   the repaired case, and record the failure in the pull request.

**Prove that a census assertion is not vacuous.** With no report under
`docs/mutation_reports/`, the census prints `0 candidates over 0 test files` and every
settlement criterion passes with no work done. #412 found that. A settlement issue states
two readings: the census names at least one candidate, and it names an unclaimed candidate
when one row leaves the record. `TestTheRecordsOfThisRepository` in
`tests/test_mutation_census.py` holds both.

**Read an acceptance criterion as a candidate too.** #32 and #177 each held the vacuous
comparison in a criterion rather than in a test. #177's first two criteria passed on the
unchanged base commit, so the gate would have reported the issue met with no change made.
Before you report a criterion met, state what would fail if the code were wrong.

## Parity

Where FoxIO specifies nothing — a field name, a default, a subcommand — the Go port at
`Crank-Git/ja4plus-go` has already shipped a choice. Adopt it. Where FoxIO does specify,
FoxIO wins, even against the port. `docs/specs/spec.md` holds the divergence register.

### A pattern the port ships carries no statement of its cost

**Parity rule 2 adopts the interface the port ships. It adopts no statement of cost.** Go
runs a finite automaton, and it backtracks nowhere. Python `re` backtracks. The two
languages therefore read one pattern at two costs. The rule that carries the shape carries
no proof that the shape is safe against hostile input.

**Warning: a pattern that is safe in the port is a pattern this project has not
measured.** Measure a regular expression this project takes from the port against hostile
input before it lands. State the measurement where the change records its evidence.

**#612 followed parity rule 2 literally, and it shipped a backtracking defect to a
branch.** Its own self-review found the defect and measured it. `GET a` plus 32000 spaces
plus `HTTPX` cost **3017.9 milliseconds** under the ported form. The repaired form reads
the same payload at **0.630 milliseconds**. `REQUEST_LINE_LIMIT` of
`ja4plus/utils/http_utils.py` reads 8192. `is_http_request` reads that many bytes of every
TCP payload, so one crafted packet bought about 200 milliseconds of processor time.

**The rule reaches every construct whose cost differs between a finite automaton and a
backtracking engine.** A regular expression is the case this project has met.

**Warning: an atomic group states the bound directly, and this project cannot write
one.** Python accepts `(?>...)` from release 3.11, and `pyproject.toml:24` reads
`requires-python = ">=3.10"`. A repair that raises the floor of the package is a ruling
for the user. Verified against https://docs.python.org/3/library/re.html (retrieved
2026-08-15).

## Measuring coverage

Use the **directory** form, `--cov=ja4plus`. For one file, use the **path** form,
`--cov=ja4plus/utils/tcp_stream.py`.

**Never pass a dotted module name.** `--cov=ja4plus.utils.tcp_stream` makes 48 JA4L and
QUIC cases fail, and the cause is not in this project. `coverage` resolves a dotted source
name inside a `sys_modules_saved()` block, which imports `ja4plus`, scapy and
`cryptography` and then deletes them. The second `cryptography` import builds Python
classes the loaded Rust extension does not recognize, so every AES cipher raises
`UnsupportedAlgorithm`, and the second scapy import changes the dissection of a committed
capture. #177 holds the measurement, and Changelog round 47 records it.
