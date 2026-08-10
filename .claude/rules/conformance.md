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

## When the FoxIO reference holds a defect

The FoxIO reference decides behaviour. It does not decide behaviour that the reference
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
  and #175 records the decision.
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
4. Add the reader of the module body. Run `python -m tests.mutation_cover <module>` and
   put the test file it names in the cover.

**Step 2 leaves every mutation of the module body without a reader, so step 4 names one
by the value and never by the cost.** `tests/mutation_cover.py` reads the names the module
body binds and the identifier strings those statements build. It then names the test file
whose own source holds the most of those tokens. A file that reads the value kills a
mutation of the value, and the cheapest file reads no value at all.

**#433 measured the repair on `ja4plus/__init__.py`, at commit `00a0c42`, over all 32
mutations of the module.** The cost rule alone builds the cover `tests/test_parity.py`. That
sweep costs 43.2 seconds, it reads 1 killed and 31 survived, and all 25 entries of `__all__`
survive it. Step 4 adds the reader `tests/test_public_interface.py`, and one sweep against
that file alone costs 39.9 seconds. The repaired cover reads 26 killed and 6 survived in
48.0 seconds, and no entry of `__all__` survives it.

**State this fourth limit beside the three below.** The reader kills a mutation of the
value it reads, and it kills no other mutation of the module body. The three survivors of
the module body above are `__version__`, `__author__` and `__license__`, which
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
seven. Write `git ls-files 'ja4plus/*.py' 'ja4plus/*/*.py'` to list every module, which is
`DEFAULT_MODULE_PATTERNS` and the pair the sweep applies by default.
`tests/test_mutation_sweep_module_list.py` fails when the two stop agreeing, so no writer
reintroduces the `**` form in silence. **The front matter of `.claude/rules/ste.md` and of
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

## Measuring coverage

Use the **directory** form, `--cov=ja4plus`. For one file, use the **path** form,
`--cov=ja4plus/utils/tcp_stream.py`.

**Never pass a dotted module name.** `--cov=ja4plus.utils.tcp_stream` makes 48 JA4L and
QUIC cases fail, and the cause is not in this project. `coverage` resolves a dotted source
name inside a `sys_modules_saved()` block, which imports `ja4plus`, scapy and
`cryptography` and then deletes them. The second `cryptography` import builds Python
classes the loaded Rust extension does not recognise, so every AES cipher raises
`UnsupportedAlgorithm`, and the second scapy import changes the dissection of a committed
capture. #177 holds the measurement, and Changelog round 47 records it.
