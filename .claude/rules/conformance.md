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

One run of the whole suite takes about 17 seconds, so 12 mutations for each module cost
about 80 minutes. Raise `--max-per-module` to sharpen the answer, and name one module to
sweep it whole.

The report holds three parts.

- `modules` names every module, and every mutation the sweep applied to it. A mutation
  records the line, the text before, the text after, and the count of the cases it killed.
- A mutation whose status is `survived` killed no case. A mutation whose status is
  `unusable` failed the whole suite, because it broke an import, and the sweep drops it.
- `candidates` names every case that no mutation killed.

Read a candidate this way.

1. Read the case first. A case may be correct and the mutation wrong.
2. If the mutations reach no code the case names, sweep that module whole with
   `--max-per-module 0`, and read the report again.
3. If the case cannot fail, repair it. Apply by hand the mutation that exposed it, run
   the repaired case, and record the failure in the pull request.

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
