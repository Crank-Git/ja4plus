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

Seven of the twelve methods are published as images. When an image does not settle a
question:

1. The expected-output file decides.
2. Record the reading in `docs/implementation_notes.md`, with the vector that supports
   it.
3. Never guess from the method name or from another implementation.

## State rules

- Every state table has a maximum entry count and a maximum age.
- Eviction uses the packet timestamp when the packet carries one. A capture file replays
  faster than real time, and a wall clock would evict state the capture still needs.
- No fingerprinter holds a reference to a packet object after `process_packet` returns.
- A stateful fingerprinter implements `cleanup_connection` and normalizes the 5-tuple to
  its own key format.
- A fingerprinter catches the parse errors it expects. It does not catch bare
  `Exception`.

## Parity

Where FoxIO specifies nothing — a field name, a default, a subcommand — the Go port at
`Crank-Git/ja4plus-go` has already shipped a choice. Adopt it. Where FoxIO does specify,
FoxIO wins, even against the port. `docs/specs/spec.md` holds the divergence register.
