---
name: conformance
description: Diagnose a FoxIO vector failure and decide what to change. Use when a spec_validation test fails, when a fingerprint does not match the reference, or when adding a new FoxIO vector.
allowed-tools: Bash, Read, Grep
---

# Diagnose a conformance failure

A conformance failure means this project produced a different fingerprint from the FoxIO
reference for the same packets. Work out which field differs before you change anything.

## Steps

1. Reproduce the failure alone, so the output is readable.

   ```bash
   python -m pytest tests/ -m spec_validation -q -k "<capture name>"
   ```

2. Read the expected value.

   ```bash
   python -c "import json,sys; print(json.dumps(json.load(open('tests/foxio_vectors/<capture>.json')), indent=2))"
   ```

3. Compute the value this project produces, and its raw form. The raw form is where the
   difference is visible; the hashed form only tells you that something differs.

   ```bash
   python -m ja4plus.cli analyze tests/foxio_vectors/<capture> --format json
   ```

4. Compare the raw form field by field against the `_r` key in the expected output. For
   JA4 the fields are, in order: the protocol and version prefix, the cipher list, the
   extension list, and the signature-algorithm list.

5. Identify which field differs, and only then read the fingerprinter.

## Where a difference usually comes from

| Symptom | Usual cause |
|---|---|
| The prefix differs | Version selection, the SNI flag, or a count that includes or excludes GREASE values. |
| The cipher or extension hash differs but the raw list looks right | A sort order, or SNI and ALPN not removed from the sorted extension list. |
| The count in the prefix differs from the list length | The count includes SNI and ALPN; the sorted list excludes them. This is correct, not a bug. |
| More fingerprints than the reference | A window or a state-reset condition fires too often. |
| Fewer fingerprints than the reference | State was evicted early, or the connection key does not match both directions. |

## Before you change the code

Read `.claude/rules/conformance.md`. Its rule is absolute: write the failing test that
names the vector and the expected value first, then change the code, then confirm that
no vector which passed before now fails.

## Adding a vector

1. Add the capture and its expected-output file under `tests/foxio_vectors/`, from the
   commit `tests/foxio_vectors/NOTICE` records.
2. Update `NOTICE` if the commit changed.
3. Run the conformance suite. A new vector that fails is a finding to report, not a
   reason to skip the vector.
