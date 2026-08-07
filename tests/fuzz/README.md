# The malformed-input suite

Every packet is hostile input. No parser trusts a length field it read from the packet.
A parser that cannot read a packet returns nothing, and it does not raise.

Run the suite:

```bash
pytest tests/fuzz/
```

`FR-correctness-audit-8` to `FR-correctness-audit-13` state the contract.

Two jobs in `.github/workflows/test.yml` run the suite:

- The `fuzz` job runs `pytest tests/fuzz/` on Python 3.13. It names the suite, so a red
  malformed-input case is visible without a log search.
- The `test` job reads `tests/`, so it runs the suite on Python 3.9 to 3.13 and on
  macOS.

Both jobs answer a pull request that targets `master` or `dev`. A pull request that
targets an epic integration branch starts no run, because the batch model skips
provider CI on a sub-issue. The batch pull request into `dev` runs the suite.

## What the suite reads

The suite reads the four committed FoxIO captures under `tests/foxio_vectors/`.

| Capture | What it holds | Parser it reaches |
|---|---|---|
| `ssh2-malformed.pcap` | An SSH session with malformed records. | `parse_ssh_packet` |
| `ssh2-moloch-crash.pcap` | An SSH capture that crashed another implementation. | `parse_ssh_packet` |
| `badcurveball.pcap` | A TLS handshake with a malformed curve list. | `parse_tls_handshake` |
| `CVE-2018-6794.pcap` | A capture that exercises a reassembly bypass. | `parse_tls_handshake` |

The suite generates every malformed copy at test time. **Never commit a generated
capture.** A committed copy stops following the capture it came from.

## The rule that governs every case

A case that asserts "no exception" passes when no parser runs. A truncated capture that
no fingerprinter opens raises nothing and proves nothing. Every case therefore states
what it produced, and every case proves that the parser read the mutated bytes.

The suite proves reachability in three ways:

- `spy_on` counts the calls of a named parser. A count of zero fails the case.
- A case pins the fingerprint the committed capture produces, in
  `RECORDED_FINGERPRINTS`.
- A case measures a method that produces a value on the committed capture and none on
  the cut copy. `SILENCED_METHOD` names the pair.

`test_the_harness_reports_a_fingerprinter_that_raises` proves that the harness observes
a raise. `Processor.process_packet` catches every exception, so `run_fingerprinters`
reads each fingerprinter directly instead. A suite that drove the processor could never
fail.

## How to add a case

1. Name the parser the case reaches, and count its calls with `spy_on`.
2. Assert what the case produced. An assertion of "no exception" alone is not enough.
3. Prove the case can fail. Break the parser by hand, run the suite, and confirm the
   case turns red.

## Why the frame cut keeps the link-layer header

`truncate_frames` never cuts below the link-layer header. scapy raises `struct.error`
when it dissects a shorter frame, so a shorter frame builds no packet object. Such a
frame reaches no fingerprinter, and a case built on it would measure scapy instead of
this project.
