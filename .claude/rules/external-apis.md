---
paths:
  - "ja4plus/**/*.py"
  - "tests/**/*.py"
  - ".github/workflows/*.yml"
  - "docs/**/*.md"
  - "docs/specs/**/*.md"
---

# External interfaces — read the documentation, never assume

Before you write a call against anything this project does not own, confirm the exact
shape from that tool's own documentation: the operation name, the required parameters,
the response fields, the error cases, the limits, and the permissions the call needs.
Cite the URL and the version in the pull-request body.

A recollection of an API is a plausible reconstruction, not a fact. It goes wrong in
repeatable ways: a parameter that was renamed, a required field remembered as optional,
a response shape from a different version, a limit invented to fill a gap. Each one
reads as confident and correct.

Code inside this repository is different. Read the code.

## The interfaces this project depends on

| Interface | Version pinned | Documentation |
|---|---|---|
| FoxIO JA4+ specification | Upstream default branch, commit dated 2026-07-21 | https://github.com/FoxIO-LLC/ja4/tree/main/technical_details |
| FoxIO test vectors | `pcap/`, `python/test/testdata/`, `wireshark/test/testdata/` and `rust/ja4/src/snapshots/` at the pinned commit | https://github.com/FoxIO-LLC/ja4/tree/main/python/test/testdata |
| FoxIO mapping file | `ja4plus-mapping.csv` at the pinned commit | https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv |
| `ja4db.com` lookup | No published version | `https://ja4db.com/api/read/<fingerprint>` |
| `scapy` | 2.4 or later | https://scapy.readthedocs.io/ |
| `cryptography` | 42 or later | https://cryptography.io/en/latest/ |
| PyPI trusted publishing | `pypa/gh-action-pypi-publish` release v1 | https://docs.pypi.org/trusted-publishers/ |
| GitHub Pages deployment | `actions/deploy-pages` v4 | https://github.com/actions/deploy-pages |
| `mkdocs-material` | 9.x | https://squidfunk.github.io/mkdocs-material/ |

## Rules specific to this project

**FoxIO is the authority on behaviour.** Seven of the twelve methods are published as
PNG images rather than text. Where an image is ambiguous, the expected-output files
under `python/test/testdata/` decide. Record the reading in
`docs/implementation_notes.md`.

**The files under `wireshark/test/testdata/` are not the authority.**
`wireshark/test/testdata/tls12.pcap.json` is an empty array, while the file with the
same name under `python/test/testdata/` holds four fingerprints. Where both directories
carry a value for a method, `python/test/testdata/` decides.

**JA4D and JA4D6 are the one exception.** The FoxIO Python implementation emits neither
method, so `python/test/testdata/dhcp.pcapng.json` and
`python/test/testdata/dhcpv6.pcap.json` each hold an empty array. The Wireshark dissector
is the only FoxIO implementation that writes a reference value for the two methods.
`tests/foxio_vectors/wireshark_expected/` holds a copy of its two files. The Zeek
baseline `zeek/tests/Traces/Scripts.ja4-dhcp/ja4d.log` holds the same four JA4D values.
`docs/implementation_notes.md` records the reading.

**A snapshot under `rust/ja4/src/snapshots/` decides for a stream the Python file omits.**
The unit is the stream, not the file. `python/test/testdata/tls3.pcapng.json` holds seven
streams and omits six, and the Rust snapshot holds all thirteen. Where the Python file
holds no value for a stream and the Rust snapshot holds one, the Rust snapshot decides.
Where both carry a value for one method on one stream, `python/test/testdata/` decides.

The FoxIO Python implementation reads no QUIC handshake, and it reads no TLS on a port it
does not know. Those two gaps produce every case. `tests/foxio_vectors/rust_expected/`
holds a copy of the eight snapshots that cover them, and
`tests/test_foxio_rust_parity.py` measures the match. #138 records the reading, and
`docs/implementation_notes.md` holds the table.

Read this rule at stream granularity. An earlier form read "only where the Python file
holds an empty array", and that form covered one capture of the eight.

**JA4D6 rests on one source.** No FoxIO implementation other than the Wireshark
dissector writes a JA4D6 value, so nothing corroborates its six values the way the
Zeek baseline corroborates the four JA4D values. Treat a JA4D6 mismatch as a question
before you treat it as a defect in this project.

**`ja4db.com` publishes no versioned document.** Treat any unexpected response shape as
a miss. Never let its response shape reach a caller unchecked.

**No network request happens without an opt-in.** A fingerprint describes traffic the
operator observed. Sending it to a third party discloses that traffic. A default that
reaches the network is a defect, not a convenience.

**Never edit `Crank-Git/ja4plus-go` from this repository.** Read it to settle an
interface question. Another session works on it.

## Evidence

Put a line like this in the pull-request body, the spec section, or the issue that
carries the claim:

```
Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/python/test/testdata (retrieved 2026-08-06)
Verified against: https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html (scapy 2.6)
```

If the documentation contradicts the plan, that is a question for the person who wrote
the plan. It is not something to reconcile by guessing.
