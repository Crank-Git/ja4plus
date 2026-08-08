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
| FoxIO Zeek package | `zeek/` at the pinned commit | https://github.com/FoxIO-LLC/ja4/tree/main/zeek |
| `FoxIO-LLC/ja4tscan` | Commit `d01bfec4e64366d37ae95982a5068a5b41ca43b0`, dated 2024-08-29 | https://github.com/FoxIO-LLC/ja4tscan |
| `FoxIO-LLC/ja4-nginx-module` | Commit `7eeee6202b9b65f5ccf85572957a816ade8cb0bc`, dated 2026-04-20 | https://github.com/FoxIO-LLC/ja4-nginx-module |
| `ja4db.com` lookup | No published version | `https://ja4db.com/api/read/<fingerprint>` |
| Wireshark core dissectors | Release 4.4.2 | https://gitlab.com/wireshark/wireshark/-/tree/v4.4.2/epan/dissectors |
| `scapy` | 2.4 or later | https://scapy.readthedocs.io/ |
| `cryptography` | 42 or later | https://cryptography.io/en/latest/ |
| PyPI trusted publishing | `pypa/gh-action-pypi-publish` release v1 | https://docs.pypi.org/trusted-publishers/ |
| GitHub Pages deployment | `actions/deploy-pages` v4 | https://github.com/actions/deploy-pages |
| `mkdocs-material` | 9.x | https://squidfunk.github.io/mkdocs-material/ |

## Rules specific to this project

**FoxIO is the authority on behaviour.** The specification decides intent and schema. The
vectors decide the exact bytes where intent runs out. A provable reference defect is
declined and recorded.

**Eleven of the twelve methods are published as an image rather than as text.** Only JA4
holds a complete text specification, in `technical_details/JA4.md`. `technical_details/JA4H.md`
is 278 bytes and states one rule, so JA4H is an image method too.
`docs/specs/foxio/README.md` holds the inventory, every SHA-256, and the transcription
procedure.

**The vector fallback needs an image that a person read and found ambiguous.** Where a
reader reads the image and the image does not settle the question, the expected-output
files under `python/test/testdata/` decide, and `docs/implementation_notes.md` records the
reading. An image that nobody read is not a license to use the fallback. Read the image
first. Transcribe it into `docs/specs/foxio/<METHOD>.md`. Use the fallback only for what
the image leaves open.

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

The FoxIO Python implementation has three gaps. It reads no QUIC handshake, it reads no
TLS on a port it does not know, and it reads no ServerHello whose handshake record spans
several TCP segments. Those three gaps produce every case.
`tests/foxio_vectors/rust_expected/` holds a copy of the ten snapshots that cover them,
and `tests/test_foxio_rust_parity.py` measures the match. #138 records the first two
readings, #151 records the third, and `docs/implementation_notes.md` holds both tables.

Read this rule at stream granularity. An earlier form read "only where the Python file
holds an empty array", and that form covered one capture of the eight.

**The Zeek package is a fourth reference, and it outranks nothing.** `zeek/` implements
eight methods and carries seven baselines under `zeek/tests/Traces/`. Every baseline
names its capture, and this project holds all seven captures.
`docs/specs/foxio/zeek.md` records the whole reading, and
`tests/compare_zeek_baselines.py` reproduces the comparison. Where
`python/test/testdata/` and a Zeek baseline both hold a value for one method on one
connection, `python/test/testdata/` decides. **Read no JA4L or JA4LS value of a Zeek
baseline as a reference value.** Three rules of the Zeek script diverge from the Python
reference.

1. It rounds the halved latency, where the Python reference truncates it.
2. It appends a third part that the Python reference does not publish.
3. It marks a QUIC connection with a `q` part.

**`FoxIO-LLC/ja4tscan` holds prose and no baseline.** Its `README.md` gives eight
JA4TScan example values against named operating systems, and two of them record TCP
option kind 0 inside the JA4T option list. #197 owns the scope decision.

**Warning: FoxIO states that `FoxIO-LLC/ja4-nginx-module` is not correct.** Its
`README.md` opens with a `# NOTICE` section that reads "This version of JA4 has known
issues and bugs and may not produce correct JA4 values. Use at your own risk." Treat none
of its four golden files under `test/testdata/` as a reference value.

**The pinned FoxIO checkout carries no core Wireshark dissector.** Its `wireshark/`
directory holds the FoxIO plugin alone, and `wireshark/source/packet-ja4.c` reads fields
that a core dissector produced. A question about which packet reaches that plugin is
therefore a question for the Wireshark repository, and the table above pins it. #231 is
the first reading that needed it: `packet-dhcp.c` states
`#define DHCP_UDP_PORT_RANGE  "67-68,4011"`, so the reference reads DHCP on three UDP
ports where `packet-ja4.c` names none.

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
