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

**A declined FoxIO Python value forfeits its precedence.** The precedence above breaks a
tie between two sources this project trusts. A value this project already ruled wrong is
not a tie. Where `tests/foxio_deviations.json` declines the Python value for one method on
one connection, under a decided entry, **any other FoxIO implementation may hold the
reference value** for that method on that connection. The Zeek baseline, the Rust
snapshot and the Wireshark dissector each qualify. #332 records the first decision, #334
records the source-neutral form, and #97 is the decline that raised the family.

**Read the condition from the register and the vectors.** Five facts state it, and a
reader checks each one.

1. The register key is the value form `<vector>/<stream>:<port>/<method>.<occurrence>`,
   and the FoxIO Python expected-output file holds a value at that connection, that
   method and that occurrence. The occurrence form `<vector>/<method>` records a stream
   that file omits, and the Rust snapshot rule above decides that case.
2. The entry carries `"decided": true`, so a recorded decision names the issue.
   `tests/foxio_deviations.py` states the marker rule.
3. The entry carries `"capability": false`, so it is a value decline and not a capability
   decline. `tests/foxio_deviations.py` states the field.
4. Another FoxIO source holds a value for the same method, the same connection and the
   same occurrence.
5. The remaining sources hold one value between them.

**Read fact 1 from the vectors, and not from the key form alone.** A value-form key
states that the Python file holds a value, and on one row that statement is false.
`gre-erspan-vxlan.pcap/0:65174/JA4T.1` carries the value form, the FoxIO Python file
holds no JA4T value, and #215 declines the FoxIO Rust value `8192__0_0` rather than a
Python one. The exception rests on a declined Python value, so it passes over that row.

**A capability decline bars the row.** The exception reaches a row only where the decline
records a disagreement about the value. It does not reach a row whose decline records a
capability this project chose not to build, because no implementation change could ever
close that difference. **#129 is that case.** `ja4plus` reads no encrypted request, by
decision, and the Wireshark file holds the decrypted values. #129 carries 37 decided
value-form keys, and another FoxIO source holds a value for 35 of them. Naming those as
the reference would create 35 permanent divergences of a kind this project chose.

**The register records the kind of every decline.** Each entry carries a `"capability"`
field: `true` records a capability this project chose not to build, and `false` records a
disagreement about the value. `tests/foxio_deviations.py` reads it beside `decided`, and
`unrecorded_kinds` in `tests/test_foxio_deviations.py` requires it on every decided
entry, so a new decline states its kind where the decline is recorded. **Fact 3 reads one
field of one entry.** 43 entries record a capability decline today, and all 43 name #129.
#334 proposed the field and #341 built it. **Never infer the kind of a decline from the
prose of its cause.** Read the field.

**The field alone carries this bar, and #347 measured it.** #334 left the 35 source
values of #129 out of `SOURCE_VALUES`, so the exclusion enforced the bar a second time.
No case could then read what the field does on the one issue the bar exists for. The
table now holds all 35, measured against the pinned commit. With `capability` false on
every #129 entry the reach rises from 6 rows to 25. The same flip on the earlier table
moved nothing. The 16 JA4H rows of the 35 stay out under the disagreement bar, because
the Rust value and the Wireshark value differ on each one.

**A disagreement between the remaining sources bars the row.** Where the remaining FoxIO
sources hold different values, **no source holds the reference and the row stays declined
exactly as it is today.** The decision removes a wrong value's precedence. It promotes no
survivor. A standing ranking among Rust, Zeek and Wireshark is declined, because this
project has found each of the three wrong in different places, so a ranking would be a
claim the evidence does not support.

**Warning: no reading of which value looks right reaches this exception.** An entry the
register leaves undecided is an open question, and the exception does not reach it. An
entry that names the issue that will decide it stays undecided.

**The bar on a JA4L or JA4LS value of a Zeek baseline stands above this exception.** The
three rules above part the Zeek script from the Python reference, so no such value is a
reference value, whatever the register holds. The bar removes the Zeek value before fact
5 reads the remaining sources.

**Warning: the reasoning of that bar reaches the Wireshark dissector, and the bar does
not name it.** The dissector appends a third part to every JA4L and JA4LS value it
writes: a delta on a TCP connection, and the marker `quic` on a QUIC connection. That is
the second of the three rules. #225 nevertheless records that this project adopted the
`quic` marker from the dissector on purpose, so widening the bar would contradict a
recorded decision. #334 reports the finding and leaves the bar as it stands. The user
decides what the bar covers.

**This exception adopts no source as a vector.** It states which source may hold a
reference value, and adoption is its own decision. "Which baselines are usable as
vectors" in `docs/specs/foxio/zeek.md` holds that decision for the Zeek package.

**The exception reaches 6 rows of the 134 the register holds.**
`tests/test_precedence_exception.py` measures the reach and both counts, and #334 records
the search. A case reads this sentence, so a register move fails the gate here.

| Row | Decline | The source that may hold the reference |
|---|---|---|
| `ssh-r.pcap/2:46396/JA4SSH.1` | #96 | Rust and Wireshark, which agree |
| `ssh-scp-1050.pcap/0:49237/JA4SSH.3` | #96 | Rust and Wireshark, which agree |
| `ssh-scp-1050.pcap/0:49237/JA4SSH.4` | #96 | Rust and Wireshark, which agree |
| `ssh2.pcapng/14:57377/JA4SSH.2` | #97 | Rust and Zeek, which agree |
| `ssh2.pcapng/33:51810/JA4L-S.1` | #225 | Wireshark alone |
| `tls3.pcapng/25:61884/JA4L-S.1` | #225 | Wireshark alone |

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
