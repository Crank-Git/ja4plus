# Implementation Notes

Behaviors in the Python ja4plus library that are not documented in the
FoxIO JA4+ specification. The Go implementation MUST match these behaviors
to produce identical fingerprints.

FoxIO publishes seven of the twelve methods as an image. Where an image leaves a question
open, the expected-output file decides, and the reading goes here. An entry names the
vector that supports the reading, or it states that no FoxIO material validates it.

---

## The raw forms

### Each method holds its own sort rule

A raw form is the unhashed form of a fingerprint. One method sorts a list in its raw
form, and another method holds the wire order. The rule of one method proves nothing
about another method, so each row below names its own evidence. The counts come from the
37 committed vectors under `tests/foxio_vectors/`.

| Method | Raw keys FoxIO publishes | Sort rule | Evidence |
|---|---|---|---|
| JA4 | `JA4_r`, `JA4_ro` | `JA4_r` sorts the ciphers and the extensions. It holds the signature algorithms in wire order. `JA4_ro` holds every list in wire order. | 160 `JA4_r` values. 156 of them carry a signature-algorithm section, and all 156 hold the ciphers and the extensions in numeric order and the signature algorithms in an order that is not numeric. The other four carry no extension and no signature algorithm. No `JA4_ro` value equals its `JA4_r` value. |
| JA4S | `JA4S_r` | The extensions stay in wire order. JA4S sorts no list. | 84 `JA4S_r` values. 35 of them hold the extensions in an order that is not numeric order, and `badcurveball.pcap.json` gives `t1205h1_c02b_0000,ff01,000b,0023,0010`. No file carries a `JA4S_ro` key. |
| JA4H | `JA4H_ro` | Every list holds the wire order. `JA4H_ro` holds the header names, the cookie names and the cookie name-and-value pairs as the request carries them. | 89 `JA4H_ro` values, and no `JA4H_r` value. `http1-with-cookies.pcapng.json` gives `yummy_cookie,tasty_cookie`, which is not sorted order, and the hashed form of the same request sorts the two names. 79 of the 89 values match after #131. |
| JA4X, JA4SSH, JA4L, JA4T, JA4TS, JA4D, JA4D6 | None | Not applicable. | No expected-output file carries a raw key for these methods. |

**Location:** `ja4plus/fingerprinters/ja4.py`, `ja4plus/fingerprinters/ja4s.py`.

### The conformance suite compares every raw key

Before #121, `tests/conformance_index.py` dropped every key that ends with `_r`, `_ro`,
`_o` or `_raw`, so no raw form reached a comparison. `RAW_METHODS` in that module now
names each raw key the reference publishes and the produced key that holds the value.

The reference publishes a raw key on exactly the stream where it publishes the hashed
key, on all 37 vectors. The occurrence-key comparison of the hashed method therefore
already reports a count defect, and the raw comparison adds a value comparison.

#121 measured the first result on `epic/12-spec-conformance` at `03c7c02`:

| Raw key | Values | Match | Differ | Owner of the failures |
|---|---|---|---|---|
| `JA4_r` | 160 | 149 | 11 | #13, on the same 11 streams as `JA4` |
| `JA4_ro` | 160 | 149 | 11 | #13, on the same 11 streams as `JA4` |
| `JA4_o` | 160 | 145 | 15 | #13 for 11, #132 for 4 |
| `JA4S_r` | 84 | 84 | 0 | None |
| `JA4H_ro` | 89 | 0 | 89 | #131 |

#131 landed the JA4H raw form. The second measurement, on `epic/12-spec-conformance`:

| Raw key | Values | Match | Differ | Owner of the failures |
|---|---|---|---|---|
| `JA4H_ro` | 89 | 79 | 10 | #129 for 9, #35 for 1 |

The ten failures sit on a stream whose hashed `JA4H` value fails too. Nine of them are the
two captures that carry a Decryption Secrets Block, and `ja4plus` decrypts nothing. The
last one is `http-empty-useragent.pcap`, which produces no JA4H value at all.

`JA4_o` holds a hash of the original-order fields rather than a raw form. The reference
publishes it beside `JA4_ro`, so the suite compares it the same way.

---

## JA4 - TLS Client Hello

### The ALPN value of a first byte that is not ASCII

`ja4plus` writes `99`. It follows the two FoxIO implementations, and the FoxIO prose
describes a different value. The user settled the reading on 2026-08-07 on #127.

The FoxIO specification states the rule: "If the first or last byte of the first ALPN is
not an ASCII alphanumeric character (meaning not `0x30-0x39`, `0x41-0x5A`, or
`0x61-0x7A`), then we print the first and last characters of the hex representation of
the first ALPN instead." The prose therefore describes the hex characters.

The FoxIO Python implementation applies a different rule. `python/ja4.py` writes `'99'`
when the first byte has `ord() > 127`. The FoxIO Rust implementation writes the same
value.

`tests/foxio_vectors/tls-non-ascii-alpn.pcapng` measures the difference. Its first ALPN
value is the two bytes `0xba 0xad`.

| Source | JA4 value |
|---|---|
| The FoxIO prose | `t13d1516bd_8daaf6152771_e5627efa2ab1` |
| FoxIO Python, FoxIO Rust and `ja4plus` | `t13d151699_8daaf6152771_e5627efa2ab1` |

Only the two ALPN characters differ. `ja4plus` follows the two implementations, because
a FoxIO vector holds the value, and because a fingerprint exists so that one tool output
can be compared against another tool output. The register holds no entry for this vector,
and `tests/test_ja4_alpn.py` compares the produced value against the reference value.

`compute_alpn_value` returns `99` when the first byte or the last byte of the first ALPN
value falls outside `0x20-0x7E`. `ja4s.py` reads the same function, so JA4 and JA4S
carry one rule.

#127 settled the value that this vector produces. It settled no condition, because
every rule fires on `0xba 0xad`. #141 measured the condition against a capture it built.
The next section holds that measurement, and it holds the part of the condition the
measurement leaves open.

**Location:** `ja4plus/fingerprinters/ja4.py:36`, in `compute_alpn_value`.

### The ALPN condition passes a printable ASCII byte through

#141 owns the condition that makes the ALPN value read `99`. The FoxIO prose tests for
an alphanumeric byte. The measurement contradicts the prose: both FoxIO implementations
pass a printable ASCII byte through, whether or not that byte is alphanumeric.

No FoxIO capture separates the rules, so #141 built one.
`tests/build_alpn_condition_capture.py` writes
`tests/foxio_vectors/alpn-condition.pcap`. Each stream carries one TLS ClientHello, and
the two ClientHellos differ in the first ALPN value alone.

**The commands.** Both ran at the pinned upstream commit
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`.

```
python python/ja4.py tests/foxio_vectors/alpn-condition.pcap -J
rust/target/release/ja4 tests/foxio_vectors/alpn-condition.pcap
```

**The measurement.** A wider probe capture reached eleven inputs. The table holds every
one of them. `?` is the Unicode replacement character `U+FFFD`, which tshark writes for
a byte it cannot decode.

| The first ALPN value | FoxIO Python | FoxIO Rust | The two agree | `ja4plus` |
|---|---|---|---|---|
| `h2` | `h2` | `h2` | yes | `h2` |
| `h\x20` | `h ` | `h ` | yes | `h ` |
| `\x20h` | ` h` | ` h` | yes | ` h` |
| `h\x20\x20\x32` | `h2` | `h2` | yes | `h2` |
| `\xba\xad` | `99` | `99` | yes | `99` |
| `h\xab` | `h?` | `h9` | no | `99` |
| `\xabh` | `99` | `9h` | no | `99` |
| `\x30\x31\xab\xcd` | `0?` | `09` | no | `99` |
| `h` | `h` | `h0` | no | `hh` |
| `\xab` | `99` | `90` | no | `99` |
| `\x20` | ` ` | ` 0` | no | `99` |

**The boundary of the range.** A second probe walked the control bytes and the top of
ASCII. It shows that the two implementations agree inside `0x20-0x7E` and disagree
outside it.

| The first ALPN value | FoxIO Python | FoxIO Rust | The two agree |
|---|---|---|---|
| `h\x00` | `h` | `h0` | no |
| `h\x01` | `h\x01` | `h1` | no |
| `h\x0a` | `h\n` | no value | no |
| `h\x1f` | `h\x1f` | `hf` | no |
| `h\x20` | `h ` | `h ` | yes |
| `h\x21` | `h!` | `h!` | yes |
| `h\x7e` | `h~` | `h~` | yes |
| `h\x7f` | `h\x7f` | `hf` | no |
| `\x01h` | `\x01h` | `\h` | no |
| `\x00\x01` | no value | `00` | no |

The cause is the tshark text form. `rust/ja4/src/tls.rs` reads a control byte as the
escape text tshark writes, so it reads `h\x1f` as the five characters `h`, `\`, `x`, `1`
and `f`, and it writes the first and the last of them. `python/ja4.py` reads the byte.
The one exception is `0x09`, where both write a tab. That one agreement is an accident of
the tshark text form, not a rule, so this project does not adopt it.

**What the measurement settles.** The two implementations agree on every input whose
first byte and last byte fall inside `0x20-0x7E`. They agree on an input whose two bytes
fall outside ASCII. `ja4plus` adopts both results. Before #141 it wrote `99` for `h\x20`
and for `\x20h`, and it now writes `h ` and ` h`.

**What the measurement leaves open.** The two implementations disagree on every byte
outside `0x20-0x7E` that sits in a position other than the first.
`python/ja4.py` tests `ord(alpn[0]) > 127`, so a byte above `0x7F` in the last position
reaches the fingerprint as the replacement character. `rust/ja4/src/tls.rs` replaces each
end character with `9` when that character falls outside ASCII. The two also disagree on
a one-byte value, because `rust/ja4/src/tls.rs` writes `0` for the absent last character.

`ja4plus` changes nothing on a case the two implementations dispute. It holds the value
it wrote before #141, which is `99` for a byte outside ASCII and `hh` for the one-byte
value `h`. `.claude/rules/conformance.md` states that a defect outside its two named
shapes is a question for the user, and #141 asks it.

**What the user settled.** On 2026-08-07 the user decided that both values stay. #162
records the decision. `docs/specs/spec.md` § Divergence register holds one row for the
disputed-byte reading and one row for the one-byte reading, and both decisions are
reversible.

**How the divergence became a comparison.** #141 left the disputed inputs out of every
capture, so the conformance suite was green because it made no comparison. #162 adds
them. `tests/build_alpn_condition_capture.py` writes seven streams, and the table in its
docstring names what each one holds.

| Stream | The first ALPN value | FoxIO Python | FoxIO Rust | `ja4plus` | Register entry |
|---|---|---|---|---|---|
| 0 | `h\x20` | `h ` | `h ` | `h ` | no, it conforms |
| 1 | `\x20h` | ` h` | ` h` | ` h` | no, it conforms |
| 2 | `h\xab` | `h?` | `h9` | `99` | yes |
| 3 | `\xabh` | `99` | `9h` | `99` | no, it conforms |
| 4 | `h\x1f` | `h\x1f` | `hf` | `99` | yes |
| 5 | `h\x0a` | `h\n` | no value | `99` | yes |
| 6 | `h` | `h` | `h0` | `hh` | yes |

Stream 3 is disputed and it still conforms, because `ja4plus` writes the FoxIO Python
value there. A strict `xfail` on a case that passes fails the suite, so that stream holds
no register entry. The other four streams hold four entries each, one per method, and
each cause states the measured output of both implementations.

**How the build writes the expected-output file.** The ALPN characters come from the two
tables above, and the build re-derives no value. The build copies the rest of each
fingerprint from stream 0. The seven client hellos carry the same ciphers and the same
extensions, so the JA4 prefix and both hashes are invariant.
`alpn-condition.pcap.json` therefore holds a measurement in its variable field and a copy
in its invariant field.
`test_every_stream_differs_from_the_others_in_the_alpn_characters_alone` proves the
invariance.

**Location:** `ja4plus/fingerprinters/ja4.py:36`, in `compute_alpn_value`. #162 changed
no line of it. `tests/test_ja4_alpn_condition.py` holds the measurement against
`ja4plus`.

### The QUIC reference value comes from the FoxIO Rust implementation

`tests/foxio_vectors/quic-with-several-tls-frames.pcapng` holds one QUIC Initial packet.
That packet carries the ClientHello in several CRYPTO frames. The FoxIO Python
implementation reads no ClientHello from it, so
`tests/foxio_vectors/quic-with-several-tls-frames.pcapng.json` holds `[]`.

The FoxIO Rust implementation reads it and writes
`ja4: q13d0310h3_55b375c5d22e_cd85d2d88918`.
`tests/foxio_vectors/rust_expected/` holds a copy of that snapshot, taken without change
from `rust/ja4/src/snapshots/` at the pinned upstream commit. `ja4plus` produces the same
value.

`.claude/rules/external-apis.md` records when a snapshot under `rust/ja4/src/snapshots/`
carries the authority. The conformance suite reads only the top level of
`tests/foxio_vectors/`, so the file adds no case to that suite and no entry to the
deviation register. The register entry `quic-with-several-tls-frames.pcapng/JA4` records
the difference against the Python material, and #138 owns its cause.

**Location:** `tests/test_quic_multipacket.py`.

### The FoxIO Python implementation omits a stream the Rust implementation holds

The capture above is not one exception. The same gap covers eight captures, and #138
settles all of them with one rule.

**The rule.** The FoxIO Python implementation reads no QUIC handshake, and it reads no
TLS on a port it does not know. The FoxIO Rust implementation reads both. Where the two
disagree on whether a stream carries a value, the Rust snapshot decides. A value that one
implementation holds and another omits is a gap in the implementation that omits it.

**The measurement.** `tests/test_foxio_rust_parity.py` holds it.

| Measurement | Count |
|---|---|
| QUIC fingerprints in every `python/test/testdata/` file | 0 |
| TCP fingerprints in the same files | 808 |
| Streams the Python file omits and the Rust snapshot holds | 85 |
| Streams where `ja4plus` produces the exact Rust value | 82 |
| Streams where `ja4plus` produces a value the Rust snapshot contradicts | 0 |

`ja4plus` never emits a value that the FoxIO Rust implementation contradicts. On
`https-connect.pcap` the Wireshark dissector corroborates the Rust snapshot, so two of
the three FoxIO implementations hold the values `ja4plus` produces.

The remaining three streams run the other way: `ja4plus` produces nothing where the Rust
snapshot holds a JA4S value. All three carry TLS over TCP on port 443, and the Python
file omits them too, so they belong to a separate question.

**The cost.** The conformance suite compares against the Python material, so the 33
register entries stay. Each one is `decided`, because no fix removes it.

**Location:** `tests/test_foxio_rust_parity.py`, `tests/foxio_deviations.json`.

### JA4X scans the record layer whatever tunnel carries it

`socks4-https.pcap` carries TLS inside a SOCKS4 tunnel on port 9901. No FoxIO
implementation holds a JA4X value for it. The Python expected-output file, the Rust
snapshot and the Wireshark dissector all hold none, and `ja4plus` produces three values.
That is the one case the #138 rule does not reach, because the rule rests on a reference
that holds the value.

**The reading.** `ja4plus` reads the record layer without regard to the tunnel protocol
that carries it. One behaviour produces both readings:

| Capture | Tunnel | FoxIO implementations that hold the JA4X values |
|---|---|---|
| `https-connect.pcap` | HTTP CONNECT, port 8080 | Rust and Wireshark, two of three |
| `socks4-https.pcap` | SOCKS4, port 9901 | none |

**The decision.** `ja4plus` keeps the three values, and the register records the
divergence. A gate on the record-layer scan would suppress the SOCKS4 values, and it
would risk the `https-connect.pcap` values that two FoxIO implementations hold. The cost
of a gate falls on a case this project wins. The cost of the divergence is one register
entry. The decision is deliberate and reversible, and it follows the form of #127 and
#129.

**The cost.** One register entry, `socks4-https.pcap/JA4X`, marked `decided`.

**Location:** `tests/foxio_deviations.json`, `tests/test_foxio_deviations.py`.

### The reader walks the records of a segment

A TLS 1.3 client that receives a HelloRetryRequest sends a second ClientHello. The
compatibility-mode ChangeCipherSpec record precedes that hello in the same TCP segment,
so the first byte of the segment is `0x14` and not `0x16`.

`parse_tls_handshake` read the first record of the segment alone, so it returned `None`
on that segment and the second hello reached no fingerprinter. `tls-handshake.pcapng`
and `tls-sni.pcapng` each hold five such streams, and the reference holds a `JA4.2` value
for every one of them.

The reader now walks the records of the segment, and it parses the first record whose
content type is `0x16` and whose handshake type is 1 or 2. The per-record length comes
from the packet, so the walk bounds every read on the real buffer length, always
advances, and returns `None` on a length that overruns the buffer.

No segment of these captures holds two ClientHellos, so the first handshake record of a
segment is sufficient.

**Location:** `ja4plus/utils/tls_utils.py:46`, in `parse_tls_handshake`.
`tests/test_ja4_hello_retry.py` holds the measurement. #137 owns the change.

### Version mapping (beyond TLS 1.0-1.3)

The spec only mentions TLS 1.0 through 1.3. The implementation also maps:

| Wire value | String | Protocol   |
|------------|--------|------------|
| `0x0300`   | `s3`   | SSL 3.0    |
| `0x0200`   | `s2`   | SSL 2.0    |
| `0xFEFF`   | `d1`   | DTLS 1.0   |
| `0xFEFD`   | `d2`   | DTLS 1.2   |
| `0xFEFC`   | `d3`   | DTLS 1.3   |

Any unrecognized version maps to `'00'`.

### Cipher sorting

Ciphers are sorted numerically on their integer values before formatting
as 4-char hex and hashing. This produces the same result as lexicographic
sort on zero-padded 4-char hex strings.

### Raw fingerprint format

Raw fingerprints use prefixed output: `JA4_r = {fp}` and `JA4_ro = {fp}`.
Note the spaces around `=`. This is a display convention, not part of the
fingerprint value itself.

### The original-order hashed value

`JA4_o` hashes the original-order raw value. It keeps the ciphers in wire
order. It keeps every extension in wire order, and it holds SNI (`0x0000`) and
ALPN (`0x0010`), which `JA4` removes. The vector
`tests/foxio_vectors/tls12.pcap.json` gives `JA4_o.1` as
`t13d1715h2_5b234860e130_014157ec0da2`, and that value is the hash of the
`JA4_ro.1` fields.

### The zero sentinel reads the sorted extension list

One rule overrides the paragraph above. FoxIO tests the **sorted** extension list for the
zero sentinel, and it sets **both** extension hashes from that one test. A client hello
whose only extensions are SNI and ALPN therefore gives `JA4_o` the zero sentinel.
`JA4_ro` still shows the extension in wire order.

`technical_details/JA4.md` states the rule, and it names one field:

> If there are no extensions in the sorted extensions list, then the value of JA4_c is
> set to `000000000000`

The specification describes `JA4_o` by example alone. It states no separate rule for the
original-order extension hash, so the reference applies the one published rule to both
renderings.

**The vector.** `tests/foxio_vectors/https3-301-get.pcap.json` stream 0, source port
62599. The client hello carries SNI as its only extension.

```
JA4.1    = t10d230100_6a57a6f57151_000000000000
JA4_o.1  = t10d230100_ce175d585f73_000000000000
JA4_ro.1 = t10d230100_0039,...,00ff_0000
```

`tests/foxio_vectors/socks-https-example.pcap.json` holds the same reading on streams 0,
2 and 4.

**The measurement.** A probe on `python/ja4.py` at the pinned commit
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` reads both strings and the guard:

```
PROBE stream=0 sorted_extensions='' original_extensions='0000' guard=bool(sorted_extensions)=False sha_encode(original_extensions)=9af15b336e6a
```

The reference computes `sha256('0000')[:12] = 9af15b336e6a`, and then it discards that
value. #132 holds the command and the full output.

Before #132, `ja4plus` emitted `9af15b336e6a` on these four streams. `JA4_o` now matches
all 160 reference values, and the count was 156 of 160.

**Location:** `ja4plus/fingerprinters/ja4.py:193`.

The JA4S section below records the `JA4S_o` reading.

---

## JA4S - TLS Server Hello

### The raw form holds the extensions in wire order

FoxIO publishes JA4S as an image, so the expected-output file decides the extension
order. `tls-alpn-h2.pcap.json` gives `JA4S_r` as `t1204h2_cca9_0000,ff01,000b,0010`.
That order is not numeric order, so it is wire order.

The JA4S fingerprint hashes the extensions in wire order, and it equals the reference
`JA4S` value `t1204h2_cca9_1428ce7b4018`.

FoxIO publishes `JA4S_r` and no `JA4S_ro`, because JA4S sorts no list. A JA4S result
therefore holds one raw value under two keys: `raw` and `raw_original_order` are equal,
and both equal the reference `JA4S_r`. Before #108, the `raw` key sorted the extensions,
and it matched 49 of the 84 reference values.

The port at `Crank-Git/ja4plus-go` holds the two key names on its result struct, as the
`Raw` field and the `RawOriginalOrder` field. `ja4plus` keeps both names under parity
rule 2. The `ja4s.go` file of the port computes no raw value, so parity rule 1 decides
the value, and FoxIO holds the wire order.

### The original-order hashed value has no reference

No FoxIO expected-output file carries a `JA4S_o` key. The 37 files hold `JA4`, `JA4_r`,
`JA4_o`, `JA4_ro`, `JA4S`, `JA4S_r`, `JA4H`, `JA4H_ro`, `JA4X`, `JA4SSH`, `JA4L-C` and
`JA4L-S`, and no other method key.

`ja4plus` derives the value from the reading above. JA4S hashes its extensions in wire
order, so the original-order hash of JA4S equals the JA4S fingerprint. The
`fingerprint_original_order` key carries that value, so one caller reads one name on JA4
and on JA4S.

**No FoxIO material validates this value, in either direction.** The `docs/specs/spec.md`
changelog records it at round 11.

**Location:** `ja4plus/fingerprinters/ja4s.py:103`.

---

## JA4T and JA4TS - TCP

### No FoxIO vector validates JA4T or JA4TS

No expected-output file of the 37 carries a `JA4T` key or a `JA4TS` key, and the vector
set holds many TCP handshakes. The image is the only FoxIO material for both methods, and
no reference value settles a question the image leaves open.

### The option list holds six option kinds

`ja4plus` maps six TCP option kinds to their IANA numbers.

- 0 for EOL
- 1 for NOP
- 2 for MSS
- 3 for Window Scale
- 4 for SACK Permitted
- 8 for Timestamp

`ja4plus` drops an option kind outside those six, and it writes no number for that kind.
A packet that carries no option of the six gives the value `0`.

The list keeps the wire order. `ja4plus` never sorts it.

**Location:** `ja4plus/fingerprinters/ja4t.py:67` and `ja4plus/fingerprinters/ja4ts.py:68`.

---

## JA4D and JA4D6 - DHCP

### The reference values come from the FoxIO Wireshark dissector

The FoxIO Python implementation emits no JA4D and no JA4D6, so the expected-output file
of each DHCP capture holds an empty array. `tests/foxio_vectors/dhcp.pcapng.json` and
`tests/foxio_vectors/dhcpv6.pcap.json` each hold `[]`. The FoxIO Rust implementation
emits neither method. Both of its snapshots hold `[]`.

The FoxIO Wireshark dissector does write a reference value for both methods.
`tests/foxio_vectors/wireshark_expected/` holds a copy of the two files, taken without
change from `wireshark/test/testdata/` at the pinned upstream commit.

`.claude/rules/external-apis.md` states that the files under `wireshark/test/testdata/`
are not the authority. `wireshark/test/testdata/tls12.pcap.json` holds an empty array
where the Python file of the same name holds four fingerprints. These two methods are the
reverse case, and the
Wireshark file is the only FoxIO reference output for them. The FoxIO Zeek baseline
`zeek/tests/Traces/Scripts.ja4-dhcp/ja4d.log` holds the same four JA4D values, which is a
second FoxIO implementation that agrees. No second FoxIO implementation emits JA4D6.

`ja4plus` matches every one of the ten reference values, and every fingerprint it emits
appears in the reference.

| Capture | Frame | Reference value |
|---|---|---|
| `dhcp.pcapng` | 1 | `disco0000in_61-55_1-3-6-42` |
| `dhcp.pcapng` | 2 | `offer0000nn_1-58-59-51-54_00` |
| `dhcp.pcapng` | 3 | `reqst0000in_61-54-55_1-3-6-42` |
| `dhcp.pcapng` | 4 | `dpack0000nn_58-59-51-54-1_00` |
| `dhcpv6.pcap` | 2 | `solct0014nn_1-6-8-25_23-24` |
| `dhcpv6.pcap` | 5 | `advrt0014nn_25-26-1-2_00` |
| `dhcpv6.pcap` | 7 | `reqst0014nn_1-2-6-8-25-26_23-24` |
| `dhcpv6.pcap` | 8 | `reply0014nn_25-26-1-2_00` |
| `dhcpv6.pcap` | 11 | `relse0014nn_1-2-6-8-25-26_23-24` |
| `dhcpv6.pcap` | 12 | `reply0014nn_1-2-13_00` |

The conformance suite reads only the top level of `tests/foxio_vectors/`. The two files
add no case to that suite and no entry to the deviation register.
`tests/test_ja4d_foxio.py` and `tests/test_ja4d6_foxio.py` compare them, and both run in
the unit suite. #109 closed the gap.

**Location:** `tests/test_ja4d_foxio.py` and `tests/test_ja4d6_foxio.py`.

### How ja4plus reads JA4D

The form is `{type}{size}{ip}{fqdn}_{options}_{parameters}`. `ja4plus` reads it as
follows. The comment at `ja4plus/fingerprinters/ja4d.py:42` names two FoxIO pull
requests, 267 and 270, as the source of the skip set. The four reference values of
`dhcp.pcapng` confirm the reading.

- The type is a five-character abbreviation of the DHCP message type. An unknown type
  gives the five-digit decimal value of the code.
- The size is the maximum message size of option 57, as four decimal digits. `ja4plus`
  caps it at 9999, and it writes `0000` when the option is absent.
- The `ip` character is `i` when option 50 is present, and `n` when it is absent.
- The `fqdn` character is `d` when option 81 is present, and `n` when it is absent.
- The option list holds the option codes in wire order. It drops 0, 50, 53 and 81. The
  end marker 255 stops the read and never reaches the list. An empty list gives `00`.
- The parameter list holds the contents of option 55 in wire order. An empty list gives
  `00`.

**Location:** `ja4plus/fingerprinters/ja4d.py:45` and `ja4plus/fingerprinters/ja4d.py:183`.

### How ja4plus reads JA4D6

The form matches JA4D, and five readings differ. The message type alone is unchanged.

- The size is the byte length of the DUID inside option 1, as four decimal digits.
  `ja4plus` caps it at 9999, and it writes `0000` when the option is absent.
- The `ip` character reads option 4, which is IA_TA. The `fqdn` character reads option
  39.
- The option list holds every option code in presence order, and it drops none. The list
  holds the codes nested inside IA_NA, IA_TA, IA_PD, IA Address and IA Prefix. The
  parameter list holds the contents of option 6.

**Location:** `ja4plus/fingerprinters/ja4d6.py:76` and `ja4plus/fingerprinters/ja4d6.py:202`.

---

## JA4L - Latency

### Output format includes prefix

JA4L fingerprints include a direction prefix:
`JA4L-S={latency_us}_{ttl}` and `JA4L-C={latency_us}_{ttl}`.
The spec describes `{latency_microseconds}_{ttl}` without a prefix.

### The latency is half the measured time

`technical_details/JA4L.png` states `One-way TCP latency in us`, and every FoxIO
vector holds half the time the capture shows. `badcurveball.pcap` stream 0 sends
the SYN at `+0.000000s` and the SYN-ACK at `+0.001563s`, and the reference
`JA4L-S` is `781_238`.

The division truncates toward zero, and it produces `0` for a difference of one
microsecond.

### The client measurement point

FoxIO publishes JA4L as an image, so the expected-output files decide the
measurement point. `python/ja4.py` in the FoxIO repository records the client
point on every TCP packet that carries the relative sequence number `1` and the
relative acknowledgement number `1`. It keeps the last one. That is the bare ACK
of the handshake first, and then the first packet of the application handshake.

`browsers-x509.pcapng` stream 0 proves it. The SYN-ACK is at `+0.003815s`, the
bare ACK at `+0.003927s` and the Client Hello at `+0.004371s`. The reference
`JA4L-C` is `278_128`, and `(4371 - 3815) / 2 = 278`.

The point moves in either direction. `http1-with-cookies.pcapng` stream 0 puts it
on the bare ACK the server sends.

### A complete HTTP request does not move the client point

The FoxIO program keeps the timestamps of a packet under the protocol the tshark
dissector reports. It holds a separate state table for `http` and for `http2`. A
packet that carries a whole HTTP request therefore never moves the client point. A
packet that carries the first part of a request does move it.

Two vectors prove both halves:

- `latest.pcapng` stream 6 sends one complete `GET` request. The reference
  `JA4L-C` is `32_128`, which is the bare ACK.
- `http-empty-useragent.pcap` sends the request line, the header and the blank
  line in three packets. The reference `JA4L-C` is `177863_64`, which is the
  request line.

`ja4plus` reads the request line and the blank line that ends the header block.

### The address layer of a tunneled capture

The reference reads the address and the TTL of the outer layer, and the port of
the inner layer. `gre-sample.pcap` carries a connection between `10.16.27.12`
and `10.16.27.131` inside a GRE tunnel between `172.27.1.66` and
`66.59.109.137`. The expected-output file names the tunnel addresses with the
inner ports.

`ja4plus/utils/tunnels.py` imports the scapy dissectors for Geneve, VXLAN and
ERSPAN, because scapy leaves them unbound and stops at the tunnel header.

### The connection key of a mirrored capture

A mirror sends both directions of one session from one outer address to one
other outer address. The outer address pair then separates no direction, and one
key cannot hold both measurement points of the connection.

`gre-erspan-vxlan.pcap` is such a capture. Every packet travels from
`100.20.9.2` to `100.20.9.1`, and the inner session is `10.16.27.12:65174` to
`10.16.27.131:80`. The SYN reached the key
`tcp_100.20.9.1:80_100.20.9.2:65174`, and the SYN-ACK reached the key
`tcp_100.20.9.1:65174_100.20.9.2:80`.

`ja4plus/fingerprinters/ja4l.py` holds two keys for one connection:

- The connection key groups the packets. It reads the inner address pair and the
  inner port pair, which name both endpoints of a mirrored session.
- The reported key names the stream. It reads the outer address pair and the
  inner port pair, because the reference reports those. The SYN pairs the source
  address with the source port, and a later packet does not move that pair.

The expected-output file holds `JA4L-S` `997_64` and `JA4L-C` `953_64` on the
stream `100.20.9.2:65174` to `100.20.9.1:80`. Read #101 for the measurement.

### The QUIC measurement points

The reference reads four QUIC packets, and it reads the direction from port 443:

- `A` is the client Initial packet.
- `B` is the server Initial packet.
- `C` is the last server Handshake packet before the client answers.
- `D` is the first client Handshake packet.

`JA4L-S` is half the time from `A` to `B`, and `JA4L-C` is half the time from `C`
to `D`.

### The QUIC measurement points never restart

A client repeats a QUIC handshake over one address pair and port pair. The reference
reads the first handshake, and it reports one value pair for the whole flow. It reads
no later handshake.

A server Initial packet arrives before its client Initial packet. The reference
discards that packet, and it reports no value at all for the flow.

`rust/ja4/src/time/udp.rs` states the mechanism. The state machine holds a terminal
`Done` state that ignores every later packet. Its `Handshake` state discards a later
`ClientInitial`, and its first state discards a `ServerInitial`.

The FoxIO Rust implementation is the only FoxIO implementation that reads a QUIC
handshake, so it decides both cases. No FoxIO vector holds either case.
`tests/build_quic_ja4l_captures.py` writes the two synthetic captures that measure
them. The reference ran at the commit `tests/download_test_vectors.py` pins:

```
$ ja4 quic_repeat.pcap
  ja4l_c: 500_64
  ja4l_s: 5000_56
$ ja4 quic_mirrored.pcap
[]
```

`tests/test_ja4l_quic_repeated_connection.py` reads the same packets from the same
builder, so the tests and the measurement cover one capture each.

`ja4plus` reports the same value pair for the first capture, and no value for the second
one. #123 measured the reference and left the client value of the second capture as an
open reading. #156 closes it, and the section below states the rule.

### When a JA4L value exists

The reference gates the server value and the client value apart, and it gates each one
on its own measurement points. It does not hold one value back until it reads every
point of the connection. The rule binds both transports:

| Value | Transport | The points it needs |
|---|---|---|
| `JA4L-S` | TCP | `A`, the first SYN, and `B`, the first SYN-ACK. |
| `JA4L-C` | TCP | `B`, and `C`, the last packet that carries both relative numbers. |
| `JA4L-S` | QUIC | `A`, the client Initial packet, and `B`, the server Initial packet. |
| `JA4L-C` | QUIC | `B`, `C`, the last server Handshake packet, and `D`, the first client one. |

A capture that cuts a connection short therefore gives the values whose points it
holds, and no other value.

Four readings measure the rule. #156 holds the commands and the counts.

- `ssh2.pcapng` holds 11 TCP connections that carry a SYN and no SYN-ACK. Its
  expected-output file names none of them, and `ja4plus` produces no value for any of
  them.
- No committed vector holds a TCP connection that carries a SYN-ACK and no client
  measurement point. Every TCP connection that holds a reference `JA4L-S` also holds a
  reference `JA4L-C`.
- `ssh2.pcapng` stream 33 and `tls3.pcapng` stream 25 are QUIC connections whose server
  sends no Handshake packet that the capture holds alone. The expected-output file holds
  `JA4L-S` `16192_57` and `3583_57`, and it holds no `JA4L-C` on either one. The two
  connections prove that the reference completes a server value without a client value.
- `quic_mirrored.pcap` holds a server Initial packet that leads its client Initial
  packet. The reference reports no value, so the QUIC client value needs point `B`.

The body of #156 states a different rule: a JA4L value exists only when the
fingerprinter reads all four measurement points. That rule is wrong, and the vectors
reject it. A rule that held `JA4L-S` back until the client point arrived breaks 80
conformance cases that pass today. It also deletes the two `JA4L-S` values above.

```
$ pytest tests/ -m spec_validation -q
FAILED tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[v6.pcap-JA4L-S]
80 failed, 1295 passed, 149 skipped, 980 deselected, 117 xfailed
```

The fingerprinter therefore gates a JA4L value per side, and not on all four
measurement points.

### The return value of a partial client point

`process_packet` returns the client value once for every packet that moves point `C`,
and the stored list holds one value for the connection. Across the committed vectors
the stored list holds 60 client values and the return path reports 105.

The two paths disagree because the reference reads the last packet that carries both
relative numbers. A reader knows which packet is last only when the connection ends.
#156 measured three candidate end-of-connection points against the 60 values:

| The end-of-connection point | Client values it reports |
|---|---|
| A FIN or a RST after the final client point | 26, and it loses 34 |
| Every measurement point read | 105, which is the behaviour today |
| A read of the stored list at the end of the capture | 60, and it loses none |

Only the last point reproduces the reference, and 34 of the 60 connections never close
inside their capture. `macos_tcp_flags.pcap` holds no FIN packet and no RST packet at
all, and `tls3.pcapng` holds 2 FIN packets against 13 client values.

`ja4plus` reads the stored list, so the conformance suite measures the correct value.
The user decided on 2026-08-07 to record the divergence and to leave the return path as
it is. The `Divergence register` of `docs/specs/spec.md` holds the row, and the decision
is reversible.

`tests/foxio_deviations.json` holds no entry for the divergence. The conformance harness
reads the stored list, and the stored list is correct, so every case passes. A strict
entry therefore reports `XPASS(strict)` and fails the suite. A probe entry for
`latest.pcapng/JA4L-C` proves it:

```
[XPASS(strict)] issue #156: Probe: the return path reports 11 client values and the stored list holds 6.
FAILED tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[latest.pcapng-JA4L-C]
```

`tests/test_ja4l_return_path.py` carries the divergence instead. It holds the returned
count and the stored count of every committed vector, so it fails when either one moves.

### A time of one second or more

The FoxIO program reads the difference of two timestamps as a `timedelta`, and it
takes the `microseconds` attribute, which holds the part below one second. A
handshake of 1.2 seconds therefore gives 100000, not 600000. No FoxIO vector
holds a difference of one second or more, so `ja4plus` divides the whole
difference and no vector separates the two readings.

---

## JA4SSH - SSH Traffic

### The fingerprint window

The window holds 200 SSH packets by default, and the constructor argument
`packet_count` sets it. `technical_details/JA4SSH.png` states the interval
verbatim: `(runs every 200 SSH packets by default)`.

The window counts the SSH packets of both directions. A bare ACK is not an SSH
packet, and it does not advance the window. The image lists `SSH packets sent
from client`, `SSH packets sent from server`, `Bare ACKs sent from client` and
`Bare ACKs sent from server` as four separate fields. `ssh-scp-1050.pcap` confirms
the reading: the reference holds four windows, each of 200 SSH packets, and the
bare ACK counts of the four differ.

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details
(retrieved 2026-08-06).

**BUG (fixed by #28):** Before #28 the window triggered at
`min(configured_packet_count, 10)`, and a complete key exchange also triggered
it. A capture of 10 SSH packets produced a fingerprint that no reference
implementation matches.

### The bare ACK

A bare ACK is one packet that carries the ACK flag alone and no payload. FoxIO
counts one only when the TCP flags equal `0x0010`, so a SYN+ACK, a FIN+ACK and a
RST+ACK never reach the bare-ACK counter.

The ACK that completes the TCP handshake is a bare ACK, and it arrives before the
first SSH packet of the connection. FoxIO counts it, because `python/ja4.py` holds
a state table entry for every packet whose source port or destination port is 22.
Four vectors confirm the reading. `ssh-r.pcap`, `ssh-scp-1050.pcap` and
`ssh2.pcapng` each hold one bare client ACK before the first SSH packet, and each
reference value reports one more client ACK than a state table built on SSH data
alone. `ssh.pcapng` holds no bare ACK, and its value is unchanged.

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4ssh.py
(retrieved 2026-08-06).

**BUG (fixed by #92):** Before #92 the fingerprinter created a state table entry
on the first SSH packet, so it dropped the ACK of the TCP handshake. It also read
the ACK flag alone, so it counted a SYN+ACK, a FIN+ACK and a RST+ACK as bare ACKs.

### The window a connection holds open

A connection that closes emits the window it holds open. `python/ja4.py` states the
rule above `finalize_ja4ssh`: `If the SSH connection is not terminated or the last
sample is less than 200 the finalize function just cleans up and prints the last
JA4SSH hash`. That function runs on a packet that carries the FIN flag and the ACK
flag. An empty window emits nothing, so the second FIN packet of a close finds the
window the first FIN packet emptied and adds no value.

`ssh-r.pcap` confirms the reading. Stream 1 holds 11 SSH packets and one
occurrence, `c64s64_c6s5_c4s5`. Stream 2 holds 931 SSH packets, four full windows,
and a fifth occurrence of 131 packets. `ssh-scp-1050.pcap` and `ssh2.pcapng` carry
no FIN packet, and each keeps its full windows alone.

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py
(retrieved 2026-08-06).

### Three defects of the reference

`ja4plus` declines to reproduce three results of the reference. Each one describes
the capture and not the connection, so a user cannot compare it against the output
of another tool. The measurement ran `python/ja4.py` at the pinned commit against
`tshark` 4.6.7.

**The mode field reads the whole capture.** `dict(ja4sh_stats)` copies the
dictionary and not the two lists inside it, so every window on every connection
shares one `client_payloads` list and one `server_payloads` list. `ssh-r.pcap`
stream 2 window 1 reports `c64s64`, and the packets of that window read `c76s76`.
`ja4plus` reads the lengths of the window. #96 records the decision.

**A bare ACK writes another occurrence.** `(entry['count'] % ssh_sample_count) == 0`
stays true for every bare ACK that follows a window boundary, so each of those
packets writes the next occurrence key from a window that holds no SSH packet.
`ssh-r.pcap` stream 0 holds `JA4SSH.2` equal to `c64s64_c0s0_c0s1`. `ja4plus` emits
a value only for a window that holds SSH packets. #97 records the decision.

**The stream index 0 is false.** `finalize_ja4ssh` guards with `if stream:`, so the
reference emits no trailing window for the connection it holds at index 0.
`gre-sample.pcap`, `sshv1.pcap` and `v6.pcap` each hold their SSH connection at that
index, and the reference holds no JA4SSH value for any of them. The same run, with
that guard read as `if stream is not None:` and nothing else changed, emits
`c24s23_c4s4_c5s4` for `gre-sample.pcap` and `c20s12_c18s23_c10s1` for `sshv1.pcap`.
`ja4plus` emits the window for every connection that closes. #105 records the
decision.

### The SSH message, not the TCP segment

The reference counts the packets `tshark` labels `ssh`. `update_ssh_entry` reads
`has_ssh = ('ssh' in x['protos'])`, and `x['protos']` is the `frame.protocols`
field of `tshark -T ek`. `tshark` reassembles an SSH message that spans two TCP
segments. It labels the segment that completes the message, and it labels the
earlier segment `tcp`.

`tshark` 4.6.7 proves it on `ssh-r.pcap` stream 2:

```
$ tshark -r tests/foxio_vectors/ssh-r.pcap -Y "tcp.stream==2 && tcp.len>0" \
    -T fields -e frame.number -e tcp.srcport -e tcp.len -e frame.protocols \
    -e tcp.segment -e tcp.reassembled.length
395	46396	21	eth:ethertype:ip:tcp:ssh
397	22	21	eth:ethertype:ip:tcp:ssh
399	46396	1448	eth:ethertype:ip:tcp
400	46396	48	eth:ethertype:ip:tcp:ssh	399,400	1496
```

Frame 399 and frame 400 carry one KEXINIT message of 1496 bytes. The reference
counts one packet for frame 400 and none for frame 399, and it records the payload
length of frame 400 alone. `SSHMessageTracker` reproduces that boundary.

The boundary is readable only while the direction sends plaintext. The tracker
follows the four-byte length field of each message, and it counts every segment
after `SSH_MSG_NEWKEYS`, because an encrypted message carries no length a reader
can trust. A capture that starts after the version banner holds no boundary, so the
tracker counts every segment there too.

The same command counts the segments each vector holds outside a message end. Only
`ssh-r.pcap` holds one on a stream with an expected value: stream 1 holds one and
stream 2 holds one. `ssh.pcapng`, `ssh-scp-1050.pcap`, `ssh2.pcapng` and `ssh-r.pcap`
stream 0 hold none, and their values do not change.

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4ssh.py
(retrieved 2026-08-06).

### Direction detection on non-standard ports

**BUG (fixed in v0.4.0):** Prior to v0.4.0, non-standard port direction
detection was inverted: the lower port was assigned as client when it
should be server. Fixed by swapping the assignment.

---

## JA4X - X.509 Certificates

### The scan reads the record layer, then the handshake messages

FoxIO publishes JA4X as an image, so the expected-output files decide. One TLS
record carries more than one handshake message, and one handshake message spans
more than one record. A scan that reads only the first handshake message of a
record misses the Certificate message that follows a ServerHello in the same
record. `latest.pcapng` stream 9 holds one 7136-byte record that carries both
messages, and the reference holds
`a373a9f83c6b_2bab15409345_0f2217ba412e` for it.

The scan therefore joins the payload of every complete handshake record that
follows without a gap, then reads the handshake messages of the joined bytes.
A proxy writes its own handshake first. The stream does not always start on a
record boundary, so the scan looks for the boundary one byte at a time.
`socks-https-example.pcap` supports this reading.

### One value for each certificate on each stream

`python/ja4x.py` of the FoxIO repository states "JA4X does not use any caching
from common.py", and it computes one JA4X value for each certificate of the
stream it reads. The key of the processed certificate set names the stream and
the certificate. A key that named only the certificate dropped the value of
every stream after the first that carried the same chain.
`socks-https-example.pcap` streams 2 and 4 exposed that defect.

Verified against
`https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4x.py` (retrieved
2026-08-06).

### Certificate deduplication cleanup

The processed certificate table holds 1000 entries. When the table is full, the
fingerprinter drops the oldest 500. This is a memory management strategy, not a
hard limit on unique certificates.

The eviction runs on each new entry. A wall clock gated it before, and a capture
replays faster than real time, so the table grew without a limit between two
runs of a gated eviction.

### The scan offset of a stream

The scan of one stream resumes where the last packet of the stream left it. A
scan that starts at zero on every packet costs the square of the stream length,
and `http2-with-cookies.pcapng` then takes 18 seconds.

The offset is stored with the sequence number the reassembled bytes start at. A
segment that arrives late lowers that number and moves every offset, so the scan
starts at zero again when the two numbers differ.

### Two reasons a JA4X value stays absent

The reference reads the TLS dissection of `tshark`, and two of its abilities
have no counterpart here.

- `tshark` decrypts a TLS 1.3 handshake with the secrets a capture carries.
  `http2-with-cookies.pcapng` and `chrome-cloudflare-quic-with-secrets.pcapng`
  hold a decryption secrets block with a `SERVER_HANDSHAKE_TRAFFIC_SECRET`
  entry, and the certificate of both reaches the wire encrypted. `ja4plus`
  decrypts nothing, so it reads no certificate there.
- `tshark` dissects TLS on the ports its dissector table names. It reads the
  tunnel of `socks-https-example.pcap` on port 1080 and holds a JA4X value. It
  reads no TLS on port 8080 of `https-connect.pcap`, and it reads none on port
  9901 of `socks4-https.pcap`. `ja4plus` reads the record layer by content, so
  it holds a JA4X value on all three. The deviation register records the two
  cases where `ja4plus` holds a value the reference does not.

### TCP reassembly

**Fixed in v0.4.0:** Stream reassembly now uses TCP sequence numbers
for correct ordering. Prior versions appended data in arrival order,
which could corrupt streams with out-of-order TCP segments.

### The order holds across a sequence wrap

A TCP sequence number is 32 bits and wraps back to zero. An order that compares the raw
numbers puts every segment after the wrap point before every segment before it, so a
connection that crosses the boundary reassembles backwards.

`_seq_before` orders two sequence numbers on the difference between them, as RFC 1982
does. `get_stream` reads it for the gap test and the overlap arithmetic, so both hold
across the wrap.

`_ordered_segments` gives the segment order. A stream occupies one arc of the sequence
space, and one step between two neighbours closes that arc. The method sorts the
segments on the raw number, finds the widest step, and starts the stream at the segment
after it. `get_stream` and `base_seq` both read that order.

A comparison of each segment against a running earliest value looks equivalent and is
not. `_seq_before` stops being transitive once the segments span more than half the
sequence space, so that form returns a different first segment for a different arrival
order. `max_stream_bytes` now bounds the stored segments, so the spread of the stored
sequence numbers stays inside one arc. The widest-step reading depends only on the
sequence numbers, so the reassembled bytes never depend on the order the capture
delivered the segments.

`add_segment` detects a duplicate against a set of `(seq, length)` pairs. The earlier
scan of every stored segment cost the square of the segment count: 10000 segments took
0.451 s, and 20000 took 1.765 s. The set gives 0.0019 s and 0.004 s.

**Location:** `ja4plus/utils/tcp_stream.py`. #32 built it.

### One stream holds a bounded number of bytes and segments

`max_stream_bytes` bounded the bytes `get_stream` returns, and nothing bounded the bytes
the stream stores. A sender of many distinct small segments grew one stream without a
limit. `add_segment` now refuses a segment once the stream holds `max_stream_bytes`
bytes, and once it holds `max_stream_segments` segments. A refused segment enters no
state, so the stream accepts it again after a trim frees the room.

The byte cap alone leaves a sender of one-byte segments a million entries in the segment
list, so the segment cap carries the second bound. The default is 4096. The largest
stream of the FoxIO vectors holds 1336 segments and 1853328 bytes, both in
`http2-with-cookies.pcapng`. The measurement runs `Processor` over every capture under
`tests/foxio_vectors/` and reads the stored segments after each call to `add_segment`.

The byte cap cuts that one vector stream at 1048576 bytes, and no reference value moves.
`get_stream` already truncated its result at `max_stream_bytes`, so no fingerprinter ever
read the bytes beyond the cap. The conformance suite reports 1375 passed, 146 skipped and
120 xfailed before the change and after it.

`get_stream` no longer truncates its result. The stream stores no more than
`max_stream_bytes`, and the result never holds more than the stream stores.

`trim_stream` compared raw sequence numbers, which holds the defect #32 removed from
`get_stream`. It now reads `_seq_before`. It takes an absolute sequence number, never a
byte offset. #78 removed its one call site, because that call passed a byte offset and
removed no segment for a realistic initial sequence number.

`ja4h.py` left a buffer that is not an HTTP request in the reassembler for the life of
the capture. It now removes the stream when no later byte can make the buffer an HTTP
request. `can_become_http_request` reads the buffer against the HTTP method tokens and
keeps a buffer that is a prefix of one, because a request line spans two segments.

The removal waits one packet. A segment that arrives out of order puts the middle of a
request at the start of the buffer, and that buffer starts no HTTP request. A removal on
that packet drops the segment, and the request never reassembles when the head arrives.
The head lowers the base sequence number, so `_drop_an_unusable_stream` removes the
stream only on a packet that leaves the base sequence number where the previous packet
left it. The measurement: the tail of `GET /index.html HTTP/1.1` arrives at sequence
number 126 and the head at 100. A removal on the first packet gives `None` for both
packets. The one-packet wait gives a fingerprint on the second.

`self.unusable_base` holds one base sequence number for each stream that waits. It drops
the keys the reassembler no longer holds once it passes `max_streams` entries, the way
`ja4x.py` prunes `scan_offsets`.

**Location:** `ja4plus/utils/tcp_stream.py`, `ja4plus/utils/http_utils.py`,
`ja4plus/fingerprinters/ja4h.py`. #33 built it, and it absorbed #103.

---

## JA4H - HTTP

### The raw form holds the wire order

FoxIO publishes one raw key for JA4H, `JA4H_ro`, and no `JA4H_r` key. `ja4plus` therefore
computes one JA4H raw form. A sorted raw form matches no reference value and no other
implementation, so the fingerprinter emits none.

The form is `<part a>_<header names>_<cookie names>_<cookie pairs>`. A request that
carries no cookie ends after the header names and one underscore, as
`http1.pcapng.json` writes it:

```
po11nn050000_Host,Accept,User-Agent,Content-Type,Content-Length_
ge11cr04da00_Host,User-Agent,Accept,Accept-Language_yummy_cookie,tasty_cookie_yummy_cookie=choco,tasty_cookie=strawberry
```

The header list drops the Cookie header, the Referer header and an HTTP/2
pseudo-header, because the first section already reports the first two and the reference
lists no pseudo-header. The hashed form and the raw form read one header list, so the raw
form explains the hash.

**Vector:** `http1-with-cookies.pcapng` and the 56 values of `http1.pcapng`.

**Location:** `ja4plus/fingerprinters/ja4h.py`.

### Both cookie hashes read one ordered cookie list

HTTP permits a repeated cookie name. `ja4plus` keeps every occurrence, and the
cookie-name hash, the cookie-value hash and the raw form read one list of pairs. An
earlier form built the cookie-value hash from a dictionary, which kept the last value of
a repeated name, so the two hashes described different cookie sets.

No FoxIO vector carries a repeated cookie name, so the FoxIO Python implementation
settles the reading. It collects the pairs into a list, and it sorts that list on the
cookie name alone:

```python
sorted_pairs = sorted(cookie_pairs, key=lambda p: p[0])
x['cookie_fields'] = [pair[0] for pair in sorted_pairs]
x['cookie_values'] = [pair[1] for pair in sorted_pairs]
```

The sort is stable, so two cookies that carry one name keep their wire order. `ja4plus`
sorts the same way. The 82 JA4H values that the vector set produces do not change.

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4h.py (retrieved
2026-08-07)

**Vector:** none carries a repeated cookie name. `tests/test_ja4h_cookie_list.py` holds
the tests.

**Location:** `ja4plus/fingerprinters/ja4h.py`.

### The request line carries an optional minor version

A request line reads `GET / HTTP/2`, and HTTP/2 and HTTP/3 name no minor version. The
request-line pattern accepts the minor version as optional for that reason. An earlier
pattern required `HTTP/\d+\.\d+`, so the parser read no HTTP/2 request line, although
`_http_version_to_str` maps `2` to the version code `20`.

**Vector:** `http2-with-cookies.pcapng` holds 15 HTTP/2 requests inside TLS records, and
`ja4plus` decrypts none of them. #129 records that deviation.

**Location:** `ja4plus/fingerprinters/ja4h.py` and `ja4plus/utils/http_utils.py`.

### TCP reassembly

**Fixed in v0.4.0:** HTTP parsing now accumulates TCP stream data
before attempting to parse. Prior versions operated on single-packet
payloads only, missing HTTP requests spanning multiple TCP segments.

---

## TLS Utilities

### SNI parsing returns boolean True for unparseable SNI

When the SNI extension is present but the hostname cannot be extracted,
`_parse_sni()` returns `True` (boolean). This works because the JA4
fingerprinter checks `'d' if sni else 'i'`, and `True` is truthy.

---

## IPv6 Support

**Added in v0.4.0:** All fingerprinters support both IPv4 and IPv6.
Prior versions only checked for scapy's `IP` layer.

---

## QUIC Support

**Added in v0.4.0.** QUIC Initial packet parsing decrypts the Initial
packet using DCID-derived keys, extracts CRYPTO frames, and parses the
contained TLS ClientHello.

**Crypto pipeline:**
1. Extract DCID from the Initial long header
2. Derive Initial secret via HKDF (salt depends on QUIC version)
3. Derive client key, IV, and header protection key
4. Remove header protection (AES-ECB mask)
5. Decrypt payload with AES-128-GCM
6. Extract CRYPTO frames and reassemble by offset
7. Parse the contained TLS ClientHello

**Version detection:** QUIC v2 identified by wire version `0x6B3343CF`;
all other non-zero versions use the v1 salt.

**Integration:** `extract_tls_info` checks for QUIC on UDP packets
before falling through to standard TLS parsing.

---

## A hello is bounded on its own length field, not on the record length

Issue #151 asked why `ja4plus` read no ServerHello on three streams for which the FoxIO
Rust snapshot holds a JA4S value. The three share one cause, and the cause was a defect
in this project.

### The mechanism

A TLS handshake record carries one or more handshake messages. A TLS 1.2 server puts the
ServerHello, the Certificate, the ServerKeyExchange and the ServerHelloDone in one
record. That record is longer than one TCP segment, so the first segment holds the whole
ServerHello and only part of the record.

`parse_tls_handshake` bounded the hello on the record length field. It returned nothing
whenever the segment held less than the record declared, so it never read a ServerHello
that a coalesced record carries. The bound now reads the three-byte length field of the
handshake message at offset 6, and the reader slices the buffer at the end of that
message. The slice keeps the reader inside the hello, because the bytes that follow
belong to the Certificate message.

### The measurement

The first server data packet of each stream, read with `scapy`:

| Capture | Stream | Packet | Segment bytes | Record needs | ServerHello ends at byte |
|---|---|---|---|---|---|
| `ssh2.pcapng` | `57374 <-> 52.178.17.3:443` | 232 | 1452 | 6296 | 94 |
| `ssh2.pcapng` | `57375 <-> 204.79.197.220:443` | 254 | 1452 | 7036 | 107 |
| `tls-handshake.pcapng` | `50167 <-> 40.126.24.84:443` | 148 | 1460 | 3955 | 98 |
| `browsers-x509.pcapng` | `54524 <-> 13.107.21.239:443` | 5 | 1458 | 5947 | 111 |
| `latest.pcapng` | `52940 <-> 52.249.29.248:443` | 158 | 1452 | 7141 | 94 |
| `latest.pcapng` | `52941 <-> 52.249.29.248:443` | 192 | 1452 | 7141 | 94 |
| `socks4-https.pcap` | `50606 <-> 10.0.0.2:9901` | 8 | 1360 | 6776 | 90 |

Every row reads the same way. The record needs more bytes than the segment carries, and
the ServerHello ends inside the segment.

### The third gap in the FoxIO Python implementation

`.claude/rules/external-apis.md` named two gaps before this issue: the FoxIO Python
implementation reads no QUIC handshake, and it reads no TLS on a port it does not know.
This is a third gap. The FoxIO Python expected-output file omits the JA4S value of every
stream in the table, and the FoxIO Rust snapshot holds it for six of the seven.

`tls-handshake.pcapng` proves the gap on one capture. Stream `50167` runs on port 443, so
neither of the first two gaps explains the omission, and the Rust snapshot holds
`t120400_c030_4e8089b08790` for it.

The six streams the Rust snapshot covers each produce the Rust value.
`tests/test_foxio_rust_parity.py` holds the measurement in
`TestTheStreamsThatCoalesceTheServerHelloRecord`. The snapshots of
`browsers-x509.pcapng` and `latest.pcapng` join the vector set for that measurement.

### The seventh stream

`socks4-https.pcap` stream `50606 <-> 10.0.0.2:9901` is the one exception. The FoxIO Rust
snapshot holds `ja4t`, `ja4l_c` and `ja4l_s` for it, and no `ja4s` and no `ja4`. No FoxIO
implementation holds a JA4S value for the stream.

`ja4plus` reads the record layer without regard to the tunnel protocol that carries it,
which is the behaviour #138 decided to keep for the three JA4X values on the same stream.
The register records the JA4S value under the same decision.

### The register

The register rises from 99 keys to 104, and the conformance suite reports 104 xfailed.
The five new keys are `browsers-x509.pcapng/JA4S`, `browsers-x509.pcapng/JA4S_r`,
`latest.pcapng/JA4S`, `latest.pcapng/JA4S_r` and `socks4-https.pcap/JA4S`. The existing
`ssh2.pcapng` and `tls-handshake.pcapng` JA4S keys hold the capture, so they absorb the
three streams #151 names, and their cause text now records the second reason.

Verified against: https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1 (TLS 1.2, retrieved 2026-08-07)
Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/rust/ja4/src/snapshots (commit 27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8)
