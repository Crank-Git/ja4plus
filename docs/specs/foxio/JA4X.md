# JA4X

This page is this project's own prose form of `technical_details/JA4X.png`. It follows the
procedure in `docs/specs/foxio/README.md`. No image enters this repository.

| Item | Value |
|---|---|
| Source | `https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4X.png` |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-08 |
| SHA-256 of the image | `71f3bd839ca7e228da8ee69dce69de870d5ee69f3e91534356bae1a48d7f322a` |
| Pixel size of the image | 960 by 540 |

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4X.png (retrieved 2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

Reproduce the hash from a checkout at the pinned commit.

```bash
shasum -a 256 technical_details/JA4X.png
```

The image is 960 by 540 pixels, which is its native size. A reader who enlarges it reads
the same text, and this page records the size so that nobody measures it again.

## What the image holds

**`JA4X.png` is the specification of JA4X.** No text file at the pinned commit states a
JA4X rule, so this page writes "the specification" and "the image" for the same file.

The image titles itself `JA4X: X509 Fingerprint`, under the subtitle
`(fingerprints how a cert is created)`. It draws one example string, three captions, six
named example values and one closing sentence. It holds nothing else.

## The field layout

The image draws one example string and labels three parts `JA4X_a`, `JA4X_b` and `JA4X_c`.

```
JA4X=96a6439c8f5c_96a6439c8f5c_aae71e8db6d7
     \__________/ \__________/ \__________/
       JA4X_a       JA4X_b       JA4X_c
```

| Part | The image's caption | Value in the example |
|---|---|---|
| JA4X_a | Hash of Issuer RDNs, in order | `96a6439c8f5c` |
| JA4X_b | Hash of Subject RDNs, in order | `96a6439c8f5c` |
| JA4X_c | Hash of Extensions, in order | `aae71e8db6d7` |

One caption sits above the three, and it applies to all three: `(does not include values)`.

The parts join with `_`.

## The six example values the image lists

The image names an application beside each value.

| Name in the image | Value in the image |
|---|---|
| SoftEther | `d55f458d5a6c_d55f458d5a6c_0fc8c171b6ae` |
| Metasploit | `2bab15409345_2bab15409345_75f1b0fafedd` |
| Qakbot | `2bab15409345_af684594efb4_e3b0c44298fc` |
| Async,Quasar,BitRAT | `7022c563de38_7022c563de38_0147df7a0c11` |
| Sliver, Havoc C2 | `000000000000_7c32fa18c13e_bf0f0589fc03` |
| Sliver, Havoc C2 | `000000000000_4f24da86fad6_bf0f0589fc03` |

The image closes with one sentence:
`Combine with JA4, JARM, or other metadata like Issuer Org to eliminate FPs`.

**The Qakbot row disagrees with the `README.md` of the `ja4` repository.** R8 holds the
measurement and the reading.

## The named question — the image states nothing about the transport

**#202 exists to test one reading against the image.** The user decided on 2026-08-07 that
`ja4plus` reads the record layer without regard to the tunnel protocol that carries it.
`docs/specs/spec.md` holds the register row, and `tests/foxio_deviations.json` holds the
key `socks4-https.pcap/JA4X`.

**The image states nothing about the transport that carries the certificate.** The
statement is a negative, and the reading below names every element that a transport rule
could occupy.

| Element of the image | What it states about the transport |
|---|---|
| The title `JA4X: X509 Fingerprint` | Nothing. It names the certificate format. |
| The subtitle `(fingerprints how a cert is created)` | Nothing. It names the purpose. |
| The caption `(does not include values)` | Nothing. It names a field rule. |
| The three part captions | Nothing. Each one names a list inside the certificate. |
| The example string and its three labels | Nothing. It draws the output schema. |
| The six example values | Nothing. Each one names an application. |
| The closing sentence | It names JA4, JARM and Issuer Org as separate metadata. It states no rule about the packet that carries the certificate. |

The image therefore names no TLS version, no TCP port, no proxy, no tunnel protocol and no
direction. **The negative confirms the existing ruling, and it reopens nothing.** The
specification states no transport rule, so the specification neither supports nor refutes
the three values on `socks4-https.pcap`. "The register" below states the same result for
each register entry.

**The register row names a payload tunnel, and not an encapsulation tunnel.** A SOCKS4
proxy writes its own handshake into the TCP payload, and the TLS record layer follows it in
the same byte stream. `ja4plus/utils/tunnels.py` reads a different case: Geneve, VXLAN and
ERSPAN each carry a second address layer that scapy dissects. `ja4x.py` reads no tunnel
header of either kind, and `ja4x.py:180` to `ja4x.py:182` state the one behaviour the
register records:

```python
# A proxy writes its own handshake before the TLS record layer starts,
# so the stream does not always start on a record boundary.
offset += 1
```

**The image states no rule that comment could break.**

## The rules

Each rule below carries two corroborations. Neither corroboration is the image. The
in-repository corroborations read the FoxIO material at the pinned commit.

**Eleven rules reach two corroborations each. The user decided R8, which the image
contradicts.**

| State | Rules |
|---|---|
| Two corroborations, and the image agrees | R1, R2, R3, R4, R5, R6, R7, R10 |
| Two corroborations, and the image states nothing | R9, R11 |
| Two corroborations, and the image contradicts them | **R8. The user decided it on 2026-08-08, and the ruling is reversible.** |

**No rule on this page holds fewer than two corroborations.** R8 was uncertain for the
opposite reason: the image draws both forms, so the image contradicts its own example.
**The user settled it, and Changelog round 77 records the ruling.**

### R1 — JA4X holds three parts, joined with `_`

The fingerprint is `<issuer hash>_<subject hash>_<extension hash>`.

- Corroboration 1: `rust/ja4x/src/lib.rs`, `X509Rec::into_out`, builds
  `let parts = [issuer_rdns, subject_rdns, extensions];` and writes
  `parts.iter().map(hash12).join("_")`.
- Corroboration 2: `wireshark/source/packet-ja4.c:589`, inside `ja4x()`, writes the format
  string `"%12.12s_%12.12s_%12.12s"`.

`README.md` lines 143 to 147 at the pinned commit publish six JA4X values, and each one
holds three parts.

### R2 — Part a hashes the object identifiers of the issuer RDNs

An RDN is a relative distinguished name. Part a reads the issuer name of the certificate.

- Corroboration 1: `rust/ja4x/src/lib.rs`, `impl From<X509Certificate> for X509Rec`, builds
  `issuer_rdns` from `x509.issuer().iter_attributes()`.
- Corroboration 2: `wireshark/source/packet-ja4.c:1045` sets `oid_type = 0` at the
  `tls.handshake.certificate` field, and line 1050 raises it to 1 at
  `x509af.validity_element`. A certificate carries the issuer before the validity period,
  so `oids[0]` holds the issuer object identifiers.

### R3 — Part b hashes the object identifiers of the subject RDNs

- Corroboration 1: `rust/ja4x/src/lib.rs` builds `subject_rdns` from
  `x509.subject().iter_attributes()`.
- Corroboration 2: `wireshark/source/packet-ja4.c:1050` sets `oid_type = 1` at the validity
  period. A certificate carries the subject after the validity period, so `oids[1]` holds
  the subject object identifiers.

### R4 — Part c hashes the object identifiers of the certificate extensions

- Corroboration 1: `rust/ja4x/src/lib.rs` builds `extensions` from
  `x509.extensions().iter().map(|ext| hex::encode(ext.oid.as_bytes()))`.
- Corroboration 2: `wireshark/source/packet-ja4.c:1070` sets `oid_type = 2`. Line 1067
  opens that block for the `x509af.extension.id` field, and line 1079 appends the bytes of
  that field.

### R5 — Each part is the first 12 characters of the SHA-256 of its list

- Corroboration 1: `rust/ja4x/src/lib.rs`, `hash12`, carries the doc comment
  `Returns first 12 characters of the SHA-256 hash of the given string.`
- Corroboration 2: `wireshark/source/packet-ja4.c:583` calls
  `g_compute_checksum_for_string(G_CHECKSUM_SHA256, ...)` and line 589 prints the result
  with `%12.12s`.

`python/ja4x.py` writes `sha256(",".join(hex_strings).encode('utf8')).hexdigest()[:12]`,
which is a third corroboration.

### R6 — A list joins with `,`, and it holds the hex form of each object identifier

The hex form is the DER content of the object identifier, without the tag byte and without
the length byte. The object identifier `2.5.4.3` becomes `550403`.

- Corroboration 1: `rust/ja4x/src/lib.rs` writes `hex::encode(a.attr_type().as_bytes())`
  and joins the results with `.join(",")`.
- Corroboration 2: `python/ja4x.py`, `oid_to_hex`, builds the DER encoding and returns
  `"".join("{:02x}".format(num) for num in oid)[4:]`. The slice drops the tag byte and the
  length byte.

`wireshark/source/packet-ja4.c:1060` carries the comment
`// BUG-FIX: Ja4x should use Hex codes instead of ascii`, and line 1063 writes each byte
with `"%02x"`. Line 1058 appends `,` before each list entry after the first.

### R7 — A list holds the object identifier alone, and never the value

The image's caption states this rule in words: `(does not include values)`.

- Corroboration 1: `rust/ja4x/src/lib.rs` reads `a.attr_type()` for the fingerprint. It
  reads the value in `Oid::new`, and that value reaches the `issuer` and `subject` output
  fields alone, never `ja4x`.
- Corroboration 2: `wireshark/source/packet-ja4.c:1053` matches the field `x509if.oid`. The
  dissector names the attribute value with a different field, and `ja4x()` never reads it.

### R8 — An empty list writes the zero sentinel, and the image contradicts itself

**The user decided this rule on 2026-08-08, and the ruling is reversible.** An empty
list writes `000000000000`. The section below records the contradiction the image
carries, so that a later reader does not derive it again.

The zero sentinel is the literal value `000000000000`.

- Corroboration 1: `rust/ja4x/src/lib.rs`, `hash12`, carries the doc comment
  `Returns "000000000000" (12 zeros) if the input string is empty.` Its unit test asserts
  `assert_eq!(hash12(""), "000000000000");`.
- Corroboration 2: `wireshark/source/packet-ja4.c:590` to `592` write
  `wmem_strbuf_get_len(cert->oids[n]) ? hashN : "000000000000"` for each of the three
  parts.

**The image draws both forms, so the image decides nothing.** Its two `Sliver, Havoc C2`
rows write `000000000000` in part a. Its `Qakbot` row writes `e3b0c44298fc` in part c, and
that value is the truncated SHA-256 of the empty string.

```bash
python3 -c "import hashlib; print(hashlib.sha256(b'').hexdigest()[:12])"
e3b0c44298fc
```

**The `README.md` of the `ja4` repository writes the zero sentinel for the same
certificate.** Line 146 at the pinned commit reads
```JA4X=2bab15409345_af684594efb4_000000000000```. The first two parts match the image's
Qakbot row exactly, and the third part does not.

**This repository holds no Qakbot certificate, so one step of the reading is an
inference.** The
arithmetic above is a measurement, and the reading that the certificate carries no extension
follows from it. A reader who obtains the certificate can settle the step.

`python/ja4x.py` explains the image. It writes
`sha256(",".join(hex_strings).encode('utf8')).hexdigest()[:12]` with no test on the empty
list, so the FoxIO Python implementation writes `e3b0c44298fc` for a certificate that
carries no extension. **The image records the FoxIO Python output, and the `README.md`
records the FoxIO Rust output and the Wireshark output.**

**No vector in this repository reaches the case.** No expected-output file under
`tests/foxio_vectors/` holds `e3b0c44298fc`, and none holds a `JA4X` value with a zero
sentinel. Measured on 2026-08-08 with `grep -rl "e3b0c44298fc" tests/foxio_vectors/`, which
matched no file.

#### The decision of 2026-08-08, and the contradiction it records

**The user decided the zero sentinel.** #228 holds the decision comment, and Changelog
round 77 of `docs/specs/spec.md` records it. The decision is reversible.

| Form | Value | Sources at the pinned commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
|---|---|---|
| **The decided form** | `000000000000` | `rust/ja4x/src/lib.rs:166` to `:176`, whose unit test at `:181` asserts `assert_eq!(hash12(""), "000000000000");`. `wireshark/source/packet-ja4.c:590` to `:592`. `README.md` line 146, which reads ```JA4X=2bab15409345_af684594efb4_000000000000```. |
| **The rejected form** | `e3b0c44298fc` | `python/ja4x.py:87`, which hashes the join with no guard on the empty list. The `Qakbot` row of `technical_details/JA4X.png`, which reads `2bab15409345_af684594efb4_e3b0c44298fc`. |

**The image contradicts itself, and this page states the contradiction rather than
hiding it.** Its two `Sliver, Havoc C2` rows write `000000000000` in part a, and its
`Qakbot` row writes `e3b0c44298fc` in part c for the same condition. The rejected form is
the truncated SHA-256 of the empty string, reproduced on 2026-08-08:

```bash
python3 -c "import hashlib; print(hashlib.sha256(b'').hexdigest()[:12])"
e3b0c44298fc
```

**The first two parts of the `Qakbot` row and of `README.md` line 146 match exactly.** The
third part does not match. The two sources therefore describe one certificate and two
implementations.

**#228 changed no fingerprinter, because `ja4plus` already wrote the decided form.**
`ja4plus/fingerprinters/ja4x.py:65` to `:71` hold the guard, one for each of the three
parts. `tests/test_ja4x_empty_ext.py` pins the sentinel and names this rule.

**The gate is proven by its reversal.** Remove the three guards, so that each part hashes
the empty join, and 7 unit cases fail: 4 of `tests/test_ja4x_empty_ext.py`,
`tests/test_comprehensive.py::TestJA4XComprehensive::test_no_extensions_cert`,
`tests/test_edge_cases.py::TestX509EdgeCases::test_generate_ja4x_empty_lists` and
`tests/test_ja4x_deep.py::TestJA4XNoExtensions::test_no_extensions_hash_is_zero_sentinel`.
**The conformance suite reports no failure under the same reversal**, which measures the
statement that no local vector reaches the case.

### R9 — JA4X reads the certificates of the Certificate handshake message

The image states no packet. This rule rests on the references alone, and this page records
it because R10 of the comparison needs it.

- Corroboration 1: `rust/ja4/src/tls.rs:93` pushes `ja4x::X509Rec::from(x509)` for each
  certificate the handshake carries.
- Corroboration 2: `wireshark/source/packet-ja4.c:1053` and `:1068` both test
  `handshake_type == 11`, which is the Certificate message.

**The references name no direction and no port.** The Wireshark dissector matches both
`tls.handshake.certificate` and `dtls.handshake.certificate`, and it tests neither the
sender nor the port.

### R10 — Nothing sorts a list, and every list holds wire order

The image's three captions state the rule in words: `in order`.

- Corroboration 1: `rust/ja4x/src/lib.rs` joins each attribute iterator with no sort. The
  contrast is `rust/ja4/src/tls.rs`, which sorts the JA4 extension list.
- Corroboration 2: `wireshark/source/packet-ja4.c:1063` and `:1079` append each object
  identifier to the end of the list, in the order the dissector reports the fields.

The deleted `technical_details/JA4X.md` states the rule in prose:
`JA4X doesn’t sort so -o does nothing here.`
`docs/specs/foxio/deleted-text-specifications.md` holds the provenance, and it is a third
corroboration.

### R11 — The two references write a raw form, and the image states none

- Corroboration 1: `rust/ja4x/src/lib.rs` writes
  `let ja4x_r = with_raw.then(|| parts.join("_"));`, which joins the three unhashed lists.
- Corroboration 2: `wireshark/source/packet-ja4.c:1726` registers the field
  `{"JA4X Raw", "ja4.ja4x_r", ...}`, and line 1628 writes it.

**The FoxIO Python implementation writes no raw form for JA4X**, and no expected-output
file under `tests/foxio_vectors/` holds a `JA4X_r` key. Measured on 2026-08-08 with
`grep -l "JA4X_r" tests/foxio_vectors/*.json`, which matched no file.

#### The decision of 2026-08-08, and the form it names

**The user decided that this project publishes the raw form, and the decision is
reversible.** #267 holds the decision comment. `ja4plus` writes `JA4X_r`, which holds the
three unhashed lists joined with `_`. The name follows the `JA4S_r` form this package
already publishes.

**Two of the three FoxIO implementations publish the value.** The decision comment of
#267 states the reading in the user's words:
`Two of the three FoxIO implementations publish it, and FoxIO specifies the value, so
parity rule 1 decides it and the port does not outrank it.` Read "FoxIO specifies the
value" as the two implementations and not as the image. The image states nothing, which
is the heading of this rule.

**The zero sentinel of R8 reaches no raw form.** `rust/ja4x/src/lib.rs` builds
`let parts = [issuer_rdns, subject_rdns, extensions];`, runs `hash12` on the hashed form
alone, and joins the same three parts for `ja4x_r`. An empty list therefore writes an
empty part.

**The comparison runs through the hash, because no snapshot field holds the raw form.**
`TestTheJa4xRawFormTheRustSnapshotImplies` in `tests/test_foxio_rust_parity.py` hashes
each part of each produced raw form and reads the snapshot value. All 43 values agree.

**The gate is proven by its reversal.** Three mutations of `generate_ja4x_raw` each make
the conformance suite fail, measured on 2026-08-08.

| Mutation | Cases the conformance suite fails |
|---|---|
| Join the three parts with `\|` rather than `_` | 46 |
| Join the issuer list with `;` rather than `,` | 44 |
| Sort the extension list | 43 |

## The comparison against this project

The comparison below reads `ja4plus/fingerprinters/ja4x.py` and
`ja4plus/utils/x509_utils.py` at commit `edfc7b2`. **This page names every field. A field
this table does not name is a field nobody read.**

### The fields that agree

| Field | Rule | `ja4x.py` | Reading |
|---|---|---|---|
| Part count and separator | R1 | `ja4x.py:74` | Agrees. The format string is `f"{issuer_hash}_{subject_hash}_{ext_hash}"`. |
| Part a source | R2 | `ja4x.py:367` to `ja4x.py:369` | Agrees. The loop reads `cert.issuer.rdns`. |
| Part b source | R3 | `ja4x.py:372` to `ja4x.py:374` | Agrees. The loop reads `cert.subject.rdns`. |
| Part c source | R4 | `ja4x.py:377` to `ja4x.py:378` | Agrees. The loop reads `cert.extensions`. |
| The hash and the truncation | R5 | `ja4x.py:65` to `ja4x.py:71` | Agrees. Each part is `hashlib.sha256(...).hexdigest()[:12]`. |
| The list separator | R6 | `ja4x.py:59` to `ja4x.py:61` | Agrees. `",".join(...)`. |
| The hex form of an object identifier | R6 | `x509_utils.py:152` to `x509_utils.py:185` | Agrees. `oid_to_hex("2.5.4.3")` returns `550403`. |
| No value in a list | R7 | `ja4x.py:369`, `ja4x.py:374`, `ja4x.py:378` | Agrees. Each line reads `attr.oid` or `ext.oid`, and none reads a value. |
| The zero sentinel | R8 | `ja4x.py:65` to `ja4x.py:71` | Agrees with the FoxIO Rust implementation, the Wireshark dissector and the `README.md`. Disagrees with the image's Qakbot row and with `python/ja4x.py`. The user decided the sentinel on 2026-08-08 under Changelog round 77, so `ja4x.py` needed no change. |
| The packet the reader selects | R9 | `ja4x.py:257` | Agrees. `message_type == TLS_CERTIFICATE_MESSAGE_TYPE` selects handshake type 11. |
| Wire order, and no sort | R10 | `ja4x.py:367` to `ja4x.py:378` | Agrees. Each loop keeps the order the certificate holds, and nothing sorts a list. |
| The direction the reader accepts | R9 | `ja4x.py:108` to `ja4x.py:135` | Agrees. `process_packet` tests no direction and no port, and the references test neither. |
| One value for each certificate | R9 | `ja4x.py:279` to `ja4x.py:289` | Agrees. The loop emits one value for each certificate of the Certificate message, and `rust/ja4/src/tls.rs:93` pushes one record for each certificate too. |
| The raw form | R11 | `generate_ja4x_raw` in `ja4x.py` | Agrees since #267. The function joins the same three unhashed lists with `_` that `rust/ja4x/src/lib.rs` joins. D1 below records the state before #267. |

**Two fields carry no rule, because the image states none.** This table records them so
that the next reader does not mistake them for fields nobody read.

| Field | `ja4x.py` | Reading |
|---|---|---|
| The address layer the stream key reads | `ja4x.py:116`, through `packet_utils.py:60` | The image states no rule. `get_ip_layer` returns the outer address layer, and `ja4l.py:108` reads the inner one through `innermost_layer`. The two methods therefore key a mirrored capture differently. |
| The state bound of the certificate table | `ja4x.py:36`, `ja4x.py:291` to `ja4x.py:302` | The image states no rule. `MAX_PROCESSED_CERTS` is a rule of this project, under the state rules of `CLAUDE.md`. |

### The measurement that proves the order rule

The order rule is the rule an implementation breaks silently, so this page measures it
rather than reading it. The measurement reads the first certificate of
`tests/foxio_vectors/https-connect.pcap` on 2026-08-08.

```
issuer, wire order      : 550406,55040a,55040b,550403
extensions, wire order  : 551d23,551d0e,551d11,551d0f,551d25,551d1f,551d20,2b06010505070101,551d13
extensions, sorted      : 2b06010505070101,551d0e,551d0f,551d11,551d13,551d1f,551d20,551d23,551d25
truncated SHA-256, wire order  : 5e17a2514980
truncated SHA-256, sorted      : fdc32d844f5f
```

`tests/foxio_vectors/rust_expected/ja4__insta@https-connect.pcap.snap` holds
`ja4x: 7d5dbb3783b4_2bab15409345_5e17a2514980`. **The wire-order hash is the reference
value, and the sorted hash is not.** The measurement proves R10 for this project, and it
proves R6 and R5 with it.

### The measurement that proves the whole schema

`ja4plus` reproduces the image's example value from the lists the deleted
`technical_details/JA4X.md` states. Measured on 2026-08-08.

```
generate_ja4x(issuer=550403,550406,550408,55040a
              subject=550403,550406,550408,55040a
              extensions=551d0f,551d25,551d11)
  -> 96a6439c8f5c_96a6439c8f5c_aae71e8db6d7
```

The image draws `JA4X=96a6439c8f5c_96a6439c8f5c_aae71e8db6d7`. The unit test of
`rust/ja4x/src/lib.rs` asserts `assert_eq!(hash12("551d0f,551d25,551d11"), "aae71e8db6d7");`,
which is part c of the same value. **Three independent sources produce the same string.**

### The disagreements

**D1 — Closed on 2026-08-08. `ja4x.py` wrote no raw form, and two FoxIO implementations
write one.**

R11 states the rule. Before #267, `ja4plus` published no `JA4X_r` value, and the FoxIO
Python implementation publishes none either. No expected-output file in this repository
holds the key, so no vector measured D1 and the reading was a code reading.

**#267 built the value, and the disagreement is gone.** `generate_ja4x_raw` in `ja4x.py`
writes `JA4X_r`, and `TestTheJa4xRawFormTheRustSnapshotImplies` compares all 43 values
against the FoxIO Rust snapshots through the hash. "The decision of 2026-08-08, and the
form it names" above holds the whole reading.

**D2 — `cryptography` rejects a certificate that holds a duplicate attribute inside one
RDN, and the FoxIO readers accept it.**

`.venv/lib/python3.14/site-packages/cryptography/x509/name.py:241` raises
`ValueError("duplicate attributes are not allowed")`. `ja4x.py:412` catches the error and
`ja4x.py:414` returns `None`, so the certificate produces no fingerprint. The FoxIO Rust
implementation
reads an attribute iterator with no such test, and the Wireshark dissector appends every
`x509if.oid` field it sees. **No vector in this repository carries such a certificate**, so
no measurement demonstrates D2. The reading is a code reading, and it names a parse
boundary rather than a schema rule.

**No other disagreement exists.** Every field the table above names agrees, and the two
measurements prove the schema against a reference value. R8 is the one rule the image
leaves open, and `ja4plus` follows two of the three FoxIO implementations there. **The
user closed R8 on 2026-08-08 and kept that form**, so the image leaves the rule open and
the project does not.

## The register

`tests/foxio_deviations.json` holds 114 entries as of #193, and **nine of them name this
method.** #193 removed six JA4H entries and no JA4X entry. The count of nine is therefore
the same on the base of this page, where the register holds 120 entries. The table states
each one as explained or unexplained by the specification.

| Key | Issue | Cause the register states, in short | Explained by the image |
|---|---|---|---|
| `chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4X.1` | 129 | The reference decrypts the QUIC handshake, and `ja4plus` reads no encrypted certificate. | **No.** |
| `chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4X.2` | 129 | The same cause. | **No.** |
| `chrome-cloudflare-quic-with-secrets.pcapng/JA4X` | 129 | The same cause, for the capture count. | **No.** |
| `http2-with-cookies.pcapng/0:58847/JA4X.1` | 129 | The reference decrypts the TLS 1.3 handshake, and `ja4plus` reads no encrypted certificate. | **No.** |
| `http2-with-cookies.pcapng/0:58847/JA4X.2` | 129 | The same cause. | **No.** |
| `http2-with-cookies.pcapng/0:58847/JA4X.3` | 129 | The same cause. | **No.** |
| `http2-with-cookies.pcapng/JA4X` | 129 | The same cause, for the capture count. | **No.** |
| `https-connect.pcap/JA4X` | 138 | The FoxIO Python implementation reads no TLS on port 8080, and the FoxIO Rust snapshot holds the value `ja4plus` produces. | **No.** |
| `socks4-https.pcap/JA4X` | 138 | `ja4plus` produces three values on the SOCKS4 tunnel on port 9901, and no FoxIO implementation holds one. | **No.** |

`docs/specs/spec.md` holds one divergence register row for this method, under the name
`JA4X on a stream that a proxy tunnel carries`. **The image explains that row no better
than it explains the nine keys.**

**The image explains none of the nine.** It states the schema of one value, and it states
no rule for any of these three subjects.

- The packet that produces a value.
- A certificate that a capture holds in encrypted form alone.
- The transport that carries the certificate.

"The named question" above holds the full reading of the third subject.

**The deleted text explains the seven #129 entries, and the image does not.** The deleted
`technical_details/JA4X.md` states
`These certificates are encrypted in TLS 1.3 but are sent in clear text in TLS 1.2.`
`docs/specs/foxio/deleted-text-specifications.md` holds the provenance. Nothing at the
pinned commit corrects that sentence, so it stands as FoxIO-authored evidence under the
rule that #221 set. **It names the mechanism the seven entries record**, and it supports the
#129 decision that decryption is out of scope. It changes no fingerprint.

### The measurement that supports the two #138 entries

Measured on 2026-08-08 in this worktree, with `JA4XFingerprinter` over each capture.

| Capture | `ja4plus` values | The reference |
|---|---|---|
| `https-connect.pcap` | `7d5dbb3783b4_2bab15409345_5e17a2514980` and `7d5dbb3783b4_7d5dbb3783b4_9c5875a5c227` | The Rust snapshot holds both values, in that order. |
| `socks4-https.pcap` | `14f85a9f494d_3f8190b6b671_80ea7ef3b044`, `14f85a9f494d_14f85a9f494d_be007da94c85` and `e7bc7ebc3d9e_14f85a9f494d_9c8ed4a87d4b` | No FoxIO implementation holds a value. |

**The `https-connect.pcap` entry stated one thing this repository did not do.** Its cause
reads `tests/test_foxio_rust_parity.py measures the match.` When this page first shipped,
the harness compared two methods and `tests/test_foxio_rust_parity.py:72` read
`SNAPSHOT_METHODS = (("JA4", "ja4"), ("JA4S", "ja4s"))`. A `ja4x` line sits inside the
`tls_certs` block of the snapshot, at a deeper indent, and `read_rust_snapshot` skipped it
by design, so no test compared a JA4X value against a Rust snapshot.

**#229 built the comparison, and the sentence is now true.** "The comparison the harness
now runs" below holds the result.

## The search for a reference value

| Source searched | Result |
|---|---|
| `tests/foxio_vectors/*.json` | **60 `JA4X.<n>` values in 11 files.** The conformance suite already compares every one. |
| `rust/ja4/src/snapshots/` at the pinned commit | Many `ja4x` values, inside the `tls_certs` block of each stream. `tests/foxio_vectors/rust_expected/` holds ten of the snapshots. |
| `README.md` at the pinned commit | Six documented values, at lines 143 to 147. |
| `zeek/` at the pinned commit | **None.** `zeek/ja4x/__load__.zeek` holds the single line `# empty`, and `zeek/config.zeek:24` sets `option JA4X_enabled:   bool = F;`. `docs/specs/foxio/zeek.md:39` records the reading, and #198 owns it. |
| `python/test/testdata/` at the pinned commit | The local copies under `tests/foxio_vectors/` are the same files. |

**One line number of `docs/specs/foxio/zeek.md` is stale, and this page corrects it.**
`docs/specs/foxio/zeek.md:41` names `zeek/config.zeek:29`. The file holds 27 lines at the
pinned commit, and line 24 holds the option. The reading that page records is correct, and
the line number alone is wrong. **The correction changes no reading and no fingerprint.**

**JA4X is not a method that lacks a reference value.** The conformance suite compares 60 of
them, and that is why nine register entries exist. The contrast is JA4T, where
`docs/specs/foxio/JA4T.md` found that no test reads the reference value at all.

## What the deleted text specification adds

**FoxIO published `technical_details/JA4X.md`, 1449 bytes, and `b6f3ff4` deleted it.**
**#221 read it, and `docs/specs/foxio/deleted-text-specifications.md` holds the whole
reading and the provenance.** This page re-reads no blob, and it rewrites no rule above.
The deleted file is not the pinned specification, so the image outranks it.

The deleted text carries three findings for this page.

1. **It contradicts nothing the image draws.** It states the same three parts, the same
   truncation to 12 characters, the same comma-separated hex lists, and the same worked
   value `96a6439c8f5c_96a6439c8f5c_aae71e8db6d7`.
2. **It states the no-sort rule in prose**, which the image states only as the word
   `in order`. R10 records it as a third corroboration.
3. **It names the TLS version that carries a certificate in clear text.** "The register"
   above holds that reading, and it explains the seven #129 entries.

**The deleted text settles nothing about the empty list.** It states no rule for a
certificate that carries no extension, so it corroborates neither form of R8.

## The comparison the harness now runs

**#229 built it.** `read_rust_snapshot` enters the `tls_certs` block, and
`TestTheJa4xValuesTheRustSnapshotHolds` compares every JA4X value the local snapshots
hold. #229 changed no fingerprinter.

| Measurement | Count |
|---|---|
| Local Rust snapshots | 10 |
| Snapshots that hold a JA4X value | 5 |
| Streams that hold at least one | 19 |
| JA4X values in those streams | 43 |
| Values `ja4plus` reproduces exactly, in snapshot order | 43 |
| Values that differ | 0 |
| Streams whose value count differs | 0 |

The five snapshots that hold a value are `browsers-x509.pcapng` with 7,
`https-connect.pcap` with 2, `latest.pcapng` with 8, `ssh2.pcapng` with 12 and
`tls-handshake.pcapng` with 14.

**The revert proves the cases run.** Remove the `tls_certs` branch of the reader, and 48
cases stop running: 43 value cases and 5 count cases. Three checks then fail and name the
loss.

```
FAILED TestTheJa4xValuesTheRustSnapshotHolds::test_the_local_snapshots_hold_the_forty_three_values_the_reading_counts
FAILED TestTheJa4xValuesTheRustSnapshotHolds::test_the_suite_collects_one_case_for_every_value_the_snapshots_hold
FAILED TestTheJa4xValuesTheRustSnapshotHolds::test_the_https_connect_stream_is_the_one_stream_the_python_file_omits
```

**The register gains no entry.** Every value agrees, so the register holds 116 keys
before and 116 after, against 116 `xfailed` cases.

**One stream carries a register key of this module.** `tests/test_spec_validation.py`
builds the key form `<capture>/<stream>:<port>/JA4X.<n>` from the FoxIO Python file, and
that file holds a JA4X value for 18 of the 19 streams. `certificate_key` keys the one
stream that file omits, which is `https-connect.pcap` stream 0 on port 54723. A check
keeps the two key sets apart, because one entry that matches a case of each module marks
both and neither fix reports itself.

**D2 stays unmeasured, and it is no mismatch.** D2 is a certificate with a duplicate
attribute, which no capture in this repository carries. **No local vector reaches R8**
either: a certificate with no extension would settle which empty form this project must
write, and this repository holds none.

**#267 measured D1.** No snapshot field holds the raw form, so the comparison hashes each
part of the produced value and reads the snapshot value.
`TestTheJa4xRawFormTheRustSnapshotImplies` holds it, and the counts below record the
result.

| Measurement | Count |
|---|---|
| Raw forms the five local snapshots imply | 43 |
| Values `ja4plus` reproduces exactly, in snapshot order | 43 |
| Values that differ | 0 |
| Streams whose value count differs | 0 |

**The register gains no entry.** Every value agrees.

**The `ja4ssh` values of the snapshots stay unread.**
`tests/foxio_vectors/rust_expected/ja4__insta@ssh2.pcapng.snap:215` holds a `ja4ssh:`
block with two values, and no other local snapshot holds the field. #199 reports the gap
and it owns the reading. #229 changes nothing there.

## The rulings this page raises

**No fingerprint moves.** #267 adds the `JA4X_r` value, and it changes no JA4X value. The
conformance suite reports 1477 passed, 143 skipped and 137 xfailed before #267, and 1529
passed, 143 skipped and 137 xfailed after it. The 52 new cases are the raw-form
comparison.

1. **R8. Decided on 2026-08-08, and the ruling is reversible.** An empty list writes
   `000000000000`. The FoxIO Rust implementation, the Wireshark dissector and the
   `README.md` write it. The project already uses the same sentinel where JA4H signals a
   request that carries no cookie. The FoxIO Python implementation and the
   image's Qakbot row write `e3b0c44298fc`, which the ruling rejects. **No local vector
   reaches the case, so no fingerprint moved.** "The ruling of 2026-08-08, and the
   contradiction it records" above holds the whole reading. #228 built it under Changelog
   round 77.
2. **D1. Decided on 2026-08-08, and the ruling is reversible.** This project publishes
   a `JA4X_r` raw form, which holds the three unhashed lists joined with `_`. Two FoxIO
   implementations write it, the FoxIO Python implementation writes none, and the image
   states nothing. **#267 holds the ruling and built the value**, under Changelog round
   TBD. #228 raised it and ruled nothing on it.

**The named question needs no ruling.** The image states nothing about the transport, so
the specification confirms the user's ruling of 2026-08-07 rather than reopening it.
