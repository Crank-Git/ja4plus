# JA4

This page is this project's own prose form of `technical_details/JA4.png` **and** of
`technical_details/JA4.md`. It follows the procedure in `docs/specs/foxio/README.md`. No
image enters this repository.

**JA4 is the one method of the twelve that carries a complete text specification beside
its image.** Every other page of this directory transcribes an image alone. This page
therefore reads two files, and it states which one carries each rule.

| Item | Value |
|---|---|
| Source of the image | `https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.png` |
| Source of the text | `https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md` |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-15 |
| SHA-256 of the image | `1bd63c14b3b96c2b70bfa8e85632450c9396af9a13e274489c0cb02f2a7e9615` |
| SHA-256 of the text | `14a9623ad05d6f8b5ccbff2023dc6fce10ff012dc2d202b497e3bc029aa75c94` |
| Blob SHA-1 of the text | `fda5c8aaa517adbb56c950df743884cbc97d7777` |
| Byte count of the text | 9153 |
| Line count of the text | 220 |

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md (retrieved 2026-08-15, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)
Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.png (retrieved 2026-08-15, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

**The two hashes reproduce the inventory of `docs/specs/foxio/README.md` exactly.** That
inventory records 9153 bytes for the text file and 61637 bytes for the image. A read of
2026-08-15 returned the same two counts and the same two hashes.

Reproduce each hash from a checkout at the pinned commit.

```bash
shasum -a 256 technical_details/JA4.md technical_details/JA4.png
```

## JA4 holds the one live text specification, and no other method holds one

**#691 asked whether a live text specification reaches any method beside JA4, and the
answer is one partial file.** A read of the provider on 2026-08-15 listed
`technical_details/` at the pinned commit. The directory holds twelve files. Nine are
images and three are text.

| Text file | Bytes | What it holds |
|---|---|---|
| `README.md` | 1567 | The table of twelve methods, the nine image links and the license note |
| `JA4.md` | 9153 | The whole JA4 algorithm |
| `JA4H.md` | 278 | One sentence of purpose and one rule, the header count |

**`JA4H.md` builds no fingerprint, so `docs/specs/foxio/README.md` treats JA4H as an image
method.** `docs/specs/foxio/JA4H.md` already transcribes it, under #203. **No third method
holds a live text file**, so this reading files no further issue. That is the clean
negative #691 asked for.

```bash
curl -s "https://api.github.com/repos/FoxIO-LLC/ja4/contents/technical_details?ref=27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8"
```

**FoxIO published a text specification for seven methods, and commit `b6f3ff4` deleted all
seven.** `docs/specs/foxio/deleted-text-specifications.md` holds that whole reading, under
#221. `JA4.md` came back as the same blob five days later, so its deletion corrected
nothing. **That page transcribes no image and it renames into no transcription page.**

**Warning: the text file of this page is not a deleted file.** It stands at the pinned
commit, so it is rank 1 material and the ranking rules of
`docs/specs/foxio/README.md` for a deleted file reach it nowhere.

## The field layout

The image titles itself `JA4: TLS Client Fingerprint`. It draws one example string and
labels three parts.

```
JA4=t13d1516h2_acb858a92679_e5627efa2ab1
    \_______/ \__________/ \__________/
      JA4_a       JA4_b        JA4_c
```

The image captions eight fields. Six of the eight sit inside `JA4_a`, and the image draws a
separate leader line to each one. Two bullets below the string caption `JA4_b` and `JA4_c`.

| Field | The image's caption | Value in the example |
|---|---|---|
| `JA4_a`, character 1 | Protocol, TCP = "t"  QUIC = "q" | `t` |
| `JA4_a`, characters 2 and 3 | TLS version, 1.2 = "12", 1.3 = "13" | `13` |
| `JA4_a`, character 4 | SNI, SNI = "d" (to domain), no SNI = "i" (to IP) | `d` |
| `JA4_a`, characters 5 and 6 | Number of Cipher Suites | `15` |
| `JA4_a`, characters 7 and 8 | Number of Extensions | `16` |
| `JA4_a`, characters 9 and 10 | First ALPN value (00 if no ALPN) | `h2` |
| `JA4_b` | Truncated SHA256 hash of the Cipher Suites, sorted | `acb858a92679` |
| `JA4_c` | Truncated SHA256 hash of the Extensions, sorted + Signature Algorithms, in the order they appear | `e5627efa2ab1` |

The three parts join with `_`. The six fields of `JA4_a` carry no separator.

**The image names two protocol characters and the text names three.** The text is the
wider statement, and R3 below holds it.

## The image draws a value that its own caption does not describe

**Warning: read the example of the text file, and never the string the image draws.**

The image captions `JA4_b` as the sorted cipher hash, and it draws `acb858a92679` in that
position. **`acb858a92679` is the hash of the unsorted cipher list.** The text file names
that same value as the `JA4_b` of the original-order form at `technical_details/JA4.md:219`,
which reads `JA4_o = t13d1516h2_acb858a92679_18f69afefd3d`.

A read of 2026-08-15 reproduced every hash of the example. Each one comes from the two
cipher lists the text file prints at `technical_details/JA4.md:112` and
`technical_details/JA4.md:118`.

| Input | First 12 characters of the SHA-256 |
|---|---|
| The cipher list, sorted | `8daaf6152771` |
| The cipher list, in wire order | `acb858a92679` |
| The extension list, sorted, then the signature algorithms | `e5627efa2ab1` |
| The extension list, in wire order, then the signature algorithms | `18f69afefd3d` |

**The image therefore pairs the part b of the original-order form with the part c of the
sorted form.** No tool writes that pair. A read of 2026-08-15 found
`t13d1516h2_acb858a92679_e5627efa2ab1` in no file of `tests/` and in no file of `docs/`.

**This page reports the finding and it rules on nothing.** The text file states the whole
algorithm, and `technical_details/JA4.md:194` draws the value the sorted rule produces.
`tests/test_foxio_ja4_transcription.py` holds this reading.

### The text file states two example values, and they disagree

`technical_details/JA4.md:36` closes the algorithm section with
`t13d1516h2_8daaf6152771_b186095e22b6`. `technical_details/JA4.md:194` closes the example
section with `t13d1516h2_8daaf6152771_e5627efa2ab1`. **The two share part a and part b, and
they differ in part c.**

**`e5627efa2ab1` is the value the stated rule produces**, and the text file prints the
whole input at `technical_details/JA4.md:154` and the whole hash at
`technical_details/JA4.md:160`. A read of 2026-08-15 reproduced that hash from that input.
**`b186095e22b6` matches no input this page reproduced**, and it appears in no file of this
repository. Read the second value and never the first.

## The worked example of the text file reproduces in this project

**The example names a client hello that this repository holds.**
`tests/foxio_vectors/tls-sni.pcapng.json:35` holds `"JA4_o.1": "t13d1516h2_acb858a92679_18f69afefd3d"`,
which is the value `technical_details/JA4.md:219` states. `ja4plus` reads the same capture
and produces all four forms byte for byte.

Measured on 2026-08-15 against `tests/foxio_vectors/tls-sni.pcapng`.

```
JA4   : t13d1516h2_8daaf6152771_e5627efa2ab1
JA4_o : t13d1516h2_acb858a92679_18f69afefd3d
JA4_r : t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601
JA4_ro: t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015_0403,0804,0401,0503,0805,0501,0806,0601
```

**Each of the four equals the value the text file states**, at
`technical_details/JA4.md:194`, `:219`, `:205` and `:213`.

**Warning: another client hello of the same capture reproduces the sorted forms and not the
original-order forms.** A client that randomizes its extension order holds the same sorted
set on every connection, and it holds a different wire order on each one. That client
therefore writes one `JA4` value and many `JA4_o` values. **The example needs the one
stream whose wire order matches**, and that property is the reason JA4 sorts.

## Which FoxIO implementations write a JA4 value

**Three of the four references write JA4, and the Wireshark dissector writes none.** A read
of `wireshark/source/packet-ja4.c` at the pinned commit lists fifteen header fields, at
`wireshark/source/packet-ja4.c:1723-1741`. The fields name JA4S, JA4X, JA4H, JA4L, JA4LS,
JA4SSH, JA4T, JA4TS and JA4D. **No field reads `ja4.ja4`**, and the dissector builds a
client string nowhere.

**That absence changes which sources corroborate a JA4 rule.** The two-corroboration rule
of `docs/specs/foxio/README.md` reads FoxIO-authored sources, and the dissector holds no
JA4 statement to read. Each rule below therefore names the FoxIO Python implementation, the
FoxIO Rust implementation and the FoxIO Zeek package.

**A shared field of the dissector is not a JA4 statement.** `wireshark/source/packet-ja4.c:729`
and `wireshark/source/packet-ja4.c:732` write the protocol character into a record that
`ja4s()` alone reads. R3 records that reading, and no rule of this page rests on it.

## The rules

Each rule below carries two corroborations. Neither corroboration is the image, and the
text specification carries the statement each one confirms.

### R1 — JA4 holds three parts, joined with `_`

The fingerprint is `<JA4_a>_<JA4_b>_<JA4_c>`. `technical_details/JA4.md:30-33` states the
two separators and `technical_details/JA4.md:36` draws the result.

- Corroboration 1: `python/ja4.py:290` writes
  `f"{ptype}{version}{sni}{cipher_len}{ext_len}{alpn}_{sorted_ciphers}_{sorted_extensions}"`.
- Corroboration 2: `rust/ja4/src/tls.rs:364` returns
  `format!("{first_chunk}_{ciphers}_{exts_sigs}")`.

`zeek/ja4/main.zeek:155-159` appends the same three parts, with `FINGERPRINT::delimiter`
between them.

### R2 — Part a holds six fields and no separator

Part a is ten characters: one protocol character, two version characters, one SNI
character, two cipher-count characters, two extension-count characters and two ALPN
characters. `technical_details/JA4.md:24-29` lists the six in that order.

- Corroboration 1: `python/ja4.py:290`, the first six terms of the format string.
- Corroboration 2: `rust/ja4/src/tls.rs:331-332` holds the format string
  `"{quic}{tls_ver}{sni_marker}{nr_ciphers:02}{nr_exts:02}{alpn_0}{alpn_1}"`.

`zeek/ja4/main.zeek:109-116` appends `proto`, `version`, `sni`, `cs_count`, `ec_count` and
`alpn` in that order, and it inserts nothing between them.

### R3 — The protocol character is `t`, `q` or `d`

`technical_details/JA4.md:24` reads `(QUIC=”q”, DTLS="d", or TLS over TCP=”t”)`, and
`technical_details/JA4.md:54` states the same three values in a sentence.

- Corroboration 1: `python/ja4.py:220` holds `ptype = 'q' if x['quic'] else 't'`.
- Corroboration 2: `zeek/ja4/main.zeek:67` sets `proto` to `"q"` and
  `zeek/ja4/main.zeek:71` sets it to `"t"`.

**This rule is uncertain for DTLS. Keep the vector fallback.** The text specification names
three values and every implementation that writes JA4 names two.
`rust/ja4/src/tls.rs:481-485` returns `q` or `t` alone. The dissector holds the `d` value at
`wireshark/source/packet-ja4.c:732`, and it writes no JA4 value at all. That line therefore
corroborates the character and never the method.

**No vector measures the rule.** The FoxIO Python expected-output files of
`tests/foxio_vectors/` hold 167 JA4 values and all 167 open with `t`. The Rust snapshots of
`tests/foxio_vectors/rust_expected/` hold 191 JA4 values, 140 open with `t`, 51 open with
`q` and 0 open with `d`. Both counts come from a read of 2026-08-15.

### R4 — The two version characters name the version of the client hello

`13` is TLS 1.3 and `12` is TLS 1.2. `technical_details/JA4.md:60-68` holds nine rows and
`technical_details/JA4.md:70` states the `00` fallback. The image draws two of the nine
rows, and both agree.

- Corroboration 1: `python/common.py:16-21` holds `TLS_MAPPER`, and `python/ja4.py:267`
  reads `TLS_MAPPER[x['version']] if x['version'] in TLS_MAPPER else '00'`.
- Corroboration 2: `rust/ja4/src/tls.rs:512-524` maps each string, and
  `rust/ja4/src/tls.rs:526-539` prints the two characters of each one.

`zeek/ja4/main.zeek:104-106` reads `FINGERPRINT::TLS_VERSION_MAPPER` and it keeps `"00"`
where the table holds no row.

**`0x0002` is SSL 2.0 and `0x0200` is not.** `technical_details/JA4.md:65` states the
corrected value, FoxIO commit `3e02a27` made the correction, and #227 repaired this project
on 2026-08-08.

### R5 — The supported_versions extension decides the version

A client hello that carries extension `0x002b` names its version there. The reader takes the
highest value that is not GREASE. `technical_details/JA4.md:58` states the rule, and it
states that the handshake version at the top of the packet is ignored.

- Corroboration 1: `python/common.py:154-156` drops the GREASE values, sorts the rest and
  returns the last.
- Corroboration 2: `rust/ja4/src/tls.rs:559-561` reads
  `tls.handshake.extensions.supported_version`, filters the GREASE values and sorts them.

### R6 — The SNI character is `d` for a domain and `i` for an address

`technical_details/JA4.md:74` states that extension `0x0000` makes the character `d`, and
that its absence makes the character `i`.

- Corroboration 1: `python/ja4.py:263` holds `sni = 'd' if 'domain' in x else 'i'`.
- Corroboration 2: `rust/ja4/src/tls.rs:319-320` returns `'d'` where the extension list
  holds `TLS_EXT_SERVER_NAME`.

`zeek/ja4/main.zeek:75` opens with `"i"` and `zeek/ja4/main.zeek:81` writes `"d"`.

### R7 — The cipher count is two decimal digits, it drops GREASE and it stops at 99

`technical_details/JA4.md:78` states all three parts. It also states that the count keeps a
value that is not a cipher, and it names SCSV and the reserved range.

- Corroboration 1: `python/common.py:140-141` drops the GREASE values and holds
  `actual_length = min(len(c), 99)`, and `python/common.py:149` prints `'{:02d}'`.
- Corroboration 2: `rust/ja4/src/tls.rs:325` holds `let nr_ciphers = 99.min(ciphers.len());`,
  and `rust/ja4/src/tls.rs:192` filters the GREASE values out of that list.

`zeek/ja4/main.zeek:89-94` writes `99` above 99 and `fmt("%02d", ...)` otherwise.

### R8 — The extension count follows the same rule, and it counts SNI and ALPN

`technical_details/JA4.md:82` reads `Same as counting ciphers. Ignore GREASE. Include SNI
and ALPN.`

- Corroboration 1: `python/ja4.py:229` holds
  `'{:02d}'.format(min(len([ x for x in x['extensions'] if x not in GREASE_TABLE]), 99))`.
- Corroboration 2: `rust/ja4/src/tls.rs:326` holds `let nr_exts = 99.min(exts.len());`, and
  `rust/ja4/src/tls.rs:328` removes SNI and ALPN after that count.

**The order of those two lines carries the rule.** A reader who removes the two extensions
first would report a count two lower on every hello that carries both.

### R9 — The ALPN field is the first and the last character of the first ALPN value

`technical_details/JA4.md:86` states the rule and `technical_details/JA4.md:93` states three
cases: no extension, no value and an empty first value each write `00`. A one-character
value repeats that character.

- Corroboration 1: `python/ja4.py:269` opens `alpn` at `'00'`, and `python/ja4.py:276-277`
  keeps the first character and the last character.
- Corroboration 2: `rust/ja4/src/tls.rs:333-334` writes `'0'` for each character the value
  does not hold.

`zeek/ja4/main.zeek:84` opens at `"00"` and `zeek/ja4/main.zeek:86` writes the first and the
last character.

**This rule is uncertain for a byte that is not ASCII alphanumeric. Keep the vector
fallback.** `technical_details/JA4.md:95-104` states a hex fallback and gives eight worked
cases. **No FoxIO implementation writes that fallback.** `python/ja4.py:279-280` writes
`'99'` where the first byte is above 127, and `rust/ja4/src/tls.rs:615-624` replaces each
non-ASCII character with `'9'`. #127 and #141 measured the split, and
`tests/foxio_vectors/tls-non-ascii-alpn.pcapng` holds `99`. **This project follows the
vector and not the prose.**

### R10 — Part b is the SHA-256 of the sorted cipher list, truncated to 12 characters

The hashed text holds the cipher values as four lowercase hex digits, joined with `,`,
sorted in hex order. `technical_details/JA4.md:108` states the rule and
`technical_details/JA4.md:42` states that every hash is lower case.

- Corroboration 1: `python/common.py:127` returns
  `sha256(','.join(values).encode('utf8')).hexdigest()[:12]`, and `python/ja4.py:255` calls
  it through `get_hex_sorted`.
- Corroboration 2: `rust/ja4/src/tls.rs:338` sorts the list, `rust/ja4/src/tls.rs:341` joins
  it, and `rust/ja4/src/lib.rs:187-188` returns the first 12 characters of the digest.

### R11 — Part c hashes the sorted extension list, then the signature algorithms

The extension list drops SNI (`0000`) and ALPN (`0010`), because part a already carries
both. `technical_details/JA4.md:128` states the removal and its reason. The signature
algorithms follow an `_`, in the order the client hello holds them, and
`technical_details/JA4.md:126` states that nothing sorts them.

- Corroboration 1: `python/common.py:144-145` removes `'0000'` and `'0010'` from the sorted
  list, and `python/ja4.py:245` appends the signature algorithms after an underscore.
- Corroboration 2: `rust/ja4/src/tls.rs:328` removes the two extensions,
  `rust/ja4/src/tls.rs:339` sorts the rest, and `rust/ja4/src/tls.rs:352` builds
  `format!("{exts}{opt_underscore}{sigs}")`.

`zeek/ja4/main.zeek:138-142` skips the same two extension codes, and
`zeek/ja4/main.zeek:147-151` appends the signature algorithms in wire order.

### R12 — A client hello that carries no signature algorithm ends without an underscore

`technical_details/JA4.md:169` states the rule and `technical_details/JA4.md:173` gives the
worked value `6d807ffa2a79`.

- Corroboration 1: `rust/ja4/src/tls.rs:347` holds
  `let opt_underscore = if sigs.is_empty() { "" } else { "_" };`.
- Corroboration 2: `python/ja4.py:241-246` appends the underscore and the list in one branch,
  and it appends nothing in the other.

`zeek/ja4/main.zeek:149-151` appends the delimiter inside the test alone.

### R13 — An empty cipher list and an empty extension list each write `000000000000`

`technical_details/JA4.md:121` states the rule for `JA4_b` and `technical_details/JA4.md:176`
states it for `JA4_c`. `technical_details/JA4.md:122` and `technical_details/JA4.md:177` each
state the reason, which reads
`We do this rather than running a sha256 hash of nothing as this makes it clear to the user when a field has no values.`

- Corroboration 1: `python/ja4.py:258-259` writes the sentinel for an empty cipher list, and
  `python/ja4.py:251-252` writes it for an empty extension string.
- Corroboration 2: `rust/ja4/src/lib.rs:184-185` returns the same twelve zeros for an empty
  input, and `rust/ja4/src/tls.rs:362-363` reaches that function for both parts.

**Four vectors measure the rule.** 4 of the 167 JA4 values of the FoxIO Python
expected-output files read `t10d230100_6a57a6f57151_000000000000`, and 0 of the 167 hold the
sentinel in part b. `https3-301-get.pcap.json` holds one and `socks-https-example.pcap.json`
holds three. A read of 2026-08-15 reproduced both counts.

**This rule is the one the divergence register of `docs/specs/spec.md` records under #653.**
JA4 and JA4S write the sentinel, and JA4X and JA4H hash an empty list.
`tests/test_empty_list_sentinel_ruling.py` holds that row against the code.

### R14 — The program drops GREASE wherever it reads a list

`technical_details/JA4.md:40` states the rule once, for the whole method, and it cites the
GREASE draft.

- Corroboration 1: `python/common.py:23-26` holds `GREASE_TABLE`, and `python/ja4.py:229`
  and `python/common.py:140` each read it.
- Corroboration 2: `rust/ja4/src/tls.rs:572-579` holds the two tables, and
  `rust/ja4/src/tls.rs:192`, `rust/ja4/src/tls.rs:560` and `rust/ja4/src/tls.rs:590` each
  filter with one of them.

### R15 — JA4 publishes four forms, and `-o` renames the field

`technical_details/JA4.md:199-200` states that the program allows a raw output, sorted or
original, under `-r` and `-o`. `technical_details/JA4.md:216` states that `-o` renames the
`ja4` field to `ja4_o`.

- Corroboration 1: `python/ja4.py:290-293` writes `JA4`, `JA4_o`, `JA4_r` and `JA4_ro` as
  four keys.
- Corroboration 2: `zeek/ja4/main.zeek:162-167`, `zeek/ja4/main.zeek:177-181` and
  `zeek/ja4/main.zeek:184-188` build the three raw forms beside the hashed one.

**The FoxIO Rust implementation publishes two keys and not four.**
`rust/ja4/src/tls.rs:231-238` switches one `ja4_r` value between the sorted form and the
unsorted form, under the `--original-order` flag. **The four-key shape therefore rests on the
text specification, the Python implementation and the Zeek package.**

### R16 — JA4 reads the TLS client hello, and it covers QUIC and DTLS

`technical_details/JA4.md:5` states that JA4 looks at the TLS Client Hello packet.
`technical_details/JA4.md:49` states that QUIC encapsulates TLS 1.3 into UDP packets, and
`technical_details/JA4.md:52` states that DTLS operates over UDP or SCTP.

- Corroboration 1: `technical_details/README.md:5` reads
  `| JA4 | JA4 | TLS Client Fingerprinting |`.
- Corroboration 2: `rust/ja4/src/tls.rs:481-485` marks the QUIC case on the client path.

## The comparison against this project

The comparison below reads `ja4plus/fingerprinters/ja4.py` and
`ja4plus/utils/tls_utils.py` at commit `47ad216`. **Every field is named. A field this
table does not name is a field nobody read.**

### The fields that agree

| Field | Rule | `ja4.py` | Reading |
|---|---|---|---|
| Part count and separators | R1 | `ja4plus/fingerprinters/ja4.py:232` | Agrees. The format string is `f"{part_a}_{cipher_hash}_{ext_hash}"`. |
| Part a composition | R2 | `ja4plus/fingerprinters/ja4.py:194` | Agrees. The six terms carry no separator. |
| Protocol character `t` and `q` | R3 | `ja4plus/fingerprinters/ja4.py:128` | Agrees. |
| Protocol character `d` | R3 | `ja4plus/fingerprinters/ja4.py:128` | Agrees with the text specification. No implementation of FoxIO writes it, and no vector measures it. |
| Version characters | R4 | `ja4plus/fingerprinters/ja4.py:142-164` | Agrees for `13`, `12`, `11`, `10`, `s3`, `s2`, `d1`, `d2`, `d3` and the `00` fallback. |
| Version from supported_versions | R5 | `ja4plus/fingerprinters/ja4.py:135`, `ja4plus/fingerprinters/ja4.py:139` | Agrees. The reader drops the GREASE values and takes the highest of the rest. |
| SNI character | R6 | `ja4plus/fingerprinters/ja4.py:168` | Agrees. `sni_type = "d" if sni else "i"`. |
| Cipher count digits | R7 | `ja4plus/fingerprinters/ja4.py:171-173` | Agrees. The reader drops GREASE, stops at 99 and prints two digits. |
| Extension count digits | R8 | `ja4plus/fingerprinters/ja4.py:176-178` | Agrees, and it counts SNI and ALPN, because the removal comes later. |
| ALPN, the absent case | R9 | `ja4plus/fingerprinters/ja4.py:76-77` | Agrees. `compute_alpn_value` returns `00`. |
| Cipher hash | R10 | `ja4plus/fingerprinters/ja4.py:198-200` | Agrees. The sorted list joins with `,` and the digest truncates to 12. |
| Extension hash, the removal | R11 | `ja4plus/fingerprinters/ja4.py:208` | Agrees. The sorted list drops `0x0000` and `0x0010`. |
| Extension hash, the signature algorithms | R11 | `ja4plus/fingerprinters/ja4.py:215-220` | Agrees. The list keeps wire order and follows one underscore. |
| The absent underscore | R12 | `ja4plus/fingerprinters/ja4.py:217` | Agrees. The test appends the underscore and the list together. |
| The empty-list sentinel | R13 | `ja4plus/fingerprinters/ja4.py:202`, `ja4plus/fingerprinters/ja4.py:229` | Agrees. Both write `000000000000`. |
| GREASE | R14 | `ja4plus/utils/tls_utils.py:444` | Agrees. The test reads the same two conditions the dissector macro reads. |
| The four forms | R15 | `ja4plus/fingerprinters/ja4.py:344-347`, `ja4plus/fingerprinters/ja4.py:399` | Agrees. One entry carries `JA4`, `JA4_o`, `JA4_r` and `JA4_ro`. |
| Packet selection | R16 | `ja4plus/fingerprinters/ja4.py:123` | Agrees. The reader requires `type` to read `client_hello`. |

### The disagreements

**D1 — `ja4plus/fingerprinters/ja4.py:109` writes `99` for a byte the text specification
prints as hex.**

`technical_details/JA4.md:95-104` states the hex fallback and gives eight worked cases.
**No FoxIO implementation builds it.** `python/ja4.py:279-280` writes `'99'` and
`rust/ja4/src/tls.rs:620` writes `'9'` for each non-ASCII character. #127 read the vector
`tls-non-ascii-alpn.pcapng`, which holds `99`, and this project follows the vector.

**The prose and every implementation disagree, so the authority rule sends this to the
vectors.** `.claude/rules/conformance.md` states that the vectors decide the exact bytes
where intent runs out.

**D2 — `ja4plus/fingerprinters/ja4.py:99-100` passes a printable ASCII byte through, and the
text specification tests for an alphanumeric byte.**

`technical_details/JA4.md:95` bars every byte outside `0x30-0x39`, `0x41-0x5A` and
`0x61-0x7A`. Both FoxIO implementations pass a printable byte through, so `h\x20` reads
`h ` rather than `99`. #141 measured that on `tests/foxio_vectors/alpn-condition.pcap`.
**The range stops at `0x7E`**, because the two implementations agree only inside it.

**D3 — `ja4plus/fingerprinters/ja4.py:226` reads the sorted extension string for the
sentinel of both forms.**

A client hello that carries SNI alone therefore gives `JA4_o` the sentinel, while its
`JA4_ro` still prints `0000`. #132 measured the shape and the FoxIO Python implementation
holds it too, at `python/ja4.py:248-253`. **This is an agreement with the reference and a
divergence from a reading of the prose alone.**

## What the register holds

`tests/foxio_deviations.json` holds 138 entries on the base of this page. **39 of them name
the JA4 family**, over the keys `JA4`, `JA4_o`, `JA4_r` and `JA4_ro`. Every one carries
`"decided": true` and `"capability": false`. **This page changes no entry.**

| Cause | Entries | What the entries record |
|---|---|---|
| #138 | 23 | A stream the FoxIO Python expected-output file omits, and `ja4plus` fingerprints |
| #162 | 16 | Four streams of `alpn-condition.pcap`, where the ALPN byte rule splits |

**The specification explains the 23 entries of #138 nowhere.** It states the schema of one
value, and it states no rule about which stream a reader reaches.

**The specification does reach the 16 entries of #162, and it does not settle them.**
`technical_details/JA4.md:95-104` states the hex fallback that D1 records, and no FoxIO
implementation writes it. A rule that every implementation contradicts settles no vector.

## The rulings this page raises

Each item needs the user, because each one changes a fingerprint that this project
publishes, or it records a rule that no vector measures. **This page changes no
fingerprinter.**

1. **D1 and D2.** Does JA4 print the hex form of a byte that is not ASCII alphanumeric?
   The text specification says yes and every FoxIO implementation says no. `ja4plus` writes
   `99`, which the vector holds.
2. **R3.** Does a DTLS client hello write `d`? The text specification says yes and every
   implementation that writes JA4 says no. `ja4plus` writes it and no vector measures it.
3. **The image draws `t13d1516h2_acb858a92679_e5627efa2ab1`**, and no tool writes that
   string. This page records the finding, and the text specification settles the algorithm.
4. **`technical_details/JA4.md:36` states `b186095e22b6` for part c**, and
   `technical_details/JA4.md:194` states `e5627efa2ab1` for the same client hello. This page
   reads the second one.

## One record this page falsifies

**The divergence register of `docs/specs/spec.md` states that
`docs/specs/foxio/` holds no `JA4.md` transcription.** #653 wrote that sentence on
2026-08-15, and it was true then. **This page makes it false.** Batch #704 owns the
divergence register, so this round edits no row of it, and #691 records the constraint on
that batch instead.

**The Changelog row of round 248 states the same sentence, and it stays as written.** A
Changelog row records a past measurement, and this project rewrites no such record.
