# JA4S

This page is this project's own prose form of `technical_details/JA4S.png`. It follows the
procedure in `docs/specs/foxio/README.md`. No image enters this repository.

| Item | Value |
|---|---|
| Source | `https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.png` |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-08 |
| SHA-256 of the image | `a4d303c3c51c2862d86abd69d6dfe6d28a43e86556a91d2c1c8261fa4de15458` |

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.png (retrieved 2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

Reproduce the hash from a checkout at the pinned commit.

```bash
shasum -a 256 technical_details/JA4S.png
```

## JA4S is the method with the most reference values

JA4T and JA4TS reach few reference values, so #196 reasoned from source code. JA4S reaches
329 published values across three FoxIO implementations, and the Zeek baseline adds 20
more. This repository already holds 194 of them. **This page therefore measures where the earlier pages reasoned.** "The search
for a reference value" holds the counts.

## The field layout

The image titles itself `JA4S: TLS Server Response Fingerprint`. It draws one example
string and labels three parts.

```
JA4S=t120400_c030_4e8089b08790
     \_____/ \__/ \__________/
      JA4S_a JA4S_b   JA4S_c
```

The image captions five fields. Four of the five sit inside `JA4S_a`, and the image draws a
separate leader line to each one.

| Field | The image's caption | Value in the example |
|---|---|---|
| `JA4S_a`, character 1 | Protocol, TCP = "t"  QUIC = "q" | `t` |
| `JA4S_a`, characters 2 and 3 | TLS version, 1.2 = "12", 1.3 = "13" | `12` |
| `JA4S_a`, characters 4 and 5 | Number of Extensions | `04` |
| `JA4S_a`, characters 6 and 7 | ALPN Chosen (00 if no ALPN) | `00` |
| `JA4S_b` | Cipher Suite Chosen | `c030` |
| `JA4S_c` | Truncated SHA256 hash of the Extensions, in the order they appear | `4e8089b08790` |

The three parts join with `_`. The four fields of `JA4S_a` carry no separator.

## The worked example of the image reproduces in this project

**The image's example names a capture this repository holds.**
`rust/ja4/src/snapshots/ja4__insta@tls-handshake.pcapng.snap:484` holds
`ja4s: t120400_c030_4e8089b08790`, and `wireshark/test/testdata/tls-handshake.pcapng.json:1197`
holds the same value. `tests/foxio_vectors/tls-handshake.pcapng` is that capture.

Measured on 2026-08-08 against the base commit.

```
The image's example : JA4S=t120400_c030_4e8089b08790
ja4plus JA4S        : t120400_c030_4e8089b08790
ja4plus JA4S_r      : t120400_c030_0005,0017,ff01,0000
```

The deleted `technical_details/JA4S.md` states the raw form
`JA4S_r = t120400_c030_0005,0017,ff01,0000`, which
`docs/specs/foxio/deleted-text-specifications.md` records. **This project reproduces both
the hashed form the image draws and the raw form the deleted text states, byte for byte.**

## The rules

Each rule below carries two corroborations. Neither corroboration is the image.

### R1 — JA4S holds three parts, joined with `_`

The fingerprint is `<JA4S_a>_<JA4S_b>_<JA4S_c>`.

- Corroboration 1: `rust/ja4/src/tls.rs:455` builds `two_chunks` as
  `"{quic}{tls_ver}{nr_exts:02}{alpn_0}{alpn_1}_{cipher}"`, and `tls.rs:466` appends
  `"_{hash}"`.
- Corroboration 2: `python/ja4.py:209` writes
  `f"{ptype}{version}{ext_len}{alpn}_{x['ciphers']}_{extensions}"`.

### R2 — Part a holds four fields and no separator

Part a is seven characters: one protocol character, two version characters, two count
characters and two ALPN characters.

- Corroboration 1: `python/ja4.py:209`, the first four terms of the format string.
- Corroboration 2: `zeek/ja4s/main.zeek:127-158`, the function `make_a`, appends `proto`,
  `version`, `ec_count` and `alpn` in that order and inserts nothing between them.

### R3 — The protocol character is `t` for TLS over TCP and `q` for QUIC

- Corroboration 1: `rust/ja4/src/tls.rs:452` calls `quic_marker(is_quic)`, and
  `rust/ja4/src/tls.rs:481-487` returns `q` or `t`.
- Corroboration 2: `zeek/ja4s/main.zeek:129-132` sets `proto` to `t`, then to `q` when the
  service holds `QUIC`.

**This rule is uncertain for DTLS. Keep the vector fallback.** The image names two values
and the four implementations name three between them. `wireshark/source/packet-ja4.c:729`
sets the character to `t` or `q`. `packet-ja4.c:732` overwrites it with `d` for DTLS.
`packet-ja4.c:979` passes that same record to `ja4s()`, so the dissector writes a `d` JA4S
value. `technical_details/JA4.md:24` and `JA4.md:46` state the same three values for JA4.
The other three implementations write `t` or `q` alone. `rust/ja4/src/tls.rs:434` reads
`is_quic` as `pkt.find_proto("udp").is_some()`, so the Rust reference writes `q` for a
ServerHello that DTLS carries over UDP. See "The decisions this page raises".

### R4 — The two version characters name the TLS version of the ServerHello

`12` is TLS 1.2 and `13` is TLS 1.3. An unknown version writes `00`.

- Corroboration 1: `wireshark/source/packet-ja4.c:550` and `packet-ja4.c:567` call
  `val_to_str_const(data->version, ssl_versions, "00")`. The table `ssl_versions` at
  `packet-ja4.c:76-87` maps `0x0303` to `12` and `0x0304` to `13`, and its fallback is
  `00`.
- Corroboration 2: `python/ja4.py:195` reads `TLS_MAPPER[x['version']]` and writes `00`
  when the map holds no row.

`technical_details/JA4.md:56-68` holds the whole version table, which the image does not
draw. **The image draws two rows of it, and both agree.**

### R5 — The supported_versions extension of the ServerHello decides the version

A ServerHello that carries extension `0x002b` names its version there rather than in the
legacy version field.

- Corroboration 1: `rust/ja4/src/tls.rs:554-567`, `TlsVersion::new`, reads
  `tls.handshake.extensions.supported_version` when the extension list holds `0x002b`, and
  it reads `tls.handshake.version` otherwise.
- Corroboration 2: `python/common.py:151-156`, `get_supported_version`, drops the GREASE
  values, sorts the rest and returns the last.

`zeek/ja4s/main.zeek:110-125` keeps the largest non-GREASE value too. **The image states
nothing about this field**, and the three implementations agree.

### R6 — The extension count is two decimal digits and it stops at 99

- Corroboration 1: `rust/ja4/src/tls.rs:453` holds `let nr_exts = 99.min(exts.len());`, and
  `tls.rs:456` prints it as `{nr_exts:02}`.
- Corroboration 2: `python/ja4.py:183` holds
  `'{:02d}'.format(min(len(x['extensions']), 99))`.

`zeek/ja4s/main.zeek:140-145` writes `99` above 99 and `fmt("%02d", ...)` otherwise.

### R7 — The ALPN field is the first and the last character of the chosen ALPN value

The field is `00` when the ServerHello names no ALPN. A ServerHello names one ALPN value,
which the image calls the chosen one.

- Corroboration 1: `rust/ja4/src/tls.rs:423-424` reads
  `tls.handshake.extensions_alpn_str` through `first_last`, and `tls.rs:457-458` writes
  `'0'` for each absent character.
- Corroboration 2: `zeek/ja4s/main.zeek:49` sets the default `alpn` to `"00"`, and
  `main.zeek:147-150` writes `alpn[0] + alpn[-1]`.

**This rule is uncertain for a byte that is not ASCII alphanumeric. Keep the vector
fallback.** The image states the absent case and no other case. `technical_details/JA4.md:86-99`
states the hex fallback for JA4, and the four implementations disagree on the bytes it
covers. #162 measured that disagreement on JA4 and no FoxIO source measures it on JA4S. See
"What the register holds".

### R8 — Part b is the one cipher the server chose, as four lowercase hex digits

- Corroboration 1: `python/ja4.py:190-191` carries the comment
  `# only one cipher for ja4s` and reads `x['ciphers'][0][2:]`.
- Corroboration 2: `zeek/ja4s/main.zeek:165` writes
  `fmt("%04x", c$fp$server_hello$cipher)`.

The deleted `technical_details/JA4S.md` states
`In the Server Hello packet, there is always a single cipher, the cipher that the server chose`,
which `docs/specs/foxio/deleted-text-specifications.md` records. That is a third
corroboration and FoxIO wrote it.

### R9 — Part c is the first 12 characters of the SHA-256 of the extension list

The hashed text holds the extension type values as four lowercase hex digits, joined with
`,`, in the order the ServerHello carries them.

- Corroboration 1: `rust/ja4/src/tls.rs:461-462` holds the comment
  `// Note that we are preserving the original order of server's TLS extensions.` above
  `exts.into_iter().map(|v| format!("{v:04x}")).join(",")`, and `rust/ja4/src/lib.rs:180-190`,
  `hash12`, returns `sha256[..12]`.
- Corroboration 2: `python/common.py:125-127`, `sha_encode`, returns
  `sha256(','.join(values).encode('utf8')).hexdigest()[:12]`.

### R10 — Nothing sorts the extension list, and FoxIO publishes no sorted JA4S key

- Corroboration 1: `rust/ja4/src/tls.rs:473-479`, `OutServer`, holds `ja4s` and `ja4s_r`
  and no third key.
- Corroboration 2: `python/ja4.py:209-213` writes `JA4S` and `JA4S_r` alone, and
  `python/ja4.py:324` deletes `JA4S_r` when the caller asks for no raw form.

The deleted `technical_details/JA4S.md` states
`with Server Hellos, the extensions are not being randomized, that means we can hash those in the order they are seen rather than sorting them`
and `JA4S doesn’t sort so -o does nothing here.`

### R11 — An empty extension list writes `000000000000`

- Corroboration 1: `wireshark/source/packet-ja4.c:573` writes
  `wmem_strbuf_get_len(data->extensions) ? _hash : "000000000000"`.
- Corroboration 2: `python/ja4.py:186-188` writes `extensions = '000000000000'` when the
  list is empty.

`rust/ja4/src/lib.rs:184-185` returns the same twelve zeros for an empty input.

### R12 — `JA4S_r` repeats part a and part b, and it writes the extension list

- Corroboration 1: `wireshark/source/packet-ja4.c:547-559`, `ja4s_r()`, writes the same
  format as `ja4s()` and substitutes `data->extensions` for the hash.
- Corroboration 2: `python/ja4.py:210` writes
  `f"{ptype}{version}{ext_len}{alpn}_{x['ciphers']}_{','.join(x['extensions'])}"`.

### R13 — The references split two against two on GREASE in the extension list

**This rule is uncertain. Keep the vector fallback.** The image captions the field
`Number of Extensions` and states no exclusion.

- `python/ja4.py:182` carries the comment
  `# get extensions in hex in the order they are present (include grease values)`, so the
  Python reference counts and hashes a GREASE extension.
- `rust/ja4/src/tls.rs:604-613`, `tls_extensions_server`, applies no GREASE test. The
  client function beside it, `tls_extensions_client` at `tls.rs:585-600`, drops the GREASE
  values, so the difference is deliberate.
- `wireshark/source/packet-ja4.c:757` guards with `if (!IS_GREASE_TLS(value))`, so the
  dissector drops a GREASE extension from the list and from the count.
- `zeek/ja4s/main.zeek:91` returns on a GREASE code, under the comment
  `# Will we see grease from the server?`.

**No vector in this repository measures the rule.** Measured on 2026-08-08 across the 38
captures of `tests/foxio_vectors/`: 0 ServerHello messages carry a GREASE extension type.

### R14 — JA4S reads the ServerHello, and it covers QUIC

- Corroboration 1: `technical_details/README.md:6` reads
  `| JA4Server | JA4S | TLS Server Response / Session Fingerprinting |`.
- Corroboration 2: `rust/ja4/src/tls.rs:406` heads `ServerStats` with the doc comment
  `/// Information obtained from a TLS Server Hello packet.`, and `tls.rs:434` marks the
  QUIC case.

## The comparison against this project

The comparison below reads `ja4plus/fingerprinters/ja4s.py` and
`ja4plus/utils/tls_utils.py` at commit `edfc7b2`. **Every field is named. A field this
table does not name is a field nobody read.**

### The fields that agree

| Field | Rule | `ja4s.py` | Reading |
|---|---|---|---|
| Part count and separators | R1 | `ja4s.py:311` | Agrees. The format string is `f"{part_a}_{cipher_str}_{extensions_hash}"`. |
| Part a composition | R2 | `ja4s.py:298` | Agrees. `f"{proto}{version_str}{ext_count}{alpn_value}"` carries no separator. |
| Protocol character `t` | R3 | `ja4s.py:276` | Agrees. 97 of the 126 measured values open with `t`. |
| Protocol character `q` | R3 | `ja4s.py:276`, `ja4s.py:258` | Agrees. 29 of the 126 measured values open with `q`, and `tests/test_foxio_rust_parity.py` matches them against the Rust snapshots. |
| Version characters | R4 | `ja4s.py:285`, `ja4s.py:385-398` | Agrees for `13`, `12`, `11`, `10`, `s3`, `d1`, `d2`, `d3` and the `00` fallback. The `0x0200` row is D5. |
| Version from supported_versions | R5 | `ja4s.py:279-284`, `tls_utils.py:266-269` | Agrees for a ServerHello that names one version. D2 covers a ServerHello that names more. |
| Extension count digits | R6 | `ja4s.py:287` | Agrees. `f"{min(len(extensions), 99):02d}"`. |
| GREASE in the extension list | R13 | `tls_utils.py:256` | Agrees with the Python and the Rust references, which R13 marks uncertain. Disagrees with the dissector and the Zeek script. |
| ALPN, the absent case | R7 | `ja4s.py:413` | Agrees. `_get_alpn_value` returns `00`. |
| ALPN, the first and the last character | R7 | `ja4s.py:297`, `ja4.py:74-75` | Agrees. 12 of the 126 measured values carry an ALPN. |
| ALPN, a byte that is not alphanumeric | R7 | `ja4.py:37-84` | Uncertain. No FoxIO JA4S value measures it. |
| Cipher, four lowercase hex digits | R8 | `ja4s.py:303` | Agrees. `f"{cipher:04x}"`. |
| Cipher, one value | R8 | `tls_utils.py:229-230` | Agrees. The reader takes the two bytes the ServerHello holds. |
| Extension hash | R9 | `ja4s.py:305-307` | Agrees. `hashlib.sha256(ext_str.encode()).hexdigest()[:12]` over `",".join(f"{e:04x}")`. |
| Extension order | R9, R10 | `ja4s.py:306`, `ja4s.py:200` | Agrees. The comprehension keeps wire order and nothing sorts it. |
| Empty extension list | R11 | `ja4s.py:309` | Agrees. `extensions_hash = "000000000000"`. |
| `JA4S_r` | R12 | `ja4s.py:361-363` | Agrees. Measured as `t120400_c030_0005,0017,ff01,0000`. |
| No sorted key | R10 | `ja4s.py:195-203` | Agrees. One raw value serves both key names, and the comment states the reason. |
| Packet selection | R14 | `ja4s.py:90`, `ja4s.py:159` | Agrees. Both paths require `handshake_type == "server_hello"`. |

### The disagreements

**D1 — `ja4s.py:276` writes `d` for a DTLS ServerHello, and the image names only `t` and
`q`.**

`proto = "q" if tls_info.get("is_quic") else "d" if tls_info.get("is_dtls") else "t"`. The
image captions the field `Protocol, TCP = “t”  QUIC = “q”`, and it draws no third value.

Two FoxIO sources support the `d` value. `wireshark/source/packet-ja4.c:732` writes it, and
`packet-ja4.c:979` passes the same record to `ja4s()`. `technical_details/JA4.md:24` states
`(QUIC=”q”, DTLS="d", or TLS over TCP=”t”)` for the protocol character of JA4.

Two FoxIO sources contradict it for JA4S. `rust/ja4/src/tls.rs:434` reads `is_quic` as
`pkt.find_proto("udp").is_some()`, so the Rust reference writes `q` for a ServerHello that
DTLS carries. `python/ja4.py:173` writes `q` or `t` alone.

**No vector measures it.** Measured on 2026-08-08 across the 38 captures of
`tests/foxio_vectors/`: `ja4plus` produces 126 JA4S values. 97 of them open with `t`, 29
open with `q`, and 0 open with `d`. No expected-output file in this repository holds a JA4S
value that opens with `d`.

**D2 — `ja4s.py:281-283` reads the first supported version, and the three references read
the largest.**

`non_grease[0]` takes the first value of the list. `rust/ja4/src/tls.rs:561-562` sorts and
takes the last, `python/common.py:155-156` sorts and takes the last, and
`zeek/ja4s/main.zeek:113-121` keeps the largest.

`tls_utils.py:267-269` reads two bytes of the extension and stores one value, so a
conformant ServerHello reaches the same answer either way. RFC 8446 section 4.2.1 states
that the ServerHello form of the extension carries one version. **The reading is a code
reading, and no vector demonstrates it.**

**D3 — `ja4s.py:281-283` falls back to the legacy version when every supported version is
GREASE, and the Rust reference emits nothing.**

`if non_grease:` leaves `version` at the ServerHello legacy field.
`rust/ja4/src/tls.rs:563-565` raises `Error::MissingField` instead, so the Rust reference
writes no JA4S value for that ServerHello. **The reading is a code reading, and no vector
demonstrates it.**

**D4 — `ja4s.py:300-302` writes no fingerprint when the ServerHello names no cipher, and
the Python reference writes an empty part b.**

`if cipher is None: return None`. `python/ja4.py:191` writes
`x['ciphers'] = x['ciphers'][0][2:] if x['ciphers'] else ''`, which produces a value of the
form `t130200__a56c5b993250`. Rule 2 of `CLAUDE.md` states that a parser which cannot read
a packet returns nothing, so this project holds the shape it holds. **No vector
demonstrates it.** Measured on 2026-08-08 across the 38 captures of
`tests/foxio_vectors/`: the reader parses 97 TCP ServerHello messages and 0 of them name no
cipher.

**D5 — `ja4s.py:393` maps `0x0200` to `s2`, and the pinned specification states `0x0002`.**

**#227 owns this repair and this page changes no file under `ja4plus/`.**
`technical_details/JA4.md:65` states `0x0002 = SSL 2.0 = “s2”`, and
`wireshark/source/packet-ja4.c:77` holds `{0x0002, "s2"}`.
`docs/specs/foxio/deleted-text-specifications.md` records the measurement and names the
FoxIO commit `3e02a27` that corrected the value. The row belongs to the version field this
page reads, so this page cites it.

## What the register holds

`tests/foxio_deviations.json` holds 120 entries. **14 of them name JA4S.** Twelve form six
pairs, each pair holding one `JA4S` entry and one `JA4S_r` entry. `https-connect.pcap` and
`socks4-https.pcap` hold a `JA4S` entry and no `JA4S_r` entry.

| Entry | Owner | Explained by the specification |
|---|---|---|
| `browsers-x509.pcapng/JA4S` | #151 | No |
| `browsers-x509.pcapng/JA4S_r` | #151 | No |
| `chrome-cloudflare-quic-with-secrets.pcapng/JA4S` | #138 | No |
| `chrome-cloudflare-quic-with-secrets.pcapng/JA4S_r` | #138 | No |
| `https-connect.pcap/JA4S` | #138 | No |
| `latest.pcapng/JA4S` | #151 | No |
| `latest.pcapng/JA4S_r` | #151 | No |
| `socks4-https.pcap/JA4S` | #151 | No |
| `ssh2.pcapng/JA4S` | #138 | No |
| `ssh2.pcapng/JA4S_r` | #138 | No |
| `tls-handshake.pcapng/JA4S` | #138 | No |
| `tls-handshake.pcapng/JA4S_r` | #138 | No |
| `tls3.pcapng/JA4S` | #138 | No |
| `tls3.pcapng/JA4S_r` | #138 | No |

**The specification explains none of the 14, and it contradicts none of them.** Every one
records a stream that the FoxIO Python expected-output file omits and that `ja4plus`
fingerprints. Nine name #138, which covers the QUIC handshake and the TLS port the Python
reference does not know. Five name #151, which covers the ServerHello whose handshake
record spans several TCP segments. **The image states the schema of one value. It states
no rule about which stream a reader reaches**, so it can settle no entry of this shape.

`socks4-https.pcap/JA4S` is the one entry of the 14 that no FoxIO implementation holds a
value for. The image states no rule about a tunnel protocol, so it explains that entry no
better than the other 13.

**Each of the 14 already carries `"decided": true`.** This page changes no entry.

### The 16 ALPN entries name JA4 and not JA4S

The plan for this issue stated that 16 register entries under #162 concern JA4S and ALPN.
**The measurement contradicts that statement.** The 16 entries name the keys `JA4.1`,
`JA4_o.1`, `JA4_r.1` and `JA4_ro.1` on four streams of `alpn-condition.pcap`. **No entry of
the 16 names JA4S or JA4S_r.**

Measured on 2026-08-08.

```
tests/foxio_vectors/alpn-condition.pcap        : 7 packets, 0 ServerHello messages
tests/foxio_vectors/alpn-condition.pcap.json   : 7 streams, 0 JA4S keys
ja4plus JA4S on alpn-condition.pcap            : 0 values
```

**The capture carries client traffic alone**, so no implementation writes a JA4S value for
it and the ALPN disagreement of #162 never reaches this method. R7 marks the
non-alphanumeric ALPN byte uncertain for JA4S, and it stays uncertain. The image states
only the absent case, and no FoxIO JA4S value measures any other case.

## The search for a reference value

**JA4S reaches more published values than any other method this epic reads.** Each count
comes from a walk of the file's structure at the pinned commit, and not from a line
pattern.

| Source searched | Result |
|---|---|
| `python/test/testdata/` | **84 JA4S values in 14 files.** |
| `rust/ja4/src/snapshots/` | **120 `ja4s` values in 15 files, 29 of them distinct.** |
| `wireshark/test/testdata/` | **125 `ja4.ja4s` values in 15 files.** |
| `zeek/tests/Traces/Scripts.ja4-tls-handshake/ssl.log` | 20 JA4S values. #198 owns that reading and reports that every one matches. |
| `README.md` at the pinned commit | Three documented values, at lines 142, 143 and 145, against `IcedID Malware`, `Sliver Malware` and `SoftEther VPN`. |

Reproduce the snapshot count from a checkout at the pinned commit.

```bash
grep -rhoE '\bja4s: [^ ]+' rust/ja4/src/snapshots/ | sort | uniq -c | sort -rn
```

**This repository already holds 194 of those values.**
`tests/foxio_vectors/*.json` holds all 84 of the Python values, and
`tests/foxio_vectors/rust_expected/` holds 110 of the 120 Rust values in 8 files.

| Capture in `tests/foxio_vectors/` | `ja4s` values in the local snapshot |
|---|---|
| `browsers-x509.pcapng` | 3 |
| `chrome-cloudflare-quic-with-secrets.pcapng` | 2 |
| `https-connect.pcap` | 1 |
| `latest.pcapng` | 5 |
| `ssh2.pcapng` | 7 |
| `tls-handshake.pcapng` | 79 |
| `tls3.pcapng` | 13 |

`tests/test_foxio_rust_parity.py:72` reads `SNAPSHOT_METHODS = (("JA4", "ja4"), ("JA4S", "ja4s"))`,
so **the harness already reads every one of those 110 values.** JA4S is the one method of
this epic where the comparison is made rather than merely available. #196, #203 and #199
each found the opposite for the method they read.

## What the deleted text specification adds

**FoxIO published `technical_details/JA4S.md`, 1584 bytes, and `b6f3ff4` deleted it.** #221
read it, and `docs/specs/foxio/deleted-text-specifications.md` holds the provenance and the
whole reading. **This page rewrites no rule above.** The deleted file is not the pinned
specification, so the image outranks it.

The deleted text carries three findings for this page.

1. **It corroborates R8, R9 and R10 in FoxIO's own prose.** It states the single cipher,
   the wire order of the extensions, the 12-character truncation, and that JA4S publishes
   no sorted form.
2. **It agrees with the image on the protocol character**, and both name `(q or t)` alone.
   #221 read the deleted `(q or t)` as a file that predates the DTLS addition. **The image
   at the pinned commit states the same two values.** That reading therefore rests on
   `technical_details/JA4.md` and the Wireshark dissector, and not on the age of the
   deleted file. D1 records the whole split.
3. **It states the raw form the image does not draw.** `JA4S_r = t120400_c030_0005,0017,ff01,0000`
   is the exact value this project produces for the capture the image's example names.

The deleted text states nothing that contradicts the image.

## The decisions this page raises

Each item needs the user, because each changes a fingerprint that this project publishes,
or it records that a rule no vector measures. **This page changes no fingerprinter.**

1. **D1.** Does JA4S carry a `d` protocol character for DTLS? The image and two FoxIO
   implementations say no, and the Wireshark dissector and `technical_details/JA4.md` say
   yes. `ja4s.py:276` writes it and no vector measures it.
2. **R13.** Does the extension count of JA4S include a GREASE extension? The Python and the
   Rust references include it, the dissector and the Zeek script drop it, and the image
   settles nothing. `ja4plus` includes it and no vector measures it.
3. **D2 and D3.** Which supported version does a ServerHello that carries several name, and
   what does a ServerHello whose supported versions are all GREASE produce?
4. **D4.** Does a ServerHello that names no cipher produce a value with an empty part b, or
   no value?
5. **D5.** `ja4s.py:393` maps the retracted `0x0200`. **#227 owns it and this page only
   cites it.**
