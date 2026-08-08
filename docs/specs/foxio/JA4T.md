# JA4T and JA4TS

This page is this project's own prose form of `technical_details/JA4T.png`. It follows the
procedure in `docs/specs/foxio/README.md`. No image enters this repository.

| Item | Value |
|---|---|
| Source | `https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4T.png` |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-08 |
| SHA-256 of the image | `1a76d4ac7645b794bdb7a29fd00d2eeaf46395af3f66c0b86b76a1f6dcef76f2` |

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4T.png (retrieved 2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

Reproduce the hash from a checkout at the pinned commit.

```bash
shasum -a 256 technical_details/JA4T.png
```

## The image specifies JA4TS

**The image titles itself `JA4T/S: TCP Fingerprint`.** The title names the server form, so
one image publishes both methods. `docs/specs/foxio/README.md` recorded this as an open
question, and this page closes it.

The image states no separate server rule. It gives one field layout and one example, and it
labels the example `JA4T=`. **The image therefore specifies the schema of JA4TS and not the
packet that JA4TS reads.** The corroborations below settle the packet.

## The field layout

The image draws one example string and labels five parts `a` to `e`.

```
JA4T=65535_2-1-3-1-1-4_1460_8_1-2-4-8-R6
      \___/ \_________/ \__/ \_/ \______/
        a        b       c    d     e
```

| Part | The image's caption | Value in the example |
|---|---|---|
| a | TCP Window Size | `65535` |
| b | TCP Options (in the order they are seen) | `2-1-3-1-1-4` |
| c | TCP Maximum Segment Size | `1460` |
| d | TCP Window Scale (multiplier) | `8` |
| e | TCP Retransmission Timings (only on JA4TScan) | `1-2-4-8-R6` |

The parts join with `_`. The values inside part b and part e join with `-`.

## The rules

Each rule below carries two corroborations. Neither corroboration is the image.

### R1 — JA4T holds four parts, joined with `_`

The fingerprint is `<window size>_<options>_<mss>_<window scale>`.

- Corroboration 1: `rust/ja4/src/tcp.rs`, `ClientStats::to_ja4t`, at the pinned commit. Its
  doc comment states `<window size>_<options>_<mss>_<window scale>` and the example
  `64240_2-1-3-1-1-4_1460_8`.
- Corroboration 2: `README.md` line 152 at the pinned commit states
  ```JA4T=64240_2-1-3-1-1-4_1460_8``` beside the label `Windows 11`.

### R2 — Part e belongs to JA4TScan, and not to JA4T

- Corroboration 1: `README.md` line 153 at the pinned commit states
  ```JA4TScan=28960_2-4-8-1-3_1460_3_1-4-8-16```. That value holds five parts, and the JA4T
  value on line 152 holds four.
- Corroboration 2: `rust/ja4/src/tcp.rs` emits four parts and no timing part.

**This rule is uncertain for JA4TS.** The image states that part e appears only on
JA4TScan. The Wireshark dissector contradicts the image: `wireshark/source/packet-ja4.c`
appends part e inside `ja4t()` whenever the caller passes a connection, and the two call
sites that pass a connection are the two that write the `JA4TS` field. Keep the vector
fallback for part e on JA4TS. See "The decisions this page raises".

### R3 — Part a is the raw window size

Part a is the value of the TCP window field, before the window scale multiplies it.

- Corroboration 1: `rust/ja4/src/tcp.rs` reads `tcp.window_size_value` and its comment
  states `Extract window size (raw, before scaling)`.
- Corroboration 2: `wireshark/source/packet-ja4.c:1258` reads the same field name,
  `tcp.window_size_value`, into `ja4t_data.window_size`.

### R4 — Part b lists every TCP option kind, in wire order

Part b holds the IANA option kind number of every option, in the order the packet carries
them. Nothing sorts the list and nothing filters it.

- Corroboration 1: `rust/ja4/src/tcp.rs` pushes every value of `tcp.option_kind` into
  `options` with no test on the kind.
- Corroboration 2: `wireshark/source/packet-ja4.c:1458` appends every option kind with
  `"%d-"` and applies no test on the kind.

The image's caption states the order rule in words: `TCP Options (in the order they are
seen)`.

### R5 — An End of Option List byte contributes a `0` for each byte

Kind 0 is End of Option List. Each such byte on the wire adds one `0` to part b.

- Corroboration 1: `rust/ja4/src/snapshots/ja4__insta@chrome-cloudflare-quic-with-secrets.pcapng.snap`
  holds `ja4t: 65535_2-1-3-1-1-8-4-0-0_1440_6`. The SYN carries two `0x00` bytes, and part b
  ends with two `0` values.
- Corroboration 2: `wireshark/source/packet-ja4.c:1458` appends one entry per option kind
  field, and Wireshark reports one `tcp.option_kind` field per pad byte.

### R6 — Part c is 0 when the packet carries no Maximum Segment Size option

- Corroboration 1: `rust/ja4/src/tcp.rs` writes `self.mss.unwrap_or(0)`.
- Corroboration 2: `rust/ja4/src/snapshots/ja4__insta@gre-erspan-vxlan.pcap.snap` holds
  `ja4t: 8192__0_0`, produced by a SYN that carries no option.

### R7 — Part d is 0 when the packet carries no Window Scale option

- Corroboration 1: `rust/ja4/src/tcp.rs` writes `self.window_scale.unwrap_or(0)`.
- Corroboration 2: `rust/ja4/src/snapshots/ja4__insta@gre-erspan-vxlan.pcap.snap` holds
  `ja4t: 8192__0_0`.

### R8 — JA4T reads the client SYN, and JA4TS reads the server SYN-ACK

- Corroboration 1: `technical_details/README.md` lines 12 and 13 name `JA4TCP` /
  `JA4T` as `TCP Client Fingerprinting` and `JA4TCPServer` / `JA4TS` as
  `TCP Server Response Fingerprinting`.
- Corroboration 2: `wireshark/source/packet-ja4.c:1265` marks the SYN and the dissector
  writes the `JA4T` field for it. Line 1278 marks the SYN-ACK and the dissector writes the
  `JA4TS` field for it.

### R9 — JA4T reads only the first SYN of a connection

- Corroboration 1: `rust/ja4/src/tcp.rs`, `Stream::update`, returns early when
  `self.client.is_some()`, under the doc comment `Only the first SYN without ACK is
  processed.`
- Corroboration 2: `rust/ja4/src/snapshots/ja4__insta@ssh2.pcapng.snap` holds 19 `ja4t`
  values for 19 connections, and `ssh2.pcapng` carries repeated SYN packets on 10 of them.

### R10 — The two references disagree on which flag combination starts a JA4T

**This rule is uncertain.** Keep the vector fallback.

- `rust/ja4/src/tcp.rs`, `is_initial_syn`, tests the flags as a mask: SYN set and ACK
  clear. Its own unit test asserts that `0xC2`, a SYN with the two ECN flags, produces a
  fingerprint.
- `wireshark/source/packet-ja4.c:1265` tests `tcp_flags == 0x02` for equality, so a SYN
  that carries an ECN flag produces no JA4T value in the dissector.

### R11 — The references disagree on the empty part b, and on a zero part c or part d

**This rule is uncertain.** Keep the vector fallback.

- `rust/ja4/src/tcp.rs` joins an empty option list to the empty string, and prints part c
  and part d with no padding. `ja4__insta@gre-erspan-vxlan.pcap.snap` holds `8192__0_0`.
- `wireshark/source/packet-ja4.c:664`, `ja4t()`, writes `00` for an empty option list,
  prints part c with `%02d`, and prints part d with `%02d` when the window scale is 0.
- The Zeek baseline follows the Wireshark form. `zeek/tests/Traces/Scripts.ja4-conn/conn.log`
  holds `ja4t 65535_00_00_00` and `ja4ts 65535_00_00_00`. #198 owns that reading and this
  page cites it rather than repeating the survey.

The image settles none of this. It draws one example, and that example carries options, a
Maximum Segment Size and a non-zero window scale.

## The comparison against this project

The comparison below reads `ja4plus/fingerprinters/ja4t.py` and
`ja4plus/fingerprinters/ja4ts.py` at commit `3c01c94`. Every field is named. A field this
table does not name is a field nobody read.

### JA4T — the fields that agree

| Field | Rule | `ja4t.py` | Reading |
|---|---|---|---|
| Part count and separator | R1 | `ja4t.py:88` | Agrees. The format string is `f"{window_size}_{options_str}_{mss}_{wscale}"`. |
| Part a, raw window | R3 | `ja4t.py:60` | Agrees. `str(tcp.window)` reads the unscaled field. |
| Part b order | R4 | `ja4t.py:67` | Agrees. The loop keeps wire order and nothing sorts it. |
| Part b separator | R4 | `ja4t.py:85` | Agrees. `"-".join(options)`. |
| Part c absent | R6 | `ja4t.py:64` | Agrees. `mss = "0"` is the default. |
| Part d absent | R7 | `ja4t.py:65` | Agrees. `wscale = "0"` is the default. |
| Packet selection | R8 | `ja4t.py:56` | Agrees. SYN set and ACK clear, tested as a mask. |
| ECN on a SYN | R10 | `ja4t.py:56` | Agrees with `tcp.rs`. Disagrees with the dissector, which R10 marks uncertain. |
| Part e | R2 | absent from `ja4t.py` | Agrees. JA4T carries no timing part. |

### JA4T — the disagreements

**D1 — `ja4t.py:85` writes `0` for an empty option list, and no reference writes `0`.**

`options_str = "-".join(options) if options else "0"` produces `8192_0_0_0`. The FoxIO Rust
snapshot holds `8192__0_0` and the Wireshark form is `8192_00_00_00`. This project matches
neither reference.

Measured on 2026-08-08 against `tests/foxio_vectors/gre-erspan-vxlan.pcap`, which this
repository already holds.

```
FoxIO rust ja4__insta@gre-erspan-vxlan.pcap.snap : 8192__0_0
ja4plus generate_ja4t                            : 8192_0_0_0
```

**D2 — `ja4t.py:67` reads scapy's parsed option list, which reports one `EOL` entry for
several pad bytes.**

The SYN of `tests/foxio_vectors/chrome-cloudflare-quic-with-secrets.pcapng` carries the
option bytes `020405a0010303060101080a88d73b2c0000000004020000`. The wire kinds are
`2, 1, 3, 1, 1, 8, 4, 0, 0`. Scapy reports
`[('MSS', 1440), ('NOP', None), ('WScale', 6), ('NOP', None), ('NOP', None), ('Timestamp', (2295806764, 0)), ('SAckOK', b''), ('EOL', None)]`,
which holds one `EOL` for two `0x00` bytes.

```
FoxIO rust ja4__insta@chrome-cloudflare-quic-with-secrets.pcapng.snap : 65535_2-1-3-1-1-8-4-0-0_1440_6
ja4plus generate_ja4t                                                 : 65535_2-1-3-1-1-8-4-0_1440_6
```

This breaks R5.

**D3 — `ja4t.py:69` to `ja4t.py:82` drop every option kind the loop does not name.**

The loop maps six names: `MSS`, `NOP`, `WScale`, `SAckOK`, `Timestamp` and `EOL`. It
appends nothing for any other kind. R4 states that both references append every kind. A SYN
that carries kind 5, kind 28, kind 30 or kind 34 therefore produces a part b that omits it.
No vector in this repository carries such an option, so no measurement demonstrates D3. The
reading is a code reading, and R4 holds two corroborations.

**D4 — `ja4t.py` holds no connection state, so it emits one value for every SYN.**

R9 states that the reference reads only the first SYN of a connection. `ja4t.py` has no
state table and `process_packet` fingerprints each SYN it sees.

Measured on 2026-08-08 against `tests/foxio_vectors/ssh2.pcapng`.

```
FoxIO rust ja4__insta@ssh2.pcapng.snap : 19 ja4t values, for 19 connections
ja4plus generate_ja4t                  : 44 values, over the same 19 connections
```

10 connections produce more than one value. `.claude/rules/conformance.md` states that a
method that emits more fingerprints than the reference is a defect. The distinct values
agree, so D4 changes the count and not the value.

**D5 — `ja4t.py:71` and `ja4t.py:76` keep the last option, and the reference keeps the
first.**

`mss = str(int(opt[1]))` and `wscale = str(opt[1])` run inside the loop, so a second
Maximum Segment Size option overwrites the first. `rust/ja4/src/tcp.rs` calls
`.next()` on the field iterator, which keeps the first. No vector in this repository carries
a repeated option, so no measurement demonstrates D5.

### JA4TS — the fields that agree

| Field | Rule | `ja4ts.py` | Reading |
|---|---|---|---|
| Part count and separator | R1 | `ja4ts.py:89` | Agrees. The four-part format matches JA4T. |
| Part a, raw window | R3 | `ja4ts.py:60` | Agrees. |
| Part b order | R4 | `ja4ts.py:68` | Agrees. |
| Part b separator | R4 | `ja4ts.py:86` | Agrees. |
| Part c absent | R6 | `ja4ts.py:64` | Agrees. |
| Part d absent | R7 | `ja4ts.py:65` | Agrees. |
| Packet selection | R8 | `ja4ts.py:56` | Agrees. `tcp.flags & 0x12 == 0x12` selects the SYN-ACK. |

### JA4TS — the disagreements

`ja4ts.py` repeats the body of `ja4t.py`, so it repeats D1, D2, D3 and D5 at
`ja4ts.py:86`, `ja4ts.py:68`, `ja4ts.py:70` to `ja4ts.py:83`, and `ja4ts.py:72` with
`ja4ts.py:77`. Two disagreements belong to JA4TS alone.

**D6 — `ja4ts.py` writes no part e, and the Wireshark dissector writes one.**

`wireshark/source/packet-ja4.c:1595` writes the `JA4TS` field through `ja4t()` with a
connection, so the dissector appends the SYN-ACK retransmission intervals when the
connection holds more than one SYN-ACK. The image states that part e appears only on
JA4TScan. R2 marks this uncertain.

**D7 — `ja4ts.py` writes no value on a RST, and the Wireshark dissector writes one.**

`wireshark/source/packet-ja4.c:1295` marks a RST, and line 1608 writes a second `JA4TS`
value from the stored connection values, with the `-R<interval>` suffix. The image's
example part e ends with `R6`, which corroborates the suffix shape. `ja4ts.py:56` reads the
SYN-ACK alone and reaches no RST.

## The search for a reference value

The issue that produced this page stated that no Rust snapshot holds a JA4T or a JA4TS
value. **The measurement contradicts that statement for JA4T.**

| Source searched | Result |
|---|---|
| `rust/ja4/src/snapshots/` | **64 `ja4t` values in 26 files, 19 of them distinct.** No `ja4ts` value. |
| `wireshark/test/testdata/` | No `ja4t` value and no `ja4ts` value. |
| `python/test/testdata/` | No `ja4t` value and no `ja4ts` value. |
| FoxIO `pcap/` | 38 captures. They carry the TCP traffic, and they hold no expected value of their own. |
| `README.md` at the pinned commit | Two documented values, at lines 152 and 153. |
| `zeek/` | Not searched here. #198 owns it and reports `ja4t 65535_00_00_00` and `ja4ts 65535_00_00_00` in `zeek/tests/Traces/Scripts.ja4-conn/conn.log`. |

Reproduce the snapshot count from a checkout at the pinned commit.

```bash
grep -rhoE '\bja4ts?: [^ ]+' rust/ja4/src/snapshots/ | sort | uniq -c | sort -rn
```

**Six of those 26 snapshot files already sit in this repository**, under
`tests/foxio_vectors/rust_expected/`, beside the captures that produce them. They hold 38
of the 64 values.

| Capture in `tests/foxio_vectors/` | `ja4t` values in the local snapshot |
|---|---|
| `browsers-x509.pcapng` | 3 |
| `chrome-cloudflare-quic-with-secrets.pcapng` | 1 |
| `https-connect.pcap` | 1 |
| `latest.pcapng` | 6 |
| `ssh2.pcapng` | 19 |
| `tls3.pcapng` | 8 |

## Why the suite reports no deviation

`tests/test_foxio_rust_parity.py:72` reads two methods from a snapshot.

```python
SNAPSHOT_METHODS = (("JA4", "ja4"), ("JA4S", "ja4s"))
```

**The snapshots this project already holds carry `ja4t` values, and the harness never reads
the field.** No other test compares a JA4T value or a JA4TS value against a FoxIO value, so
`tests/foxio_deviations.json` holds no entry for either method. The JA4T cases in
`tests/test_comprehensive.py` build a packet with scapy and assert this project's own
format, so no reference decides them.

This is the shape `.claude/rules/conformance.md` names under "Ask whether a case can fail".

## The conformance evidence a later issue can build

**#216 owns this work.**

1. **JA4T needs no new file.** Add `("JA4T", "ja4t")` to `SNAPSHOT_METHODS` and compare the
   38 local values. D1 and D2 fail immediately, so the change lands with a deviation entry
   or with a repair.
2. **Twenty more snapshots reach the remaining 26 values.** The captures are in the FoxIO
   `pcap/` directory and this repository holds several of them already.
3. **`gre-erspan-vxlan.pcap` is the one case that measures the empty part b.** The capture
   is local and the snapshot is not.
4. **JA4TS reaches no FoxIO reference value except the Zeek baseline.** No Rust snapshot and
   no Wireshark expected-output file holds one. #198 owns the Zeek reading.

## What the deleted text specification adds

**FoxIO published `technical_details/JA4T.md`, 6423 bytes, and `b6f3ff4` deleted it on
2024-02-22.** #221 read it, and `docs/specs/foxio/deleted-text-specifications.md` holds the
whole reading and the provenance. **This page rewrites no rule above.** The deleted file is
not the pinned specification, so the image outranks it.

The deleted text carries two findings for this page.

1. **It contradicts the image on part e of JA4TS.** Its form for JA4TS reads
   `WindowSize_TCPOptions_MSSValue_WindowScale_TimeSinceLastSYNACK`, and the image's caption
   reads `TCP Retransmission Timings (only on JA4TScan)`. The deleted text agrees with the
   Wireshark dissector, which D6 records. **R2 stays uncertain and the vector fallback
   stays.** #215 item 4 owns the decision.
2. **It states the empty-field form that R11 records the image does not settle.** It reads
   `If any field does not exist, then the output is 00.` and it gives
   `JA4T = 1024_00_00_00`. `wireshark/source/packet-ja4.c:664` and the Zeek baseline both
   write that form, so the rule now holds two corroborations that are not the deleted file.
   `rust/ja4/src/tcp.rs` writes `8192__0_0` and `ja4plus` writes `8192_0_0_0`. **#215 item 1
   owns the decision, and this is the FoxIO prose it lacked.**

The deleted text also states four rules the image does not state: the interval of part e
rounds to the nearest second, a RST appends an `R` and its delay, a RST carries no window
size or option, and the state bound is 10 retransmissions with a timeout of 2 minutes.
**The state bound rests on the deleted file alone**, so it stays uncertain and it specifies
no bound of this project.

## The decisions this page raises

**#215 holds these decisions and #216 holds the conformance evidence.** Each item needs the
user, because each changes a fingerprint that this project publishes. This page changes no
fingerprinter.

1. **D1.** Which empty form does this project write? Rust writes `8192__0_0`, Wireshark and
   Zeek write `8192_00_00_00`, and this project writes `8192_0_0_0`.
2. **D2.** Reading the raw option bytes rather than scapy's parsed list repairs the pad-byte
   count. That changes a published fingerprint.
3. **D4.** Holding one JA4T value per connection changes the count this project emits.
4. **D6 and D7.** Does JA4TS carry part e? The image and the Wireshark dissector disagree.
