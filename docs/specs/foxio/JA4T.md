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

**This rule holds for JA4T alone. JA4TS carries part e, and the user decided that on
2026-08-08.** The decision reverses the D6 and D7 ruling of #215, which followed the
image. #226 holds the decision and the measurement, and R12 below states the reading.
`ja4plus/fingerprinters/ja4ts.py` writes part e.

The image is the one source that keeps part e off JA4TS. Three FoxIO sources put it
there, and no source ever corrected them.

- The deleted `technical_details/JA4T.md` heads its form
  `__JA4TS and JA4TScan Fingerprint formats:__` and writes
  `WindowSize_TCPOptions_MSSValue_WindowScale_TimeSinceLastSYNACK`. `b6f3ff4` deleted
  the file on 2024-02-22 and no commit restored it, so the statement stands as
  FoxIO-authored under the rule #221 established.
- `wireshark/source/packet-ja4.c:1595` writes the `JA4TS` field through `ja4t()` with a
  connection, and `ja4t()` appends part e at line 684 whenever the connection holds more
  than one SYN-ACK.
- `zeek/ja4t/main.zeek:227-236` appends the delay list to `c$conn$ja4ts`.

**The image's own example contradicts its caption.** The caption reads
`TCP Retransmission Timings (only on JA4TScan)`, and the example value `1-2-4-8-R6`
carries the `R` suffix that the deleted file defines for a JA4TS RST.

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

### R12 — JA4TS carries part e, and the fingerprint omits part e when the server answers once

**The user decided this on 2026-08-08, and the decision reverses the D6 and D7 ruling of
#215.** R2 above names the three FoxIO sources. #226 built the reading.

Part e holds the delay between each SYN-ACK of one connection, in whole seconds, joined
with `-`. The deleted `technical_details/JA4T.md` states four rules, and this project
adopts all four.

1. **The fingerprint omits part e when it sees no retransmission.** The file reads: "If
   no retransmissions are seen, as there shouldn't be in normal network communications,
   the fingerprint will omit section e. If retransmissions are seen, the fingerprint
   will fill out section e." Part e is absent, and it is not `00`.
   `wireshark/source/packet-ja4.c:684` appends part e only when `syn_ack_count > 1`, and
   `zeek/ja4t/main.zeek:227` appends it only when the delay list holds a value. Both
   corroborate the omission.
2. **Each delay is the interval since the last SYN-ACK, rounded to the nearest whole
   second.** The file reads: "we start with the timestamp of the first SYNACK and
   subtract it from the next SYNACK, rounding the result to the nearest whole number in
   seconds." `timediff` in `wireshark/source/packet-ja4.c` calls the C `round`, which
   carries a half away from zero, and `ja4plus` reads the same rule. A negative half
   rounds away from zero too, because a capture that holds a SYN-ACK out of order
   produces a negative delay.
   **`zeek/ja4t/main.zeek:180` truncates instead**, because it divides an integer count
   of microseconds. The prose and the dissector agree, so `ja4plus` follows them.
3. **A fingerprint grows with each SYN-ACK.** The file lists the value that each SYN-ACK
   of its example produces, from `62727_2_8961_00` through `62727_2_8961_00_1-2-4-8-16`.
   `ja4plus` emits one JA4TS value for each SYN-ACK, so it reproduces the sequence.
4. **The state holds ten retransmissions and a timeout of two minutes.** The file reads:
   "The max is 10 retransmissions counted and the timeout is 2 minutes after the last
   SYNACK." `zeek/ja4t/main.zeek:185` stops at ten delays and corroborates the count.
   **`MAX_SYN_ACK_TIMES` in `wireshark/source/packet-ja4.c:234` stores ten timestamps,
   which holds nine delays**, so the dissector reads one fewer than the prose states.
   The prose and Zeek agree at ten, and `ja4plus` follows them. No vector reaches the
   bound, because the largest reading in `tests/foxio_vectors/` is two SYN-ACKs.

**The RST suffix stays out of this rule.** R13 records it.

### R13 — The RST value of JA4TS is not built, and #246 owns it

The deleted file states that a RST appends `R` and its delay to part e, and that a RST
packet carries no window size and no option, so the reader needs the previous JA4TS.
`wireshark/source/packet-ja4.c:1608` writes a second `JA4TS` value on the RST, and it
rebuilds part a through part d from the stored connection.

**The RST value separates from part e, and #226 measured the separation.** Both
implementations nest the RST branch inside the delay branch:
`wireshark/source/packet-ja4.c:693` reads `rst_time` only when `syn_ack_count > 1`, and
`zeek/ja4t/main.zeek:233` reads `rst_ts` only when the delay list holds a value. A delay
list is therefore complete and correct with no RST, which the deleted file's own second
example shows: it ends at `62727_2_8961_00_1-2-4-8-16` and carries no RST. The RST value
also needs two things part e does not: a reader of RST packets, and stored part a
through part d for a packet that carries neither.

No vector reaches this rule. `tests/foxio_vectors/` holds one connection with more than
one SYN-ACK, and the server sent no RST on it.

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
| Part count and separator | R1 | `ja4ts.py:253` | Agrees. Part a through part d match JA4T, and part e follows them. |
| Part a, raw window | R3 | `ja4ts.py:224` | Agrees. |
| Part b order | R4 | `ja4ts.py:232` | Agrees. |
| Part b separator | R4 | `ja4ts.py:250` | Agrees. |
| Part c absent | R6 | `ja4ts.py:228` | Agrees. |
| Part d absent | R7 | `ja4ts.py:229` | Agrees. |
| Packet selection | R8 | `ja4ts.py:220` | Agrees. `tcp.flags & 0x12 == 0x12` selects the SYN-ACK. |
| Part e, delay list | R12 | `ja4ts.py:169` | Agrees. `_part_e` writes the delay list and omits it when the server answers once. |
| Part e, state bound | R12 | `ja4ts.py:18` | Agrees. Ten delays, and a timeout of two minutes. |
| RST value | R13 | none | **Absent.** #246 owns it. |

### JA4TS — the disagreements

`ja4ts.py` repeats the body of `ja4t.py`, so it repeats D1, D2, D3 and D5 at
`ja4ts.py:250`, `ja4ts.py:232`, `ja4ts.py:234` to `ja4ts.py:247`, and `ja4ts.py:236` with
`ja4ts.py:241`. Two disagreements belong to JA4TS alone. **#226 added part e above that
body, so every line number in this section moved.**

**D6 — repaired. `ja4ts.py` writes part e.**

`wireshark/source/packet-ja4.c:1595` writes the `JA4TS` field through `ja4t()` with a
connection, so the dissector appends the SYN-ACK retransmission intervals when the
connection holds more than one SYN-ACK. The image states that part e appears only on
JA4TScan. **The user decided against the image on 2026-08-08**, and #226 built part e.
R12 states the rule and R2 names the three FoxIO sources.

**D7 — open. `ja4ts.py` writes no value on a RST, and the Wireshark dissector writes one.**

`wireshark/source/packet-ja4.c:1295` marks a RST, and line 1608 writes a second `JA4TS`
value from the stored connection values, with the `-R<interval>` suffix. The image's
example part e ends with `R6`, which corroborates the suffix shape. `ja4ts.py` reads the
SYN-ACK alone and reaches no RST.

**#226 measured that D7 separates from D6, so #246 owns D7.** R13 states the measurement.

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

**Seven of those 26 snapshot files already sit in this repository**, under
`tests/foxio_vectors/rust_expected/`, beside the captures that produce them. They hold 39
of the 64 values. #216 held six of the seven, and #242 added
`ja4__insta@gre-erspan-vxlan.pcap.snap`.

| Capture in `tests/foxio_vectors/` | `ja4t` values in the local snapshot |
|---|---|
| `browsers-x509.pcapng` | 3 |
| `chrome-cloudflare-quic-with-secrets.pcapng` | 1 |
| `gre-erspan-vxlan.pcap` | 1 |
| `https-connect.pcap` | 1 |
| `latest.pcapng` | 6 |
| `ssh2.pcapng` | 19 |
| `tls3.pcapng` | 8 |

## Why the suite reported no deviation, and what #216 changed

**#216 closed this gap on 2026-08-08.** The text below records both states, because the
gap is the finding and the repair is the evidence.

Before #216, `tests/test_foxio_rust_parity.py:72` read two methods from a snapshot.

```python
SNAPSHOT_METHODS = (("JA4", "ja4"), ("JA4S", "ja4s"))
```

**The snapshots this project already held carried `ja4t` values, and the harness never read
the field.** No other test compared a JA4T value or a JA4TS value against a FoxIO value, so
`tests/foxio_deviations.json` held no entry for either method. The JA4T cases in
`tests/test_comprehensive.py` build a packet with scapy and assert this project's own
format, so no reference decides them.

This is the shape `.claude/rules/conformance.md` names under "Ask whether a case can fail".

`tests/test_foxio_rust_parity.py` now reads three methods.

```python
SNAPSHOT_METHODS = (("JA4", "ja4"), ("JA4S", "ja4s"), ("JA4T", "ja4t"))
```

`TestTheJa4tValuesTheRustSnapshotHolds` collected 38 value cases and 6 occurrence-key
cases from the six local snapshots #216 held. #242 added the seventh snapshot, so the
class now collects 39 value cases and 7 occurrence-key cases. Each case carries a
register key, so a disagreement another issue owns reports as `xfailed`.

**The revert proves the cases run.** Remove `("JA4T", "ja4t")` from `SNAPSHOT_METHODS` and
46 cases stop running, 39 value cases and 7 occurrence-key cases. Three checks then fail
and name the loss.

| Check that fails on the revert | What it reports |
|---|---|
| `test_the_local_snapshots_hold_the_thirty_nine_values_the_reading_counts` | The snapshot reader finds no JA4T value. |
| `test_the_suite_collects_one_case_for_every_value_the_snapshots_hold` | The parameter list is empty. |
| `test_every_register_entry_matches_a_collected_case` | The two JA4T register entries match no case. |

## What the comparison reports

**37 of the 39 values reproduce exactly, and two differ.** No value the register does
not name disagrees. Neither #216 nor #242 changed a file under `ja4plus/`, and #215 owns
all three entries.

| Capture | Values | Result |
|---|---|---|
| `browsers-x509.pcapng` | 3 | Each value matches. |
| `chrome-cloudflare-quic-with-secrets.pcapng` | 1 | D2. The value differs by one `0`. |
| `gre-erspan-vxlan.pcap` | 1 | D1. The value differs in part b. |
| `https-connect.pcap` | 1 | The value matches. |
| `latest.pcapng` | 6 | Each value matches. |
| `ssh2.pcapng` | 19 | Each value matches, and D4 makes 10 streams carry more than one. |
| `tls3.pcapng` | 8 | Each value matches. |

The three register entries are these.

| Key | Issue | The reading it records |
|---|---|---|
| `chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4T.1` | 215 | D2 |
| `gre-erspan-vxlan.pcap/0:65174/JA4T.1` | 215 | D1 |
| `ssh2.pcapng/JA4T` | 215 | D4 |

**D3 and D5 reach no local snapshot value.** They need a SYN that no local capture
carries. #242 brought D1 into the comparison, and "The snapshot the comparison now
reaches" section below records how.

## JA4TS stays uncovered

**No local Rust snapshot holds a `ja4ts` field.** The measurement of 2026-08-08 reads all
eleven files under `tests/foxio_vectors/rust_expected/` and finds none, which confirms the
count in "The search for a reference value" above. No FoxIO Python expected-output file
holds a `JA4T` key or a `JA4TS` key either.

**JA4TS therefore reaches no FoxIO reference value in this repository.** Its only
reference values are the Zeek baselines, which #198 owns and `docs/specs/foxio/zeek.md`
records. `TestTheLocalSnapshotsHoldNoJa4tsValue` states both facts as checks, so a vector
refresh that adds a `ja4ts` field fails and names the file.

**This is why part e moved no conformance case.** #226 added part e, and the conformance
suite reported 116 `xfailed` before the change and 116 after, against 116 keys in
`tests/foxio_deviations.json`. No case compares a JA4TS value, so none could move.

## The snapshot the comparison now reaches

**`ja4__insta@gre-erspan-vxlan.pcap.snap` measures D1, and #242 committed it.** #216 read
the file at the pinned commit and declined to commit it, because the two references name
the stream by different addresses.

| Reference | Addresses it names |
|---|---|
| `python/test/testdata/gre-erspan-vxlan.pcap.json` | `100.20.9.2` and `100.20.9.1` |
| `rust/ja4/src/snapshots/ja4__insta@gre-erspan-vxlan.pcap.snap` | `10.16.27.12` and `10.16.27.131` |

The capture carries GRE, ERSPAN and VXLAN, so one packet holds three address layers. The
measurement of 2026-08-08 reads the outer pair `100.20.9.2` and `100.20.9.1`, the middle
pair `172.16.27.131` and `172.16.27.121`, and the inner pair `10.16.27.12` and
`10.16.27.131`. The ports `65174` and `80` come from the inner layer, and both references
name them.

**`ja4plus` reports the outer pair with the inner ports**, which is the pair the FoxIO
Python file reports. The measurement gives one JA4T entry:

```
{'fingerprint': '8192_0_0_0', 'src': '100.20.9.2', 'dst': '100.20.9.1', 'srcport': 65174, 'dstport': 80}
```

### Which address pair names the stream

**The outer pair names the stream, and no fingerprinter changes.** Rule 1 of `CLAUDE.md`
states that the specification decides intent and schema, and that the vectors decide the
exact bytes where intent runs out. Here the two FoxIO references disagree with each other,
so no vector decides. The ALPN disputed region of #162 settled this shape: a move is
forbidden where the two implementations disagree. `ja4plus` already matches the FoxIO
Python file, so the present behaviour stands.

### How the harness names the stream

**`tests/test_foxio_rust_parity.py` records the pair in `SNAPSHOT_ADDRESS_ALIASES`.** The
map holds the identity the Rust snapshot names, and it returns the identity `ja4plus`
produces. `read_rust_snapshot` reads the map for every stream of every snapshot.

Three identities reach this capture, and the map is the narrowest of them.

| Identity | What it stops measuring |
|---|---|
| The port pair alone | Every address. `ssh2.pcapng` holds 19 JA4T streams, and a port pair matches any stream that shares it. |
| The value alone, with no stream | The whole stream attribution. A value that moves to another stream still passes. |
| The recorded address pair | Nothing. A wrong address on either side finds no entry, so the case reports `ja4plus=<none>` and fails. |

`TestTheStreamIdentityOfTheTunneledCapture` holds seven checks that measure each part of
the map. `test_a_stream_the_alias_does_not_name_finds_no_entry` substitutes a wrong
address, a wrong source port and a wrong destination port, and it checks that each one
reaches nothing. `test_the_alias_moves_no_other_capture` checks that the map renames no
stream of the other ten snapshots.

**The D1 measurement is now a conformance case.** `ja4plus` produces `8192_0_0_0` for the
SYN of `tests/foxio_vectors/gre-erspan-vxlan.pcap`, and the snapshot holds `8192__0_0`.
The register key `gre-erspan-vxlan.pcap/0:65174/JA4T.1` names #215, and it carries
`strict=True`, so the case fails the suite the moment #215 lands.

## The conformance evidence a later issue can build

**#216 owned this work, and it landed on 2026-08-08. #242 extended it the same day.**

1. **JA4T needs no new file. Done.** `SNAPSHOT_METHODS` holds `("JA4T", "ja4t")` and the
   suite compares the 39 local values. D1, D2 and D4 report, and each one is a register
   entry that names #215.
2. **Nineteen more snapshots reach the remaining 25 values.** The captures are in the
   FoxIO `pcap/` directory and this repository holds several of them already. This work is
   open.
3. **`gre-erspan-vxlan.pcap` is the one case that measures the empty part b. Done.** #242
   committed the snapshot and recorded the stream identity, and "The snapshot the
   comparison now reaches" above states the mechanism.
4. **JA4TS reaches no FoxIO reference value except the Zeek baseline. Measured.** No Rust
   snapshot and no Wireshark expected-output file holds one. #198 owns the Zeek reading,
   and "JA4TS stays uncovered" above holds the measurement.

## What the deleted text specification adds

**FoxIO published `technical_details/JA4T.md`, 6423 bytes, and `b6f3ff4` deleted it on
2024-02-22.** #221 read it, and `docs/specs/foxio/deleted-text-specifications.md` holds the
whole reading and the provenance. **This page rewrites no rule above.** The deleted file is
not the pinned specification, so the image outranks it.

The deleted text carries two findings for this page.

1. **It contradicts the image on part e of JA4TS.** Its form for JA4TS reads
   `WindowSize_TCPOptions_MSSValue_WindowScale_TimeSinceLastSYNACK`, and the image's caption
   reads `TCP Retransmission Timings (only on JA4TScan)`. The deleted text agrees with the
   Wireshark dissector, which D6 records. **The user decided for the deleted text on
   2026-08-08, and #226 built part e.** R12 states the rule. The decision reverses the
   #215 ruling of the same day, which followed the image.
2. **It states the empty-field form that R11 records the image does not settle.** It reads
   `If any field does not exist, then the output is 00.` and it gives
   `JA4T = 1024_00_00_00`. `wireshark/source/packet-ja4.c:664` and the Zeek baseline both
   write that form, so the rule now holds two corroborations that are not the deleted file.
   `rust/ja4/src/tcp.rs` writes `8192__0_0` and `ja4plus` writes `8192_0_0_0`. **#215 item 1
   owns the decision, and this is the FoxIO prose it lacked.**

The deleted text also states four rules the image does not state: the interval of part e
rounds to the nearest second, a RST appends an `R` and its delay, a RST carries no window
size or option, and the state bound is 10 retransmissions with a timeout of 2 minutes.
**#226 read the blob again and found a second corroboration for three of the four**, so
R12 adopts them and states each source. `zeek/ja4t/main.zeek:185` stops at ten delays,
which corroborates the retransmission count. The two-minute timeout still rests on the
deleted file alone, and `ja4plus` adopts it because no other source states any timeout.
The two RST rules stay unbuilt, and #246 owns them.

## What part e moved

#226 replayed all 38 captures under `tests/foxio_vectors/` through `Processor`, before
the change and after it, and compared every value.

| Reading | Before | After |
|---|---|---|
| Values the 38 captures produce | 803 | 803 |
| Values that differ | — | **1** |
| Zeek JA4TS rows that match | 9 of 10 | 9 of 10 |
| Keys in `tests/foxio_deviations.json` | 116 | 116 |
| `xfailed` in the conformance suite | 116 | 116 |

**One value moved, and it is a JA4TS value.** `ssh2.pcapng` packet index 372, which is frame 373 in a one-based reader, moves from
`64240_2-1-1-4-1-3_1460_7` to `64240_2-1-1-4-1-3_1460_7_0`. No value of another method
moved, so part e reaches nothing it should not reach.

**One connection in the whole vector set carries more than one SYN-ACK.** It is
`184.150.157.177:80` to `172.16.225.48:57380` in `ssh2.pcapng`. The server answered at
1688672871.347960 and again at 1688672871.353789, and the interval of 0.005829 s rounds
to `0`. Packet 369 is the first SYN-ACK and keeps four parts, which R12 rule 1 requires.

**The bounds of R12 reach no vector.** The largest reading is two SYN-ACKs, against a
bound of ten, and the largest interval is 0.005829 s, against a timeout of two minutes.
`tests/test_ja4ts_part_e.py` therefore carries the constructed cases that measure them.

## The decisions this page raises

**#215 holds these decisions and #216 holds the conformance evidence.** Each item needs the
user, because each changes a fingerprint that this project publishes. This page changes no
fingerprinter.

1. **D1.** Which empty form does this project write? Rust writes `8192__0_0`, Wireshark and
   Zeek write `8192_00_00_00`, and this project writes `8192_0_0_0`.
2. **D2.** Reading the raw option bytes rather than scapy's parsed list repairs the pad-byte
   count. That changes a published fingerprint.
3. **D4.** Holding one JA4T value per connection changes the count this project emits.
4. **D6 — decided on 2026-08-08, and #226 built it.** JA4TS carries part e. The user
   read #221's finding and reversed the #215 ruling of the same day. R12 states the
   rule. **D7 stays open**, and #246 owns it, because #226 measured that the RST value
   separates from part e. R13 states the measurement.
