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
2026-08-08.** The ruling reverses the D6 and D7 ruling of #215, which followed the
image. #226 holds the ruling and the measurement, and R12 below states the reading.
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
- `zeek/ja4t/main.zeek:229-235` appends the delay list to `c$conn$ja4ts`.

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

### R11 — The empty part b, the zero part c and the zero part d take the two-digit form

**The user decided this on 2026-08-08, and #215 built it.** The three FoxIO forms
disagree, so this is a reference split and the authority rule settles nothing. Two of the
three agree, and the user follows them. `ja4plus` writes `8192_00_00_00` for a SYN that
carries no option.

- `rust/ja4/src/tcp.rs` joins an empty option list to the empty string, and prints part c
  and part d with no padding. `ja4__insta@gre-erspan-vxlan.pcap.snap` holds `8192__0_0`.
- `wireshark/source/packet-ja4.c:664`, `ja4t()`, writes `00` for an empty option list,
  prints part c with `%02d`, and prints part d with `%02d` when the window scale is 0.
- The Zeek baseline follows the Wireshark form. `zeek/tests/Traces/Scripts.ja4-conn/conn.log`
  holds `ja4t 65535_00_00_00` and `ja4ts 65535_00_00_00`. #198 owns that reading and this
  page cites it rather than repeating the survey. `zeek/ja4t/main.zeek:195-211` states the
  same three rules for JA4T and repeats them for JA4TS.
- The deleted `technical_details/JA4T.md` states the rule in prose and corroborates the
  form a third time. It reads "If any field does not exist, then the output is 00." and
  gives `JA4T = 1024_00_00_00`. Its example table repeats the form three times:
  `Nmap | 1024_2_1460_00`, `Zmap | 65535_00_00_00` and `Web Scanner | 1024_00_00_00`.
  `docs/specs/foxio/deleted-text-specifications.md` holds the whole quotation.

**The prose and the two implementations part on one input, and `ja4plus` follows the
implementations.** The prose reads `00` as the mark of an absent field. The two
implementations read the value instead: `wireshark/source/packet-ja4.c:664` tests
`data->window_scale == 0`, and `zeek/ja4t/main.zeek:206-210` tests
`syn_opts$window_scale == 0`. Neither one records whether the packet carried the option,
because each stores the scale as an integer that defaults to zero. A packet that carries
a Window Scale option of value 0 therefore writes `00` in both implementations and `0`
under the prose alone. **7 of the 12 moved values are of that shape**, and
`gre-sample.pcap`, `sshv1.pcap` and `v6.pcap` each carry such a SYN or SYN-ACK. A
fingerprint exists so that one tool's output can be compared against another tool's
output, so `ja4plus` writes the value the two executable references write. The user cited
those two references on 2026-08-08, and the reading is reversible.

**State the cost, because the reading departs from the reference the harness compares
against.** The parity harness compares JA4T against the FoxIO Rust snapshots, and this
form diverges from every one of them where the two forms differ. 12 values across 6
captures take the new form, and 1 of the 12 reaches a comparison:
`gre-erspan-vxlan.pcap/0:65174/JA4T.1`, which stays in `tests/foxio_deviations.json` as a
decided divergence. The `Divergence register` in `docs/specs/spec.md` holds the whole
measurement.

The image settles none of this. It draws one example, and that example carries options, a
Maximum Segment Size and a non-zero window scale.

**The rule reaches three separate cases, and a reader who reads it as one case reads it
wrong.** A packet that carries options and a window scale of zero takes the two-digit part
d, and 7 of the 12 moved values are of that shape.

### R12 — JA4TS carries part e, and the fingerprint omits part e when the server answers once

**The user decided this on 2026-08-08, and the ruling reverses the D6 and D7 ruling of
#215.** R2 above names the three FoxIO sources. #226 built the reading.

Part e holds the delay between each SYN-ACK of one connection, in whole seconds, joined
with `-`. The deleted `technical_details/JA4T.md` states four rules, and this project
adopts all four.

1. **The fingerprint omits part e when it sees no retransmission.** The file reads: "If
   no retransmissions are seen, as there shouldn't be in normal network communications,
   the fingerprint will omit section e. If retransmissions are seen, the fingerprint
   will fill out section e." Part e is absent, and it is not `00`.
   `wireshark/source/packet-ja4.c:684` appends part e only when `syn_ack_count > 1`, and
   `zeek/ja4t/main.zeek:229` appends it only when the delay list holds a value. Both
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

### R13 — A RST appends `R` and its delay to part e

**Changelog round 79 records this reading, and #246 built it.** The deleted
`technical_details/JA4T.md` is the primary source, and two implementations corroborate
it. The file reads: "the final TCP packet, a RST packet, should be appended to the last
JA4TS denoted with 'R' and its delay." Its example ends
`65535_2-1-3-1-1-4_65495_8_1-2-4-8-R6`.

This project adopts four rules.

1. **A RST that the server sends appends `-R` and its delay to part e.** The delay is the
   interval since the last SYN-ACK, in whole seconds.
   `wireshark/source/packet-ja4.c:694` subtracts
   `conn->syn_ack_times[conn->syn_ack_count - 1]` from `conn->rst_time`, and
   `zeek/ja4t/main.zeek:233` subtracts `last_ts` from `rst_ts`. The delay rounds the way
   part e rounds, which R12 rule 2 states.
2. **A RST on a connection with no delay produces no value.** Both implementations nest
   the RST branch inside the delay branch. `wireshark/source/packet-ja4.c:693` reads
   `rst_time` only when `syn_ack_count > 1`, and `zeek/ja4t/main.zeek:232` reads `rst_ts`
   only when the delay list holds a value. A delay list is therefore complete and correct
   with no RST, which the deleted file's own second example shows: it ends at
   `62727_2_8961_00_1-2-4-8-16` and carries no RST.
3. **The RST value reads part a through part d from the stored connection.** The file
   reads: "Note that RST packets do not contain TCP options or window sizes, as such the
   program will need to be aware of the previous JA4TS."
   `wireshark/source/packet-ja4.c:1608` writes a second `JA4TS` value on the RST packet,
   and lines 1601 to 1607 restore `window_scale`, `window_size`, `mss_val` and
   `tcp_options` from the connection. `ja4plus` stores the parts of the **first** SYN-ACK,
   which `zeek/ja4t/main.zeek:177-178` also reads and never replaces. A retransmission
   repeats the SYN-ACK, so the two readings agree on real traffic.
4. **The RST value reads the same two bounds that part e reads.** The stored parts live in
   the connection table that R12 rule 4 bounds, and they add no table.
   `zeek/ja4t/main.zeek:162` drops the connection on the timeout before it reads the RST,
   so a RST that arrives more than two minutes after the last SYN-ACK produces no value.

**The two implementations disagree on the flag combination that names a RST packet, and
this project reads the bit.** `zeek/ja4t/main.zeek:167` tests `rph$tcp$flags & TH_RST`,
so any packet that carries the RST bit reaches the rule.
`wireshark/source/packet-ja4.c:1296` tests `tcp_flags == 0x004` for equality, so the
dissector reads no RST that also carries ACK. The deleted file writes "a RST packet" and
names no flag combination, so the prose and the Zeek script agree and the dissector reads
one case fewer. A RST that carries ACK is common on real traffic, and the narrow reading
would drop it.

**`ja4plus` emits no value for a RST on a connection with no delay, where the dissector
emits the four parts again.** `wireshark/source/packet-ja4.c:1599` writes the `JA4TS`
field whenever `syn == 3`, and `ja4t()` then omits part e. That second value repeats the
value the SYN-ACK already produced and describes no packet of its own, which
`.claude/rules/conformance.md` declines under its second shape. `zeek/ja4t/main.zeek`
writes one JA4TS value for one connection and never a second, so the Zeek package
corroborates the decline.

**A client RST produces no value.** Every SYN-ACK travels from the server, so the
connection key names the server first and a client RST reverses it.
`zeek/ja4t/main.zeek:189` sets the packet threshold with `F`, so the Zeek script reads
responder packets alone. The dissector reads either direction, because
`wireshark/source/packet-ja4.c:1296` holds no direction guard.

**No vector reaches this rule.** `tests/foxio_vectors/` holds 10 RST packets across its 38
captures, and none of the 10 sits on a connection with more than one SYN-ACK.
`ssh2.pcapng` holds the one connection of the set that the server answered twice, and the
server sent no RST on it. `tests/build_ja4ts_rst.py` therefore writes the capture from the
six capture times the deleted file lists, and `tests/test_ja4ts_reset.py` reads it back.

## The comparison against this project

The comparison below reads `ja4plus/fingerprinters/ja4t.py` and
`ja4plus/fingerprinters/ja4ts.py` at commit `3c01c94`. Every field is named. A field this
table does not name is a field nobody read.

**#215 moved part a through part d of both methods into
`ja4plus/utils/tcp_options.py`, so every line number below that names part a, part b,
part c or part d names the file as it stood before #215.** The reading each row records
still holds, and `tcp_prefix` is where the code now sits.

### JA4T — the fields that agree

| Field | Rule | `ja4t.py` | Reading |
|---|---|---|---|
| Part count and separator | R1 | `tcp_options.py`, `tcp_prefix` | Agrees. The format string is `"{}_{}_{:02d}_{}"`. |
| Part a, raw window | R3 | `tcp_options.py`, `tcp_prefix` | Agrees. `tcp.window` reads the unscaled field. |
| Part b order | R4 | `tcp_options.py`, `read_options` | Agrees. The loop keeps wire order and nothing sorts it. |
| Part b separator | R4 | `tcp_options.py`, `tcp_prefix` | Agrees. `"-".join(...)`. |
| Part c absent | R6 | `tcp_options.py`, `read_options` | Agrees on the value and diverges on the form. The default is 0, and R11 writes it as `00`. |
| Part d absent | R7 | `tcp_options.py`, `read_options` | Agrees on the value and diverges on the form. The default is 0, and R11 writes it as `00`. |
| Packet selection | R8 | `ja4t.py`, `generate_ja4t` | Agrees. SYN set and ACK clear, tested as a mask. |
| ECN on a SYN | R10 | `ja4t.py`, `generate_ja4t` | Agrees with `tcp.rs`. Disagrees with the dissector, which R10 marks uncertain. |
| Part e | R2 | absent from `ja4t.py` | Agrees. JA4T carries no timing part. |
| One value for one connection | R9 | `ja4t.py`, `_first_syn_of_connection` | Agrees. The connection table reads the first SYN alone. |

### JA4T — the disagreements, all five repaired

**#215 landed all five on 2026-08-08.** The user ruled on D1, D2 and D4. D3 and D5 are
plain defects and rode with them. `ja4plus/utils/tcp_options.py` now holds part a through
part d for both methods, so one reader answers all five.

**D1 — repaired. `ja4t.py` writes the two-digit form.**

The old expression `options_str = "-".join(options) if options else "0"` produced
`8192_0_0_0`, which matched no reference. R11 above states the decided rule and names the
three FoxIO forms.

Measured on 2026-08-08 against `tests/foxio_vectors/gre-erspan-vxlan.pcap`, which this
repository already holds.

```
FoxIO rust ja4__insta@gre-erspan-vxlan.pcap.snap : 8192__0_0
ja4plus before #215                              : 8192_0_0_0
ja4plus after #215                               : 8192_00_00_00
```

**This value diverges from the FoxIO Rust snapshot on purpose**, so the register keeps
`gre-erspan-vxlan.pcap/0:65174/JA4T.1` and marks it decided.

**D2 — repaired. `ja4t.py` reads the raw TCP option bytes.**

The SYN of `tests/foxio_vectors/chrome-cloudflare-quic-with-secrets.pcapng` carries the
option bytes `020405a0010303060101080a88d73b2c0000000004020000`. The wire kinds are
`2, 1, 3, 1, 1, 8, 4, 0, 0`. Scapy reports
`[('MSS', 1440), ('NOP', None), ('WScale', 6), ('NOP', None), ('NOP', None), ('Timestamp', (2295806764, 0)), ('SAckOK', b''), ('EOL', None)]`,
which holds one `EOL` for two `0x00` bytes.

```
FoxIO rust ja4__insta@chrome-cloudflare-quic-with-secrets.pcapng.snap : 65535_2-1-3-1-1-8-4-0-0_1440_6
ja4plus before #215                                                   : 65535_2-1-3-1-1-8-4-0_1440_6
ja4plus after #215                                                    : 65535_2-1-3-1-1-8-4-0-0_1440_6
```

The reading follows R5, and 16 values across the vector set move to the reference form.

**D3 — repaired. Part b holds every option kind.**

The old loop mapped six names: `MSS`, `NOP`, `WScale`, `SAckOK`, `Timestamp` and `EOL`. It
appended nothing for any other kind. R4 states that both references append every kind. A
SYN that carries kind 5, kind 28, kind 30 or kind 34 therefore produced a part b that
omitted it. No vector in this repository carries such an option, so
`tests/test_ja4t_form.py` holds two constructed cases instead.

**D4 — repaired. One connection produces one JA4T value.**

R9 states that the reference reads only the first SYN of a connection. `ja4t.py` now holds
a connection table, and that table carries a maximum entry count of 10000 and a maximum
age of 600 seconds.

Measured on 2026-08-08 against `tests/foxio_vectors/ssh2.pcapng`.

```
FoxIO rust ja4__insta@ssh2.pcapng.snap : 19 ja4t values, for 19 connections
ja4plus before #215                    : 44 values, over the same 19 connections
ja4plus after #215                     : 19 values, over the same 19 connections
```

10 connections produced more than one value. `.claude/rules/conformance.md` states that a
method that emits more fingerprints than the reference is a defect. The distinct values
agreed before the repair, so D4 changed the count and no value.

**D4 reaches JA4T alone.** R12 rule 3 states that a JA4TS value grows with each SYN-ACK,
so JA4TS keeps one value for each SYN-ACK packet.

**D5 — repaired. A repeated option keeps the first value.**

The old lines `mss = str(int(opt[1]))` and `wscale = str(opt[1])` ran inside the loop, so a
second Maximum Segment Size option overwrote the first. `rust/ja4/src/tcp.rs` calls
`.next()` on the field iterator, which keeps the first. No vector in this repository
carries a repeated option, so `tests/test_ja4t_form.py` holds two constructed cases
instead.

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

**#215 repaired D1, D2, D3 and D5 on JA4TS too.** `ja4ts.py` repeated the body of
`ja4t.py`, so it repeated all four. Both methods now call `tcp_prefix` in
`ja4plus/utils/tcp_options.py`, which holds part a through part d once. The FoxIO
references build the two methods from one function as well: `ja4t()` in
`wireshark/source/packet-ja4.c` serves both fields, and `zeek/ja4t/main.zeek:195-236`
repeats one block. 13 JA4TS values across the vector set moved, and the `Divergence
register` in `docs/specs/spec.md` holds the count.

Two disagreements belong to JA4TS alone.

**D6 — repaired. `ja4ts.py` writes part e.**

`wireshark/source/packet-ja4.c:1595` writes the `JA4TS` field through `ja4t()` with a
connection, so the dissector appends the SYN-ACK retransmission intervals when the
connection holds more than one SYN-ACK. The image states that part e appears only on
JA4TScan. **The user decided against the image on 2026-08-08**, and #226 built part e.
R12 states the rule and R2 names the three FoxIO sources.

**D7 — measured. `ja4ts.py` writes no value on a RST, and the Wireshark dissector writes
one.**

`wireshark/source/packet-ja4.c:1295` marks a RST, and line 1608 writes a second `JA4TS`
value from the stored connection values, with the `-R<interval>` suffix. The image's
example part e ends with `R6`, which corroborates the suffix shape. `ja4ts.py` reads the
SYN-ACK alone and reaches no RST.

**#226 measured that D7 separates from D6, so #246 owns D7.** R13 states the measurement.

**#515 brought D7 into the conformance suite, and it reaches 6 of the 58 Wireshark JA4TS
values.** Every one of the 6 sits on a connection the server answered once, so the
dissector writes the four parts again with no part e. R13 rule 2 states that a RST on a
connection with no delay produces no value in this project, and
`.claude/rules/conformance.md` declines a value that describes no packet of its own.
`tests/foxio_deviations.json` holds the 6 keys under #246, each marked decided.

| Register key | Frame | The value the dissector repeats |
|---|---|---|
| `browsers-x509.pcapng/2:54603/JA4TS.2` | 174 | `64400_2-1-3-4-0-0_1400_2` |
| `https3-301-get.pcap/0:62599/JA4TS.2` | 20 | `14240_2-4-8-1-3_1436_10` |
| `https3-301-get.pcap/0:62599/JA4TS.3` | 21 | `14240_2-4-8-1-3_1436_10` |
| `https3-301-get.pcap/0:62599/JA4TS.4` | 23 | `14240_2-4-8-1-3_1436_10` |
| `ssh2.pcapng/5:57368/JA4TS.2` | 849 | `42600_2-1-1-4-1-3_1300_9` |
| `ssh2.pcapng/5:57368/JA4TS.3` | 850 | `42600_2-1-1-4-1-3_1300_9` |

`TestTheDifferencesAreTheRecordedResetDecline` measures three facts of each row, so the
decline stays proven rather than asserted. Each frame carries the RST flag alone, each
value equals the value the first SYN-ACK of that stream produced, and `ja4plus` writes one
value for the stream.

## The search for a reference value

The issue that produced this page stated that no Rust snapshot holds a JA4T or a JA4TS
value. **The measurement contradicts that statement for JA4T.**

| Source searched | Result |
|---|---|
| `rust/ja4/src/snapshots/` | **64 `ja4t` values in 26 files, 19 of them distinct.** No `ja4ts` value. |
| `wireshark/test/testdata/` | **118 `ja4.ja4t` values and 58 `ja4.ja4ts` values, in 24 of the 37 files.** #515 corrected this row, and the section below states the correction. |
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
| `test_every_register_entry_matches_a_collected_case` | The one JA4T register entry matches no case. #215 left one entry, and #216 and #242 read two. |

## What the comparison reports

**#216 and #242 read 37 of the 39 values as exact and two as different. #215 landed the
rulings, and the reading is now 38 of 39 exact and one decided divergence.** No value
the register does not name disagrees.

| Capture | Values | Result before #215 | Result after #215 |
|---|---|---|---|
| `browsers-x509.pcapng` | 3 | Each value matches. | Each value matches. |
| `chrome-cloudflare-quic-with-secrets.pcapng` | 1 | D2. The value differs by one `0`. | The value matches. |
| `gre-erspan-vxlan.pcap` | 1 | D1. The value differs in part b. | D1. The value differs in part b, part c and part d, and the user decided it. |
| `https-connect.pcap` | 1 | The value matches. | The value matches. |
| `latest.pcapng` | 6 | Each value matches. | Each value matches. |
| `ssh2.pcapng` | 19 | Each value matches, and D4 makes 10 streams carry more than one. | Each value matches, and each stream carries one. |
| `tls3.pcapng` | 8 | Each value matches. | Each value matches. |

One register entry remains, and #215 marked it decided.

| Key | Issue | The reading it records | State |
|---|---|---|---|
| `gre-erspan-vxlan.pcap/0:65174/JA4T.1` | 215 | D1 | Decided. `ja4plus` writes `8192_00_00_00` and the snapshot holds `8192__0_0`. |

The D2 entry and the D4 entry left the register when #215 landed, because each case
resolves to a pass. The register falls from 137 keys to 135.

**D3 and D5 reach no local snapshot value.** They need a SYN that no local capture
carries, so `tests/test_ja4t_form.py` holds constructed cases for both. #242 brought D1
into the comparison, and "The snapshot the comparison now reaches" section below records
how.

## JA4TS reaches a FoxIO reference value, and #515 committed it

**This section held the reading `JA4TS stays uncovered` until 2026-08-10.** That reading
rested on one wrong row of the table above, and this section states the correction. The
superseded wording is quoted below rather than rewritten.

> **JA4TS therefore reaches no FoxIO reference value in this repository.** Its only
> reference values are the Zeek baselines, which #198 owns and `docs/specs/foxio/zeek.md`
> records.

**No local Rust snapshot holds a `ja4ts` field**, and that half of the reading stands. The
measurement of 2026-08-08 reads all eleven files under `tests/foxio_vectors/rust_expected/`
and finds none. No FoxIO Python expected-output file holds a `JA4T` key or a `JA4TS` key
either. `TestTheLocalSnapshotsHoldNoJa4tsValue` states both facts as checks, so a vector
refresh that adds a `ja4ts` field fails and names the file.

**The FoxIO Wireshark dissector writes 58 JA4TS values, and the earlier reading searched
for the wrong key.** The dissector writes the field name `ja4.ja4ts`, and a search for
`ja4ts` alone finds it. The earlier search read the key `ja4t`, which the directory holds
nowhere. Reproduce the count from a checkout at the pinned commit.

```bash
grep -c '"ja4.ja4ts"' wireshark/test/testdata/*.json
```

`tests/foxio_vectors/wireshark_expected/` now holds the 24 files that carry a value, and
`tests/test_foxio_wireshark_ja4ts.py` compares all 58 against `ja4plus`. **52 values match
byte for byte and 6 reach the register**, and all 6 are the RST decline that R13 records.
`tests/foxio_vectors/zeek_expected/` holds the seven Zeek baselines beside them, and
`tests/test_foxio_zeek_ja4ts.py` compares 9 of their 10 JA4TS values.

**Two FoxIO implementations therefore corroborate JA4TS, and they agree on the one
connection both read.** `ipv6.pcapng` is that connection. The dissector writes
`65535_2-1-1-4-1-3_1346_10`, which is the value `ja4plus` writes, and the Zeek baseline
writes `65535_00_00_00` from the `DLT_NULL` defect that `docs/specs/foxio/zeek.md` proves.
**The dissector is the second FoxIO source that reads the options of that packet**, so it
corroborates the defect from outside the Zeek script.

**Warning: no value of either source carries a delay list of more than one delay, so part e
stays measured by a constructed case alone.** The self-review of #515 mutated the
separator of the delay list in `ja4plus/fingerprinters/ja4ts.py`, from `"-".join(...)` to
`",".join(...)`, and no case of the 58 Wireshark values or the 9 adopted Zeek values
failed. **The gap belongs to the FoxIO material and not to the two modules.** No capture
of the vector set holds a connection the server answered three times, which "What part e
moved" below already measures: the largest reading is two SYN-ACKs.
`tests/test_ja4ts_part_e.py` therefore keeps the constructed cases that measure the
separator, the rounding rule and both bounds.

**Read this as the reason part e moved no conformance case in 2026-08-08.** #226 added part
e, and the conformance suite reported 116 `xfailed` before the change and 116 after,
against 116 keys in `tests/foxio_deviations.json`. No case compared a JA4TS value then,
so none could move. **A case compares one now**, and the suite reports 140 `xfailed`
against 140 keys.

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
4. **JA4TS reaches two FoxIO reference sources. Done, and #515 corrected this item.** The
   item read that no Wireshark expected-output file holds a JA4TS value, and the directory
   holds 58 of them. No Rust snapshot holds one, which stands. #198 owns the Zeek reading,
   and "JA4TS reaches a FoxIO reference value, and #515 committed it" above holds the
   measurement and the correction.

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
   2026-08-08, and #226 built part e.** R12 states the rule. The ruling reverses the
   #215 ruling of the same day, which followed the image.
2. **It states the empty-field form that R11 records the image does not settle.** It reads
   `If any field does not exist, then the output is 00.` and it gives
   `JA4T = 1024_00_00_00`. `wireshark/source/packet-ja4.c:664` and the Zeek baseline both
   write that form, so the rule now holds two corroborations that are not the deleted file.
   `rust/ja4/src/tcp.rs` writes `8192__0_0` and `ja4plus` writes `8192_0_0_0`. **#215 item 1
   owns the ruling, and this is the FoxIO prose it lacked.**

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

## The rulings this page raises

**#215 holds these rulings. #216 and #242 hold the conformance evidence.** Each item needs the
user, because each changes a fingerprint that this project publishes. This page changes no
fingerprinter.

1. **D1.** Which empty form does this project write? Rust writes `8192__0_0`, Wireshark and
   Zeek write `8192_00_00_00`, and this project writes `8192_0_0_0`. #242 committed the
   one local snapshot that measures it, and the register key
   `gre-erspan-vxlan.pcap/0:65174/JA4T.1` carries the case.
2. **D2.** Reading the raw option bytes rather than scapy's parsed list repairs the pad-byte
   count. That changes a published fingerprint.
3. **D4.** Holding one JA4T value per connection changes the count this project emits.
4. **D6 — decided on 2026-08-08, and #226 built it.** JA4TS carries part e. The user
   read #221's finding and reversed the #215 ruling of the same day. R12 states the
   rule. **D7 stays open**, and #246 owns it, because #226 measured that the RST value
   separates from part e. R13 states the measurement.
