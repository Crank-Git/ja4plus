# JA4L

This page is this project's own prose form of `technical_details/JA4L.png`. It follows the
procedure in `docs/specs/foxio/README.md`. No image enters this repository.

| Item | Value |
|---|---|
| Source | `https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4L.png` |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-08 |
| SHA-256 of the image | `04036284edfcf0d8e94f3ca6660b1ab688813df7bfb82b0f001b65d7daa07354` |

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4L.png (retrieved 2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

Reproduce the hash from a checkout at the pinned commit.

```bash
shasum -a 256 technical_details/JA4L.png
```

## The image specifies the client form alone

**The image titles itself `JA4L: Light Distance/Location Fingerprint`.** The title names no
server form. It labels its one example `JA4L=`, and it states no separate server rule.

`docs/specs/foxio/README.md` recorded the presumption that `JA4L.png` carries the JA4LS
form, and it confirmed nothing. **This page answers the question: the image does not
specify JA4LS.** That is a finding, and the reader loses nothing that the reference
implementations do not supply. Two FoxIO-authored sources name JA4LS as a separate method.

- `technical_details/README.md:9` at the pinned commit reads
  `| JA4LatencyServer | JA4LS | Server to Client Latency Measurement / Light Distance |`.
- `README.md:50` at the pinned commit reads the same row.

`technical_details/` holds no `JA4LS.png`. The inventory in `docs/specs/foxio/README.md`
records that, and #195 measured it.

**The JA4T half of the presumption was true and the JA4L half is false.** `JA4T.png` titles
itself `JA4T/S: TCP Fingerprint`, so one image specifies both TCP methods.
`docs/specs/foxio/JA4T.md` holds that reading.

Compare this with the reading of JA4T, and do not read the two the same way. Every rule
below therefore describes the client form. The rules the server form follows come from the
reference implementations, and this page marks each one.

## The field layout

The image draws one example string and labels three parts `a`, `b` and `c`.

```
JA4L=5191_42_45014
     \__/ \_/ \___/
      a    b    c
```

| Part | The image's caption | Value in the example |
|---|---|---|
| a | One-way TCP latency in µs (1ms = 1,000µs) | `5191` |
| b | Observed TTL | `42` |
| c | One-way application handshake latency | `45014` |

The parts join with `_`.

The image lists four more statements beside the example.

- `Initial TTL 64   - Mac, Linux, Phones, IoT`
- `Initial TTL 128 - Windows`
- `Initial TTL 255 - Cisco, F5, Networking Devices`
- `Estimated Hop Count = Estimated Initial TTL - Observed TTL`

## The distance the image derives

The image states that a reader derives a distance from part a.

```
D = jc/p

D = Distance
j = JA4L_a (or delta between JA4L_a and JA4L_c in the case of VPNs)
c = Speed of light per µs in fiber (0.128 miles or 0.206 km per µs)
p = Propagation delay factor
```

It gives one propagation factor table.

| Hop Count | Propagation Delay Factor |
|---|---|
| `<=21` | 1.5 |
| 22 | 1.6 |
| 23 | 1.7 |
| 24 | 1.8 |
| 25 | 1.9 |
| `>=26` | 2.0 |

It works its own example, for a client that reaches the server through a VPN.

```
5191x0.128/1.6 = 415 miles (distance of VPN exit node from server)
45014-5191 = 39823µs (delta between client and VPN exit node)
39823x0.128/1.6 = 3,185 miles (distance of client from VPN exit node)
```

The image closes with `In this example, the VPN exit node was 402 miles from the server and
the client was 3,180 miles from the exit node.`

**The worked example is internally consistent, and that consistency confirms the reading of
the two tables.** Part b of the example is `42`. The initial TTL 64 gives an estimated hop
count of 22, and the table row for 22 gives the factor 1.6, which is the factor both
distance lines use. Internal consistency is not a corroboration, because it reads the image
alone.

## The rules

Each rule below states its corroborations. Neither corroboration is the image. Every
in-repository path names the FoxIO `ja4` repository at the pinned commit.

### R1 — JA4L reports one-way latency, so it halves every measured interval

- Corroboration 1: `python/common.py:179` to `python/common.py:182` defines `epoch_diff`,
  which returns `int((dt2-dt1).microseconds/2)`.
- Corroboration 2: `rust/ja4/src/time/tcp.rs:179` writes
  `let ja4l_c = (t_c.timestamp - t_b.timestamp) / 2;` and
  `rust/ja4/src/time/tcp.rs:182` writes `let ja4l_s = (t_b.timestamp - t_a.timestamp) / 2;`.

`wireshark/source/packet-ja4.c:1372` writes `latency.nsecs / 2 / 1000`, which agrees.

### R2 — Part a is the one-way latency, in microseconds

- Corroboration 1: `python/ja4.py:157` writes `f"{diff}_{ttl}"`, where `diff` comes from
  `epoch_diff` and `python/common.py:182` reads `.microseconds`.
- Corroboration 2: `rust/ja4/src/time/tcp.rs:186` writes
  `format!("{ja4l_c}_{client_ttl}", client_ttl = client_ttl.0)`.

### R3 — Part b is the observed TTL of the endpoint the value describes

The client value carries the TTL of the client SYN. The server value carries the TTL of the
server SYN-ACK.

- Corroboration 1: `python/ja4.py:566` stores `client_ttl` on the SYN and
  `python/ja4.py:569` stores `server_ttl` on the SYN-ACK. `python/ja4.py:159` reads
  `client_ttl` for `JA4L-C` and `python/ja4.py:156` reads `server_ttl` for `JA4L-S`.
- Corroboration 2: `wireshark/source/packet-ja4.c:1266` to
  `wireshark/source/packet-ja4.c:1276` stores `client_ttl` on the SYN, and
  `wireshark/source/packet-ja4.c:1279` to `wireshark/source/packet-ja4.c:1293` stores
  `server_ttl` on the SYN-ACK.

### R4 — The image states three parts, and two FoxIO implementations write three

**#225 settled this rule on 2026-08-08. `ja4plus` writes two timing parts.** The rule keeps
the vector fallback, and it now states the reason rather than an open question. Two FoxIO
implementations write three parts and two write two parts.

The user decided on the conformance evidence. Every one of the 114 JA4L values in
`tests/foxio_vectors/*.json` holds two parts, and `tests/foxio_vectors/wireshark_expected/`
holds two files that carry no JA4L key. A three-part form deviates from all 114
comparisons, which moves the register from 116 entries to 230 and leaves no case that
measures any JA4L value. **20 of the 114 sit on 10 captures that the Wireshark dissector
publishes no JA4L value for**, so those 20 would carry a third part that no reference
verifies.

A second reading blocks the adoption, and it is a finding of #225. **The Wireshark part c
is not computable where `ja4plus` writes a value.** `wireshark/source/packet-ja4.c:1370`
reads the interval from D to E for `ja4ls`, and
`wireshark/source/packet-ja4.c:1382` reads the interval from E to F for `ja4l`.
`wireshark/source/packet-ja4.c:1328`, `wireshark/source/packet-ja4.c:1343` and
`wireshark/source/packet-ja4.c:1366` set D, E and F on application packets. `ja4l.py`
emits the server value on the SYN-ACK and the client value on the first packet that carries
both relative numbers, and both points lead D. **Adopting part c is an emission-model
change and not a format change.** The dissector also publishes 44 values on each key where
the Python reference publishes 46 `JA4L-C` and 48 `JA4L-S`, so the two references emit on
different connections.

`docs/specs/spec.md` holds the `Divergence register` row.

- Corroboration 1: `wireshark/source/packet-ja4.c:1371` to
  `wireshark/source/packet-ja4.c:1374` writes the `JA4LS` field with `"%d_%d_%d"`, from the
  SYN to SYN-ACK interval, the server TTL, and the interval from the first client
  application packet to the first server application packet.
  `wireshark/source/packet-ja4.c:1381` to `wireshark/source/packet-ja4.c:1386` writes the
  `JA4L` field with the same three-part form.
- Corroboration 2: `zeek/ja4l/main.zeek:191-192` appends half the interval from the
  ClientHello to the ServerHello as the third part of `ja4ls`, and
  `zeek/ja4l/main.zeek:132-133` appends half the interval from the ServerHello to the first
  client data packet as the third part of `ja4l`. #198 owns that reading and
  `docs/specs/foxio/zeek.md` records it.

**The two other references write two parts.** `python/ja4.py:157`, `python/ja4.py:161` and
`python/ja4.py:165` each write `f"{diff}_{ttl}"`, and `rust/ja4/src/time.rs:18` to
`rust/ja4/src/time.rs:22` holds two fields and no third.

The measurement below states the size of the disagreement.

| Source | Part count | Sample |
|---|---|---|
| `python/test/testdata/` | 2 | `"JA4L-S": "18861_59"` |
| `rust/ja4/src/snapshots/` | 2 | `ja4l_c: 62_128`, `ja4l_s: 33804_227` |
| `wireshark/test/testdata/` | 3 on all 44 `ja4.ja4l` values and all 44 `ja4.ja4ls` values | `45_64_66`, under the `ja4.ja4l` key of `https-connect.pcap.json` |
| `zeek/tests/Traces/Scripts.ja4-conn/conn.log` | 3 | `ja4ls 18862_59_14792` |

**Every JA4L value this repository holds carries two parts.** Measured on 2026-08-08 across
`tests/foxio_vectors/*.json`: 114 values, 58 of `JA4L-S` and 56 of `JA4L-C`, in 24 files,
and each one holds two parts.

The authority rule decides the bytes this project writes, and it does not close the
question the image raises. `.claude/rules/conformance.md` states the rule, and #225 holds
the ruling.

**This measurement corrects a reading of #198.** `docs/specs/foxio/zeek.md` stated that the
Zeek script adds a third part that no other reference holds. #198 compared the Python
reference against the Zeek script, and it read neither the image nor
`wireshark/test/testdata/`. **Zeek is not the outlier on the part count.** This branch
corrects that section, and #198's measurement itself stands.

### R5 — The references disagree on what a connection with no application handshake writes

**#225 settled the QUIC half of this rule on 2026-08-08. `ja4plus` writes the `quic`
marker on a QUIC connection.** The HTTP half stays open, and `ja4plus` writes no `tcp`
literal.

The image draws one example, and that example carries all three parts. It states no rule
for a connection whose application handshake the reader cannot measure.

**The marker spells `quic`, and the spelling follows Wireshark.** Two FoxIO
implementations write a marker and they spell it differently.
`.claude/rules/external-apis.md:95` reads "Read no JA4L or JA4LS value of a Zeek baseline
as a reference value", and `.claude/rules/external-apis.md:101` names the `q` marker as one
of three Zeek divergences. The rule declines the Zeek spelling, so the Wireshark spelling
is the one published reading that remains.

| Source | Marker | Published values that carry it |
|---|---|---|
| `wireshark/source/packet-ja4.c:1441` and `:1447` | `quic` | 9 of the 44 `ja4.ja4l` values, and 9 of the 44 `ja4.ja4ls` values. |
| `zeek/ja4l/main.zeek:233` and `:252` | `q` | 14 values across the `conn.log` baselines. |
| `python/ja4.py:165` | none | Two parts on every connection. |
| `rust/ja4/src/time.rs` | none | Two parts on every connection. |

**The `tcp` literal is not adopted.** `wireshark/source/packet-ja4.c:1348` and
`wireshark/source/packet-ja4.c:1354` write it on an HTTP connection, and **none of the 88
published Wireshark values carries it**. The reading rests on the source alone, and no
vector proves it.

The change moves 36 values, all on a QUIC connection.
`chrome-cloudflare-quic-with-secrets.pcapng` holds 2, `ssh2.pcapng` holds 3,
`tls-handshake.pcapng` holds 20 and `tls3.pcapng` holds 11. **No TCP value moves.** The
register gains 16 entries, because `tls-handshake.pcapng` carries no JA4L key in its
expected-output file and the existing occurrence entry already covers its 20 values.

- `wireshark/source/packet-ja4.c:1348` and `wireshark/source/packet-ja4.c:1354` write
  `"%d_%d_tcp"` on an HTTP connection, and `wireshark/source/packet-ja4.c:1441` and
  `wireshark/source/packet-ja4.c:1447` write `"%d_%d_quic"` on a QUIC connection. The third
  part is then a protocol name and not a latency.
- `zeek/ja4l/main.zeek:232-233` and `zeek/ja4l/main.zeek:251-252` append the literal `q` on
  a QUIC connection. #198 owns that reading.
- `python/ja4.py:165` writes two parts on a QUIC connection, and `rust/ja4/src/time.rs`
  writes two parts everywhere.

### R6 — JA4L names the client method and JA4LS names the server method

- Corroboration 1: `technical_details/README.md:8` reads
  `| JA4Latency | JA4L | Client to Server Latency Measurment / Light Distance |` and
  `technical_details/README.md:9` reads
  `| JA4LatencyServer | JA4LS | Server to Client Latency Measurement / Light Distance |`.
- Corroboration 2: `README.md:49` and `README.md:50` at the pinned commit read the same two
  rows.

**The reference implementations write two spellings of the server name.** `python/ja4.py:157`
writes the output key `JA4L-S`, and `wireshark/source/packet-ja4.c:1735` registers the field
`ja4.ja4ls` under the display name `JA4LS`. `python/ja4.py` holds no `JA4LS` name at all.
This project writes `JA4L-S`, which follows the expected-output files.

### R7 — The delta the image names is a subtraction, and it is no part of the fingerprint

The image names one delta, `delta between JA4L_a and JA4L_c in the case of VPNs`, and its
worked example computes it as `45014-5191 = 39823µs`. The delta feeds the distance formula.
No part of the example string holds it.

- Corroboration 1: `wireshark/source/packet-ja4.c:1732` to
  `wireshark/source/packet-ja4.c:1737` registers `ja4.ja4l_delta` and `ja4.ja4ls_delta` as
  fields separate from `ja4.ja4l` and `ja4.ja4ls`.
- Corroboration 2: `zeek/ja4l/main.zeek:269` and `zeek/ja4l/main.zeek:274` write the
  `ja4l_delta` and `ja4ls_delta` columns of `conn.log`, separate from the `ja4l` and `ja4ls`
  columns. #198 owns that reading.

**The two implementations write a ratio, and the image states a subtraction.**
`wireshark/source/packet-ja4.c:1377` writes
`double delta = (double)latency2.nsecs / (double)latency.nsecs;` and rounds it with
`round(delta * 10.0) / 10.0`. `zeek/ja4l/main.zeek:269` writes
`fmt("%.1f", (c$fp$ja4l$first_client_data - c$fp$ja4l$server_hello) / client_denom)`. Each
one divides the part c interval by the part a interval. **The image therefore specifies
neither column.**

`ja4plus` publishes no delta value, and R7 asks for none.

### R8 — The initial TTL table rests on the image alone

**This rule is uncertain. It holds no corroboration.**

The image gives three initial TTL values: 64 for Mac, Linux, phones and IoT devices, 128 for
Windows, and 255 for Cisco, F5 and networking devices.

Measured on 2026-08-08 with `grep -rn` over the whole checkout at the pinned commit, outside
`zeek/`: no FoxIO source and no FoxIO document states the three values.

**One FoxIO code reading contradicts the low band.** `python/ja4.py:140` to
`python/ja4.py:147` defines `hops`, and `python/ja4.py:142` reads `initial_ttl = 54`. No line
of `python/ja4.py` calls `hops`, so no reference value rests on it.

### R9 — The hop count formula rests on one reading, and that reading is dead code

**This rule is uncertain. It holds one corroboration.**

The image states `Estimated Hop Count = Estimated Initial TTL - Observed TTL`.

- Corroboration 1: `python/ja4.py:147` returns `(initial_ttl - x)`, which is the same
  subtraction. The function is dead code, and its low band reads 54.

No second FoxIO source states the formula.

### R10 — The distance formula rests on the image alone

**This rule is uncertain. It holds no corroboration.**

The image states `D = jc/p`, with `c` as 0.128 miles or 0.206 kilometers per microsecond.

Measured on 2026-08-08 at the pinned commit, outside `zeek/`: `grep -rn "propagation"`
reports no match, `grep -rn "Hop Count"` reports no match, and `grep -rn "0\.128"` reports
only IP addresses.

### R11 — The propagation factor table rests on the image alone

**This rule is uncertain. It holds no corroboration.**

The six rows of the table appear in no FoxIO source and in no FoxIO document at the pinned
commit. The measurement is the one R10 states.

No rule of R8 to R11 builds a fingerprint. Each one feeds the distance a reader derives, so
an uncertain reading changes no published value.

## The comparison against this project

The comparison below reads `ja4plus/fingerprinters/ja4l.py` at commit `247275d`. **Every
field is named. A field this table does not name is a field nobody read.**

### The fields that agree

| Field | Rule | `ja4l.py` | Reading |
|---|---|---|---|
| The halving | R1 | `ja4l.py:44` and `ja4l.py:324` | Agrees. `LATENCY_DIVISOR = 2`, and `_one_way_latency` returns `int((end - start) / LATENCY_DIVISOR)`. |
| The rounding of part a | R1 | `ja4l.py:324` | Agrees with `python/common.py:182` and `rust/ja4/src/time/tcp.rs:179`, which truncate toward zero. `zeek/ja4l/main.zeek:158` rounds half to even, and #198 owns that difference. |
| Part a unit | R2 | `ja4l.py:299` to `ja4l.py:311` | Agrees. `_packet_microseconds` returns microseconds. |
| Part a, the server interval | R2 | `ja4l.py:409` and `ja4l.py:424` | Agrees. `JA4L-S` measures from the SYN to the SYN-ACK, as `python/ja4.py:155` does. |
| Part a, the client interval | R2 | `ja4l.py:439` | Agrees. `JA4L-C` measures from the SYN-ACK to the client measurement point, as `python/ja4.py:160` does. |
| Part b, the client TTL | R3 | `ja4l.py:403` | Agrees. The SYN supplies it. |
| Part b, the server TTL | R3 | `ja4l.py:420` | Agrees. The SYN-ACK supplies it. |
| Part b, the layer read | R3 | `ja4l.py:588` | Agrees. `get_ttl(packet)` reads the outer address layer, which is the layer each reference reads. |
| The separator | R2 and R3 | `ja4l.py:408`, `ja4l.py:423`, `ja4l.py:439`, `ja4l.py:504` and `ja4l.py:549` | Agrees. Each format string joins with `_`. |
| The client measurement point | R2 | `ja4l.py:433` | Agrees with `python/ja4.py:570`. Both require the relative sequence number 1 and the relative acknowledgement number 1. |
| The method names | R6 | `ja4l.py:408` and `ja4l.py:439` | Agrees with the expected-output files. This project writes `JA4L-S` and `JA4L-C`, as `python/ja4.py:157` and `python/ja4.py:161` do. |
| No delta value | R7 | absent from `ja4l.py` | Agrees. No delta is a fingerprint part, so this project needs no counterpart. |
| The initial TTL bands | R8 | `ja4l.py:243` to `ja4l.py:258` | Agrees with the image. `estimate_os` reads 64, 128 and 255, and it names the same three device groups. |
| The hop count formula | R9 | `ja4l.py:260` to `ja4l.py:275` | Agrees with the image. `estimate_hop_count` subtracts the observed TTL from the estimated initial TTL. It disagrees with `python/ja4.py:142`, which reads 54 for the low band and which nothing calls. |
| The distance formula | R10 | `ja4l.py:215` to `ja4l.py:227` | Agrees. `calculate_distance` returns `(latency_us * MILES_PER_MICROSECOND) / factor`. |
| The speed of light | R10 | `ja4l.py:72` and `ja4l.py:73` | Agrees. `MILES_PER_MICROSECOND = 0.128` and `KILOMETERS_PER_MICROSECOND = 0.206`. |
| The propagation factor table | R11 | `ja4l.py:57` to `ja4l.py:60` | Agrees, row for row. `PROPAGATION_FACTOR_TABLE` holds `(21, 1.5)`, `(22, 1.6)`, `(23, 1.7)`, `(24, 1.8)` and `(25, 1.9)`, `ja4l.py:211` tests `hop_count <= highest`, and `MAXIMUM_PROPAGATION_FACTOR = 2.0` covers 26 hops or more. |
| The worked example | R10 and R11 | `ja4l.py:227` | Agrees. `calculate_distance(5191, ttl=42)` returns 415.28 miles, and the image states `5191x0.128/1.6 = 415 miles`. |

### The disagreements

**D1 — `ja4l.py` writes two parts, and the image states three.**

`ja4l.py:408`, `ja4l.py:423`, `ja4l.py:439`, `ja4l.py:504` and `ja4l.py:549` each write
`"{}_{}"`. R4 states that the image labels three parts, and that the Wireshark dissector and
the Zeek script both write three.

Measured on 2026-08-08 in this worktree.

```
foxio wireshark/test/testdata/https-connect.pcap.json (ja4.ja4l) : 45_64_66
ja4plus JA4L-C on tests/foxio_vectors/https-connect.pcap          : 45_64
```

Part a and part b agree. This project publishes no part c.

**The Python reference and the Rust reference agree with this project**, and every one of
the 114 JA4L values in `tests/foxio_vectors/*.json` holds two parts. **#225 settled this on
2026-08-08: the two timing parts stay.** R4 holds the reason.

**D2 — `ja4l.py:227` computes no distance for the VPN case the image works.**

The image states `j = JA4L_a (or delta between JA4L_a and JA4L_c in the case of VPNs)`.
`calculate_distance` takes one latency and it reads no part c, because D1 leaves this project
with no part c to read. A caller therefore reaches the first distance line of the image's
example and neither of the other two.

This changes no fingerprint. It changes what a caller of `calculate_distance` can derive.

**D3 — `ja4l.py` writes no protocol part, and two references write one.**

R5 records that `wireshark/source/packet-ja4.c:1441` writes `_quic` and that
`zeek/ja4l/main.zeek:232-233` writes `q`. `ja4l.py:549` writes two parts on a QUIC
connection.

Measured on 2026-08-08 against
`tests/foxio_vectors/chrome-cloudflare-quic-with-secrets.pcapng`.

```
zeek Scripts.ja4-conn-quic/conn.log : 113_64_q
ja4plus JA4L-C                      : 113_64
foxio python/test/testdata/chrome-cloudflare-quic-with-secrets.pcapng.json : 113_64
```

**#225 settled this on 2026-08-08. `ja4plus` now writes `113_64_quic` on this connection.**
R5 holds the reason and the spelling reading, and #198 already recorded the Zeek half.

**D4 — `ja4l.py:416` to `ja4l.py:425` write a second server value for a retransmitted
SYN-ACK.**

The branch stores the measurement point only when the connection holds none, and it then
returns a value for every SYN-ACK it reads. A retransmitted SYN-ACK therefore produces a
second identical `JA4L-S`.

Measured on 2026-08-08 against `tests/foxio_vectors/ssh2.pcapng`.

```
foxio python/test/testdata/ssh2.pcapng.json : 10 JA4L-S values
ja4plus                                     : 11 JA4L-S values
The extra value is JA4L-S=6252_58, on tcp_172.16.225.48:57380_184.150.157.177:80.
The reference holds 6252_58 once, on stream 15.
```

The value agrees. The count does not. `.claude/rules/conformance.md` states that a method
that emits more fingerprints than the reference is a defect. The image states no emission
rule, so the specification does not decide D4.

## The register

**#225 added 16 entries on 2026-08-08, and the register now holds 22 JA4L entries.** Each
of the 16 names a QUIC connection where the marker is the whole difference, and each one
names #225. The register moved from 116 entries to 132, and the `xfailed` count moved with
it. The six entries below are the ones that predate #225, and all six stand unchanged.

`tests/foxio_deviations.json` holds 114 entries as of #193, and **six of them name this
method**. #193 removed six JA4H entries and no JA4L entry. The count of six is therefore
the same on the base of this page, where the register holds 120 entries. All six name #34.
#193
left all six unmarked on `batch/193-register-and-state-rule`, and the
audit read Changelog round 38 as the round that settled them. **Round 38 settled the stored
list and the return path of `process_packet`, and it did not settle these six.** The
measurement below states what each one is.

| Key | Cause the register states | Explained by the specification |
|---|---|---|
| `CVE-2018-6794.pcap/JA4L-C` | `ja4plus emits more JA4L-C values than the reference holds.` | **No.** |
| `CVE-2018-6794.pcap/JA4L-S` | `ja4plus emits more JA4L-S values than the reference holds.` | **No.** |
| `https-connect.pcap/JA4L-C` | `ja4plus emits more JA4L-C values than the reference holds.` | **No.** |
| `https-connect.pcap/JA4L-S` | `ja4plus emits more JA4L-S values than the reference holds.` | **No.** |
| `ssh2.pcapng/JA4L-S` | `ja4plus emits more JA4L-S values than the reference holds.` | **No.** |
| `tls-handshake.pcapng/JA4L-S` | `ja4plus emits more JA4L-S values than the reference holds.` | **No.** |

**The specification explains none of the six.** The image states the schema of one value and
the distance a reader derives from it. It states no rule about which connection produces a
value, and no rule about how many values a capture produces.

**Five of the six compare against a file that publishes no JA4L key at all.** Measured on
2026-08-08 over `tests/foxio_vectors/*.json`.

| Capture | Method keys the expected-output file holds | JA4L values it holds | `ja4plus` values |
|---|---|---|---|
| `CVE-2018-6794.pcap` | `JA4H`, `JA4H_ro` | 0 | 3 `JA4L-S`, 3 `JA4L-C` |
| `https-connect.pcap` | `JA4H`, `JA4H_ro` | 0 | 1 `JA4L-S`, 1 `JA4L-C` |
| `tls-handshake.pcapng` | `JA4`, `JA4_o`, `JA4_r`, `JA4_ro`, `JA4S`, `JA4S_r`, `JA4X` | 0 | 20 `JA4L-S` |
| `ssh2.pcapng` | twelve method keys, including `JA4L-C` and `JA4L-S` | 10 `JA4L-S`, 9 `JA4L-C` | 11 `JA4L-S`, 9 `JA4L-C` |

`python/ja4.py:339` reads
`if 'ja4l' not in output_types: delete_keys(['JA4L-S', 'JA4L-C'], final)`, and
`python/ja4.py:471` builds `output_types` from the command-line flags. **The reading is that
the three files were produced with a method filter**, and the key lists support it: two files
hold JA4H keys alone, and one holds JA4 keys, JA4S keys and JA4X keys alone. The upstream
files agree with the local copies. Measured on 2026-08-08 at the pinned commit: `grep -c
'"JA4L-'` reports 0 for `python/test/testdata/CVE-2018-6794.pcap.json`,
`python/test/testdata/https-connect.pcap.json` and
`python/test/testdata/tls-handshake.pcapng.json`, and 19 for
`python/test/testdata/ssh2.pcapng.json`.

**The `ssh2.pcapng/JA4L-S` entry is the one entry that compares two measured counts**, and
D4 states its cause and its evidence.

**The Wireshark reference does hold a value for two of the three filtered captures.**
`wireshark/test/testdata/https-connect.pcap.json` holds `"ja4.ja4l": ["45_64_66"]`, and
`.claude/rules/external-apis.md` states that `python/test/testdata/` decides where both hold
a value for one method on one connection. Here the Python file holds none.

## The search for a reference value

| Source searched | Result |
|---|---|
| `python/test/testdata/` | **114 `JA4L-C` and `JA4L-S` values, in 24 files.** Every value holds two parts, and none holds three. |
| `rust/ja4/src/snapshots/` | `ja4l_c` and `ja4l_s` values in 27 files. Every value holds two parts, and none holds three. |
| `wireshark/test/testdata/` | **44 `ja4.ja4l` values and 44 `ja4.ja4ls` values, 88 in all, in 15 files. Every one of the 88 holds three parts.** 9 of each key carry the literal `quic` as the third part, so 18 do, and the other 70 carry a latency. |
| `README.md` at the pinned commit | Lines 49 and 50 name the two methods. No example value. |
| `technical_details/README.md` | Lines 8 and 9 name the two methods. Line 34 embeds the image. No example value. |
| `zeek/` | Not searched here. #198 owns that survey, and it reports `ja4l` and `ja4ls` columns of three parts in the `conn.log` baselines. |

Reproduce the part counts from a checkout at the pinned commit.

```bash
grep -rhoE '"JA4L-[CS]": "[^"]+"' python/test/testdata/ | wc -l
grep -rhoE 'ja4l_[cs]: [^ ]+' rust/ja4/src/snapshots/ | sort | uniq -c
```

**Count the Wireshark values by walking the JSON, and not with a line pattern.** A file
under `wireshark/test/testdata/` prints one JSON value on its own line, and it carries two
keys, `ja4.ja4l` and `ja4.ja4ls`. A line pattern therefore reports a number whose key set
the reader cannot see, and two readers then disagree over one measurement. **Name the key
beside the number.**

```bash
python - <<'PY'
import collections, glob, json, os
per = collections.defaultdict(list)
def walk(node, name):
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("ja4.ja4l", "ja4.ja4ls"):
                for one in (value if isinstance(value, list) else [value]):
                    per[key].append((name, one))
            else:
                walk(value, name)
    elif isinstance(node, list):
        for item in node:
            walk(item, name)
for path in sorted(glob.glob("wireshark/test/testdata/*.json")):
    try:
        walk(json.load(open(path)), os.path.basename(path))
    except ValueError:
        continue
for key, values in per.items():
    parts = collections.Counter(len(str(v).split("_")) for _, v in values)
    print(key, len(values), "values in", len({f for f, _ in values}), "files", dict(parts))
PY
```

Measured on 2026-08-08 at the pinned commit: `ja4.ja4l` reports 44 values in 15 files, and
`ja4.ja4ls` reports 44 values in 15 files. Each key reports `{3: 44}`.

**This repository already holds 114 JA4L values**, in `tests/foxio_vectors/*.json`, across 24
captures. Reproduce that count from the root of this repository.

```bash
python - <<'PY'
import collections, glob, json
total = collections.Counter()
for path in glob.glob("tests/foxio_vectors/*.json"):
    document = json.load(open(path))
    if not isinstance(document, list):
        continue
    for stream in document:
        for key in stream:
            method = key.split(".")[0]
            if method in ("JA4L-C", "JA4L-S"):
                total[method] += 1
print(dict(total))
PY
```

## The conformance evidence a later issue can build

1. **`tests/foxio_vectors/rust_expected/` holds `ja4l_c` and `ja4l_s` values that no case
   reads.** `tests/test_foxio_rust_parity.py:72` reads
   `SNAPSHOT_METHODS = (("JA4", "ja4"), ("JA4S", "ja4s"))`. This is the shape #196 found for
   JA4T and #203 found for JA4H.
2. **D4 needs no new vector.** `ssh2.pcapng` measures it today, and the register entry
   already xfails on it.
3. **D1 needs no new vector either.** The 114 local values measure the part count on every
   run, and each one holds two parts.
4. **The Wireshark expected-output files are the only local route to a three-part value.**
   `tests/foxio_vectors/wireshark_expected/` holds two files today, and neither carries a
   JA4L key.

## The rulings this page raises

**#225 holds these rulings**, as #215 holds those of #196, #214 those of #198 and #219
those of #203. Each one needs the user, because each one changes a fingerprint that this
project publishes or changes a recorded cause. **This page changes no fingerprinter and no
register entry.**

1. **D1. Settled on 2026-08-08. `ja4plus` writes two timing parts.** R4 holds the reason
   and `docs/specs/spec.md` holds the `Divergence register` row.
2. **D3. Settled on 2026-08-08. A QUIC connection carries the `quic` marker.** R5 holds
   the reason and the spelling reading. A TCP connection carries no marker.
3. **D2. Open.** If part c stays absent, does `calculate_distance` keep an interface that
   cannot compute the VPN case the image works? #225 ruled on the part count and on the
   marker, and it ruled on neither D2 nor D4. **Both await a ruling.**
4. **D4. Settled on 2026-08-09. A retransmitted SYN-ACK produces no second `JA4L-S`.**
   #272 holds the ruling and the measurement. A retransmitted SYN-ACK moves neither
   point `B` nor the server TTL, so a second value repeats the first one and describes no
   second measurement. `ssh2.pcapng` stream 15 held `JA4L-S=6252_58` twice against one
   reference value, and a replay of the 38 committed captures moves that one value alone.
   `tests/foxio_deviations.json` holds `ssh2.pcapng/JA4L-S` no longer, because the counts
   now agree. `docs/specs/spec.md` holds the `Divergence register` row.
4. **Settled on 2026-08-09. Five register entries are declined, and the register records
   why.** `CVE-2018-6794.pcap`, `https-connect.pcap` and `tls-handshake.pcapng` hold no
   JA4L value, because a method filter produced the file. **This project was never emitting
   more than the reference. The reference published nothing to compare.** The comparison is
   unreachable, not satisfied. #272 declined the five on 2026-08-08, each cause cites
   `python/ja4.py:339`, and each entry carries `"decided": true` with `"capability": false`.
5. **R8 to R11 stay uncertain, and none of them builds a fingerprint.** The initial TTL
   table, the hop count formula, the distance formula and the propagation factor table rest
   on the image alone. `ja4l.py` follows the image on all four, and one dead FoxIO function
   contradicts the low band of the initial TTL table.
