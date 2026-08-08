# The Zeek package as a fourth reference

FoxIO ships a Zeek package under `zeek/` in `https://github.com/FoxIO-LLC/ja4`. The
package implements eight methods, and it carries seven baselines under
`zeek/tests/Traces/`. This page records what the package holds and which capture produced
each baseline. It also compares each baseline value against the value `ja4plus` produces
on the same capture.

| Item | Value |
|---|---|
| Source | `https://github.com/FoxIO-LLC/ja4/tree/main/zeek` |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-08 |
| Author line | `# Zeek script by Jo Johnson`, in every `main.zeek` |
| License | FoxIO License 1.1, in every `main.zeek` |

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/zeek (retrieved 2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

No file of the reference changed. No file under `ja4plus/` changed, and no fingerprint
moved.

## What the package implements

`zeek/config.zeek` enables each method with one option. `zeek/README.md` names the log
that carries each method.

| Method | Zeek module | Enabled by default | Log |
|---|---|---|---|
| JA4 | `ja4/` | yes | `ssl.log` |
| JA4S | `ja4s/` | yes | `ssl.log` |
| JA4H | `ja4h/` | yes | `http.log` |
| JA4L | `ja4l/` | yes | `conn.log`, column `ja4l` |
| JA4LS | `ja4l/` | yes | `conn.log`, column `ja4ls` |
| JA4T | `ja4t/` | yes | `conn.log`, column `ja4t` |
| JA4TS | `ja4t/` | yes | `conn.log`, column `ja4ts` |
| JA4SSH | `ja4ssh/` | yes | `ja4ssh.log` |
| JA4D | `ja4d/` | yes | `ja4d.log` |
| JA4D6 | none | no | `zeek/README.md` states "awaiting Zeek DHCPv6 suppport" |
| JA4X | `ja4x/` | **no** | `zeek/README.md` states "awaiting Zeek object support" |

**`zeek/ja4x/__load__.zeek` holds the single line `# empty`.** `zeek/config.zeek:29` sets
`option JA4X_enabled: bool = F`. The Zeek package implements no JA4X and no JA4D6, so it
corroborates neither method.

The Zeek `conn.log` also carries two columns that no other reference holds, `ja4l_delta`
and `ja4ls_delta`. The section `The three readings of the audit` below states what they
hold.

## Which capture produced each baseline

`zeek/tests/btest.cfg` sets `TRACES=%(testbase)s/../../pcap`, so every baseline reads a
capture from the `pcap/` directory of the same checkout. Each test script names its
capture on its first line. Read the capture for a baseline with one command, from the
root of a checkout at the pinned commit.

```bash
grep -n "@TEST-EXEC: zeek" zeek/tests/Scripts/*.zeek
```

| Baseline | Test script | Capture | This project holds it |
|---|---|---|---|
| `Scripts.ja4-conn/conn.log` | `ja4-conn.zeek` | `ipv6.pcapng` | yes |
| `Scripts.ja4-conn-tls3/conn.log` | `ja4-conn-tls3.zeek` | `tls3.pcapng` | yes |
| `Scripts.ja4-conn-quic/conn.log` | `ja4-conn-quic.zeek` | `chrome-cloudflare-quic-with-secrets.pcapng` | yes |
| `Scripts.ja4-dhcp/ja4d.log` | `ja4-dhcp.zeek` | `dhcp.pcapng` | yes |
| `Scripts.ja4-http1-with-cookies/http.log` | `ja4-http1-with-cookies.zeek` | `http1-with-cookies.pcapng` | yes |
| `Scripts.ja4-ssh2/ja4ssh.log` | `ja4-ssh2.zeek` | `ssh2.pcapng` | yes |
| `Scripts.ja4-tls-handshake/ssl.log` | `ja4-tls-handshake.zeek` | `tls-handshake.pcapng` | yes |

**Every baseline names its capture, and this project holds all seven captures under
`tests/foxio_vectors/`.** No baseline is unattributable, and the page states no guess.

## How to reproduce the comparison

`tests/compare_zeek_baselines.py` reads a baseline, runs `ja4plus` on the same capture,
and prints one row for each connection and method. Run it from the root of a checkout,
with the path to a `FoxIO-LLC/ja4` checkout at the pinned commit.

```bash
python tests/compare_zeek_baselines.py <path-to-FoxIO-ja4-checkout>
```

**The current reading is 98 rows, of which 63 match and 35 differ.** #327 ran the script
on 2026-08-08 against a checkout at the pinned commit, and it read those counts.

**Every count this page states for this comparison rests on the run of #327.** The table
below names the round that records each run, so a reader can tell a current count from a
stale one. A count of this comparison that names no round is a stale count.

| Run | Rows | Match | Differ | Changelog round |
|---|---|---|---|---|
| The first run, on #198 | 98 | 62 | 36 | 52 |
| The re-run of #324 | 98 | 63 | 35 | `TBD`, the row of #324 |
| The re-run of #327 | 98 | 63 | 35 | `TBD`, the row of #327 |

**#324 repaired the script on 2026-08-08, and the repair is why the two later runs could
run.** #49 removed the composite `source` field the reader read, so the script raised
`KeyError` on the first output line between round 52 and the repair. The reader now reads
`src_ip`, `src_port`, `dst_ip` and `dst_port`, which `docs/output-schema.md` states.

**One row moved since round 52, and it is JA4SSH.** #214 landed, so `ssh2.pcapng` now
produces `c36s52_c42s76_c51s2` as its second value, which the Zeek baseline holds. Every
other method reads the same as the table below.

**`tests/test_compare_zeek_baselines.py` runs the script over `dhcp.pcapng`, so a later
change to the output schema fails a case instead of breaking the script in silence.** The
case writes its own baseline in the Zeek TSV form, because this repository holds no Zeek
baseline.

## What the comparison measured

One row holds one connection and one method. A row holds every value that connection
produced for that method, so the two JA4D rows carry four values. **The run of #327
produced this table**, and the round table above names the round that records the run.

| Method | Rows compared | Rows that match |
|---|---|---|
| JA4 | 20 | 20 |
| JA4S | 20 | 20 |
| JA4H | 1 | 1 |
| JA4D | 2 | 2 |
| JA4T | 10 | 8 |
| JA4TS | 10 | 9 |
| JA4SSH | 1 | 1 |
| JA4L | 17 | 1 |
| JA4LS | 17 | 1 |

**JA4, JA4S, JA4H and JA4D match on every value.** The 20 JA4 values and the 20 JA4S
values of `tls-handshake.pcapng` are the largest independent corroboration this project
holds for the two methods outside `python/test/testdata/`.

**JA4SSH matches on its one row.** #214 made `ja4plus` emit the window a connection holds
open when the capture ends, so both values now equal the two the Zeek baseline holds.
"JA4SSH: `ssh2.pcapng` produces two values here, and the Zeek baseline holds both" below
states the reading.

**JA4TS matches on nine of ten rows, and this is the first external comparison the method
has ever had.** #196 cites this reading.

**#226 added part e to JA4TS on 2026-08-08, and it re-ran this comparison. JA4TS still
matches on nine of ten rows.** The reading above is unchanged, and "The part e reading of
#226" below states why, with the measurement.

## The differences, with the cause of each

### JA4T: Zeek reads no TCP option on a capture whose link type is not Ethernet

`ipv6.pcapng` produces `65535_00_00_00` for both JA4T and JA4TS in the Zeek baseline.
`ja4plus` produces `65535_2-1-3-1-1-8-4-0_1346_6` and `65535_2-1-1-4-1-3_1346_10`.

**This is a proven defect of the Zeek script, not a disagreement about JA4T.**
`zeek/ja4t/main.zeek:66-68` returns an empty option record when the link layer is not
Ethernet.

```
  if (rph$l2$encap != LINK_ETHERNET) {
    return opts;
  }
```

The link type of `ipv6.pcapng` is `0`, which is `DLT_NULL`. Two commands measure it.

```bash
python -c "from scapy.all import PcapReader; r = PcapReader('tests/foxio_vectors/ipv6.pcapng'); print(r.linktype)"
python -c "from scapy.all import rdpcap, TCP; print(rdpcap('tests/foxio_vectors/ipv6.pcapng')[0][TCP].options)"
```

The first prints `0`. The second prints the eight options the SYN packet carries, which
begin `('MSS', 1346)` and end `('EOL', None)`. The packet holds the options, and the
Zeek script never reads them. `ja4plus` reads them.

### JA4T: `ja4plus` records TCP option kind 0 and Zeek stops at it

`chrome-cloudflare-quic-with-secrets.pcapng` produces `65535_2-1-3-1-1-8-4_1440_6` in the
Zeek baseline and `65535_2-1-3-1-1-8-4-0_1440_6` in `ja4plus`. The one difference is the
trailing `-0`, which is the End Of Option List, TCP option kind 0.

`zeek/ja4t/main.zeek:95-98` leaves the option loop at kind 0 and records nothing for it.

```
    local opt_kind = bytestring_to_count(pkt$data[offset]);
    if (opt_kind == 0) {
      break;
    }
```

**FoxIO's own JA4TScan documentation records option kind 0 inside the option list**, so
`ja4plus` follows the reference and the Zeek script does not. The `README.md` of
`FoxIO-LLC/ja4tscan` at commit `d01bfec4e64366d37ae95982a5068a5b41ca43b0` gives
`65535_2-1-3-1-1-8-4-0-0_1460_6` for `Mac OSX / iPhone` and
`16384_2-1-3-1-1-8-1-1-4_1460_00_2-7` for `Windows 2003`.

The remaining eight JA4T rows and nine JA4TS rows match byte for byte.

### JA4L and JA4LS: Zeek rounds the halved latency and `ja4plus` truncates it

Eight values differ by one microsecond. `zeek/ja4l/main.zeek:158` converts the halved
interval with `double_to_count`, and `ja4plus/fingerprinters/ja4l.py:324` truncates it
toward zero.

The eight values sit on five connections. `ipv6.pcapng` holds one, on `ja4ls`.
`chrome-cloudflare-quic-with-secrets.pcapng` holds one, on `ja4ls`. `tls3.pcapng` holds
six, two on each of `172.253.122.95:443`, `192.168.1.169:63250` and
`192.168.1.169:63251`.

A measurement of the eight TCP connections of `tls3.pcapng` settles the rule Zeek
applies. The table below holds every connection whose half-interval lands exactly on
`.5`, and Zeek rounds each one to the even value. Two of the four therefore round down,
and the `ja4plus` value matches those two.

| Connection | Exact half-interval | Truncated | Rounded half to even | Zeek |
|---|---|---|---|---|
| `192.168.1.169:63250` | 36549.5 | 36549 | 36550 | 36550 |
| `192.168.1.169:63251` | 34691.5 | 34691 | 34692 | 34692 |
| `192.168.1.169:63253` | 36498.5 | 36498 | 36498 | 36498 |
| `192.168.1.169:63255` | 33738.5 | 33738 | 33738 | 33738 |

**On the rounding rule, the FoxIO Python reference agrees with `ja4plus` and the Zeek
script is the outlier.** `tests/foxio_vectors/ipv6.pcapng.json` holds `JA4L-S` as
`18861_59`, and the Zeek baseline holds `18862_59_14792`. The exact half-interval is
18861.5. `tests/foxio_vectors/chrome-cloudflare-quic-with-secrets.pcapng.json` holds
`JA4L-S` as `5749_56`, and the Zeek baseline holds `5750_56_15994`. The exact
half-interval is 5749.583.

The authority rule decides it. `python/test/testdata/` decides the exact bytes, so
`ja4plus` needs no change. **No fingerprint moves for this difference.**

**Read that sentence for the rounding rule alone. It does not hold for the part count**,
and the section below states the correction #200 measured.

### JA4L and JA4LS: the third part, and the correction #200 made to this section

**This section first read that the Zeek script adds a third part that no other reference
holds. That heading was wrong, and #200 measured the correction.** The specification
carries a third part, and so does the Wireshark reference. #198 compared the Python
reference against the Zeek script. It read neither `technical_details/JA4L.png` nor
`wireshark/test/testdata/`, so it saw two of the five readings below. The measurement
#198 made is correct. The conclusion it drew from two sources does not survive the
other three.

| Source | Parts |
|---|---|
| `technical_details/JA4L.png`, the specification | **three** |
| `wireshark/test/testdata/`, the `ja4.ja4l` and `ja4.ja4ls` keys | **three** |
| `zeek/tests/Traces/`, the `ja4l` and `ja4ls` columns | **three** |
| `python/test/testdata/` | two |
| `ja4plus` | two |

**The Zeek script is therefore not the outlier on the part count.** The specification and
two implementations write three parts, the Python reference writes two, and this project
follows the Python reference.

- The image labels three parts, and it captions the third `One-way application handshake
  latency`. `docs/specs/foxio/JA4L.md` holds the transcription, and #200 read the image.
- `wireshark/test/testdata/https-connect.pcap.json:58-59` holds
  `"ja4.ja4l": [` and `"45_64_66"`. **Every `ja4.ja4l` value and every `ja4.ja4ls` value
  under `wireshark/test/testdata/` holds three parts**: 44 of each key, 88 in all, in 15
  files. 9 of each key carry the literal `quic` as the third part. Measured on 2026-08-08
  by walking the JSON of each file, and not with a line pattern.
  `docs/specs/foxio/JA4L.md` holds the command and states why the method matters.
- `zeek/ja4l/main.zeek:191-192` appends half the interval from the ClientHello to the
  ServerHello to `ja4ls`, for example `18862_59_14792`. `zeek/ja4l/main.zeek:132-133`
  appends a third part to `ja4l` in the same way, and that part is half the interval from
  the ServerHello to the first client data packet.

**The FoxIO Python reference publishes the two-part form, and `ja4plus` emits it.**
`tests/foxio_vectors/ipv6.pcapng.json` holds `JA4L-S` as `18861_59` and `JA4L-C` as
`3911_64`. Each value carries two parts, and so does every one of the 114 JA4L values
this repository holds. **The authority rule keeps the two-part form today and no
fingerprint moves**, because no vector this project reads measures a third part. #225
holds the decision, and the user decides it.

`ja4plus` reports a second measurement as a second `JA4L-C` value where the Zeek script
reports it as a third part. The two implementations measure different intervals, so the
numbers do not correspond: `ipv6.pcapng` gives `3911` in `ja4plus` and `14792` in the
Zeek third part.

### JA4L and JA4LS: the Zeek script marks a QUIC connection with a `q` part

The Zeek baselines carry `113_64_q` and `10990_56_q` on a QUIC connection.
`zeek/ja4l/main.zeek:232-233` and `zeek/ja4l/main.zeek:251-252` append the literal `q`.
`ja4plus` emits `113_64` and `10990_56`, and
`tests/foxio_vectors/chrome-cloudflare-quic-with-secrets.pcapng.json` holds the same two
values. The Python reference holds no `q` part. The authority rule decides it, and no
fingerprint moves.

### JA4L: the Zeek script holds a client value for one stream that the Python file omits

`tls3.pcapng` stream `192.168.1.169:61884` carries `271_128_q` in the Zeek baseline.
`tests/foxio_vectors/tls3.pcapng.json` holds `JA4L-S` as `3583_57` for the same stream
and holds no `JA4L-C`. `ja4plus` emits no client value for it, so `ja4plus` matches the
Python reference. This page records the Zeek value and asks for no change.

### JA4SSH: `ssh2.pcapng` produces two values here, and the Zeek baseline holds both

| Source | First value | Second value |
|---|---|---|
| `python/test/testdata/ssh2.pcapng.json` | `c36s36_c76s124_c74s5` | `c36s36_c0s0_c2s0` |
| Zeek baseline | `c36s36_c76s124_c74s5` | `c36s52_c42s76_c51s2` |
| `ja4plus` | `c36s36_c76s124_c74s5` | `c36s52_c42s76_c51s2` |

The first value matches across all three implementations.

**#214 closed and this row now matches.** #214 made JA4SSH emit the window a connection
holds open when the capture ends, so `ja4plus` writes the second value the Zeek baseline
holds. The run of #327 reads the row as a match. "What the comparison measured" above
therefore reads one JA4SSH row compared and one matched.

**The two references still disagree about the second value, and `ja4plus` follows the
Zeek script.** `tests/foxio_deviations.json` declines the Python second value under #97,
at the key `ssh2.pcapng/14:57377/JA4SSH.2`. `c0s0` states that the window holds no SSH
packet. A fingerprint that describes no traffic is one of the two shapes
`.claude/rules/conformance.md` declines. The Zeek second value holds 42 client packets
and 76 server packets, so **it describes real traffic and falls outside the shape #97
declined.**

`zeek/ja4ssh/main.zeek:160-164` emits the value from `connection_state_remove`, so the
Zeek script always writes the window a connection holds open when it closes.

**This page held one open decision, and #214 closed it.** The value rating of the JA4SSH
baseline rested on that decision, and "The rating this baseline now needs" below states
what the closure leaves open.

### The Zeek log columns `ja4l_delta` and `ja4ls_delta` are ratios, not fingerprints

`zeek/ja4l/main.zeek:269` and `zeek/ja4l/main.zeek:274` write each column with
`fmt("%.1f", ...)`. Each column holds one interval divided by another interval, and no
part of any JA4L fingerprint reads it. The Zeek script writes both columns as an empty
string on a QUIC connection, from `zeek/ja4l/main.zeek:263-265`.

**Neither column is a fingerprint, and `ja4plus` needs no counterpart.** The audit that
opened #198 read them as a possible gap, and this measurement answers it.

## The three readings of the audit

The issue body of #198 stated three readings. Each one is confirmed against the file, and
each one is answered.

1. **`JA4T` and `JA4TS` hold a reference value.** Confirmed. The three `conn.log`
   baselines hold 10 JA4T values and 10 JA4TS values. **JA4TS matches `ja4plus` on nine
   of ten rows, and the tenth is the `DLT_NULL` defect of the Zeek script.** The reading
   holds after #226 added part e, and "The part e reading of #226" states the
   measurement. JA4T matches
   on eight of ten. Two rules cause the two that differ: the same `DLT_NULL` defect, and
   the option kind 0 rule that FoxIO's own JA4TScan documentation settles.
2. **`ja4ls` carries three parts where `python/test/testdata/` carries two.** Confirmed.
   The Python reference and `ja4plus` both carry two parts, and the Zeek script carries a
   third. The authority rule decides it in favour of the two-part form.
   **#200 corrected the conclusion this reading drew.** The Zeek script is not alone: the
   specification labels three parts and every value under `wireshark/test/testdata/`
   holds three. This reading compared two sources of five, and the section above states
   the measurement. #225 holds the decision.
3. **`ja4l_delta` and `ja4ls_delta` appear in no other reference.** Confirmed. Both are
   ratios that the Zeek script writes with `%.1f`, and neither is part of a fingerprint.

## Which baselines are usable as vectors

A baseline is usable where this project holds the capture it read. This project holds all
seven captures, so all seven baselines are usable. The value of each one differs.

| Baseline | Methods it would add | Value |
|---|---|---|
| `Scripts.ja4-conn-tls3/conn.log` | JA4T, JA4TS | **High.** It holds eight JA4T values and eight JA4TS values that `ja4plus` matches byte for byte, and no other reference holds one. |
| `Scripts.ja4-conn-quic/conn.log` | JA4TS | **High.** It holds the one JA4TS value on a capture the vector set already reads. |
| `Scripts.ja4-tls-handshake/ssl.log` | JA4, JA4S | Medium. It corroborates 20 JA4 values and 20 JA4S values that `python/test/testdata/` already covers. |
| `Scripts.ja4-dhcp/ja4d.log` | JA4D | Low. `tests/foxio_vectors/wireshark_expected/` already holds the same four values, and `.claude/rules/external-apis.md` records the match. |
| `Scripts.ja4-http1-with-cookies/http.log` | JA4H | Low. One value that `python/test/testdata/` already holds. |
| `Scripts.ja4-conn/conn.log` | none | **None.** Its JA4T and JA4TS values come from the `DLT_NULL` defect, and its JA4L values come from the Zeek rounding rule. |
| `Scripts.ja4-ssh2/ja4ssh.log` | JA4SSH | **Undecided.** #214 closed, so this baseline is no longer blocked. "The rating this baseline now needs" below states the question, and the user decides it. |

**A later issue adds them. This issue adds none.** Three things are needed to add one.

1. A directory beside `tests/foxio_vectors/wireshark_expected/` and
   `tests/foxio_vectors/rust_expected/`, holding a copy of each baseline.
2. A precedence rule in `.claude/rules/external-apis.md`, of the shape the Wireshark and
   Rust rules already have. The rule must state that `python/test/testdata/` outranks a
   Zeek baseline where both hold a value for one method on one connection.
3. A reader for the Zeek TSV form. `tests/compare_zeek_baselines.py` holds one.

**A JA4L or JA4LS value of any Zeek baseline is not usable as a vector.** The Zeek
rounding rule and the Zeek third part both diverge from the Python reference.

### The rating this baseline now needs

**The `Blocked` rating of `Scripts.ja4-ssh2/ja4ssh.log` rested on #214, and #214 closed.**
The rating no longer follows from its evidence. #327 states that and writes no
replacement, because the replacement is a precedence question and not a count. The user
decides it.

Three measured facts frame the question, and the run of #327 holds each one.

1. `ja4plus` and the Zeek baseline agree on both JA4SSH values of `ssh2.pcapng`, so the
   baseline corroborates the method that #214 settled.
2. `python/test/testdata/ssh2.pcapng.json` holds `c36s36_c0s0_c2s0` as the second value,
   and `tests/foxio_deviations.json` declines it under #97 at the key
   `ssh2.pcapng/14:57377/JA4SSH.2`.
3. `.claude/rules/external-apis.md` states that `python/test/testdata/` decides where it
   and a Zeek baseline both hold a value for one method on one connection. It names no
   exception for a value the register declines.

**The question is whether a Zeek baseline may hold the reference JA4SSH value for a
connection whose Python value the register declines.** Fact 3 answers no, and facts 1 and
2 are the case that rule did not anticipate. **No baseline of the seven is adopted as a
vector today**, which the section above already states. The open question therefore stops
no work that this project has built.

## The Zeek reading of each method

The Zeek scripts are FoxIO-authored code, so each one counts as a corroboration under the
two-corroboration rule of `docs/specs/foxio/README.md`. This section records what each
script builds. Cite the file path and the pinned commit when you use one.

### JA4

- `zeek/ja4/main.zeek:110-115` builds part a as protocol, version, SNI flag, cipher
  count, extension count and ALPN.
- `zeek/ja4/main.zeek:69` sets the protocol to `q` on a QUIC connection and to `t`
  otherwise.
- `zeek/ja4/main.zeek:74-82` sets the SNI flag to `d` when the ClientHello carries a
  server name, and to `i` otherwise.
- `zeek/ja4/main.zeek:89-101` caps the cipher count and the extension count at `99`.
- `zeek/ja4/main.zeek:84-87` builds the ALPN field from the first character and the last
  character of the first offered protocol. It writes `00` when the ClientHello offers
  none.
- `zeek/ja4/helpers.zeek:56-70` and `zeek/ja4/helpers.zeek:83` remove every GREASE value
  from the ciphers, the compression methods and the extensions.
- `zeek/ja4/main.zeek:141-152` sorts the ciphers and the extensions. It excludes the SNI
  extension and the ALPN extension from part c, and it appends the signature algorithms
  in wire order.
- `zeek/utils/common.zeek:62-70` truncates each SHA-256 to 12 hexadecimal characters and
  returns `000000000000` for an empty list.

### JA4S

- `zeek/ja4s/main.zeek:152-158` builds part a as protocol, version, extension count and
  ALPN.
- `zeek/ja4s/main.zeek:165` writes the one selected cipher as `%04x`, unhashed.
- `zeek/ja4s/main.zeek:166` holds the server extensions in wire order and sorts none of
  them.
- `zeek/ja4s/main.zeek:103-104` records that the script assumes the server returns one
  ALPN value.

### JA4H

- `zeek/ja4h/main.zeek:146-170` builds part a as method, version, cookie flag, referer
  flag, header count and language.
- `zeek/ja4h/main.zeek:76-110` excludes the `Cookie` header and the `Referer` header from
  the header count and from part b. `technical_details/JA4H.md` states the same rule.
- `zeek/ja4h/main.zeek:95-108` reads the first comma-separated value of
  `Accept-Language`, lowercases it, removes each hyphen, and pads it to four characters
  with `0`.
- `zeek/ja4h/main.zeek:193-195` holds the header names in wire order.
- `zeek/ja4h/main.zeek:172-184` sorts the cookie names for part c and the cookie pairs
  for part d.

### JA4SSH

- `zeek/ja4ssh/main.zeek:28` sets the window to 200 packets.
- `zeek/ja4ssh/main.zeek:140` emits a fingerprint when the client count plus the server
  count reaches the window.
- `zeek/ja4ssh/main.zeek:79-85` builds the fingerprint as
  `c<client mode>s<server mode>_c<client packets>s<server packets>_c<client ACKs>s<server ACKs>`.
- `zeek/ja4ssh/main.zeek:122-136` counts a packet that carries no payload and holds only
  the ACK flag as an ACK. It counts every other packet by its TCP payload length.
- `zeek/ja4ssh/main.zeek:68-70` breaks a tie between two modes in favour of the smaller
  value.
- `zeek/ja4ssh/main.zeek:160-164` emits the window a connection holds open when it
  closes.

### JA4D

- `zeek/ja4d/main.zeek:113-118` builds the fingerprint from six fields, in this order.
  It hashes nothing.
  1. The message type.
  2. The maximum message size.
  3. The requested-address flag.
  4. The FQDN flag.
  5. The option list.
  6. The parameter list.
- `zeek/ja4d/consts.zeek:4-23` maps each DHCP message type to a five-character name.
- `zeek/ja4d/consts.zeek:25-30` excludes option codes 53, 255, 50 and 81 from the option
  list, because the earlier fields already carry them.
- `zeek/ja4d/main.zeek:79-92` writes each code in decimal, joins them with `-`, and sorts
  neither list.

### JA4T and JA4TS

- `zeek/ja4t/main.zeek:195-211` builds JA4T as the SYN window size, the option kinds
  joined with `-`, the maximum segment size and the window scale.
- `zeek/ja4t/main.zeek:198-202` writes `00` for the option list when the SYN packet
  carries no option.
- `zeek/ja4t/main.zeek:204` writes the maximum segment size with `%02d`, so an absent
  value reads `00`.
- `zeek/ja4t/main.zeek:206-210` writes `00` for a window scale of zero.
- `zeek/ja4t/main.zeek:212-236` builds JA4TS from the first SYN-ACK packet, and appends
  the delay of each later SYN-ACK packet in seconds.
- `zeek/ja4t/main.zeek:232-234` appends `-R<seconds>` when the server sends a RST packet.
- `zeek/ja4t/main.zeek:185` stops after ten SYN-ACK delays.

**The JA4TS delay list and the `R` marker reach no baseline.** Each of the ten JA4TS
values comes from a connection the server answered once. This project emits the
four-part form, and the Zeek baselines corroborate the four-part form alone.

### The two-digit form of #215

**#215 gave JA4T and JA4TS the two-digit form on 2026-08-08, which is the form this Zeek
script writes.** `zeek/ja4t/main.zeek:198-202` writes `00` for an empty option list, line
204 writes the maximum segment size with `%02d`, and lines 206 to 210 write `00` for a
window scale of zero. `ja4plus` wrote `0` in all three places until #215.

**This comparison was not re-run, because it needs a `FoxIO-LLC/ja4` checkout that the
worktree of #215 does not hold.** The reading below therefore states what the row-level
evidence on this page already settles, and it states no measured number of its own.

**No row of the ten JA4T rows or the ten JA4TS rows changes its verdict.** The three
`conn.log` baselines read `ipv6.pcapng`, `tls3.pcapng` and
`chrome-cloudflare-quic-with-secrets.pcapng`. #215 moved one JA4T value on `ipv6.pcapng`,
one JA4T value on `chrome-cloudflare-quic-with-secrets.pcapng` and no value on
`tls3.pcapng`. Both moved rows already differed, and each keeps the cause this page
records: the `DLT_NULL` defect for `ipv6.pcapng`, and TCP option kind 0 for
`chrome-cloudflare-quic-with-secrets.pcapng`. The two-digit form reaches none of the
twenty rows, because every SYN and every SYN-ACK of the three captures carries a window
scale above zero.

**#215 widened the kind 0 difference by one entry and changed no verdict.**
`chrome-cloudflare-quic-with-secrets.pcapng` now gives `65535_2-1-3-1-1-8-4-0-0_1440_6`
where it gave `65535_2-1-3-1-1-8-4-0_1440_6`, and the Zeek baseline holds
`65535_2-1-3-1-1-8-4_1440_6`. `zeek/ja4t/main.zeek:95-98` leaves the option loop at kind
0, and both other FoxIO implementations count one entry for each such byte.

**Re-run the comparison at the next refresh.** The command is above, and it needs the path
to a checkout at the pinned commit.

### The part e reading of #226

**#226 added part e to JA4TS on 2026-08-08, and the comparison above did not move.** The
user reversed the D6 and D7 ruling of #215, so `ja4plus` now writes the delay between
each SYN-ACK of a connection. `docs/specs/foxio/JA4T.md` states the rule as R12.

**The user accepted a fall in this comparison in advance. The measurement reports none.**

| Reading | #198, before part e | #226, after part e |
|---|---|---|
| JA4TS rows compared | 10 | 10 |
| JA4TS rows that match | 9 | **9** |
| `ja4plus` JA4TS values that carry part e | 0 | **0** |

**The cause is the omission rule, and the sentence above already stated it.** Each of the
ten baseline connections holds one SYN-ACK. The deleted `technical_details/JA4T.md`
states that a fingerprint omits part e when it sees no retransmission, so `ja4plus`
writes the same four-part value it wrote before. `zeek/ja4t/main.zeek:229` appends the
delay list only when the list holds a value, so the Zeek script omits part e on the same
ten rows for the same reason.

**The one row that differs is unchanged, and it is the `DLT_NULL` defect.** The Zeek
baseline holds `ja4ts 65535_00_00_00` for the `ipv6.pcapng` connection and `ja4plus`
holds `65535_2-1-1-4-1-3_1346_10`. Part e appears in neither value. "JA4T: Zeek reads no
TCP option on a capture whose link type is not Ethernet" above states the cause, and
#226 changed nothing about it.

**The two scripts still disagree on how a delay rounds, and no baseline reaches the
disagreement.** `zeek/ja4t/main.zeek:180` divides an integer count of microseconds, which
truncates. `timediff` in `wireshark/source/packet-ja4.c` calls the C `round`, which
carries a half away from zero, and the deleted file states "rounding the result to the
nearest whole number in seconds". `ja4plus` follows the prose and the dissector. A
baseline that carried a retransmission of 1.6 s would separate the two readings, and none
does.

### JA4L and JA4LS

- `zeek/ja4l/main.zeek:151-160` builds JA4LS as half the SYN to SYN-ACK interval, then
  the server TTL.
- `zeek/ja4l/main.zeek:105-114` builds JA4L as half the SYN-ACK to ACK interval, then the
  client TTL.
- `zeek/ja4l/main.zeek:7` records that JA4L cannot work when the traffic is out of order.
- `zeek/ja4l/main.zeek:10` records that the script handles no duplicate packet.

## The two FoxIO repositories that this project had not read

#198 asked what `FoxIO-LLC/ja4tscan` and `FoxIO-LLC/ja4-nginx-module` hold.
`.claude/rules/external-apis.md` records both with their pinned commits.

### `FoxIO-LLC/ja4tscan`

Pinned commit `d01bfec4e64366d37ae95982a5068a5b41ca43b0`, dated 2024-08-29. It holds six
files: `LICENSE`, `README.md`, `build.sh`, `ja4tscan.py`, `module_ja4tscan.c` and
`probe_modules.c`. It is a probe module for Zmap with a Python wrapper, and it sends a
SYN packet to a target to read a server fingerprint.

**It holds prose worth reading and it holds no baseline.** `README.md` gives eight
JA4TScan example values against named operating systems, and those values carry the JA4T
option list. Two of them record TCP option kind 0 inside the list, which corroborates the
`ja4plus` rule. #197 owns the JA4TScan scope decision, and `Non-goals` in
`docs/specs/spec.md` records the decline.

### `FoxIO-LLC/ja4-nginx-module`

Pinned commit `7eeee6202b9b65f5ccf85572957a816ade8cb0bc`, dated 2026-04-20. It is an
nginx module in C, with a patch to the nginx core, Docker images, and four golden files
under `test/testdata/`.

**Warning: FoxIO states that this implementation is not correct.** The first line of its
`README.md` is a `# NOTICE` section, and it reads:

> Development for JA4 on Nginx has been on pause due to other priorities taking
> development resources. This version of JA4 has known issues and bugs and may not
> produce correct JA4 values. Use at your own risk.

**Treat none of its values as a reference.** Its four golden files hold JA4, JA4S and
JA4H values from a local nginx server. They hold an empty `JA4T` field, an empty `JA4TS`
field and an empty `JA4X` field. They hold a `JA4L` field of `0_0_64`, which carries
three parts and describes a connection over the loopback interface. This project reads
none of it.

## What this page does not do

- It adds no vector, and it moves no fingerprint.
- It adds no entry to `tests/foxio_deviations.json`.
- It adds no row to the divergence register, because no comparison against the port ran.
