# JA4TScan

This page is this project's own prose form of the FoxIO JA4TScan scanner. It follows the
procedure in `docs/specs/foxio/README.md`. No FoxIO file enters this repository.

| Item | Value |
|---|---|
| Source | `https://github.com/FoxIO-LLC/ja4tscan` |
| Pinned commit | `d01bfec4e64366d37ae95982a5068a5b41ca43b0` |
| Commit date | 2024-08-29 |
| Retrieval date | 2026-09-30 |
| License | FoxIO License 1.1, which `LICENSE:1` of the source states |
| Build dependency | `zmap` at the tag `v4.1.0-RC1`, commit `4d4166ed4ea6944bb6f74cbe061388d086fc11a2`, which `ja4tscan/build.sh:11` checks out |

Verified against: https://github.com/FoxIO-LLC/ja4tscan (retrieved 2026-09-30, commit `d01bfec4e64366d37ae95982a5068a5b41ca43b0`)
Verified against: https://github.com/zmap/zmap/tree/v4.1.0-RC1 (retrieved 2026-09-30, commit `4d4166ed4ea6944bb6f74cbe061388d086fc11a2`)

**Every citation on this page opens with `ja4tscan/` or `zmap/`.** The prefix names the
FoxIO repository or the zmap repository, and never a path of this repository. This
repository holds a `README.md` of its own, so a bare `README.md:21` would name the wrong
file.

## The inventory

Each hash below comes from `shasum -a 256`, run on 2026-09-30 against a checkout at the
pinned commit. Each size is the exact byte count.

| File | Bytes | SHA-256 | What it holds |
|---|---|---|---|
| `module_ja4tscan.c` | 16811 | `98c0fe21a19cf82dcf282e133dc1340d137e1146ab0b19c0cf44dd7d7295d699` | The zmap probe module. It builds the SYN, reads each response and writes the value. 507 lines |
| `ja4tscan.py` | 4663 | `f868968664f11a22b5c9dcee708492a66bcf7d2b2b9780adf574bdbbfbfbe424` | The wrapper. It sets the firewall, runs zmap and rewrites the output. 131 lines |
| `README.md` | 5983 | `5545d421d1f2a9271dedab908b3953b888b93d5a87d153b2a1548d268181d545` | The purpose, eight example values, three example runs and the build steps |
| `probe_modules.c` | 4294 | `807bd9b3b102f263dfc474cd90050201746d5d6883959344795dae3a872adb30` | The zmap module list, with `module_ja4tscan` added at line 39 |
| `build.sh` | 793 | `99b8ebe45cd6961d21bdf01aed89a636ad28496e45be8b54e2f4ff7e2af0adfe` | The build of zmap `v4.1.0-RC1` with the module |
| `LICENSE` | 4873 | `3fe16034b369d12641eedefdb0c5dc6eb90614dd292a525184312a2c878061eb` | The FoxIO License 1.1, with `Software: JA4TScan` |

Reproduce the measurement with one command, from the root of a checkout at the pinned
commit.

```bash
shasum -a 256 build.sh ja4tscan.py LICENSE module_ja4tscan.c probe_modules.c README.md
```

## What the inventory states

1. **JA4TScan holds no image, no text specification and no vector.** `technical_details/`
   of the `ja4` repository carries no JA4TScan file, and the scanner repository carries no
   capture and no expected output.
2. **`module_ja4tscan.c` is the normative source.** The maintainer named it so on
   2026-09-30, in #775. The module is the one file that writes a JA4TScan value.
3. **The `README.md` holds the only published values.** It lists eight values against
   named systems at `ja4tscan/README.md:21-28`, and it shows one value in its example runs.
   `The published values` below reads each of them against the module.
4. **Three FoxIO sources outside this repository describe part e.** `JA4T.png` captions it
   `TCP Retransmission Timings (only on JA4TScan)`. The deleted
   `technical_details/JA4T.md` heads its form `__JA4TS and JA4TScan Fingerprint formats:__`.
   `docs/specs/foxio/JA4T.md` transcribes both.

## How this page proves a rule

**The two-corroboration rule of `docs/specs/foxio/README.md` exists because a person reads
an image, and a person can misread it.** This source is C and Python text, so no reading
of a picture stands between the source and a rule. A reading of the source alone still
proves no defect, and `.claude/rules/conformance.md` states that bar.

**This page therefore measures each rule that decides a byte of the value.** The
measurement copies the lines the rule cites out of `module_ja4tscan.c` at the pin, with no
edit. It compiles them against stubs of the zmap field functions, and it runs them on
constructed inputs. GCC 14.2.0 on Linux ran each measurement on 2026-09-30. The two
harnesses read these line ranges.

| Harness | Lines of `module_ja4tscan.c` | What it runs |
|---|---|---|
| The formatter | 47-87 and 121-163 | `num_of_digits`, `timediff` and `compute_ja4tscan` |
| The option reader | 333-433 | The option loop of `ja4tscan_process_packet` |

**The harnesses run no zmap, send no packet and open no socket.** A rule that depends on
zmap cites the zmap source at its tag instead.

## The rules

### S1 — The scanner sends one TCP SYN to each target and sends nothing more

- `ja4tscan/README.md:7` states that the tool "generates TCP server fingerprints with a
  single SYN packet".
- `ja4tscan/README.md:86` states that the tool "will not respond to the SYN-ACK but will
  continue to listen".
- `ja4tscan/module_ja4tscan.c:184` calls `make_tcp_header(tcp_header, TH_SYN)`, and no
  function of the module builds a second packet kind.

### S2 — The SYN carries fixed IPv4 and TCP header values

The module calls three zmap functions at `ja4tscan/module_ja4tscan.c:179-186`. Each value
below comes from `zmap/src/probe_modules/packet.c` at the tag.

| Field | Value | Source |
|---|---|---|
| IP version | 4 | `zmap/src/probe_modules/packet.c:88` |
| IP identification | 54321 | `zmap/src/probe_modules/packet.c:91` |
| IP time to live | 255 | `zmap/src/probe_modules/packet.c:93` writes `MAXTTL`, and `zmap/src/zopt.ggo.in:113-116` sets the `probe-ttl` default to 255 |
| TCP flags | SYN alone | `zmap/src/probe_modules/packet.c:114-115` |
| TCP window | 65535 | `zmap/src/probe_modules/packet.c:116` |
| TCP acknowledgment number | 0 | `zmap/src/probe_modules/packet.c:111` |
| TCP header length | 40 bytes, so 20 option bytes | `ja4tscan/module_ja4tscan.c:32` and `ja4tscan/module_ja4tscan.c:117` |
| TCP sequence number | The zmap validation value of the target | `ja4tscan/module_ja4tscan.c:199` and `ja4tscan/module_ja4tscan.c:212` |
| TCP source port | A port of the zmap source range | `ja4tscan/module_ja4tscan.c:209-210` |

**The sequence number, the source port and the IP identification reach no part of the
value.** The server echoes none of them into a field that S5 to S9 read.

### S3 — The SYN carries four options in a fixed order, then one zero byte

| Bytes | Option | Value | Source |
|---|---|---|---|
| `02 04 05 b4` | Maximum Segment Size, kind 2 | 1460 | `zmap/src/probe_modules/packet.c:135-140` |
| `03 03 07` | Window Scale, kind 3 | 7 | `ja4tscan/module_ja4tscan.c:96-98` |
| `04 02` | SACK Permitted, kind 4 | none | `ja4tscan/module_ja4tscan.c:101-102` |
| `08 0a` and eight bytes | Timestamp, kind 8 | The value is the send time in whole seconds, and the echo reply is 0 | `ja4tscan/module_ja4tscan.c:105-114` |
| `00` | End of Option List, kind 0 | none | See below |

**The comment at `ja4tscan/module_ja4tscan.c:95` states a scaling factor of 2, and the
code at line 98 writes 7.** The code decides the byte.

**The last byte is 0 because zmap zeroes the send buffer.** The module raises the header
length by 16 bytes at `ja4tscan/module_ja4tscan.c:117`, and it writes 15. `zmap/src/send.c:473`
allocates the buffer with `xmalloc`, and `zmap/lib/xalloc.c:42` sets every byte to 0.

**This project's JA4T of that SYN is `65535_2-3-4-8-0_1460_7`.** A measurement of
2026-09-30 built the SYN with scapy from the option bytes above and passed it to
`JA4TFingerprinter`. The option reader harness reads the same bytes as `2-3-4-8-0`, a
Maximum Segment Size of 1460 and a scale of 7.

**The options of the SYN decide which options the server returns.** A server returns a
Window Scale option or a Timestamp option only when the SYN carried one. A scanner that
sends other options therefore reads another part b from the same server.

### S4 — A response names its target by the pair of IPv4 addresses, and by no port

- `ja4tscan/module_ja4tscan.c:306` builds the key from `ip_src` and `ip_dst` alone. The
  port fields stand in a comment on that line.
- `ja4tscan/module_ja4tscan.c:169` creates the table with `cachehash_init(10000, NULL)`,
  so the table holds 10000 entries.

**The first response of a pair creates the entry, whatever its flags.**
`ja4tscan/module_ja4tscan.c:310` tests for an absent entry and reads no flag. A RST that
arrives first therefore sets part a to part d, and S12 measures the result.

**zmap passes a response to the module only where it answers the SYN.**
`ja4tscan/module_ja4tscan.c:250-262` requires an acknowledgment number of the sequence
number plus one. A RST may also carry the sequence number itself.

### S5 — Part a is the raw window of the first response

`ja4tscan/module_ja4tscan.c:431` writes `ntohs(tcp->th_win)`. No scale multiplies it.

### S6 — Part b lists the option kinds of the first response up to the first End of Option List

- `ja4tscan/module_ja4tscan.c:371-372` appends the kind of every option the loop reads.
- `ja4tscan/module_ja4tscan.c:412-425` joins the kinds with `-`, in wire order.
- `ja4tscan/module_ja4tscan.c:427-428` writes `00` when the list is empty.
- **`ja4tscan/module_ja4tscan.c:393` sets the remaining length to 1 on kind 0, and line 401
  then subtracts 1.** The loop ends at the first End of Option List.
- `ja4tscan/module_ja4tscan.c:366-369` ends the loop at an option length below 1 or past
  the end of the option bytes.

The option reader harness measured three inputs.

```
mss nop ws nop nop ts sackok eol eol   options="2-1-3-1-1-8-4-0" mss=1460 scale=6
mss eol ws                             options="2-0" mss=1460 scale=0
no option                              options="00" mss=0 scale=0
```

**Part b therefore holds one `0` for any run of End of Option List bytes.** R5 of
`docs/specs/foxio/JA4T.md` states the opposite for JA4T and JA4TS: one `0` for each byte.

### S7 — Part c is the Maximum Segment Size of the first response, printed with `%02u`

`ja4tscan/module_ja4tscan.c:137` prints part c with `%02u`, and
`ja4tscan/module_ja4tscan.c:347` sets 0 when the response carries no such option. A
response with no Maximum Segment Size option therefore writes `00`.

### S8 — Part d is the Window Scale of the first response, printed with `%d`

`ja4tscan/module_ja4tscan.c:137` prints part d with `%d`. A response with no Window Scale
option therefore writes `0`, and never `00`. The formatter harness measured it.

```
window=5840 options=2 mss=1460 scale=0 retransmits="3-6-12-" -> "5840_2_1460_0_3-6-12"
```

R11 of `docs/specs/foxio/JA4T.md` writes `00` for JA4T and JA4TS. `The published values`
below records two published JA4TScan values that write `00`.

### S9 — Part e lists the delay before each later response, and a RST adds `R`

- `ja4tscan/module_ja4tscan.c:436` reads the delay since the previous response of the pair,
  and lines 442-443 store the time of this response.
- `ja4tscan/module_ja4tscan.c:440` appends `<delay>-` for a response without the RST flag.
- `ja4tscan/module_ja4tscan.c:438` appends `R<delay>-` for a response with the RST flag.
- `ja4tscan/module_ja4tscan.c:142-143` appends `_` and the list to part d.

**The size that line 143 passes to `snprintf` drops the last `-` of the list.** The
formatter harness measured it.

```
window=64240 options=2-1-3-1-1-4 mss=1460 scale=8 retransmits="1-2-4-8-R6-" -> "64240_2-1-3-1-1-4_1460_8_1-2-4-8-R6"
window=65535 options=2-1-3-1-1-4 mss=1460 scale=8 retransmits="" -> "65535_2-1-3-1-1-4_1460_8"
```

**A value with no later response holds four parts.** Line 142 appends part e only when the
list holds a character.

**The module sets no bound on the count of delays.** The list is a buffer of 256 bytes at
`ja4tscan/module_ja4tscan.c:53`, and the wait of S13 bounds the count in practice.

### S10 — Each delay is whole seconds, plus one when the fraction exceeds one half

`ja4tscan/module_ja4tscan.c:75-87` subtracts the two times. It converts the nanoseconds to
a `float` and adds 1 when the fraction is above 0.5. The formatter harness measured it.

```
timediff(1.000000000, 0.000000000) -> 1
timediff(1.499999999, 0.000000000) -> 1
timediff(1.500000000, 0.000000000) -> 1
timediff(1.500000001, 0.000000000) -> 1
timediff(1.500000100, 0.000000000) -> 2
timediff(0.600000000, 0.000000000) -> 1
timediff(11.100000000, 10.900000000) -> 0
```

**A fraction of exactly one half rounds down, and so does a fraction that `float` stores as
one half.** R12 of `docs/specs/foxio/JA4T.md` rounds a half away from zero for JA4TS. The
two rules differ on these inputs alone.

### S11 — The module writes one output row for each response

`ja4tscan/module_ja4tscan.c:451` calls `compute_ja4tscan` for every response, and that
function writes the fields at lines 146-161. Each row carries the value so far.

| Field | Value | Source |
|---|---|---|
| `ja4tscan` | The value | `ja4tscan/module_ja4tscan.c:151` |
| `timestamp` | The receive time of the response, in whole seconds | `ja4tscan/module_ja4tscan.c:152` |
| `classification` | `rst` once any response carried RST, else `synack` | `ja4tscan/module_ja4tscan.c:155-161` |
| `success` | 1 for `rst`, 0 for `synack` | `ja4tscan/module_ja4tscan.c:157` and `ja4tscan/module_ja4tscan.c:160` |

**The `success` field contradicts the help text.** `ja4tscan/module_ja4tscan.c:501-504`
states that a SYN-ACK is a success and a reset is a failure.

**An ICMP response writes a row with an empty value.** `ja4tscan/module_ja4tscan.c:456-469`
writes `null` into `ja4tscan` and `icmp` into `classification`.

### S12 — The formatter drops the last character when the Maximum Segment Size is below 10

`ja4tscan/module_ja4tscan.c:123-129` computes the buffer size from `num_of_digits` of the
Maximum Segment Size. Line 137 prints that field with `%02u`, which writes two digits for a
value below 10. The size is then one byte short, and `snprintf` drops the last character.

```
window=0 options=00 mss=0 scale=0 retransmits="" -> "0_00_00_"
window=0 options=00 mss=0 scale=0 retransmits="R3-" -> "0_00_00__R3"
window=8192 options=2 mss=9 scale=0 retransmits="" -> "8192_2_09_"
```

**A RST that answers the SYN meets this shape.** A RST carries no option and, on real
traffic, a window of 0. S4 lets it set part a to part d, so the value reads `0_00_00_`.

**This is a defect, and this page proves it by measurement.** The format string at line 137
states four parts, and the value holds three and a separator. `.claude/rules/conformance.md`
states the two shapes that decline a defect. Whether either shape reaches this one is a
question for the maintainer, and `docs/specs/features/12-active-scan.md` holds it.

### S13 — The scanner waits 120 seconds for retransmissions

- `ja4tscan/ja4tscan.py:109` runs zmap with `--cooldown-time=120` when retransmissions are
  on.
- `ja4tscan/ja4tscan.py:114` runs zmap with no cooldown option when they are off.
  `zmap/src/zopt.ggo.in:56-59` sets the default to 8 seconds.
- `ja4tscan/README.md:86` states that the tool "listens for 2 minutes".
- **`ja4tscan/module_ja4tscan.c:41` defines `RST_TIMEOUT 120`, and no line of the module
  reads it.** The wait belongs to zmap alone.

**The zmap cooldown counts from the last probe that zmap sends, and not from each
target.** `zmap/src/zopt.ggo.in:56` states "How long to continue receiving after sending
last probe". A target that zmap probes early therefore gets a longer wait.

### S14 — The wrapper holds two modes, and each one sets the firewall

| `--retransmit` | zmap `--dedup-method` | Firewall | Source |
|---|---|---|---|
| `yes`, the default | `none` | The wrapper adds four rules | `ja4tscan/ja4tscan.py:104-109` |
| `no` | `full` | The wrapper removes the four rules | `ja4tscan/ja4tscan.py:104-105` and `ja4tscan/ja4tscan.py:112-114` |

**The four rules drop every inbound packet except these three classes.**
`ja4tscan/ja4tscan.py:15-18` holds them.

```
iptables -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t filter -A INPUT -p icmp -j ACCEPT
iptables -t filter -A INPUT -i lo -j ACCEPT
iptables -t filter -A INPUT -j DROP
```

**The rules exist so that the kernel of the scanning host sends no RST for the SYN-ACK.**
The kernel holds no socket for the connection, so it answers a SYN-ACK with a RST. The
server then stops its retransmissions, and part e stays empty. The last rule drops the
SYN-ACK before the kernel reads it. zmap reads the SYN-ACK with libpcap, which reads the
packet before the firewall does.

**`ja4tscan/README.md:93` describes the rules as a drop of "RST packets coming from
servers".** The rules drop every new inbound packet, so the prose names a narrower effect.

**`ja4tscan/README.md:95` contradicts the code.** It states that `retransmit` set to "yes"
selects `dedup-method` full. `ja4tscan/ja4tscan.py:104-105` selects `full` for `no`.

**The wrapper removes the rules on SIGINT, on a zmap failure and on a Python exception.**
`ja4tscan/ja4tscan.py:27-29`, `:118-120` and `:125-127` hold the three paths.
`ja4tscan/ja4tscan.py:129-130` removes them after a normal run.

### S15 — The wrapper keeps the last row of each target and rewrites one shape

`ja4tscan/ja4tscan.py:31-52` reads the zmap output file. It keeps the last row for each
source address, and it writes the rows in address order.

**`ja4tscan/ja4tscan.py:44-45` rewrites a value that ends with `00_00_`.** It replaces
`00_00_` with `rst-ack`. The value `0_00_00_` of S12 therefore becomes `0_rst-ack`, and a
Python measurement of 2026-09-30 confirmed the replacement. `ja4tscan/ja4tscan.py:42-43`
holds a second form of the rewrite as a comment.

**The rewrite reads the value that S12 truncates.** A value `0_00_00__R3` does not end with
`00_00_`, so the wrapper leaves it as it is.

### S16 — The wrapper accepts three target forms and one target port

| Input | What the wrapper passes to zmap | Source |
|---|---|---|
| One IPv4 address | It writes the address to the file `input` and passes `-I input` | `ja4tscan/ja4tscan.py:84-88` |
| One network in CIDR form | It passes the network as a zmap argument | `ja4tscan/ja4tscan.py:90-91` |
| Any other text | It passes `-I <text>`, a file of one address for each line | `ja4tscan/ja4tscan.py:92-94` |

`zmap/src/zopt.ggo.in:27` describes `-I` as "List of individual addresses to scan in random
order".

| Option | Default | Source |
|---|---|---|
| `-p`, `--port` | 80 | `ja4tscan/ja4tscan.py:58` and `ja4tscan/ja4tscan.py:96-97` |
| `-r`, `--rate` | 10 packets each second | `ja4tscan/ja4tscan.py:57` and `ja4tscan/ja4tscan.py:98-99` |
| `--output-fields` | `timestamp,saddr,ja4tscan` | `ja4tscan/ja4tscan.py:59` |
| `-o`, `--output-file` | `console`, and the wrapper always writes `output.csv` | `ja4tscan/ja4tscan.py:60` and `ja4tscan/ja4tscan.py:76` |
| `--retransmit` | `yes` | `ja4tscan/ja4tscan.py:61` and `ja4tscan/ja4tscan.py:104-105` |

**The help text of `--port` names the TCP source port, and the value is the target port.**
`ja4tscan/ja4tscan.py:71` states `tcp source port`, and line 109 passes the value to zmap
`-p`, which names the port to scan.

### S17 — The module reads IPv4 alone

`ja4tscan/module_ja4tscan.c:180` and `ja4tscan/module_ja4tscan.c:301` read `struct ip`,
the IPv4 header. `zmap/src/probe_modules/packet.c:88` writes IP version 4. No line of the
module reads an IPv6 header.

## The published values, read against the module

`ja4tscan/README.md:21-28` lists eight values. The table reads each one against the
module at the pin. A value the module cannot write came from another source, and the
README names none.

| System | Published value | The module writes this shape | Reason |
|---|---|---|---|
| Windows 10 | `64240_2-1-3-1-1-4_1460_8_1-2-4-8-R6` | Yes | |
| Windows 2003 | `16384_2-1-3-1-1-8-1-1-4_1460_00_2-7` | No | Part d is `00`, and S8 writes `0` |
| Amazon AWS Linux 2 | `62727_2-4-8-1-3_8961_7_1-2-4-8-16` | Yes | |
| Mac OSX / iPhone | `65535_2-1-3-1-1-8-4-0-0_1460_6_1-2-4-8-16-32-12` | No | Part b holds two `0` values, and S6 writes one |
| F5 Big IP | `4380_2-4-8_1460_0_3-6-12` | Yes | |
| HP ILO | `5840_2_1460_00_3-6-12-24-48-60-60-60-60-60` | No | Part d is `00`. The delays add to 393 seconds, and S13 waits 120 |
| Epson Printer | `28960_2-4-8-1-3_1460_3_1-4-8-16` | Yes | |
| Ubiquiti Router | `43440_2-4-8-1-3_1460_12_1-2-4-8-17` | Yes | |

**Five of the eight values fit the module, and three do not.** The example runs at
`ja4tscan/README.md:44-83` show one value, `65535_2-1-3-1-1-4_1440_8_0-1-R2`, and the
module writes that shape.

**The form this project already writes for JA4TS fits seven of the eight.** That form
writes one `0` for each End of Option List byte and writes a zero part d as `00`. It
fits every value except F5 Big IP, which writes part d as `0`. The HP ILO value still
exceeds the wait of S13 under either form.

**No published value is a vector.** Each one names a system and no capture, so no case can
replay the packets that produced it.

## What this page leaves to the feature

`docs/specs/features/12-active-scan.md` states what this project builds. The rulings of
2026-09-30 decide the firewall and the packaging. Four questions reach no ruling yet, and
that page names each one with its options.

1. Which form parts a to e follow: the module bytes of S6, S8 and S10, or the JA4TS form
   this project already writes.
2. What a target that answers with no SYN-ACK produces, where S12 and S15 publish
   `0_rst-ack`.
3. Whether the scanner reads IPv6, which S17 leaves outside the FoxIO scanner.
4. Which firewall rule the scanner states, where S14 records the four rules of the
   wrapper.
