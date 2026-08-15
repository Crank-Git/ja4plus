# JA4SSH

This page is this project's own prose form of `technical_details/JA4SSH.png`. It follows
the procedure in `docs/specs/foxio/README.md`. No image enters this repository.

| Item | Value |
|---|---|
| Source | `https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4SSH.png` |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-08 |
| SHA-256 of the image | `98524e55021e9d0bc42efe35e6aa0fdf002df38e65311a34d34a1bcc45e78e8c` |

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4SSH.png (retrieved 2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

Reproduce the hash from a checkout at the pinned commit.

```bash
shasum -a 256 technical_details/JA4SSH.png
```

## FoxIO published a text specification of JA4SSH, and then deleted it

**`technical_details/JA4SSH.md` existed, and one commit deleted it.** The deleted file
states the six fields of the image in words, and it states two rules the image only
draws. This page cites it, and this page states where it came from so that the next
reader can weigh it.

| Item | Value |
|---|---|
| Path | `technical_details/JA4SSH.md` |
| Commit that holds it | `16850cc2c8bcb8328c1a43a851a3a9a6eaa56103` |
| Blob SHA-1 | `e9bb04b11a06ee1dfd3dbeaa18b45a0138bcdf48` |
| Bytes | 2288 |
| Commit that created it | `cbef671`, `Create JA4SSH.md` |
| Commit that deleted it | `b6f3ff4`, `Update README.md` |

**The pinned commit points at this file.** `rust/ja4/src/ssh.rs:283`, at the pinned
commit, carries the reference
`https://github.com/FoxIO-LLC/ja4/blob/16850cc2c8bcb8328c1a43a851a3a9a6eaa56103/technical_details/JA4SSH.md#how-to-measure-the-mode-for-tcp-payload-lengths-across-200-packets-in-the-session`.
The deleted file is therefore the source that FoxIO's own Rust implementation cites for
its mode rule. It is FoxIO-authored, so it counts as a corroboration.

Read one blob from a checkout at the pinned commit. The command reaches no network,
because the checkout holds the whole history.

```bash
git cat-file -p 16850cc2c8bcb8328c1a43a851a3a9a6eaa56103:technical_details/JA4SSH.md
```

**The same commit `b6f3ff4` deleted seven files.** It removed `technical_details/JA4.md`,
`JA4H.md`, `JA4L.md`, `JA4S.md`, `JA4SSH.md`, `JA4T.md` and `JA4X.md`. `JA4.md` and
`JA4H.md` exist again at the pinned commit, and the other five do not. **Five methods of
the epic therefore hold a deleted text specification that no transcription has read.**
#221 owns that work.

```bash
git log --oneline --diff-filter=D --name-only -- 'technical_details/*.md'
```

**Warning: a deleted file is not the pinned specification.** The image at the pinned
commit is the transcribed source. The deleted file corroborates it, and it never outranks
it. Every rule below that rests on the deleted file carries a second corroboration from
code at the pinned commit.

## The field layout

The image draws one example string and labels three parts `a`, `b` and `c`.

```
JA4SSH=c36s36_c55s75_c70s0
       \_____/ \_____/ \____/
          a       b      c
```

The image draws six leader lines, and it captions each one.

| Leader line | The image's caption | Value in the example |
|---|---|---|
| 1 | Mode of Client Packet Length | `c36` |
| 2 | Mode of Server Packet Length | `s36` |
| 3 | SSH packets sent from client | `c55` |
| 4 | SSH packets sent from server | `s75` |
| 5 | Bare ACKs sent from client | `c70` |
| 6 | Bare ACKs sent from server | `s0` |

The image carries three more captions.

- `(runs every 200 SSH packets by default)`, beside the leader lines.
- `Bare ACKs are sent from the initiating side (eg. side doing the typing)`, in italic.
- Three worked examples, listed under "The worked examples the image gives".

## The rules

Each rule below carries two corroborations. Neither corroboration is the image.

### R1 — JA4SSH holds three parts, joined with `_`, and each part names a client value and a server value

The fingerprint is
`c<client mode>s<server mode>_c<client packets>s<server packets>_c<client ACKs>s<server ACKs>`.

- Corroboration 1: `rust/ja4/src/ssh.rs:287-289` at the pinned commit writes
  `"c{mode_client}s{mode_server}_c{nr_ssh_client_packets}s{nr_ssh_server_packets}_c{nr_tcp_client_acks}s{nr_tcp_server_acks}"`.
- Corroboration 2: `python/ja4ssh.py:152` at the pinned commit writes
  `f'c{mode_client}s{mode_server}_c{client_packets}s{server_packets}_c{client_acks}s{server_acks}'`.

`wireshark/source/packet-ja4.c:655-659` writes the same six values with the format
`"c%ds%d_c%ds%d_c%ds%d"`, and `docs/specs/foxio/zeek.md` records the same order for
`zeek/ja4ssh/main.zeek:79-85`.

### R2 — Part a holds the mode of the TCP payload length of each direction

The mode is the value that appears the most times. The measurement reads the TCP payload
length, and not the length of the whole packet.

- Corroboration 1: `rust/ja4/src/ssh.rs:206-213` at the pinned commit documents the two
  maps as `client TCP payload length, bytes` and states `tshark exposes TCP payload
  length as tcp.len`. Line 235 reads `tcp.len`.
- Corroboration 2: the deleted `technical_details/JA4SSH.md` states
  `Reminder: We’re looking at the TCP payload lengths, not the packet length. In
  wireshark this is under “tcp.len”.`

**The image's own caption reads `Mode of Client Packet Length`, and the two
corroborations both state the TCP payload length.** The image's word `Packet Length` is
therefore looser than the rule. This page records the difference, because a reader who
reads the image alone would read the frame length.

### R3 — Part a reads the SSH packets alone

A bare ACK contributes no length to the mode, and neither does any other packet that
carries no SSH layer.

- Corroboration 1: `rust/ja4/src/ssh.rs:234-245` at the pinned commit records a length
  only inside `if pkt.find_proto("ssh").is_some()`.
- Corroboration 2: the deleted `technical_details/JA4SSH.md` states `And this is only for
  SSH (layer 7) packets. This does not include TCP ACK packets or other layer 4 packets.`

### R4 — Two lengths that tie for the highest count give the smaller length

- Corroboration 1: `rust/ja4/src/ssh.rs:294-315`, `min_key_with_max_value`, keeps the
  smaller key on a tie. Its unit test asserts `Some(16)` at `rust/ja4/src/ssh.rs:334` and
  `Some(23)` at `rust/ja4/src/ssh.rs:340`, for two sets whose counts all equal 1.
- Corroboration 2: `python/ja4ssh.py:49-54`, `_mode_from_lengths`, returns
  `min(k for k, v in counts.items() if v == max_count)`.

The deleted `technical_details/JA4SSH.md` states the rule in words: `If there is a
collision, the program choses the smaller byte value.` `docs/specs/foxio/zeek.md` records
the same rule for `zeek/ja4ssh/main.zeek:68-70`.

### R5 — Part b holds the count of SSH packets of each direction

- Corroboration 1: `rust/ja4/src/ssh.rs:215-218` names the two counters `Total number of
  SSH packets sent from the client` and `Total number of SSH packets sent from the
  server`.
- Corroboration 2: the deleted `technical_details/JA4SSH.md` states `JA4SSH counts the
  number of SSH (layer 7) packets sent from the client and server separately. This does
  not include ACK packets, TCP replays or any other layer 4 packets.`

**The deleted file excludes a retransmission from the count.** The word it uses is `TCP
replays`. `ja4plus` reads the same rule, and Changelog round 28 records the measurement.

### R6 — Part c holds the count of bare ACK packets of each direction

A bare ACK is a TCP packet whose flags equal `0x0010` and which carries no payload.

- Corroboration 1: `rust/ja4/src/ssh.rs:228` defines `const BARE_ACK_FLAG: &str =
  "0x0010"`, and line 246 counts a packet only when `tcp.flags` equals it and the packet
  holds no SSH layer.
- Corroboration 2: `python/ja4ssh.py:112` counts a packet only when
  `(not has_ssh) and flags == 0x0010 and tcp_len == 0`.

`docs/specs/foxio/zeek.md` records that `zeek/ja4ssh/main.zeek:122-136` counts a packet
that carries no payload and holds only the ACK flag as an ACK.

### R7 — The window is 200 SSH packets, and the count is configurable

The window counts the SSH packets of both directions together.

- Corroboration 1: `rust/ja4/src/conf.rs:61` sets `.set_default("ssh.sample_size", 200)`,
  and `rust/ja4/src/ssh.rs:35` compares
  `self.stats.nr_ssh_client_packets + self.stats.nr_ssh_server_packets == sample_size`.
- Corroboration 2: `python/ja4.py:439` sets `ssh_sample_count = 200`, and
  `python/ja4ssh.py:125` tests `(entry['count'] % ssh_sample_count) == 0`.

`wireshark/source/packet-ja4.c:33` holds `#define SAMPLE_COUNT 200`. The deleted
`technical_details/JA4SSH.md` states `Runs every n packets per SSH TCP stream. n = 200 by
default but is configurable.`

**A bare ACK does not advance the window.** The window counts SSH packets, and R6 counts
a bare ACK in a separate field.

### R8 — A window boundary resets every counter of the window

- Corroboration 1: `rust/ja4/src/ssh.rs:36` takes the statistics with
  `std::mem::take(&mut self.stats)`, which leaves the default value behind.
- Corroboration 2: `wireshark/source/packet-ja4.c:1485-1490` sets the four counters to
  `0` and builds two new mode maps.

**The FoxIO Python implementation intends the same reset and does not achieve it.** See
"The three declined reference behaviours" below.

### R9 — A connection produces several fingerprints

- Corroboration 1: `rust/ja4/src/ssh.rs:23` documents the vector `ja4ssh` as `New entry
  is added every sample_size packets.`
- Corroboration 2: the deleted `technical_details/JA4SSH.md` states `This means each SSH
  stream will have multiple JA4SSH results.`

`.claude/rules/conformance.md` reads the occurrence counter `JA4SSH.1`, `JA4SSH.2` in the
expected-output file the same way.

### R10 — The image states which side sends the bare ACKs, and states it as guidance

The image's italic caption reads `Bare ACKs are sent from the initiating side (eg. side
doing the typing)`.

**This is a statement about SSH traffic, and it is not a rule a fingerprinter applies.**
No implementation reads it. It explains why the three worked examples put the ACK count
on one side.

- Corroboration 1: the deleted `technical_details/JA4SSH.md` states `Forward SSH shell
  (notice the ACKs come from the client)` and `Reverse SSH shell (notice the ACKs come
  from the server)`.
- Corroboration 2: `README.md` line 151 at the pinned commit gives
  ```JA4SSH=c76s76_c71s59_c0s70``` beside the label `Reverse SSH Shell`, which carries
  every ACK on the server side.

### R11 — The specification states no rule that closes the last window

**This rule is uncertain, and #214 settled the behaviour without it.** The specification
states nothing, so the user decided. `ja4plus` closes the last window at the end of the
capture, as the FoxIO Rust implementation and the FoxIO Zeek package do. The section "The
trailing window" holds the measurement, and the ruling is reversible.

The image states one boundary, the 200 SSH packets of R7. It states nothing about these
three things.

- A connection that closes.
- The end of a capture.
- The window a connection holds open when either happens.

The deleted `technical_details/JA4SSH.md` states nothing about them either. The section
"What the image does not state" lists the whole gap, and "The trailing window" holds the
measurement.

## The worked examples the image gives

The image gives three examples under the field layout. Each one is reproduced verbatim.

| The image's label | Value | The image's note |
|---|---|---|
| `Interactive SSH Session` | `c36s36_c51s80_c69s0` | `Padded to 36 (minimum length over chacha20-poly1305), all ACKs from client` |
| `Reverse SSH Session` | `c76s76_c71s59_c0s70` | `Double Padded to 76, all ACKs from server` |
| `WinSCP File Transfer to Client` | `c112s1460_c0s179_c21s0` | `Max window from server 1460, all ACKs from client` |

The deleted `technical_details/JA4SSH.md` gives the same three values, and it labels the
third `SCP file transfer (always c112s1460)`. `README.md` line 151 at the pinned commit
gives the second value.

**The three examples describe traffic, and none of them is a rule.** No implementation
reads them, and this project reads them only in `interpret_fingerprint`.

## What the image does not state

A reader of the image alone cannot answer these questions. Each one reaches the vector
fallback under `.claude/rules/conformance.md`.

1. **What closes the last window.** R11 holds it. #214 decided it on 2026-08-08.
2. **Which endpoint is the client.** The image writes `client` and `server` and states no
   rule that decides them.
3. **Which connection JA4SSH reads.** The image names no port. `python/ja4.py:549`
   requires port 22 on one endpoint, and `rust/ja4/src/ssh.rs` reads any stream on which
   tshark finds an `ssh` layer.
4. **What counts as one SSH packet when one message spans several TCP segments.** R5
   excludes a retransmission and states nothing about a split message.
5. **The empty window.** The image states no value for a window that holds no SSH packet.
6. **The upper bound on the count of fingerprints per connection.**
   `zeek/ja4ssh/main.zeek` holds the option `ja4_ssh_max_fingerprints`, and no other
   reference holds a bound.

## The three declined reference behaviours

`tests/foxio_deviations.json` holds 14 JA4SSH entries under four issues, and this section
reads three of the four. #96 holds 4 entries, #97 holds 2 entries and #105 holds 3
entries. The plan asked
whether the specification explains each behaviour or contradicts it. **The specification
explains none of the three, and it contradicts two.** No decline reopens.

**#611 corrected the entry count of this section on 2026-08-15, and this record supersedes
the earlier wording.** #214 registered 5 occurrence-form entries after the section was
written. The three issues of the section hold 9 entries today, against the ten the earlier
sentence states. The sentence below is the superseded wording, quoted rather than
rewritten.

> `tests/foxio_deviations.json` holds ten JA4SSH entries under three issues.

**The correction reopens no decline.** #611 read the count alone, and the three subsections
below hold the same three reference behaviours they held before. The 5 entries of #214 are
a separate register family, and this section reads none of them.

### #96 — the reference mode reads the packet lengths of the whole capture

`tests/foxio_deviations.json` states the cause: `dict(ja4sh_stats) shares one payload list
across every window and every connection, so the reference mode field reads the packet
lengths of the whole capture.`

**Confirmed against the file at the pinned commit.** `python/ja4ssh.py:8-15` builds one
module-level dictionary whose values `client_payloads` and `server_payloads` are lists.
`python/ja4ssh.py:88` and `python/ja4ssh.py:128` copy it with `dict(ja4sh_stats)`, which
is a shallow copy, so every window of every connection appends to the same two list
objects.

**The specification contradicts the behaviour.** R2 and the deleted
`technical_details/JA4SSH.md` state the measurement as
`How to measure the mode for TCP payload lengths across 200 packets in the session`. The
mode reads the 200 packets of the window, and not the packets of another connection.
`rust/ja4/src/ssh.rs:211-213` holds one map per window and `wireshark/source/packet-ja4.c:1487-1490`
builds a new map at each boundary, so two references disagree with the Python
implementation as well.

**Status: the specification explains the behaviour as a defect. The decline stands.** The behaviour
also meets shape 1 of `.claude/rules/conformance.md`, because the value depends on the
composition of the capture.

### #97 — the reference writes an occurrence from a window that holds no SSH packet

`tests/foxio_deviations.json` states the cause: `A bare ACK that follows a window boundary
makes FoxIO write another occurrence from a window that holds no SSH packet.`

**Confirmed against the file at the pinned commit, and the mechanism is exact.**
`python/ja4ssh.py:125` runs the test `(entry['count'] % ssh_sample_count) == 0` on every
packet, and `python/ja4ssh.py:98-99` advances `entry['count']` only for an SSH packet. A
bare ACK that arrives after packet 200 and before packet 201 therefore finds `count`
still equal to 200, and it calls `to_ja4ssh` again. `python/ja4ssh.py:145` guards that
call with `if e['client_payloads'] or e['server_payloads']`. The shared list of #96
defeats the guard. The reference then writes `JA4SSH.2` from a window whose packet
counters are `c0s0`, and whose mode comes from the previous window.

`tests/foxio_vectors/ssh2.pcapng.json` holds the result on stream 14:
`'JA4SSH.1': 'c36s36_c76s124_c74s5', 'JA4SSH.2': 'c36s36_c0s0_c2s0'`.

**The specification contradicts the behaviour, and so does the Rust reference.** R5 states
that part b holds the count of SSH packets, and `c0s0` states that the window holds none.
`rust/ja4/src/ssh.rs:271-274` returns no fingerprint when both length maps are empty, and
it carries the comment `This doesn't seem to be an *SSH* TCP stream after all.`
**`ja4plus/fingerprinters/ja4ssh.py:342-343` holds the same guard as the Rust reference.**

**Status: the specification explains the behaviour as a defect. The decline stands.** The behaviour
also meets shape 2 of `.claude/rules/conformance.md`, because the fingerprint describes
no traffic.

### #105 — the reference writes no trailing window for the connection at stream index 0

`tests/foxio_deviations.json` states the cause: `finalize_ja4ssh guards with `if stream:`,
and the stream index 0 is false in Python, so the reference emits no trailing window for
the connection it holds at index 0.`

**Confirmed against the file at the pinned commit.** `python/ja4.py:370-377` opens
`finalize_ja4ssh` with `if stream:`, and `python/ja4.py:556` calls it as
`finalize_ja4ssh(x['stream'])`. The stream index of the first connection of a capture is
`0`, which Python reads as false, so the body never runs for it.

**The specification states no rule that the behaviour could follow.** R11 records that the
image and the deleted text state nothing about the last window. The decline therefore
rests on the shape rule and not on a statement of intent.

**The behaviour meets shape 1 of `.claude/rules/conformance.md`.** The value depends on
the position of the connection in the file. The same connection produces a trailing
fingerprint at stream index 1, and it produces none at stream index 0.

**Two other references write the trailing window for every connection.**
`rust/ja4/src/ssh.rs:45-55`, `Stream::finish`, pushes the held window with no test on the
stream index, and `docs/specs/foxio/zeek.md` records that `zeek/ja4ssh/main.zeek:160-164`
emits from `connection_state_remove`. `wireshark/source/packet-ja4.c:1399-1404` writes one
on a FIN+ACK packet, under the comment `// Fix to add JA4SSH when a connection
terminates`, and it applies no test on the stream index.

**Status: the specification does not explain the behaviour. The decline rests on the
shape rule alone, and it stands.** Three references contradict the reference behaviour, and no reference supports
it.

## The trailing window, and the reading #214 needed

**This page states what the specification holds.** #214 held the user's ruling, and the
user decided it on 2026-08-08. The section "The ruling #214 made" records the result.

### What the specification states

**The specification states the window boundary.** R7 holds it: the window is 200 SSH
packets, and the count is configurable. The image states `(runs every 200 SSH packets by
default)` and the deleted `technical_details/JA4SSH.md` states `Runs every n packets per
SSH TCP stream. n = 200 by default but is configurable.`

**The specification states nothing about what closes the last window.** Neither the image
nor the deleted text names a FIN packet, a connection that closes, or the end of a
capture. R11 records this, and it is the answer to the first half of #214's question.

### What each reference does

| Reference | What closes the last window | File and line |
|---|---|---|
| FoxIO Python | A FIN+ACK packet, on a connection whose stream index is not `0` | `python/ja4.py:554-556`, `python/ja4.py:372` |
| FoxIO Rust | The end of the capture, for every connection | `rust/ja4/src/ssh.rs:45-55` |
| FoxIO Wireshark | A FIN+ACK packet, when one endpoint uses port 22 | `wireshark/source/packet-ja4.c:1399-1404` |
| FoxIO Zeek | The removal of the connection state, which the end of the capture reaches | `zeek/ja4ssh/main.zeek:160-164`, per `docs/specs/foxio/zeek.md` |
| `ja4plus` | A FIN+ACK packet, or the end of the capture | `ja4plus/fingerprinters/ja4ssh.py:221-222`, `ja4plus/fingerprinters/ja4ssh.py:328-351` |

**The FoxIO Python implementation runs no end-of-capture step for JA4SSH.**
`python/ja4.py:610` reads
`#finalize_ja4ssh() if 'ja4ssh' in output_types else None`, and the line is commented out.

**The references split two against two.** Python and Wireshark close the last window on a
FIN+ACK packet. Rust and Zeek close it at the end of the capture. **`ja4plus` applies both
rules, so it emits the window whichever event comes first.** #214 decided it.

### The measurement on `ssh2.pcapng`

`ssh2.pcapng` carries **no FIN+ACK packet on port 22**, so no FIN+ACK rule fires on it.
The connection holds its last window open when the capture ends.

Reproduce the measurement from the root of this repository.

```bash
python -c "
from scapy.all import PcapReader, TCP
n = 0
with PcapReader('tests/foxio_vectors/ssh2.pcapng') as r:
    for p in r:
        if p.haslayer(TCP) and 22 in (p[TCP].sport, p[TCP].dport):
            if int(p[TCP].flags) & 0x01 and int(p[TCP].flags) & 0x10:
                n += 1
print(n)
"
```

The command prints `0`.

**`ja4plus` already counts the held window, and it matches two references byte for byte.**
The measurement of 2026-08-08 reads the connection `172.16.225.48:57377-54.160.114.75:22`
after the last packet of the capture.

```
ja4plus emitted            : c36s36_c76s124_c74s5
ja4plus holds open         : 42 client SSH packets, 76 server SSH packets, 51 client ACKs, 2 server ACKs
the held window would give : c36s52_c42s76_c51s2
```

| Source | First value | Second value |
|---|---|---|
| `tests/foxio_vectors/ssh2.pcapng.json` | `c36s36_c76s124_c74s5` | `c36s36_c0s0_c2s0` |
| `tests/foxio_vectors/rust_expected/ja4__insta@ssh2.pcapng.snap:215-217` | `c36s36_c76s124_c74s5` | `c36s52_c42s76_c51s2` |
| Zeek baseline, per `docs/specs/foxio/zeek.md` | `c36s36_c76s124_c74s5` | `c36s52_c42s76_c51s2` |
| `ja4plus` | `c36s36_c76s124_c74s5` | none |

**The FoxIO Rust snapshot already sits in this repository, and #198 did not read it.**
`tests/foxio_vectors/rust_expected/ja4__insta@ssh2.pcapng.snap` holds
`c36s52_c42s76_c51s2`, which equals the Zeek baseline value and equals the value the
`ja4plus` counters already hold. Two FoxIO references and this project therefore agree on
the content of the last window, and they disagree only about whether to emit it.

**The Python second value is the #97 defect.** `c36s36_c0s0_c2s0` is not a trailing
window. It is the extra occurrence a bare ACK writes at a window boundary, and its mode
comes from the shared list of #96.

### Why the parity harness never compared this value

`tests/test_foxio_rust_parity.py:72` reads
`SNAPSHOT_METHODS = (("JA4", "ja4"), ("JA4S", "ja4s"))`. **The harness parses the snapshot
that holds the two `ja4ssh` values and never reads the field.** This is the same shape
`docs/specs/foxio/JA4T.md` reports for `ja4t`, and `.claude/rules/conformance.md` names it
under "Ask whether a case can fail".

### The ruling #214 made

**`ja4plus` closes the last window at the end of a capture, as the Rust and Zeek
references do.** The user decided it on 2026-08-08, and the ruling is reversible.

Two reasons carry the ruling.

1. **The specification cannot settle it, and the reference values can.** #199 read the
   deleted `technical_details/JA4SSH.md`, and it states nothing about a FIN packet, a
   connection that closes, the end of a capture or a trailing window.
2. **Two FoxIO references agree on the value, and this repository already held the
   proof.** `tests/foxio_vectors/rust_expected/ja4__insta@ssh2.pcapng.snap:215-217` and
   the Zeek baseline both hold `c36s52_c42s76_c51s2`, and the `ja4plus` counters already
   held that value.

**`tests/foxio_vectors/ssh2.pcapng.json` holds a different second value, and the conflict
resolves.** `.claude/rules/external-apis.md` states that `python/test/testdata/` decides
where it and a Rust snapshot both carry a value for one method on one stream. Here the
Python value is `c36s36_c0s0_c2s0`, which #97 declines, so the precedence rule points at a
value this project already declined. The decline outranks it, and the Rust snapshot
decides.

**The rule that licenses this reading is "A declined FoxIO Python value forfeits its
precedence" in `.claude/rules/external-apis.md`.** The register key is
`ssh2.pcapng/14:57377/JA4SSH.2`, the entry carries `"decided": true` under #97, the
decline records a disagreement about the value, and the Rust snapshot and the Zeek
baseline both hold `c36s52_c42s76_c51s2` for that method on that connection. The rule
therefore lets either one hold the reference value.
`tests/test_precedence_exception.py` measures the reach and holds this row.

**The page asserted this reading before the rule licensed it.** #332 wrote the exception
for the Zeek baseline alone, and the sentence above names the Rust snapshot. #334 made
the exception source-neutral and wrote this citation, so the next reader checks the rule
rather than trusting the page.

**#97 stays declined, and its reasoning is unchanged.** A window that holds no SSH packet
describes no traffic. `ja4plus/fingerprinters/ja4ssh.py:368-369` holds the guard, and the
new rule reaches it.

**The guard is proven by its removal.** Replace the guard condition with `False` and 11
cases fail. Five of the eleven are new cases of #214. Four cases name the decline
directly.

- `test_the_end_of_the_capture_emits_nothing_for_a_connection_of_bare_acks_alone`
- `test_the_end_of_the_capture_emits_nothing_when_the_open_window_holds_no_ssh_packet`
- `test_processor_close_open_windows_declines_a_window_with_no_ssh_packet`
- `test_the_long_capture_produces_no_declined_empty_window`

### What the change moved

**Six JA4SSH comparisons moved, and no value of another method moved.** The measurement
replayed all 38 committed captures.

| Vector | Value the end of the capture adds |
|---|---|
| `ssh2.pcapng` | `c36s52_c42s76_c51s2` |
| `ssh.pcapng` | `c36s52_c42s76_c0s0` |
| `ssh-scp-1050.pcap` | `c0s1460_c0s53_c6s0` |
| `ssh2-malformed.pcap` | `c16s23_c7s6_c3s4` |
| `ssh2-moloch-crash.pcap` | `c16s23_c7s6_c3s4` |
| `tcpdump-geneve.pcap` | `c144s48_c10s11_c6s4` |

**`gre-sample.pcap`, `sshv1.pcap` and `v6.pcap` did not move.** Each one carries a FIN+ACK
packet, so each already produced a trailing value. The rule is now one rule for every
capture.

**The register moved by four keys, from 116 to 120.** It lost `ssh2.pcapng/JA4SSH`,
because the occurrence keys of that vector now equal the reference. It gained one entry
under #214 for each of the five other vectors, because the FoxIO Python reference emits no
trailing window for a connection that sends no FIN+ACK packet.

## The comparison against this project

The comparison below reads `ja4plus/fingerprinters/ja4ssh.py` at commit `ec01cdc`. **Every
field is named. A field this table does not name is a field nobody read.**

### The fields that agree

| Field | Rule | `ja4ssh.py` | Reading |
|---|---|---|---|
| Part count and separator | R1 | `ja4ssh.py:393` | Agrees. `f"{part_a}_{part_b}_{part_c}"`. |
| Part a shape | R1 | `ja4ssh.py:380` | Agrees. `f"c{client_mode}s{server_mode}"`. |
| Part b shape | R1 | `ja4ssh.py:385` | Agrees. `f"c{client_ssh_count}s{server_ssh_count}"`. |
| Part c shape | R1 | `ja4ssh.py:390` | Agrees. `f"c{client_ack_count}s{server_ack_count}"`. |
| Part a source | R2 | `ja4ssh.py:373-378` | Agrees. The mode reads the lengths `SSHMessageTracker.add_segment` returns, which are TCP payload lengths. |
| Part a excludes a bare ACK | R3 | `ja4ssh.py:203-207` | Agrees. A bare ACK reaches the ACK counter and appends no length. |
| Mode tie-break | R4 | `ja4ssh.py:397-410` | Agrees. `min(v for v, c in counter.items() if c == max_count)`. |
| Mode of an empty list | R4 | `ja4ssh.py:404-405` | Agrees. Returns `0`, as `rust/ja4/src/ssh.rs:284` does with `unwrap_or(0)`. |
| Part b source | R5 | `ja4ssh.py:383-385` | Agrees. The counts read the SSH packet lists of the window. |
| Part b excludes a retransmission | R5 | `ja4ssh.py:176` | Agrees. `add_segment` drops a segment the direction already sent. Changelog round 28 holds the measurement. |
| Bare ACK definition | R6 | `ja4ssh.py:126` | Agrees. `int(tcp.flags) == ACK_FLAG and not packet.haslayer(Raw)`, and `ACK_FLAG` is `0x10`. |
| Window size | R7 | `ja4ssh.py:28` | Agrees. `DEFAULT_PACKET_COUNT = 200`. |
| Window is configurable | R7 | `ja4ssh.py:57` | Agrees. `__init__` takes `packet_count`. |
| Window counts both directions | R7 | `ja4ssh.py:212` | Agrees. It sums the two SSH packet lists. |
| A bare ACK does not advance the window | R7 | `ja4ssh.py:212` | Agrees. The sum reads no ACK counter. |
| Window boundary resets the counters | R8 | `ja4ssh.py:358-361` | Agrees. It clears both packet lists and both ACK counters. |
| One connection produces several fingerprints | R9 | `ja4ssh.py:347` | Agrees. Each window appends to `self.fingerprints`. |
| The empty window | #97 | `ja4ssh.py:342-343` | Agrees with `rust/ja4/src/ssh.rs:271-274`. Both emit nothing when the window holds no SSH packet. |
| FIN+ACK closes a window | R11, uncertain | `ja4ssh.py:221-222` | Agrees with `python/ja4.py:554-556` and `wireshark/source/packet-ja4.c:1400`. |
| The end of the capture closes a window | R11, uncertain | `ja4ssh.py:328-351` | Agrees with `rust/ja4/src/ssh.rs:45-55` and `zeek/ja4ssh/main.zeek:160-164`. #214 decided it. |

### The disagreements

**D1 — closed by #214.** `ja4ssh.py:221-222` closed the last window on a FIN+ACK packet
alone, and two references also close it at the end of the capture.

`rust/ja4/src/ssh.rs:45-55` and `zeek/ja4ssh/main.zeek:160-164` emit the held window when
the capture ends. `ja4plus` emitted nothing then, so `ssh2.pcapng` produced one
fingerprint here and two in both references. **The user decided on 2026-08-08 that
`ja4plus` emits the trailing window.** `ja4ssh.py:328-351`, `close_open_windows`, holds
the rule. The section "The trailing window" holds the measurement and the values.

**D2 — `ja4ssh.py:135` reads a connection that carries SSH data on any port, and
`python/ja4.py:549` reads only a connection with port 22 on one endpoint.**

`python/ja4.py:549` tests `(int(x['srcport']) == 22) or (int(x['dstport']) == 22)`, and
`wireshark/source/packet-ja4.c:1401` applies the same test on its FIN+ACK path.
`ja4ssh.py:135` admits a packet that carries SSH data on any port, so `ja4plus` can build
a connection that the Python reference never tracks. `rust/ja4/src/ssh.rs` names no port
and agrees with `ja4plus`, so the two references disagree with each other.

**No vector in this repository carries SSH traffic on a port other than 22, so no
measurement demonstrates D2.** The reading is a code reading. R7 and the whole
specification name no port, so nothing settles the rule.

**D3 — `ja4ssh.py:284-326` decides the client endpoint from three rules, and no
specification states one.**

`_decide_endpoints` reads port 22 first, then the TCP handshake, then the lower port as a
guess. `python/ja4ssh.py:104` falls back to `'client' if entry['src'] == x['src'] else
'server'`, which reads the first packet of the connection that reached the cache.
`python/ja4ssh.py:112-116` assigns a bare ACK by port 22 alone. The image writes `client`
and `server` and states no rule, so this is item 2 of "What the image does not state".

**On a connection whose server uses port 22, every rule gives the same answer**, so no
vector in this repository separates them. The reading is a code reading.

**D4 — `ja4ssh.py:214` tests `total_packets >= self.packet_count`, and two references test
equality.**

`rust/ja4/src/ssh.rs:35` tests `== sample_size` and `python/ja4ssh.py:125` tests
`% ssh_sample_count == 0`. `ja4ssh.py:201` extends the window with every message that one
segment completes. One packet can therefore advance the count by more than one. An
equality test would then miss the boundary. `zeek/ja4ssh/main.zeek:140` tests `>=`, per
`docs/specs/foxio/zeek.md`, so `ja4plus` agrees with the Zeek reference.

**This disagreement moves no measured fingerprint.** No vector in this repository crosses
the boundary by more than one packet.

### The fields that need no comparison

`ja4ssh.py` holds three groups the specification does not describe, so no rule of this
page reads them.

- `interpret_fingerprint`, at `ja4ssh.py:459`. It reads the three examples of the image as
  session labels. No reference implements it, and no vector measures it.
- The HASSH fields, at `ja4ssh.py:186-194` and `ja4ssh.py:412`. HASSH is not a JA4+ method.
  `python/ja4ssh.py:61-80` and `rust/ja4/src/ssh.rs:58-67` carry the same values as
  extras, outside the fingerprint.
- `generate_ja4ssh`, at `ja4ssh.py:571`. It builds a fingerprinter with a window of one
  packet, which R7 contradicts. No vector reads it.

## What the deleted text specification adds

**#221 read the deleted `technical_details/JA4SSH.md` again, and it changes no rule of this
page.** `docs/specs/foxio/deleted-text-specifications.md` holds that reading, with the
provenance of all seven deleted files.

**Every statement of the deleted file corroborates this page, and none contradicts it.**
Its three worked values equal the three the image gives, and its top example equals the
image's example.

**R11 gains its corroboration, and it gains it as a negative result.** #221 read the file
for a statement about the window boundary, and the file names no FIN packet, no connection
that closes, no end of a capture and no trailing window. **A source that states nothing is
not a source that states a rule**, so R11 stays uncertain and the vector fallback stays.
**#214 is still the user's ruling.**

## What this page does not do

- It adds no vector, and it moves no fingerprint.
- It changes no file under `ja4plus/`.
- It adds no entry to `tests/foxio_deviations.json`, and it removes none. The three
  declines stand.
- **It rules on nothing. #214 holds the one open ruling, and the user decides it.**
