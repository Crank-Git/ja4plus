# The seven deleted FoxIO text specifications

FoxIO published a text specification for seven methods. One commit deleted all seven.
This page records what each deleted file holds, and it reconciles each one against the
material FoxIO publishes today.

**Warning: no file of the FoxIO repository enters this repository.** JA4+ carries the
FoxIO license and this package publishes to PyPI. This page records a path, a commit, a
blob hash and a byte count. It quotes a sentence where the exact words decide a reading.

| Item | Value |
|---|---|
| Source | `https://github.com/FoxIO-LLC/ja4` |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Commit that deleted the seven files | `b6f3ff4`, titled `Update README.md`, dated 2024-02-22 |
| Retrieval date | 2026-08-08 |

Verified against: https://github.com/FoxIO-LLC/ja4 (retrieved 2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

Every measurement below comes from a checkout at the pinned commit. That checkout holds
the whole history, so each command reaches no network.

```bash
git log --oneline --diff-filter=D --name-only -- 'technical_details/*.md'
git ls-tree -l -r b6f3ff4^ -- technical_details/
```

## The rule this page follows

The user set the rule on 2026-08-08.

> Make sure these match up with the image specs though, they may have been deleted due to
> incorrectness or updates.

**A deleted file is not evidence of suppression. It is equally evidence of a correction.**
This page therefore reconciles, and it does not promote the deleted text. It applies four
readings.

1. **The material at the pinned commit outranks a deleted file wherever the two
   disagree.** The specification decides intent and schema, and the pinned material is
   what FoxIO publishes today.
2. **Where the deleted text agrees with the pinned material, it corroborates**, under the
   two-corroboration rule of `docs/specs/foxio/README.md`. FoxIO wrote it, so it is a
   strong corroboration.
3. **Where the deleted text states a rule the pinned material only draws, this page
   records it as a rule the pinned material does not state.** The rule stays uncertain
   until a second FoxIO-authored source that is not the deleted file corroborates it.
4. **Where the deleted text contradicts the pinned material, this page reports both
   readings and rules on nothing.** A contradiction is a finding. The user decides it.

## The provenance of each deleted file

Each file below sits at `b6f3ff4^`, the parent of the commit that deleted it. Each
SHA-256 comes from `shasum -a 256`, run on 2026-08-08 against the blob content.

| Path | Bytes | Blob SHA-1 | SHA-256 | Created by | State at the pinned commit |
|---|---|---|---|---|---|
| `technical_details/JA4.md` | 6922 | `02c493ad032c8828ccfa67dd60d607c4ee89a95c` | `a8c2b4c2ecf4f7836a04ad3f2614ca33d0b9f0836805aa3de9e6d0be6fbd20ec` | `11d9250`, `Create JA4.md` | Restored, and now 9153 bytes |
| `technical_details/JA4H.md` | 9137 | `15f0b265456210462c7a456cdb7c8e0e35b5dfe7` | `0587d4180145e7c1f02adde3583fbb2929486e85a05a082f5c139d21d16f918f` | `5fd3927`, `Create JA4H.md` | Replaced by a 278-byte file |
| `technical_details/JA4L.md` | 4205 | `8ee86952385d89d478af53f67581551e8ff6066f` | `bcf02bc318f7d783da45eff5d00aa32fb5f7b874688eb17e766ba3d6956e8247` | `f716c3b`, `Create JA4L.md`, 2023-09-25 | Absent |
| `technical_details/JA4S.md` | 1584 | `82cebff8f56e1d2776eb90ca8b1b0ca96709048b` | `d762c3aadf34ef3999bcbb777ca43c20db0b42923910cb7018430f292e6baf51` | `be85ab6`, `Create JA4S.md`, 2023-09-25 | Absent |
| `technical_details/JA4SSH.md` | 2288 | `e9bb04b11a06ee1dfd3dbeaa18b45a0138bcdf48` | `843c8f737ec40b4e38300021fcaca7ac8a058ed869ecda5de068fc57cf8af66c` | `cbef671`, `Create JA4SSH.md`, 2023-09-26 | Absent |
| `technical_details/JA4T.md` | 6423 | `54f207980273c77d5df928d592c694e4cae52cd7` | `d8ec985535f5bbf2cf411989f6ab19b17191585137e4ee448041e9ee91191d76` | `f0ae44c`, `Create JA4T.md`, 2024-02-09 | Absent |
| `technical_details/JA4X.md` | 1449 | `b0fc46f219c3956f5b9a74927a38115b02f37ad0` | `b094b74a74c541fabb6c3c01150fe10960f41047e6ef5ac8fd15c32259407c8b` | `8656f17`, `Create JA4X.md`, 2023-09-26 | Absent |

**The same commit deleted three images.** They illustrated `JA4T.md`, and no file at the
pinned commit references them.

| Path | Bytes | Blob SHA-1 |
|---|---|---|
| `technical_details/exampleja4t1.PNG` | 72549 | `43578d470ed704357353412455561c39856ed184` |
| `technical_details/exampleja4t2.PNG` | 36125 | `bac1d7c86f396831e4078820a5828d3184306e84` |
| `technical_details/exampleja4t3.PNG` | 28227 | `94bb0ff0e340282043655d7ab22e1555d9db8fac` |

Read one deleted blob with one command.

```bash
git cat-file -p b6f3ff4^:technical_details/JA4T.md
```

## What the deletion means, measured on the two files that came back

**`JA4.md` and `JA4H.md` were both deleted, and both names exist again at the pinned
commit. The two cases are opposite, and the measurement settles the user's question for
each one separately.**

### JA4.md — the deletion carried no correction

**The deleted blob and the restored blob are the same blob.** Both are
`02c493ad032c8828ccfa67dd60d607c4ee89a95c`, and both are 6922 bytes. `b6f3ff4` removed the
file on 2024-02-22, and `ad2e13c`, titled `Create JA4.md`, added the identical content back
five days later, on 2024-02-27.

```bash
git rev-parse b6f3ff4^:technical_details/JA4.md
git rev-parse ad2e13c:technical_details/JA4.md
```

Both commands print `02c493ad032c8828ccfa67dd60d607c4ee89a95c`.

**The deletion of `JA4.md` therefore corrected nothing.** It removed a file and restored
it unchanged. Every later change to `JA4.md` is an ordinary commit that follows the
restoration, and none of them belongs to the deletion.

**FoxIO later corrected two statements the deleted form holds.** `3e02a27`, dated
2024-08-23, is titled `Fix SSL version fields: SSL 2.0 is 0x0002, SSL 1.0 never existed`.
The table below reads the deleted form against the form at the pinned commit.

| Subject | The deleted form, 2024-02-22 | The pinned form, 9153 bytes |
|---|---|---|
| SSL 2.0 | `0x0200 = SSL 2.0 = “s2”` | `0x0002 = SSL 2.0 = “s2”` |
| SSL 1.0 | `0x0100 = SSL 1.0 = “s1”` | Absent. `3e02a27` states that SSL 1.0 never existed |
| DTLS | Absent | `0xfeff`, `0xfefd` and `0xfefc` write `d1`, `d2` and `d3`, and the first character `d` names DTLS |
| The first character | `(QUIC=”q” or TCP=”t”)` | `(QUIC=”q”, DTLS="d", or TLS over TCP=”t”)` |
| A non-cipher value | Silent | The cipher count and the cipher hash both keep SCSV and the reserved range |
| The ALPN value | `The first and last characters` | `The first and last ASCII alphanumeric characters`, with eight worked hexadecimal examples |
| An empty cipher list | Silent | `If there are no ciphers in the sorted cipher list, then the value of JA4_b is set to 000000000000` |
| The hash case | Silent | `All sha256 functions must output in lower case.` |

**The pinned form loses no rule the deleted form states.** Every difference adds a rule or
corrects one. The deleted `JA4.md` is therefore superseded in full, and it corroborates
nothing that the pinned `JA4.md` does not state better.

### JA4H.md — the deletion was never undone

**The 9137-byte file never came back.** `b6f3ff4` deleted blob
`15f0b265456210462c7a456cdb7c8e0e35b5dfe7` on 2024-02-22. Seven months later, on
2024-09-25, `f5ef25b`, titled `Add technical details file for JA4H`, created a **different**
337-byte file. `eee9a48` trimmed it to the 278 bytes the pinned commit holds.

```
9137 B   b6f3ff4^   the full text specification
   0 B   b6f3ff4    deleted, 2024-02-22
 337 B   f5ef25b    a new file with the same name, 2024-09-25
 278 B   eee9a48    the pinned form, 2025-02-15
```

**FoxIO replaced 9137 bytes of prose with an image and one rule.** The 278-byte file
states the purpose of JA4H and the two-digit header count. It builds no fingerprint.
`docs/specs/foxio/README.md` already records that reading, and this measurement confirms
it: JA4H is an image method by an explicit FoxIO choice, and not by an oversight.

**The replacement corrected a defect.** The deleted file states the cap on the header
count as `99 = anything > than 100 headers`. That sentence names two different thresholds.
The 278-byte file states `If there are more than 99, the output is 99.`, which names one.
`python/ja4h.py:55` writes `min(len(x['headers']), 99)` and `rust/ja4/src/http.rs:180`
writes `99.min(headers.len())`, so both implementations follow the corrected sentence.
`docs/specs/foxio/JA4H.md` R8 already holds the corrected rule.

### The reading the two cases give together

**A deletion in this repository is not one act with one meaning.** One of the two files
came back unchanged, and one never came back at all. The user's caution is therefore
correct, and this page applies it per statement rather than per file. A deleted sentence
that the pinned material contradicts is superseded. A deleted sentence that the pinned
material does not carry is a corroboration at best, and it stays uncertain alone.

## JA4SSH — the reading #214 needs

**#214 asked what closes the last JA4SSH window. This section reports what the deleted
file states. It answers nothing and it decides nothing.**

`rust/ja4/src/ssh.rs:283` at the pinned commit cites
`https://github.com/FoxIO-LLC/ja4/blob/16850cc2c8bcb8328c1a43a851a3a9a6eaa56103/technical_details/JA4SSH.md#how-to-measure-the-mode-for-tcp-payload-lengths-across-200-packets-in-the-session`,
so the citation outlived the file. **The blob that URL names is the blob this page read.**
`16850cc2c8bcb8328c1a43a851a3a9a6eaa56103:technical_details/JA4SSH.md` and
`b6f3ff4^:technical_details/JA4SSH.md` are both
`e9bb04b11a06ee1dfd3dbeaa18b45a0138bcdf48`.

```bash
git rev-parse 16850cc2c8bcb8328c1a43a851a3a9a6eaa56103:technical_details/JA4SSH.md
git rev-parse b6f3ff4^:technical_details/JA4SSH.md
```

### What the deleted JA4SSH.md states about a window boundary

**It states one boundary and no other.** The first sentence of the file reads
`Runs every n packets per SSH TCP stream. n = 200 by default but is configurable.` The
section heading reads
`How to measure the mode for TCP payload lengths across 200 packets in the session`. That
is the whole statement of the boundary.

### What the deleted JA4SSH.md states about the five things #214 asks

Each row states the truth, and four of the five rows are negative results.

| Subject | What the deleted `technical_details/JA4SSH.md` states |
|---|---|
| The window boundary | The window is `n` SSH packets per SSH TCP stream, `n = 200` by default, and `n` is configurable |
| The trailing window | **It states nothing.** The file names no partial window and no last window |
| A FIN packet | **It states nothing.** The word `FIN` does not appear in the file |
| A connection that closes | **It states nothing.** The file names no close, no teardown and no reset |
| The end of a capture | **It states nothing.** The file names no capture and no end of a capture |

**The deleted file therefore corroborates R11 of `docs/specs/foxio/JA4SSH.md`, and it
adds no rule.** R11 reads `The specification states no rule that closes the last window`,
and it stayed uncertain because #199 could not corroborate it. **This page corroborates
the negative result from the file FoxIO's own Rust implementation cites.** The gap is a
gap in the specification, and not a gap in the reading.

**R11 stays uncertain, and the vector fallback stays.** A second source that states
nothing is not a source that states a rule. **#214 is still the user's decision, and this
page does not answer it.**

### The rest of the deleted JA4SSH.md

**Every other statement of the deleted file corroborates
`docs/specs/foxio/JA4SSH.md`, and none contradicts it.** #199 already read this file, so
this page adds no rule. The three worked values it gives, `c36s36_c51s80_c69s0`,
`c76s76_c71s59_c0s70` and `c112s1460_c0s179_c21s0`, equal the three the image gives, and
its top example `c36s36_c55s75_c70s0` equals the image's example.

**Verdict for JA4SSH: the deleted text corroborates, and it extends nothing.**

## JA4T and JA4TS — the deleted text carries two findings

`docs/specs/foxio/JA4T.md` transcribes `technical_details/JA4T.png`. The deleted
`technical_details/JA4T.md` is 6423 bytes, and it is the largest source of new statements
this issue found.

### F1 — The deleted text states that JA4TS carries part e, and the image states that it does not

**This is a contradiction. This page reports both readings and rules on nothing.**

- **The image states**, per `docs/specs/foxio/JA4T.md` R2, that part e is
  `TCP Retransmission Timings (only on JA4TScan)`.
- **The deleted text states** the opposite. Its heading reads
  `__JA4TS and JA4TScan Fingerprint formats:__` and the form under it reads
  `WindowSize_TCPOptions_MSSValue_WindowScale_TimeSinceLastSYNACK`. It then states
  `JA4TS takes into account the number of SYNACK TCP Retransmissions, or RST, as well as
  the time delay between each retransmission or RST.` and
  `If no retransmissions are seen, as there shouldn't be in normal network communications,
  the fingerprint will omit section e. If retransmissions are seen, the fingerprint will
  fill out section e.`

**The deleted text agrees with the Wireshark dissector.** `docs/specs/foxio/JA4T.md` D6
records that `wireshark/source/packet-ja4.c:1595` writes the `JA4TS` field through `ja4t()`
with a connection, which appends part e. The image and `rust/ja4/src/tcp.rs` state the
other reading.

**The user decided for the deleted text on 2026-08-08, and #226 built part e.** The
decision reverses the D6 and D7 ruling of #215 of the same day, which followed the image.
R2 of `docs/specs/foxio/JA4T.md` now holds for JA4T alone, and R12 states the JA4TS rule.

**#226 read the blob rather than this page**, and it confirms every quotation above. It
also found a third source that this page does not name: `zeek/ja4t/main.zeek:227-236`
appends the delay list to `c$conn$ja4ts`, so two FoxIO implementations write part e on
JA4TS and only the image withholds it. The image's own example value `1-2-4-8-R6` carries
the `R` suffix that its caption denies.

**The two sentences on the omission rule decide the absent form.** A fingerprint omits
part e when it sees no retransmission, so part e is absent and it is not `00`. Both
implementations corroborate it, because each appends part e only when a delay exists.
`ja4plus` follows the rule, and it is why the Zeek comparison held at 9 of 10 across the
change: each of the ten baseline connections holds one SYN-ACK.

**The RST rules of this file stay unbuilt, and #246 owns them.** #226 measured that the
RST value separates from part e.

### F2 — The deleted text states the empty-field form, and the image states nothing

**This is a rule the image does not state.** `docs/specs/foxio/JA4T.md` R11 reads
`The image settles none of this.`

The deleted text states it in one sentence.

> If any field does not exist, then the output is 00. For example, a packet with a Window
> of 1024 and no TCP options, and therefore no Window scale would be:
> JA4T = 1024_00_00_00

Its example table carries the same form three times: `Nmap | 1024_2_1460_00`,
`Zmap | 65535_00_00_00` and `Web Scanner | 1024_00_00_00`.

**Read `00` as a placeholder for an absent field, and not as a width.** The `Nmap` row
writes a present option list as `2` and a present maximum segment size as `1460`, with no
padding. The two-character `00` marks absence alone.

**Two FoxIO-authored sources that are not the deleted file corroborate the form.**
`wireshark/source/packet-ja4.c:664` writes `00` for an empty option list, and
`zeek/tests/Traces/Scripts.ja4-conn/conn.log` holds `ja4t 65535_00_00_00`. **The rule
therefore holds two corroborations and it is no longer uncertain on the deleted file
alone.**

**One FoxIO reference contradicts it.** `rust/ja4/src/tcp.rs` joins an empty option list
to the empty string and pads nothing, and
`rust/ja4/src/snapshots/ja4__insta@gre-erspan-vxlan.pcap.snap` holds `8192__0_0`.
`ja4plus` wrote a third form, `8192_0_0_0`, until #215. The user decided the two-digit
form on 2026-08-08, so `ja4plus` now writes `8192_00_00_00` and follows this prose.

**#215 owns this decision and this page rules on nothing.** #215 item 1 asked which empty
form this project writes, with three candidate forms and no FoxIO prose. **This page
supplies the prose #215 lacked.** It names `00` and it names no other form.

### What else the deleted JA4T.md states

Each statement below corroborates a rule of `docs/specs/foxio/JA4T.md`, or it states a
rule the image does not state. None contradicts the image.

| Subject | The deleted text | Reading |
|---|---|---|
| The four parts | `WindowSize_TCPOptions_MSSValue_WindowScale` | Corroborates R1 |
| The packet each method reads | `JA4T fingerprints the TCP SYN packet sent from the client.` and `JA4TS fingerprints the TCP SYN ACK response packet(s) sent from the server.` | Corroborates R8 |
| The window size | `The TCP Window Size is captured in decimal` | Corroborates R3. It states no scaling, so it does not settle the raw reading on its own |
| The option list | `TCP options are limited to 1 byte.` and `Some specific devices will use options up to 255.` | Corroborates R4. The reference filters no kind |
| Option kind 1 and kind 0 | `Option 1 is used to pad the options to be divisible by 4 and option 0 is sometimes used to denote the end of the options list.` | Corroborates R5. The list carries a pad byte and an end byte |
| The option separator | `These would be captured as their decimal values, hyphen delimited` | Corroborates R4 |
| Part e delimiter and units | The worked example rounds each interval `to the nearest whole number in seconds` | A rule the image does not state. The image draws `1-2-4-8-R6` and states no unit |
| The RST suffix | `the final TCP packet, a RST packet, should be appended to the last JA4TS denoted with “R” and its delay` | A rule the image only draws. It corroborates `docs/specs/foxio/JA4T.md` D7 |
| A RST carries no state | `Note that RST packets do not contain TCP options or window sizes, as such the program will need to be aware of the previous JA4TS.` | A rule the image does not state |
| The state bound | `The max is 10 retransmissions counted and the timeout is 2 minutes after the last SYNACK.` | **A rule the image does not state, and no other FoxIO source states it.** It stays uncertain |
| JA4TS depends on the JA4T | `Note that the JA4TS is dependant on the JA4T that was sent to it.` | A statement about traffic. No implementation reads it |
| JA4TScan | `JA4TScan is a tool that sends a very specific SYN packet` | Corroborates that JA4TScan is a separate tool. `docs/specs/spec.md` records JA4TScan as out of scope |

**The state bound is the one rule with a single source.** `CLAUDE.md` requires a maximum
entry count and a maximum age on every state table, and this project already sets its own.
The deleted text names FoxIO's numbers, 10 retransmissions and 120 seconds. **Nothing else
in the FoxIO material names either number**, so a reader must not treat them as a
specification of this project's bounds.

**Verdict for JA4T and JA4TS: the deleted text corroborates eight rules, states five rules
the image does not state, and contradicts the image once, on part e of JA4TS.**

## JA4H — the deleted text carries one finding and one reference defect

`docs/specs/foxio/JA4H.md` transcribes `technical_details/JA4H.png` and the 278-byte file.
The deleted 9137-byte `JA4H.md` corroborates most of that page.

| Subject | The deleted text | Reading |
|---|---|---|
| The four parts | The six fields of part a, then the three hashes | Corroborates R1 and R2 |
| The version codes | `10 = HTTP/1.0`, `11 = HTTP/1.1`, `20 = HTTP/2`, `30 = HTTP/3` | Corroborates R4 |
| The cookie flag | `If there is a Cookie in the HTTP header, the value is “c”` | Corroborates R5. It reads the header |
| The referer flag | `If there is a Referer in the HTTP header, the value is “r”` | Corroborates R6. It reads the header |
| The omitted names | `This ignores the cookie and referer header as that is captured above.` | Corroborates R7 and R13 |
| The language field | `Use 0s if less than 4 characters are used or if no accept-language field exists.` | Corroborates R10 and R11 |
| The header order | `JA4H captures all HTTP header fields, case-sensitive` | Corroborates R14, and it states the case rule the image does not state |
| Part c | `The cookie fields are the values before “=” and are delimited by “;”.` | Corroborates R15 |
| Part d | `The cookie fields+values are now captured and sorted like above` | Corroborates R16 |
| The raw forms | It publishes `JA4H_r` and `JA4H_ro` with worked values | Corroborates `docs/specs/foxio/JA4H.md` D6, which found a `ja4.ja4h_r` key in the Wireshark expected output |

### F3 — The deleted text names exactly nine request methods, and the image does not close the list

**This is not a contradiction, and it is evidence #219 lacks.**

The deleted text gives a closed table.

```
ge = GET
he = HEAD
op = OPTIONS
tr = TRACE
de = DELETE
pu = PUT
po = POST
pa = PATCH
co = CONNECT
```

**The image's caption ends with `etc`**, per `docs/specs/foxio/JA4H.md` R3, so the image
closes no list. `rust/ja4/src/http.rs:364` to `rust/ja4/src/http.rs:379` writes the same
nine codes and no other. `python/ja4h.py:9` writes `method.lower()[:2]` for any method, so
it reads a tenth method.

**`docs/specs/foxio/JA4H.md` D1 records that `ja4plus` reads the same nine methods**, and
#219 item 5 asks whether it should read a method outside them. **The deleted text supports
the nine, the image does not close the list, and the Python reference reads any method.**
#219 owns the decision.

### F4 — The FoxIO worked example computes 11 headers and publishes 13

**This is a defect in the FoxIO example, and it is present in both the deleted text and
the image at the pinned commit. It changes no `ja4plus` fingerprint.**

The deleted text carries the request that produces the image's example value. The request
holds thirteen header fields, and two of them are `Cookie` and `Referer`. The deleted text
lists the eleven names it hashes, and it annotates the count field as
`11 (13 header fields minus Cookie and Referer as those are accounted for above)`.

**The value it then publishes is 13.** Both the file's worked example and its top example
read `JA4H=ge20cr13enus_...`, and `docs/specs/foxio/JA4H.md` records the same `13` in the
image at the pinned commit.

**The stated rule and the published example disagree.** The rule reads
`not counting Cookie and Referer`, and eleven names reach the hash. `ja4plus` follows the
rule, and so do all three FoxIO implementations. `docs/specs/foxio/JA4H.md` R7 and R9 hold
the rule, and two whole captures match the reference value for value.

**No issue follows from this.** The example is documentation, no implementation reads it,
and no vector carries it. This page records the measurement so that the next reader does
not repeat it.

**Verdict for JA4H: the deleted text corroborates ten rules, states one rule the image
does not state, supports the closed method list #219 asks about, and carries one example
defect that the image repeats.**

## JA4 — the deleted text is superseded in full

The section "JA4.md — the deletion carried no correction" holds the measurement.
`technical_details/JA4.md` at the pinned commit is the specification of JA4, and it is
text rather than an image. **The deleted form states no rule the pinned form omits.**

### F5 — `ja4plus` wrote the retracted SSL 2.0 version value

**#227 repaired this on 2026-08-08.** `ja4.py` and `ja4s.py` now hold `0x0002`, and
`0x0200` reaches the `00` fallback. `docs/implementation_notes.md` holds the reading and
the three FoxIO sources that decide it. The section below records the measurement #221
made, and it stays in the form #221 wrote it.

**This was a defect against the pinned specification, and #221 changed no file under
`ja4plus/`.**

`technical_details/JA4.md` at the pinned commit states `0x0002 = SSL 2.0 = “s2”`. The
deleted form states `0x0200 = SSL 2.0 = “s2”`, and `3e02a27`, dated 2024-08-23, is titled
`Fix SSL version fields: SSL 2.0 is 0x0002, SSL 1.0 never existed`.

**Three lines of `ja4plus` follow the retracted value.**

```
ja4plus/fingerprinters/ja4.py:127   elif version == 0x0200:  # SSL 2.0
ja4plus/fingerprinters/ja4.py:250   elif version == 0x0200:  # SSL 2.0
ja4plus/fingerprinters/ja4s.py:393  0x0200: "s2",  # SSL 2.0
```

A ClientHello whose protocol version is `0x0002` therefore writes `00`, and the pinned
specification requires `s2`.

**`ja4plus` already follows the pinned form everywhere else in that table.** It writes
`d1`, `d2` and `d3` for the three DTLS versions, which the deleted form does not carry, and
it writes no `s1`, which the deleted form does carry. **The stale value is one row of one
table, and it is the only row.**

**No vector measures it.** No capture in `tests/foxio_vectors/` carries an SSL 2.0 hello,
so no conformance case fails today and no register entry names it. **#227 shipped the
repair on 2026-08-08, and no fingerprint moved.**

## JA4S — the deleted text states nothing the material does not

`technical_details/JA4S.png` has no transcription yet. #201 owns it. This section records
the deleted `JA4S.md`, 1584 bytes, so that #201 starts from it.

| Subject | The deleted text |
|---|---|
| The form | `(q or t)`, then a two-character TLS version, a two-character extension count, the first and last character of the chosen ALPN, `_`, the chosen cipher suite in hex, `_`, a truncated SHA-256 of the extensions |
| The extension order | `with Server Hellos, the extensions are not being randomized, that means we can hash those in the order they are seen rather than sorting them` |
| The single cipher | `In the Server Hello packet, there is always a single cipher, the cipher that the server chose` |
| The absent ALPN | `00 here as there’s no ALPN extension` |
| The truncation | `Truncated to the first 12 characters` |
| The worked value | `JA4S = t120400_c030_4e8089b08790` |
| The raw form | `JA4S doesn’t sort so -o does nothing here.` and `JA4S_r = t120400_c030_0005,0017,ff01,0000` |

**One statement is superseded.** The deleted text writes the first character as
`(q or t)`. `technical_details/JA4.md` at the pinned commit adds `d` for DTLS, and
`ja4plus/fingerprinters/ja4s.py:276` already writes `d`. **Read the deleted `(q or t)` as
a file that predates the DTLS addition, and not as a rule that excludes `d`.** The deleted
`JA4S.md` is dated 2023-09-25 and the DTLS support arrived in `5903cd4`.

**Every other statement agrees with what `ja4plus` builds.** `ja4s.py:200` already carries
the comment `JA4S hashes the extensions in wire order`, and `ja4s.py:306` joins the
extensions with no sort.

**Verdict for JA4S: the deleted text corroborates the wire-order rule and the single-cipher
rule, states one superseded protocol list, and contradicts nothing. #201 reads the image.**

## JA4X — the deleted text states nothing the material does not

`technical_details/JA4X.png` has no transcription yet. #202 owns it. The deleted
`JA4X.md` is 1449 bytes, the smallest of the seven.

| Subject | The deleted text |
|---|---|
| The three parts | A truncated SHA-256 of the issuer RDNs, of the subject RDNs, and of the extensions, each `in the order they are seen` |
| The truncation | `When truncating SHA256 we are using the first 12 characters.` |
| The list form | `We use only the hex values for the RDNs, comma separated` |
| The worked value | `Issuer = 550403,550406,550408,55040a = 96a6439c8f5c` |
| The example | `Example JA4X = 96a6439c8f5c_96a6439c8f5c_aae71e8db6d7` |
| The raw form | `JA4X doesn’t sort so -o does nothing here.` |
| The purpose | `These certificates are encrypted in TLS 1.3 but are sent in clear text in TLS 1.2.` |

**The file carries one typographical defect.** One line reads
`JA4X = 96a6439c8f5c_96a6439c8f5c _aae71e8db6d7`, with a space before the second `_`. The
example three lines above it carries no space. **No implementation reads either line, and
the space is a defect in the prose alone.**

**Verdict for JA4X: the deleted text states the three-part form and the wire-order rule,
and it contradicts nothing. #202 reads the image.**

## JA4L — the deleted text states the whole distance model

`technical_details/JA4L.png` has no transcription yet. #200 and #204 own it. The deleted
`JA4L.md` is 4205 bytes, and it is the richest of the five that never came back.

**Warning: the JA4L image changed after the deletion.** `technical_details/JA4L.png` is
198175 bytes at `b6f3ff4^`, blob `b57217dff8eb3c0dd9843d2706448849b48c52cb`, and it is
162323 bytes at the pinned commit, blob `bb38546bfaf70ac2737c9d7a4f52670afed124b6`. **The
deleted text describes a form of the method that the current image may not draw.** #200
reads the current image and this page does not read either image.

| Subject | The deleted text |
|---|---|
| The unit | `Time is measured in microseconds (µs). 1ms = 1000µs.` |
| The two halves | `JA4L is split up into 2 measurements, client and server.` |
| The TCP points | `A` is the client SYN, `B` is the server SYN-ACK, `C` is the client ACK |
| The TCP formulas | `JA4L-C = {(C - B) / 2}_Client TTL` and `JA4L-S = {(B - A) / 2}_Server TTL` |
| The TCP worked values | `JA4L-C = 11_128` and `JA4L-S = 1759_42` |
| The QUIC points | `A` is the client Initial, `B` is the server Initial, `C` is the last server packet before the client sends again, `D` is the client handshake packet |
| The QUIC formulas | `JA4L-C = { (D - C) / 2 }_Client TTL` and `JA4L-S = { (B - A) / 2 }_Server TTL` |
| The distance formula | `D = jc/p` |
| The speed of light | `0.128 miles/µs or 0.206km/µs` |
| The terrain factors | `Poor terrain factor = 2`, `Good terrain factor = 1.5` |
| The hop-count table | `<= 21` gives 1.5, then 1.6, 1.7, 1.8, 1.9, and `>=26` gives 2.0 |
| The initial TTL | 255 for networking devices, 128 for Windows, 64 for Mac, Linux, phones and IoT |
| The estimate rule | Below 64 estimates 64, `65-128` estimates 128, above 128 estimates 255 |
| The worked distance | `2449x0.128/1.6=195` from `JA4L-S` of `2449_42` |
| The multiple reading | `If there are multiple JA4Ls for the same host, the lowest value should be taken as the most accurate.` |

**`ja4plus` already builds this model.** `ja4plus/fingerprinters/ja4l.py:72` holds
`MILES_PER_MICROSECOND = 0.128`, `ja4l.py:57` and `ja4l.py:60` carry the hop-count table
with the same six factors, and `ja4l.py:260`, `estimate_hop_count`, applies the three
initial values. **The deleted text corroborates every one of those numbers**, and
Changelog round 20 records that #30 read the same table.

### The negative result the deleted JA4L.md gives

**It states no rounding rule.** The two formulas read `{(C - B) / 2}` and `{(B - A) / 2}`
and nothing states whether an odd microsecond count rounds or truncates.
`.claude/rules/external-apis.md` records that the Zeek script rounds and the FoxIO Python
reference truncates, and that this project follows the Python reference. **The deleted text
does not settle that divergence.**

**It states no third part and no `q` marker.** The deleted form carries two fields,
a latency and a TTL. `.claude/rules/external-apis.md` records that the Zeek script appends
a third part and marks a QUIC connection with a `q` part. **The deleted text corroborates
the two-field form that this project publishes**, and it corroborates the reading that the
two Zeek behaviours are Zeek's alone.

**Verdict for JA4L: the deleted text corroborates the whole distance model `ja4plus`
already builds, and it settles neither the rounding divergence nor the third Zeek part.
#200 reads the current image, which changed after the deletion.**

## The findings this page raises

**This page changes no file under `ja4plus/`, moves no fingerprint, and rules on nothing.**

| Finding | Subject | Owner |
|---|---|---|
| F1 | JA4TS part e. The deleted `JA4T.md` states that JA4TS carries part e, and the image states that part e appears only on JA4TScan | **#226.** It names #215 item 4 as the issue a triager may fold it into |
| F2 | The empty JA4T field is `00`. The deleted `JA4T.md` states the form the image does not state, and Wireshark and Zeek corroborate it. `rust/ja4/src/tcp.rs` writes another form and `ja4plus` writes a third | #215 item 1, which lacked FoxIO prose |
| F3 | The deleted `JA4H.md` names exactly nine request methods, and the image ends its caption with `etc` | #219 item 5 |
| F4 | The FoxIO JA4H worked example computes 11 headers and publishes 13. The image repeats the value | No issue. It changes no fingerprint |
| F5 | `ja4plus` wrote `0x0200` for SSL 2.0, and the pinned `JA4.md` states `0x0002` | **#227 repaired it on 2026-08-08** |
| F6 | The JA4L image changed after the deletion, from 198175 bytes to 162323 bytes | #200, which reads the current image |

## What this page does not do

- It copies no FoxIO file into this repository.
- It changes no file under `ja4plus/`, and it moves no fingerprint.
- It rewrites no rule of `docs/specs/foxio/JA4T.md`, `JA4H.md` or `JA4SSH.md`.
- It adds no entry to `tests/foxio_deviations.json`, and it removes none.
- **It does not answer #214.** The deleted `JA4SSH.md` states nothing about the trailing
  window, and that negative result is the whole of this page's contribution to it.
