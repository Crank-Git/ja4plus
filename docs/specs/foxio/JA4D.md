# JA4D and JA4D6

This page is this project's own prose form of `technical_details/JA4D.png` and
`technical_details/JA4D6.png`. It follows the procedure in
`docs/specs/foxio/README.md`. No image enters this repository.

| Item | Value |
|---|---|
| Source | `https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4D.png` |
| Source | `https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4D6.png` |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-08 |
| SHA-256 of `JA4D.png` | `3d862024be16c0b4679179d5433e1dc823a4721ded5b8912de1876edc4895268` |
| SHA-256 of `JA4D6.png` | `26b06ae218761e532d04687131b52c88f7293f9f6f81b4e9c97f81cd8a078ff9` |

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details (retrieved 2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

Reproduce the two hashes from a checkout at the pinned commit.

```bash
shasum -a 256 technical_details/JA4D.png technical_details/JA4D6.png
```

## These two methods hold no text specification, and none ever existed

**JA4D and JA4D6 are the only two methods for which FoxIO has never published prose.**
`docs/specs/foxio/deleted-text-specifications.md` reads the seven text files that
commit `b6f3ff4` deleted on 2024-02-22. Those seven are `JA4.md`, `JA4H.md`, `JA4L.md`,
`JA4S.md`, `JA4SSH.md`, `JA4T.md` and `JA4X.md`. **Neither `JA4D.md` nor `JA4D6.md` is
among them, because neither file has ever existed.**

Measured on 2026-08-08 from a checkout at the pinned commit. The command reads the whole
history and it reaches no network.

```bash
git log --all --oneline --name-only --diff-filter=ADR -- '*JA4D*'
```

It reports one commit, `6239c08`, titled `Adding JA4D/6`, dated 2025-11-07. That commit
adds `technical_details/JA4D.png` and `technical_details/JA4D6.png` and nothing else.
Neither image has changed since.

**Two consequences follow, and a later reader must weigh both.**

1. **The image is the only FoxIO prose that has ever specified either method.** Every
   other page under `docs/specs/foxio/` can reach a deleted text file for a second
   FoxIO-authored statement. This page cannot.
2. **The two-corroboration rule of `docs/specs/foxio/README.md` is therefore satisfied
   from implementations alone.** The corroborations below are the Wireshark dissector,
   the Zeek scripts, the two Wireshark expected-output files, the Zeek baseline and the
   two documented values in `README.md`. **An uncertain rule on this page is uncertain
   because one implementation states it and no second implementation states anything**,
   which is a weaker position than an uncertain rule on any other page.

**The images also postdate the deletion by 21 months.** `b6f3ff4` deleted the seven text
files on 2024-02-22, and `6239c08` added these two images on 2025-11-07. The reading of
`docs/specs/foxio/README.md` applies: rank a statement, and not a file. No statement of
either image corrects a deleted statement, because no deleted statement names either
method.

## The field layout of JA4D

The image titles itself `JA4D: DHCP Fingerprint` and subtitles the example
`(iPhone Example)`. It draws one example string and labels three parts `a`, `b` and `c`.

```
JA4D=reqst1500in_55-57-61-51-12_1-121-3-6-15-108-114-119-252
     \_________/ \____________/ \_________________________/
          a             b                    c
```

The image boxes four subfields inside part a and captions each one. It captions part b and
part c below the string.

| Part | Subfield | The image's caption | Value in the example |
|---|---|---|---|
| a | 1 | DHCP Message Type | `reqst` |
| a | 2 | Maximum DHCP Message Size | `1500` |
| a | 3 | Requesting specific IP (i) or New IP (n) | `i` |
| a | 4 | Has a Domain name (d) or No domain (n) | `n` |
| b | — | DHCP Options List, ignoring options 50, 53, 81, and 255 | `55-57-61-51-12` |
| c | — | DHCP Parameter Request List | `1-121-3-6-15-108-114-119-252` |

The parts join with `_`. The four subfields of part a join with nothing. The values inside
part b and part c join with `-`.

## The field layout of JA4D6

The image titles itself `JA4D6: DHCPv6 Fingerprint` and subtitles the example
`(Windows 11 Example)`. It uses the same three-part layout.

```
JA4D6=solct0014nn_8-1-3-39-16-6_17-23-24-39
      \_________/ \____________/ \_________/
           a            b             c
```

| Part | Subfield | The image's caption | Value in the example |
|---|---|---|---|
| a | 1 | DHCPv6 Message Type | `solct` |
| a | 2 | Client DUID Length | `0014` |
| a | 3 | Requesting specific IP (i) or New IP (n) | `n` |
| a | 4 | Has a Domain name (d) or No domain (n) | `n` |
| b | — | DHCPv6 Options List | `8-1-3-39-16-6` |
| c | — | DHCPv6 Option Request List | `17-23-24-39` |

**Two captions differ from the JA4D image, and the difference decides two rules.**

1. Subfield 2 reads `Client DUID Length`, where the JA4D image reads
   `Maximum DHCP Message Size`.
2. The part b caption reads `DHCPv6 Options List` with no exclusion clause, where the
   JA4D caption reads `DHCP Options List, ignoring options 50, 53, 81, and 255`.

## The rules

Each rule carries two corroborations unless it is marked uncertain. No corroboration is an
image. Each in-repository citation reads the pinned commit.

### R1 — JA4D holds three parts, joined with `_`

The fingerprint is `<part a>_<part b>_<part c>`. It hashes nothing.

- Corroboration 1: `wireshark/source/packet-ja4.c:713-720`, the function `ja4d()`, writes
  the format `"%s%s%c%c_%s_%s"`.
- Corroboration 2: `zeek/ja4d/main.zeek:113-118` appends `FINGERPRINT::delimiter` twice,
  and `zeek/config.zeek:4` sets that delimiter to `_`.

### R2 — Part a concatenates four subfields with no separator

Part a is `<message type><size><ip character><domain character>`. The message type holds
five characters, the size holds four characters, and each of the last two holds one
character. Part a therefore holds eleven characters.

- Corroboration 1: `wireshark/source/packet-ja4.c:713-720` writes the four values with no
  separator between them.
- Corroboration 2: `README.md:154` states
  ```JA4D=disco0000in_61-12-60-55_1-3-6-15-31-33-43-44-46-47-119-121-249-252```. Part a of
  that value is `disco0000in`, which holds eleven characters.

### R3 — The DHCP message type is a five-character name from a table of eighteen

- Corroboration 1: `wireshark/source/packet-ja4.c:804-832`, the function
  `get_dhcp_type_code`, maps codes 1 to 18 to `disco`, `offer`, `reqst`, `decln`,
  `dpack`, `dpnak`, `relse`, `infor`, `frenw`, `lqery`, `lunas`, `lunkn`, `lactv`,
  `blklq`, `lqdon`, `actlq`, `lqsta` and `dhtls`.
- Corroboration 2: `zeek/ja4d/consts.zeek:4-23` holds the same eighteen names against the
  same eighteen codes. `docs/specs/foxio/zeek.md:411` records that reading.

### R4 — An unknown DHCP message type gives the five-digit decimal code

- Corroboration 1: `wireshark/source/packet-ja4.c:1504` writes `"%05u"` when
  `get_dhcp_type_code` returns no name.
- Corroboration 2: `zeek/ja4d/main.zeek:51` writes `fmt("%05d", msg$m_type)` when the map
  holds no entry.

### R5 — The maximum message size is four decimal digits, 9999 at most, and `0000` when absent

- Corroboration 1: `wireshark/source/packet-ja4.c:1507-1516` writes `"%04d"` below 9999
  and the literal `9999` at 9999 or above. `wireshark/source/packet-ja4.c:706-707` writes
  `0000` when the option is absent.
- Corroboration 2: `zeek/ja4d/main.zeek:55-63` writes `9999` above 9999, `fmt("%04d", ...)`
  otherwise, and `0000` when the option is absent.

`README.md:154` and all four values of `wireshark/test/testdata/dhcp.pcapng.json` hold
`0000`, so the absent form reaches a reference value.

### R6 — The ip character is `i` when the message requests a specific address, else `n`

- Corroboration 1: `wireshark/source/packet-ja4.c:1518-1520` sets `'i'` when the field
  `dhcp.option.requested_ip_address` exists.
- Corroboration 2: `zeek/ja4d/main.zeek:65-70` returns `"i"` when `options?$addr_request`
  holds, which is DHCP option 50.

**The two references read two different things.** The dissector reads the address inside
option 50, and the Zeek script reads the presence of option 50. An option 50 that carries
no address distinguishes them, and no vector carries one. The distinction changes no value
in this repository.

### R7 — The domain character is `d` when the message carries a domain name, else `n`

- Corroboration 1: `wireshark/source/packet-ja4.c:1521-1523` sets `'d'` when the field
  `dhcp.fqdn.name` exists.
- Corroboration 2: `zeek/ja4d/main.zeek:72-77` returns `"d"` when `options?$client_fqdn`
  holds, which is DHCP option 81.

**The two references read two different things, and the image's caption sides with the
dissector.** The caption reads `Has a Domain name (d) or No domain (n)`, which names the
name and not the option. An option 81 that carries an empty name distinguishes the two
readings, and no vector carries one.

### R8 — Part b lists the DHCP option codes in wire order, joined with `-`

Nothing sorts part b and nothing deduplicates it.

- Corroboration 1: `wireshark/source/packet-ja4.c:1524-1529` appends each
  `dhcp.option.type` value with `"%d-"` in the order Wireshark reports the fields.
- Corroboration 2: `zeek/ja4d/main.zeek:79-85` calls `vector_of_count_to_str` on
  `options$options` with the separator `-`, and `zeek/utils/common.zeek:21-33` walks that
  vector in index order. `docs/specs/foxio/zeek.md:414-415` records that it sorts nothing.

`wireshark/test/testdata/dhcp.pcapng.json` frame 4 holds `dpack0000nn_58-59-51-54-1_00`,
whose part b is not in ascending order.

### R9 — Part b omits option codes 50, 53, 81 and 255

- Corroboration 1: `zeek/ja4d/consts.zeek:25-30` holds
  `DHCP_SKIP_OPTIONS: set[count] = { 53, 255, 50, 81 }`, which is the same four codes the
  image's caption names.
- Corroboration 2: the four values of `wireshark/test/testdata/dhcp.pcapng.json` and the
  four values of `zeek/tests/Traces/Scripts.ja4-dhcp/ja4d.log` carry none of the four
  codes, and each of the four frames carries option 53.

**The dissector names a different set, and this page reports both readings.**
`wireshark/source/packet-ja4.c:1526` tests `val != 0 && val != 53 && val != 50 &&
val != 81`. It names code 0 and it does not name code 255. The image and the Zeek script
name code 255 and neither names code 0. The output of the four vectors is the same under
both sets, so no reference value separates them.

**The Zeek baseline also shows that Zeek never sees code 255.**
`zeek/utils/common.zeek:30-32` appends the separator whenever the index is below the last
index, so a skipped last element would leave a trailing `-`. `ja4d.log` holds
`disco0000in_61-55_1-3-6-42` with no trailing `-`, so `options$options` ends at code 55
and holds no End option. The Zeek entry for 255 is therefore defensive, and no run
exercises it.

### R10 — Part b omits the Pad option, code 0

**This rule is uncertain. It holds one corroboration.** Keep the vector fallback.

- `wireshark/source/packet-ja4.c:1526` tests `val != 0`.
- The image states nothing about code 0. `zeek/ja4d/consts.zeek:25-30` states nothing
  about code 0. No reference value carries a Pad option.

### R11 — An empty part b gives `00`, and an empty part c gives `00`

- Corroboration 1: `wireshark/source/packet-ja4.c:708-711` writes `00` into the option
  list and into the request list when either holds no character.
- Corroboration 2: `zeek/ja4d/main.zeek:80-83` and `zeek/ja4d/main.zeek:88-90` each
  return `"00"`.

`wireshark/test/testdata/dhcp.pcapng.json` frames 2 and 4 hold `_00` as part c.

### R12 — Part c holds the Parameter Request List of option 55, in wire order

- Corroboration 1: `wireshark/source/packet-ja4.c:1530-1534` appends each
  `dhcp.option.request_list_item` value with `"%d-"`.
- Corroboration 2: `zeek/ja4d/main.zeek:87-92` writes `options$param_list` with the
  separator `-` and no skip set.

`README.md:154` holds `1-3-6-15-31-33-43-44-46-47-119-121-249-252`, and the image example
holds `1-121-3-6-15-108-114-119-252`. Neither is in ascending order.

### R13 — JA4D reads one DHCP message and holds no connection state

- Corroboration 1: `zeek/ja4d/main.zeek:123-124` carries the comment
  `We log per DHCP message for this fingerprint instead of aggregating across a DHCP
  conversation`, and `zeek/ja4d/main.zeek:125-128` calls `do_ja4d` on each
  `dhcp_message` event.
- Corroboration 2: `wireshark/source/packet-ja4.c:943-950` builds `ja4d_info_t` inside the
  per-packet function, and `wireshark/source/packet-ja4.c:1662-1672` emits one value for
  that packet.

Both baselines hold one value for each of the four frames of `dhcp.pcapng`.

### R14 — JA4D6 holds the same three-part shape as JA4D

- Corroboration 1: `wireshark/source/packet-ja4.c:702-721` holds one builder, and
  `wireshark/source/packet-ja4.c:1662-1672` calls it for both DHCP and DHCPv6.
- Corroboration 2: `README.md:155` states ```JA4D6=solct0010nn_8-1-3-6_24-23```, whose
  part a holds eleven characters and whose three parts join with `_`.

### R15 — The DHCPv6 message type is a five-character name, and an unknown type gives the five-digit code

**The table is uncertain beyond the one entry a second source states.** Keep the vector
fallback for any entry other than `solct`.

- `wireshark/source/packet-ja4.c:833-878`, the function `get_dhcpv6_type_code`, maps codes
  1 to 37 and writes `"%05u"` at `wireshark/source/packet-ja4.c:1544` for any other code.
- `README.md:155` states `solct` for a Solicit message, which corroborates code 1 alone.
- No second FoxIO implementation exists. `zeek/README.md:15` states
  `JA4D6 &rarr; ja4d.log (awaiting Zeek DHCPv6 suppport)`, so the Zeek package builds no
  JA4D6.

The six values of `wireshark/test/testdata/dhcpv6.pcap.json` exercise four more entries:
`solct`, `advrt`, `reqst`, `reply` and `relse`.

### R16 — Subfield 2 of JA4D6 holds the Client DUID length in bytes, as four decimal digits

**This rule is uncertain. It holds one corroboration.** Keep the vector fallback.

- `wireshark/source/packet-ja4.c:1547-1559` writes the byte length of the field
  `dhcpv6.duid.bytes` with `"%04d"`, capped at 9999. The guard reads the length only after
  DHCPv6 option type 1, the Client Identifier, appears, and only while the subfield is
  still empty.
- The image caption reads `Client DUID Length`, which names the same thing.
- `README.md:155` holds `0010` and states no meaning for it. That value is consistent with
  a DUID of ten bytes, and it corroborates the width and not the source.

### R17 — Part b of JA4D6 lists every DHCPv6 option code in the order Wireshark reports it, and omits none

- Corroboration 1: `wireshark/source/packet-ja4.c:1566-1573` appends every
  `dhcpv6.option.type` value with `"%d-"` and applies no skip test. The JA4D skip test at
  `wireshark/source/packet-ja4.c:1526` has no JA4D6 equivalent.
- Corroboration 2: `README.md:155` holds `8-1-3-6`, which is not in ascending order and
  which carries option 1, the Client Identifier that subfield 2 already reports.

The image corroborates the second half of the rule from the other side: the JA4D caption
carries the clause `ignoring options 50, 53, 81, and 255` and the JA4D6 caption carries no
such clause.

### R18 — Part c of JA4D6 holds the Option Request option, code 6, in wire order

- Corroboration 1: `wireshark/source/packet-ja4.c:1574-1578` appends each
  `dhcpv6.requested_option_code` value with `"%d-"`.
- Corroboration 2: `README.md:155` holds `24-23`, which is not in ascending order.

### R19 — The ip character of JA4D6 is `i` when the message carries an IA_TA option

**This rule is uncertain. It holds one corroboration.** Keep the vector fallback.

- `wireshark/source/packet-ja4.c:1560-1562` sets `'i'` when the field `dhcpv6.iata`
  exists. That field belongs to DHCPv6 option 4, IA_TA.
- The image caption reads `Requesting specific IP (i) or New IP (n)` and names no option.
- All six values of `wireshark/test/testdata/dhcpv6.pcap.json` hold `n`, so no reference
  value exercises `i`.

### R20 — The domain character of JA4D6 is `d` when the message carries a client domain

**This rule is uncertain. It holds one corroboration.** Keep the vector fallback.

- `wireshark/source/packet-ja4.c:1563-1565` sets `'d'` when the field
  `dhcpv6.client_domain` exists. That field belongs to DHCPv6 option 39, Client FQDN.
- All six values of `wireshark/test/testdata/dhcpv6.pcap.json` hold `n`, so no reference
  value exercises `d`.

### R21 — An empty part b or an empty part c of JA4D6 gives `00`

- Corroboration 1: `wireshark/source/packet-ja4.c:708-711`, the shared builder.
- Corroboration 2: `wireshark/test/testdata/dhcpv6.pcap.json` frames 5, 8 and 12 hold `00`
  as part c.

### R22 — The dissector publishes JA4D6 under the field name `ja4.ja4d`

The dissector registers one field for both methods. It registers no `ja4.ja4d6`.

- Corroboration 1: `wireshark/source/packet-ja4.c:1741` registers `{"JA4D", "ja4.ja4d"}`,
  and `wireshark/source/packet-ja4.c:1671` writes both methods through it.
- Corroboration 2: `wireshark/README.md:178` lists one row, `**JA4D** (DHCP)` against
  `ja4.ja4d`, and every entry of `wireshark/test/testdata/dhcpv6.pcap.json` uses the key
  `ja4.ja4d`.

## The search for a reference value

The issue that produced this page states that JA4D and JA4D6 have no Python reference.
**The measurement confirms that statement, and it corrects nothing.** The search below ran
on 2026-08-08 against a checkout at the pinned commit, outside this repository.

| Source searched | Result |
|---|---|
| `python/` | **No implementation.** The directory holds `ja4.py`, `ja4h.py`, `ja4ssh.py`, `ja4x.py` and `common.py`, and no DHCP module. `grep -ril 'ja4d\|dhcp' python/` reports no file. |
| `python/test/testdata/dhcp.pcapng.json` | `[]` |
| `python/test/testdata/dhcpv6.pcap.json` | `[]` |
| `rust/ja4/src/` | **No implementation.** `grep -ril 'ja4d\|dhcp' rust/` reports no file. No snapshot holds a `ja4d` key. |
| `wireshark/source/packet-ja4.c` | **The implementation of both methods.** One builder, `ja4d()`, and two field-extraction blocks. |
| `wireshark/test/testdata/dhcp.pcapng.json` | **Four JA4D values**, under the key `ja4.ja4d`. |
| `wireshark/test/testdata/dhcpv6.pcap.json` | **Six JA4D6 values**, under the same key `ja4.ja4d`. |
| `zeek/ja4d/` | **The implementation of JA4D alone.** `zeek/README.md:15` states `awaiting Zeek DHCPv6 suppport` for JA4D6. `docs/specs/foxio/zeek.md:37-38` records it. |
| `zeek/tests/Traces/Scripts.ja4-dhcp/ja4d.log` | **Four JA4D values**, equal to the four Wireshark values. #198 owns that reading. |
| `README.md` at the pinned commit | **One documented JA4D value at line 154 and one documented JA4D6 value at line 155.** |
| `technical_details/` | Two images and no text file. |
| `technical_details/*.md` across the whole history | **No `JA4D.md` and no `JA4D6.md` has ever existed.** |
| `ja4plus-mapping.csv` | **No column for either method.** Its header is `Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes`, and 66 data rows carry no JA4D value. |
| `ja4-nginx-module` and `ja4tscan` | Neither project reads DHCP. `.claude/rules/external-apis.md` states that the nginx module is not a reference in any case. |
| A FoxIO blog post | **Not searched.** This reading reaches no network, so no blog post corroborates any rule on this page. |

Reproduce the two counts from a checkout at the pinned commit.

```bash
grep -c 'ja4.ja4d' wireshark/test/testdata/dhcp.pcapng.json wireshark/test/testdata/dhcpv6.pcap.json
git log --all --oneline --name-only --diff-filter=ADR -- '*JA4D*'
```

**JA4D reaches two independent FoxIO implementations. JA4D6 reaches one.**
`.claude/rules/external-apis.md` already records that reading, and this page confirms it
against the images.

## The comparison against this project

The comparison below reads `ja4plus/fingerprinters/ja4d.py` and
`ja4plus/fingerprinters/ja4d6.py` at commit `edfc7b2`. **Every field is named. A field
this table does not name is a field nobody read.**

### JA4D — the fields that agree

| Field | Rule | `ja4d.py` | Reading |
|---|---|---|---|
| Part count and separator | R1 | `ja4d.py:194` | Agrees. The format string is `f"{section_a}_{section_b}_{section_c}"`. |
| Part a layout | R2 | `ja4d.py:186` | Agrees. `f"{msg_type_str}{max_msg_size:04d}{request_ip_flag}{fqdn_flag}"` joins four subfields with nothing. |
| Message type table | R3 | `ja4d.py:21-40` | Agrees. The same eighteen names against the same eighteen codes. |
| Unknown message type | R4 | `ja4d.py:183` | Agrees. `f"{msg_type:05d}"`. |
| Size width | R5 | `ja4d.py:186` | Agrees. `{max_msg_size:04d}`. |
| Size cap | R5 | `ja4d.py:178` | Agrees. `min(parsed["max_msg_size"], 9999)`. |
| Size when absent | R5 | `ja4d.py:104` | Agrees. `max_msg_size = 0` gives `0000`. |
| Size source | R5 | `ja4d.py:132-133` | Agrees. Option 57, read as two bytes, big-endian. |
| ip character | R6 | `ja4d.py:134-135`, `ja4d.py:184` | Agrees with the Zeek reading. Option 50 presence gives `i`. |
| Domain character | R7 | `ja4d.py:136-137`, `ja4d.py:185` | Agrees with the Zeek reading. Option 81 presence gives `d`. |
| Part b order | R8 | `ja4d.py:128`, `ja4d.py:65` | Agrees. The parse loop appends in wire order and nothing sorts the list. |
| Part b separator | R8 | `ja4d.py:66` | Agrees. `"-".join(parts)`. |
| Part b skip set | R9 | `ja4d.py:45`, `ja4d.py:115` | Agrees on the result. `DHCP_SKIP_OPTIONS = {0, 53, 50, 81}` and the loop breaks at 255, so all five codes leave the list. |
| Pad option | R10 | `ja4d.py:117-118`, `ja4d.py:45` | Agrees with the dissector. R10 is uncertain. |
| Empty part b | R11 | `ja4d.py:66` | Agrees. `"00"`. |
| Empty part c | R11 | `ja4d.py:80-81` | Agrees. `"00"`. |
| Part c source | R12 | `ja4d.py:138-139` | Agrees. Option 55, byte for byte. |
| Part c order and separator | R12 | `ja4d.py:82` | Agrees. Wire order, joined with `-`. |
| State | R13 | `ja4d.py:200-208` | Agrees. `process_packet` reads one packet and `cleanup_connection` is a no-op. |

**Measured on 2026-08-08.** All four values of `tests/foxio_vectors/dhcp.pcapng` match the
four reference values, and this project emits no fifth value.

```
frame 1  ja4plus disco0000in_61-55_1-3-6-42        FoxIO disco0000in_61-55_1-3-6-42
frame 2  ja4plus offer0000nn_1-58-59-51-54_00      FoxIO offer0000nn_1-58-59-51-54_00
frame 3  ja4plus reqst0000in_61-54-55_1-3-6-42     FoxIO reqst0000in_61-54-55_1-3-6-42
frame 4  ja4plus dpack0000nn_58-59-51-54-1_00      FoxIO dpack0000nn_58-59-51-54-1_00
```

### JA4D — the disagreements

**No disagreement changes a value on any vector this repository holds.** Each item below is
a code reading, and each names the packet that would separate the two readings.

**D1 — `ja4d.py:168` selects a packet by UDP port, and no FoxIO source states a port.**

`if udp.sport not in _DHCP_PORTS and udp.dport not in _DHCP_PORTS: return None` reads
ports 67 and 68. The dissector reads whatever Wireshark dissects as DHCP, and the Zeek
script reads the `dhcp_message` event. A DHCP message on another port therefore reaches
the two references and not this project. The image states no port.

**D2 — `ja4d.py:141-142` emits nothing without option 53, and the Zeek script emits
`00000`.**

`if msg_type == 0: return None` requires the DHCP Message Type option.
`zeek/ja4d/main.zeek:43-45` returns `"00000"` when the message carries no type, which
builds a fingerprint from a BOOTP message. `wireshark/source/packet-ja4.c:1498` sets
`ja4d_data.proto` only inside the option 53 block, so the dissector agrees with this
project and the `00000` default at `wireshark/source/packet-ja4.c:705` is unreachable for
DHCP. **Two references against one.** No vector carries a BOOTP message.

**D3 — `ja4d.py:136-137` reads the presence of option 81, and the dissector reads the name
inside it.**

R7 records that the image caption sides with the dissector. An option 81 that carries a
zero-length name gives `d` here and gives `n` in the dissector. No vector carries one.

**D4 — `ja4d.py:132-133` keeps the last option 57, and the dissector concatenates every
option 57.**

`max_msg_size = (opt_data[0] << 8) | opt_data[1]` runs on each occurrence, so a repeated
option 57 keeps the last. `wireshark/source/packet-ja4.c:1508-1512` appends `"%04d"` to
the same buffer on each occurrence, so a repeated option 57 gives an eight-digit subfield
and an unreadable part a. **The dissector reading is a defect of the dissector.**
`zeek/ja4d/main.zeek:55-63` reads one value. No vector carries a repeated option 57.

**D5 — `ja4d.py:138-139` keeps the last option 55, and the dissector concatenates every
option 55.**

`param_list = list(opt_data)` overwrites on each occurrence.
`wireshark/source/packet-ja4.c:1530-1534` appends every `dhcp.option.request_list_item`,
so a split Parameter Request List reaches part c whole in the dissector and in part here.
RFC 3396 allows a long option to split. No vector carries one.

**D6 — `ja4d.py:42-44` cites two FoxIO pull requests as the source of the skip set, and
this page now holds the FoxIO statement.**

The comment reads `Options to skip in section b (per FoxIO spec PR #267/#270)`. Neither
number can be read from a checkout at the pinned commit. **R9 replaces that citation**:
the image caption states the four codes, and `zeek/ja4d/consts.zeek:25-30` states the same
four.

### JA4D6 — the fields that agree

| Field | Rule | `ja4d6.py` | Reading |
|---|---|---|---|
| Part count and separator | R14 | `ja4d6.py:212` | Agrees. `f"{section_a}_{section_b}_{section_c}"`. |
| Part a layout | R14 | `ja4d6.py:208` | Agrees. Eleven characters, four subfields, no separator. |
| Message type table | R15 | `ja4d6.py:31-69` | Agrees. The same thirty-seven names against the same thirty-seven codes as `wireshark/source/packet-ja4.c:833-878`. |
| Unknown message type | R15 | `ja4d6.py:202` | Agrees. `f"{msg_type:05d}"`. |
| Size source | R16 | `ja4d6.py:140-141` | Agrees. The length of the option 1 data. |
| Size width and cap | R16 | `ja4d6.py:203-204` | Agrees. `min(..., 9999)` and `f"{duid_len:04d}"`. |
| Size when absent | R16 | `ja4d6.py:124` | Agrees. `duid_len = 0` gives `0000`. |
| ip character | R19 | `ja4d6.py:142-143`, `ja4d6.py:205` | Agrees. Option 4, IA_TA. R19 is uncertain. |
| Domain character | R20 | `ja4d6.py:144-145`, `ja4d6.py:206` | Agrees. Option 39. R20 is uncertain. |
| Part b order | R17 | `ja4d6.py:85-106` | Agrees. `_walk_options` appends in wire order and nothing sorts the list. |
| Part b skip set | R17 | `ja4d6.py:163-166` | Agrees. The builder omits no code. |
| Part b separator | R17 | `ja4d6.py:166` | Agrees. `"-".join(...)`. |
| Empty part b | R21 | `ja4d6.py:164-165` | Agrees. `"00"`. |
| Empty part c | R21 | `ja4d6.py:170-171` | Agrees. `"00"`. |
| Part c source | R18 | `ja4d6.py:146-151` | Agrees. Option 6, read as two-byte codes. |
| Part c order and separator | R18 | `ja4d6.py:172` | Agrees. Wire order, joined with `-`. |
| Field name of the reference | R22 | `tests/test_ja4d6_foxio.py:39` | Agrees. The test reads the key `ja4.ja4d`. |
| State | R14 | `ja4d6.py:218-225` | Agrees. `process_packet` reads one packet and `cleanup_connection` is a no-op. |

**Measured on 2026-08-08.** All six values of `tests/foxio_vectors/dhcpv6.pcap` match the
six reference values, and this project emits no seventh value.

```
frame  2  ja4plus solct0014nn_1-6-8-25_23-24         FoxIO solct0014nn_1-6-8-25_23-24
frame  5  ja4plus advrt0014nn_25-26-1-2_00           FoxIO advrt0014nn_25-26-1-2_00
frame  7  ja4plus reqst0014nn_1-2-6-8-25-26_23-24    FoxIO reqst0014nn_1-2-6-8-25-26_23-24
frame  8  ja4plus reply0014nn_25-26-1-2_00           FoxIO reply0014nn_25-26-1-2_00
frame 11  ja4plus relse0014nn_1-2-6-8-25-26_23-24    FoxIO relse0014nn_1-2-6-8-25-26_23-24
frame 12  ja4plus reply0014nn_1-2-13_00              FoxIO reply0014nn_1-2-13_00
```

### JA4D6 — the disagreements

**No disagreement changes a value on any vector this repository holds.**

**D7 — `ja4d6.py:190` selects a packet by UDP port, and no FoxIO source states a port.**

The test reads ports 546 and 547. This is the JA4D6 form of D1.

**D8 — `ja4d6.py:76-82` lists five container options by hand, and the dissector reads
whatever Wireshark reports.**

`_DHCPV6_NESTED_OPTIONS` holds codes 3, 4, 25, 5 and 26 with a fixed header length each.
The dissector applies no such table: `wireshark/source/packet-ja4.c:1566` reads every
field named `dhcpv6.option.type`, whatever nests it. A message that nests an option inside
a container this table omits therefore gives a shorter part b here. **DHCPv6 option 9,
Relay Message, is the clearest case**, because it carries a whole inner DHCPv6 message.
`ja4d6.py:110` states `relay-forw/reply not unwrapped`. No vector carries a relay message.

**This item also names an internal contradiction.** The comment at `ja4d6.py:74-75` reads
`Option 17 (Vendor-specific Information) carries enterprise-specific sub-options keyed by
enterprise-number`, and `ja4d6.py:76-82` holds no entry for code 17. The comment describes
a behaviour the table does not build. **This page rules on nothing here**, because the
Wireshark field name for a vendor sub-option cannot be read from the FoxIO checkout, and
no vector carries option 17.

**D9 — `ja4d6.py:140-141` keeps the last option 1, and the dissector keeps the first.**

`duid_len = len(opt_data)` runs on each occurrence.
`wireshark/source/packet-ja4.c:1547-1549` reads `dhcpv6.duid.bytes` only while the
subfield is still empty, so it keeps the first. No vector carries a repeated option 1.

**D10 — `ja4d6.py:146-151` keeps the last option 6, and the dissector concatenates every
option 6.**

This is the JA4D6 form of D5.

**D11 — `ja4d6.py:199-200` emits nothing for message type 0, and the dissector emits a
value.**

`if msg_type == 0: return None`. `wireshark/source/packet-ja4.c:1537-1538` sets
`ja4d_data.proto = '6'` for any `dhcpv6.msgtype` field, so a type of 0 gives `00000`.
DHCPv6 defines no message type 0, and no vector carries one.

## The register

**`tests/foxio_deviations.json` holds 120 keys, and no key names JA4D or JA4D6.** Every
register entry that names either method is therefore accounted for, and the count of such
entries is zero.

Reproduce the search.

```bash
python -c "import json; d=json.load(open('tests/foxio_deviations.json')); print(len(d)); print([k for k in d if 'JA4D' in k.upper()])"
```

It reports `120` and `[]`.

**The reason the register holds no entry is structural, and not an absence of evidence.**
The conformance suite walks the top level of `tests/foxio_vectors/`, and the two DHCP
reference files sit under `tests/foxio_vectors/wireshark_expected/`.
`docs/implementation_notes.md:510-513` records that reading.
`tests/test_ja4d_foxio.py` and `tests/test_ja4d6_foxio.py` compare all ten values inside
the unit suite instead, and both compare the whole map in both directions, so a value this
project adds fails the same as a value it drops.

**This is the opposite of the shape `docs/specs/foxio/JA4T.md` reports.** There the
snapshots this project holds carry `ja4t` values that no harness reads. Here the reference
values are read, and they all pass.

## The decisions this page raises

**None of the eleven disagreements moves a fingerprint on evidence this page holds**, and
each rests on a packet no vector carries. #231 collects them, and a person decides them.
This page changes no fingerprinter.

The five uncertain rules are R10, R15, R16, R19 and R20. Each keeps the vector fallback.
**R16, R19 and R20 are uncertain for one reason: JA4D6 reaches one FoxIO implementation,
and a second implementation would settle all three.** `zeek/README.md:15` states that the
Zeek package is waiting for DHCPv6 support, so a second implementation may arrive.
