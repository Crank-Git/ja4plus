# JA4H

This page is this project's own prose form of `technical_details/JA4H.png`. It follows the
procedure in `docs/specs/foxio/README.md`. No image enters this repository.

| Item | Value |
|---|---|
| Source | `https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.png` |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-08 |
| SHA-256 of the image | `08592925d1371d64bf42eeed90506dddf30e4451ba062485ae437abe6c556b80` |

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.png (retrieved 2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

Reproduce the hash from a checkout at the pinned commit.

```bash
shasum -a 256 technical_details/JA4H.png
```

## The text file is not the specification

`technical_details/JA4H.md` exists, and it is **278 bytes**. Its SHA-256 is
`7c96d53af6f51f88bb90b0d6582e10c8b2984e449cfe32940cc51b44fd4eec96`. It holds one sentence
of purpose and one rule. It builds no fingerprint.

The file states two facts this page uses.

- `JA4H fingerprints the HTTP client based on each HTTP request.`
- `2 digit number of headers, not counting Cookie and Referer. For 3 headers the value is "03". If there are more than 99, the output is 99.`

**`JA4H.png` is the specification, and the 278 bytes corroborate it.** Where the image and
the text file agree, that is one corroboration and not two. Every rule below therefore
carries two corroborations that are neither the image nor a restatement of it.

## The field layout

The image titles itself `JA4H: HTTP Client Fingerprint`. It draws one example string and
labels four parts `JA4H_a` to `JA4H_d`.

```
JA4H=ge20cr13enus_974ebe531c03_b66fa821d02c_e97928733c74
     \__________/ \__________/ \__________/ \__________/
        JA4H_a       JA4H_b       JA4H_c       JA4H_d
```

The image captions six fields inside `JA4H_a`, in this order.

| Field | The image's caption | Value in the example |
|---|---|---|
| a1 | HTTP Method, GET = "ge", PUT = "pu", POST = "po", etc | `ge` |
| a2 | HTTP Version, 2.0 = "20", 1.1 = "11" | `20` |
| a3 | Cookie, if there's a Cookie "c", if no Cookie "n" | `c` |
| a4 | Referer, if there's a Referer "r" if no Referer "n" | `r` |
| a5 | Number of HTTP Headers (ignoring Cookie and Referer) | `13` |
| a6 | First 4 characters of primary Accept-Language (0000 if no Accept-Language) | `enus` |

The image captions the three remaining parts.

| Part | The image's caption | Value in the example |
|---|---|---|
| JA4H_b | Truncated SHA256 hash of Headers, in the order they appear | `974ebe531c03` |
| JA4H_c | Truncated SHA256 hash of Cookie Fields, sorted | `b66fa821d02c` |
| JA4H_d | Truncated SHA256 hash of Cookie Fields + Values, sorted | `e97928733c74` |

The four parts join with `_`. Part a carries no separator between its six fields.

## The rules

Each rule below carries two corroborations. Neither corroboration is the image. Every
in-repository path names the FoxIO `ja4` repository at the pinned commit.

### R1 — JA4H holds four parts, joined with `_`

- Corroboration 1: `python/ja4h.py:77` writes
  `f'{method}{version}{cookie}{referer}{header_len}{lang}_{headers}_{cookies...}_{cookie_values}'`.
- Corroboration 2: `python/test/testdata/http1-with-cookies.pcapng.json` holds
  `ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442`, which carries four parts.

`rust/ja4/src/http.rs:206` and `wireshark/source/packet-ja4.c:639` write the same four-part
form.

### R2 — Part a holds six fields, in the order the image draws them

- Corroboration 1: `python/ja4h.py:77` writes the six fields with no separator.
- Corroboration 2: `wireshark/source/packet-ja4.c:639` writes `"%s%s%s%s%02d%s_..."`, which
  is the method, the version, the cookie flag, the referer flag, the two-digit count and the
  language.

### R3 — Field a1 is two lowercase characters that name the request method

- Corroboration 1: `python/ja4h.py:9` defines `http_method` as `method.lower()[:2]`.
  Measured at the pinned commit: `http_method('GET')` returns `'ge'`.
- Corroboration 2: `rust/ja4/src/http.rs:364` to `rust/ja4/src/http.rs:379` writes `co`,
  `de`, `ge`, `he`, `op`, `pa`, `po`, `pu` and `tr`.

`python/test/testdata/https-connect.pcap.json` holds `co10nn010000_...`, which is the
`CONNECT` method.

### R4 — Field a2 is two digits that name the HTTP version

`HTTP/1.0` writes `10`, `HTTP/1.1` writes `11`, HTTP/2 writes `20` and HTTP/3 writes `30`.

- Corroboration 1: `rust/ja4/src/http.rs:423` to `rust/ja4/src/http.rs:433` maps the four
  versions to those four codes.
- Corroboration 2: `python/test/testdata/https-connect.pcap.json` holds `co10nn010000_...`
  for an `HTTP/1.0` request, and `python/test/testdata/http2-with-cookies.pcapng.json` holds
  `ge20cn19enus_...` for an HTTP/2 request.

### R5 — Field a3 reads the Cookie header, and it does not read the cookie count

Field a3 is `c` when the request carries a Cookie header. It is `n` when the request carries
none. A Cookie header whose value holds no cookie pair still writes `c`.

- Corroboration 1: `rust/ja4/src/http.rs:83` sets `has_cookie_header` from the header name,
  and `rust/ja4/src/http.rs:178` writes `c` from that flag alone.
- Corroboration 2: `wireshark/source/packet-ja4.c:1165` sets `ja4h_data.cookie` when the
  dissector reports the `http.cookie` field, and line 640 writes `c` from that flag alone.

### R6 — Field a4 reads the Referer header, and it does not read the header value

Field a4 is `r` when the request carries a Referer header, whatever the header value holds.

- Corroboration 1: `rust/ja4/src/http.rs:87` sets `has_referer_header` from the header name,
  and `rust/ja4/src/http.rs:179` writes `r` from that flag alone.
- Corroboration 2: `wireshark/source/packet-ja4.c:1169` sets `ja4h_data.referer` when the
  dissector reports the `http.referer` field.

### R7 — Field a5 is a two-digit count that omits Cookie and Referer

- Corroboration 1: `technical_details/JA4H.md` states
  `2 digit number of headers, not counting Cookie and Referer. For 3 headers the value is "03".`
- Corroboration 2: `python/ja4h.py:48` to `python/ja4h.py:55` drops the two names and then
  formats the length with `'{:02d}'`.

### R8 — A count above 99 writes 99

- Corroboration 1: `technical_details/JA4H.md` states
  `If there are more than 99, the output is 99.`
- Corroboration 2: `python/ja4h.py:55` writes `min(len(x['headers']), 99)`, and
  `rust/ja4/src/http.rs:180` writes `99.min(headers.len())`.

### R9 — Field a5 counts the same list that part b hashes

- Corroboration 1: `python/ja4h.py:48` filters the header list, and `python/ja4h.py:55`
  counts the filtered list that `python/ja4h.py:76` hashes.
- Corroboration 2: `wireshark/source/packet-ja4.c:1208` appends the name and line 1209
  increments the count, inside one branch, so no name reaches one and not the other.

### R10 — Field a6 is the first four characters of the primary Accept-Language value

Field a6 takes the value up to the first `,`. It removes each `-`, it lowercases the
result, it keeps four characters, and it pads the result with `0`.

- Corroboration 1: `python/ja4h.py:12` to `python/ja4h.py:15`. Measured at the pinned
  commit: `http_language('en-US,en;q=0.9')` returns `'enus'`, and
  `http_language('da, en-GB;q=0.8, en;q=0.7')` returns `'da00'`.
- Corroboration 2: `python/test/testdata/http1-with-cookies.pcapng.json` holds
  `ge11cr04da00_...` for a request whose Accept-Language value is
  `da, en-GB;q=0.8, en;q=0.7`.

### R11 — A request that carries no Accept-Language header writes `0000`

- Corroboration 1: `python/ja4h.py:75` writes `'0000'` when the request holds no language.
- Corroboration 2: `wireshark/source/packet-ja4.c:1648` appends `0000` when the language
  buffer is empty.

`python/test/testdata/https-connect.pcap.json` holds `co10nn010000_...`, whose language
field is `0000`.

### R12 — Part b is the first 12 hexadecimal characters of one SHA-256 hash

Part b joins the header names with `,`, in wire order, and it hashes the joined string.

- Corroboration 1: `python/common.py:125` to `python/common.py:129` defines `sha_encode`.
  Measured at the pinned commit: `sha_encode(['User-Agent'])` returns `'b8bcd45ac095'`,
  which is the part b of `python/test/testdata/https-connect.pcap.json`.
- Corroboration 2: `rust/ja4/src/http.rs:191` joins with `,` and
  `rust/ja4/src/lib.rs:188` truncates the hash to 12 characters.

### R13 — Part b omits Cookie and Referer, which are the two names field a5 omits

- Corroboration 1: `rust/ja4/src/http.rs:82` to `rust/ja4/src/http.rs:92` drops the two
  names from the header list.
- Corroboration 2: `wireshark/source/packet-ja4.c:1204` to
  `wireshark/source/packet-ja4.c:1207` drops the two names.

### R14 — Part b lists the header names in wire order, and nothing sorts them

- Corroboration 1: `rust/ja4/src/http.rs:74` reads `http.request.line` in order and
  `rust/ja4/src/http.rs:191` joins the list with no sort.
- Corroboration 2: `python/test/testdata/http1-with-cookies.pcapng.json` holds the raw form
  `..._Host,User-Agent,Accept,Accept-Language_...`, which is the order of the request.

### R15 — Part c hashes the cookie names, sorted

- Corroboration 1: `python/ja4h.py:68` sorts the cookie pairs by name, and
  `python/ja4h.py:72` hashes the sorted names.
- Corroboration 2: `wireshark/source/packet-ja4.c:1188` inserts each cookie into a sorted
  list, and line 631 hashes the sorted field string.

### R16 — Part d hashes the `name=value` cookie pairs, sorted by name

- Corroboration 1: `rust/ja4/src/http.rs:247` to `rust/ja4/src/http.rs:261` writes
  `format!("{name}={value}")` for each pair.
- Corroboration 2: `python/test/testdata/http1-with-cookies.pcapng.json` holds the raw form
  `..._yummy_cookie=choco,tasty_cookie=strawberry`, and `python/ja4h.py:70` builds the
  hashed list from the same sorted pairs.

### R17 — A request that carries no Cookie header writes 12 zeros in part c and part d

- Corroboration 1: `python/ja4h.py:72` and `python/ja4h.py:73` write `'0'*12`.
- Corroboration 2: `wireshark/source/packet-ja4.c:637` defines
  `zero_hash = "000000000000"`, and lines 641 and 642 write it when the cookie flag is
  false.

`python/test/testdata/https-connect.pcap.json` holds
`co10nn010000_b8bcd45ac095_000000000000_000000000000`.

### R18 — JA4H reads one HTTP request and writes one fingerprint

- Corroboration 1: `technical_details/JA4H.md` states
  `JA4H fingerprints the HTTP client based on each HTTP request.`
- Corroboration 2: `rust/ja4/src/http.rs:18` holds a `Vec<HttpStats>` for a stream, and
  `rust/ja4/src/http.rs:37` writes one output value for each entry.

### R19 — The references disagree on a request that carries no header

**This rule is uncertain.** Keep the vector fallback.

- `rust/ja4/src/lib.rs:184` returns `000000000000` for an empty string, under the doc
  comment `Returns "000000000000" (12 zeros) if the input string is empty.`
- `python/common.py:127` hashes the empty string. Measured at the pinned commit:
  `sha_encode([])` returns `'e3b0c44298fc'`.

The image settles nothing here. Its example carries 13 headers.

### R20 — The references disagree on a cookie that carries no equals sign

**This rule is uncertain.** Keep the vector fallback.

- `python/ja4h.py:59` keeps the token as a pair of the token with itself.
- `rust/ja4/src/http.rs:228` keeps the name with no value, and
  `rust/ja4/src/http.rs:256` writes the bare name into part d.
- `wireshark/source/packet-ja4.c:1177` requires both halves of the split and drops the
  cookie when either is absent.

### R21 — The references disagree on the order of two cookies that carry one name

**This rule is uncertain.** Keep the vector fallback.

- `python/ja4h.py:68` sorts by the name alone, and the Python sort is stable, so the two
  cookies keep their wire order.
- `rust/ja4/src/http.rs:187` calls `sort_unstable()` on the `(name, value)` tuple, so the
  value decides the order.

### R22 — The references disagree on a header name that begins with `cookie`

**This rule is uncertain.** Keep the vector fallback.

- `python/ja4h.py:49` drops every name that `startswith('cookie')`, so it drops `Cookie2`.
- `rust/ja4/src/http.rs:83` and `wireshark/source/packet-ja4.c:1204` test the whole name, so
  they keep `Cookie2`.

### R23 — The references disagree on where the primary language token ends

**This rule is uncertain.** Keep the vector fallback.

- `python/ja4h.py:13` replaces `;` with `,` before the split, so `en;q=0.9` writes `en00`.
  Measured at the pinned commit: `http_language('en;q=0.9')` returns `'en00'`.
- `wireshark/source/packet-ja4.c:478` ends the token at `;`, which agrees with the Python
  reference.
- `rust/ja4/src/http.rs:293` splits on `,` alone, so `en;q=0.9` writes `en;q`.

`wireshark/source/packet-ja4.c:489` also writes a non-alpha character as two hexadecimal
digits, and neither other reference does.

### R24 — The references disagree on an HTTP/2 pseudo-header

**This rule is uncertain.** Keep the vector fallback.

A pseudo-header name begins with `:`. HTTP/2 carries four of them: `:method`,
`:authority`, `:scheme` and `:path`.

- `python/ja4h.py:47` splits each name on `:` and keeps the first half, so `:method`
  becomes the empty string. `python/ja4h.py:49` tests `not h.startswith(':')` and
  `python/ja4h.py:50` ends the filter with `and h`, which drops the empty name.
- `wireshark/source/packet-ja4.c:1200` splits the name on `:`, and
  `wireshark/source/packet-ja4.c:1203` drops the name when the first half is empty, which
  is the pseudo-header case.
- `rust/ja4/src/http.rs:127` to `rust/ja4/src/http.rs:144` tests for `cookie` and
  `referer` alone, so it keeps every pseudo-header.

Measured on 2026-08-08 against `http2-with-cookies.pcapng` at the pinned commit. **The
Rust count is four higher than the Python count on every request of the capture**, which
is the number of pseudo-headers.

```
rust/ja4/src/snapshots/ja4__insta@http2-with-cookies.pcapng.snap : ge20cn17enus  ge20cn23enus  ge20cr22enus
python/test/testdata/http2-with-cookies.pcapng.json              : ge20cn13enus  ge20cn19enus  ge20cr18enus
```

The two references therefore write a different field a5 and a different part b for one
request. The image settles nothing here, because its example is an HTTP/2 request and it
states no pseudo-header rule.

`python/test/testdata/` decides, under the rule `.claude/rules/external-apis.md` states.
This project follows the Python reference.

## The comparison against this project

The comparison below reads `ja4plus/fingerprinters/ja4h.py` and
`ja4plus/utils/http_utils.py` at commit `1a87f45`. **Every field is named. A field this
table does not name is a field nobody read.**

`#193` landed two changes on `batch/193-register-and-state-rule`, which is not the base of
this page. There, `ja4h.py` reads a request that ends with LF, and it holds the consumed
sequence position. This page reads the base of Epic 10 and cites #193 rather than
re-deriving either reading.

The cookie list carries no bound. The user decided that on 2026-08-08 and #175 records it.
This page raises no bound question.

### Part a — the fields that agree

| Field | Rule | `ja4h.py` | Reading |
|---|---|---|---|
| a1, method code | R3 | `ja4h.py:285` and `ja4h.py:305` | Agrees. `method[:2].lower()` writes the same two characters as the reference for each of the nine methods the parser reads. |
| a2, version code | R4 | `ja4h.py:29` to `ja4h.py:50`, used at `ja4h.py:286` | Agrees. `HTTP/1.0` writes `10`, `HTTP/1.1` writes `11`, `HTTP/2` writes `20`, `HTTP/3` writes `30`. |
| a2, version token | R4 | `http_utils.py:18` | Agrees. The pattern reads `HTTP/<major>.<minor>`, `HTTP/2` and `HTTP/3`, and it reads no other token. |
| a5, the two omitted names | R7 | `ja4h.py:293` | Agrees. The count drops `cookie` and `referer`, and it ignores the case of the name. |
| a5, the cap | R8 | `ja4h.py:295` | Agrees. `min(header_count, 99)`. |
| a5, the width | R7 | `ja4h.py:296` | Agrees. `f"{header_count:02d}"`. |
| a6, the language token | R10 | `ja4h.py:301` | Agrees. The line applies the four operations of `python/ja4h.py:13`: it removes each `-`, it replaces `;` with `,`, it lowercases the value, and it takes the part before the first `,`. |
| a6, the pad | R10 | `ja4h.py:302` and `ja4h.py:303` | Agrees. Four characters, padded with `0`. |
| a6, no Accept-Language | R11 | `ja4h.py:299` | Agrees. `lang_code = "0000"` is the default. |
| Field order | R2 | `ja4h.py:305` | Agrees. The format string writes the six fields in the image's order. |

### Part b, part c and part d — the fields that agree

| Field | Rule | `ja4h.py` | Reading |
|---|---|---|---|
| b, join and hash | R12 | `ja4h.py:354` to `ja4h.py:356` | Agrees. `",".join(...)` and `sha256(...).hexdigest()[:12]`. |
| b, wire order | R14 | `ja4h.py:321` to `ja4h.py:325` | Agrees. The comprehension keeps the order of `header_names`, and nothing sorts it. |
| b, the two omitted names | R13 | `ja4h.py:324` | Agrees. The list drops `cookie` and `referer`. |
| b, a pseudo-header | R24 | `ja4h.py:324` | Agrees with the Python reference and the dissector, which both drop a name that begins with `:`. Disagrees with `rust/ja4/src/http.rs:127`, which R24 marks uncertain. The branch is unreachable here, because `http_utils.py:208` requires one non-colon character before the colon. |
| c, the sort | R15 | `ja4h.py:364` | Agrees. `sorted(name for name, _ in cookie_pairs)`. |
| c, join and hash | R15 | `ja4h.py:364` to `ja4h.py:366` | Agrees. |
| c, no cookie | R17 | `ja4h.py:367` to `ja4h.py:369` | Agrees. `"000000000000"`. |
| c, a repeated name | R21 | `ja4h.py:364` | Agrees with `python/ja4h.py:68`. Disagrees with `rust/ja4/src/http.rs:187`, which R21 marks uncertain. |
| d, the pair form | R16 | `ja4h.py:374` | Agrees. `f"{k}={v}"`. |
| d, the sort key | R16 | `ja4h.py:373` | Agrees. The sort reads the name alone and it is stable. |
| d, no cookie | R17 | `ja4h.py:375` to `ja4h.py:379` | Agrees. `"000000000000"`. |
| One value per request | R18 | `ja4h.py:116` to `ja4h.py:120` | Agrees for a request the parser reads once. D5 below reports the retransmission case. |
| b, no header | R19 | `ja4h.py:356` | Agrees with `rust/ja4/src/lib.rs:184`. Disagrees with `python/common.py:127`, which R19 marks uncertain. |
| b, `Cookie2` | R22 | `ja4h.py:324` | Agrees with the Rust reference and the dissector. Disagrees with `python/ja4h.py:49`, which R22 marks uncertain. |
| d, a cookie with no equals sign | R20 | `http_utils.py:100` and `ja4h.py:231` | Agrees with `wireshark/source/packet-ja4.c:1177`. Disagrees with the other two references, which R20 marks uncertain. |
| The language token end | R23 | `ja4h.py:301` | Agrees with the Python reference and the dissector. Disagrees with `rust/ja4/src/http.rs:293`, which R23 marks uncertain. |

### Two whole captures agree, value for value

Measured on 2026-08-08 in this worktree.

```
foxio python/test/testdata/http1-with-cookies.pcapng.json : ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442
foxio wireshark/test/testdata/http1-with-cookies.pcapng.json (ja4.ja4h) : ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442
ja4plus Processor                                         : ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442

foxio python/test/testdata/https-connect.pcap.json        : co10nn010000_b8bcd45ac095_000000000000_000000000000
ja4plus Processor                                         : co10nn010000_b8bcd45ac095_000000000000_000000000000
```

The raw original-order form agrees on the same capture.

```
foxio  JA4H_ro : ge11cr04da00_Host,User-Agent,Accept,Accept-Language_yummy_cookie,tasty_cookie_yummy_cookie=choco,tasty_cookie=strawberry
ja4plus        : ge11cr04da00_Host,User-Agent,Accept,Accept-Language_yummy_cookie,tasty_cookie_yummy_cookie=choco,tasty_cookie=strawberry
```

### The disagreements

**D1 — `http_utils.py:17` names nine request methods, and the reference reads any method.**

`REQUEST_LINE_PATTERN` lists `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `CONNECT`,
`TRACE` and `PATCH`. A request that carries any other method produces no JA4H value. R3
states that the reference writes the first two characters of the method.

Measured on 2026-08-08.

```
foxio python/ja4h.py http_method('PROPFIND') : 'pr'
ja4plus _generate_ja4h_from_info             : None
```

The image's caption ends with `etc`, so the image does not close the method list. No vector
in this repository carries such a request.

**D2 — `ja4h.py:288` reads the parsed cookie list, and R5 states that field a3 reads the
Cookie header.**

`has_cookie = "c" if http_info.get("cookie_fields", []) else "n"`. A Cookie header whose
value holds no `=` produces an empty list, so this project writes `n` where all three
references write `c`.

Measured on 2026-08-08 against the request
`GET / HTTP/1.1\r\nHost: a\r\nCookie: sessionid\r\n\r\n`.

```
ja4plus : ge11nn010000_4a823118b9ba_000000000000_000000000000
```

Field a3 is `n`. R5 requires `c`.

**D3 — `ja4h.py:289` reads the Referer header value, and R6 states that field a4 reads the
header.**

`has_referer = "r" if http_info.get("referer", "") else "n"`. A Referer header that carries
an empty value produces `n` where all three references write `r`.

Measured on 2026-08-08 against the request
`GET / HTTP/1.1\r\nHost: a\r\nReferer: \r\n\r\n`.

```
ja4plus : ge11nn010000_4a823118b9ba_000000000000_000000000000
```

Field a4 is `n`. R6 requires `r`.

**D4 — `ja4h.py:291` to `ja4h.py:294` count a list that `ja4h.py:321` to `ja4h.py:325` does
not hash.**

The count keeps a header whose name is empty, and the hashed list drops it. R9 states that
all three references count the list they hash.

Measured on 2026-08-08 against the request
`GET / HTTP/1.1\r\nHost: a\r\n : b\r\n\r\n`.

```
ja4plus JA4H    : ge11nn020000_4a823118b9ba_000000000000_000000000000
ja4plus JA4H_ro : ge11nn020000_Host_
```

Field a5 reports two headers, and part b hashes one name. `4a823118b9ba` is the first 12
characters of the SHA-256 of `Host`. No vector in this repository carries such a header.

**D5 — `ja4h.py:92` adds every TCP segment to the reassembler, so a retransmitted request
produces a second fingerprint.**

R18 states that JA4H writes one fingerprint for each HTTP request. A retransmission carries
no new request.

Measured on 2026-08-08 against `tests/foxio_vectors/CVE-2018-6794.pcap`.

```
Each of the two streams carries 6 request packets and 1 distinct TCP sequence number.
foxio python/test/testdata/CVE-2018-6794.pcap.json : 2 JA4H values, one for each stream
ja4plus Processor                                  : 12 JA4H values, six for each stream
```

The values agree. The count does not. The conformance suite reports the same reading.

```
E  Failed: CVE-2018-6794.pcap JA4H: 10 extra occurrence key(s) [...]; 0 missing occurrence key(s) []
```

`.claude/rules/conformance.md` states that a method that emits more fingerprints than the
reference is a defect.

**D6 — `ja4h.py:62` states that FoxIO publishes no `JA4H_r` key, and the Wireshark expected
output publishes one.**

The docstring reads `FoxIO publishes no JA4H_r key, so this fingerprinter computes no
sorted raw form: a sorted value matches no reference value and no other implementation.`

`wireshark/test/testdata/http1-with-cookies.pcapng.json` holds a `ja4.ja4h_r` key at the
pinned commit, and `wireshark/source/packet-ja4.c:609` builds it with the sorted cookie fields.
`python/ja4h.py:78` builds `JA4H_r` as well, and the files under `python/test/testdata/`
publish no such key.

The claim holds for `python/test/testdata/` and it does not hold for the Wireshark expected
output. This changes no fingerprint. It changes what a person reading `ja4h.py` believes
the reference publishes.

### One more finding that changes no fingerprint

`ja4h.py:20` imports `parse_http_request`, and no line of `ja4h.py` calls it.
`tests/test_ja4h_cookie_list.py` reaches `ja4h.py:254`, `_convert_parsed_to_extract_format`.
No line under `ja4plus/` reaches it. That function reads
`parsed["headers"]`, which `http_utils.py:86` keys on the lowercased name, so it would drop
both the wire casing and a repeated header name. No fingerprint reads it today.

## The register

`tests/foxio_deviations.json` holds 114 entries as of #193, and **36 of them name JA4H**.
They cover two captures and one issue. Each row states whether the specification explains
it.

| Capture | Key | Entries | Issue | Explained by the specification |
|---|---|---|---|---|
| `chrome-cloudflare-quic-with-secrets.pcapng` | `JA4H`, `JA4H_ro`, and the two stream keys | 4 | #129 | **No.** The specification states the schema of a request and states nothing about how an implementation reaches a request inside QUIC. The reference decrypts the traffic with the secrets the capture carries. |
| `http2-with-cookies.pcapng` | `JA4H` and `JA4H_ro`, 16 each | 32 | #129 | **Partly.** R4 states that an HTTP/2 request writes version `20`, so the specification does cover HTTP/2 as a source. It states nothing about how an implementation reaches a request inside TLS 1.3. The reference decrypts the traffic with the secrets the capture carries. |

### The six entries #193 removed

**#193 repaired the defect behind each of the six entries, and it reclassified none of
them.** The FoxIO reference holds the JA4H values it always held. This project now produces
them too, so the comparison passes and the register needs no entry.

The base of this page is `epic/194-read-the-specification-images`, where the register holds
120 entries and 42 of them name JA4H. The two rows below state the six as that register
holds them.

| Capture | Key | Entries | Issue | Explained by the specification | What #193 changed |
|---|---|---|---|---|---|
| `CVE-2018-6794.pcap` | `JA4H`, `JA4H_ro` | 2 | #35 | **Yes, and the stated cause is wrong.** R18 states one fingerprint for each request. The measurement above shows 10 extra occurrence keys and 0 missing keys, so the values match and the count does not. The entry states `ja4plus produces no JA4H fingerprint the reference holds.` | `ja4h.py` now holds the sequence range of a request it read, and a retransmission of that request produces no second value. The count agrees, and the two entries leave the register. |
| `http-empty-useragent.pcap` | `JA4H`, `JA4H_ro`, and the two stream keys | 4 | #35 | **No.** The specification states no line-terminator rule and no rule about an empty header value. #193 owns the cause, and its fix landed on `batch/193-register-and-state-rule`. The reference value is `ge10nn010000_b8bcd45ac095_000000000000_000000000000`, so R7 and R12 confirm that a header with an empty value still counts and still hashes. | The capture ends each request line with one line feed, and the parser read the two bytes CRLF as the only line ending. `http_utils.py` now reads both line endings, this project produces the reference value, and the four entries leave the register. |

No register entry names a rule this page transcribes as a value disagreement. **The two
value disagreements this page finds, D2 and D3, reach no vector**, so the register holds no
entry for either.

## The search for a reference value

JA4H is the method the FoxIO material covers most.

| Source searched | Result |
|---|---|
| `python/test/testdata/` | **89 `JA4H` values and 89 `JA4H_ro` values, in 11 files.** |
| `rust/ja4/src/snapshots/` | **89 `ja4h` values, in 11 files.** No `ja4h_r` value and no `ja4h_o` value. |
| `wireshark/test/testdata/` | **126 `ja4.ja4h` values, in 12 files.** The same files carry `ja4.ja4h_r` and `ja4.ja4h_ro`. |
| `README.md` at the pinned commit | Four values, at lines 141, 144, 148 and 149. Each carries two parts or three, not four. They are threat-report examples and they do not corroborate the part count. |
| `technical_details/README.md` | Line 7 names `JA4HTTP` / `JA4H` as `HTTP Client Fingerprinting`. Line 26 embeds the image. |
| `zeek/` | Not searched here. #198 owns that survey. |

Reproduce the counts from a checkout at the pinned commit.

```bash
grep -rhoE '"JA4H": "[^"]+"' python/test/testdata/ | wc -l
grep -rhoE 'ja4h[a-z_]*:' rust/ja4/src/snapshots/ | sort | uniq -c
```

**This repository already holds 89 of those values**, in `tests/foxio_vectors/*.json`,
across 11 captures.

| Capture in `tests/foxio_vectors/` | `JA4H` values |
|---|---|
| `CVE-2018-6794.pcap` | 2 |
| `chrome-cloudflare-quic-with-secrets.pcapng` | 1 |
| `http-empty-useragent.pcap` | 1 |
| `http1-with-cookies.pcapng` | 1 |
| `http1.pcapng` | 56 |
| `http2-with-cookies.pcapng` | 15 |
| `https-connect.pcap` | 1 |
| `latest.pcapng` | 1 |
| `single-packets.pcap` | 8 |
| `ssh2.pcapng` | 2 |
| `tls3.pcapng` | 1 |

## The conformance evidence a later issue can build

1. **The local Rust snapshots hold 6 `ja4h` values that no case reads.**
   `tests/test_foxio_rust_parity.py:72` reads two methods,
   `SNAPSHOT_METHODS = (("JA4", "ja4"), ("JA4S", "ja4s"))`. The six values sit in
   `tests/foxio_vectors/rust_expected/`, in `latest.pcapng`,
   `chrome-cloudflare-quic-with-secrets.pcapng`, `https-connect.pcap`, `ssh2.pcapng` and
   `tls3.pcapng`. This is the shape #196 found for JA4T.
2. **D2 and D3 need one new vector each.** No capture in this repository carries a Cookie
   header with no `=`, and none carries a Referer header with an empty value.
3. **D4 needs a request with a header whose name is empty.** No capture carries one.
4. **D1 needs a request whose method is outside the nine.** No capture carries one.
5. **D5 needs no new vector.** `CVE-2018-6794.pcap` measures it today. On the base of this
   page the register entry xfails on it. #193 repaired the count and removed the entry, so
   the conformance suite reports a pass for the capture as of #193.

## What the deleted text specification adds

**A 9137-byte `technical_details/JA4H.md` existed, and `b6f3ff4` deleted it on 2024-02-22.**
The 278-byte file this page reads is a different file, created on 2024-09-25. #221 read the
deleted one, and `docs/specs/foxio/deleted-text-specifications.md` holds the reading and the
provenance. **This page rewrites no rule above.**

**The replacement corrected a defect, which answers why the deletion happened.** The deleted
file states the cap as `99 = anything > than 100 headers`, which names two thresholds. The
278-byte file states `If there are more than 99, the output is 99.`, which names one. R8
holds the corrected rule and both implementations follow it.

The deleted text corroborates R1, R2, R4, R5, R6, R7, R10, R11, R13, R14, R15 and R16, and
it contradicts none of them. It carries two further findings.

1. **It names exactly nine request methods**, and the image's caption ends with `etc`.
   `rust/ja4/src/http.rs:364` writes the same nine and `python/ja4h.py:9` reads any method.
   **D1 and #219 item 5 own the decision**, and this is a FoxIO-authored source for the
   closed list.
2. **The FoxIO worked example computes 11 headers and publishes 13.** The deleted file
   carries the request that produces the image's example value, and that request holds 13
   header fields, two of which are `Cookie` and `Referer`. The file lists the 11 names it
   hashes and then writes `ge20cr13enus`. **The example disagrees with the rule R7 states,
   and the image repeats the value.** No implementation reads the example and no vector
   carries it, so **this changes no fingerprint and it raises no decision.**

## The decisions this page raises

**#219 holds these decisions.** Each item needs the user, because each changes a
fingerprint that this project publishes, or it changes a recorded cause. **This page
changes no fingerprinter and no register entry.**

**The user settled every item on 2026-08-08. `## What the user decided` below states each
ruling and the repair that carries it.** The list that follows records what this page
raised, and it reads as the page wrote it.

1. **D2.** Does field a3 read the Cookie header or the parsed cookie list? All three
   references read the header.
2. **D3.** Does field a4 read the Referer header or its value? All three references read
   the header.
3. **D4.** Which list does field a5 count? R9 states that the count and the hash read one
   list.
4. **D5.** Does a retransmitted request produce a second fingerprint? R18 states one
   fingerprint for each request.
5. **D1.** Does this project read a request method outside the nine the pattern names?
6. **The register cause of `CVE-2018-6794.pcap/JA4H` and `/JA4H_ro` is wrong.** The
   measurement shows extra values, and the entry states that this project produces none.
   #193 removed both entries when it repaired the count, so no entry carries the wrong
   cause as of #193. The reading stands for a reader of the base of this page.
7. **R19 to R24 stay uncertain.** Each holds a disagreement between two FoxIO
   implementations, and the image settles none of them. The vector fallback stays. R24 is
   the widest. The Rust reference counts and hashes the four HTTP/2 pseudo-headers, and
   the other two references drop them, so the two disagree on every HTTP/2 request.

## What the user decided

The user settled D1, D2, D3 and D4 on 2026-08-08, and #219 carries the repair. #193 had
already repaired D5 and D6 on `batch/193-register-and-state-rule`, which is not the base of
this page.

**No FoxIO vector reaches any of the four readings.** The largest JA4H vector carries no
valueless Cookie header, no empty Referer value, no header named with a space and no method
outside the nine. The repair therefore holds two measurements.

- The 38 captures under `tests/foxio_vectors/` produce 791 fingerprint values before the
  repair and 791 after, and every value is unchanged. 73 of them are JA4H values.
- The conformance suite reports 114 `xfailed` before the repair and 114 after, and
  `tests/foxio_deviations.json` holds 114 keys before and after.

`tests/test_ja4h_part_a_readings.py` holds 42 constructed cases, and 28 of them fail on the
base commit. Each repair is also proven by reverting it alone.

| Ruling | What changed | Cases that fail when the repair is reverted |
|---|---|---|
| **D2.** Field a3 reads the Cookie header, and it does not read the parsed cookie list. R5 states the rule, and all three references read the header. This is a defect, so the `Divergence register` gains no row. | `ja4h.py:_ja4h_part_a` reads the header name list. | 3 |
| **D3.** Field a4 reads the Referer header, and it does not read the header value. R6 states the rule. This is a defect, so the `Divergence register` gains no row. | `ja4h.py:_ja4h_part_a` reads the header name list. | 5 |
| **D4.** Field a5 counts the list part b hashes. R9 states the rule, and a value that reports two headers while it hashes one contradicts itself. | `ja4h.py:_ja4h_part_a` counts `_ja4h_header_names`. | 5 |
| **D1.** Field a1 reads the first two characters of any method, as `python/ja4h.py:9` does. The three references disagree, so the `Divergence register` of `docs/specs/spec.md` holds a row. | `http_utils.py:REQUEST_LINE_PATTERN` reads a method token and names no method. The three parse paths read that one pattern. | 15 |

The reassembly gate keeps a narrow test. `is_http_request` admits a method the nine tokens
omit only when the buffer holds a whole request line. `ja4l.py:365` reads the same gate, and
a wider test would admit an SSH banner, which starts with method characters and one space.
