---
id: correctness-audit
feature: Correctness audit
epic: "Epic 2: Correctness audit"
status: issued
issues: [13, 32, 33, 34, 35, 36, 37, 89]
mockups: []
---

## Purpose

The FoxIO vectors are well-formed captures of ordinary traffic. Real traffic is
neither. This feature set covers the defects that produce a wrong fingerprint, or a
crash, on input the vectors do not reach.

Every item below was found by reading the code at commit `5ab0252`. Each names a
file and a line. Each needs a failing test before a fix.

## User stories

- As a monitor operator, I want a malformed packet to be ignored, so that one
  hostile packet does not stop my monitor.
- As a capture analyst, I want one JA4L client value per connection, so that my
  output has one row per handshake.
- As a capture analyst, I want a repeated cookie name to be handled the same way in
  both cookie hashes, so that the two hashes describe the same request.

## Functional requirements

FR-correctness-audit-1 — The TCP reassembler orders segments correctly when the
sequence number wraps past its 32-bit maximum.

FR-correctness-audit-2 — The TCP reassembler holds no more than a fixed number of
segments for one connection.

FR-correctness-audit-3 — The TCP reassembler detects a duplicate segment without
scanning every stored segment.

FR-correctness-audit-4 — JA4L emits one client fingerprint per TCP connection.

FR-correctness-audit-5 — The project withdraws this requirement. It stated that JA4L
emits the client fingerprint from the ACK that completes the handshake, and
`browsers-x509.pcapng` contradicts that. `features/01-spec-conformance.md` holds the
JA4L measurement points as `FR-spec-conformance-17` to `FR-spec-conformance-21`. #88
built them, and #89 withdrew this requirement. The number stays, because four issues
quote the numbers below it.

FR-correctness-audit-6 — JA4H builds both cookie hashes from the same list of
cookies.

FR-correctness-audit-7 — JA4H keeps every occurrence of a repeated cookie name.

FR-correctness-audit-8 — No parser trusts a length field it read from the packet.

FR-correctness-audit-9 — No fingerprinter raises when given a truncated packet.

FR-correctness-audit-10 — No fingerprinter raises when given a packet whose declared
length exceeds its actual length.

FR-correctness-audit-11 — The project removes `_src_is_client` from
`ja4plus/fingerprinters/ja4l.py`.

FR-correctness-audit-12 — `get_raw_fingerprint` has one branch for the original
order and one branch for the sorted order, and the two produce different values, or
the branch is removed.

FR-correctness-audit-13 — The malformed-input suite runs on every pull request.

## User flows

**A hostile packet reaches the processor.**

1. The processor receives a packet whose TLS record declares a length of 65535
   bytes and carries 12 bytes.
2. Each fingerprinter reads the declared length and compares it against the
   available bytes.
3. Each fingerprinter returns nothing.
4. The processor returns an empty list of results.
5. The monitor continues with the next packet.

**A long-lived connection crosses the sequence-number boundary.**

1. The reassembler holds segments near the 32-bit maximum.
2. A segment arrives with a small sequence number.
3. The reassembler compares sequence numbers using modular arithmetic.
4. The reassembler places the new segment after the stored segments.

## Screens & states

This feature set has no screen. Its output is the test report.

## Behaviour rules

The table below is the audit register. Each row is one defect, its evidence, and
the rule the fix must satisfy.

| # | Location | What is wrong | Rule for the fix |
|---|---|---|---|
| 1 | `ja4plus/utils/tcp_stream.py:53` | `sorted(...)` orders raw sequence numbers. A sequence number is 32 bits and wraps. A connection that crosses the boundary reassembles in the wrong order. | Compare with modular arithmetic. #32 built it. |
| 2 | `ja4plus/utils/tcp_stream.py:37` | The duplicate check scans every stored segment for each new segment. Cost grows with the square of the segment count. | Use a set of `(seq, length)` pairs. #32 built it. |
| 3 | `ja4plus/utils/tcp_stream.py:41` | `max_stream_bytes` limits the reassembled output, not the stored segments. A sender that emits many distinct small segments grows one stream without bound. | Cap the stored bytes per stream, not only the output. #33 built it, with a segment cap beside the byte cap. |
| 4 | `ja4plus/utils/tcp_stream.py:33` | `base_seq` is stored and never read. | Remove it, or use it. #32 removed the stored value. The `base_seq` method stays, because `ja4x.py` reads it. |
| 5 | `ja4plus/fingerprinters/ja4l.py:223` | The client branch matches every ACK without a SYN flag. Each later ACK overwrites timestamp `C` and emits another client fingerprint with a larger latency. | Emit one client value for one connection. `FR-spec-conformance-19` gives the measurement point, and #88 built it. |
| 6 | `ja4plus/fingerprinters/ja4l.py:279` | `_src_is_client` is never called. | Remove it. |
| 7 | `ja4plus/fingerprinters/ja4h.py:163` | `cookies[k] = v` drops a repeated cookie name, while `cookie_fields` keeps it. The cookie-name hash and the cookie-value hash then describe different cookie sets. | Build both hashes from one ordered list of pairs. #35 built it. |
| 8 | `ja4plus/fingerprinters/ja4h.py:131` | The request-line pattern requires `HTTP/<digit>.<digit>`. A request line that reads `HTTP/2` never matches, although `_http_version_to_str` handles `2`. | Accept an optional minor version. #35 built it. |
| 9 | `ja4plus/fingerprinters/ja4h.py:82` | When the buffer is not an HTTP request, the segment stays in the reassembler forever. | Remove the stream when the buffer cannot become an HTTP request. #33 built it. |
| 10 | `ja4plus/fingerprinters/ja4.py:292` | The `if original_order:` branch and its `else:` branch build the same string. | Remove the branch, or make the two differ. #36 removed the branch that builds the signature-algorithm form. The cipher branch and the extension branch stay, because the two arms differ. |
| 11 | `ja4plus/fingerprinters/base.py:38` | `add_fingerprint` stores the packet object. A monitor holds every packet it ever fingerprinted. | Store what the result needs. Never store the packet. #36 built it. An entry now holds `src`, `dst`, `srcport` and `dstport`. |
| 12 | `ja4plus/fingerprinters/ja4ssh.py:80` | On a non-standard port, the lower port number decides which side is the server. Two ephemeral ports make this arbitrary. | Decide from the first SSH banner, and fall back to the port. |
| 13 | `ja4plus/collector.py:33` | The module holds mutable state in module-level variables. It is deprecated and states removal at version 0.4.0. The project is at 0.6.0. | Remove the module in Epic 4. |
| 14 | `ja4plus/fingerprinters/ja4ssh.py:354` | `interpret_fingerprint` catches every exception and returns an error dictionary. | Catch the parse errors it expects. #36 built it. The handler now names `AttributeError`, `IndexError` and `ValueError`. |

## Data touched

- Changed files: `ja4plus/utils/tcp_stream.py`, `ja4plus/fingerprinters/ja4l.py`,
  `ja4plus/fingerprinters/ja4h.py`, `ja4plus/fingerprinters/ja4.py`,
  `ja4plus/fingerprinters/ja4ssh.py`, `ja4plus/fingerprinters/base.py`.
- New directory `tests/fuzz/`.

## Interfaces

This feature set changes no external interface. It reads two FoxIO captures that
exist for this purpose.

| Capture | What it holds |
|---|---|
| `ssh2-malformed.pcap` | An SSH session with malformed records. |
| `ssh2-moloch-crash.pcap` | An SSH capture that crashed another implementation. |
| `badcurveball.pcap` | A TLS handshake with a malformed curve list. |
| `CVE-2018-6794.pcap` | A capture that exercises a reassembly bypass. |

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/pcap (retrieved
2026-08-06).

## Edge cases & failures

| Case | What happens |
|---|---|
| A TCP segment arrives with a sequence number below the stored base, because the number wrapped. | The reassembler places it after the stored segments, in sequence order. |
| A sender emits 100000 distinct one-byte segments on one connection. | The reassembler holds no more than the per-stream byte cap, and no more than the per-stream segment cap. |
| A buffer holds bytes that no HTTP request line starts with. | JA4H removes the stream from the reassembler. |
| A TLS record declares a length larger than the packet. | The parser returns nothing. |
| An extension list declares more extensions than the packet carries. | The parser returns nothing. |
| An HTTP request repeats a cookie name with two values. | Both hashes describe both occurrences. |
| A TCP connection sends 1000 ACKs after the handshake. | JA4L emits one client fingerprint. |
| Both endpoints use an ephemeral port for SSH. | The first banner decides which side is the server. |
| No banner is seen. | The lower port decides, and the result is recorded as a guess. |

## Acceptance criteria

- [ ] A reassembly test that crosses the 32-bit sequence boundary produces the
      segments in the correct order.
- [ ] Adding 10000 segments to one stream completes in under one second.
- [ ] One stream holds no more than the configured byte cap, whatever the segment
      count.
- [ ] A TCP connection with 100 ACKs after the handshake produces exactly one
      `JA4L-C` value.
- [ ] An HTTP request with a repeated cookie name produces a cookie-name hash and a
      cookie-value hash that both describe two cookies.
- [ ] An HTTP request line that reads `GET / HTTP/2` produces a fingerprint whose
      version code is `20`.
- [ ] `pytest tests/fuzz/` passes.
- [ ] Every FoxIO capture named in `Interfaces` produces no exception.
- [ ] A truncated copy of every FoxIO capture produces no exception.
- [ ] `rtk git grep -n "_src_is_client" ja4plus/` reports nothing.
- [x] No fingerprinter stores a packet object after `process_packet` returns.
      `tests/test_no_retained_packets.py` walks each fingerprinter and reports every
      path that reaches a packet. #36 built it.

## Out of scope

- The concurrency contract. Epic 3 covers it.
- State-table eviction by age. Epic 3 covers it.
- Removing `ja4plus/collector.py`. Epic 4 removes it.
- Any change that a FoxIO vector would detect. Epic 1 covers those.

## Open questions

None.
