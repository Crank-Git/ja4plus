---
id: spec-conformance
feature: Spec conformance
epic: "Epic 1: Spec conformance"
status: issued
issues: [12, 27, 28, 29, 30, 31, 78, 80, 88, 89, 94]
mockups: []
---

## Purpose

A fingerprint exists so that one tool's output can be compared against another
tool's output. A fingerprint that does not match the FoxIO reference is worse than
no fingerprint, because it looks usable and is not.

Epic 0 makes the conformance suite run. This feature set makes it pass. It also
fixes the three places where this project knowingly departs from the published
FoxIO specification.

## User stories

- As a capture analyst, I want the JA4 value from this project to equal the JA4
  value from the FoxIO Wireshark plugin, so that I can search one against the
  other.
- As a maintainer, I want to know which method a vector failed on, so that I can
  fix one method at a time.
- As a library integrator, I want every raw form the reference publishes, so that
  I can debug a fingerprint that does not match.

## Functional requirements

FR-spec-conformance-1 — The conformance suite reads every committed vector.

FR-spec-conformance-2 — The suite compares one method on one stream at a time.

FR-spec-conformance-3 — A failure message names the vector, the stream, the method,
the expected value, and the produced value.

FR-spec-conformance-4 — JA4SSH emits one fingerprint for every 200 SSH packets on a
connection.

FR-spec-conformance-5 — The JA4SSH window size is the value the caller passed to the
constructor.

FR-spec-conformance-6 — JA4SSH emits no fingerprint before the window fills.

FR-spec-conformance-7 — The JA4 fingerprinter exposes the value `JA4_o`.

FR-spec-conformance-8 — The JA4S fingerprinter exposes the value `JA4_o`.

FR-spec-conformance-9 — `calculate_distance` reads the propagation factor from the
FoxIO hop-count table.

FR-spec-conformance-10 — `calculate_distance` accepts an explicit propagation
factor that overrides the table.

FR-spec-conformance-11 — The project documents every reading it made of an
ambiguous part of the specification.

FR-spec-conformance-12 — `tests/test_parity.py` no longer asserts that a name
exists.

FR-spec-conformance-13 — The conformance suite reports the same counts on every
host.

FR-spec-conformance-14 — `ja4plus` reads the IPv6 layer of a loopback capture on
every host.

FR-spec-conformance-15 — JA4L halves every round-trip time it measures.

FR-spec-conformance-16 — `JA4L-S` measures from the first SYN to the first SYN-ACK.

FR-spec-conformance-17 — The client measurement point is the last packet that carries
the relative sequence number 1 and the relative acknowledgement number 1.

FR-spec-conformance-18 — `JA4L-C` measures from the first SYN-ACK to the client
measurement point.

FR-spec-conformance-19 — A packet that holds a whole HTTP request moves no
measurement point.

## User flows

**A maintainer fixes a failing method.**

1. The maintainer runs `pytest tests/ -m spec_validation`.
2. The suite reports a failure that names the vector, the method, and both values.
3. The maintainer reads the FoxIO material for that method.
4. The maintainer changes the fingerprinter.
5. The maintainer runs the suite again and sees the vector pass.

**A maintainer reads a raw form to explain a mismatch.**

1. The maintainer computes the fingerprint with `raw=True`.
2. The maintainer compares the raw form against `JA4_r` in the expected-output
   file.
3. The maintainer identifies the field that differs.

## Screens & states

This feature set has no screen. Its output is the test report.

| State | What the maintainer sees |
|---|---|
| All vectors pass | The suite reports 37 vectors passed. |
| One method fails | The report names the vector, the stream index, the method key, and both values. |
| A method is absent from a vector | The report records it as not applicable and continues. |
| A vector produces more fingerprints than the reference | The report names the extra occurrence keys. |

## Behaviour rules

- FoxIO specifies the behaviour. Where the FoxIO material is an image and the image
  is ambiguous, the expected-output file decides, and the reading goes into
  `docs/implementation_notes.md`.
- The JA4SSH window counts SSH packets sent by either side. A bare ACK is not an
  SSH packet, and does not advance the window. The bare-ACK counters reset with the
  window.
- The JA4SSH occurrence counter starts at 1 and increases for each window on the
  same connection.
- The JA4L propagation factor follows the hop count. The table is 1.5 for 21 hops
  or fewer, then 1.6, 1.7, 1.8 and 1.9 for 22, 23, 24 and 25 hops, and 2.0 for 26
  hops or more.
- JA4L reports one-way latency. FoxIO halves the time between the two measurement
  points of a value, and it truncates the result toward zero.
- The client measurement point starts at the bare ACK of the handshake. The first
  packet of the application handshake then moves it. Either endpoint sends that
  packet. `http1-with-cookies.pcapng` stream 0 puts the point on a bare ACK the
  server sends, and its expected `JA4L-C` is `20_64`.
- A packet that holds a whole HTTP request moves no measurement point. The reference
  reads that packet as HTTP, and the HTTP dissector holds its timestamps in a
  separate cache. `latest.pcapng` stream 6 sends one complete `GET` request, and its
  expected `JA4L-C` is `32_128`, which is the bare ACK.
- `docs/implementation_notes.md` records the reading of the JA4L image that these
  rules come from.
- `JA4_o` is the hashed form of the original-order raw value. `JA4_ro` is that raw
  value unhashed. The relationship between them matches the relationship between
  `JA4` and `JA4_r`.
- No fingerprinter changes in a way that a vector does not require. A change that
  no vector covers belongs to Epic 2.
- A vector produces one result on every host. A capture whose link type is
  `DLT_NULL` starts each frame with the address family value of the host that
  captured it, and that value is 24 on NetBSD and OpenBSD, 28 on FreeBSD, and 30
  on Darwin. `ja4plus` binds all three values to the IPv6 layer, because scapy
  binds only the value of the reading host.
- A register entry names a real deviation from FoxIO. A failure that one host
  produces and another host does not is a defect in this project, and it never
  earns a register entry.

## Data touched

- Changed file `ja4plus/fingerprinters/ja4ssh.py`.
- Changed file `ja4plus/fingerprinters/ja4.py`.
- Changed file `ja4plus/fingerprinters/ja4s.py`.
- Changed file `ja4plus/fingerprinters/ja4l.py`.
- Changed file `tests/test_spec_validation.py`.
- New file `tests/conformance_index.py`. It groups a fingerprint by stream, by
  method and by occurrence, so one test case compares one value.
- Changed file `tests/test_parity.py`.
- Changed file `docs/implementation_notes.md`.
- New file `ja4plus/utils/loopback.py`. It binds the BSD address family values of
  a loopback frame to the IPv6 layer.
- New file `tests/test_loopback_link_type.py`.
- Changed file `ja4plus/__init__.py`.

## Interfaces

FoxIO publishes each method's description in `technical_details/`. Two are text
files. The rest are images.

| Method | Source | Format |
|---|---|---|
| JA4 | `technical_details/JA4.md` | Text |
| JA4H | `technical_details/JA4H.md` | Text |
| JA4L, JA4S, JA4SSH, JA4T, JA4X, JA4D, JA4D6 | `technical_details/<name>.png` | Image |

The JA4SSH image states, verbatim: `(runs every 200 SSH packets by default)`.

The JA4L image gives the propagation delay factor as a table keyed on hop count:
`<=21` maps to `1.5`, `22` to `1.6`, `23` to `1.7`, `24` to `1.8`, `25` to `1.9`,
and `>=26` to `2.0`. It gives the speed of light in fiber as `0.128 miles or 0.206
km per µs`.

The JA4L image names the value it reports, verbatim: `One-way TCP latency in us`.
That name states the halving. The image names no measurement point, so the
expected-output files decide both points.

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details
(retrieved 2026-08-06).

Stream 0 of `browsers-x509.pcapng` proves the halving and the client measurement
point. These are its first four packets.

| Offset from the SYN | Packet | TTL |
|---|---|---|
| `0.000000` | SYN | 128 |
| `0.003815` | SYN-ACK | 112 |
| `0.003927` | Bare ACK | 128 |
| `0.004371` | Client Hello, 517 payload bytes | 128 |

The expected `JA4L-S` is `1907_112`, and `3815 / 2 = 1907`. The expected `JA4L-C` is
`278_128`, and `(4371 - 3815) / 2 = 278`. Measured to the bare ACK the client value
is 56, and measured without the halving it is 556. No expected value holds either
number.

Verified against:
https://github.com/FoxIO-LLC/ja4/blob/main/python/test/testdata/browsers-x509.pcapng.json
(retrieved 2026-08-06).

The expected value for `ssh.pcapng` is a single JA4SSH fingerprint,
`c36s36_c76s124_c0s0`. The two counts sum to 200, which confirms the window size.

Verified against:
https://github.com/FoxIO-LLC/ja4/blob/main/python/test/testdata/ssh.pcapng.json
(retrieved 2026-08-06).

libpcap defines the address family value of a `DLT_NULL` frame. The value of
`AF_INET6` is 24 on NetBSD, OpenBSD and BSD/OS, 28 on FreeBSD, and 30 on Darwin.
libpcap reads all three values from a savefile, and it reads one value from a live
capture.

Verified against:
https://github.com/the-tcpdump-group/libpcap/blob/f98637ad7f086a34c4027339c9639ae1ef842df3/gencode.c#L3333-L3354
(retrieved 2026-08-06).

scapy names 24, 28 and 30 as IPv6 in `LOOPBACK_TYPES`, and binds `socket.AF_INET6`
alone. That value is 10 on Linux.

Verified against: `scapy/layers/inet6.py:4226-4228` and `scapy/layers/l2.py:720-724`
(scapy 2.7.0).

## Edge cases & failures

| Case | What happens |
|---|---|
| A connection ends before the JA4SSH window fills. | No fingerprint is emitted. This matches the reference. |
| A capture holds fewer than 200 SSH packets on a connection. | No JA4SSH fingerprint is emitted for that connection. |
| A caller constructs `JA4SSHFingerprinter(packet_count=10)`. | The window is 10. The caller asked for it. |
| A TTL implies a hop count above 26. | The propagation factor is 2.0. |
| A TTL implies a negative hop count. | The hop count is clamped to zero and the factor is 1.5. |
| A vector holds a method key this project does not implement, such as `JA4TScan`. | The suite ignores the key. |
| The reference emits two fingerprints and this project emits one. | The suite fails and names the missing occurrence. |
| A capture holds the `DLT_NULL` link type and the address family value 24, 28 or 30. | The reader dissects the frame as IPv6 on every host. |
| A caller builds a loopback frame. | The address family value is the scapy default. This project binds the dissection path alone. |

## Acceptance criteria

- [ ] `pytest tests/ -m spec_validation` passes on all 37 vectors.
- [ ] A JA4SSH fingerprinter built with default arguments emits nothing at 10
      packets.
- [ ] A JA4SSH fingerprinter built with default arguments emits one fingerprint at
      200 SSH packets.
- [ ] `ssh.pcapng` produces exactly one JA4SSH fingerprint, and it equals
      `c36s36_c76s124_c0s0`.
- [ ] `JA4Fingerprinter` exposes a `JA4_o` value for `tls12.pcap`, and it equals
      `t13d1715h2_5b234860e130_014157ec0da2`.
- [ ] `JA4SFingerprinter` exposes a `JA4_o` value.
- [ ] `calculate_distance` returns a different result for a 20-hop path and a
      30-hop path with the same latency.
- [ ] `calculate_distance(latency, propagation_factor=1.6)` uses 1.6.
- [ ] `docs/implementation_notes.md` records one entry for each ambiguous reading.
- [ ] No test in `tests/test_parity.py` asserts only that an attribute exists.
- [ ] `pytest tests/ -m spec_validation` reports the same counts on Linux and on
      macOS.
- [ ] A loopback frame that holds the address family value 24, 28 or 30 dissects
      as IPv6.
- [ ] `ipv6.pcapng` produces the JA4 value `t12d4605h2_85626a9a5f7f_aaf95bb78ec9`
      on Linux and on macOS.

## Out of scope

- JA4TScan. The spec places it out of scope, and it is an open question.
- Any change that no vector requires. That work is Epic 2.
- Performance of the conformance suite.

## Open questions

- Whether the port adopts the 200-packet window. This project follows FoxIO either
  way, under parity rule 1.
