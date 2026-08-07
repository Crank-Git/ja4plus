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

FR-spec-conformance-15 — JA4SSH counts one SSH packet for the TCP segment that
completes an SSH message.

FR-spec-conformance-16 — JA4SSH counts no SSH packet for a TCP segment that holds
part of an SSH message and no message end.

FR-spec-conformance-17 — JA4L halves every round-trip time it measures.

FR-spec-conformance-18 — On a TCP connection, `JA4L-S` measures from the first SYN to
the first SYN-ACK.

FR-spec-conformance-19 — On a TCP connection, the client measurement point is the last
packet that carries the relative sequence number 1 and the relative acknowledgement
number 1.

FR-spec-conformance-20 — On a TCP connection, `JA4L-C` measures from the first SYN-ACK
to the client measurement point.

FR-spec-conformance-21 — On a TCP connection, a packet that holds a whole HTTP request
moves no measurement point.

FR-spec-conformance-22 — On a QUIC connection, the server measurement point is the
Initial packet that completes the ServerHello.

FR-spec-conformance-23 — On a QUIC connection, an Initial packet the fingerprinter
cannot decrypt supplies no measurement point.

FR-spec-conformance-24 — A reader of a QUIC Initial packet decrypts the bytes the
Length field of the long header names, and no byte behind them.

FR-spec-conformance-25 — A reader collects at most 16384 bytes of CRYPTO frame data
for one connection.

FR-spec-conformance-26 — JA4S emits the fingerprint of a QUIC server Initial packet
that carries a whole ServerHello.

FR-spec-conformance-27 — A QUIC server Initial packet replaces no stored client
connection ID.

FR-spec-conformance-28 — The conformance suite compares every raw key the FoxIO
expected-output files hold, one case for each key on each stream.

FR-spec-conformance-29 — A raw key that ja4plus computes no value for fails its case.
The suite reports no such key as not applicable.

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
- The JA4SSH window counts an SSH message, not a TCP segment. FoxIO counts the
  packets `tshark` labels `ssh`, and `tshark` labels only the segment that
  completes an SSH message. A segment that holds part of a message advances no
  counter and contributes no packet length.
- The SSH message boundary is readable only while the direction sends plaintext.
  Before the version banner, and after `SSH_MSG_NEWKEYS`, JA4SSH counts every
  segment that carries a payload.
- The JA4L propagation factor follows the hop count. The table is 1.5 for 21 hops
  or fewer, then 1.6, 1.7, 1.8 and 1.9 for 22, 23, 24 and 25 hops, and 2.0 for 26
  hops or more.
- JA4L reports one-way latency. FoxIO halves the time between the two measurement
  points of a value, and it truncates the result toward zero.
- The client measurement point starts at the bare ACK of the handshake. A later
  packet that meets `FR-spec-conformance-19` moves the point. Either endpoint sends
  that packet. `http1-with-cookies.pcapng` stream 0 puts the point on a bare ACK the
  server sends, and its expected `JA4L-C` is `20_64`.
- A packet that holds a whole HTTP request moves no measurement point.
  `latest.pcapng` stream 6 sends one complete `GET` request, and its expected
  `JA4L-C` is `32_128`, which is the bare ACK. `docs/implementation_notes.md` states
  the mechanism the project infers: the reference reads that packet as HTTP, and it
  holds the timestamps of each protocol in a separate table. The vectors prove the
  behaviour. They do not prove the mechanism.
- `FR-spec-conformance-18` to `FR-spec-conformance-21` describe the TCP form of
  JA4L. `FR-spec-conformance-17` applies to both forms. The QUIC form reads the
  Initial packets and the Handshake packets.
- The QUIC server measurement point is the Initial packet that completes the
  ServerHello. A server sends an Initial packet that holds an ACK frame before it
  sends the ServerHello, and that packet moves no point. The reference reads the
  point where `packet_type` is `0` and the TLS handshake type is `2`.
- A reader of a QUIC Initial packet decrypts the bytes the Length field names. RFC
  9000 Section 12.2 lets a sender coalesce several QUIC packets in one datagram, and
  the AEAD tag covers the bytes of one packet. A reader that decrypts to the end of
  the datagram fails on the tag for every coalesced packet.
- The server Initial keys derive from the connection ID the client chose. A capture
  that holds no client Initial packet gives no QUIC `JA4L-S` value.
- A client Initial packet and a server Initial packet carry the same long-header
  packet type, so the port names the direction. JA4S reads the port, and JA4L reads
  it the same way. A flow whose two ports are 443 names no server, and JA4S reads no
  Initial packet of that flow.
- A server Initial packet names the client with the connection ID the client chose as
  its source. It therefore supplies no client connection ID, and it replaces no stored
  value.
- The reference reads no QUIC handshake in the committed vectors. JA4S produces a
  fingerprint on nine QUIC streams that the reference holds no value for, in
  `chrome-cloudflare-quic-with-secrets.pcapng`, `ssh2.pcapng` and `tls3.pcapng`. JA4
  produces a fingerprint on the same nine streams, and #13 owns both.
- A reader collects at most 16384 bytes of CRYPTO frame data for one connection. RFC
  9000 Section 16 lets a CRYPTO frame offset reach 4611686018427387903, and a
  reassembly allocates a buffer that reaches the highest offset. A sender would
  otherwise name the size of that buffer.
- `docs/implementation_notes.md` states how the project reads the JA4L image.
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
- Changed file `ja4plus/utils/ssh_utils.py`. It holds `SSHMessageTracker`, which
  reports whether one TCP segment completes an SSH message.
- New file `tests/test_ja4ssh_message_count.py`.
- Changed file `ja4plus/utils/quic_utils.py`. It holds `_initial_packet_end`, which
  bounds an Initial packet by its Length field, and
  `decrypt_quic_server_initial_crypto`, which returns the CRYPTO fragments of one
  server Initial packet.
- New file `tests/quic_builder.py`. It builds a QUIC server Initial packet that
  decrypts, so a test states the JA4L server point without a capture file.
- New file `tests/test_quic_server_initial.py`.
- New file `tests/test_ja4l_quic_server_hello.py`.

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
That name states that JA4L halves the time it measures. The image names no
measurement point, so the expected-output files decide both points.

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details
(retrieved 2026-08-06).

Stream 0 of `browsers-x509.pcapng` proves both rules. It proves that JA4L halves the
time it measures, and it proves the client measurement point. These are its first
four packets.

| Offset from the SYN | Packet | TTL |
|---|---|---|
| `0.000000` | SYN | 128 |
| `0.003815` | SYN-ACK | 112 |
| `0.003927` | Bare ACK | 128 |
| `0.004371` | Client Hello, 517 payload bytes | 128 |

The expected `JA4L-S` is `1907_112`, and `3815 / 2 = 1907`. The expected `JA4L-C` is
`278_128`, and `(4371 - 3815) / 2 = 278`. Measured to the bare ACK, the client value
is 56. Measured before JA4L halves it, the value is 556. No expected value holds
either number.

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

`python/ja4.py` records the QUIC server measurement point with this test, verbatim:

```python
if x['packet_type'] == '0' and 'type' in x and x['type'] == '2':
    cache_update(x, 'B', x['timestamp'], STREAM)
    cache_update(x, 'server_ttl', x['ttl'], STREAM)
```

The value `0` is the Initial packet type, and the value `2` is the ServerHello
handshake type.

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py
(retrieved 2026-08-07).

RFC 9000 Section 12.2 states, verbatim: `Initial (Section 17.2.2), 0-RTT (Section
17.2.3), and Handshake (Section 17.2.4) packets contain a Length field that
determines the end of the packet.` It also states: `Using the Length field, a sender
can coalesce multiple QUIC packets into one UDP datagram.`

RFC 9000 Section 17.2 defines the field, verbatim: `Length: This is the length of the
remainder of the packet (that is, the Packet Number and Payload fields) in bytes,
encoded as a variable-length integer (Section 16).`

RFC 9001 Section 5.3 names the AEAD plaintext, verbatim: `The payload of the QUIC
packet, as described in [QUIC-TRANSPORT].` The Length field therefore bounds the
ciphertext, and a reader that decrypts every byte behind the packet number fails the
AEAD tag for every coalesced packet.

Verified against: https://www.rfc-editor.org/rfc/rfc9000.txt and
https://www.rfc-editor.org/rfc/rfc9001.html (retrieved 2026-08-07).

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
| One SSH message spans two TCP segments. | The second segment counts as one SSH packet. The first counts as none. |
| A capture starts after the SSH version banner. | The tracker reads no message boundary, and every segment counts as one SSH packet. |
| A length field names a size outside 2 and 65536 bytes. | The tracker stops the walk, and every later segment counts as one SSH packet. |
| The SSH version banner spans two TCP segments. | The second segment counts as one SSH packet, and the tracker keeps the message boundary. |
| The SSH version banner is longer than 255 bytes. | The tracker stops the walk, and every later segment counts as one SSH packet. |
| A server sends an Initial packet that holds an ACK frame, then one that holds the ServerHello. | `JA4L-S` measures to the second packet. |
| A server splits the ServerHello across two Initial packets. | `JA4L-S` measures to the packet that carries the last fragment. |
| A server coalesces a Handshake packet behind its Initial packet. | The reader decrypts the Initial packet and reads its ServerHello. |
| A QUIC server Initial packet does not decrypt. | The connection carries no `JA4L-S` value. |
| A capture starts after the client Initial packet. | The connection carries no `JA4L-S` value, because the server keys derive from the client connection ID. |
| A server repeats a fragment that completes no ServerHello. | The fragment buffer of the connection stops at 16384 bytes. |
| A CRYPTO frame names an offset of 2**40. | The reader drops the fragment and allocates no buffer. |

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
- [ ] `ssh-r.pcap` stream 1 produces one JA4SSH fingerprint whose packet counts
      equal `c6s5`.
- [ ] `ssh-r.pcap` stream 2 produces the fingerprint `c76s76_c66s65_c9s51` as its
      fifth occurrence.
- [ ] A loopback frame that holds the address family value 24, 28 or 30 dissects
      as IPv6.
- [ ] `ipv6.pcapng` produces the JA4 value `t12d4605h2_85626a9a5f7f_aaf95bb78ec9`
      on Linux and on macOS.
- [ ] `chrome-cloudflare-quic-with-secrets.pcapng` produces `JA4L-S=10990_56` on
      stream 0, port 50280.
- [ ] `tls3.pcapng` produces `JA4L-S=3583_57` on stream 25, port 61884.

## Out of scope

- JA4TScan. The spec places it out of scope, and it is an open question.
- Any change that no vector requires. That work is Epic 2.
- Performance of the conformance suite.

## Open questions

- Whether the port adopts the 200-packet window. This project follows FoxIO either
  way, under parity rule 1.
