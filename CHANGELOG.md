# Changelog

All notable changes to ja4plus are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **BREAKING — JA4SSH counts a bare ACK the way FoxIO counts one** (#92). A bare
  ACK carries the ACK flag alone and no payload. `ja4plus` read the ACK flag
  alone, so it counted a SYN+ACK, a FIN+ACK and a RST+ACK as bare ACKs. It also
  created its state table entry on the first SSH packet, so it dropped the ACK
  that completes the TCP handshake. The two ACK counts of a JA4SSH fingerprint
  therefore change on any connection that carries a bare ACK. `ssh-r.pcap`,
  `ssh-scp-1050.pcap` and `ssh2.pcapng` now equal the reference on their first
  window. `ssh.pcapng` holds no bare ACK, and it stays at `c36s36_c76s124_c0s0`.

- **JA4SSH emits the window a connection holds open when it closes** (#92). A
  connection that carries fewer than 200 SSH packets produced no fingerprint at
  all, and a connection that closed part way through a window lost those packets.
  `ja4plus` now emits that window on a packet that carries the FIN flag and the ACK
  flag, which is the rule `python/ja4.py` states above `finalize_ja4ssh`. An empty
  window emits nothing. `ssh-r.pcap` now produces the occurrence keys the reference
  holds on all three of its streams.

### Divergence from the FoxIO reference

- **JA4SSH declines three results of the reference** (#96, #97, #105). Each one
  describes the capture and not the connection, so it cannot be compared against
  the output of another tool. The reference reads its mode field from the packet
  lengths of every connection in the capture, because `dict(ja4sh_stats)` shares
  one payload list (#96). It writes an extra occurrence from a window of zero SSH
  packets whenever a bare ACK follows a window boundary (#97). It emits no trailing
  window for the connection it holds at stream index 0, because `finalize_ja4ssh`
  guards with `if stream:` (#105). `ja4plus` reads the window alone, emits a value
  only for a window that holds SSH packets, and emits the trailing window for every
  connection that closes. `docs/implementation_notes.md` holds the measurement.

- **A loopback capture that carries IPv6 now reads the same way on every host**
  (#94). A capture whose link type is `DLT_NULL` starts each frame with the
  address family value of the host that captured it. That value is 24 on NetBSD
  and OpenBSD, 28 on FreeBSD, and 30 on Darwin. scapy binds one value,
  `socket.AF_INET6`, which is 10 on Linux, and no capture holds 10. `ipv6.pcapng`,
  `tls-alpn-h2.pcap` and `http-empty-useragent.pcap` therefore produced
  fingerprints on macOS and none on Linux. `ja4plus` binds all three BSD values
  when a caller imports it, and the conformance suite now reports the same counts
  on both hosts.

### Changed

- **BREAKING — JA4SSH emits one fingerprint for every 200 SSH packets** (#28).
  The window triggered at `min(packet_count, 10)`, and a complete key exchange
  also triggered it. A caller who relies on a fingerprint at 10 packets gets no
  fingerprint now. FoxIO states the interval verbatim in
  `technical_details/JA4SSH.png`: `(runs every 200 SSH packets by default)`. The
  constructor argument `packet_count` sets the window, and it defaults to 200. A
  bare ACK is not an SSH packet, and it does not advance the window. `ssh.pcapng`
  now produces exactly one JA4SSH fingerprint, `c36s36_c76s124_c0s0`, which
  equals the reference.

## [0.6.0] - 2026-05

Major spec-compliance update against the May 2026 FoxIO JA4+ spec
(PRs #267, #270, #277, #281, #288), and a parity pass against the Go
reference implementation.

### Added

- **JA4D6** (`ja4plus.JA4D6Fingerprinter` / `generate_ja4d6`): DHCPv6
  fingerprinting (10th JA4+ method). Format mirrors JA4D with DHCPv6
  semantics — DUID size from option 1, IATA presence flag, Client FQDN
  flag, all option types in presence order including nested options
  inside IA_NA / IA_TA / IA_PD / IA Address / IA Prefix.
- **JA4D** is now a public package export
  (`from ja4plus import JA4DFingerprinter, generate_ja4d`).
- **`Processor`** aggregator class (`ja4plus.Processor`) — runs every
  JA4+ fingerprinter on each packet and returns a list of result dicts.
  Provides `process_packet`, `reset`, `cleanup_connection`,
  `get_shard_key` (sorted 5-tuple, direction-independent).
- **JA4 / JA4S raw exposure**: every result entry on these fingerprinters
  now includes `raw` and `raw_original_order` keys, plus
  `last_raw` / `last_raw_original_order` instance attributes for the most
  recent successful parse. JSON CLI output emits these fields.
- **Multi-packet QUIC CRYPTO reassembly**: large ClientHellos that span
  multiple Initial datagrams (sharing a DCID) are now reassembled. New
  helpers `decrypt_quic_initial_crypto`, `parse_crypto_frames`,
  `reassemble_crypto_fragments`, `client_hello_from_crypto_fragments` in
  `ja4plus.utils.quic_utils`. The CRYPTO frame parser now skips ACK
  frames (0x02/0x03) instead of bailing on them.
- **X.509 module helpers**: `compute_ja4x_from_pem(bytes)` and
  `compute_ja4x_from_der(bytes)` mirroring Go's
  `ComputeJA4XFromPEM` / `ComputeJA4XFromDER`.
- CLI `--types` accepts `ja4d` and `ja4d6`.

### Fixed

- **JA4 ALPN non-alphanumeric** (PR #277): when the first or last byte
  of the first ALPN value is not ASCII alphanumeric, the JA4 ALPN
  component is now the first/last character of the lowercase HEX of the
  full first ALPN value. Previously ja4plus dropped non-ASCII bytes via
  `decode('ascii', errors='ignore')` and emitted `"99"` on the first
  byte being non-ASCII. Raw ALPN bytes are now preserved on
  `tls_info["alpn_raw"]`.
- **JA4H HTTP/2 + HTTP/3 version codes** (PR #288): `HTTP/2` now maps to
  `"20"` and `HTTP/3` to `"30"` in the JA4H part-A version code (not
  `"2"` / `"3"`). HTTP/1.0 / HTTP/1.1 unchanged.
- **JA4H cookie-VALUES sort by NAME only** (PR #288): the cookie-values
  hash component now sorts pairs explicitly by cookie name; previously
  relied on tuple-sort tie-breaking.
- **JA4SSH deterministic mode tiebreak** (PR #281): when multiple packet
  sizes tie for the highest frequency, the LOWEST value wins. Previously
  used `Counter.most_common(1)[0][0]`, whose result could vary based on
  insertion order.
- **JA4L UDP/QUIC server-first orderings**: the QUIC timing path no
  longer requires the connection's lexicographic direction to be
  `forward`. The first packet on the flow defines the client; subsequent
  packets are routed by comparing endpoints to that anchor.
- **JA4D skip set** matches the spec exactly: `{0, 53, 50, 81}`. The
  End marker (255) is handled by the parse loop and never recorded.

### Changed

- Bumped version to **0.6.0**.
- README updated to reflect 10 JA4+ methods and new APIs.

### Internal

- Per-DCID QUIC fragment buffer + reverse map for cleanup.
- New `ja4plus.utils.quic_utils._parse_alpn_with_bytes` returns both
  decoded strings and raw bytes for ALPN.
