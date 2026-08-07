# Implementation Notes

Behaviors in the Python ja4plus library that are not documented in the
FoxIO JA4+ specification. The Go implementation MUST match these behaviors
to produce identical fingerprints.

---

## JA4 - TLS Client Hello

### ALPN non-ASCII handling

When the first byte of the first ALPN protocol has `ord() > 127`, the ALPN
field is set to `'99'` rather than the hex representation of the byte.

**Location:** `ja4plus/fingerprinters/ja4.py:90`

**Rationale:** Simplifies output to a fixed 2-char field. The spec says
"hex representation of the byte" but `'99'` is used as an unambiguous
sentinel for non-ASCII protocols.

### Version mapping (beyond TLS 1.0-1.3)

The spec only mentions TLS 1.0 through 1.3. The implementation also maps:

| Wire value | String | Protocol   |
|------------|--------|------------|
| `0x0300`   | `s3`   | SSL 3.0    |
| `0x0200`   | `s2`   | SSL 2.0    |
| `0xFEFF`   | `d1`   | DTLS 1.0   |
| `0xFEFD`   | `d2`   | DTLS 1.2   |
| `0xFEFC`   | `d3`   | DTLS 1.3   |

Any unrecognized version maps to `'00'`.

### Cipher sorting

Ciphers are sorted numerically on their integer values before formatting
as 4-char hex and hashing. This produces the same result as lexicographic
sort on zero-padded 4-char hex strings.

### Raw fingerprint format

Raw fingerprints use prefixed output: `JA4_r = {fp}` and `JA4_ro = {fp}`.
Note the spaces around `=`. This is a display convention, not part of the
fingerprint value itself.

### The original-order hashed value

`JA4_o` hashes the original-order raw value. It keeps the ciphers in wire
order. It keeps every extension in wire order, and it holds SNI (`0x0000`) and
ALPN (`0x0010`), which `JA4` removes. The vector
`tests/foxio_vectors/tls12.pcap.json` gives `JA4_o.1` as
`t13d1715h2_5b234860e130_014157ec0da2`, and that value is the hash of the
`JA4_ro.1` fields.

FoxIO publishes no `JA4S_o` key. JA4S hashes its extensions in wire order, and
the published `JA4S_r` value holds that same wire order. The original-order
hashed value of JA4S therefore equals the JA4S fingerprint. The
`fingerprint_original_order` key carries it, so one caller reads one name on
JA4 and on JA4S.

---

## JA4L - Latency

### Output format includes prefix

JA4L fingerprints include a direction prefix:
`JA4L-S={latency_us}_{ttl}` and `JA4L-C={latency_us}_{ttl}`.
The spec describes `{latency_microseconds}_{ttl}` without a prefix.

### Latency is raw time difference, not RTT/2

The latency value is the raw time difference between handshake points,
not the round-trip time divided by 2.

---

## JA4SSH - SSH Traffic

### The fingerprint window

The window holds 200 SSH packets by default, and the constructor argument
`packet_count` sets it. `technical_details/JA4SSH.png` states the interval
verbatim: `(runs every 200 SSH packets by default)`.

The window counts the SSH packets of both directions. A bare ACK is not an SSH
packet, and it does not advance the window. The image lists `SSH packets sent
from client`, `SSH packets sent from server`, `Bare ACKs sent from client` and
`Bare ACKs sent from server` as four separate fields. `ssh-scp-1050.pcap` confirms
the reading: the reference holds four windows, each of 200 SSH packets, and the
bare ACK counts of the four differ.

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details
(retrieved 2026-08-06).

**BUG (fixed by #28):** Before #28 the window triggered at
`min(configured_packet_count, 10)`, and a complete key exchange also triggered
it. A capture of 10 SSH packets produced a fingerprint that no reference
implementation matches.

### The bare ACK

A bare ACK is one packet that carries the ACK flag alone and no payload. FoxIO
counts one only when the TCP flags equal `0x0010`, so a SYN+ACK, a FIN+ACK and a
RST+ACK never reach the bare-ACK counter.

The ACK that completes the TCP handshake is a bare ACK, and it arrives before the
first SSH packet of the connection. FoxIO counts it, because `python/ja4.py` holds
a state table entry for every packet whose source port or destination port is 22.
Four vectors confirm the reading. `ssh-r.pcap`, `ssh-scp-1050.pcap` and
`ssh2.pcapng` each hold one bare client ACK before the first SSH packet, and each
reference value reports one more client ACK than a state table built on SSH data
alone. `ssh.pcapng` holds no bare ACK, and its value is unchanged.

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4ssh.py
(retrieved 2026-08-06).

**BUG (fixed by #92):** Before #92 the fingerprinter created a state table entry
on the first SSH packet, so it dropped the ACK of the TCP handshake. It also read
the ACK flag alone, so it counted a SYN+ACK, a FIN+ACK and a RST+ACK as bare ACKs.

### The remainder of a stream

The reference emits the packets that remain on some connections and not on others,
and the vectors do not settle the condition. On `ssh-r.pcap` stream 1 the reference
holds `c64s64_c6s5_c4s5`, which counts 11 SSH packets. `gre-sample.pcap`,
`sshv1.pcap` and `v6.pcap` each hold one SSH connection of the same shape, with a
banner, data packets and a FIN packet, and the reference holds no JA4SSH value for
any of them.

`python/ja4.py` runs `finalize_ja4ssh` on a packet that carries the FIN flag and
the ACK flag, and that function acts only when `entry['protos']` ends with `:ssh`.
Every FIN+ACK packet of these captures carries no payload, so the condition depends
on a `tshark` protocol label that a capture file alone does not give. ja4plus emits
no value for a window a connection holds open, because a rule that emits one gives
`gre-sample.pcap`, `sshv1.pcap` and `v6.pcap` a value the reference does not hold.
#92 owns the question.

### Two defects of the reference

The reference produces two JA4SSH results that a simulation of `python/ja4ssh.py`
reproduces, and that describe no property of the connection.

`dict(ja4sh_stats)` copies the dictionary and not the two lists inside it, so every
window on every connection shares one `client_payloads` list and one
`server_payloads` list. The mode field therefore reads the packet lengths of every
connection the tool has seen. `ssh-r.pcap` stream 2 window 1 reports `c64s64`, and
the packets of that window read `c76s76`. #96 owns the decision.

`(entry['count'] % ssh_sample_count) == 0` stays true for every bare ACK that
follows a window boundary, so each of those packets writes the next occurrence key
from a window that holds no SSH packet. `ssh-r.pcap` stream 0 holds `JA4SSH.2`
equal to `c64s64_c0s0_c0s1`. #97 owns the decision.

### The TCP segment

ja4plus counts one SSH packet for every TCP segment that carries a payload, and
the reference counts the packets `tshark` labels `ssh`. `tshark` labels the segment
that completes an SSH message and not the earlier segment, so the two disagree by
one packet for each message that spans two segments. #98 owns the defect.

### Direction detection on non-standard ports

**BUG (fixed in v0.4.0):** Prior to v0.4.0, non-standard port direction
detection was inverted: the lower port was assigned as client when it
should be server. Fixed by swapping the assignment.

---

## JA4X - X.509 Certificates

### Certificate deduplication cleanup

The processed certificate set is pruned when it exceeds 1000 entries,
keeping the most recent 500. This is a memory management strategy,
not a hard limit on unique certificates.

### TCP reassembly

**Fixed in v0.4.0:** Stream reassembly now uses TCP sequence numbers
for correct ordering. Prior versions appended data in arrival order,
which could corrupt streams with out-of-order TCP segments.

---

## JA4H - HTTP

### TCP reassembly

**Fixed in v0.4.0:** HTTP parsing now accumulates TCP stream data
before attempting to parse. Prior versions operated on single-packet
payloads only, missing HTTP requests spanning multiple TCP segments.

---

## TLS Utilities

### SNI parsing returns boolean True for unparseable SNI

When the SNI extension is present but the hostname cannot be extracted,
`_parse_sni()` returns `True` (boolean). This works because the JA4
fingerprinter checks `'d' if sni else 'i'`, and `True` is truthy.

---

## IPv6 Support

**Added in v0.4.0:** All fingerprinters support both IPv4 and IPv6.
Prior versions only checked for scapy's `IP` layer.

---

## QUIC Support

**Added in v0.4.0.** QUIC Initial packet parsing decrypts the Initial
packet using DCID-derived keys, extracts CRYPTO frames, and parses the
contained TLS ClientHello.

**Crypto pipeline:**
1. Extract DCID from the Initial long header
2. Derive Initial secret via HKDF (salt depends on QUIC version)
3. Derive client key, IV, and header protection key
4. Remove header protection (AES-ECB mask)
5. Decrypt payload with AES-128-GCM
6. Extract CRYPTO frames and reassemble by offset
7. Parse the contained TLS ClientHello

**Version detection:** QUIC v2 identified by wire version `0x6B3343CF`;
all other non-zero versions use the v1 salt.

**Integration:** `extract_tls_info` checks for QUIC on UDP packets
before falling through to standard TLS parsing.
