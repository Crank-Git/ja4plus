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

### The window a connection holds open

A connection that closes emits the window it holds open. `python/ja4.py` states the
rule above `finalize_ja4ssh`: `If the SSH connection is not terminated or the last
sample is less than 200 the finalize function just cleans up and prints the last
JA4SSH hash`. That function runs on a packet that carries the FIN flag and the ACK
flag. An empty window emits nothing, so the second FIN packet of a close finds the
window the first FIN packet emptied and adds no value.

`ssh-r.pcap` confirms the reading. Stream 1 holds 11 SSH packets and one
occurrence, `c64s64_c6s5_c4s5`. Stream 2 holds 931 SSH packets, four full windows,
and a fifth occurrence of 131 packets. `ssh-scp-1050.pcap` and `ssh2.pcapng` carry
no FIN packet, and each keeps its full windows alone.

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py
(retrieved 2026-08-06).

### Three defects of the reference

`ja4plus` declines to reproduce three results of the reference. Each one describes
the capture and not the connection, so a user cannot compare it against the output
of another tool. The measurement ran `python/ja4.py` at the pinned commit against
`tshark` 4.6.7.

**The mode field reads the whole capture.** `dict(ja4sh_stats)` copies the
dictionary and not the two lists inside it, so every window on every connection
shares one `client_payloads` list and one `server_payloads` list. `ssh-r.pcap`
stream 2 window 1 reports `c64s64`, and the packets of that window read `c76s76`.
`ja4plus` reads the lengths of the window. #96 records the decision.

**A bare ACK writes another occurrence.** `(entry['count'] % ssh_sample_count) == 0`
stays true for every bare ACK that follows a window boundary, so each of those
packets writes the next occurrence key from a window that holds no SSH packet.
`ssh-r.pcap` stream 0 holds `JA4SSH.2` equal to `c64s64_c0s0_c0s1`. `ja4plus` emits
a value only for a window that holds SSH packets. #97 records the decision.

**The stream index 0 is false.** `finalize_ja4ssh` guards with `if stream:`, so the
reference emits no trailing window for the connection it holds at index 0.
`gre-sample.pcap`, `sshv1.pcap` and `v6.pcap` each hold their SSH connection at that
index, and the reference holds no JA4SSH value for any of them. The same run, with
that guard read as `if stream is not None:` and nothing else changed, emits
`c24s23_c4s4_c5s4` for `gre-sample.pcap` and `c20s12_c18s23_c10s1` for `sshv1.pcap`.
`ja4plus` emits the window for every connection that closes. #105 records the
decision.

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

### The scan reads the record layer, then the handshake messages

FoxIO publishes JA4X as an image, so the expected-output files decide. One TLS
record carries more than one handshake message, and one handshake message spans
more than one record. A scan that reads only the first handshake message of a
record misses the Certificate message that follows a ServerHello in the same
record. `latest.pcapng` stream 9 holds one 7136-byte record that carries both
messages, and the reference holds
`a373a9f83c6b_2bab15409345_0f2217ba412e` for it.

The scan therefore joins the payload of every complete handshake record that
follows without a gap, then reads the handshake messages of the joined bytes.
A proxy writes its own handshake first. The stream does not always start on a
record boundary, so the scan looks for the boundary one byte at a time.
`socks-https-example.pcap` supports this reading.

### One value for each certificate on each stream

`python/ja4x.py` of the FoxIO repository states "JA4X does not use any caching
from common.py", and it computes one JA4X value for each certificate of the
stream it reads. The key of the processed certificate set names the stream and
the certificate. A key that named only the certificate dropped the value of
every stream after the first that carried the same chain.
`socks-https-example.pcap` streams 2 and 4 exposed that defect.

Verified against
`https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4x.py` (retrieved
2026-08-06).

### Certificate deduplication cleanup

The processed certificate table holds 1000 entries. When the table is full, the
fingerprinter drops the oldest 500. This is a memory management strategy, not a
hard limit on unique certificates.

The eviction runs on each new entry. A wall clock gated it before, and a capture
replays faster than real time, so the table grew without a limit between two
runs of a gated eviction.

### The scan offset of a stream

The scan of one stream resumes where the last packet of the stream left it. A
scan that starts at zero on every packet costs the square of the stream length,
and `http2-with-cookies.pcapng` then takes 18 seconds.

The offset is stored with the sequence number the reassembled bytes start at. A
segment that arrives late lowers that number and moves every offset, so the scan
starts at zero again when the two numbers differ.

### Two reasons a JA4X value stays absent

The reference reads the TLS dissection of `tshark`, and two of its abilities
have no counterpart here.

- `tshark` decrypts a TLS 1.3 handshake with the secrets a capture carries.
  `http2-with-cookies.pcapng` and `chrome-cloudflare-quic-with-secrets.pcapng`
  hold a decryption secrets block with a `SERVER_HANDSHAKE_TRAFFIC_SECRET`
  entry, and the certificate of both reaches the wire encrypted. `ja4plus`
  decrypts nothing, so it reads no certificate there.
- `tshark` dissects TLS on the ports its dissector table names. It reads the
  tunnel of `socks-https-example.pcap` on port 1080 and holds a JA4X value. It
  reads no TLS on port 8080 of `https-connect.pcap`, and it reads none on port
  9901 of `socks4-https.pcap`. `ja4plus` reads the record layer by content, so
  it holds a JA4X value on all three. The deviation register records the two
  cases where `ja4plus` holds a value the reference does not.

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
