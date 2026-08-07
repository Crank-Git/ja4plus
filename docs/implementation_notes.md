# Implementation Notes

Behaviors in the Python ja4plus library that are not documented in the
FoxIO JA4+ specification. The Go implementation MUST match these behaviors
to produce identical fingerprints.

FoxIO publishes seven of the twelve methods as an image. Where an image leaves a question
open, the expected-output file decides, and the reading goes here. An entry names the
vector that supports the reading, or it states that no FoxIO material validates it.

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

The JA4S section below records the `JA4S_o` reading.

---

## JA4S - TLS Server Hello

### The raw form holds the extensions in wire order

FoxIO publishes JA4S as an image, so the expected-output file decides the extension
order. `tls-alpn-h2.pcap.json` gives `JA4S_r` as `t1204h2_cca9_0000,ff01,000b,0010`.
That order is not numeric order, so it is wire order.

The JA4S fingerprint hashes the extensions in wire order, and it equals the reference
`JA4S` value `t1204h2_cca9_1428ce7b4018`. The `raw_original_order` key holds the wire
order, and it equals the reference `JA4S_r`. The `raw` key sorts the extensions, so it
does not equal `JA4S_r`. #108 owns that difference.

### The original-order hashed value has no reference

No FoxIO expected-output file carries a `JA4S_o` key. The 37 files hold `JA4`, `JA4_r`,
`JA4_o`, `JA4_ro`, `JA4S`, `JA4S_r`, `JA4H`, `JA4H_ro`, `JA4X`, `JA4SSH`, `JA4L-C` and
`JA4L-S`, and no other method key.

`ja4plus` derives the value from the reading above. JA4S hashes its extensions in wire
order, so the original-order hash of JA4S equals the JA4S fingerprint. The
`fingerprint_original_order` key carries that value, so one caller reads one name on JA4
and on JA4S.

**No FoxIO material validates this value, in either direction.** The `docs/specs/spec.md`
changelog records it at round 11.

**Location:** `ja4plus/fingerprinters/ja4s.py:102`.

---

## JA4T and JA4TS - TCP

### No FoxIO vector validates JA4T or JA4TS

No expected-output file of the 37 carries a `JA4T` key or a `JA4TS` key, and the vector
set holds many TCP handshakes. The image is the only FoxIO material for both methods, and
no reference value settles a question the image leaves open.

### The option list holds six option kinds

`ja4plus` maps six TCP option kinds to their IANA numbers.

- 0 for EOL
- 1 for NOP
- 2 for MSS
- 3 for Window Scale
- 4 for SACK Permitted
- 8 for Timestamp

`ja4plus` drops an option kind outside those six, and it writes no number for that kind.
A packet that carries no option of the six gives the value `0`.

The list keeps the wire order. `ja4plus` never sorts it.

**Location:** `ja4plus/fingerprinters/ja4t.py:67` and `ja4plus/fingerprinters/ja4ts.py:68`.

---

## JA4D and JA4D6 - DHCP

### The reference values come from the FoxIO Wireshark dissector

The FoxIO Python implementation emits no JA4D and no JA4D6, so the expected-output file
of each DHCP capture holds an empty array. `tests/foxio_vectors/dhcp.pcapng.json` and
`tests/foxio_vectors/dhcpv6.pcap.json` each hold `[]`. The FoxIO Rust implementation
emits neither method. Both of its snapshots hold `[]`.

The FoxIO Wireshark dissector does write a reference value for both methods.
`tests/foxio_vectors/wireshark_expected/` holds a copy of the two files, taken without
change from `wireshark/test/testdata/` at the pinned upstream commit.

`.claude/rules/external-apis.md` states that the files under `wireshark/test/testdata/`
are not the authority. `wireshark/test/testdata/tls12.pcap.json` holds an empty array
where the Python file of the same name holds four fingerprints. These two methods are the
reverse case, and the
Wireshark file is the only FoxIO reference output for them. The FoxIO Zeek baseline
`zeek/tests/Traces/Scripts.ja4-dhcp/ja4d.log` holds the same four JA4D values, which is a
second FoxIO implementation that agrees. No second FoxIO implementation emits JA4D6.

`ja4plus` matches every one of the ten reference values, and every fingerprint it emits
appears in the reference.

| Capture | Frame | Reference value |
|---|---|---|
| `dhcp.pcapng` | 1 | `disco0000in_61-55_1-3-6-42` |
| `dhcp.pcapng` | 2 | `offer0000nn_1-58-59-51-54_00` |
| `dhcp.pcapng` | 3 | `reqst0000in_61-54-55_1-3-6-42` |
| `dhcp.pcapng` | 4 | `dpack0000nn_58-59-51-54-1_00` |
| `dhcpv6.pcap` | 2 | `solct0014nn_1-6-8-25_23-24` |
| `dhcpv6.pcap` | 5 | `advrt0014nn_25-26-1-2_00` |
| `dhcpv6.pcap` | 7 | `reqst0014nn_1-2-6-8-25-26_23-24` |
| `dhcpv6.pcap` | 8 | `reply0014nn_25-26-1-2_00` |
| `dhcpv6.pcap` | 11 | `relse0014nn_1-2-6-8-25-26_23-24` |
| `dhcpv6.pcap` | 12 | `reply0014nn_1-2-13_00` |

The conformance suite reads only the top level of `tests/foxio_vectors/`. The two files
add no case to that suite and no entry to the deviation register.
`tests/test_ja4d_foxio.py` and `tests/test_ja4d6_foxio.py` compare them, and both run in
the unit suite. #109 closed the gap.

**Location:** `tests/test_ja4d_foxio.py` and `tests/test_ja4d6_foxio.py`.

### How ja4plus reads JA4D

The form is `{type}{size}{ip}{fqdn}_{options}_{parameters}`. `ja4plus` reads it as
follows. The comment at `ja4plus/fingerprinters/ja4d.py:42` names two FoxIO pull
requests, 267 and 270, as the source of the skip set. The four reference values of
`dhcp.pcapng` confirm the reading.

- The type is a five-character abbreviation of the DHCP message type. An unknown type
  gives the five-digit decimal value of the code.
- The size is the maximum message size of option 57, as four decimal digits. `ja4plus`
  caps it at 9999, and it writes `0000` when the option is absent.
- The `ip` character is `i` when option 50 is present, and `n` when it is absent.
- The `fqdn` character is `d` when option 81 is present, and `n` when it is absent.
- The option list holds the option codes in wire order. It drops 0, 50, 53 and 81. The
  end marker 255 stops the read and never reaches the list. An empty list gives `00`.
- The parameter list holds the contents of option 55 in wire order. An empty list gives
  `00`.

**Location:** `ja4plus/fingerprinters/ja4d.py:45` and `ja4plus/fingerprinters/ja4d.py:183`.

### How ja4plus reads JA4D6

The form matches JA4D, and five readings differ. The message type alone is unchanged.

- The size is the byte length of the DUID inside option 1, as four decimal digits.
  `ja4plus` caps it at 9999, and it writes `0000` when the option is absent.
- The `ip` character reads option 4, which is IA_TA. The `fqdn` character reads option
  39.
- The option list holds every option code in presence order, and it drops none. The list
  holds the codes nested inside IA_NA, IA_TA, IA_PD, IA Address and IA Prefix. The
  parameter list holds the contents of option 6.

**Location:** `ja4plus/fingerprinters/ja4d6.py:76` and `ja4plus/fingerprinters/ja4d6.py:202`.

---

## JA4L - Latency

### Output format includes prefix

JA4L fingerprints include a direction prefix:
`JA4L-S={latency_us}_{ttl}` and `JA4L-C={latency_us}_{ttl}`.
The spec describes `{latency_microseconds}_{ttl}` without a prefix.

### The latency is half the measured time

`technical_details/JA4L.png` states `One-way TCP latency in us`, and every FoxIO
vector holds half the time the capture shows. `badcurveball.pcap` stream 0 sends
the SYN at `+0.000000s` and the SYN-ACK at `+0.001563s`, and the reference
`JA4L-S` is `781_238`.

The division truncates toward zero, and it produces `0` for a difference of one
microsecond.

### The client measurement point

FoxIO publishes JA4L as an image, so the expected-output files decide the
measurement point. `python/ja4.py` in the FoxIO repository records the client
point on every TCP packet that carries the relative sequence number `1` and the
relative acknowledgement number `1`. It keeps the last one. That is the bare ACK
of the handshake first, and then the first packet of the application handshake.

`browsers-x509.pcapng` stream 0 proves it. The SYN-ACK is at `+0.003815s`, the
bare ACK at `+0.003927s` and the Client Hello at `+0.004371s`. The reference
`JA4L-C` is `278_128`, and `(4371 - 3815) / 2 = 278`.

The point moves in either direction. `http1-with-cookies.pcapng` stream 0 puts it
on the bare ACK the server sends.

### A complete HTTP request does not move the client point

The FoxIO program keeps the timestamps of a packet under the protocol the tshark
dissector reports. It holds a separate state table for `http` and for `http2`. A
packet that carries a whole HTTP request therefore never moves the client point. A
packet that carries the first part of a request does move it.

Two vectors prove both halves:

- `latest.pcapng` stream 6 sends one complete `GET` request. The reference
  `JA4L-C` is `32_128`, which is the bare ACK.
- `http-empty-useragent.pcap` sends the request line, the header and the blank
  line in three packets. The reference `JA4L-C` is `177863_64`, which is the
  request line.

`ja4plus` reads the request line and the blank line that ends the header block.

### The address layer of a tunneled capture

The reference reads the address and the TTL of the outer layer, and the port of
the inner layer. `gre-sample.pcap` carries a connection between `10.16.27.12`
and `10.16.27.131` inside a GRE tunnel between `172.27.1.66` and
`66.59.109.137`. The expected-output file names the tunnel addresses with the
inner ports.

`ja4plus/utils/tunnels.py` imports the scapy dissectors for Geneve, VXLAN and
ERSPAN, because scapy leaves them unbound and stops at the tunnel header.

### The QUIC measurement points

The reference reads four QUIC packets, and it reads the direction from port 443:

- `A` is the client Initial packet.
- `B` is the server Initial packet.
- `C` is the last server Handshake packet before the client answers.
- `D` is the first client Handshake packet.

`JA4L-S` is half the time from `A` to `B`, and `JA4L-C` is half the time from `C`
to `D`.

### A time of one second or more

The FoxIO program reads the difference of two timestamps as a `timedelta`, and it
takes the `microseconds` attribute, which holds the part below one second. A
handshake of 1.2 seconds therefore gives 100000, not 600000. No FoxIO vector
holds a difference of one second or more, so `ja4plus` divides the whole
difference and no vector separates the two readings.

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

### The SSH message, not the TCP segment

The reference counts the packets `tshark` labels `ssh`. `update_ssh_entry` reads
`has_ssh = ('ssh' in x['protos'])`, and `x['protos']` is the `frame.protocols`
field of `tshark -T ek`. `tshark` reassembles an SSH message that spans two TCP
segments. It labels the segment that completes the message, and it labels the
earlier segment `tcp`.

`tshark` 4.6.7 proves it on `ssh-r.pcap` stream 2:

```
$ tshark -r tests/foxio_vectors/ssh-r.pcap -Y "tcp.stream==2 && tcp.len>0" \
    -T fields -e frame.number -e tcp.srcport -e tcp.len -e frame.protocols \
    -e tcp.segment -e tcp.reassembled.length
395	46396	21	eth:ethertype:ip:tcp:ssh
397	22	21	eth:ethertype:ip:tcp:ssh
399	46396	1448	eth:ethertype:ip:tcp
400	46396	48	eth:ethertype:ip:tcp:ssh	399,400	1496
```

Frame 399 and frame 400 carry one KEXINIT message of 1496 bytes. The reference
counts one packet for frame 400 and none for frame 399, and it records the payload
length of frame 400 alone. `SSHMessageTracker` reproduces that boundary.

The boundary is readable only while the direction sends plaintext. The tracker
follows the four-byte length field of each message, and it counts every segment
after `SSH_MSG_NEWKEYS`, because an encrypted message carries no length a reader
can trust. A capture that starts after the version banner holds no boundary, so the
tracker counts every segment there too.

The same command counts the segments each vector holds outside a message end. Only
`ssh-r.pcap` holds one on a stream with an expected value: stream 1 holds one and
stream 2 holds one. `ssh.pcapng`, `ssh-scp-1050.pcap`, `ssh2.pcapng` and `ssh-r.pcap`
stream 0 hold none, and their values do not change.

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4ssh.py
(retrieved 2026-08-06).

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
