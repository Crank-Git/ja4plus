# Usage Guide

Detailed usage for each JA4+ fingerprinter.

## Table of Contents

- [JA4 - TLS Client](#ja4---tls-client)
- [JA4S - TLS Server](#ja4s---tls-server)
- [JA4H - HTTP](#ja4h---http)
- [JA4T - TCP Client](#ja4t---tcp-client)
- [JA4TS - TCP Server](#ja4ts---tcp-server)
- [JA4L - Latency](#ja4l---latency)
- [JA4X - X.509 Certificate](#ja4x---x509-certificate)
- [JA4SSH - SSH](#ja4ssh---ssh)
- [PCAP Analysis](#pcap-analysis)
- [Live Capture](#live-capture)

---

## JA4 - TLS Client

Fingerprints TLS clients from ClientHello messages. Identifies browsers, malware, and applications by their TLS negotiation behavior.

**Format:** `{proto}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{extension_hash}`

```python
from ja4plus import JA4Fingerprinter

fp = JA4Fingerprinter()
result = fp.process_packet(packet)
# Example: t13d1516h2_8daaf6152771_e5627efa2ab1
```

**Format breakdown:**
- `t` = TCP, `q` = QUIC (auto-detected from UDP/QUIC Initial), `d` = DTLS
- `13` = TLS 1.3 (from `supported_versions` extension)
- `d` = domain name present via SNI (`i` = IP / no SNI)
- `15` = 15 cipher suites (excluding GREASE, max 99)
- `16` = 16 extensions (excluding GREASE, max 99)
- `h2` = first and last character of first ALPN value (`00` if absent)
- First hash = SHA-256 of sorted cipher suites, truncated to 12 hex chars
- Second hash = SHA-256 of sorted extensions (excluding SNI/ALPN) + signature algorithms in original order

**Raw fingerprint** (unhashed, useful for debugging):

```python
fp = JA4Fingerprinter()
raw = fp.get_raw_fingerprint(packet)
# Shows the full sorted cipher/extension lists before hashing
```

---

## JA4S - TLS Server

Fingerprints TLS servers from ServerHello responses. The same client always produces the same server response from a given server.

**Format:** `{proto}{version}{ext_count}{alpn}_{cipher}_{extension_hash}`

```python
from ja4plus import JA4SFingerprinter

fp = JA4SFingerprinter()
result = fp.process_packet(packet)
# Example: t130200_1301_a56c5b993250
```

**Key differences from JA4:**
- Single cipher (server selects one)
- Extensions include GREASE values (per spec)
- No SNI or cipher count fields

---

## JA4H - HTTP

Fingerprints HTTP clients from request headers and cookies. Useful for identifying bots, browsers, and web scrapers.

**Format:** `{method}{version}{cookie}{referer}{header_count}{language}_{header_hash}_{cookie_name_hash}_{cookie_value_hash}`

```python
from ja4plus import JA4HFingerprinter

fp = JA4HFingerprinter()
result = fp.process_packet(packet)
# Example: ge11cr0800_edb4461d7a83_4817af47a558_2bc12b45e6f8
```

**Format breakdown:**
- `ge` = GET (first 2 chars of method, lowercase)
- `11` = HTTP/1.1 (`10` = 1.0, `20` = 2, `30` = 3)
- `c` = cookie present (`n` = no cookie)
- `r` = referer present (`n` = no referer)
- `08` = 8 headers (excluding Cookie and Referer, max 99)
- `0000` = Accept-Language value, zero-padded to 4 chars
- Header hash = sorted header names (excluding Cookie, Referer, pseudo-headers)
- Cookie name hash = sorted cookie field names
- Cookie value hash = sorted `name=value` cookie pairs

---

## JA4T - TCP Client

Fingerprints operating systems from TCP SYN packets. Identifies OS type and network conditions without any application-layer data.

**Format:** `{window_size}_{tcp_options}_{mss}_{window_scale}`

```python
from ja4plus import JA4TFingerprinter

fp = JA4TFingerprinter()
result = fp.process_packet(packet)
# Example: 65535_2-4-8-1-3_1460_7
```

**TCP option codes:** 2=MSS, 3=Window Scale, 4=SACK Permitted, 8=Timestamps, 1=NOP, 0=EOL

Options are listed in their **original packet order** (never sorted).

**Common OS patterns:**
- Linux: `29200_2-4-8-1-3_1460_7`
- Windows: typically omits option 8 (timestamps)
- macOS: includes option 0 (EOL padding)

**MSS values** can reveal VPN usage (MSS < 1460 indicates overhead).

---

## JA4TS - TCP Server

Fingerprints TCP servers from SYN-ACK responses. Response depends on the client SYN.

**Format:** `{window_size}_{tcp_options}_{mss}_{window_scale}_{synack_delays}`

```python
from ja4plus import JA4TSFingerprinter

fp = JA4TSFingerprinter()
result = fp.process_packet(packet)
# Example: 14600_2-4-8-1-3_1460_0
```

Part a through part d match JA4T, and the fingerprinter reads the server's SYN-ACK
packet.

**Part e holds the delay between each SYN-ACK of the connection, in whole seconds.** A
server retransmits a SYN-ACK when it receives no acknowledgement, and the delay pattern
identifies the TCP stack. The fingerprinter emits one value for each SYN-ACK, so the
value grows with each retransmission.

```python
# The server answered once. The fingerprint omits part e.
# 62727_2_8961_0
#
# The server retransmitted five times, at 1, 2, 4, 8 and 16 seconds.
# 62727_2_8961_0_1-2-4-8-16
```

**The fingerprint omits part e when the server answers once**, which is the normal case.
Part e is absent, and it is not `0`.

`JA4TSFingerprinter` holds one entry for each connection it tracks. Call
`cleanup_connection` when a connection ends, or `reset` to drop every entry. The
fingerprinter counts ten retransmissions for one connection, and it drops a connection
two minutes after the last SYN-ACK.

---

## JA4L - Latency

Measures network latency from TCP handshake timing. Estimates light distance between client and server.

The latency is one way, so it is half the time the capture shows. `JA4L-S` measures
the SYN to the SYN-ACK. `JA4L-C` measures the SYN-ACK to the last packet that starts
the payload of its sender and acknowledges no payload. That packet is the first one
of the application handshake, and it stays the bare ACK when the application sends a
whole HTTP request. `docs/implementation_notes.md` states the rule and names the
vectors that prove it.

**Format:** `JA4L-S={latency_microseconds}_{ttl}` and
`JA4L-C={latency_microseconds}_{ttl}`

```python
from ja4plus import JA4LFingerprinter

fp = JA4LFingerprinter()

# Must process the full TCP handshake (SYN, SYN-ACK, ACK)
for packet in handshake_packets:
    result = fp.process_packet(packet)
    if result:
        print(result)  # e.g., "JA4L-S=2500_56"
```

**TTL-based OS hints:**
- 255 = Cisco / networking devices
- 128 = Windows
- 64 = Linux / macOS / mobile

**Distance estimation:**

`calculate_distance` returns miles and `calculate_distance_km` returns kilometers. The
formula is `latency_us * 0.128 / propagation_factor` for miles, and it uses `0.206` for
kilometers.

Pass the observed TTL, and the method reads the propagation factor from the FoxIO
hop-count table:

| Hop count | Propagation factor |
|---|---|
| 21 or fewer | 1.5 |
| 22 | 1.6 |
| 23 | 1.7 |
| 24 | 1.8 |
| 25 | 1.9 |
| 26 or more | 2.0 |

A TTL above the initial TTL implies a negative hop count, which clamps to zero hops.

```python
# The TTL 44 implies 20 hops, so the factor is 1.5.
fp.calculate_distance(5191, ttl=44)

# An explicit factor overrides the table.
fp.calculate_distance(5191, propagation_factor=1.6)

# A call without a TTL gives no hop count, so the factor stays 1.6.
fp.calculate_distance(5191)
```

---

## JA4X - X.509 Certificate

Fingerprints certificate **structure** (OID sequences), not values. Two certificates with the same field types but different values produce the same fingerprint.

**Format:** `{issuer_hash}_{subject_hash}_{extension_hash}`

```python
from ja4plus import JA4XFingerprinter

fp = JA4XFingerprinter()

# From DER-encoded certificate bytes
result = fp.fingerprint_certificate(cert_der_bytes)
# Example: a37f49ba31e2_a37f49ba31e2_dd4f1a0ef8b2
```

**How it works:**
- Extracts OID dotted strings from issuer, subject, and extensions
- Converts OIDs to ASN.1 hex encoding
- Hashes each section with SHA-256, truncated to 12 hex chars
- Empty sections produce `000000000000`

**Self-signed certificates** have matching issuer and subject hashes.

Useful for detecting C2 frameworks (Cobalt Strike, Sliver) and programmatically generated certificates.

---

## JA4SSH - SSH

Classifies SSH session types from encrypted traffic patterns. Generates rolling fingerprints over configurable packet windows.

**Format:** `c{client_mode}s{server_mode}_c{client_pkts}s{server_pkts}_c{client_acks}s{server_acks}`

```python
from ja4plus import JA4SSHFingerprinter

fp = JA4SSHFingerprinter(packet_count=200)

for packet in packets:
    result = fp.process_packet(packet)
    if result:
        info = fp.interpret_fingerprint(result)
        print(f"{result} -> {info['session_type']}")
```

**Session type patterns:**
- `c36s36_...` = Interactive terminal session (36-byte padding)
- `c76s76_...` = Reverse SSH shell (double-padded)
- `c112s1460_...` = SCP file transfer (maxed window)

**HASSH support:**

```python
# After processing packets, retrieve HASSH fingerprints
hassh_fps = fp.get_hassh_fingerprints()
for h in hassh_fps:
    print(f"{h['type']}: {h['fingerprint']}")

# Look up known HASSH values
info = fp.lookup_hassh("b5752e36ba6c5979a575e43178908adf")
print(info["identified_as"])  # "Paramiko 2.4.1 (Metasploit)"
```

---

## QUIC Support

QUIC Initial packets (RFC 9001, RFC 9369) are automatically detected on UDP.
The library decrypts the Initial packet using DCID-derived keys, extracts
the CRYPTO frames containing the TLS ClientHello, and feeds it into the
standard JA4 fingerprinting pipeline.

**Supported:** QUIC v1 (`0x00000001`) and v2 (`0x6b3343cf`).

**Limitations:** Only client Initial packets. No retry or 0-RTT. No coalesced packet splitting.

```python
from scapy.all import rdpcap
from ja4plus import JA4Fingerprinter

fp = JA4Fingerprinter()
for packet in rdpcap("quic_capture.pcap"):
    result = fp.process_packet(packet)
    if result:
        print(result)  # QUIC: q13d1007h2_...
```

---

## PCAP Analysis

Analyze a PCAP file with all fingerprinters:

```python
from scapy.all import rdpcap
from ja4plus import (
    JA4Fingerprinter, JA4SFingerprinter, JA4HFingerprinter,
    JA4TFingerprinter, JA4TSFingerprinter, JA4LFingerprinter,
    JA4XFingerprinter, JA4SSHFingerprinter,
)

packets = rdpcap("capture.pcap")

fingerprinters = {
    "JA4": JA4Fingerprinter(),
    "JA4S": JA4SFingerprinter(),
    "JA4H": JA4HFingerprinter(),
    "JA4T": JA4TFingerprinter(),
    "JA4TS": JA4TSFingerprinter(),
    "JA4L": JA4LFingerprinter(),
    "JA4X": JA4XFingerprinter(),
    "JA4SSH": JA4SSHFingerprinter(),
}

for packet in packets:
    for name, fp in fingerprinters.items():
        result = fp.process_packet(packet)
        if result:
            print(f"{name}: {result}")
```

Or use the included example script:

```bash
python examples/pcap_analysis.py capture.pcap
```

---

## Live Capture

Fingerprint live traffic using scapy's `sniff`:

```python
from scapy.all import sniff
from ja4plus import JA4Fingerprinter, JA4TFingerprinter

ja4 = JA4Fingerprinter()
ja4t = JA4TFingerprinter()

def handle_packet(packet):
    result = ja4.process_packet(packet)
    if result:
        print(f"JA4: {result}")
    result = ja4t.process_packet(packet)
    if result:
        print(f"JA4T: {result}")

# Capture on port 443 (requires root/admin)
sniff(filter="tcp port 443", prn=handle_packet)
```

> Note: Live capture typically requires root privileges.
