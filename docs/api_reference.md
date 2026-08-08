# API Reference

## Fingerprinter Classes

All fingerprinters inherit from `BaseFingerprinter` and share a common interface.

### Common Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `process_packet(packet)` | `str` or `None` | Process a scapy packet. Returns fingerprint string if one is generated. |
| `get_fingerprints()` | `list[dict]` | Returns all collected fingerprints as `{"fingerprint": str, ...}` dicts. |
| `reset()` | `None` | Clears all collected fingerprints and internal state. |
| `close_open_windows()` | `list[dict]` | Emits the window every connection holds open, and returns the new entries. |

#### When to call `close_open_windows`

Call this method when the packet source ends. A file reader reaches the last packet, and
a live capture stops. JA4SSH is the only method that holds a window, so every other
fingerprinter returns an empty list.

A connection that sends no FIN+ACK packet holds its last window open, and no other rule
emits it. `ssh2.pcapng` carries 452 TCP packets on port 22 and no FIN+ACK packet, so this
method produces its second value, `c36s52_c42s76_c51s2`. #214 holds the decision.

A window that holds no SSH packet emits nothing. A fingerprint of an empty window
describes no traffic, and #97 declines the same value in the FoxIO Python reference.

The method emits the window and evicts no entry, so the state table holds the same keys
after the call. A second call emits nothing, because the first call cleared the counters.

```python
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter
from scapy.all import PcapReader

fp = JA4SSHFingerprinter()
with PcapReader("ssh2.pcapng") as reader:
    for packet in reader:
        fp.process_packet(packet)
trailing = fp.close_open_windows()   # [{"fingerprint": "c36s52_c42s76_c51s2", ...}]
```

`Processor.close_open_windows()` runs the same method on every fingerprinter it holds,
and it returns one result dict for each window. Each dict holds the keys `type`,
`fingerprint` and `connection`. It holds no packet endpoint, because no packet produces
the value.

#### The fields of one entry

Every entry holds the key `fingerprint`. An entry that one packet produced also holds
these four fields. A method adds its own keys beside them, such as `raw` on JA4.

| Field | Type | Description |
|--------|--------|-------------|
| `src` | `str` | The source address of the packet. |
| `dst` | `str` | The destination address of the packet. |
| `srcport` | `int` | The source port of the packet. |
| `dstport` | `int` | The destination port of the packet. |

A tunnelled packet reports the outer address layer and the innermost port layer,
because the reference reports one tunnelled connection that way.

No entry holds the packet object. A monitor runs for weeks, and a stored packet holds
every packet the monitor ever fingerprinted. A caller that needs the packet reads it
inside its own `process_packet` call.

JA4SSH reports a window of many packets rather than one packet, so its entry holds the
key `connection` instead of these four fields. JA4L holds both.

#### The fields of one JA4SSH entry

A JA4SSH fingerprint names a client packet size and a server packet size, so which
endpoint is the server changes the value. Every JA4SSH entry therefore carries
`server_decided_by`, and a consumer reads a measured endpoint and a guessed endpoint
differently.

| Value | What decided the server |
|--------|--------|
| `port` | One endpoint uses port 22. |
| `handshake` | The TCP handshake names the endpoints. The SYN sender is the client, and the SYN+ACK sender is the server. |
| `guess` | The capture holds no handshake and no endpoint on port 22, so the lower port decided. Two ephemeral ports carry no meaning, so treat the two endpoints as unproven. |

The first SSH banner decides nothing. RFC 4253 section 4.2 has both endpoints send an
identification string, and a client that does not wait sends first.

### JA4Fingerprinter

TLS Client Hello fingerprinting.

```python
from ja4plus import JA4Fingerprinter

fp = JA4Fingerprinter()
result = fp.process_packet(packet)        # Returns JA4 string or None
raw = fp.get_raw_fingerprint(packet)      # Returns unhashed fingerprint
```

### JA4SFingerprinter

TLS Server Hello fingerprinting.

```python
from ja4plus import JA4SFingerprinter

fp = JA4SFingerprinter()
result = fp.process_packet(packet)
```

### JA4HFingerprinter

HTTP request fingerprinting.

```python
from ja4plus import JA4HFingerprinter

fp = JA4HFingerprinter()
result = fp.process_packet(packet)
```

### JA4TFingerprinter

TCP client fingerprinting from SYN packets.

```python
from ja4plus import JA4TFingerprinter

fp = JA4TFingerprinter()
result = fp.process_packet(packet)
```

### JA4TSFingerprinter

TCP server fingerprinting from SYN-ACK packets.

```python
from ja4plus import JA4TSFingerprinter

fp = JA4TSFingerprinter()
result = fp.process_packet(packet)
```

The fingerprinter holds the SYN-ACK times of each connection, because part e reads the
delay between two SYN-ACK packets. It counts ten retransmissions for one connection, and
it drops a connection two minutes after the last SYN-ACK. Call `cleanup_connection` when
a connection ends, or `reset` to drop every entry.

### JA4LFingerprinter

Network latency estimation from TCP handshake timing.

```python
from ja4plus import JA4LFingerprinter

fp = JA4LFingerprinter()
result = fp.process_packet(packet)
```

### JA4XFingerprinter

X.509 certificate structure fingerprinting.

```python
from ja4plus import JA4XFingerprinter

fp = JA4XFingerprinter()
result = fp.fingerprint_certificate(der_bytes)  # From DER-encoded cert
result = fp.process_packet(packet)               # From TLS packet
details = fp.get_cert_details(x509_cert)         # Extract OID details
```

### JA4SSHFingerprinter

SSH session classification.

```python
from ja4plus import JA4SSHFingerprinter

fp = JA4SSHFingerprinter(packet_count=200)
result = fp.process_packet(packet)
info = fp.interpret_fingerprint(result)          # Session type analysis
hassh = fp.get_hassh_fingerprints()              # HASSH fingerprints
lookup = fp.lookup_hassh(hassh_value)            # Known HASSH lookup
```

## Convenience Functions

One-shot fingerprinting without maintaining state:

```python
from ja4plus import (
    generate_ja4,
    generate_ja4s,
    generate_ja4h,
    generate_ja4t,
    generate_ja4ts,
    generate_ja4l,
    generate_ja4x,
    generate_ja4ssh,
)

# Each takes a scapy packet and returns a fingerprint string or None
result = generate_ja4(packet)
```

| Function | Input | Description |
|----------|-------|-------------|
| `generate_ja4(packet)` | scapy packet | JA4 TLS client fingerprint |
| `generate_ja4s(packet)` | scapy packet | JA4S TLS server fingerprint |
| `generate_ja4h(packet)` | scapy packet | JA4H HTTP fingerprint |
| `generate_ja4t(packet)` | scapy packet | JA4T TCP client fingerprint |
| `generate_ja4ts(packet, tracker=None)` | scapy packet | JA4TS TCP server fingerprint. One packet names no retransmission, so a call with no tracker writes four parts. `JA4TSFingerprinter` passes its own tracker and writes part e. |
| `generate_ja4l(packet)` | scapy packet | JA4L latency fingerprint |
| `generate_ja4x(cert_info)` | dict | JA4X certificate fingerprint (takes cert_info dict) |
| `generate_ja4ssh(packet)` | scapy packet | JA4SSH session fingerprint |

## Utility Modules

### ja4plus.utils.tls_utils

| Function | Description |
|----------|-------------|
| `extract_tls_info(packet)` | Extract TLS handshake details from a packet |
| `is_grease_value(value)` | Check if a value is a GREASE value |
| `parse_client_hello(data)` | Parse raw ClientHello bytes |
| `parse_server_hello(data)` | Parse raw ServerHello bytes |

### ja4plus.utils.http_utils

| Function | Description |
|----------|-------------|
| `extract_http_info(packet)` | Extract HTTP request details from a packet |
| `is_http_request(data)` | Check if data is an HTTP request |
| `parse_http_request(data)` | Parse raw HTTP request bytes |

### ja4plus.utils.ssh_utils

| Function | Description |
|----------|-------------|
| `is_ssh_packet(data)` | Check if data is SSH traffic |
| `parse_ssh_packet(data)` | Parse SSH packet structure |
| `extract_hassh(data)` | Extract HASSH fingerprint from KEXINIT |

### ja4plus.utils.x509_utils

| Function | Description |
|----------|-------------|
| `oid_to_hex(oid_string)` | Convert OID dotted string to ASN.1 hex encoding |
| `get_cert_details(cert)` | Extract issuer/subject RDNs and extensions from an x509 certificate |
| `extract_certificate_from_bytes(data)` | Find DER certificates in raw TLS record bytes |
| `extract_certificate_info(packet)` | Extract certificate details from a scapy packet |

### ja4plus.utils.quic_utils

| Function | Description |
|----------|-------------|
| `parse_quic_initial(udp_payload)` | Parse QUIC Initial, return tls_info with `is_quic=True` or None |
| `derive_initial_secrets(dcid, version)` | Derive secrets from DCID (version 1 or 2) |
| `extract_crypto_frames(plaintext)` | Reassemble CRYPTO frames from decrypted payload |

### ja4plus.utils.tcp_stream

| Class/Function | Description |
|----------------|-------------|
| `TCPStreamReassembler(max_streams, max_stream_bytes, max_stream_segments, max_stream_age)` | Sequence-aware TCP stream reassembly |
| `.add_segment(key, seq, data, timestamp)` | Add a TCP segment. `timestamp` is the packet time in seconds, and it ages the stream |
| `.get_stream(key)` | Get reassembled contiguous bytes |
| `.remove_stream(key)` | Remove a tracked stream |

### ja4plus.utils.state_table

| Class/Function | Description |
|----------------|-------------|
| `BoundedStateTable(max_connections, max_connection_age, eviction_interval)` | A mapping that evicts on the entry count and on the entry age |
| `.on_packet(timestamp)` | Announce one packet. The table reads `timestamp` for every later operation, and it runs one age eviction pass for every `eviction_interval` packets |
| `.evict_aged(now)` | Run one age eviction pass, and return the count of entries it removed |
| `.evictions` | The count of entries the table itself removed. `pop`, `del` and `clear` raise none |

The table answers the dictionary operations a fingerprinter uses: `[]`, `[] =`, `del`,
`in`, `get`, `pop`, `setdefault`, `len`, `keys`, `values`, `items` and iteration.

A read of one key holds that entry against both bounds. A pass over the whole table
holds no entry, so `keys`, `values`, `items` and iteration change no eviction order.

Two operations read differently from the dictionary this table replaces. `dict(table)`
reads each key through `__getitem__`, so it holds every entry; call `items` for a pass
that holds none. `popitem` removes the least recently used entry, and a dictionary
removes the entry it received last.

Warning: state the packet timestamp on every packet of one capture, or on none of them.
One `on_packet()` call that states no timestamp moves the table to the wall clock, and a
replay of a capture recorded in the past then ages out whole.

The defaults are 10000 entries, 600 seconds and 1000 packets. `ssh-r.pcap` sets the age.
It holds the longest gap between two segments of one connection across
`tests/foxio_vectors/`, at 320.714503 seconds.

### ja4plus.utils.packet_utils

| Function | Description |
|----------|-------------|
| `get_ip_layer(packet)` | Return IP or IPv6 layer, or None |
| `get_ttl(packet)` | Return TTL (IPv4) or Hop Limit (IPv6), or None |
| `packet_seconds(packet)` | Return the capture timestamp in seconds, or None |

## CLI Module

### ja4plus.cli

Command-line interface for JA4+ fingerprinting. Installed as the `ja4plus` command.

```bash
ja4plus analyze <pcap_file>   # Fingerprint a PCAP file
ja4plus live <interface>      # Live capture (requires root)
ja4plus cert <cert_file>      # Fingerprint an X.509 certificate
```

| Option | Description |
|--------|-------------|
| `--format table\|json\|csv` | Output format (default: table) |
| `--types ja4,ja4s,...` | Filter to specific fingerprint types |
| `--lookup` | Identify fingerprints using bundled ja4db database |
| `--version` | Print version |

## Lookup Module

### ja4plus.ja4db

Fingerprint identification using FoxIO's ja4plus-mapping.csv database.

```python
from ja4plus.ja4db import JA4DBClient, lookup

# Module-level convenience function
result = lookup("t13d1516h2_8daaf6152771_02713d6af862")
# {"application": "Chromium Browser", "type": "ja4", "notes": ""}

# Or use the client for caching across multiple lookups
client = JA4DBClient()
result = client.lookup(fingerprint_string)
```

| Class/Function | Description |
|----------------|-------------|
| `JA4DBClient()` | Client with local cache and bundled database |
| `JA4DBClient.lookup(fingerprint)` | Look up a fingerprint, returns dict or None |
| `lookup(fingerprint)` | Module-level convenience using a shared client |
