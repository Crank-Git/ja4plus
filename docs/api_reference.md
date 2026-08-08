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

## Processor

### ja4plus.processor

| Class/Function | Description |
|----------------|-------------|
| `Processor(thread_safe=True)` | Build one processor and the ten fingerprinters it drives |
| `.process_packet(packet)` | Run every fingerprinter on one packet, and return a list of result dicts |
| `.close_open_windows()` | Emit every window the fingerprinters hold open |
| `.get_shard_key(packet)` | Return one stable key for the connection of a packet |
| `.cleanup_connection(src_ip, src_port, dst_ip, dst_port, proto)` | Drop the state of one connection across every fingerprinter |
| `.reset()` | Reset every fingerprinter, and return every count to zero |
| `.stats()` | Return one `ProcessorStats` for each of the ten methods |
| `.thread_safe` | The value the constructor read |

`stats()` reports what the state tables hold, and #41 built it. One processor holds
**fifteen** state tables across the ten methods: the thirteen `BoundedStateTable`
instances and the two `TCPStreamReassembler` instances of JA4H and JA4X. A method that
holds no state reports an empty `tables` list.

| Field of `ProcessorStats` | Description |
|----------------|-------------|
| `method` | The method name, such as `ja4l` |
| `packets` | The count of packets the processor gave this method |
| `entries` | The count of entries every state table of this method holds |
| `evictions` | The count of entries those tables evicted |
| `returned_connections` | The count of returned connections those tables saw |
| `tables` | The name of each state table this method holds |

A **returned connection** is one connection that a state table evicted and then saw
again. Its new entry holds none of the packets that came before the eviction, so its
fingerprint may be incomplete. A key the caller removed through `cleanup_connection`,
`del`, `pop` or `clear` leaves no memory, so a connection that returns after that counts
as a first sighting.

`stats()` holds the lock of one fingerprinter at a time and never two, so it deadlocks
against neither the locks of the fingerprinters nor the module lock of `ja4plus.ja4db`.

#### The concurrency contract of the processor

Several threads may call `process_packet` on one `Processor()`. Each fingerprinter holds
one `threading.RLock` of its own, so ten threads work at once on ten methods rather than
waiting on one lock. The lock is reentrant, because `Processor.process_packet` holds the
lock of a fingerprinter and then calls a method that holds it again.

The contract is narrower than "thread safe", and it has three clauses.

1. Give each thread whole connections. `get_shard_key` sorts the 5-tuple, so both
   directions of one connection return one key, and a caller routes on that key. Eight
   threads arranged this way read the value set one thread reads.
2. A caller that splits the packets of one connection across threads gets undefined
   results. The state of that connection then advances out of capture order, and no lock
   restores the order.
3. Feed one processor the packets of one timeline. Every state table evicts an entry that
   receives no packet for its maximum age, and the pass reads the timestamp of the most
   recent packet. Two packet sources whose clocks sit far apart therefore age out state
   that the later source still needs.

Warning: `thread_safe=False` is a promise the caller makes, not a mode the library
checks. `Processor(thread_safe=False)` gives every fingerprinter the shared `NULL_LOCK`
and acquires nothing. A caller that runs one processor for each shard pays no lock, and a
caller that breaks the promise gets undefined results and no error.

Clause 1 holds whether the lock is present or absent, because a thread that owns whole
connections touches keys no other thread touches. The lock guards the caller who shares
one processor without that arrangement, and it guards a `reset` that runs beside a packet.

#### The memory bound of the processor

One processor holds fifteen state tables: thirteen `BoundedStateTable` instances and two
`TCPStreamReassembler` instances. `features/03-concurrency-safety.md` states the maximum
entry count and the maximum age of each one. A table that reaches its maximum entry count
evicts the least recently used entry. A long capture can therefore evict a connection
that later returns, and the fingerprint of a returned connection may be incomplete.
Eviction runs on packet arrival, and the library starts no thread.

`BaseFingerprinter.fingerprints` holds one result for each fingerprint rather than
per-connection data, and it holds no bound. A caller that runs for a long time reads
`get_fingerprints()` and calls `reset()`. A caller can instead read the return value of
`process_packet` and never let the list grow.
`JA4SSHFingerprinter.hassh_fingerprints` holds no bound either.

This package states no memory ceiling.

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

## Processor Statistics

`Processor.stats()` returns a dict that maps each of the ten method names to one
`ProcessorStats`. FR-concurrency-safety-11 and FR-concurrency-safety-12 state the
requirement, and #41 built it.

```python
from ja4plus.processor import Processor
from scapy.all import PcapReader

processor = Processor()
with PcapReader("latest.pcapng") as reader:
    for packet in reader:
        processor.process_packet(packet)

report = processor.stats()
print(report["ja4l"].packets)                        # 209
print(report["ja4l"].entries)                        # the entries of both JA4L tables
print(report["ja4l"].tables["connections"].evictions)
```

| Field of `ProcessorStats` | Description |
|---|---|
| `.method` | The method name, such as `ja4h` |
| `.packets` | The count of packets the processor gave this method. A packet the method ignores counts too |
| `.tables` | A dict that maps the state table name to its `TableStats` |
| `.entries` | The sum of the entry counts of the tables |
| `.evictions` | The sum of the eviction counts of the tables |
| `.returned_connections` | The sum of the counts of connections that returned after an eviction |

| Field of `TableStats` | Description |
|---|---|
| `.entries` | The count of entries the table holds now |
| `.max_entries` | The maximum entry count of the table |
| `.inserts` | The count of keys the table ever added |
| `.evictions` | The count of entries the table itself removed, on either bound |
| `.removals` | The count of entries the caller removed |
| `.returned_connections` | The count of connections the table evicted and then saw again |

The six counts hold the invariant `inserts == entries + evictions + removals`. A reader
who sees it broken read the table while another thread wrote it.

A returned connection matters to an operator. Its new entry holds none of the packets
that came before the eviction, so its fingerprint may be incomplete. A count above zero
states that the bounds of the table are too small for the traffic. A connection the
caller removed with `cleanup_connection` counts as a first sighting when it returns,
because the caller asked for that removal.

A table remembers the keys it evicted, so that it can recognise a return. The memory
holds the entry bound of its own table. The fifteen tables of one processor hold 46400
remembered keys between them, at 187 bytes for one key, so the memory costs 8.3 MiB
when every table is full and every entry of every table has been replaced.

Ten methods hold fifteen state tables between them. `JA4TFingerprinter`,
`JA4DFingerprinter` and `JA4D6Fingerprinter` hold none, and each reports an empty
`tables` dict.

`stats()` holds the lock of one fingerprinter across the read of that fingerprinter, so
the counts of one method describe one instant. The report describes ten instants and not
one. If you need one instant across the ten methods, stop the packet source first.

`Processor.reset()` returns every packet count to zero, because a reset drops the state
tables that the counts describe.

`ProcessorStats` is a plain object. Epic 4 makes it a typed dataclass.

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
| `.remove_stream(key)` | Remove a tracked stream. The removal belongs to the caller, so it evicts nothing |
| `.stats()` | Return the `TableStats` of the reassembler |

The reassembler holds per-connection data across packets, so it is a state table. It
inherits `StateTable` and reports the six counts every state table reports.

### ja4plus.utils.state_table

| Class/Function | Description |
|----------------|-------------|
| `BoundedStateTable(max_connections, max_connection_age, eviction_interval)` | A mapping that evicts on the entry count and on the entry age |
| `.on_packet(timestamp)` | Announce one packet. The table reads `timestamp` for every later operation, and it runs one age eviction pass for every `eviction_interval` packets |
| `.evict_aged(now)` | Run one age eviction pass, and return the count of entries it removed |
| `.evictions` | The count of entries the table itself removed. `pop`, `del` and `clear` raise none |
| `.stats()` | Return the `TableStats` of the table |
| `StateTable` | The base class every state table inherits. It holds the six counts and the memory of the evicted keys |
| `TableStats` | The counts one state table reports: `entries`, `max_entries`, `inserts`, `evictions`, `removals` and `returned_connections` |

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
| `JA4DBClient(cache_size=100000)` | Client with a bounded lookup cache and the bundled database |
| `JA4DBClient.lookup(fingerprint)` | Look up a fingerprint, returns dict or None |
| `lookup(fingerprint)` | Module-level convenience using a shared client |

#### The concurrency contract of the lookup client

The first caller of `lookup` builds the module-level client. Two threads that call
`lookup` at the same time receive results from one client. Several threads may share
one `JA4DBClient`, and the client holds a lock over the lookup cache read and over the
lookup cache write.

#### The bound of the lookup cache

The lookup cache holds a hit and it holds a miss, so a repeated miss costs one read.
It holds no more than `cache_size` entries, and it evicts the least recently used
entry at that count. It also evicts an entry that receives no read for 600 seconds.
An age pass reads every entry, so the pass runs once for every `cache_size` lookups,
and once for every 100000 lookups at most.

A caller that shares one client between threads therefore receives a result the client
looked up before, or a result the client looks up now. An entry that leaves the lookup
cache costs the next caller one more lookup, and it changes no result.

The client reads the mapping file once, at construction. A caller that replaces the
mapping file builds a new client, and the new client holds an empty lookup cache.
