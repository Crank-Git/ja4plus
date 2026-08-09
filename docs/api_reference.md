# API Reference

## Public interface

`ja4plus.__all__` names the interface the project promises. Version 1.0.0 promises that
a name in that list stays until version 2.0.0. A name absent from the list is not
promised, and the project may change it in any release.

```python
import ja4plus

ja4plus.__all__   # the 25 promised names
```

| Group | Names |
|---|---|
| Result and processor | `FingerprintResult`, `Processor` |
| Fingerprinter classes | `JA4Fingerprinter`, `JA4SFingerprinter`, `JA4HFingerprinter`, `JA4LFingerprinter`, `JA4XFingerprinter`, `JA4SSHFingerprinter`, `JA4TFingerprinter`, `JA4TSFingerprinter`, `JA4DFingerprinter`, `JA4D6Fingerprinter` |
| One-shot functions | `generate_ja4`, `generate_ja4s`, `generate_ja4h`, `generate_ja4l`, `generate_ja4x`, `generate_ja4ssh`, `generate_ja4t`, `generate_ja4ts`, `generate_ja4d`, `generate_ja4d6` |
| Certificate helpers | `compute_ja4x_from_der`, `compute_ja4x_from_pem` |
| Version | `__version__` |

A module states its own public names in its own `__all__`. `ja4plus.types` names
`FingerprintResult`, and `ja4plus.processor` names `Processor` and `ProcessorStats`.
`Processor.stats` returns `dict[str, ProcessorStats]`, so a caller who annotates the
report imports the class from `ja4plus.processor`.

Four names of the top-level namespace are not promised. `bind_loopback_ipv6` and
`register_tunnel_dissectors` are the two calls the package makes at import time, so a
caller needs neither name. `__author__` and `__license__` describe the project and not
the interface, and the distribution metadata carries the license.

### Type checking

The package ships a `py.typed` marker, and the wheel carries it. A caller who runs
`mypy --strict` against their own code therefore resolves the annotations of `ja4plus`.

```python
from ja4plus import FingerprintResult

result = FingerprintResult(type="ja4", fingerprint="t13d1516h2_8daaf6152771_b0da82dd1658")
name: str = result.fingerprint   # mypy reads `str`
```

Verified against: https://peps.python.org/pep-0561/ (retrieved 2026-08-08).

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

One connection produces one value, from its first SYN. The fingerprinter holds a
connection table that carries 10000 entries at most and evicts an entry after 600
seconds. Call `cleanup_connection` when a connection ends, or `reset` to drop every
entry. #215 records the decision.

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

The fingerprinter also reads the RST packet that the server sends. A RST on a connection
that already holds a delay appends `R` and its own delay to part e, and the value reads
part a through part d from the first SYN-ACK of the connection. A RST on a connection
with no delay produces no value, and a client RST produces no value.

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
value, raw = fp.read_certificate(der_bytes)     # The value and the JA4X_r raw form
result = fp.process_packet(packet)               # From TLS packet
details = fp.get_cert_details(x509_cert)         # Extract OID details
```

A JA4X entry holds the `raw` key, which carries the `JA4X_r` value. It holds the three
unhashed lists of the fingerprint, joined with `_`. JA4X sorts no list, so
`raw_original_order` holds the same value. #267 decided the form, and
`docs/implementation_notes.md` holds the reading.

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

## Result type

### ja4plus.types

`FingerprintResult` is the typed result of the public interface. It is a frozen
dataclass, because a result describes something that already happened.

| Field | Type | Constraint |
|---|---|---|
| `type` | `str` | One of the ten method names, lowercase. |
| `fingerprint` | `str` | The fingerprint string. Never empty. |
| `raw` | `str \| None` | The raw form, when the method defines one. |
| `raw_original_order` | `str \| None` | The original-order raw form, when the method defines one. |
| `src_ip` | `str` | The source address. Empty when the packet carries no address. |
| `src_port` | `int` | The source port. Zero when the packet carries no port. |
| `dst_ip` | `str` | The destination address. |
| `dst_port` | `int` | The destination port. |
| `timestamp` | `datetime \| None` | The packet timestamp, or `None` when the packet carries none. |

The field names are the snake-case form of the `FingerprintResult` struct of the Go
port, under parity rule 2. The field that names the method is `type`, not `method`.

```python
from ja4plus import FingerprintResult

result = FingerprintResult(type="ja4", fingerprint="t13d1516h2_8daaf6152771_b0da82dd1658")
result.type          # "ja4"
result.fingerprint   # "t13d1516h2_8daaf6152771_b0da82dd1658"
result.timestamp     # None
```

#### The deprecated item access

Version 0.6.0 returned a dictionary. A result reads by field name too, so that code
written against the dictionary keeps working for one major version.

Warning: item access emits a `DeprecationWarning`. Read the attribute instead.

```python
result["fingerprint"]   # the same value, and one DeprecationWarning
result["method"]        # KeyError. The field is `type`.
```

The item access covers reading only. `result["fingerprint"] = "x"` raises `TypeError`,
and `result.fingerprint = "x"` raises `dataclasses.FrozenInstanceError`.

`Processor.process_packet` returns a list of `FingerprintResult`, and #45 changed it.
`Processor.close_open_windows` still returns a list of dictionaries, because a window
carries a connection key and no `FingerprintResult` field holds one.

## Processor

### ja4plus.processor

| Class/Function | Description |
|----------------|-------------|
| `Processor(thread_safe=True)` | Build one processor and the ten fingerprinters it drives |
| `.process_packet(packet)` | Run every fingerprinter on one packet, and return a list of `FingerprintResult` |
| `.process_packet_with_errors(packet)` | Return the same list, and the errors the fingerprinters raised |
| `.process_packet_with_method_errors(packet)` | Return the same list, and each error with the name of the method that raised it |
| `.close_open_windows()` | Emit every window the fingerprinters hold open |
| `.get_shard_key(packet)` | Return one stable key for the connection of a packet |
| `.cleanup_connection(src_ip, src_port, dst_ip, dst_port, proto)` | Drop the state of one connection across every fingerprinter |
| `.reset()` | Reset every fingerprinter, and return every count to zero |
| `.stats()` | Return one `ProcessorStats` for each of the ten methods |
| `.thread_safe` | The value the constructor read |

#### How to read the parse failures

`process_packet` returns the results alone. A fingerprinter that raises produces no
result, and the processor logs the error at DEBUG. One method that raises poisons no
other method.

`process_packet_with_errors` returns the results and the errors together. Call it to
tell a packet that produces no fingerprint from a packet that failed a parse.
FR-typed-api-4 states the requirement.

```python
results, errors = processor.process_packet_with_errors(packet)
for error in errors:
    print(f"one method failed to read the packet: {error!r}")
```

The results follow the fixed method order `ja4`, `ja4s`, `ja4h`, `ja4t`, `ja4ts`,
`ja4l`, `ja4x`, `ja4ssh`, `ja4d`, `ja4d6`. The order is part of the interface. The
errors follow the same order.

An exception names no method, so a caller that reports an error to a person calls
`process_packet_with_method_errors` instead. It returns the same results, and one pair
of the method name and the exception for each method that raised. #51 added it, and the
command-line program reads it.

```python
results, errors = processor.process_packet_with_method_errors(packet)
for method, error in errors:
    print(f"{method} could not read the packet: {error}")
```

Warning: every returned exception carries no traceback. A traceback holds the frame of
every call it passed, and those frames hold the packet. A monitor that keeps the errors
of every packet would therefore hold every packet it read. `CLAUDE.md` states that no
code holds a reference to a packet object after `process_packet` returns. The type, the
message and the error chain stay, so `repr(error)` reads the same. If the stack matters,
log the error inside the loop that reads it.

`process_packet_with_errors` sets no `timestamp` on a result, because the processor
reads no packet timestamp. The field holds `None`.

`stats()` reports what the state tables hold, and #41 built it. One processor holds
**seventeen** state tables across the ten methods: the fifteen `BoundedStateTable`
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

One processor holds seventeen state tables: fifteen `BoundedStateTable` instances and
two `TCPStreamReassembler` instances. `features/03-concurrency-safety.md` states the maximum
entry count and the maximum age of each one. A table that reaches its maximum entry count
evicts the least recently used entry. A long capture can therefore evict a connection
that later returns, and the fingerprint of a returned connection may be incomplete.
Eviction runs on packet arrival, and the library starts no thread.

`BaseFingerprinter.fingerprints` holds one result for each fingerprint rather than
per-connection data, and it holds no bound. A caller that runs for a long time reads
`get_fingerprints()` and calls `reset()`. A caller can instead read the return value of
`process_packet` and never let the list grow.
`JA4SSHFingerprinter.hassh_fingerprints` holds no bound either.

This package states a memory ceiling of 512 MiB. One `Processor()` at the shipped
defaults reads 1000000 packets across 100000 distinct connections and holds resident
memory below that number, and #279 measured 394.94 MiB at the highest of four runs.
`features/03-concurrency-safety.md` states the defaults the ceiling holds at and the
traffic the case feeds. **The ceiling covers that packet run and no longer run**, because
of the two unbounded lists the paragraph above names. The same traffic passes 512 MiB at
1500000 packets, where it reads 513.06 MiB.

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
| `generate_ja4ts(packet, tracker=None)` | scapy packet | JA4TS TCP server fingerprint. One packet names no retransmission, so a call with no tracker writes four parts. `JA4TSFingerprinter` passes its own tracker and writes part e. A RST that the server sends on a connection that already holds a delay appends `R` and its own delay to part e, and that value reads part a through part d from the tracker. A call with no tracker reads no RST. |
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
holds the entry bound of its own table. The seventeen tables of one processor hold 57400
remembered keys between them, at 187 bytes for one key, so the memory costs 10.2 MiB
when every table is full and every entry of every table has been replaced.

Ten methods hold seventeen state tables between them. `JA4DFingerprinter` and
`JA4D6Fingerprinter` hold none, and each reports an empty `tables` dict.

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
| `BoundedStateTable(max_connections, max_connection_age, eviction_interval, on_eviction)` | A mapping that evicts on the entry count and on the entry age |
| `.on_packet(timestamp)` | Announce one packet. The table reads `timestamp` for every later operation, and it runs one age eviction pass for every `eviction_interval` packets |
| `.evict_aged(now)` | Run one age eviction pass, and return the count of entries it removed |
| `.evict_key(key)` | Remove one entry, count it as an eviction, and call `on_eviction`. Return False when the table holds no such key |
| `.on_eviction` | A callable the table calls with the key of every entry it evicts. A caller removal calls nothing. #285 added it, so that a second table holding the same keys stays in lockstep |
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
ja4plus watch <interface>     # Read an interface (needs the capture privilege)
ja4plus live <interface>      # An alias of watch
ja4plus cert <cert_file>      # Fingerprint an X.509 certificate
ja4plus db update             # Download the mapping file to the cache directory
ja4plus db info               # Report the mapping file the client reads
```

| Option | Description |
|--------|-------------|
| `--format table\|json\|csv` | Output format (default: table) |
| `--types ja4,ja4s,...` | Filter to specific fingerprint types |
| `--lookup` | Identify fingerprints from the bundled database. It makes no network request |
| `--lookup-remote` | Identify fingerprints, and send each one the bundled database holds no entry for to `https://ja4db.com` |
| `--output FILE` | Write the results to FILE instead of standard output |
| `--force` | Overwrite the file that `--output` names when it exists |
| `--version` | Print version |

The `watch` command carries four more options. The first two bound the connection table
it owns.

| Option | Description |
|--------|-------------|
| `--max-connections COUNT` | Maximum number of tracked connections (default: 10000) |
| `--connection-timeout SECONDS` | Maximum age of a connection that sends no packet (default: 300) |
| `--stats-interval SECONDS` | Write a statistics line every SECONDS seconds (default: no schedule) |
| `--bpf FILTER` | Capture filter, in Berkeley Packet Filter syntax (default: no filter) |

The command reads no user identity. It attempts the capture and reads the failure, so a
Linux host that grants `CAP_NET_RAW` without the user identity zero runs the monitor.
The command names the privilege, lists the interfaces of the host, or reports the filter
error, and it ends the run with the status 1.

### ja4plus.watch

The monitor loop and the connection table of `ja4plus watch`.

The command owns the connection table. It records the connection of every packet it
reads, and it evicts a connection on two bounds.

- The count bound removes the least recently used connection as soon as the table
  reaches `--max-connections`.
- The age bound removes every connection that sends no packet for
  `--connection-timeout` seconds of capture time.

Each eviction calls `Processor.cleanup_connection`, so it drops the entry of the
connection table and the per-connection state of all ten methods together. Version 0.6.0
called `cleanup_connection` never, and its monitor grew until the host stopped it.

Eviction runs on packet arrival. The statistics thread is the only thread the module
starts, and `report_statistics` starts it only when the caller states an interval.

| Class/Function | Description |
|----------------|-------------|
| `Monitor(processor, report, ...)` | The monitor loop, without the packet source |
| `Monitor.stats` | The counts the statistics line reports |
| `Monitor.handle_packet(packet)` | Record the connection of one packet, evict, and report the packet |
| `Monitor.tracked_connections()` | Return the key of every connection the table holds |
| `Monitor.evictions` | The count of connections the monitor evicted |
| `connection_key(packet)` | Return the key of the connection the packet belongs to, or None |
| `read_interface(interface, handle_packet, stop_filter, capture_filter, stop_requested, poll_interval, open_socket)` | Read packets from one interface until the capture stops |
| `open_capture_socket(interface, capture_filter)` | Return an open capture socket for one interface |
| `DEFAULT_POLL_INTERVAL` | The count of seconds one `sniff` call reads before the loop reads the stop request |
| `CAPTURE_FAILURES` | The exception classes the capture layer raises when it refuses an interface |
| `available_interfaces()` | Return the name of every interface the host holds |
| `describe_capture_failure(error, ...)` | Return the message the operator reads for one capture failure |
| `unsupported_platform_message(platform, command)` | Return the reason the platform runs no monitor, or None |
| `StopRequest` | The flag a termination signal sets and the capture reads |
| `StopRequest.requested()` | Return True after a termination signal arrived |
| `StopRequest.stop_after(packet)` | Return True when the capture stops after this packet |
| `stop_on_signal(signal_numbers)` | Yield the stop request, with a handler installed for each signal |
| `MonitorStats(clock, dropped_source)` | The counts of one monitor, and the lock that guards them |
| `MonitorStats.count_fingerprints(count)` | Add the fingerprints of one packet to the fingerprint count |
| `MonitorStats.record_packet(connections, evicted)` | Count one packet, and publish the two table counts |
| `MonitorStats.snapshot()` | Return the counts of one instant |
| `StatisticsSnapshot` | The counts one statistics line reports |
| `format_statistics(snapshot)` | Return the statistics line of one snapshot |
| `write_statistics(stats, stream)` | Write one statistics line, and flush the stream |
| `StatisticsReporter(stats, interval, stream)` | The thread that writes a statistics line on a schedule |
| `report_statistics(stats, interval, stream)` | Yield the reporter, and stop it when the body returns |

The capture thread writes the counts and the statistics thread reads them. Every write
and every read holds one lock, so a reader reads the counts of one instant. The capture
thread publishes the two table counts through `record_packet`, so the statistics thread
reads `MonitorStats` and never the connection table.

The `dropped` field reports the count a `dropped_source` returns, and `null` where the
caller passes none. `ja4plus watch` passes none, because `scapy` 2.7.0 reports no drop
count to a caller of `sniff`. Issue #326 records the measurement.

`SIGINT` and `SIGTERM` both stop the monitor, and both end the run with the status zero.
The handler sets the stop request and returns. It calls `sys.exit` never, because a
signal arrives at any point, including the point where the output holds half a line.
`scapy` reads the stop request through the `stop_filter` argument of `sniff`, and it
applies that filter after it reports a packet. The monitor therefore finishes the line it
writes, and the command flushes the output before it exits.

`scapy` applies `stop_filter` to a packet and to nothing else, so an interface that
carries no traffic reaches that filter never. `read_interface` therefore opens the
capture socket itself and calls `sniff` with `opened_socket` and a timeout of
`DEFAULT_POLL_INTERVAL` seconds, in a loop. It reads `stop_requested` after each call, so
a monitor on a quiet interface stops within one second of the signal. The socket stays
open across the calls, because `AsyncSniffer._run` closes the sockets it opened itself
and no other socket; a loop that reopened the socket would lose every packet the host
buffered between two calls. Issue #320 records the whole reading.

`describe_capture_failure` reads the failure the capture layer reported and returns one
message. It calls no capture function, so it classifies the failure of any capture layer
that raises one of `CAPTURE_FAILURES`. It reads the privilege first, because a host that
refuses the privilege refuses it before it reads the interface name or the filter.

## Lookup Module

### ja4plus.ja4db

Fingerprint identification using FoxIO's ja4plus-mapping.csv database.

```python
from ja4plus.ja4db import JA4DBClient, lookup

# Module-level convenience function
result = lookup("t13d1516h2_8daaf6152771_02713d6af862")
# LookupResult(application="Chromium Browser", type="ja4", notes="", source="embedded")

# Or use the client for caching across multiple lookups
client = JA4DBClient()
result = client.lookup(fingerprint_string)

# One call for many fingerprints
results = client.lookup_many([fingerprint_string, another_fingerprint])
```

| Class/Function | Description |
|----------------|-------------|
| `JA4DBClient(allow_remote=False, cache_size=100000)` | Client with a bounded lookup cache and the bundled database |
| `JA4DBClient.lookup(fingerprint)` | Look up a fingerprint, returns a `LookupResult` or None |
| `JA4DBClient.lookup_many(fingerprints)` | Look up a sequence, returns one entry per fingerprint |
| `lookup(fingerprint)` | Module-level convenience using a shared client |
| `LookupResult` | The frozen result: `application`, `type`, `notes` and `source` |

#### The result records the source it came from

`LookupResult` is a frozen dataclass. It carries the three fields that `LookupResult` of
`lookup.go:23` carries, plus `source`, FR-db-enrichment-8. An analyst needs to know where
a name came from to judge how much to trust it.

| Field | What it holds |
|---|---|
| `application` | The name the mapping file or the lookup service gives |
| `type` | The fingerprint method the entry names, such as `ja4` |
| `notes` | The note the entry carries, or an empty string |
| `source` | `embedded`, `cache` or `remote` |

The value `embedded` names the mapping file that ships inside the package, `cache` names
the file that `ja4plus db update` wrote to the cache directory, and `remote` names the
lookup service. The port publishes the first two at `lookup.go:31`, and `CLAUDE.md`
parity rule 2 adopts them.

Version 0.6.0 returned a dict from `lookup`. Version 1.0.0 returns the frozen result, so
a caller reads `result.application` where it read `result["application"]` before.

#### The deprecated item access

A result reads by field name too, so that code written against the dict of version 0.6.0
keeps working for one major version, FR-db-enrichment-16. Version 0.6.0 published the
three keys `application`, `type` and `notes`, and each one names a field, so no key of
version 0.6.0 returns the value of another field.

Warning: item access emits a `DeprecationWarning`, FR-db-enrichment-17. Read the
attribute instead.

```python
result["application"]   # the same value, and one DeprecationWarning
result["method"]        # KeyError. `LookupResult` holds no field of that name.
```

The item access covers reading only. `result["application"] = "x"` raises `TypeError`,
and `result.application = "x"` raises `dataclasses.FrozenInstanceError`.

#### One call identifies many fingerprints

`lookup_many` accepts a sequence of fingerprints and returns one entry per fingerprint,
FR-db-enrichment-7. A miss holds None, so a caller reads one entry for every fingerprint
it passed. The returned mapping keys the fingerprint, so a sequence that repeats a
fingerprint holds one entry for it.

```python
results = client.lookup_many(["t13d1516h2_8daaf6152771_02713d6af862", "t99z9999h0_0_0"])
# {"t13d1516h2_8daaf6152771_02713d6af862": LookupResult(...), "t99z9999h0_0_0": None}
```

`lookup_many` reaches the lookup service under the rule that `lookup` holds, and under no
other rule. A client that the operator built with `allow_remote=False` sends nothing,
whatever count of fingerprints the call carries. A client that the operator built with
`allow_remote=True` sends one request for each fingerprint the mapping file holds no entry
for. The lookup cache holds a miss as well as a hit, so a repeated fingerprint costs one
request and no more.

#### The remote lookup is opt-in

A fingerprint describes traffic the operator observed. A request to the lookup service
`ja4db.com` discloses that traffic to a third party. The client therefore reads the
bundled mapping file and performs no network request by default, FR-db-enrichment-1. The
module-level `lookup` function holds the same default.

`JA4DBClient(allow_remote=True)` permits one request for each fingerprint the mapping
file holds no entry for, FR-db-enrichment-2. The request goes to
`https://ja4db.com/api/read/<fingerprint>`, and it waits 5 seconds at most,
FR-db-enrichment-14. Version 1.0.0 is the first release that may make the interval
configurable.

`allow_remote` takes True or False, and the constructor raises `TypeError` for every
other value. `cache_size` was the first parameter before #57, so `JA4DBClient(100)` asked
for a lookup cache of 100 entries. That call now reads as a request for the remote
lookup, and the client refuses it. Write `JA4DBClient(cache_size=100)` instead.

The request needs the `requests` package, which the `lookup` extra installs. A client
that reaches no service returns None for the miss, and it raises nothing,
FR-db-enrichment-15. The same holds for a request that times out, for a status other
than 200, and for a package that is absent.

The lookup service publishes no versioned API document. The client therefore accepts one
shape: an object that carries a non-empty `application` string. It reads `type` and
`notes` as strings, and it substitutes an empty string for a field of another type. It
returns None for every other shape, so no unchecked value reaches a caller.

#### The command asks for the remote lookup with an option or a variable

`--lookup` identifies each fingerprint from the bundled mapping file, and it makes no
network request, FR-db-enrichment-3.

`--lookup-remote` identifies each fingerprint, and it sends every fingerprint the mapping
file holds no entry for to the lookup service, FR-db-enrichment-4. It asks for the lookup
as well as for the disclosure, so an operator who passes it needs no `--lookup`.

`JA4PLUS_DB_LOOKUP=1` permits the same disclosure, FR-db-enrichment-5. It serves an
operator who runs a command line another program builds. The variable permits the
disclosure and asks for no lookup, so `JA4PLUS_DB_LOOKUP=1 ja4plus analyze capture.pcap`
looks nothing up. `JA4PLUS_DB_LOOKUP=1 ja4plus analyze capture.pcap --lookup` performs
the remote lookup.

The option and the variable each permit the disclosure, and neither one refuses it.
`JA4PLUS_DB_LOOKUP=0` therefore cancels no option, and an operator who wants the local
lookup passes `--lookup`. The variable permits the disclosure on the value `1` and on no
other value.

The command writes one notice to standard error for each run that permits the remote
lookup, FR-db-enrichment-6. The notice names the lookup service and the two ways to stop
the request. It appears once whatever count of fingerprints the run looks up, and it
goes to standard error, because a notice on standard output would enter the pipe that
carries the results.

```
Notice: the remote lookup is on. Each fingerprint the bundled mapping file holds no entry for goes to the lookup service at https://ja4db.com. To stop it, pass no --lookup-remote option and unset JA4PLUS_DB_LOOKUP.
```

The command needs the `requests` package for the remote lookup. Where the operator asks
for the remote lookup and the package is absent, the command reports the extra to install
and ends the run with the status 1.

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

A full lookup cache holds about 47 MiB. Two methods agree on that total: `tracemalloc`
reads 47.06 MiB and `sys.getsizeof` reads 46.95 MiB. The figure covers two structures,
because the client also remembers the 100000 keys it evicted. A run of 200000 distinct
lookups fills both, and a run of 100000 fills the entries alone at 25.34 MiB. #279 holds
the memory ceiling of this package, and it states no decided number yet.

The client reads the mapping file once, at construction. A caller that replaces the
mapping file builds a new client, and the new client holds an empty lookup cache.

#### The cached mapping file

`ja4plus db update` downloads `ja4plus-mapping.csv` from FoxIO and writes it to the cache
directory, FR-db-enrichment-12. It writes no file inside the installed package. A package
directory may be read-only, several users may share it, and the next `pip install`
discards a file written there. The cache directory follows the platform convention.

| Platform | Cache directory |
|---|---|
| Linux | `$XDG_CACHE_HOME/ja4plus`, or `~/.cache/ja4plus` where the variable holds no value |
| macOS | `~/Library/Caches/ja4plus` |

The command writes a temporary file and renames it, so a reader of the cache file reads
the whole new file or the file the last run wrote. Where the command creates no cache
directory, it names the directory and ends the run with the status 1. Where the download
fails, it leaves the cache file as it was and ends the run with the status 1.

`JA4DBClient` prefers the cached mapping file over the bundled one, FR-db-enrichment-13.
A cache file that is empty, corrupt or unreadable falls back to the bundled file, and the
client writes one `WARNING` record that names the path.

`ja4plus db info` reports the source, the path, the entry count and the modification time
of the mapping file the client reads, FR-db-enrichment-11. The source is `embedded` or
`cache`. The port publishes the value `embedded` for the file that ships inside the
package, at `lookup.go:31`, and `CLAUDE.md` parity rule 2 adopts it. The prose of this
project still calls that file the bundled mapping file. Where the source is `embedded`,
the command names the cache file as well. It
reports that the cache file holds no entry, or that no cache file exists, and it names
`ja4plus db update` in each case.
