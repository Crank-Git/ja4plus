<p align="center"><img src="assets/logo.png" width="300"></p>

A Python library and CLI for JA4+ network fingerprinting. Implements all ten JA4+ methods for identifying and classifying network traffic based on TLS, TCP, HTTP, SSH, X.509, and DHCP characteristics. Supports QUIC, IPv4/IPv6, and multi-segment TCP reassembly.

JA4+ is a set of network fingerprinting standards created by [FoxIO](https://foxio.io). This library is an independent Python implementation of the published specification. For the original spec, see the [FoxIO JA4+ repository](https://github.com/FoxIO-LLC/ja4).

[![Tests](https://github.com/Crank-Git/ja4plus/actions/workflows/test.yml/badge.svg)](https://github.com/Crank-Git/ja4plus/actions/workflows/test.yml)
[![PyPI version](https://badge.fury.io/py/ja4plus.svg)](https://pypi.org/project/ja4plus/)
[![Python versions](https://img.shields.io/pypi/pyversions/ja4plus.svg)](https://pypi.org/project/ja4plus/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

## Supported Fingerprint Types

| Type | Protocol | Description |
|------|----------|-------------|
| JA4 | TLS/QUIC | Client fingerprint from ClientHello messages |
| JA4S | TLS/QUIC | Server fingerprint from ServerHello messages |
| JA4H | HTTP | Client fingerprint from request headers and cookies |
| JA4T | TCP | Client OS fingerprint from SYN packets |
| JA4TS | TCP | Server fingerprint from SYN-ACK packets |
| JA4L | TCP/QUIC | Light distance and latency estimation |
| JA4X | X.509 | Certificate structure fingerprint from OID sequences |
| JA4SSH | SSH | Session type classification from traffic patterns |
| JA4D | DHCPv4 | DHCP client/server fingerprint (FoxIO PR #267/#270) |
| JA4D6 | DHCPv6 | DHCPv6 client/server fingerprint (FoxIO PR #267/#270) |

QUIC Initial packets (RFC 9001/9369) are automatically decrypted to extract TLS ClientHellos. IPv4 and IPv6 are both supported across all fingerprinters.

## Installation

```bash
pip install ja4plus
```

For fingerprint identification (browsers, malware, C2 frameworks):

```bash
pip install ja4plus[lookup]
```

## CLI

The `ja4plus` command is available after installation:

```bash
# Analyze a PCAP file
ja4plus analyze capture.pcap

# JSON output for SIEM ingestion
ja4plus --format json analyze capture.pcap

# Only specific fingerprint types
ja4plus --types ja4,ja4t analyze capture.pcap

# Live capture (requires root)
sudo ja4plus live eth0

# Fingerprint a certificate
ja4plus cert server.der

# Identify known fingerprints
ja4plus --lookup analyze capture.pcap

# Write the results to a file
ja4plus analyze capture.pcap --format json --output results.json

# Overwrite a file that exists
ja4plus analyze capture.pcap --format json --output results.json --force
```

Every option runs before the subcommand name and after it.
`ja4plus --format json analyze capture.pcap` and
`ja4plus analyze capture.pcap --format json` do the same thing.

Output formats: `--format table` (default), `json` (JSONL), `csv`

The `json` and the `csv` formats write the same fields whatever flags you pass. Each
record carries the source address, the source port, the destination address and the
destination port as separate fields, in this order:

```
schema_version,timestamp,type,fingerprint,raw,raw_original_order,src_ip,src_port,dst_ip,dst_port,identified_as
```

A field with no value is `null` in the `json` format and empty in the `csv` format. The
`table` format is for a person reading a terminal, and it carries no stability promise.

The command writes results to standard output and diagnostics to standard error, so a
pipe that reads standard output reads results alone. A method that fails to read a
packet writes one line that names the method, and the run continues:

```
Warning: ja4h could not read a packet: the parser read a length field it cannot trust
```

The command runs every method whatever `--types` names, and it selects the results it
reports. It therefore reports the error of a method that `--types` leaves out.

`--output FILE` writes the results to a file and leaves standard output empty. The
command refuses to overwrite a file that exists, and it exits with the status 1:

```
Error: the output file exists: results.json. Pass --force to overwrite it.
```

`--force` overwrites that file. Without `--force` the command creates the file, so it
writes through no symbolic link. A reader that closes the pipe early, such as `head -1`,
ends the run without a traceback.

## Fingerprint Lookup

ja4plus includes a bundled database of known JA4+ fingerprints from FoxIO's [ja4plus-mapping.csv](https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv). Identifies Chrome, Firefox, Safari, Python, Cobalt Strike, Sliver, IcedID, and more.

```python
from ja4plus.ja4db import lookup

result = lookup("t13d1516h2_8daaf6152771_02713d6af862")
# {"application": "Chromium Browser", "type": "ja4", "notes": ""}
```

## Python API

### Quick Start

```python
from scapy.all import rdpcap
from ja4plus import JA4Fingerprinter

packets = rdpcap("capture.pcap")

fp = JA4Fingerprinter()
for packet in packets:
    result = fp.process_packet(packet)
    if result:
        print(f"JA4: {result}")
```

### All Fingerprinters

```python
from ja4plus import (
    JA4Fingerprinter,      # TLS Client
    JA4SFingerprinter,     # TLS Server
    JA4HFingerprinter,     # HTTP
    JA4TFingerprinter,     # TCP Client (SYN)
    JA4TSFingerprinter,    # TCP Server (SYN-ACK)
    JA4LFingerprinter,     # Latency
    JA4XFingerprinter,     # X.509 Certificate
    JA4SSHFingerprinter,   # SSH
    JA4DFingerprinter,     # DHCPv4
    JA4D6Fingerprinter,    # DHCPv6
)
```

All fingerprinters share a common interface:

| Method | Description |
|--------|-------------|
| `process_packet(pkt)` | Process a packet, returns fingerprint string or `None` |
| `get_fingerprints()` | Returns list of all collected fingerprint dicts |
| `reset()` | Clears all collected state |

### Function-Based API

For one-shot fingerprinting without maintaining state:

```python
from ja4plus import generate_ja4, generate_ja4s, generate_ja4h

fingerprint = generate_ja4(packet)
```

### Aggregating Processor

Run every fingerprinter on each packet and get a list of results:

```python
from ja4plus import Processor

p = Processor()
for packet in packets:
    for r in p.process_packet(packet):
        print(r.type, r.fingerprint, r.raw)

# Read the errors as well when a failed parse must be told from no fingerprint.
results, errors = p.process_packet_with_errors(packet)

# The packet source ends here. JA4SSH emits the window each connection holds open.
for r in p.close_open_windows():
    print(r["type"], r["fingerprint"], r["connection"])

# Use get_shard_key to bucket packets per connection
shard_key = p.get_shard_key(packet)

# Cleanup state for a finished connection
p.cleanup_connection(src_ip, src_port, dst_ip, dst_port, "tcp")
```

#### The concurrency contract

Several threads may share one `Processor()`, and each fingerprinter guards its own state
with a reentrant lock. Give each thread whole connections, which is what `get_shard_key`
returns, and eight threads read the value set one thread reads. A caller that splits the
packets of one connection across threads gets undefined results. The state of that
connection then advances out of capture order. A caller that runs one processor for each
shard constructs `Processor(thread_safe=False)` to acquire no lock. `thread_safe=False`
is a promise the caller makes, not a mode the library checks. Feed one processor the
packets of one timeline. Every state table evicts an entry that receives no packet for
its maximum age. Two packet sources whose clocks sit far apart therefore age out state
that the later source still needs.

#### The memory bound

Every state table holds a maximum entry count and a maximum age. A monitor that runs for
a day therefore stops growing rather than running out of memory.
[`docs/specs/features/03-concurrency-safety.md`](docs/specs/features/03-concurrency-safety.md)
states both numbers for each table. A table that reaches its maximum entry count evicts
the least recently used entry. A connection can therefore leave a long capture and
return, and the fingerprint of a returned connection may be incomplete.
`Processor.stats()` reports the count of returned connections for each method. Eviction
runs on packet arrival and the library starts no thread. This package states no memory
ceiling.

JA4 and JA4S result dicts include the unhashed `raw` and
`raw_original_order` variants — useful for human-readable output and
fingerprint debugging.

A JA4 result holds two different raw values. `raw` is the FoxIO `JA4_r` value,
which sorts the ciphers and the extensions. `raw_original_order` is the FoxIO
`JA4_ro` value, which holds every list in wire order. A JA4S result holds one
raw value under both keys, because JA4S sorts no list. That value is the FoxIO
`JA4S_r` value, and it holds the extensions in wire order.

The same dicts include `fingerprint_original_order`, the FoxIO `JA4_o` value.
It is the hashed form of `raw_original_order`, and its relationship to
`fingerprint` matches the relationship of `raw_original_order` to `raw`. The
`JA4Fingerprinter` and `JA4SFingerprinter` classes also hold the most recent
one on `last_fingerprint_original_order`.

### X.509 Helpers

```python
from ja4plus import compute_ja4x_from_pem, compute_ja4x_from_der

ja4x = compute_ja4x_from_pem(pem_bytes)
ja4x = compute_ja4x_from_der(der_bytes)
```

See [`docs/usage.md`](docs/usage.md) for detailed usage of each fingerprinter and [`docs/api_reference.md`](docs/api_reference.md) for the full API.

## Fingerprint Formats

| Type | Format | Example |
|------|--------|---------|
| JA4 | `{proto}{ver}{sni}{ciphers}{exts}{alpn}_{hash}_{hash}` | `t13d1516h2_8daaf6152771_e5627efa2ab1` |
| JA4S | `{proto}{ver}{exts}{alpn}_{cipher}_{hash}` | `t130200_1301_a56c5b993250` |
| JA4H | `{method}{ver}{cookie}{ref}{cnt}{lang}_{h}_{h}_{h}` | `ge11cr0800_edb4461d7a83_...` |
| JA4T | `{window}_{options}_{mss}_{wscale}` | `65535_2-4-8-1-3_1460_7` |
| JA4TS | `{window}_{options}_{mss}_{wscale}` | `14600_2-4-8-1-3_1460_00` |
| JA4L | `JA4L-{C\|S}={latency_us}_{ttl}` | `JA4L-S=2500_56` |
| JA4X | `{issuer}_{subject}_{extensions}` | `a37f49ba31e2_a37f49ba31e2_dd4f1a0ef8b2` |
| JA4SSH | `c{mode}s{mode}_c{pkts}s{pkts}_c{acks}s{acks}` | `c36s36_c51s80_c69s0` |
| JA4D | `{type}{size}{ip}{fqdn}_{options}_{request_list}` | `disco0000in_61-55_1-3-6-42` |
| JA4D6 | `{type}{size}{ip}{fqdn}_{options}_{request_list}` | `solct0014nn_1-6-8-25_23-24` |

## Spec Validation

ja4plus is validated against [FoxIO's official test vectors](https://github.com/FoxIO-LLC/ja4):

```bash
python tests/download_test_vectors.py
pytest -m spec_validation -v
```

## Development

```bash
git clone https://github.com/Crank-Git/ja4plus.git
cd ja4plus
pip install -e ".[dev]"
pytest tests/ -v
```

### Requirements

- Python 3.9+
- [scapy](https://scapy.net/) >= 2.4.0
- [cryptography](https://cryptography.io/) >= 42.0.0

## License

This library is released under the **BSD 3-Clause License**.

The JA4+ fingerprinting specifications were created by [FoxIO](https://foxio.io). JA4 (TLS Client) is open source under BSD-3-Clause per FoxIO. Other JA4+ methods (JA4S, JA4H, JA4T, JA4TS, JA4L, JA4X, JA4SSH) implement FoxIO's specifications under the [FoxIO License 1.1](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE), which is permissive for academic, internal business, and security research use.

See [LICENSE](LICENSE) for full details.

## Acknowledgments

JA4+ was created by John Althouse at [FoxIO](https://foxio.io). This library is an independent implementation of the published specification. For the original spec and reference implementation, see [github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4).
