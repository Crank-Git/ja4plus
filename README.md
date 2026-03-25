[![Tests](https://github.com/Crank-Git/ja4plus/actions/workflows/test.yml/badge.svg)](https://github.com/Crank-Git/ja4plus/actions/workflows/test.yml)
[![PyPI version](https://badge.fury.io/py/ja4plus.svg)](https://pypi.org/project/ja4plus/)
[![Python versions](https://img.shields.io/pypi/pyversions/ja4plus.svg)](https://pypi.org/project/ja4plus/)

# JA4+

A Python library for JA4+ network fingerprinting. Implements all eight JA4+ methods for identifying and classifying network traffic based on TLS, TCP, HTTP, SSH, and X.509 characteristics.

JA4+ is a set of network fingerprinting standards created by [FoxIO](https://foxio.io). This library is an independent Python implementation of the published specification. For the original spec, see the [FoxIO JA4+ repository](https://github.com/FoxIO-LLC/ja4).

## Supported Fingerprint Types

| Type | Protocol | Description |
|------|----------|-------------|
| JA4 | TLS | Client fingerprint from ClientHello messages |
| JA4S | TLS | Server fingerprint from ServerHello messages |
| JA4H | HTTP | Client fingerprint from request headers and cookies |
| JA4T | TCP | Client OS fingerprint from SYN packets |
| JA4TS | TCP | Server fingerprint from SYN-ACK packets |
| JA4L | TCP | Light distance and latency estimation |
| JA4X | X.509 | Certificate structure fingerprint from OID sequences |
| JA4SSH | SSH | Session type classification from traffic patterns |

## Installation

```bash
pip install ja4plus
```

Or install from source:

```bash
git clone https://github.com/Crank-Git/ja4plus.git
cd ja4plus
pip install -e .
```

## Quick Start

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

## Usage

### Class-Based API

Each fingerprinter processes packets and collects results:

```python
from ja4plus import JA4Fingerprinter, JA4SFingerprinter, JA4TFingerprinter

ja4 = JA4Fingerprinter()
ja4s = JA4SFingerprinter()
ja4t = JA4TFingerprinter()

for packet in packets:
    ja4.process_packet(packet)
    ja4s.process_packet(packet)
    ja4t.process_packet(packet)

for entry in ja4.get_fingerprints():
    print(entry["fingerprint"])
```

### Function-Based API

For one-shot fingerprinting of individual packets:

```python
from ja4plus import generate_ja4, generate_ja4s, generate_ja4h

fingerprint = generate_ja4(packet)
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
)
```

All fingerprinters share a common interface:

| Method | Description |
|--------|-------------|
| `process_packet(pkt)` | Process a packet, returns fingerprint string or `None` |
| `get_fingerprints()` | Returns list of all collected fingerprint dicts |
| `reset()` | Clears all collected state |

See [`docs/usage.md`](docs/usage.md) for detailed usage of each fingerprinter.

## Fingerprint Formats

| Type | Format | Example |
|------|--------|---------|
| JA4 | `{proto}{ver}{sni}{ciphcnt}{extcnt}{alpn}_{hash}_{hash}` | `t13d1516h2_8daaf6152771_e5627efa2ab1` |
| JA4S | `{proto}{ver}{extcnt}{alpn}_{cipher}_{hash}` | `t130200_1301_a56c5b993250` |
| JA4H | `{method}{ver}{cookie}{ref}{cnt}{lang}_{hash}_{hash}_{hash}` | `ge11cr0800_edb4461d7a83_4817af47a558_...` |
| JA4T | `{window}_{options}_{mss}_{wscale}` | `65535_2-4-8-1-3_1460_7` |
| JA4TS | `{window}_{options}_{mss}_{wscale}` | `14600_2-4-8-1-3_1460_0` |
| JA4L | `{latency_us}_{ttl}` | `2500_56` |
| JA4X | `{issuer_hash}_{subject_hash}_{ext_hash}` | `a37f49ba31e2_a37f49ba31e2_dd4f1a0ef8b2` |
| JA4SSH | `c{mode}s{mode}_c{pkts}s{pkts}_c{acks}s{acks}` | `c36s36_c51s80_c69s0` |

## Requirements

- Python 3.8+
- [scapy](https://scapy.net/) >= 2.4.0
- [cryptography](https://cryptography.io/) >= 3.4.0

## Development

```bash
git clone https://github.com/Crank-Git/ja4plus.git
cd ja4plus
pip install -e ".[dev]"
pytest tests/ -v
```

## License

BSD 3-Clause License. See [LICENSE](LICENSE) for details.

## Acknowledgments

JA4+ was created by John Althouse at [FoxIO](https://foxio.io). This library is an independent implementation of the published specification. For the original spec and reference implementation, see [github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4).
