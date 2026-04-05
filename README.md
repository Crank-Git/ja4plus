<p align="center">[![Tests](https://github.com/Crank-Git/ja4plus/actions/workflows/test.yml/badge.svg)](https://github.com/Crank-Git/ja4plus/actions/workflows/test.yml)
[![PyPI version](https://badge.fury.io/py/ja4plus.svg)](https://pypi.org/project/ja4plus/)
[![Python versions](https://img.shields.io/pypi/pyversions/ja4plus.svg)](https://pypi.org/project/ja4plus/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)
</p>

<p align="center"><img src="assets/logo.png" width="300"></p>

A Python library and CLI for JA4+ network fingerprinting. Implements all eight JA4+ methods for identifying and classifying network traffic based on TLS, TCP, HTTP, SSH, and X.509 characteristics.

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
```

Output formats: `--format table` (default), `json` (JSONL), `csv`

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

See [`docs/usage.md`](docs/usage.md) for detailed usage of each fingerprinter and [`docs/api_reference.md`](docs/api_reference.md) for the full API.

## Fingerprint Formats

| Type | Format | Example |
|------|--------|---------|
| JA4 | `{proto}{ver}{sni}{ciphers}{exts}{alpn}_{hash}_{hash}` | `t13d1516h2_8daaf6152771_e5627efa2ab1` |
| JA4S | `{proto}{ver}{exts}{alpn}_{cipher}_{hash}` | `t130200_1301_a56c5b993250` |
| JA4H | `{method}{ver}{cookie}{ref}{cnt}{lang}_{h}_{h}_{h}` | `ge11cr0800_edb4461d7a83_...` |
| JA4T | `{window}_{options}_{mss}_{wscale}` | `65535_2-4-8-1-3_1460_7` |
| JA4TS | `{window}_{options}_{mss}_{wscale}` | `14600_2-4-8-1-3_1460_0` |
| JA4L | `{latency_us}_{ttl}` | `2500_56` |
| JA4X | `{issuer}_{subject}_{extensions}` | `a37f49ba31e2_a37f49ba31e2_dd4f1a0ef8b2` |
| JA4SSH | `c{mode}s{mode}_c{pkts}s{pkts}_c{acks}s{acks}` | `c36s36_c51s80_c69s0` |

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

- Python 3.8+
- [scapy](https://scapy.net/) >= 2.4.0
- [cryptography](https://cryptography.io/) >= 42.0.0

## License

This library is released under the **BSD 3-Clause License**.

The JA4+ fingerprinting specifications were created by [FoxIO](https://foxio.io). JA4 (TLS Client) is open source under BSD-3-Clause per FoxIO. Other JA4+ methods (JA4S, JA4H, JA4T, JA4TS, JA4L, JA4X, JA4SSH) implement FoxIO's specifications under the [FoxIO License 1.1](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE), which is permissive for academic, internal business, and security research use.

See [LICENSE](LICENSE) for full details.

## Acknowledgments

JA4+ was created by John Althouse at [FoxIO](https://foxio.io). This library is an independent implementation of the published specification. For the original spec and reference implementation, see [github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4).
