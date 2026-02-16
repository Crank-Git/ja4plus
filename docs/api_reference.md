# API Reference

## Fingerprinter Classes

All fingerprinters inherit from `BaseFingerprinter` and share a common interface.

### Common Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `process_packet(packet)` | `str` or `None` | Process a scapy packet. Returns fingerprint string if one is generated. |
| `get_fingerprints()` | `list[dict]` | Returns all collected fingerprints as `{"fingerprint": str, ...}` dicts. |
| `reset()` | `None` | Clears all collected fingerprints and internal state. |

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
| `generate_ja4ts(packet)` | scapy packet | JA4TS TCP server fingerprint |
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
