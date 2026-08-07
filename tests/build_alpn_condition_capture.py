"""Build the capture that separates the JA4 ALPN rules.

#127 settled the value that the ALPN branch writes. It settled no condition, because
`tls-non-ascii-alpn.pcapng` holds the first ALPN value `0xba 0xad`, and every rule
fires on it. #141 owns the condition, and it needs an input the rules separate.

This capture supplies two such inputs. It is synthetic, and it is not FoxIO material.
`tests/foxio_vectors/NOTICE` records that. Its expected-output file holds a
measurement of the FoxIO Python implementation at the pinned upstream commit, and the
FoxIO Rust implementation produces the same two values.

| Stream | The first ALPN value | What it separates |
|---|---|---|
| 0 | `h\\x20` | The last byte is ASCII and it is not alphanumeric |
| 1 | `\\x20h` | The first byte is ASCII and it is not alphanumeric |

Both FoxIO implementations write the two bytes through on both streams. The FoxIO
prose writes the hex form, and `ja4plus` wrote `99` before #141. The three rules
therefore disagree on both streams.

Each stream carries one TLS ClientHello and nothing else. The capture holds no TCP
handshake, because a SYN packet adds a JA4T value and a JA4L value to the comparison,
and #141 owns the ALPN condition alone.

The two ClientHellos differ in the first ALPN value alone, so the two JA4 values
differ in the two ALPN characters and in nothing else.

Run this file to write the capture:

```
python tests/build_alpn_condition_capture.py tests/foxio_vectors
```

Then measure both FoxIO implementations at the commit
`tests/download_test_vectors.py` pins:

```
python ja4.py alpn-condition.pcap -J
ja4 alpn-condition.pcap
```

`docs/implementation_notes.md` records the output, and
`tests/test_ja4_alpn_condition.py` holds `ja4plus` against it.
"""

import sys
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT_IP = "10.1.0.1"
SERVER_IP = "10.1.0.2"

# The FoxIO Python implementation reads TLS on a port it knows. Port 443 is such a
# port, so every stream uses it.
SERVER_PORT = 443

# scapy asks the host for a MAC address when a packet names none, and the answer
# changes with the host. The capture names both addresses, so every host writes the
# same bytes.
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"

FIRST_CLIENT_PORT = 44401

# The second ALPN value of the FoxIO vector `tls-non-ascii-alpn.pcapng`. The capture
# repeats it, because a rule that reads the wrong ALPN value shows up against it.
SECOND_ALPN = b"http/1.1"

# Each stream carries one of these as the first ALPN value. The docstring holds the
# table of what each one separates.
ALPN_CASES = (b"h\x20", b"\x20h")

CIPHERS = (0x1301, 0x1302, 0x1303)
SNI_HOSTNAME = b"example.com"
SUPPORTED_VERSIONS = (0x0304,)
SIGNATURE_ALGORITHMS = (0x0403, 0x0804)


def _extension(ext_type, body):
    """Return one TLS extension of the type, with the body as its data."""
    return ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def _sni_extension(hostname):
    """Return the server_name extension that names the host."""
    entry = b"\x00" + len(hostname).to_bytes(2, "big") + hostname
    return _extension(0x0000, len(entry).to_bytes(2, "big") + entry)


def _alpn_extension(values):
    """Return the application_layer_protocol_negotiation extension of the values.

    Args:
        values: The ALPN values as bytes, in wire order.

    Returns:
        The encoded extension.
    """
    body = b"".join(len(value).to_bytes(1, "big") + value for value in values)
    return _extension(0x0010, len(body).to_bytes(2, "big") + body)


def _supported_versions_extension(versions):
    """Return the supported_versions extension of the versions."""
    body = b"".join(version.to_bytes(2, "big") for version in versions)
    return _extension(0x002B, len(body).to_bytes(1, "big") + body)


def _signature_algorithms_extension(algorithms):
    """Return the signature_algorithms extension of the algorithms."""
    body = b"".join(algorithm.to_bytes(2, "big") for algorithm in algorithms)
    return _extension(0x000D, len(body).to_bytes(2, "big") + body)


def client_hello(first_alpn):
    """Return one TLS record that carries a ClientHello with the first ALPN value.

    Args:
        first_alpn: The bytes of the first ALPN value.

    Returns:
        The bytes of one TLS handshake record.
    """
    extensions = (
        _sni_extension(SNI_HOSTNAME)
        + _supported_versions_extension(SUPPORTED_VERSIONS)
        + _alpn_extension((first_alpn, SECOND_ALPN))
        + _signature_algorithms_extension(SIGNATURE_ALGORITHMS)
    )

    ciphers = b"".join(cipher.to_bytes(2, "big") for cipher in CIPHERS)

    body = (
        # The legacy version field. The supported_versions extension carries the
        # version that JA4 reads.
        b"\x03\x03"
        + b"\x00" * 32  # The random field. A fingerprint reads none of it.
        + b"\x00"  # The session ID is empty.
        + len(ciphers).to_bytes(2, "big")
        + ciphers
        + b"\x01\x00"  # One compression method, which is null.
        + len(extensions).to_bytes(2, "big")
        + extensions
    )

    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def hello_packet(first_alpn, client_port, timestamp):
    """Return one client packet that carries the ClientHello of the ALPN value.

    Args:
        first_alpn: The bytes of the first ALPN value.
        client_port: The TCP source port of the client.
        timestamp: The time of the packet, in seconds.

    Returns:
        One scapy packet.
    """
    packet = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64)
        / TCP(sport=client_port, dport=SERVER_PORT, flags="PA", seq=1, ack=1)
        / Raw(load=client_hello(first_alpn))
    )
    packet.time = timestamp
    return packet


def build_packets():
    """Return every packet of the capture, in wire order."""
    return [
        hello_packet(first_alpn, FIRST_CLIENT_PORT + index, 1000.0 + index)
        for index, first_alpn in enumerate(ALPN_CASES)
    ]


def write_capture(directory):
    """Write the capture into the directory and return its path."""
    path = Path(directory) / "alpn-condition.pcap"
    wrpcap(str(path), build_packets())
    return path


if __name__ == "__main__":
    print(write_capture(sys.argv[1] if len(sys.argv) > 1 else "."))
