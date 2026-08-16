"""Build the two captures that measure the JA4L QUIC measurement points.

No FoxIO vector holds a repeated QUIC connection, and none holds a server Initial
packet that leads its client Initial packet. #123 asks for a behavior change on both
cases, so both need a measurement of the reference.

These two captures supply it. They are synthetic. The packets carry no real handshake,
because JA4L reads the long-header packet type and the direction only.

Run this file to write the captures:

```
python tests/build_quic_ja4l_captures.py /tmp
```

Then build the FoxIO Rust implementation at the commit
`tests/download_test_vectors.py` pins, and run it on each capture:

```
ja4 /tmp/quic_repeat.pcap
ja4 /tmp/quic_mirrored.pcap
```

`docs/implementation_notes.md` records the output, and
`tests/test_ja4l_quic_repeated_connection.py` holds `ja4plus` against it.
"""

import sys
from pathlib import Path

from scapy.all import IP, UDP, Ether, Raw, wrpcap

from tests.quic_builder import (
    ACK_FRAME,
    client_initial,
    crypto_frame,
    handshake_packet,
    server_hello,
    server_initial,
)

CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 44444
SERVER_PORT = 443

CLIENT_TTL = 64
SERVER_TTL = 56

FIRST_DCID = bytes.fromhex("0102030405060708")
SECOND_DCID = bytes.fromhex("1112131415161718")

SERVER_HELLO_FRAMES = crypto_frame(0, server_hello()) + ACK_FRAME


# The FoxIO Rust implementation reads a capture through tshark, and tshark needs a
# link layer. Every packet therefore carries one.
def _to_server(payload, t):
    """Return one client packet that carries the payload at the timestamp."""
    packet = (
        Ether()
        / IP(src=CLIENT_IP, dst=SERVER_IP, ttl=CLIENT_TTL)
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / Raw(load=payload)
    )
    packet.time = t
    return packet


def _from_server(payload, t):
    """Return one server packet that carries the payload at the timestamp."""
    packet = (
        Ether()
        / IP(src=SERVER_IP, dst=CLIENT_IP, ttl=SERVER_TTL)
        / UDP(sport=SERVER_PORT, dport=CLIENT_PORT)
        / Raw(load=payload)
    )
    packet.time = t
    return packet


def handshake_round(dcid, base):
    """Return the four packets of one complete QUIC handshake.

    Args:
        dcid: The connection ID the client chooses.
        base: The timestamp of the client Initial packet, in seconds.

    Returns:
        The client Initial packet, the server Initial packet, one server Handshake
        packet and one client Handshake packet, in that order.
    """
    return [
        _to_server(client_initial(dcid), base + 0.000),
        _from_server(server_initial(dcid, SERVER_HELLO_FRAMES), base + 0.010),
        _from_server(handshake_packet(), base + 0.011),
        _to_server(handshake_packet(), base + 0.012),
    ]


def mirrored_round(dcid, base):
    """Return the four packets of one handshake whose server Initial packet leads.

    Args:
        dcid: The connection ID the client chooses.
        base: The timestamp of the server Initial packet, in seconds.

    Returns:
        The server Initial packet, the client Initial packet, one server Handshake
        packet and one client Handshake packet, in that order.
    """
    return [
        _from_server(server_initial(dcid, SERVER_HELLO_FRAMES), base + 0.000),
        _to_server(client_initial(dcid), base + 0.010),
        _from_server(handshake_packet(), base + 0.011),
        _to_server(handshake_packet(), base + 0.012),
    ]


def write_captures(directory):
    """Write both captures into the directory and return their two paths."""
    directory = Path(directory)
    repeat = directory / "quic_repeat.pcap"
    mirrored = directory / "quic_mirrored.pcap"
    wrpcap(str(repeat), handshake_round(FIRST_DCID, 1000.0) + handshake_round(SECOND_DCID, 1001.0))
    wrpcap(str(mirrored), mirrored_round(FIRST_DCID, 2000.0))
    return repeat, mirrored


if __name__ == "__main__":
    for path in write_captures(sys.argv[1] if len(sys.argv) > 1 else "."):
        print(path)
