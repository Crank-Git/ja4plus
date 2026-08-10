"""Build the capture that holds one retransmitted SSH segment.

`tests/data/ssh-retransmission.pcap` holds one SSH connection. The client sends a
1496-byte SSH message in two TCP segments, and it sends the first segment twice. No
FoxIO vector holds a retransmitted SSH segment, so this capture is the only one that
covers the case.

Run this file to write the capture again:

```
python tests/build_ssh_retransmission.py
```
"""

import struct
from pathlib import Path

from scapy.all import IP, TCP, Raw, wrpcap

CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 50000
SERVER_PORT = 22

BANNER = b"SSH-2.0-OpenSSH_8.1\r\n"

# The first segment of the split message. The message spans two segments on a maximum
# transmission unit of 1500 bytes.
FIRST_SEGMENT_BYTES = 1448

OUTPUT = Path(__file__).parent / "data" / "ssh-retransmission.pcap"


def message(body_length, code):
    """Return one complete SSH message.

    Args:
        body_length: The value of the length field, in bytes.
        code: The message code, which follows the padding length.

    Returns:
        The message bytes, which are `body_length` plus the four length bytes.
    """
    return struct.pack(">I", body_length) + bytes([4, code]) + b"A" * (body_length - 2)


def build():
    """Return the packets of the capture, in the order the capture holds them.

    Returns:
        The list of packets.
    """
    packets = []
    state = {"client": 1, "server": 1}

    def send(source, payload=b"", flags="PA"):
        """Append one packet, and advance the sequence number of the direction."""
        if source == "client":
            layer = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(
                sport=CLIENT_PORT,
                dport=SERVER_PORT,
                flags=flags,
                seq=state["client"],
                ack=state["server"],
            )
        else:
            layer = IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(
                sport=SERVER_PORT,
                dport=CLIENT_PORT,
                flags=flags,
                seq=state["server"],
                ack=state["client"],
            )
        packet = layer / Raw(payload) if payload else layer
        packets.append(packet)
        state[source] += len(payload)
        return packet

    # The TCP handshake. FoxIO counts the third packet as one bare ACK.
    send("client", flags="S")
    state["client"] += 1
    send("server", flags="SA")
    state["server"] += 1
    send("client", flags="A")

    send("client", BANNER)
    send("server", BANNER)

    # The client sends a 1496-byte message in two segments, and it sends the first
    # segment twice. `tshark` labels only the segment that completes the message.
    split = message(body_length=1492, code=20)
    first = send("client", split[:FIRST_SEGMENT_BYTES])
    packets.append(first.copy())
    send("client", split[FIRST_SEGMENT_BYTES:])

    for _ in range(3):
        send("client", message(body_length=32, code=94))
        send("server", message(body_length=32, code=94))

    send("client", flags="FA")
    return packets


if __name__ == "__main__":
    wrpcap(str(OUTPUT), build())
    print(f"wrote {OUTPUT}")
