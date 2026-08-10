"""Build the capture that holds the RST example of the deleted FoxIO file.

`tests/data/ja4ts-rst.pcap` holds one TCP connection. The server answers the client SYN
five times and then sends a RST. The deleted `technical_details/JA4T.md` states the six
capture times and the six JA4TS values that they produce, and the last value is
`65535_2-1-3-1-1-4_65495_8_1-2-4-8-R6`.

No capture in `tests/foxio_vectors/` reaches the rule. `ssh2.pcapng` holds the one
connection of the vector set that the server answered twice, and the server sent no RST
on it. This capture is therefore the only one that measures the rule against a packet
list.

Run this file to write the capture again:

```
python tests/build_ja4ts_rst.py
```
"""

from pathlib import Path

from scapy.all import IP, TCP, wrpcap

CLIENT_IP = "10.0.0.2"
SERVER_IP = "10.0.0.1"
CLIENT_PORT = 50000
SERVER_PORT = 443

# Part a through part d of the example of the deleted file. The window scale of 8 and the
# Maximum Segment Size of 65495 produce `65535_2-1-3-1-1-4_65495_8`.
SERVER_WINDOW = 65535
SERVER_OPTIONS = [
    ("MSS", 65495),
    ("NOP", None),
    ("WScale", 8),
    ("NOP", None),
    ("NOP", None),
    ("SAckOK", b""),
]

# The capture times that the deleted file lists for its third example. The first five
# belong to the SYN-ACK packets and the last belongs to the RST packet.
SYN_ACK_TIMES = [16.681435, 17.683799, 19.691548, 23.703045, 31.714762]
RST_TIME = 37.723966

# The client SYN arrives before the first SYN-ACK. The deleted file states no time for
# it, so this capture places it one millisecond earlier.
SYN_TIME = SYN_ACK_TIMES[0] - 0.001

OUTPUT = Path(__file__).parent / "data" / "ja4ts-rst.pcap"


def build():
    """Return the packets of the capture, in the order the capture holds them.

    Returns:
        The list of packets.
    """
    packets = []

    syn = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(
        sport=CLIENT_PORT,
        dport=SERVER_PORT,
        flags="S",
        seq=1,
        window=SERVER_WINDOW,
        options=SERVER_OPTIONS,
    )
    syn.time = SYN_TIME
    packets.append(syn)

    for time in SYN_ACK_TIMES:
        syn_ack = IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(
            sport=SERVER_PORT,
            dport=CLIENT_PORT,
            flags="SA",
            seq=1,
            ack=2,
            window=SERVER_WINDOW,
            options=SERVER_OPTIONS,
        )
        syn_ack.time = time
        packets.append(syn_ack)

    # The deleted file reads "the final TCP packet, a RST packet". A RST packet carries
    # no window size and no option, so the reader restores part a through part d from the
    # connection.
    reset = IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(
        sport=SERVER_PORT, dport=CLIENT_PORT, flags="R", seq=2, window=0
    )
    reset.time = RST_TIME
    packets.append(reset)

    return packets


if __name__ == "__main__":
    wrpcap(str(OUTPUT), build())
    print(f"wrote {OUTPUT}")
