"""Read the TCP option field of a SYN packet or a SYN-ACK packet.

JA4T and JA4TS write the same four parts, and the FoxIO references build both from one
function: `ja4t()` in `wireshark/source/packet-ja4.c` serves both fields, and
`zeek/ja4t/main.zeek:195-236` repeats one block. This module holds that one reading, so
one repair covers both methods.

`docs/specs/foxio/JA4T.md` states the rules. R4 and R5 state the option list, R6 and R7
state the two zero parts, and R11 records the disagreement the user settled on
2026-08-08.

**The reader trusts no length field it reads.** Every packet is hostile input, so a
length that reaches past the option field stops the reader, and the reader returns the
options it read. It raises nothing.
"""

# This import makes every annotation a string. No annotation therefore evaluates at
# import time, and a forward reference needs no quotation mark.
from __future__ import annotations

import logging

from scapy.all import Packet

logger = logging.getLogger(__name__)

# The TCP header holds 20 bytes before the option field, and the high half of byte 12
# holds the data offset in 32-bit words.
TCP_HEADER_BYTES = 20
DATA_OFFSET_BYTE = 12

# The two option kinds that carry no length byte. RFC 9293 section 3.1 names both.
END_OF_OPTION_LIST = 0
NO_OPERATION = 1

# The two option kinds that carry a value this project reads.
MAXIMUM_SEGMENT_SIZE = 2
WINDOW_SCALE = 3

# The length each of those two options carries, including the kind byte and the length
# byte. A length other than these describes another option, so the reader takes the kind
# and no value.
MAXIMUM_SEGMENT_SIZE_LENGTH = 4
WINDOW_SCALE_LENGTH = 3

# The shortest option that carries a length byte. A length below this reaches back over
# the kind byte, so it names no option and the reader stops.
SHORTEST_OPTION_LENGTH = 2

# The offset of the window field inside the TCP header.
WINDOW_OFFSET = 14


def option_bytes(tcp: Packet) -> bytes:
    """Return the raw TCP option bytes of one TCP layer.

    Scapy reports a parsed option list, and that list collapses several End of Option
    List bytes into one entry. Both FoxIO implementations count one entry for each byte,
    so this reads the bytes the capture carries. #215 records the reading as D2.

    Args:
        tcp: The TCP layer of one packet.

    Returns:
        The option bytes, or an empty byte string when the packet carries none. A data
        offset that reaches past the packet returns an empty byte string.
    """
    raw = getattr(tcp, "original", b"") or b""
    if not raw:
        # A caller that built the packet in memory holds no captured bytes, so the
        # builder writes them. A built option field carries the pad bytes the wire
        # carries, because scapy pads the field to a 32-bit boundary.
        raw = bytes(tcp)
    if len(raw) <= DATA_OFFSET_BYTE:
        return b""
    end = (raw[DATA_OFFSET_BYTE] >> 4) * 4
    if end <= TCP_HEADER_BYTES or end > len(raw):
        return b""
    return raw[TCP_HEADER_BYTES:end]


def read_options(data: bytes) -> tuple[list[int], int, int]:
    """Return the option kinds, the maximum segment size and the window scale.

    Args:
        data: The raw TCP option bytes.

    Returns:
        A tuple of the option kinds in wire order, the maximum segment size and the
        window scale. The segment size is 0 when the packet carries no such option, and
        the window scale is 0 when the packet carries no such option. A repeated option
        keeps the first value, which `rust/ja4/src/tcp.rs` also does. #215 records that
        reading as D5.
    """
    kinds: list[int] = []
    mss: int | None = None
    window_scale: int | None = None
    offset = 0
    while offset < len(data):
        kind = data[offset]
        if kind in (END_OF_OPTION_LIST, NO_OPERATION):
            kinds.append(kind)
            offset += 1
            continue
        if offset + 1 >= len(data):
            break
        length = data[offset + 1]
        if length < SHORTEST_OPTION_LENGTH or offset + length > len(data):
            break
        # Part b holds every kind, and not the six kinds a name list holds. #215 records
        # the reading as D3, and R4 names both FoxIO implementations.
        kinds.append(kind)
        if kind == MAXIMUM_SEGMENT_SIZE and length == MAXIMUM_SEGMENT_SIZE_LENGTH:
            if mss is None:
                mss = int.from_bytes(data[offset + 2 : offset + 4], "big")
        elif kind == WINDOW_SCALE and length == WINDOW_SCALE_LENGTH:
            if window_scale is None:
                window_scale = data[offset + 2]
        offset += length
    return kinds, mss or 0, window_scale or 0


def tcp_prefix(tcp: Packet) -> str:
    """Return part a through part d of a JA4T value or a JA4TS value.

    The user decided the two-digit form on 2026-08-08, and #215 records it as D1. An
    empty option list writes `00`, part c writes two digits, and a window scale of zero
    writes `00`. `wireshark/source/packet-ja4.c:664` and `zeek/ja4t/main.zeek:195-211`
    both write that form, and `rust/ja4/src/tcp.rs` writes one digit. The
    `Divergence register` in `docs/specs/spec.md` records the cost against the Rust
    implementation.

    Args:
        tcp: The TCP layer of one SYN packet or one SYN-ACK packet.

    Returns:
        The four parts, joined with `_`.
    """
    return _prefix(tcp.window, option_bytes(tcp))


def tcp_prefix_from_header(header: bytes) -> str:
    """Return part a through part d of a JA4T value from raw TCP header bytes.

    A TCP header that an ICMP error message quotes reaches no `scapy` layer, because
    `TCP(bytes)` raises `struct.error` on a truncated option. `ja4plus/utils/icmp_quoted.py`
    records that measurement, and it calls this function in place of `tcp_prefix`.

    Args:
        header: The TCP header, from the first byte to the end of the option list. The
            caller bounds the argument on the data offset, and it holds 20 bytes or more.

    Returns:
        The four parts, joined with `_`.
    """
    window = int.from_bytes(header[WINDOW_OFFSET : WINDOW_OFFSET + 2], "big")
    return _prefix(window, header[TCP_HEADER_BYTES:])


def _prefix(window: int, options: bytes) -> str:
    """Return part a through part d of a JA4T value or a JA4TS value.

    Args:
        window: The window field of the TCP header.
        options: The raw TCP option bytes.

    Returns:
        The four parts, joined with `_`.
    """
    kinds, mss, window_scale = read_options(options)
    part_b = "-".join(str(kind) for kind in kinds) if kinds else "00"
    part_d = "00" if window_scale == 0 else str(window_scale)
    return "{}_{}_{:02d}_{}".format(window, part_b, mss, part_d)
