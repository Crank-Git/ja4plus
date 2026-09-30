"""Build the SYN frame the scanner sends, and parse each frame it receives.

S2 and S3 of `docs/specs/foxio/JA4TScan.md` state every byte of the FoxIO SYN. The
builder writes those bytes itself rather than through `scapy`, so a case compares the
frame against the transcription byte for byte.

**The parser trusts no length field it reads.** Every response is hostile input, so a
length that reaches past the frame stops the parser, and the parser returns None. It
raises nothing.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

__all__ = ["Reply", "build_syn", "parse_frame"]

ETHERNET_HEADER_BYTES = 14
ETHERTYPE_IPV4 = 0x0800
IP_HEADER_BYTES = 20
TCP_HEADER_BYTES = 20
PROTOCOL_TCP = 6

# S2 of `docs/specs/foxio/JA4TScan.md` cites `zmap/src/probe_modules/packet.c:88-116`.
IP_IDENTIFICATION = 54321
IP_TIME_TO_LIVE = 255
TCP_FLAG_SYN = 0x02
TCP_WINDOW = 65535

# S3 of `docs/specs/foxio/JA4TScan.md`: Maximum Segment Size 1460, Window Scale 7, SACK
# Permitted, and the kind and length bytes of Timestamp. The Timestamp value, the echo
# reply of 0 and one End of Option List byte follow, which makes 20 option bytes.
SYN_OPTIONS_HEAD = bytes.fromhex("020405b4 030307 0402 080a")
SYN_OPTIONS_TAIL = bytes(4) + b"\x00"
SYN_TCP_HEADER_BYTES = TCP_HEADER_BYTES + len(SYN_OPTIONS_HEAD) + 4 + len(SYN_OPTIONS_TAIL)

# The flags and fragment offset field of the IP header. A fragment carries a part of a
# segment, so the parser reads neither the first fragment nor a later one.
IP_MORE_FRAGMENTS = 0x2000
IP_FRAGMENT_OFFSET = 0x1FFF


@dataclass(frozen=True)
class Reply:
    """Holds the fields of one received TCP segment that the scanner reads.

    Attributes:
        src_ip: The source address, which names the target.
        dst_ip: The destination address.
        src_port: The source port, which is the port the scanner sent to.
        dst_port: The destination port, which is the source port of the SYN.
        acknowledgment: The acknowledgment number.
        flags: The TCP flags byte.
        window: The window field.
        options: The raw TCP option bytes.
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    acknowledgment: int
    flags: int
    window: int
    options: bytes


def _checksum(data: bytes) -> int:
    """Return the Internet checksum of the data, as RFC 1071 states it.

    Args:
        data: The bytes the checksum covers.

    Returns:
        The ones' complement of the ones' complement sum, as 16 bits.
    """
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_syn(
    *,
    src_mac: bytes,
    dst_mac: bytes,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    sequence: int,
    timestamp: int,
) -> bytes:
    """Return the Ethernet frame of one FoxIO SYN.

    Args:
        src_mac: The link-layer address of the interface that sends the frame.
        dst_mac: The link-layer address of the next hop.
        src_ip: The IPv4 address of the scanning host.
        dst_ip: The IPv4 address of the target.
        src_port: The TCP source port.
        dst_port: The TCP port of the target.
        sequence: The TCP sequence number. A response acknowledges it.
        timestamp: The Timestamp option value. FoxIO writes the send time in whole
            seconds, and the builder keeps the low 32 bits.

    Returns:
        74 bytes: the Ethernet header, the IP header and a TCP header with 20 option
        bytes.
    """
    source = ipaddress.IPv4Address(src_ip).packed
    destination = ipaddress.IPv4Address(dst_ip).packed
    options = SYN_OPTIONS_HEAD + struct.pack("!I", timestamp & 0xFFFFFFFF) + SYN_OPTIONS_TAIL
    tcp = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        sequence & 0xFFFFFFFF,
        0,
        (SYN_TCP_HEADER_BYTES // 4) << 4,
        TCP_FLAG_SYN,
        TCP_WINDOW,
        0,
        0,
    ) + options
    pseudo = source + destination + struct.pack("!BBH", 0, PROTOCOL_TCP, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", _checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        IP_HEADER_BYTES + len(tcp),
        IP_IDENTIFICATION,
        0,
        IP_TIME_TO_LIVE,
        PROTOCOL_TCP,
        0,
        source,
        destination,
    )
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    ethernet = dst_mac + src_mac + struct.pack("!H", ETHERTYPE_IPV4)
    return ethernet + ip + tcp


def parse_frame(frame: bytes) -> Reply | None:
    """Return the TCP fields of one received Ethernet frame, or None.

    Args:
        frame: The bytes the capture returned, from the first byte of the Ethernet
            header.

    Returns:
        The fields, or None when the frame carries no whole unfragmented IPv4 TCP
        segment. The parser bounds every read on the frame and on the IP total length,
        so the Ethernet padding of a short frame reaches no field.
    """
    if len(frame) < ETHERNET_HEADER_BYTES + IP_HEADER_BYTES:
        return None
    if struct.unpack("!H", frame[12:14])[0] != ETHERTYPE_IPV4:
        return None
    ip = frame[ETHERNET_HEADER_BYTES:]
    if ip[0] >> 4 != 4:
        return None
    ip_header_bytes = (ip[0] & 0x0F) * 4
    total_length = struct.unpack("!H", ip[2:4])[0]
    if ip_header_bytes < IP_HEADER_BYTES or total_length < ip_header_bytes:
        return None
    if total_length > len(ip):
        return None
    if struct.unpack("!H", ip[6:8])[0] & (IP_MORE_FRAGMENTS | IP_FRAGMENT_OFFSET):
        return None
    if ip[9] != PROTOCOL_TCP:
        return None
    segment = ip[ip_header_bytes:total_length]
    if len(segment) < TCP_HEADER_BYTES:
        return None
    data_offset = (segment[12] >> 4) * 4
    if data_offset < TCP_HEADER_BYTES or data_offset > len(segment):
        return None
    src_port, dst_port, _, acknowledgment = struct.unpack("!HHII", segment[:12])
    return Reply(
        src_ip=str(ipaddress.IPv4Address(ip[12:16])),
        dst_ip=str(ipaddress.IPv4Address(ip[16:20])),
        src_port=src_port,
        dst_port=dst_port,
        acknowledgment=acknowledgment,
        flags=segment[13],
        window=struct.unpack("!H", segment[14:16])[0],
        options=segment[TCP_HEADER_BYTES:data_offset],
    )
