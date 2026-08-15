"""Read the TCP header that an ICMP error message quotes.

The maintainer ruled on 2026-08-14, under `Crank-Git/ja4plus-go#484`, and the library
reads that header. `wireshark/source/packet-ja4.c:1261` matches the field abbreviation
`tcp.flags` anywhere in the protocol tree, so the dissector writes a JA4T value for such a
frame. `internal/parser/icmp_quoted.go` of `Crank-Git/ja4plus-go` holds the same reading,
and #610 carries this half.

**The quoted datagram is hostile input.** It carries four length fields, and each one
names bytes the message need not hold. The reader bounds the IP header length, the IP
total length, the TCP data offset and the TCP option list before it slices. A reader that
cannot read the quoted header returns nothing, and it raises nothing.

**The reader calls no `scapy` dissector on the quoted datagram.** `TCP(bytes)` raises
`struct.error` on a truncated option, which `generate_ja4t` catches nowhere. A run of
200000 random 20-byte to 60-byte headers raised it 9 times, and #610 records that
measurement. `readQuotedTCPFields` of the Go port declines `DecodeFromBytes` for the
matching defect of `gopacket`, which `Crank-Git/ja4plus-go#510` records.

The reader reads an IPv4 header alone, because no capture of the corpus carries an ICMPv6
error message.
"""

# This import makes every annotation a string. No annotation therefore evaluates at
# import time, and a forward reference needs no quotation mark.
from __future__ import annotations

import logging
from typing import NamedTuple

from scapy.all import Packet
from scapy.layers.inet import ICMP

logger = logging.getLogger(__name__)

# RFC 792 gives the quoted header to an error message alone. An informational message
# carries an identifier field and a sequence number field in place of it. Verified
# against https://www.rfc-editor.org/rfc/rfc792.txt (retrieved 2026-08-15).
DESTINATION_UNREACHABLE = 3
SOURCE_QUENCH = 4
REDIRECT = 5
TIME_EXCEEDED = 11
PARAMETER_PROBLEM = 12
ICMP_ERROR_TYPES = frozenset(
    {DESTINATION_UNREACHABLE, SOURCE_QUENCH, REDIRECT, TIME_EXCEEDED, PARAMETER_PROBLEM}
)

# The shortest IPv4 header and the shortest TCP header, each in bytes.
IP_HEADER_BYTES = 20
TCP_HEADER_BYTES = 20

# The offsets of the IPv4 header fields the reader bounds or tests.
VERSION_BYTE = 0
TOTAL_LENGTH_OFFSET = 2
FRAGMENT_OFFSET = 6
PROTOCOL_OFFSET = 9
SOURCE_ADDRESS_OFFSET = 12
DESTINATION_ADDRESS_OFFSET = 16

IP_VERSION_4 = 4
IP_PROTOCOL_TCP = 6

# The low 13 bits of the flag field hold the fragment offset. A value other than zero
# names a later fragment, which carries no transport header.
FRAGMENT_OFFSET_MASK = 0x1FFF

# The high half of byte 12 of the TCP header holds the data offset, in 32-bit words.
DATA_OFFSET_BYTE = 12


class QuotedHeader(NamedTuple):
    """The TCP header of the connection an ICMP error message reports.

    Attributes:
        src: The address the quoted IPv4 header names as the source.
        dst: The address the quoted IPv4 header names as the destination.
        header: The TCP header bytes, from the first byte to the end of the option list.
    """

    src: str
    dst: str
    header: bytes

    @property
    def sport(self) -> int:
        """Return the port the quoted TCP header names as the source."""
        return int.from_bytes(self.header[0:2], "big")

    @property
    def dport(self) -> int:
        """Return the port the quoted TCP header names as the destination."""
        return int.from_bytes(self.header[2:4], "big")

    @property
    def flags(self) -> int:
        """Return the flag byte of the quoted TCP header."""
        return self.header[13]


def _address(quoted: bytes, offset: int) -> str:
    """Return one IPv4 address of the quoted datagram in dotted form.

    Args:
        quoted: The quoted IPv4 datagram.
        offset: The offset of the address field.

    Returns:
        The four octets, joined with `.`.
    """
    return ".".join(str(octet) for octet in quoted[offset : offset + 4])


def read_quoted_header(quoted: bytes) -> QuotedHeader | None:
    """Return the TCP header that a quoted IPv4 datagram holds.

    Args:
        quoted: The bytes an ICMP error message quotes.

    Returns:
        The quoted header, or None for every input that states a length the argument does
        not hold. It returns None for an IP version other than 4, for a protocol other
        than TCP, and for a later fragment.
    """
    if len(quoted) < IP_HEADER_BYTES:
        return None

    if quoted[VERSION_BYTE] >> 4 != IP_VERSION_4:
        return None

    # A declared total length above the carried length names bytes the message never
    # quotes, so the read keeps the carried length. A declared length below it ends the
    # datagram, and the trailing bytes belong to no quoted packet.
    end = len(quoted)
    declared = int.from_bytes(quoted[TOTAL_LENGTH_OFFSET : TOTAL_LENGTH_OFFSET + 2], "big")
    if declared < end:
        end = declared

    header_length = (quoted[VERSION_BYTE] & 0x0F) * 4
    if header_length < IP_HEADER_BYTES or header_length > end:
        return None

    # A later fragment of the quoted datagram carries no transport header, so the bytes
    # at the header offset hold payload.
    flags = int.from_bytes(quoted[FRAGMENT_OFFSET : FRAGMENT_OFFSET + 2], "big")
    if flags & FRAGMENT_OFFSET_MASK != 0:
        return None

    if quoted[PROTOCOL_OFFSET] != IP_PROTOCOL_TCP:
        return None

    transport = quoted[header_length:end]
    if len(transport) < TCP_HEADER_BYTES:
        return None

    data_offset = (transport[DATA_OFFSET_BYTE] >> 4) * 4
    if data_offset < TCP_HEADER_BYTES or data_offset > len(transport):
        return None

    return QuotedHeader(
        src=_address(quoted, SOURCE_ADDRESS_OFFSET),
        dst=_address(quoted, DESTINATION_ADDRESS_OFFSET),
        header=transport[:data_offset],
    )


def quoted_tcp_header(packet: Packet) -> QuotedHeader | None:
    """Return the TCP header that an ICMP error message of one packet quotes.

    Args:
        packet: A network packet.

    Returns:
        The quoted header, or None when the packet carries no ICMP error message and None
        when the quoted datagram holds no whole TCP header.
    """
    if not packet.haslayer(ICMP):
        return None

    icmp = packet[ICMP]
    if icmp.type not in ICMP_ERROR_TYPES:
        return None

    # `scapy` dissects the quoted datagram as `IPerror`, and `original` holds the bytes
    # that dissection read. A rebuild from the dissected layers writes its own checksum,
    # so the reader reads the captured bytes instead.
    quoted = getattr(icmp.payload, "original", b"") or b""
    return read_quoted_header(bytes(quoted))
