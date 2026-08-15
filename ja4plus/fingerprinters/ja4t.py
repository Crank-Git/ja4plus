"""
JA4T TCP Client Fingerprinting implementation.
"""

# This import makes every annotation a string. No annotation therefore evaluates at
# import time, and a forward reference needs no quotation mark.
from __future__ import annotations

import logging

from scapy.all import TCP, Packet

from ja4plus.fingerprinters.base import BaseFingerprinter
from ja4plus.utils.icmp_quoted import quoted_tcp_header
from ja4plus.utils.packet_utils import packet_endpoints, packet_seconds
from ja4plus.utils.state_table import BoundedStateTable
from ja4plus.utils.tcp_options import tcp_prefix, tcp_prefix_from_header

logger = logging.getLogger(__name__)

TCP_SYN_FLAG = 0x02
TCP_ACK_FLAG = 0x10

# `rust/ja4/src/tcp.rs` returns early when the connection already holds a client, so one
# connection produces one JA4T value. This table names the connections that already
# produced one. A monitor reads a SYN for every connection on the wire, so the table
# carries a maximum entry count and a maximum age. `connections` in
# `ja4plus/fingerprinters/ja4ssh.py` holds the same two values.
MAX_TRACKED_CONNECTIONS = 10000
CONNECTION_TIMEOUT_SECONDS = 600

# The key names one connection: the client address and port, then the server address and
# port. `_connection_key` builds it, and `connections` stores it.
ConnectionKey = tuple[str, int, str, int]


class JA4TFingerprinter(BaseFingerprinter):
    """
    JA4T TCP Client Fingerprinting implementation.

    JA4T fingerprints TCP client behavior based on TCP options and window sizes.
    Format: <window_size>_<options>_<mss>_<wscale>
    Example: 29200_2-4-8-1-3_1424_7

    One connection produces one value, from its first SYN. `docs/specs/foxio/JA4T.md`
    states the rule as R9, and #215 records it as D4.
    """

    def __init__(self, thread_safe: bool = True) -> None:
        """Initialize the fingerprinter and its connection table."""
        super().__init__(thread_safe=thread_safe)
        self.connections = BoundedStateTable(
            max_connections=MAX_TRACKED_CONNECTIONS,
            max_connection_age=CONNECTION_TIMEOUT_SECONDS,
        )

    def process_packet(self, packet: Packet) -> str | None:
        """
        Process a packet and extract JA4T fingerprint if applicable.

        Args:
            packet: A network packet to analyze

        Returns:
            The extracted fingerprint if successful, None otherwise. A SYN that repeats
            the first SYN of its connection produces None.
        """
        with self._lock:
            fingerprint = generate_ja4t(packet, self.connections)
            if fingerprint:
                self.add_fingerprint(fingerprint, packet)
                return fingerprint
            return None

    def reset(self) -> None:
        """Reset the collected fingerprints and the connection table."""
        with self._lock:
            super().reset()
            self.connections.clear()

    def cleanup_connection(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str
    ) -> None:
        """Remove the stored connection, so a later SYN produces a value again.

        A SYN travels from the client to the server, so the key names the client first.
        The caller names either direction, so both orderings are dropped.
        """
        with self._lock:
            self.connections.pop((src_ip, src_port, dst_ip, dst_port), None)
            self.connections.pop((dst_ip, dst_port, src_ip, src_port), None)


def _connection_key(packet: Packet) -> ConnectionKey | None:
    """Return the connection key of one SYN packet, or None.

    Every SYN of one connection travels from the client to the server, so the packet
    order names the connection and nothing normalizes it.
    """
    endpoints = packet_endpoints(packet)
    if endpoints["src"] is None or endpoints["srcport"] is None:
        return None
    return (endpoints["src"], endpoints["srcport"], endpoints["dst"], endpoints["dstport"])


def _first_syn_of_connection(
    packet: Packet,
    connections: BoundedStateTable | None,
    key: ConnectionKey | None = None,
) -> bool:
    """Report whether this SYN is the first SYN of its connection.

    Args:
        packet: The packet that announces the SYN. It is the SYN itself, or an ICMP error
            message that quotes it.
        connections: A `BoundedStateTable` that names the connections that already
            produced a value, or None when the caller holds no connection state.
        key: The connection key, or None when the packet itself names the connection.

    Returns:
        True when the connection produces a value. A caller that holds no table reads
        every SYN, and so does a packet that names no connection.
    """
    if connections is None:
        return True
    if key is None:
        key = _connection_key(packet)
    if key is None:
        return True
    now = packet_seconds(packet)
    if now is not None:
        # The packet announces its own time, and the announcement runs the age pass. A
        # capture replays faster than real time, so the table reads no wall clock.
        connections.on_packet(now)
    if key in connections:
        return False
    connections[key] = True
    return True


def _generate_from_quoted_header(
    packet: Packet, connections: BoundedStateTable | None
) -> str | None:
    """Return the JA4T value of the connection an ICMP error message reports.

    The maintainer ruled on 2026-08-14, under `Crank-Git/ja4plus-go#484`, and the
    library reads the TCP header that an ICMP error message quotes.
    `wireshark/source/packet-ja4.c:1261` matches the field abbreviation `tcp.flags`
    anywhere in the protocol tree, so the dissector writes a value for such a frame.
    `scapy` decodes that header as `TCPerror`, so `haslayer(TCP)` reports false and the
    reader before #610 produced nothing. #484 is the reversal path, and a reversal changes
    both repositories.

    The quoted header names the connection, and the outer address pair of the message
    names a router and the client. R9 gives one value to one connection, so the key reads
    the quoted header. A monitor that reads the SYN itself therefore produces one value,
    and the message that reports that same SYN produces no second one.

    Args:
        packet: A network packet that carries no TCP layer.
        connections: A `BoundedStateTable` that names the connections that already
            produced a value, or None when the caller holds no connection state.

    Returns:
        The fingerprint, or None when the packet carries no ICMP error message that quotes
        a SYN.
    """
    quoted = quoted_tcp_header(packet)
    if quoted is None:
        return None

    if not (quoted.flags & TCP_SYN_FLAG) or (quoted.flags & TCP_ACK_FLAG):
        return None

    value = tcp_prefix_from_header(quoted.header)

    key = (quoted.src, quoted.sport, quoted.dst, quoted.dport)
    if not _first_syn_of_connection(packet, connections, key):
        return None

    return value


def generate_ja4t(packet: Packet, connections: BoundedStateTable | None = None) -> str | None:
    """
    Generate JA4T fingerprint from TCP SYN packet.

    Format: <window_size>_<options>_<mss>_<wscale>
    Example: 64240_2-1-3-1-4_1460_8

    TCP options use IANA numbers: 0=EOL, 1=NOP, 2=MSS, 3=WScale, 4=SACK, 8=Timestamp
    Options preserve original order per JA4T spec (never sorted).

    Args:
        packet: A network packet to analyze.
        connections: A `BoundedStateTable` that names the connections that already
            produced a value. A caller that holds no table reads every SYN, so the
            module function alone reads one packet.

    Returns:
        The fingerprint, or None when the packet carries no JA4T value.
    """
    try:
        if not packet.haslayer(TCP):
            return _generate_from_quoted_header(packet, connections)

        tcp = packet[TCP]

        # Only process SYN packets (not SYN-ACK)
        if not (tcp.flags & TCP_SYN_FLAG) or (tcp.flags & TCP_ACK_FLAG):
            return None

        # The reader runs before the gate marks the connection. A packet the reader
        # cannot read produces no value, and a connection that produced no value must
        # stay open for the SYN that follows it.
        value = tcp_prefix(tcp)

        if not _first_syn_of_connection(packet, connections):
            return None

        return value

    except (ValueError, TypeError, IndexError, AttributeError) as e:
        logger.debug(f"Packet does not contain JA4T data: {e}")
        return None
