"""Packet utility helpers for IPv4/IPv6 support."""

from scapy.all import IP, IPv6


def get_ip_layer(packet):
    """Return the IP layer (v4 or v6) from a packet, or None.

    Checks IPv4 first (most common), then IPv6.
    """
    if IP in packet:
        return packet[IP]
    if IPv6 in packet:
        return packet[IPv6]
    return None


def packet_seconds(packet):
    """Return the capture timestamp of one packet, in seconds, or None.

    A caller ages a state table on this value. It reads no wall clock, because a
    capture file replays faster than real time, and a wall clock would evict state the
    capture still needs.

    Args:
        packet: A network packet.

    Returns:
        The capture timestamp in seconds, or None when the packet carries none.
    """
    if not hasattr(packet, "time"):
        return None
    return float(packet.time)


def get_ttl(packet):
    """Return TTL (IPv4) or Hop Limit (IPv6), or None."""
    if IP in packet:
        return packet[IP].ttl
    if IPv6 in packet:
        return packet[IPv6].hlim
    return None
