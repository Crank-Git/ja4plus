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


def get_ttl(packet):
    """Return TTL (IPv4) or Hop Limit (IPv6), or None."""
    if IP in packet:
        return packet[IP].ttl
    if IPv6 in packet:
        return packet[IPv6].hlim
    return None
