"""
Packet utility helpers for IPv4/IPv6 compatibility.
"""

from scapy.all import IP, IPv6


def get_ip_layer(packet):
    """
    Return the IP or IPv6 layer from a packet, or None if neither is present.

    Args:
        packet: A scapy packet

    Returns:
        The IP or IPv6 layer, or None
    """
    if IP in packet:
        return packet[IP]
    if IPv6 in packet:
        return packet[IPv6]
    return None


def get_ttl(packet):
    """
    Return the TTL (IPv4) or hop limit (IPv6) from a packet, or None.

    Args:
        packet: A scapy packet

    Returns:
        Integer TTL/hop-limit value, or None
    """
    if IP in packet:
        return packet[IP].ttl
    if IPv6 in packet:
        return packet[IPv6].hlim
    return None
