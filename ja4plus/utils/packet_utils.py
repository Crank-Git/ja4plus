"""
Packet utility helpers for ja4plus fingerprinters.
"""

from scapy.all import IP, IPv6


def get_ip_layer(packet):
    """
    Return the IP or IPv6 layer from a Scapy packet.

    Args:
        packet: A Scapy packet.

    Returns:
        The IP or IPv6 layer, or None if neither is present.
    """
    if IP in packet:
        return packet[IP]
    if IPv6 in packet:
        return packet[IPv6]
    return None
