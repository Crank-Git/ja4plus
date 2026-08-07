"""Packet utility helpers for IPv4/IPv6 support."""

from scapy.all import IP, IPv6, TCP, UDP

from ja4plus.utils.tunnels import innermost_layer

ENDPOINT_FIELDS = ("src", "dst", "srcport", "dstport")


def packet_endpoints(packet):
    """Return the address pair and the port pair of one packet.

    A fingerprint result carries these four fields instead of the packet that produced
    it. A monitor runs for weeks, and a stored packet holds the whole capture in
    memory.

    The values name the innermost address layer and the innermost port layer. A tunnel
    carries an outer header that the reference does not describe, so an outer address
    would group a value under a stream the reference does not hold.

    Args:
        packet: A network packet.

    Returns:
        A dictionary with the keys `src`, `dst`, `srcport` and `dstport`. A value is
        None when the packet carries no layer that holds it.
    """
    address_layer = innermost_layer(packet, (IP, IPv6))
    port_layer = innermost_layer(packet, (TCP, UDP))
    return {
        "src": getattr(address_layer, "src", None),
        "dst": getattr(address_layer, "dst", None),
        "srcport": getattr(port_layer, "sport", None),
        "dstport": getattr(port_layer, "dport", None),
    }


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
