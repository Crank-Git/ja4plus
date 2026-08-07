"""Packet utility helpers for IPv4/IPv6 support."""

from scapy.all import IP, IPv6, TCP, UDP

from ja4plus.utils.tunnels import innermost_layer

# A TCP client opens a connection with the SYN flag alone. The server answers with the
# SYN flag and the ACK flag. The two packets name the two endpoints exactly, and no
# later packet does.
SYN_FLAG = 0x02
HANDSHAKE_ACK_FLAG = 0x10

# A packet that carries the RST flag opens no connection and accepts none, whatever
# other flag it carries. Every packet is hostile input, and a sender that sets SYN and
# RST together would otherwise name the client of a connection it never opened.
RST_FLAG = 0x04


def opens_a_connection(port_layer, proto):
    """Report whether the packet is a TCP SYN that carries no acknowledgement.

    The sender of that packet is the client of the connection.

    Args:
        port_layer: The TCP layer or the UDP layer of the packet.
        proto: The protocol name of the connection, `tcp` or `udp`.

    Returns:
        True when the packet opens a TCP connection, and False otherwise.
    """
    if proto != "tcp":
        return False
    flags = int(port_layer.flags)
    if flags & RST_FLAG:
        return False
    return bool(flags & SYN_FLAG) and not bool(flags & HANDSHAKE_ACK_FLAG)


def accepts_a_connection(port_layer, proto):
    """Report whether the packet is a TCP SYN that carries an acknowledgement.

    The sender of that packet is the server of the connection. A capture that starts
    after the SYN still holds this packet.

    Args:
        port_layer: The TCP layer or the UDP layer of the packet.
        proto: The protocol name of the connection, `tcp` or `udp`.

    Returns:
        True when the packet accepts a TCP connection, and False otherwise.
    """
    if proto != "tcp":
        return False
    flags = int(port_layer.flags)
    if flags & RST_FLAG:
        return False
    return bool(flags & SYN_FLAG) and bool(flags & HANDSHAKE_ACK_FLAG)


def get_ip_layer(packet):
    """Return the IP layer (v4 or v6) from a packet, or None.

    Checks IPv4 first (most common), then IPv6.
    """
    if IP in packet:
        return packet[IP]
    if IPv6 in packet:
        return packet[IPv6]
    return None


def packet_endpoints(packet):
    """Return the address pair and the port pair of one packet.

    A fingerprint result carries these four fields instead of the packet that produced
    it. A monitor runs for weeks, and a stored packet holds the whole capture in
    memory.

    The address pair names the outer address layer, and the port pair names the
    innermost port layer. The reference reports one tunnelled connection that way.
    `gre-sample.pcap`, `gre-erspan-vxlan.pcap` and `tcpdump-geneve.pcap` each carry an
    inner address that the reference never reports, and each carries an outer port that
    the reference never reports.

    | Capture | Reference address pair | Reference port pair |
    |---|---|---|
    | `gre-sample.pcap` | `172.27.1.66` and `66.59.109.137`, the outer pair | 40264 and 22, the inner pair |
    | `gre-erspan-vxlan.pcap` | `100.20.9.2` and `100.20.9.1`, the outer pair | 65174 and 80, the inner pair |
    | `tcpdump-geneve.pcap` | `20.0.0.2` and `20.0.0.1`, the outer pair | 51225 and 22, the inner pair |

    `_reported_key` in `ja4plus/fingerprinters/ja4l.py` reads the same two layers.

    Args:
        packet: A network packet.

    Returns:
        A dictionary with the keys `src`, `dst`, `srcport` and `dstport`. A value is
        None when the packet carries no layer that holds it.
    """
    address_layer = get_ip_layer(packet)
    port_layer = innermost_layer(packet, (TCP, UDP))
    return {
        "src": getattr(address_layer, "src", None),
        "dst": getattr(address_layer, "dst", None),
        "srcport": getattr(port_layer, "sport", None),
        "dstport": getattr(port_layer, "dport", None),
    }


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
