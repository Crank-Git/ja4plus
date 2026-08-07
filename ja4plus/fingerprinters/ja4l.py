"""JA4L light distance fingerprints.

JA4L reports the one-way latency of a connection and the observed TTL, so that a
reader estimates the distance between the client and the server. The TCP form reads
the handshake. The QUIC form reads the Initial packets and the Handshake packets.
Format: `JA4L-C=<latency_us>_<ttl>` and `JA4L-S=<latency_us>_<ttl>`.

The reference holds three measurement points on a TCP connection:

- `A` is the first SYN, and it carries the client TTL.
- `B` is the first SYN-ACK, and it carries the server TTL.
- `C` is the last packet that carries the relative sequence number 1 and the relative
  acknowledgement number 1, and that holds no complete HTTP request.

`JA4L-S` is half the time from `A` to `B`. `JA4L-C` is half the time from `B` to `C`.
"""

import time
import logging
from scapy.all import IP, IPv6, TCP, UDP

from ja4plus.fingerprinters.base import BaseFingerprinter
from ja4plus.utils.http_utils import is_http_request
from ja4plus.utils.quic_utils import (
    QUIC_HANDSHAKE,
    QUIC_INITIAL,
    long_header_packet_type,
)

logger = logging.getLogger(__name__)

# FoxIO reports one-way latency, so it halves every measured round-trip time. The
# JA4L material states "One-way TCP latency in us", and every vector holds half of
# the time the capture shows.
LATENCY_DIVISOR = 2

# The reference reads the direction of a QUIC flow from this port. A QUIC flow on
# another port carries no JA4L value, because neither endpoint is then the server.
QUIC_PORT = 443

# A TCP sequence number and acknowledgement number are 32 bits wide, so a relative
# number needs this mask.
SEQUENCE_MASK = 0xFFFFFFFF


class JA4LFingerprinter(BaseFingerprinter):
    """
    JA4L Light Distance/Location Fingerprinting implementation.

    JA4L measures latency between client and server to estimate physical distance.
    """

    def __init__(self):
        """Initialize the fingerprinter."""
        super().__init__()
        self.connections = {}

    def process_packet(self, packet):
        """
        Process a packet and extract JA4L fingerprint if applicable.

        Args:
            packet: A network packet to analyze

        Returns:
            The extracted fingerprint if successful, None otherwise
        """
        if (IP not in packet and IPv6 not in packet) or (TCP not in packet and UDP not in packet):
            return None

        if TCP in packet:
            proto = "tcp"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        else:
            proto = "udp"
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        from ja4plus.utils.packet_utils import get_ip_layer

        ip_layer = get_ip_layer(packet)
        if ip_layer is None:
            return None
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Normalize connection key (ordered src/dst)
        if src_ip < dst_ip or (src_ip == dst_ip and sport < dport):
            conn_key = f"{proto}_{src_ip}:{sport}_{dst_ip}:{dport}"
            direction = "forward"
        else:
            conn_key = f"{proto}_{dst_ip}:{dport}_{src_ip}:{sport}"
            direction = "reverse"

        if conn_key not in self.connections:
            self.connections[conn_key] = {
                "proto": proto,
                "direction": direction,
                "conn_key": conn_key,
                "timestamps": {},
                "ttls": {},
                "isns": {},
            }

        conn = self.connections[conn_key]
        fingerprint = generate_ja4l(packet, conn)

        if not fingerprint:
            return None

        # The reference holds one client value for one connection and overwrites it
        # while the measurement point moves. A later packet therefore replaces the
        # value this fingerprinter already reported, and it adds no second value.
        if fingerprint.startswith("JA4L-C="):
            index = conn.get("client_entry")
            if index is not None:
                self.fingerprints[index]["fingerprint"] = fingerprint
                self.fingerprints[index]["packet"] = packet
                return fingerprint
            conn["client_entry"] = len(self.fingerprints)

        self.fingerprints.append(
            {"fingerprint": fingerprint, "packet": packet, "connection": conn_key}
        )
        return fingerprint

    def reset(self):
        """Reset all fingerprints and connection tracking."""
        super().reset()
        self.connections = {}

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        """Remove stored timing state for the given connection."""
        # JA4L normalizes the key so we must try both orderings
        fwd = f"{proto}_{src_ip}:{src_port}_{dst_ip}:{dst_port}"
        rev = f"{proto}_{dst_ip}:{dst_port}_{src_ip}:{src_port}"
        self.connections.pop(fwd, None)
        self.connections.pop(rev, None)

    def calculate_distance(self, latency_us, propagation_factor=1.6):
        """
        Calculate the physical distance based on JA4L latency.

        Args:
            latency_us: One-way latency in microseconds
            propagation_factor: Propagation delay factor (default: 1.6)

        Returns:
            Distance in miles
        """
        # Speed of light per us in fiber (miles/us)
        speed_of_light = 0.128
        distance = (latency_us * speed_of_light) / propagation_factor
        return distance

    def calculate_distance_km(self, latency_us, propagation_factor=1.6):
        """
        Calculate the physical distance in kilometers.

        Args:
            latency_us: One-way latency in microseconds
            propagation_factor: Propagation delay factor (default: 1.6)

        Returns:
            Distance in kilometers
        """
        speed_of_light_km = 0.206  # km/us in fiber
        distance = (latency_us * speed_of_light_km) / propagation_factor
        return distance

    def estimate_os(self, ttl):
        """
        Estimate the operating system based on TTL value.

        Args:
            ttl: Observed TTL value

        Returns:
            String indicating likely OS or device type
        """
        if ttl <= 64:
            return "Mac, Linux, Phone, or IoT device (initial TTL: 64)"
        elif ttl <= 128:
            return "Windows (initial TTL: 128)"
        else:
            return "Cisco, F5, or Networking Device (initial TTL: 255)"

    def estimate_hop_count(self, ttl):
        """
        Estimate the hop count based on TTL value.

        Args:
            ttl: Observed TTL value

        Returns:
            Estimated hop count
        """
        if ttl <= 64:
            return 64 - ttl
        elif ttl <= 128:
            return 128 - ttl
        else:
            return 255 - ttl


def _packet_microseconds(packet):
    """Return the timestamp of one packet, in microseconds.

    Args:
        packet: A network packet.

    Returns:
        The capture timestamp when the packet carries one, and the wall clock when it
        does not. A capture file replays faster than real time, so an offline read
        needs the capture timestamp.
    """
    seconds = float(packet.time) if hasattr(packet, "time") else time.time()
    return int(round(seconds * 1000000))


def _one_way_latency(start, end):
    """Return the one-way latency between two timestamps, in microseconds.

    Args:
        start: The earlier timestamp, in microseconds.
        end: The later timestamp, in microseconds.

    Returns:
        Half the time between the two timestamps, truncated toward zero.
    """
    return int((end - start) / LATENCY_DIVISOR)


def _relative_numbers(conn, source, target, tcp_layer):
    """Return the relative sequence number and acknowledgement number of one packet.

    Args:
        conn: The connection state.
        source: The (address, port) pair of the sender.
        target: The (address, port) pair of the receiver.
        tcp_layer: The TCP layer of the packet.

    Returns:
        A (sequence, acknowledgement) pair, counted from the initial sequence number
        of each endpoint. Returns None when the capture holds no SYN for one endpoint,
        because a relative number needs that initial sequence number.
    """
    initial = conn.get("isns", {})
    if source not in initial or target not in initial:
        return None
    sequence = (int(tcp_layer.seq) - initial[source]) & SEQUENCE_MASK
    acknowledgement = (int(tcp_layer.ack) - initial[target]) & SEQUENCE_MASK
    return sequence, acknowledgement


def _holds_a_complete_http_request(payload):
    """Report whether the payload holds an HTTP request with its whole header block.

    The reference keeps the timestamps of a packet under the protocol its dissector
    reports. A packet that holds a whole HTTP request reaches a separate cache, so it
    never moves the client measurement point. A packet that holds the first part of a
    request reaches the same cache as any other TCP packet, and it does move the
    point. `http-empty-useragent.pcap` and `latest.pcapng` prove both halves.

    Args:
        payload: The TCP payload bytes.

    Returns:
        True when the payload starts an HTTP request and holds the blank line that
        ends the header block.
    """
    if not is_http_request(payload):
        return False
    return b"\r\n\r\n" in payload or b"\n\n" in payload


def _restart_connection(conn):
    """Drop every measurement point of one connection.

    A later connection reuses the endpoints of a closed one, and the reference counts
    the two separately. Without this call the later connection reads the measurement
    points of the earlier one. It also replaces the client value the fingerprinter
    already reported.
    """
    conn["timestamps"] = {}
    conn["ttls"] = {}
    conn["isns"] = {}
    conn.pop("client_entry", None)


def _tcp_ja4l(packet, conn, ip_layer, ttl, now):
    """Return the JA4L value this TCP packet gives, or None."""
    tcp_layer = packet[TCP]
    flags = int(tcp_layer.flags)
    syn = bool(flags & 0x02)
    ack = bool(flags & 0x10)
    source = (ip_layer.src, int(tcp_layer.sport))
    target = (ip_layer.dst, int(tcp_layer.dport))
    sequence = int(tcp_layer.seq)

    if syn and not ack:
        # A SYN that carries another initial sequence number opens another connection
        # on the same endpoints.
        if "A" in conn["timestamps"] and conn["isns"].get(source) != sequence:
            _restart_connection(conn)
        conn["isns"][source] = sequence
        if "A" in conn["timestamps"]:
            return None
        conn["timestamps"]["A"] = now
        conn["ttls"]["client"] = ttl
        if "B" not in conn["timestamps"]:
            return None
        # A reordered capture holds the SYN-ACK before the SYN. This packet is then
        # the last one that reaches both points of the server value.
        return "JA4L-S={}_{}".format(
            _one_way_latency(conn["timestamps"]["A"], conn["timestamps"]["B"]),
            conn["ttls"]["server"],
        )

    timestamps = conn["timestamps"]
    ttls = conn["ttls"]

    if syn and ack:
        conn["isns"][source] = sequence
        if "B" not in timestamps:
            timestamps["B"] = now
            ttls["server"] = ttl
        if "A" not in timestamps:
            return None
        return "JA4L-S={}_{}".format(
            _one_way_latency(timestamps["A"], timestamps["B"]), ttls["server"]
        )

    if not ack or "B" not in timestamps or "client" not in ttls:
        return None

    # The reference moves the client measurement point to every packet that starts
    # the payload of its sender and acknowledges no payload. That is the bare ACK of
    # the handshake first, and then the first packet of the application handshake.
    if _relative_numbers(conn, source, target, tcp_layer) != (1, 1):
        return None
    if _holds_a_complete_http_request(bytes(tcp_layer.payload)):
        return None

    timestamps["C"] = now
    return "JA4L-C={}_{}".format(_one_way_latency(timestamps["B"], timestamps["C"]), ttls["client"])


def _quic_ja4l(packet, conn, ttl, now):
    """Return the JA4L value this QUIC packet gives, or None."""
    udp_layer = packet[UDP]
    packet_type = long_header_packet_type(bytes(udp_layer.payload))
    if packet_type is None:
        return None
    to_server = int(udp_layer.dport) == QUIC_PORT
    from_server = int(udp_layer.sport) == QUIC_PORT
    # A flow whose two ports are 443 names no server, so the direction of a packet is
    # unknown and every value it gives is a guess.
    if to_server and from_server:
        return None
    timestamps = conn["timestamps"]
    ttls = conn["ttls"]

    if packet_type == QUIC_INITIAL:
        if to_server and "A" not in timestamps:
            timestamps["A"] = now
            ttls["client"] = ttl
        elif from_server and "A" in timestamps and "B" not in timestamps:
            timestamps["B"] = now
            ttls["server"] = ttl
            return "JA4L-S={}_{}".format(
                _one_way_latency(timestamps["A"], timestamps["B"]), ttls["server"]
            )
        return None

    if packet_type != QUIC_HANDSHAKE:
        return None

    # The server sends one to five Handshake packets. The client measurement starts
    # at the last of them, so this point moves until the client answers.
    if from_server and "D" not in timestamps:
        timestamps["C"] = now
        return None

    if to_server and "C" in timestamps and "D" not in timestamps:
        timestamps["D"] = now
        return "JA4L-C={}_{}".format(
            _one_way_latency(timestamps["C"], timestamps["D"]), ttls.get("client", ttl)
        )
    return None


def generate_ja4l(packet, conn=None):
    """Return the JA4L value this packet gives, or None.

    The function reads the measurement points of the connection from `conn` and
    writes the point this packet supplies back into it.

    Args:
        packet: A network packet.
        conn: The connection state, which holds `timestamps`, `ttls` and `isns`.

    Returns:
        A `JA4L-S=` value, a `JA4L-C=` value, or None when the packet supplies no
        value. Returns None for a packet this fingerprinter cannot read.
    """
    if not conn:
        return None

    from ja4plus.utils.packet_utils import get_ip_layer, get_ttl

    ip_layer = get_ip_layer(packet)
    if ip_layer is None:
        return None

    try:
        conn.setdefault("timestamps", {})
        conn.setdefault("ttls", {})
        conn.setdefault("isns", {})

        ttl = get_ttl(packet)
        if ttl is None:
            return None

        now = _packet_microseconds(packet)

        if packet.haslayer(TCP):
            return _tcp_ja4l(packet, conn, ip_layer, ttl, now)
        if packet.haslayer(UDP) and conn.get("proto") == "udp":
            return _quic_ja4l(packet, conn, ttl, now)
        return None
    except (ValueError, TypeError, IndexError, AttributeError) as e:
        logger.debug(f"Packet does not contain JA4L data: {e}")
        return None


def _src_is_client(packet, conn):
    """
    Determine if the source of the packet is the client side.

    Args:
        packet: The packet to analyze
        conn: Connection tracking information

    Returns:
        True if the source is the client, False otherwise
    """
    from ja4plus.utils.packet_utils import get_ip_layer

    ip_layer = get_ip_layer(packet)
    if ip_layer is None:
        return False

    src_ip = ip_layer.src

    if conn.get("direction") == "forward":
        conn_key = conn.get("conn_key", "")
        parts = conn_key.split("_")
        if len(parts) >= 2:
            client_part = parts[1].split(":")[0]
            return src_ip == client_part

    return False
