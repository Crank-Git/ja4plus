"""
JA4L Light Distance/Location Fingerprinting implementation.

JA4L measures the one-way latency between a client and a server. The FoxIO slide at
`technical_details/JA4L.png` names field `a` the "One-way TCP latency in us", so every
value is half of the round-trip time the capture holds.

Format: JA4L-C=<latency_us>_<ttl> and JA4L-S=<latency_us>_<ttl>
"""

import logging
import time
from decimal import Decimal

from scapy.all import IP, IPv6, TCP, UDP

from ja4plus.fingerprinters.base import BaseFingerprinter

logger = logging.getLogger(__name__)

# The TCP flag bits JA4L reads.
TCP_SYN = 0x02
TCP_ACK = 0x10

# A TCP sequence number and an acknowledgement number wrap at 32 bits.
SEQUENCE_MODULUS = 0x100000000

# The long-header bit of a QUIC packet, and the field that holds the packet type.
QUIC_LONG_HEADER = 0x80
QUIC_PACKET_TYPE = 0x30

# The version number of QUIC version 2, from RFC 9369. Version 2 numbers the long-header
# packet types one higher than version 1 does.
QUIC_VERSION_2 = 0x6B3343CF

# The request methods that open an HTTP message. A packet that carries an HTTP message
# does not move JA4L point C. See `_carries_http_message` for the evidence.
HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"TRACE ",
    b"CONNECT ",
    b"PATCH ",
)


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
            }

        conn = self.connections[conn_key]
        fingerprint = generate_ja4l(packet, conn)

        if fingerprint:
            self._record(conn, conn_key, packet, fingerprint)
            return fingerprint

        return None

    def _record(self, conn, conn_key, packet, fingerprint):
        """Hold one fingerprint, and replace the value the connection already holds.

        The FoxIO reference program keeps one JA4L-S value and one JA4L-C value for each
        stream, and it overwrites the value every time a later packet moves the
        measurement point. `tests/foxio_vectors/badcurveball.pcap.json` holds one
        JA4L-C value for a stream that carries two candidate packets, so an
        implementation that appends a second value reports a fingerprint the reference
        does not hold.

        Args:
            conn: The connection state.
            conn_key: The normalized connection key.
            packet: The packet that produced the value.
            fingerprint: The produced value, such as `JA4L-C=2181_64`.
        """
        method, _, _ = fingerprint.partition("=")
        entry = {"fingerprint": fingerprint, "packet": packet, "connection": conn_key}
        position = conn.setdefault("positions", {}).get(method)
        if position is None:
            conn["positions"][method] = len(self.fingerprints)
            self.fingerprints.append(entry)
        else:
            self.fingerprints[position] = entry

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


def packet_microseconds(packet):
    """Return the capture timestamp of one packet, in whole microseconds.

    Args:
        packet: A network packet.

    Returns:
        The timestamp as a whole number of microseconds. Returns the wall clock when
        the packet carries no timestamp, which happens on a live capture.
    """
    value = getattr(packet, "time", None)
    if value is None:
        return int(time.time() * 1000000)
    if not isinstance(value, Decimal):
        # A test builds a packet and sets a float. Read the decimal form of the float,
        # because a binary float multiplied by a million lands one microsecond out.
        value = Decimal(str(value))
    return int(value * 1000000)


def one_way_latency(start_us, end_us):
    """Return the one-way latency between two capture timestamps.

    The FoxIO slide names field `a` the one-way latency, and the FoxIO reference
    program halves the round-trip time to produce it. See `python/common.py` line 182
    of the FoxIO repository.

    Args:
        start_us: The timestamp of the first packet, in microseconds.
        end_us: The timestamp of the second packet, in microseconds.

    Returns:
        Half of the time between the two packets, truncated to a whole microsecond, or
        None when the second packet comes before the first one.
    """
    difference = end_us - start_us
    if difference < 0:
        return None
    return difference // 2


def generate_ja4l(packet, conn=None):
    """
    Generate JA4L latency fingerprint based on packet timing.

    Uses the TCP handshake or the QUIC handshake to measure one-way latency. Time is
    measured in microseconds, and every value is half of the round-trip time.

    Args:
        packet: A network packet
        conn: Connection tracking object with timestamps dict

    Returns:
        JA4L fingerprint string if successful, None otherwise
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

        ttl = get_ttl(packet)
        if ttl is None:
            return None

        timestamp = packet_microseconds(packet)

        if packet.haslayer(TCP):
            return _tcp_fingerprint(packet[TCP], ip_layer, conn, timestamp, ttl)
        if packet.haslayer(UDP) and conn.get("proto") == "udp":
            return _quic_fingerprint(packet[UDP], ip_layer, conn, timestamp, ttl)
        return None
    except (ValueError, TypeError, IndexError, AttributeError) as e:
        logger.debug(f"Packet does not contain JA4L data: {e}")
        return None


def _tcp_fingerprint(tcp, ip_layer, conn, timestamp, ttl):
    """Return the JA4L value one TCP packet produces, or None.

    The FoxIO reference program marks three points on a TCP stream, at `python/ja4.py`
    lines 560 to 572. Point A is the SYN, point B is the SYN-ACK, and point C is a
    packet that carries relative sequence number 1 and relative acknowledgement number
    1. The program keeps the last such packet, so the client Client Hello replaces the
    bare ACK. It reads no direction, so point C is a server packet on
    `gre-sample.pcap`.

    Args:
        tcp: The TCP layer of the packet.
        ip_layer: The address layer of the packet.
        conn: The connection state.
        timestamp: The capture timestamp, in microseconds.
        ttl: The TTL of the packet.

    Returns:
        The JA4L value, or None when the packet marks no point.
    """
    timestamps = conn["timestamps"]
    flags = int(tcp.flags)
    endpoint = (ip_layer.src, int(tcp.sport))

    if flags & TCP_SYN and not flags & TCP_ACK:
        # A retransmitted SYN keeps the first timestamp, because the reference program
        # writes point A once.
        if "A" not in timestamps:
            timestamps["A"] = timestamp
            conn["ttls"]["client"] = ttl
            conn["client_isn"] = int(tcp.seq)
            conn["client_endpoint"] = endpoint
        return None

    if flags & TCP_SYN and flags & TCP_ACK:
        if "B" in timestamps:
            return None
        timestamps["B"] = timestamp
        conn["ttls"]["server"] = ttl
        conn["server_isn"] = int(tcp.seq)
        if "A" not in timestamps:
            return None
        latency = one_way_latency(timestamps["A"], timestamps["B"])
        if latency is None:
            return None
        return f"JA4L-S={latency}_{ttl}"

    if not flags & TCP_ACK:
        return None
    if "B" not in timestamps or "client_isn" not in conn or "server_isn" not in conn:
        return None

    if endpoint == conn.get("client_endpoint"):
        own_isn, peer_isn = conn["client_isn"], conn["server_isn"]
    else:
        own_isn, peer_isn = conn["server_isn"], conn["client_isn"]
    relative_seq = (int(tcp.seq) - own_isn) % SEQUENCE_MODULUS
    relative_ack = (int(tcp.ack) - peer_isn) % SEQUENCE_MODULUS
    if relative_seq != 1 or relative_ack != 1:
        return None

    client_ttl = conn["ttls"].get("client")
    if client_ttl is None:
        return None
    timestamps["C"] = timestamp
    latency = one_way_latency(timestamps["B"], timestamps["C"])
    if latency is None:
        return None
    return f"JA4L-C={latency}_{client_ttl}"


def quic_long_header_type(payload, version_2_offset=1):
    """Return the long-header packet type of one QUIC payload, or None.

    Args:
        payload: The UDP payload, as bytes.
        version_2_offset: The amount QUIC version 2 adds to every packet-type number.

    Returns:
        `initial` for an Initial packet, `handshake` for a Handshake packet, `other`
        for another long-header packet, and None for a short header or a payload that
        is too short.
    """
    if len(payload) < 5 or not payload[0] & QUIC_LONG_HEADER:
        return None
    version = int.from_bytes(payload[1:5], "big")
    if version == 0:
        return None
    packet_type = (payload[0] & QUIC_PACKET_TYPE) >> 4
    if version == QUIC_VERSION_2:
        packet_type -= version_2_offset
    if packet_type == 0:
        return "initial"
    if packet_type == 2:
        return "handshake"
    return "other"


def _quic_destination_id(payload):
    """Return the Destination Connection ID of one QUIC long-header packet, or None."""
    if len(payload) < 6:
        return None
    length = payload[5]
    if len(payload) < 6 + length:
        return None
    return bytes(payload[6 : 6 + length])


def _quic_fingerprint(udp, ip_layer, conn, timestamp, ttl):
    """Return the JA4L value one QUIC packet produces, or None.

    The FoxIO reference program marks four points on a QUIC stream, at `python/ja4.py`
    lines 576 to 587. Point A is the client Initial packet that carries the Client
    Hello, and point B is the server Initial packet that carries the Server Hello. A
    server sends more than one Initial packet, and only the packet that carries the
    Server Hello marks point B. Point C is the last server Handshake packet before the
    first client Handshake packet, and point D is that client Handshake packet.

    The program reads no point on a UDP flow that carries no QUIC long header, so this
    function produces no value for such a flow.

    Args:
        udp: The UDP layer of the packet.
        ip_layer: The address layer of the packet.
        conn: The connection state.
        timestamp: The capture timestamp, in microseconds.
        ttl: The TTL of the packet.

    Returns:
        The JA4L value, or None when the packet marks no point.
    """
    payload = bytes(udp.payload)
    kind = quic_long_header_type(payload)
    if kind is None:
        return None

    timestamps = conn["timestamps"]
    endpoint = (ip_layer.src, int(udp.sport))
    is_client = endpoint == conn.get("client_endpoint")

    if kind == "initial":
        if "A" not in timestamps:
            conn["client_endpoint"] = endpoint
            conn["client_dcid"] = _quic_destination_id(payload)
            timestamps["A"] = timestamp
            conn["ttls"]["client"] = ttl
            return None
        if is_client or "B" in timestamps or not conn.get("client_dcid"):
            return None

        from ja4plus.utils.quic_utils import parse_quic_server_initial

        if parse_quic_server_initial(payload, conn["client_dcid"]) is None:
            return None
        timestamps["B"] = timestamp
        conn["ttls"]["server"] = ttl
        latency = one_way_latency(timestamps["A"], timestamps["B"])
        if latency is None:
            return None
        return f"JA4L-S={latency}_{ttl}"

    if kind != "handshake" or "D" in timestamps:
        return None

    if not is_client:
        # The reference program keeps the last server Handshake packet before the first
        # client Handshake packet.
        timestamps["C"] = timestamp
        return None

    if "C" not in timestamps:
        return None
    client_ttl = conn["ttls"].get("client")
    if client_ttl is None:
        return None
    timestamps["D"] = timestamp
    latency = one_way_latency(timestamps["C"], timestamps["D"])
    if latency is None:
        return None
    return f"JA4L-C={latency}_{client_ttl}"


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
