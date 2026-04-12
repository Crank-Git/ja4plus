"""
JA4L Light Distance/Location Fingerprinting implementation.

JA4L measures the latency between client and server by analyzing
TCP handshake timing, allowing for physical distance estimation.
Format: JA4L-C=<latency_us>_<ttl> and JA4L-S=<latency_us>_<ttl>
"""

import time
import logging
from scapy.all import IP, IPv6, TCP, UDP

logger = logging.getLogger(__name__)
from ja4plus.fingerprinters.base import BaseFingerprinter


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
            proto = 'tcp'
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        else:
            proto = 'udp'
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
            direction = 'forward'
        else:
            conn_key = f"{proto}_{dst_ip}:{dport}_{src_ip}:{sport}"
            direction = 'reverse'

        if conn_key not in self.connections:
            self.connections[conn_key] = {
                'proto': proto,
                'direction': direction,
                'conn_key': conn_key,
                'timestamps': {},
                'ttls': {}
            }

        conn = self.connections[conn_key]
        fingerprint = generate_ja4l(packet, conn)

        if fingerprint:
            self.fingerprints.append({
                'fingerprint': fingerprint,
                'packet': packet,
                'connection': conn_key
            })
            return fingerprint

        return None

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


def generate_ja4l(packet, conn=None):
    """
    Generate JA4L latency fingerprint based on packet timing.

    Uses the TCP 3-way handshake or QUIC handshake to measure one-way latency.
    Time is measured in microseconds.

    Args:
        packet: A network packet
        conn: Connection tracking object with timestamps dict

    Returns:
        JA4L fingerprint string if successful, None otherwise
    """
    if not conn:
        return None

    from ja4plus.utils.packet_utils import get_ip_layer as _get_ip, get_ttl
    if _get_ip(packet) is None:
        return None

    try:
        if 'timestamps' not in conn:
            conn['timestamps'] = {}
        if 'ttls' not in conn:
            conn['ttls'] = {}

        ttl = get_ttl(packet)
        if ttl is None:
            return None

        # Use pcap timestamp if available (for offline analysis), else wall clock
        current_time = float(packet.time) if hasattr(packet, 'time') else time.time()

        # Handle TCP protocol
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags

            # SYN packet (point A) - client initiates
            if tcp_flags & 0x02 == 0x02 and not tcp_flags & 0x10:
                conn['timestamps']['A'] = current_time
                conn['ttls']['client'] = ttl
                return None

            # SYN-ACK packet (point B) - server responds
            elif tcp_flags & 0x12 == 0x12:
                conn['timestamps']['B'] = current_time
                conn['ttls']['server'] = ttl

                if 'A' in conn['timestamps']:
                    # Per FoxIO spec: use raw time difference (not divided by 2)
                    diff = conn['timestamps']['B'] - conn['timestamps']['A']
                    latency = max(1, int(diff * 1000000))
                    return f"JA4L-S={latency}_{ttl}"

            # ACK packet (point C) - client completes handshake
            elif tcp_flags & 0x10 == 0x10 and not tcp_flags & 0x02:
                conn['timestamps']['C'] = current_time

                if 'B' in conn['timestamps']:
                    diff = conn['timestamps']['C'] - conn['timestamps']['B']
                    latency = max(1, int(diff * 1000000))
                    return f"JA4L-C={latency}_{ttl}"

        # Handle QUIC (UDP) protocol
        elif packet.haslayer(UDP) and conn.get('proto') == 'udp':
            is_client = _src_is_client(packet, conn)

            if 'A' not in conn['timestamps'] and is_client:
                conn['timestamps']['A'] = current_time
                conn['ttls']['client'] = ttl

            elif 'A' in conn['timestamps'] and not is_client and 'B' not in conn['timestamps']:
                conn['timestamps']['B'] = current_time
                conn['ttls']['server'] = ttl
                diff = conn['timestamps']['B'] - conn['timestamps']['A']
                latency = max(1, int(diff * 1000000))
                return f"JA4L-S={latency}_{ttl}"

            elif 'B' in conn['timestamps'] and is_client and 'C' not in conn['timestamps']:
                conn['timestamps']['C'] = current_time

            elif 'C' in conn['timestamps'] and not is_client and 'D' not in conn['timestamps']:
                conn['timestamps']['D'] = current_time
                diff = conn['timestamps']['D'] - conn['timestamps']['C']
                latency = max(1, int(diff * 1000000))
                return f"JA4L-C={latency}_{conn['ttls'].get('client', ttl)}"

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

    if conn.get('direction') == 'forward':
        conn_key = conn.get('conn_key', '')
        parts = conn_key.split('_')
        if len(parts) >= 2:
            client_part = parts[1].split(':')[0]
            return src_ip == client_part

    return False
