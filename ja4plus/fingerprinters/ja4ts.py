"""
JA4TS TCP Server Response Fingerprinting implementation.
"""

import logging
import math

from scapy.all import TCP

from ja4plus.fingerprinters.base import BaseFingerprinter
from ja4plus.utils.packet_utils import packet_endpoints, packet_seconds

logger = logging.getLogger(__name__)

# The deleted FoxIO file `technical_details/JA4T.md` states both bounds: "The max is 10
# retransmissions counted and the timeout is 2 minutes after the last SYNACK."
# `zeek/ja4t/main.zeek:185` stops at ten delays and corroborates the first.
MAX_SYN_ACK_DELAYS = 10
SYN_ACK_TIMEOUT_SECONDS = 120

# FoxIO bounds the delay list and states no bound on the connection count. A monitor
# reads a SYN-ACK for every connection on the wire, so this table needs one of its own.
# `MAX_HANDSHAKE_CONNECTIONS` in `ja4plus/fingerprinters/ja4ssh.py` holds the same value,
# and this table drops the oldest half the same way.
MAX_TRACKED_CONNECTIONS = 1000


def _delay_seconds(later, earlier):
    """Return the delay between two capture timestamps, in whole seconds.

    `timediff` in `wireshark/source/packet-ja4.c` calls the C `round`, which carries a
    half away from zero. The Python built-in `round` carries a half to the even number,
    so it writes `0` for a delay of half a second where the dissector writes `1`.

    Args:
        later: The capture timestamp of the later packet, in seconds.
        earlier: The capture timestamp of the earlier packet, in seconds.

    Returns:
        The delay in whole seconds.
    """
    return math.floor((later - earlier) + 0.5)


class SynAckTracker:
    """Holds the SYN-ACK arrival times that part e of JA4TS reads.

    One entry holds the capture timestamps of one connection. The entry count and the
    entry age both hold a bound, because a monitor runs for weeks.
    """

    def __init__(self):
        self.times = {}

    def clear(self):
        """Drop every connection."""
        self.times.clear()

    def drop(self, key):
        """Drop one connection."""
        self.times.pop(key, None)

    def record(self, key, now):
        """Store one SYN-ACK time and return the delay list that part e writes.

        Args:
            key: The connection key of the SYN-ACK packet.
            now: The capture timestamp of the SYN-ACK packet, in seconds.

        Returns:
            The delay of each SYN-ACK after the first, in whole seconds. The list is
            empty for the first SYN-ACK of a connection.
        """
        self._expire(now)
        stamps = self.times.get(key)
        if stamps is None:
            self._evict()
            stamps = []
            self.times[key] = stamps
        # A retransmission past the bound changes no fingerprint, so the packet only
        # keeps the entry alive. FoxIO counts ten retransmissions and no more.
        if len(stamps) <= MAX_SYN_ACK_DELAYS:
            stamps.append(now)
        return [_delay_seconds(stamps[i], stamps[i - 1]) for i in range(1, len(stamps))]

    def _expire(self, now):
        """Drop every connection whose last SYN-ACK is older than the timeout.

        The age reads the capture timestamp and no wall clock, because a capture file
        replays faster than real time.
        """
        stale = [
            key for key, stamps in self.times.items() if now - stamps[-1] > SYN_ACK_TIMEOUT_SECONDS
        ]
        for key in stale:
            del self.times[key]

    def _evict(self):
        """Drop the oldest half of the table when the table is full.

        A dictionary keeps its insertion order, so the oldest entry comes first.
        """
        if len(self.times) < MAX_TRACKED_CONNECTIONS:
            return
        for key in list(self.times)[: MAX_TRACKED_CONNECTIONS // 2]:
            del self.times[key]


class JA4TSFingerprinter(BaseFingerprinter):
    """
    JA4TS TCP Server Response Fingerprinting implementation.

    JA4TS fingerprints TCP server behavior based on SYN-ACK responses.
    Format: <window_size>_<options>_<mss>_<wscale>_<synack_delays>
    Example: 14600_2-1-3-4-1-1_1460_0

    Part e holds the delay between each SYN-ACK of the connection, and the fingerprint
    omits it when the server answers once.
    """

    def __init__(self):
        """Initialize the fingerprinter and its SYN-ACK table."""
        super().__init__()
        self.syn_ack_times = SynAckTracker()

    def process_packet(self, packet):
        """
        Process a packet and extract JA4TS fingerprint if applicable.

        Args:
            packet: A network packet to analyze

        Returns:
            The extracted fingerprint if successful, None otherwise
        """
        fingerprint = generate_ja4ts(packet, self.syn_ack_times)
        if fingerprint:
            self.add_fingerprint(fingerprint, packet)
            return fingerprint
        return None

    def reset(self):
        """Reset the collected fingerprints and the SYN-ACK table."""
        super().reset()
        self.syn_ack_times.clear()

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        """Remove the stored SYN-ACK times of the given connection.

        The key names the server first, because every SYN-ACK travels from the server.
        The caller names either direction, so both orderings are dropped.
        """
        self.syn_ack_times.drop((src_ip, src_port, dst_ip, dst_port))
        self.syn_ack_times.drop((dst_ip, dst_port, src_ip, src_port))


def _connection_key(packet):
    """Return the connection key of one SYN-ACK packet, or None.

    Every SYN-ACK of one connection travels from the server to the client, so the
    packet order names the connection without normalization.
    """
    endpoints = packet_endpoints(packet)
    if endpoints["src"] is None or endpoints["srcport"] is None:
        return None
    return (endpoints["src"], endpoints["srcport"], endpoints["dst"], endpoints["dstport"])


def _part_e(packet, tracker):
    """Return part e of the fingerprint, with its leading `_`, or an empty string.

    Args:
        packet: The SYN-ACK packet.
        tracker: A `SynAckTracker`, or None when the caller holds no connection state.

    Returns:
        The delay list, or an empty string when the server answered once. The deleted
        FoxIO file states the omission: "If no retransmissions are seen, as there
        shouldn't be in normal network communications, the fingerprint will omit
        section e."
    """
    if tracker is None:
        return ""
    now = packet_seconds(packet)
    key = _connection_key(packet)
    if now is None or key is None:
        return ""
    delays = tracker.record(key, now)
    if not delays:
        return ""
    return "_" + "-".join(str(delay) for delay in delays)


def generate_ja4ts(packet, tracker=None):
    """
    Generate JA4TS fingerprint from TCP SYN-ACK packet.

    Format: <window_size>_<options>_<mss>_<wscale>_<synack_delays>
    Example: 14600_2-1-3-4-1-1_1460_0

    TCP options use IANA numbers: 0=EOL, 1=NOP, 2=MSS, 3=WScale, 4=SACK, 8=Timestamp
    Options preserve original order per spec (never sorted).

    Args:
        packet: A network packet to analyze.
        tracker: A `SynAckTracker` that holds the SYN-ACK times of each connection.
            Part e reads the delay between two SYN-ACK packets, so a caller that holds
            no tracker reads one packet and produces four parts.

    Returns:
        The fingerprint, or None when the packet carries no JA4TS value.
    """
    try:
        if not packet.haslayer(TCP):
            return None

        tcp = packet[TCP]

        # Only process SYN-ACK packets (server response)
        if not (tcp.flags & 0x12 == 0x12):  # SYN+ACK flags
            return None

        # Get window size
        window_size = str(tcp.window)

        # Parse TCP options - preserve order as seen
        options = []
        mss = "0"
        wscale = "0"

        # Process options in the order they appear
        for opt in tcp.options:
            opt_name = opt[0]
            if opt_name == "MSS":
                options.append("2")
                mss = str(int(opt[1]))
            elif opt_name == "NOP":
                options.append("1")
            elif opt_name == "WScale":
                options.append("3")
                wscale = str(opt[1])
            elif opt_name == "SAckOK":
                options.append("4")
            elif opt_name == "Timestamp":
                options.append("8")
            elif opt_name == "EOL":
                options.append("0")

        # Join with dashes - maintain original option ordering
        options_str = "-".join(options) if options else "0"

        # Format: window_options_mss_wscale_synackdelays
        ja4ts = f"{window_size}_{options_str}_{mss}_{wscale}{_part_e(packet, tracker)}"

        return ja4ts

    except (ValueError, TypeError, IndexError, AttributeError) as e:
        logger.debug(f"Packet does not contain JA4TS data: {e}")
        return None
