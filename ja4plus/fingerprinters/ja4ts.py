"""
JA4TS TCP Server Response Fingerprinting implementation.
"""

import logging
import math

from scapy.all import TCP

from ja4plus.fingerprinters.base import BaseFingerprinter
from ja4plus.utils.packet_utils import packet_endpoints, packet_seconds
from ja4plus.utils.state_table import BoundedStateTable

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

# The two references disagree on the flag combination that names a RST packet.
# `zeek/ja4t/main.zeek:167` tests the RST bit alone, and
# `wireshark/source/packet-ja4.c:1296` tests `tcp_flags == 0x004` for equality, so the
# dissector reads no RST that also carries ACK. The deleted FoxIO file writes "a RST
# packet" and names no flag combination, so this project reads the bit.
# `docs/specs/foxio/JA4T.md` R13 records the reading.
TCP_RST_FLAG = 0x04
TCP_SYN_ACK_FLAGS = 0x12


def _delay_seconds(later, earlier):
    """Return the delay between two capture timestamps, in whole seconds.

    `timediff` in `wireshark/source/packet-ja4.c` calls the C `round`, which carries a
    half away from zero. The Python built-in `round` carries a half to the even number,
    so it writes `0` for a delay of half a second where the dissector writes `1`.

    `math.floor(delay + 0.5)` also fails to match, because it carries a negative half
    towards zero and writes `0` for `-0.5` where the dissector writes `-1`. A capture
    that holds a SYN-ACK out of order produces a negative delay, and every packet is
    hostile input, so this reads the sign separately.

    Args:
        later: The capture timestamp of the later packet, in seconds.
        earlier: The capture timestamp of the earlier packet, in seconds.

    Returns:
        The delay in whole seconds.
    """
    delay = later - earlier
    return int(math.copysign(math.floor(abs(delay) + 0.5), delay))


def _delay_list(stamps):
    """Return the delay between each stored SYN-ACK, in whole seconds.

    Args:
        stamps: The capture timestamps of one connection, in arrival order.

    Returns:
        One delay for each SYN-ACK after the first. The list is empty for a connection
        the server answered once.
    """
    return [_delay_seconds(stamps[i], stamps[i - 1]) for i in range(1, len(stamps))]


class SynAckTracker:
    """Holds what a later packet of one connection needs to write a JA4TS value.

    `times` holds the capture timestamps of one connection, which part e reads.
    `prefixes` holds part a through part d of the first SYN-ACK, which the RST value
    reads. The entry count and the entry age both hold a bound, because a monitor runs
    for weeks.

    The two tables hold the same keys, and #285 states the one mechanism that keeps them
    so: `times` evicts, and its eviction hook removes the same key from `prefixes`. Every
    other path writes both tables in the same call. `record` stores into `times` before
    it stores into `prefixes`, so the hook runs before the new prefix arrives and
    `prefixes` never passes the count of `times`.

    `prefixes` receives no packet, so its own age pass never runs and its own count bound
    never fires. Both bounds are a second limit that the hook keeps the table away from.
    The eviction count of `prefixes` therefore reports what the hook removed.
    """

    def __init__(self):
        # The age pass runs on each SYN-ACK packet, because a connection sends few of
        # them and the default pass of `BoundedStateTable` waits for 1000 packets.
        self.times = BoundedStateTable(
            max_connections=MAX_TRACKED_CONNECTIONS,
            max_connection_age=SYN_ACK_TIMEOUT_SECONDS,
            eviction_interval=1,
            on_eviction=self._drop_prefix,
        )
        self.prefixes = BoundedStateTable(
            max_connections=MAX_TRACKED_CONNECTIONS,
            max_connection_age=SYN_ACK_TIMEOUT_SECONDS,
        )

    def _drop_prefix(self, key):
        """Remove the stored parts of a connection that `times` evicted.

        Args:
            key: The connection key that `times` removed.
        """
        self.prefixes.evict_key(key)

    def clear(self):
        """Drop every connection."""
        self.times.clear()
        self.prefixes.clear()

    def drop(self, key):
        """Drop one connection."""
        self.times.pop(key, None)
        self.prefixes.pop(key, None)

    def record(self, key, now, prefix):
        """Store one SYN-ACK and return the delay list that part e writes.

        Args:
            key: The connection key of the SYN-ACK packet.
            now: The capture timestamp of the SYN-ACK packet, in seconds.
            prefix: Part a through part d of the SYN-ACK packet.

        Returns:
            The delay of each SYN-ACK after the first, in whole seconds. The list is
            empty for the first SYN-ACK of a connection.
        """
        # The packet announces its own time, and the announcement runs the age pass.
        # A capture replays faster than real time, so the table reads no wall clock.
        self.times.on_packet(now)
        stamps = self.times.get(key)
        if stamps is None:
            stamps = []
            self.times[key] = stamps
            # A RST packet carries no window size and no option, so the connection keeps
            # the parts of its first SYN-ACK. `zeek/ja4t/main.zeek:177-178` reads the
            # first SYN-ACK too, and it never replaces the stored parts.
            self.prefixes[key] = prefix
        # FoxIO counts ten retransmissions and no more, so the eleventh timestamp is the
        # last one this entry stores. A later SYN-ACK changes no fingerprint, and it does
        # not renew the entry either, so the entry ages from the tenth retransmission.
        if len(stamps) <= MAX_SYN_ACK_DELAYS:
            stamps.append(now)
        return _delay_list(stamps)

    def reset_value(self, key, now):
        """Return the JA4TS value that a RST on one connection produces, or None.

        The deleted FoxIO file states the rule: "the final TCP packet, a RST packet,
        should be appended to the last JA4TS denoted with 'R' and its delay."

        Args:
            key: The connection key of the RST packet, which names the server first.
            now: The capture timestamp of the RST packet, in seconds.

        Returns:
            The value, or None when the connection holds no delay. Both implementations
            nest the RST branch inside the delay branch, so a connection the server
            answered once carries no RST suffix.
        """
        # A RST packet is a packet, and the announcement runs the age pass on it too.
        self.times.on_packet(now)
        stamps = self.times.get(key)
        if stamps is None or len(stamps) < 2:
            return None
        delays = "-".join(str(delay) for delay in _delay_list(stamps))
        return f"{self.prefixes[key]}_{delays}-R{_delay_seconds(now, stamps[-1])}"


class JA4TSFingerprinter(BaseFingerprinter):
    """
    JA4TS TCP Server Response Fingerprinting implementation.

    JA4TS fingerprints TCP server behavior based on SYN-ACK responses.
    Format: <window_size>_<options>_<mss>_<wscale>_<synack_delays>
    Example: 14600_2-1-3-4-1-1_1460_0

    Part e holds the delay between each SYN-ACK of the connection, and the fingerprint
    omits it when the server answers once.

    A RST that the server sends on a connection that already holds a delay appends `R`
    and its own delay to part e. That value reads part a through part d from the stored
    connection, because a RST packet carries neither a window size nor an option.
    """

    def __init__(self, thread_safe=True):
        """Initialize the fingerprinter and its SYN-ACK table."""
        super().__init__(thread_safe=thread_safe)
        # The tracker holds no lock of its own. Every caller of it runs inside a method
        # of this fingerprinter, and that method holds the lock of this fingerprinter.
        self.syn_ack_times = SynAckTracker()

    def process_packet(self, packet):
        """
        Process a packet and extract JA4TS fingerprint if applicable.

        Args:
            packet: A network packet to analyze

        Returns:
            The extracted fingerprint if successful, None otherwise
        """
        with self._lock:
            fingerprint = generate_ja4ts(packet, self.syn_ack_times)
            if fingerprint:
                self.add_fingerprint(fingerprint, packet)
                return fingerprint
            return None

    def reset(self):
        """Reset the collected fingerprints and the connection table."""
        with self._lock:
            super().reset()
            self.syn_ack_times.clear()

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        """Remove the stored SYN-ACK times and stored parts of the given connection.

        The key names the server first, because every SYN-ACK travels from the server.
        The caller names either direction, so both orderings are dropped.
        """
        with self._lock:
            self.syn_ack_times.drop((src_ip, src_port, dst_ip, dst_port))
            self.syn_ack_times.drop((dst_ip, dst_port, src_ip, src_port))


def _connection_key(packet):
    """Return the connection key of one SYN-ACK packet or one RST packet, or None.

    Every SYN-ACK of one connection travels from the server to the client, so the
    packet order names the connection without normalization. A RST that the server sends
    travels the same way and produces the same key. A client RST reverses the key, so it
    finds no connection.
    """
    endpoints = packet_endpoints(packet)
    if endpoints["src"] is None or endpoints["srcport"] is None:
        return None
    return (endpoints["src"], endpoints["srcport"], endpoints["dst"], endpoints["dstport"])


def _part_e(packet, tracker, prefix):
    """Return part e of the fingerprint, with its leading `_`, or an empty string.

    Args:
        packet: The SYN-ACK packet.
        tracker: A `SynAckTracker`, or None when the caller holds no connection state.
        prefix: Part a through part d of the SYN-ACK packet.

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
    delays = tracker.record(key, now, prefix)
    if not delays:
        return ""
    return "_" + "-".join(str(delay) for delay in delays)


def _reset_value(packet, tracker):
    """Return the JA4TS value that one RST packet produces, or None.

    Args:
        packet: The RST packet.
        tracker: A `SynAckTracker`, or None when the caller holds no connection state.

    Returns:
        The value, or None when the connection holds no delay. A RST packet carries no
        window size and no option, so a caller that holds no tracker reads nothing from
        it.
    """
    if tracker is None:
        return None
    now = packet_seconds(packet)
    key = _connection_key(packet)
    if now is None or key is None:
        return None
    return tracker.reset_value(key, now)


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
            no tracker reads one packet and produces four parts. The RST value reads the
            stored connection alone, so a caller that holds no tracker reads no RST.

    Returns:
        The fingerprint, or None when the packet carries no JA4TS value. A RST packet
        produces a value only on a connection that already holds a delay.
    """
    try:
        if not packet.haslayer(TCP):
            return None

        tcp = packet[TCP]

        # The RST branch comes first, because a RST packet ends the connection and
        # `zeek/ja4t/main.zeek:167` reads the RST bit before it reads the SYN-ACK flags.
        if tcp.flags & TCP_RST_FLAG:
            return _reset_value(packet, tracker)

        # Only process SYN-ACK packets (server response)
        if not (tcp.flags & TCP_SYN_ACK_FLAGS == TCP_SYN_ACK_FLAGS):  # SYN+ACK flags
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
        prefix = f"{window_size}_{options_str}_{mss}_{wscale}"

        return prefix + _part_e(packet, tracker, prefix)

    except (ValueError, TypeError, IndexError, AttributeError) as e:
        logger.debug(f"Packet does not contain JA4TS data: {e}")
        return None
