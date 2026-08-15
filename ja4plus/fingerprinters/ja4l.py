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

# This import makes every annotation a string. No annotation therefore evaluates at
# import time, and a forward reference needs no quotation mark.
from __future__ import annotations

import time
import logging
from typing import Any

from scapy.all import IP, IPv6, TCP, UDP, Packet

from ja4plus.fingerprinters.base import BaseFingerprinter
from ja4plus.utils.http_utils import header_block_end, is_http_request
from ja4plus.utils.packet_utils import opens_a_connection, packet_endpoints, packet_seconds
from ja4plus.utils.state_table import BoundedStateTable
from ja4plus.utils.quic_utils import (
    QUIC_HANDSHAKE,
    QUIC_INITIAL,
    collect_crypto_fragments,
    decrypt_quic_server_initial_crypto,
    initial_packet_dcid,
    long_header_packet_type,
    server_hello_is_complete,
)

logger = logging.getLogger(__name__)

# JA4SSH reads the same handshake to name the client of a connection. One reader keeps
# the two from naming two different clients for one connection.
_opens_a_connection = opens_a_connection

# FoxIO reports one-way latency, so it halves every measured round-trip time. The
# JA4L material states "One-way TCP latency in us", and every vector holds half of
# the time the capture shows.
LATENCY_DIVISOR = 2

# The reference reads the direction of a QUIC flow from this port. A QUIC flow on
# another port carries no JA4L value, because neither endpoint is then the server.
QUIC_PORT = 443

# A QUIC connection carries a protocol marker as the third part. The Wireshark dissector
# writes `quic` at `packet-ja4.c:1441` and `packet-ja4.c:1447`, and
# `wireshark/test/testdata/` publishes that spelling on 18 values. The Zeek script writes
# `q`, and `.claude/rules/external-apis.md:95` declines every JA4L value of a Zeek
# baseline as a reference value. #225 holds the ruling.
QUIC_MARKER = "quic"

# A TCP sequence number and acknowledgement number are 32 bits wide, so a relative
# number needs this mask.
SEQUENCE_MASK = 0xFFFFFFFF

# FoxIO gives the propagation factor as a table keyed on the hop count. Each pair
# holds the highest hop count of one row and the factor of that row. A longer path
# crosses more terrain that the fiber does not follow, so the factor grows.
PROPAGATION_FACTOR_TABLE = ((21, 1.5), (22, 1.6), (23, 1.7), (24, 1.8), (25, 1.9))

# The last row of the FoxIO table covers a hop count of 26 or more.
MAXIMUM_PROPAGATION_FACTOR = 2.0

# A caller that passes no TTL gives no hop count, so the table answers nothing. The
# worked example in the FoxIO material uses 1.6, and this project used 1.6 before it
# read the table.
DEFAULT_PROPAGATION_FACTOR = 1.6

# FoxIO gives the speed of light in fiber as 0.128 miles or 0.206 kilometers per
# microsecond.
# Verified against
# https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4L.png
# (retrieved 2026-08-06). The image holds both the table above and these two values.
MILES_PER_MICROSECOND = 0.128
KILOMETERS_PER_MICROSECOND = 0.206


class JA4LFingerprinter(BaseFingerprinter):
    """
    JA4L Light Distance/Location Fingerprinting implementation.

    JA4L measures latency between client and server to estimate physical distance.
    """

    def __init__(self, thread_safe: bool = True) -> None:
        """Initialize the fingerprinter."""
        super().__init__(thread_safe=thread_safe)
        self.connections = BoundedStateTable()
        # A caller of `cleanup_connection` holds the address pair this fingerprinter
        # reports, and a tunnelled connection groups under its inner address pair. This
        # map reads the grouping key from the reported key.
        self.grouping_keys = BoundedStateTable()

    def process_packet(self, packet: Packet) -> str | None:
        """
        Process a packet and extract JA4L fingerprint if applicable.

        Args:
            packet: A network packet to analyze

        Returns:
            The extracted fingerprint if successful, None otherwise
        """
        with self._lock:
            if (IP not in packet and IPv6 not in packet) or (
                TCP not in packet and UDP not in packet
            ):
                return None

            # The two tables age against the capture clock, so every packet announces its
            # own timestamp. A table that reads the wall clock evicts state a replay needs.
            seconds = packet_seconds(packet)
            self.connections.on_packet(seconds)
            self.grouping_keys.on_packet(seconds)

            from ja4plus.utils.packet_utils import get_ip_layer
            from ja4plus.utils.tunnels import innermost_layer

            port_layer = innermost_layer(packet, (TCP, UDP))
            outer_layer = get_ip_layer(packet)
            if port_layer is None or outer_layer is None:
                return None
            proto = "tcp" if isinstance(port_layer, TCP) else "udp"
            sport = int(port_layer.sport)
            dport = int(port_layer.dport)

            # The reference reports the outer address pair, and it groups by the inner
            # one. A mirror sends both directions of one session from one outer address
            # to one other outer address, so the outer pair separates no direction there.
            inner_layer = innermost_layer(packet, (IP, IPv6)) or outer_layer
            src_ip = inner_layer.src
            dst_ip = inner_layer.dst

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
                    "reported_key": None,
                    "timestamps": {},
                    "ttls": {},
                    "isns": {},
                }

            conn = self.connections[conn_key]
            # The reference pairs the source address of a packet with the source port of
            # that packet, and it names the client first. The SYN carries that direction,
            # so a SYN replaces the pair the first packet of the connection gave.
            if conn.get("reported_key") is None or _opens_a_connection(port_layer, proto):
                self.grouping_keys.pop(conn.get("reported_key"), None)
                conn["reported_key"] = _reported_key(proto, outer_layer, sport, dport)
                self.grouping_keys[conn["reported_key"]] = conn_key
            fingerprint = generate_ja4l(packet, conn)

            if not fingerprint:
                return None

            # The reference holds one client value for one connection and overwrites it
            # while the measurement point moves. A later packet therefore replaces the
            # value this fingerprinter already reported, and it adds no second value.
            endpoints = packet_endpoints(packet)
            if fingerprint.startswith("JA4L-C="):
                index = conn.get("client_entry")
                if index is not None:
                    self.fingerprints[index]["fingerprint"] = fingerprint
                    self.fingerprints[index].update(endpoints)
                    return fingerprint
                # The stored index names a position in `self.fingerprints`, so the read
                # of the length and the append that follows form one operation. A second
                # thread that appends between the two gives two connections one entry.
                conn["client_entry"] = len(self.fingerprints)

            entry = {"fingerprint": fingerprint, "connection": conn["reported_key"]}
            entry.update(endpoints)
            self.fingerprints.append(entry)
            return fingerprint

    def reset(self) -> None:
        """Reset all fingerprints and connection tracking."""
        with self._lock:
            super().reset()
            self.connections = BoundedStateTable()
            self.grouping_keys = BoundedStateTable()

    def cleanup_connection(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str
    ) -> None:
        """Remove stored timing state for the given connection."""
        with self._lock:
            # JA4L normalizes the key so we must try both orderings
            fwd = f"{proto}_{src_ip}:{src_port}_{dst_ip}:{dst_port}"
            rev = f"{proto}_{dst_ip}:{dst_port}_{src_ip}:{src_port}"
            for reported in (fwd, rev):
                # The caller names the address pair this fingerprinter reports. A
                # tunnelled connection groups under another key, and the map holds it.
                self.connections.pop(self.grouping_keys.pop(reported, reported), None)

    def _propagation_factor(self, ttl: int | None, propagation_factor: float | None) -> float:
        """Return the propagation factor one distance call uses.

        Args:
            ttl: The observed TTL, or None when the caller knows none.
            propagation_factor: The factor the caller passed, or None.

        Returns:
            One of three values:

            - The factor the caller passed.
            - The factor of the FoxIO table row for the hop count the TTL implies.
            - `DEFAULT_PROPAGATION_FACTOR`, when the caller passes neither value.

            A TTL above the initial TTL implies a negative hop count, which clamps to
            zero hops.
        """
        if propagation_factor is not None:
            return propagation_factor
        if ttl is None:
            return DEFAULT_PROPAGATION_FACTOR
        hop_count = max(self.estimate_hop_count(ttl), 0)
        for highest, factor in PROPAGATION_FACTOR_TABLE:
            if hop_count <= highest:
                return factor
        return MAXIMUM_PROPAGATION_FACTOR

    def calculate_distance(
        self, latency_us: float, ttl: int | None = None, propagation_factor: float | None = None
    ) -> float:
        """Return the distance the JA4L latency implies, in miles.

        Args:
            latency_us: The one-way latency, in microseconds.
            ttl: The observed TTL. The FoxIO table reads the hop count it implies.
            propagation_factor: An explicit factor, which overrides the table.

        Returns:
            The distance in miles.
        """
        factor = self._propagation_factor(ttl, propagation_factor)
        return (latency_us * MILES_PER_MICROSECOND) / factor

    def calculate_distance_km(
        self, latency_us: float, ttl: int | None = None, propagation_factor: float | None = None
    ) -> float:
        """Return the distance the JA4L latency implies, in kilometers.

        Args:
            latency_us: The one-way latency, in microseconds.
            ttl: The observed TTL. The FoxIO table reads the hop count it implies.
            propagation_factor: An explicit factor, which overrides the table.

        Returns:
            The distance in kilometers.
        """
        factor = self._propagation_factor(ttl, propagation_factor)
        return (latency_us * KILOMETERS_PER_MICROSECOND) / factor

    def estimate_os(self, ttl: int) -> str:
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

    def estimate_hop_count(self, ttl: int) -> int:
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


def _reported_key(proto: str, outer_layer: Packet, sport: int, dport: int) -> str:
    """Return the connection key the reference reports for one connection.

    The reference reports the outer address pair and the inner port pair. It pairs the
    source address of one packet with the source port of that packet.

    Args:
        proto: The protocol name of the connection, `tcp` or `udp`.
        outer_layer: The outer address layer of the packet.
        sport: The inner source port of the packet.
        dport: The inner destination port of the packet.

    Returns:
        A key of the form `<protocol>_<address>:<port>_<address>:<port>`. The two
        endpoints are in sorted order, so both directions of one connection give one
        key.
    """
    first, second = sorted(((outer_layer.src, sport), (outer_layer.dst, dport)))
    return "{}_{}:{}_{}:{}".format(proto, first[0], first[1], second[0], second[1])


def _packet_microseconds(packet: Packet) -> int:
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


def _one_way_latency(start: int, end: int) -> int:
    """Return the one-way latency between two timestamps, in microseconds.

    Args:
        start: The earlier timestamp, in microseconds.
        end: The later timestamp, in microseconds.

    Returns:
        Half the time between the two timestamps, truncated toward zero.
    """
    return int((end - start) / LATENCY_DIVISOR)


def _relative_numbers(
    conn: dict[str, Any], source: tuple[str, int], target: tuple[str, int], tcp_layer: Packet
) -> tuple[int, int] | None:
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


def _holds_a_complete_http_request(payload: bytes) -> bool:
    """Report whether the payload holds an HTTP request with its whole header block.

    The reference keeps the timestamps of a packet under the protocol its dissector
    reports. A packet that holds a whole HTTP request reaches a separate cache, so it
    never moves the client measurement point. A packet that holds the first part of a
    request reaches the same cache as any other TCP packet, and it does move the
    point. `http-empty-useragent.pcap` and `latest.pcapng` prove both halves.

    The reader of `ja4plus.utils.http_utils` answers where a header block ends, and this
    gate calls it rather than holding a second copy of the rule. Two fixed byte groups
    stood here before, and they declined a header block that ends with one line feed
    followed by a carriage return and a line feed. Such a request then completed a client
    value that the reference does not publish. #630 records the defect.

    Args:
        payload: The TCP payload bytes.

    Returns:
        True when the payload starts an HTTP request and holds the whole header block.
    """
    if not is_http_request(payload):
        return False
    return header_block_end(payload) is not None


def _restart_connection(conn: dict[str, Any]) -> None:
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


def _tcp_ja4l(
    packet: Packet, conn: dict[str, Any], ip_layer: Packet, ttl: int, now: int
) -> str | None:
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
        # A retransmitted SYN-ACK finds point `B` set, and it moves neither the point
        # nor the TTL. A value here would repeat the value the first SYN-ACK gave, and
        # the reference publishes one server value for one connection. #272 measured the
        # repeat on `ssh2.pcapng` stream 15.
        if "B" in timestamps:
            return None
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


def _quic_client_initial(conn: dict[str, Any], udp_payload: bytes, ttl: int, now: int) -> None:
    """Record the client measurement point of a QUIC connection.

    The function also stores the destination connection ID, because the server Initial
    keys derive from it. A Retry packet makes the client choose another connection ID.
    The latest client Initial packet therefore supplies the value.

    Args:
        conn: The connection state.
        udp_payload: The bytes of the UDP payload.
        ttl: The TTL of the packet.
        now: The timestamp of the packet, in microseconds.

    Returns:
        None. A client Initial packet completes no JA4L value.
    """
    dcid = initial_packet_dcid(udp_payload)
    if dcid:
        conn["quic_dcid"] = dcid
    if "A" in conn["timestamps"]:
        return None
    conn["timestamps"]["A"] = now
    conn["ttls"]["client"] = ttl
    return None


def _quic_server_initial(
    conn: dict[str, Any], udp_payload: bytes, ttl: int, now: int
) -> str | None:
    """Return the JA4L server value this QUIC server Initial packet gives, or None.

    The reference records the server measurement point on the Initial packet that
    completes the ServerHello. A server that splits the ServerHello across two Initial
    packets therefore gives the timestamp of the second one. `python/ja4.py` reads the
    point where `packet_type` is `0` and `tls.handshake.type` is `2`.

    Args:
        conn: The connection state.
        udp_payload: The bytes of the UDP payload.
        ttl: The TTL of the packet.
        now: The timestamp of the packet, in microseconds.

    Returns:
        A `JA4L-S=` value, or None while the ServerHello is incomplete. Returns None
        when the packet does not decrypt, because the fingerprinter then cannot tell
        which Initial packet carries the ServerHello.
    """
    timestamps = conn["timestamps"]
    if "A" not in timestamps or "B" in timestamps:
        return None
    client_dcid = conn.get("quic_dcid")
    if not client_dcid:
        return None
    fragments = decrypt_quic_server_initial_crypto(udp_payload, client_dcid)
    if not fragments:
        return None

    collected = collect_crypto_fragments(conn.setdefault("server_crypto", []), fragments)
    if not server_hello_is_complete(collected):
        return None

    conn.pop("server_crypto", None)
    timestamps["B"] = now
    conn["ttls"]["server"] = ttl
    return "JA4L-S={}_{}_{}".format(
        _one_way_latency(timestamps["A"], timestamps["B"]), ttl, QUIC_MARKER
    )


def _quic_ja4l(packet: Packet, conn: dict[str, Any], ttl: int, now: int) -> str | None:
    """Return the JA4L value this QUIC packet gives, or None."""
    udp_layer = packet[UDP]
    udp_payload = bytes(udp_layer.payload)
    packet_type = long_header_packet_type(udp_payload)
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
        if to_server:
            # `_quic_client_initial` returns None on every path, so this call and the
            # return below match the call the code made before annotation.
            _quic_client_initial(conn, udp_payload, ttl, now)
            return None
        if from_server:
            return _quic_server_initial(conn, udp_payload, ttl, now)
        return None

    if packet_type != QUIC_HANDSHAKE:
        return None

    # The client value needs the server Initial point, exactly as the TCP client value
    # needs the SYN-ACK. The reference discards a server Initial packet that leads its
    # client Initial packet. Its state machine therefore never reaches the state that
    # reads a Handshake packet. `quic_mirrored.pcap` measures it, and #156 holds the
    # reading.
    if "B" not in timestamps:
        return None

    # The server sends one to five Handshake packets. The client measurement starts
    # at the last of them, so this point moves until the client answers.
    if from_server and "D" not in timestamps:
        timestamps["C"] = now
        return None

    if to_server and "C" in timestamps and "D" not in timestamps:
        timestamps["D"] = now
        return "JA4L-C={}_{}_{}".format(
            _one_way_latency(timestamps["C"], timestamps["D"]),
            ttls.get("client", ttl),
            QUIC_MARKER,
        )
    return None


def generate_ja4l(packet: Packet, conn: dict[str, Any] | None = None) -> str | None:
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
    from ja4plus.utils.tunnels import innermost_layer

    # The measurement points belong to the two inner endpoints. A mirror carries both
    # directions of one session under one outer address pair, so the outer address
    # names no endpoint there. The TTL still comes from the outer layer, because the
    # reference reports that value.
    ip_layer = innermost_layer(packet, (IP, IPv6)) or get_ip_layer(packet)
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
