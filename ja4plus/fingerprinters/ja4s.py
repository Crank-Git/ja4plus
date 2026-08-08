"""
JA4S TLS Server Hello Fingerprinting implementation.
"""

# Python 3.9 is the floor, and it evaluates no annotation written as `str | None`
# without this import.
from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

from scapy.all import IP, IPv6, UDP, Packet

from ja4plus.utils.tls_utils import extract_tls_info, is_grease_value, parse_tls_handshake
from ja4plus.utils.quic_utils import (
    QUIC_INITIAL,
    collect_crypto_fragments,
    decrypt_quic_server_initial_crypto,
    initial_packet_dcid,
    long_header_packet_type,
    reassemble_crypto_fragments,
    server_hello_is_complete,
)
from ja4plus.utils.packet_utils import packet_endpoints
from ja4plus.utils.state_table import BoundedStateTable
from ja4plus.fingerprinters.base import BaseFingerprinter
from ja4plus.fingerprinters.ja4 import quic_fragment_table

logger = logging.getLogger(__name__)

# A QUIC server listens on port 443, and the port is the only field that names the
# direction of an Initial packet. A client Initial packet and a server Initial packet
# carry the same long-header packet type. `ja4l.py` reads the direction the same way.
QUIC_PORT = 443

# A TLS record carries a 16-bit length field, so a longer message reaches no reader.
MAXIMUM_TLS_RECORD_BYTES = 0xFFFF


class JA4SFingerprinter(BaseFingerprinter):
    """
    JA4S TLS Server Hello Fingerprinting implementation.

    JA4S fingerprints server responses in TLS handshakes, including QUIC.
    For QUIC, tracks the client's Destination Connection ID (DCID) from
    client Initial packets, then uses it to decrypt server Initial packets.

    Format: <proto><version><ext_count><alpn>_<cipher>_<ext_hash>
    """

    def __init__(self, thread_safe: bool = True) -> None:
        super().__init__(thread_safe=thread_safe)
        # Maps "srcIP:srcPort-dstIP:dstPort" -> client DCID bytes. The connection ID
        # outlives the fragments, because a server answers a client Initial packet
        # after a round trip, so this table holds the default age of 600 seconds.
        self._quic_dcids = BoundedStateTable()
        # Maps the same connection key -> the CRYPTO fragments the server sent. RFC 9000
        # Section 12.2 lets a server split the ServerHello across two Initial packets,
        # and neither packet then holds the whole message.
        self._quic_server_crypto = quic_fragment_table()
        self.last_raw: str | None = None
        self.last_raw_original_order: str | None = None
        self.last_fingerprint_original_order: str | None = None

    def process_packet(self, packet: Packet) -> str | None:
        """
        Process a packet and extract JA4S fingerprint if applicable.

        Handles:
        - TCP/TLS ServerHello (existing path)
        - QUIC Server Initial: requires a prior Client Initial in the same flow

        Args:
            packet: A network packet to analyze

        Returns:
            The extracted fingerprint if successful, None otherwise
        """
        with self._lock:
            # Try QUIC path first (UDP packets)
            udp = packet.getlayer(UDP)
            if udp is not None:
                udp_payload = bytes(udp.payload)
                if udp_payload and long_header_packet_type(udp_payload) == QUIC_INITIAL:
                    return self._quic_initial(packet, udp, udp_payload)

            # TCP/TLS path
            from ja4plus.utils.tls_utils import extract_tls_info as _extract

            tls_info = _extract(packet)
            if not tls_info or tls_info.get("handshake_type") != "server_hello":
                return None
            fingerprint = _generate_ja4s_from_tls_info(tls_info)
            if fingerprint:
                self._record(fingerprint, tls_info, packet)
                return fingerprint
            return None

    def _quic_initial(self, packet: Packet, udp: Packet, udp_payload: bytes) -> str | None:
        """Return the JA4S value one QUIC Initial packet gives, or None.

        A client Initial packet supplies the connection ID that derives the server
        Initial keys. A server Initial packet names the client with the connection ID
        the client chose as its source, so it supplies no client connection ID and it
        replaces no stored value.

        The fingerprinter collects the CRYPTO fragments of the server Initial packets of
        one connection, because a server splits the ServerHello across two Initial
        packets. It reads the message on the packet that completes it.

        Args:
            packet: The packet the caller processes.
            udp: The UDP layer of the packet.
            udp_payload: The bytes of the UDP payload.

        Returns:
            A JA4S fingerprint, or None. Returns None for a client Initial packet.
            Returns None when the fingerprinter holds no client connection ID, and
            while the collected fragments hold no whole ServerHello.
        """
        # `ja4.py` reads the packet clock the same way. A capture file replays faster
        # than real time, so a wall clock would evict state the capture still needs.
        seconds = float(packet.time) if hasattr(packet, "time") else time.time()
        self._quic_dcids.on_packet(seconds)
        self._quic_server_crypto.on_packet(seconds)

        src_ip, dst_ip = _get_ip_pair(packet)
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
        to_server = dst_port == QUIC_PORT
        from_server = src_port == QUIC_PORT
        # A flow that holds two port 443 values names no server, and a flow that holds
        # none names no server either. The direction of a packet is then unknown, and
        # every value it gives is a guess.
        if to_server == from_server:
            return None

        if to_server:
            dcid = initial_packet_dcid(udp_payload)
            if dcid:
                self._quic_dcids[f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"] = dcid
            return None

        connection_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        client_dcid = self._quic_dcids.get(connection_key)
        if not client_dcid:
            return None
        fragments = decrypt_quic_server_initial_crypto(udp_payload, client_dcid)
        if not fragments:
            return None

        collected = collect_crypto_fragments(
            self._quic_server_crypto.setdefault(connection_key, []), fragments
        )
        if not server_hello_is_complete(collected):
            return None

        tls_info = _server_hello_from_crypto_fragments(collected)
        # The ServerHello is whole, so the fingerprinter holds the fragments no longer.
        self._drop_quic_server_crypto(connection_key)
        if not tls_info or tls_info.get("handshake_type") != "server_hello":
            return None
        fingerprint = _generate_ja4s_from_tls_info(tls_info)
        if not fingerprint:
            return None
        self._record(fingerprint, tls_info, packet)
        return fingerprint

    def _drop_quic_server_crypto(self, connection_key: str) -> None:
        """Drop the fragment table entry one connection holds."""
        self._quic_server_crypto.pop(connection_key, None)

    def _record(self, fingerprint: str, tls_info: dict[str, Any], packet: Packet) -> None:
        """Append a JA4S fingerprint result with raw / raw_original_order."""
        raw = _generate_ja4s_raw_from_tls_info(tls_info)
        # JA4S sorts no list, so one raw value serves both keys. FoxIO publishes
        # `JA4S_r` and no `JA4S_ro`, and `JA4S_r` holds the wire order. A sorted
        # `raw` value matches no reference value and no other implementation.
        self.last_raw = raw
        self.last_raw_original_order = raw
        # JA4S hashes the extensions in wire order, so the original-order hashed
        # value equals the fingerprint. FoxIO publishes no `JA4S_o` key. The field
        # exists so one caller reads one name on JA4 and on JA4S.
        self.last_fingerprint_original_order = fingerprint
        entry: dict[str, Any] = {
            "fingerprint": fingerprint,
            "fingerprint_original_order": fingerprint,
            "raw": raw,
            "raw_original_order": raw,
        }
        entry.update(packet_endpoints(packet))
        self.fingerprints.append(entry)

    def cleanup_connection(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str
    ) -> None:
        """Remove stored QUIC DCID state for the given connection."""
        with self._lock:
            fwd = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            rev = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
            self._quic_dcids.pop(fwd, None)
            self._quic_dcids.pop(rev, None)
            self._drop_quic_server_crypto(fwd)
            self._drop_quic_server_crypto(rev)

    def reset(self) -> None:
        """Reset all state."""
        with self._lock:
            super().reset()
            self._quic_dcids = BoundedStateTable()
            self._quic_server_crypto = quic_fragment_table()
            self.last_raw = None
            self.last_raw_original_order = None
            self.last_fingerprint_original_order = None


def _server_hello_from_crypto_fragments(
    fragments: list[tuple[int, bytes]],
) -> dict[str, Any] | None:
    """Return the ServerHello fields the collected CRYPTO fragments hold, or None.

    `quic_utils.parse_quic_server_initial` reads a ServerHello that one Initial packet
    carries. A ServerHello that two Initial packets split reaches no such payload, so
    this function reads the collected fragments of the connection instead.

    Args:
        fragments: The (offset, data) pairs the fingerprinter collected.

    Returns:
        The parsed ServerHello fields, or None when the bytes hold no ServerHello that
        the reader parses.
    """
    server_hello_bytes = reassemble_crypto_fragments(fragments)
    if not server_hello_bytes or server_hello_bytes[0] != 0x02:
        return None
    if len(server_hello_bytes) > MAXIMUM_TLS_RECORD_BYTES:
        return None

    record = (
        bytes([0x16, 0x03, 0x01]) + len(server_hello_bytes).to_bytes(2, "big") + server_hello_bytes
    )
    # The untyped TLS reader gives this value as `Any`. The local annotation states the
    # type the value holds, and it changes no value.
    tls_info: dict[str, Any] | None = parse_tls_handshake(record)
    if tls_info:
        tls_info["is_quic"] = True
    return tls_info


def _get_ip_pair(packet: Packet) -> tuple[str, str]:
    """Extract (src_ip, dst_ip) as strings from a packet."""
    ip = packet.getlayer(IP) or packet.getlayer(IPv6)
    if ip:
        return str(ip.src), str(ip.dst)
    return "0.0.0.0", "0.0.0.0"


def _generate_ja4s_from_tls_info(tls_info: dict[str, Any]) -> str | None:
    """
    Generate a JA4S fingerprint from an already-parsed tls_info dict.
    Shared by the TCP path (via generate_ja4s) and the QUIC server path.
    """
    try:
        proto = "q" if tls_info.get("is_quic") else "d" if tls_info.get("is_dtls") else "t"

        version = tls_info.get("version")
        supported_versions = tls_info.get("supported_versions", [])
        if supported_versions:
            non_grease = [v for v in supported_versions if not is_grease_value(v)]
            if non_grease:
                version = non_grease[0]

        version_str = _version_to_str(version)
        extensions = tls_info.get("extensions", [])
        ext_count = f"{min(len(extensions), 99):02d}"

        alpn_protocols = tls_info.get("alpn_protocols", [])
        alpn_raw = tls_info.get("alpn_raw") or []
        if not alpn_protocols:
            for ext_id, ext_data in tls_info.get("extension_data", {}).items():
                if ext_id == 0x0010 and "protocols" in ext_data and ext_data["protocols"]:
                    alpn_protocols = ext_data["protocols"]
                    break

        alpn_value = _get_alpn_value(alpn_protocols, alpn_raw)
        part_a = f"{proto}{version_str}{ext_count}{alpn_value}"

        cipher = tls_info.get("cipher")
        if cipher is None:
            return None
        cipher_str = f"{cipher:04x}"

        if extensions:
            ext_str = ",".join([f"{e:04x}" for e in extensions])
            extensions_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
        else:
            extensions_hash = "000000000000"

        return f"{part_a}_{cipher_str}_{extensions_hash}"

    except (ValueError, TypeError, IndexError, KeyError, AttributeError) as e:
        logger.debug(f"JA4S generation from tls_info failed: {e}")
        return None


def _generate_ja4s_raw_from_tls_info(tls_info: dict[str, Any]) -> str | None:
    """Return the raw JA4S value of an already-parsed tls_info dict.

    JA4S has one variable-length section, which holds the extensions. The section holds
    the extensions in the order the ServerHello carries them, because the FoxIO `JA4S_r`
    value holds that order.

    Args:
        tls_info: The parsed ServerHello fields.

    Returns:
        The raw JA4S value. Returns None when the ServerHello names no cipher.
        Returns None when a parsed field holds a value this function cannot read.
    """
    try:
        proto = "q" if tls_info.get("is_quic") else "d" if tls_info.get("is_dtls") else "t"

        version = tls_info.get("version")
        supported_versions = tls_info.get("supported_versions", [])
        if supported_versions:
            non_grease = [v for v in supported_versions if not is_grease_value(v)]
            if non_grease:
                version = non_grease[0]
        version_str = _version_to_str(version)

        extensions = tls_info.get("extensions", [])
        ext_count = f"{min(len(extensions), 99):02d}"

        alpn_protocols = tls_info.get("alpn_protocols", [])
        alpn_raw = tls_info.get("alpn_raw") or []
        if not alpn_protocols:
            for ext_id, ext_data in tls_info.get("extension_data", {}).items():
                if ext_id == 0x0010 and "protocols" in ext_data and ext_data["protocols"]:
                    alpn_protocols = ext_data["protocols"]
                    break
        alpn_value = _get_alpn_value(alpn_protocols, alpn_raw)
        part_a = f"{proto}{version_str}{ext_count}{alpn_value}"

        cipher = tls_info.get("cipher")
        if cipher is None:
            return None
        cipher_str = f"{cipher:04x}"

        ext_list = ",".join(f"{e:04x}" for e in extensions)

        return f"{part_a}_{cipher_str}_{ext_list}"
    except (ValueError, TypeError, IndexError, KeyError, AttributeError) as e:
        logger.debug(f"JA4S raw generation failed: {e}")
        return None


def generate_ja4s(packet: Packet) -> str | None:
    """
    Generate a JA4S fingerprint from a packet.

    Args:
        packet: A packet containing a TLS Server Hello message

    Returns:
        A JA4S fingerprint string or None if not applicable
    """
    tls_info = extract_tls_info(packet)
    if not tls_info or tls_info.get("handshake_type") != "server_hello":
        return None
    return _generate_ja4s_from_tls_info(tls_info)


def _version_to_str(version: int | None) -> str:
    """Convert TLS version number to JA4 version string.

    The table follows `technical_details/JA4.md:65` at the pinned commit. A value the
    table omits reaches the `00` fallback, which the same line states.
    """
    # `version` is `int | None`, and this dict never carries a `None` key. The
    # annotation widens the key type to match the caller, and it changes no value.
    version_map: dict[int | None, str] = {
        0x0304: "13",  # TLS 1.3
        0x0303: "12",  # TLS 1.2
        0x0302: "11",  # TLS 1.1
        0x0301: "10",  # TLS 1.0
        0x0300: "s3",  # SSL 3.0
        # FoxIO commit `3e02a27` corrected the SSL 2.0 value from `0x0200` to `0x0002`.
        # #227 holds the reading.
        0x0002: "s2",  # SSL 2.0
        0xFEFF: "d1",  # DTLS 1.0
        0xFEFD: "d2",  # DTLS 1.2
        0xFEFC: "d3",  # DTLS 1.3
    }
    return version_map.get(version, "00")


def _get_alpn_value(alpn_protocols: list[str], alpn_raw: list[bytes] | None = None) -> str:
    """Extract the ALPN value for the JA4S fingerprint.

    Delegates to ja4plus.fingerprinters.ja4.compute_alpn_value() to get
    PR #277 non-alphanumeric handling. Prefers raw bytes when available.
    """
    from ja4plus.fingerprinters.ja4 import compute_alpn_value

    if alpn_raw:
        return compute_alpn_value(alpn_raw[0])
    if alpn_protocols and alpn_protocols[0]:
        return compute_alpn_value(alpn_protocols[0].encode("latin-1", errors="replace"))
    return "00"
