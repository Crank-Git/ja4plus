"""
JA4S TLS Server Hello Fingerprinting implementation.
"""

import hashlib
import logging

from scapy.all import IP, IPv6, UDP

from ja4plus.utils.tls_utils import extract_tls_info, is_grease_value
from ja4plus.utils.quic_utils import (
    QUIC_INITIAL,
    initial_packet_dcid,
    long_header_packet_type,
    parse_quic_server_initial,
)
from ja4plus.fingerprinters.base import BaseFingerprinter

logger = logging.getLogger(__name__)

# A QUIC server listens on port 443, and the port is the only field that names the
# direction of an Initial packet. A client Initial packet and a server Initial packet
# carry the same long-header packet type. `ja4l.py` reads the direction the same way.
QUIC_PORT = 443


class JA4SFingerprinter(BaseFingerprinter):
    """
    JA4S TLS Server Hello Fingerprinting implementation.

    JA4S fingerprints server responses in TLS handshakes, including QUIC.
    For QUIC, tracks the client's Destination Connection ID (DCID) from
    client Initial packets, then uses it to decrypt server Initial packets.

    Format: <proto><version><ext_count><alpn>_<cipher>_<ext_hash>
    """

    def __init__(self):
        super().__init__()
        # Maps "srcIP:srcPort-dstIP:dstPort" -> client DCID bytes
        self._quic_dcids = {}
        self.last_raw = None
        self.last_raw_original_order = None
        self.last_fingerprint_original_order = None

    def process_packet(self, packet):
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

    def _quic_initial(self, packet, udp, udp_payload):
        """Return the JA4S value one QUIC Initial packet gives, or None.

        A client Initial packet supplies the connection ID that derives the server
        Initial keys. A server Initial packet names the client with the connection ID
        the client chose as its source, so it supplies no client connection ID and it
        replaces no stored value.

        Args:
            packet: The packet the caller processes.
            udp: The UDP layer of the packet.
            udp_payload: The bytes of the UDP payload.

        Returns:
            A JA4S fingerprint, or None. Returns None for a client Initial packet.
            Returns None when the fingerprinter holds no client connection ID, and
            when the packet carries no whole ServerHello.
        """
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

        client_dcid = self._quic_dcids.get(f"{dst_ip}:{dst_port}-{src_ip}:{src_port}")
        if not client_dcid:
            return None
        tls_info = parse_quic_server_initial(udp_payload, client_dcid)
        if not tls_info or tls_info.get("handshake_type") != "server_hello":
            return None
        fingerprint = _generate_ja4s_from_tls_info(tls_info)
        if not fingerprint:
            return None
        self._record(fingerprint, tls_info, packet)
        return fingerprint

    def _record(self, fingerprint, tls_info, packet):
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
        self.fingerprints.append(
            {
                "fingerprint": fingerprint,
                "fingerprint_original_order": fingerprint,
                "raw": raw,
                "raw_original_order": raw,
                "packet": packet,
            }
        )

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        """Remove stored QUIC DCID state for the given connection."""
        fwd = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        rev = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        self._quic_dcids.pop(fwd, None)
        self._quic_dcids.pop(rev, None)

    def reset(self):
        """Reset all state."""
        super().reset()
        self._quic_dcids = {}
        self.last_raw = None
        self.last_raw_original_order = None
        self.last_fingerprint_original_order = None


def _get_ip_pair(packet):
    """Extract (src_ip, dst_ip) as strings from a packet."""
    ip = packet.getlayer(IP) or packet.getlayer(IPv6)
    if ip:
        return str(ip.src), str(ip.dst)
    return "0.0.0.0", "0.0.0.0"


def _generate_ja4s_from_tls_info(tls_info):
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


def _generate_ja4s_raw_from_tls_info(tls_info):
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


def generate_ja4s(packet):
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


def _version_to_str(version):
    """Convert TLS version number to JA4 version string."""
    version_map = {
        0x0304: "13",  # TLS 1.3
        0x0303: "12",  # TLS 1.2
        0x0302: "11",  # TLS 1.1
        0x0301: "10",  # TLS 1.0
        0x0300: "s3",  # SSL 3.0
        0x0200: "s2",  # SSL 2.0
        0xFEFF: "d1",  # DTLS 1.0
        0xFEFD: "d2",  # DTLS 1.2
        0xFEFC: "d3",  # DTLS 1.3
    }
    return version_map.get(version, "00")


def _get_alpn_value(alpn_protocols, alpn_raw=None):
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
