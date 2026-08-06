"""
JA4S TLS Server Hello Fingerprinting implementation.
"""

import hashlib
import logging
import struct

from scapy.all import IP, IPv6, TCP, UDP, Raw

from ja4plus.utils.tls_utils import extract_tls_info, is_grease_value
from ja4plus.utils.quic_utils import parse_quic_server_initial, parse_quic_initial
from ja4plus.fingerprinters.base import BaseFingerprinter

logger = logging.getLogger(__name__)


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
            if udp_payload:
                src_ip, dst_ip = _get_ip_pair(packet)
                src_port = int(udp.sport)
                dst_port = int(udp.dport)

                fwd_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                rev_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"

                # Check if this is a QUIC Client Initial — capture its DCID
                if _is_quic_client_initial(udp_payload):
                    dcid = _extract_dcid(udp_payload)
                    if dcid is not None:
                        self._quic_dcids[fwd_key] = dcid
                    return None

                # Try to decode as QUIC Server Initial using the stored client DCID
                if rev_key in self._quic_dcids:
                    client_dcid = self._quic_dcids[rev_key]
                    tls_info = parse_quic_server_initial(udp_payload, client_dcid)
                    if tls_info and tls_info.get("handshake_type") == "server_hello":
                        fingerprint = _generate_ja4s_from_tls_info(tls_info)
                        if fingerprint:
                            self._record(fingerprint, tls_info, packet)
                            return fingerprint

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

    def _record(self, fingerprint, tls_info, packet):
        """Append a JA4S fingerprint result with raw / raw_original_order."""
        raw = _generate_ja4s_raw_from_tls_info(tls_info, original_order=False)
        raw_oo = _generate_ja4s_raw_from_tls_info(tls_info, original_order=True)
        # JA4S hashes the extensions in wire order, and the FoxIO `JA4S_r` value
        # holds that same wire order. The original-order hashed value therefore
        # equals the fingerprint. FoxIO publishes no `JA4S_o` key. The field
        # exists so one caller reads one name on JA4 and on JA4S.
        self.last_raw = raw
        self.last_raw_original_order = raw_oo
        self.last_fingerprint_original_order = fingerprint
        self.fingerprints.append(
            {
                "fingerprint": fingerprint,
                "fingerprint_original_order": fingerprint,
                "raw": raw,
                "raw_original_order": raw_oo,
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


def _is_quic_client_initial(udp_payload):
    """Return True if the UDP payload looks like a QUIC v1/v2 client Initial."""
    if len(udp_payload) < 6:
        return False
    first_byte = udp_payload[0]
    if not (first_byte & 0x80):
        return False
    version = struct.unpack("!I", udp_payload[1:5])[0]
    if version == 0:
        return False
    packet_type = (first_byte & 0x30) >> 4
    is_v2 = version == 0x6B3343CF
    if is_v2:
        return packet_type == 0x01
    return packet_type == 0x00


def _extract_dcid(udp_payload):
    """Extract the Destination Connection ID bytes from a QUIC long header."""
    if len(udp_payload) < 6:
        return None
    dcid_len = udp_payload[5]
    if 6 + dcid_len > len(udp_payload):
        return None
    return udp_payload[6 : 6 + dcid_len]


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


def _generate_ja4s_raw_from_tls_info(tls_info, original_order=False):
    """Generate the raw (unhashed) JA4S variant.

    JA4S has only one variable-length section (extensions). For the
    sorted form (default), extensions are emitted in numeric order; for
    original_order, in the order they appeared. Mirrors the Go reference's
    ComputeJA4SRaw / ComputeJA4SRawOriginalOrder.
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

        if original_order:
            ext_list = ",".join(f"{e:04x}" for e in extensions)
        else:
            ext_list = ",".join(f"{e:04x}" for e in sorted(extensions))

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
