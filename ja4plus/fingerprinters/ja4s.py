"""
JA4S TLS Server Hello Fingerprinting implementation.
"""

import hashlib
import logging
from scapy.all import IP, TCP, Raw

logger = logging.getLogger(__name__)
from ja4plus.utils.tls_utils import extract_tls_info, is_grease_value
from ja4plus.fingerprinters.base import BaseFingerprinter


class JA4SFingerprinter(BaseFingerprinter):
    """
    JA4S TLS Server Hello Fingerprinting implementation.

    JA4S fingerprints server responses in TLS handshakes.
    Format: <proto><version><ext_count><alpn>_<cipher>_<ext_hash>
    """

    def process_packet(self, packet):
        """
        Process a packet and extract JA4S fingerprint if applicable.

        Args:
            packet: A network packet to analyze

        Returns:
            The extracted fingerprint if successful, None otherwise
        """
        fingerprint = generate_ja4s(packet)
        if fingerprint:
            self.add_fingerprint(fingerprint, packet)
            return fingerprint
        return None


def generate_ja4s(packet):
    """
    Generate a JA4S fingerprint from a packet.

    Args:
        packet: A packet containing a TLS Server Hello message

    Returns:
        A JA4S fingerprint string or None if not applicable
    """
    # Extract TLS info
    tls_info = extract_tls_info(packet)
    if not tls_info or tls_info.get('handshake_type') != 'server_hello':
        return None

    try:
        # Protocol indicator (t for TCP/TLS, q for QUIC, d for DTLS)
        proto = 'q' if tls_info.get('is_quic') else 'd' if tls_info.get('is_dtls') else 't'

        # Get TLS version - check supported_versions first (for TLS 1.3)
        version = tls_info.get('version')
        supported_versions = tls_info.get('supported_versions', [])
        if supported_versions:
            non_grease = [v for v in supported_versions if not is_grease_value(v)]
            if non_grease:
                version = non_grease[0]

        version_str = _version_to_str(version)

        # Get extensions - JA4S INCLUDES GREASE values per FoxIO spec
        # (unlike JA4 client which excludes them)
        extensions = tls_info.get('extensions', [])
        ext_count = f"{min(len(extensions), 99):02d}"

        # Extract ALPN - use first and last character of first protocol
        alpn_protocols = tls_info.get('alpn_protocols', [])
        if not alpn_protocols:
            # Check extension_data for backward compatibility
            for ext_id, ext_data in tls_info.get('extension_data', {}).items():
                if ext_id == 0x0010 and 'protocols' in ext_data and ext_data['protocols']:
                    alpn_protocols = ext_data['protocols']
                    break

        alpn_value = _get_alpn_value(alpn_protocols)

        # Form part_a of the fingerprint
        part_a = f"{proto}{version_str}{ext_count}{alpn_value}"

        # Get selected cipher
        cipher = tls_info.get('cipher')
        if cipher is None:
            return None
        cipher_str = f"{cipher:04x}"

        # Hash the extensions as comma-separated hex values
        # JA4S extensions are NOT sorted - they maintain original order per spec
        # JA4S INCLUDES GREASE values in the hash per FoxIO spec
        if extensions:
            ext_str = ','.join([f"{e:04x}" for e in extensions])
            extensions_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
        else:
            extensions_hash = '000000000000'

        # Form the complete JA4S fingerprint
        ja4s = f"{part_a}_{cipher_str}_{extensions_hash}"

        return ja4s

    except (ValueError, TypeError, IndexError, KeyError, AttributeError) as e:
        logger.debug(f"Packet does not contain JA4S data: {e}")
        return None


def _version_to_str(version):
    """Convert TLS version number to JA4 version string."""
    version_map = {
        0x0304: '13',  # TLS 1.3
        0x0303: '12',  # TLS 1.2
        0x0302: '11',  # TLS 1.1
        0x0301: '10',  # TLS 1.0
        0x0300: 's3',  # SSL 3.0
        0x0200: 's2',  # SSL 2.0
        0xfeff: 'd1',  # DTLS 1.0
        0xfefd: 'd2',  # DTLS 1.2
        0xfefc: 'd3',  # DTLS 1.3
    }
    return version_map.get(version, '00')


def _get_alpn_value(alpn_protocols):
    """
    Extract ALPN value for JA4S fingerprint.
    Per FoxIO spec: first and last char of first protocol.
    Non-ASCII (ord > 127) -> '99'.
    """
    if not alpn_protocols:
        return '00'

    first_alpn = alpn_protocols[0]
    if not first_alpn:
        return '00'

    # FoxIO spec: if first char is non-ASCII, use '99'
    if ord(first_alpn[0]) > 127:
        return '99'

    if len(first_alpn) == 1:
        return first_alpn[0] + first_alpn[0]

    return f"{first_alpn[0]}{first_alpn[-1]}"
