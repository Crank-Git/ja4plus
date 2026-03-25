"""
Enhanced TLS utility functions for JA4+ fingerprinting.
"""

import struct
import logging
from scapy.all import Raw

logger = logging.getLogger(__name__)


def extract_tls_info(packet):
    """
    Extract TLS information from a packet.

    Args:
        packet: A network packet

    Returns:
        Dictionary with TLS handshake information or None if not applicable
    """
    # Special handling for test packets with embedded TLS info
    if hasattr(packet, 'tls_info'):
        return packet.tls_info

    if Raw not in packet:
        return None

    try:
        raw_data = bytes(packet[Raw])
        return parse_tls_handshake(raw_data)
    except (ValueError, TypeError, AttributeError) as e:
        logger.debug(f"Packet does not contain TLS data: {e}")
        return None


def parse_tls_handshake(raw_data):
    """
    Parse a TLS handshake message from raw bytes.

    Args:
        raw_data: Raw bytes of a TLS record

    Returns:
        Dictionary with TLS handshake information or None
    """
    # Check minimum length for TLS record header
    if len(raw_data) < 5:
        return None

    record_type = raw_data[0]
    if record_type != 0x16:  # 0x16 = Handshake
        return None

    # Get TLS record version and length
    record_length = (raw_data[3] << 8) | raw_data[4]

    # Ensure we have enough data
    if len(raw_data) < 5 + record_length:
        return None

    # Extract handshake type
    if len(raw_data) < 6:
        return None

    handshake_type = raw_data[5]

    if handshake_type == 1:
        return _parse_client_hello(raw_data)
    elif handshake_type == 2:
        return _parse_server_hello(raw_data)
    else:
        return None


def _parse_client_hello(raw_data):
    """Parse a TLS ClientHello message."""
    if len(raw_data) < 11:
        return None

    # ClientHello version is at offset 9-10 (after record header + handshake header)
    version = (raw_data[9] << 8) | raw_data[10]

    tls_info = {
        'handshake_type': 'client_hello',
        'type': 'client_hello',
        'version': version,
        'is_quic': False,
        'is_dtls': False,
    }

    # Skip past record header (5) + handshake header (4) + version (2) + random (32)
    pos = 11 + 32

    # Session ID
    if pos + 1 > len(raw_data):
        return tls_info
    session_id_len = raw_data[pos]
    pos += 1 + session_id_len

    # Cipher suites
    if pos + 2 > len(raw_data):
        return tls_info
    cipher_suites_len = (raw_data[pos] << 8) | raw_data[pos + 1]
    pos += 2

    ciphers = []
    for i in range(0, cipher_suites_len, 2):
        if pos + i + 2 > len(raw_data):
            break
        cipher = (raw_data[pos + i] << 8) | raw_data[pos + i + 1]
        ciphers.append(cipher)

    tls_info['ciphers'] = ciphers
    pos += cipher_suites_len

    # Compression methods
    if pos + 1 > len(raw_data):
        return tls_info
    compression_len = raw_data[pos]
    pos += 1 + compression_len

    # Parse extensions
    extensions = []
    extension_data = {}
    supported_versions = []
    alpn_protocols = []
    signature_algorithms = []
    sni = None

    if pos + 2 <= len(raw_data):
        extensions_len = (raw_data[pos] << 8) | raw_data[pos + 1]
        pos += 2
        extensions_end = min(pos + extensions_len, len(raw_data))

        while pos + 4 <= extensions_end:
            ext_type = (raw_data[pos] << 8) | raw_data[pos + 1]
            ext_len = (raw_data[pos + 2] << 8) | raw_data[pos + 3]
            ext_data_start = pos + 4
            ext_data_end = min(ext_data_start + ext_len, len(raw_data))

            extensions.append(ext_type)

            # Parse SNI (0x0000)
            if ext_type == 0x0000:
                sni = _parse_sni(raw_data[ext_data_start:ext_data_end])

            # Parse supported_versions (0x002b)
            elif ext_type == 0x002b:
                supported_versions = _parse_supported_versions_client(
                    raw_data[ext_data_start:ext_data_end]
                )

            # Parse ALPN (0x0010)
            elif ext_type == 0x0010:
                alpn_protocols = _parse_alpn(raw_data[ext_data_start:ext_data_end])

            # Parse signature_algorithms (0x000d)
            elif ext_type == 0x000d:
                signature_algorithms = _parse_signature_algorithms(
                    raw_data[ext_data_start:ext_data_end]
                )

            pos = ext_data_start + ext_len

    tls_info['extensions'] = extensions
    tls_info['extension_data'] = extension_data
    tls_info['supported_versions'] = supported_versions
    tls_info['alpn_protocols'] = alpn_protocols
    tls_info['signature_algorithms'] = signature_algorithms
    if sni is not None:
        tls_info['sni'] = sni

    return tls_info


def _parse_server_hello(raw_data):
    """Parse a TLS ServerHello message."""
    if len(raw_data) < 11:
        return None

    # ServerHello version at offset 9-10
    version = (raw_data[9] << 8) | raw_data[10]

    tls_info = {
        'handshake_type': 'server_hello',
        'type': 'server_hello',
        'version': version,
        'is_quic': False,
    }

    # Skip past record header (5) + handshake header (4) + version (2) + random (32)
    pos = 11 + 32

    # Session ID
    if pos + 1 > len(raw_data):
        return tls_info
    session_id_len = raw_data[pos]
    pos += 1 + session_id_len

    # Cipher suite (single cipher for ServerHello)
    if pos + 2 > len(raw_data):
        return tls_info
    cipher = (raw_data[pos] << 8) | raw_data[pos + 1]
    tls_info['cipher'] = cipher
    pos += 2

    # Compression method
    if pos + 1 > len(raw_data):
        return tls_info
    pos += 1

    # Parse extensions
    extensions = []
    extension_data = {}
    alpn_protocols = []
    supported_versions = []

    if pos + 2 <= len(raw_data):
        extensions_len = (raw_data[pos] << 8) | raw_data[pos + 1]
        pos += 2
        extensions_end = min(pos + extensions_len, len(raw_data))

        while pos + 4 <= extensions_end:
            ext_type = (raw_data[pos] << 8) | raw_data[pos + 1]
            ext_len = (raw_data[pos + 2] << 8) | raw_data[pos + 3]
            ext_data_start = pos + 4
            ext_data_end = min(ext_data_start + ext_len, len(raw_data))

            extensions.append(ext_type)

            # Parse ALPN (0x0010)
            if ext_type == 0x0010:
                alpn_protocols = _parse_alpn(raw_data[ext_data_start:ext_data_end])
                extension_data[0x0010] = {'protocols': alpn_protocols}

            # Parse supported_versions (0x002b) - server selects one version
            elif ext_type == 0x002b:
                if ext_len >= 2:
                    sv = (raw_data[ext_data_start] << 8) | raw_data[ext_data_start + 1]
                    supported_versions = [sv]

            pos = ext_data_start + ext_len

    tls_info['extensions'] = extensions
    tls_info['extension_data'] = extension_data
    tls_info['alpn_protocols'] = alpn_protocols
    tls_info['supported_versions'] = supported_versions

    # If supported_versions indicates TLS 1.3, update the version
    if supported_versions:
        non_grease = [v for v in supported_versions if not is_grease_value(v)]
        if non_grease:
            tls_info['version'] = non_grease[0]

    return tls_info


def _parse_sni(data):
    """Parse Server Name Indication extension data."""
    if len(data) < 5:
        return True  # Extension exists but can't parse hostname

    try:
        # SNI list length (2 bytes)
        sni_list_len = (data[0] << 8) | data[1]
        pos = 2

        if pos + 3 > len(data):
            return True

        # SNI type (1 byte) - 0 = hostname
        sni_type = data[pos]
        pos += 1

        # Hostname length (2 bytes)
        hostname_len = (data[pos] << 8) | data[pos + 1]
        pos += 2

        if sni_type == 0 and pos + hostname_len <= len(data):
            hostname = data[pos:pos + hostname_len].decode('ascii', errors='ignore')
            return hostname if hostname else True

        return True
    except (ValueError, IndexError, UnicodeDecodeError) as e:
        logger.debug(f"Failed to parse SNI: {e}")
        return True


def _parse_supported_versions_client(data):
    """Parse supported_versions extension from ClientHello."""
    versions = []
    if len(data) < 1:
        return versions

    try:
        # First byte is the length of the version list
        list_len = data[0]
        pos = 1

        while pos + 2 <= min(1 + list_len, len(data)):
            ver = (data[pos] << 8) | data[pos + 1]
            versions.append(ver)
            pos += 2
    except (ValueError, IndexError) as e:
        logger.debug(f"Failed to parse supported_versions: {e}")

    return versions


def _parse_alpn(data):
    """Parse Application-Layer Protocol Negotiation extension data."""
    protocols = []
    if len(data) < 2:
        return protocols

    try:
        # ALPN list length (2 bytes)
        alpn_list_len = (data[0] << 8) | data[1]
        pos = 2

        while pos < min(2 + alpn_list_len, len(data)):
            if pos + 1 > len(data):
                break
            proto_len = data[pos]
            pos += 1

            if pos + proto_len > len(data):
                break
            protocol = data[pos:pos + proto_len].decode('ascii', errors='ignore')
            protocols.append(protocol)
            pos += proto_len
    except (ValueError, IndexError, UnicodeDecodeError) as e:
        logger.debug(f"Failed to parse ALPN: {e}")

    return protocols


def _parse_signature_algorithms(data):
    """Parse signature_algorithms extension data."""
    algorithms = []
    if len(data) < 2:
        return algorithms

    try:
        # Signature algorithms list length (2 bytes)
        list_len = (data[0] << 8) | data[1]
        pos = 2

        while pos + 2 <= min(2 + list_len, len(data)):
            alg = (data[pos] << 8) | data[pos + 1]
            algorithms.append(alg)
            pos += 2
    except (ValueError, IndexError, struct.error) as e:
        logger.debug(f"Failed to parse signature algorithms: {e}")

    return algorithms


def is_grease_value(value):
    """
    Check if a value is a TLS GREASE value.

    GREASE values match the pattern 0x?A?A where ? is the same nibble.
    The canonical check is: (value & 0x0F0F) == 0x0A0A and high byte == low byte.

    Known GREASE values: 0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
                         0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
                         0xCACA, 0xDADA, 0xEAEA, 0xFAFA
    """
    if not value and value != 0:
        return False

    try:
        if isinstance(value, str):
            int_val = int(value, 16)
        elif isinstance(value, int):
            int_val = value
        else:
            return False

        return (int_val & 0x0F0F) == 0x0A0A and ((int_val >> 8) & 0xFF) == (int_val & 0xFF)
    except (ValueError, TypeError):
        return False


def find_tls_extension(extensions, extension_type):
    """Find a specific TLS extension by type."""
    for ext in extensions:
        if hasattr(ext, 'type') and ext.type == extension_type:
            return ext
    return None
