"""
Enhanced TLS utility functions for JA4+ fingerprinting.
"""

# This import makes every annotation a string. No annotation therefore evaluates at
# import time, and a forward reference needs no quotation mark.
from __future__ import annotations

import struct
import logging
from collections.abc import Iterable
from typing import Any

from scapy.all import Raw, UDP, Packet

from ja4plus.utils.quic_utils import parse_quic_initial

logger = logging.getLogger(__name__)


def extract_tls_info(packet: Packet) -> dict[str, Any] | None:
    """
    Extract TLS information from a packet.

    Checks for QUIC Initial packets on UDP before falling through
    to standard TLS record parsing on TCP.

    Args:
        packet: A network packet

    Returns:
        Dictionary with TLS handshake information or None if not applicable
    """
    if hasattr(packet, "tls_info"):
        # scapy ships no type information, so this attribute reads as `Any`. The local
        # annotation states the type the attribute holds, and it changes no value.
        cached: dict[str, Any] | None = packet.tls_info
        return cached

    if Raw not in packet:
        return None

    try:
        raw_data = bytes(packet[Raw])

        if UDP in packet:
            quic_info = parse_quic_initial(raw_data)
            if quic_info:
                return quic_info

        return parse_tls_handshake(raw_data)
    except (ValueError, TypeError, AttributeError) as e:
        logger.debug(f"Packet does not contain TLS data: {e}")
        return None


def parse_tls_handshake(raw_data: bytes) -> dict[str, Any] | None:
    """
    Parse the first ClientHello or ServerHello of a TLS segment.

    The walk reads every record of the segment, because a hello does not always start
    the segment. A TLS 1.3 client that answers a HelloRetryRequest puts the
    compatibility-mode ChangeCipherSpec record before its second ClientHello, so the
    first byte of that segment is 0x14.

    Args:
        raw_data: Raw bytes of one TLS segment

    Returns:
        Dictionary with TLS handshake information or None
    """
    offset = 0

    # The per-record length comes from the packet, so the walk bounds every read on the
    # real buffer length. A record header is five bytes, so the walk always advances.
    while offset + 5 <= len(raw_data):
        record_type = raw_data[offset]
        record_length = (raw_data[offset + 3] << 8) | raw_data[offset + 4]

        if record_type == 0x16 and offset + 9 <= len(raw_data):  # 0x16 = Handshake
            handshake_type = raw_data[offset + 5]

            if handshake_type in (1, 2):
                # A handshake record carries one or more handshake messages, so the
                # record length bounds the group and not the hello. A TLS 1.2 server
                # coalesces the ServerHello, the Certificate and the ServerHelloDone
                # into one record that spans several TCP segments, and issue #151 names
                # the three FoxIO streams the record bound rejected.
                handshake_length = int.from_bytes(raw_data[offset + 6 : offset + 9], "big")
                end = offset + 9 + handshake_length
                # A hello the segment cuts holds no cipher and no extension list.
                if end > len(raw_data):
                    return None

                # The slice stops at the end of the hello, because the bytes that follow
                # belong to the next handshake message. A reader that walks into them
                # reports an extension the peer never sent.
                record = raw_data[offset:end]
                if handshake_type == 1:
                    return _parse_client_hello(record)
                return _parse_server_hello(record)

        offset += 5 + record_length

    return None


def _parse_client_hello(raw_data: bytes) -> dict[str, Any] | None:
    """Parse a TLS ClientHello message."""
    if len(raw_data) < 11:
        return None

    # ClientHello version is at offset 9-10 (after record header + handshake header)
    version = (raw_data[9] << 8) | raw_data[10]

    tls_info: dict[str, Any] = {
        "handshake_type": "client_hello",
        "type": "client_hello",
        "version": version,
        "is_quic": False,
        "is_dtls": False,
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

    tls_info["ciphers"] = ciphers
    pos += cipher_suites_len

    # Compression methods
    if pos + 1 > len(raw_data):
        return tls_info
    compression_len = raw_data[pos]
    pos += 1 + compression_len

    # Parse extensions
    extensions: list[int] = []
    extension_data: dict[int, Any] = {}
    supported_versions: list[int] = []
    alpn_protocols: list[str] = []
    alpn_raw: list[bytes] = []
    signature_algorithms: list[int] = []
    sni: str | bool | None = None

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
            elif ext_type == 0x002B:
                supported_versions = _parse_supported_versions_client(
                    raw_data[ext_data_start:ext_data_end]
                )

            # Parse ALPN (0x0010)
            elif ext_type == 0x0010:
                alpn_protocols, alpn_raw = _parse_alpn_with_bytes(
                    raw_data[ext_data_start:ext_data_end]
                )

            # Parse signature_algorithms (0x000d)
            elif ext_type == 0x000D:
                signature_algorithms = _parse_signature_algorithms(
                    raw_data[ext_data_start:ext_data_end]
                )

            pos = ext_data_start + ext_len

    tls_info["extensions"] = extensions
    tls_info["extension_data"] = extension_data
    tls_info["supported_versions"] = supported_versions
    tls_info["alpn_protocols"] = alpn_protocols
    tls_info["alpn_raw"] = alpn_raw
    tls_info["signature_algorithms"] = signature_algorithms
    if sni is not None:
        tls_info["sni"] = sni

    return tls_info


def _parse_server_hello(raw_data: bytes) -> dict[str, Any] | None:
    """Parse a TLS ServerHello message."""
    if len(raw_data) < 11:
        return None

    # ServerHello version at offset 9-10
    version = (raw_data[9] << 8) | raw_data[10]

    tls_info: dict[str, Any] = {
        "handshake_type": "server_hello",
        "type": "server_hello",
        "version": version,
        "is_quic": False,
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
    tls_info["cipher"] = cipher
    pos += 2

    # Compression method
    if pos + 1 > len(raw_data):
        return tls_info
    pos += 1

    # Parse extensions
    extensions: list[int] = []
    extension_data: dict[int, Any] = {}
    alpn_protocols: list[str] = []
    alpn_raw: list[bytes] = []
    supported_versions: list[int] = []

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
                alpn_protocols, alpn_raw = _parse_alpn_with_bytes(
                    raw_data[ext_data_start:ext_data_end]
                )
                extension_data[0x0010] = {"protocols": alpn_protocols}

            # Parse supported_versions (0x002b) - server selects one version
            elif ext_type == 0x002B:
                # `ext_len` is the length the packet declares, and `ext_data_end` is the
                # clamp that bounds the bytes the record holds. #617 records that a
                # record which declares two bytes and supplies none raised `IndexError`
                # here.
                if ext_data_end - ext_data_start >= 2:
                    sv = (raw_data[ext_data_start] << 8) | raw_data[ext_data_start + 1]
                    supported_versions = [sv]

            pos = ext_data_start + ext_len

    tls_info["extensions"] = extensions
    tls_info["extension_data"] = extension_data
    tls_info["alpn_protocols"] = alpn_protocols
    tls_info["alpn_raw"] = alpn_raw
    tls_info["supported_versions"] = supported_versions

    # If supported_versions indicates TLS 1.3, update the version
    if supported_versions:
        non_grease = [v for v in supported_versions if not is_grease_value(v)]
        if non_grease:
            tls_info["version"] = non_grease[0]

    return tls_info


def _parse_sni(data: bytes) -> str | bool:
    """Parse Server Name Indication extension data."""
    if len(data) < 5:
        return True  # Extension exists but can't parse hostname

    try:
        # SNI list length (2 bytes)
        _sni_list_len = (data[0] << 8) | data[1]
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
            hostname = data[pos : pos + hostname_len].decode("ascii", errors="ignore")
            return hostname if hostname else True

        return True
    except (ValueError, IndexError, UnicodeDecodeError) as e:
        logger.debug(f"Failed to parse SNI: {e}")
        return True


def _parse_supported_versions_client(data: bytes) -> list[int]:
    """Parse supported_versions extension from ClientHello."""
    versions: list[int] = []
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


def _parse_alpn(data: bytes) -> list[str]:
    """Parse Application-Layer Protocol Negotiation extension data.

    Returns a list of decoded strings. Raw bytes are stored separately on the
    tls_info dict via _parse_alpn_with_bytes() — callers that need byte-level
    fidelity (e.g. JA4 ALPN per PR #277) should use that helper.
    """
    protocols, _ = _parse_alpn_with_bytes(data)
    return protocols


def _parse_alpn_with_bytes(data: bytes) -> tuple[list[str], list[bytes]]:
    """Parse ALPN, returning both decoded strings and original bytes.

    Returns:
        (protocols, raw_protocols) where ``protocols`` is a list of best-effort
        ASCII-decoded strings (errors ignored, non-ASCII bytes dropped) and
        ``raw_protocols`` is a list of the corresponding raw bytes objects.
    """
    protocols: list[str] = []
    raw_protocols: list[bytes] = []
    if len(data) < 2:
        return protocols, raw_protocols

    try:
        alpn_list_len = (data[0] << 8) | data[1]
        pos = 2

        while pos < min(2 + alpn_list_len, len(data)):
            if pos + 1 > len(data):
                break
            proto_len = data[pos]
            pos += 1

            if pos + proto_len > len(data):
                break
            raw = bytes(data[pos : pos + proto_len])
            raw_protocols.append(raw)
            protocols.append(raw.decode("ascii", errors="ignore"))
            pos += proto_len
    except (ValueError, IndexError, UnicodeDecodeError) as e:
        logger.debug(f"Failed to parse ALPN: {e}")

    return protocols, raw_protocols


def _parse_signature_algorithms(data: bytes) -> list[int]:
    """Parse signature_algorithms extension data."""
    algorithms: list[int] = []
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


def is_grease_value(value: Any) -> bool:
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


def find_tls_extension(extensions: Iterable[Any], extension_type: Any) -> Any:
    """Find a specific TLS extension by type."""
    for ext in extensions:
        if hasattr(ext, "type") and ext.type == extension_type:
            return ext
    return None
