"""QUIC Initial packet parsing for JA4+ fingerprinting.

Decrypts QUIC v1 (RFC 9001) and v2 (RFC 9369) Initial packets to
extract the TLS ClientHello for JA4 fingerprinting.
"""

import hashlib
import hmac
import logging
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
QUIC_V2_SALT = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")

QUIC_V2_VERSION = 0x6B3343CF

# The long-header packet types of QUIC version 1 (RFC 9000 Section 17.2).
QUIC_INITIAL = 0
QUIC_ZERO_RTT = 1
QUIC_HANDSHAKE = 2
QUIC_RETRY = 3

# QUIC version 2 gives the same four types different codes (RFC 9369 Section 3.2).
# This table reads a version 2 code and returns the version 1 code, so that a caller
# compares one number for both versions.
_VERSION_2_PACKET_TYPES = {
    1: QUIC_INITIAL,
    2: QUIC_ZERO_RTT,
    3: QUIC_HANDSHAKE,
    0: QUIC_RETRY,
}


def long_header_packet_type(udp_payload):
    """Return the long-header packet type of a QUIC datagram, or None.

    Args:
        udp_payload: The bytes of the UDP payload.

    Returns:
        `QUIC_INITIAL`, `QUIC_ZERO_RTT`, `QUIC_HANDSHAKE` or `QUIC_RETRY`. Returns
        None when the datagram is too short, when it holds a short header, or when it
        holds a version negotiation packet.
    """
    if len(udp_payload) < 5:
        return None
    first_byte = udp_payload[0]
    if not first_byte & 0x80:
        return None
    version = struct.unpack("!I", udp_payload[1:5])[0]
    if version == 0:
        return None
    packet_type = (first_byte & 0x30) >> 4
    if version == QUIC_V2_VERSION:
        return _VERSION_2_PACKET_TYPES.get(packet_type)
    return packet_type


def _decode_varint(data):
    """Decode a QUIC variable-length integer (RFC 9000 Section 16)."""
    prefix = data[0] >> 6
    length = 1 << prefix
    val = data[0] & 0x3F
    for i in range(1, length):
        val = (val << 8) | data[i]
    return val, length


def hkdf_expand_label(secret, label, context, length):
    """HKDF-Expand-Label as defined in TLS 1.3 (RFC 8446 Section 7.1)."""
    full_label = b"tls13 " + label
    hkdf_label = struct.pack("!H", length)
    hkdf_label += struct.pack("B", len(full_label)) + full_label
    hkdf_label += struct.pack("B", len(context)) + context
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=hkdf_label).derive(secret)


def derive_initial_secrets(dcid, version=1):
    """Derive QUIC Initial client and server secrets from the DCID."""
    salt = QUIC_V1_SALT if version == 1 else QUIC_V2_SALT
    initial_secret = hmac.new(salt, dcid, hashlib.sha256).digest()
    client_secret = hkdf_expand_label(initial_secret, b"client in", b"", 32)
    server_secret = hkdf_expand_label(initial_secret, b"server in", b"", 32)
    return client_secret, server_secret


def derive_key_iv_hp(secret):
    """Derive AES key, IV, and header protection key from a traffic secret."""
    key = hkdf_expand_label(secret, b"quic key", b"", 16)
    iv = hkdf_expand_label(secret, b"quic iv", b"", 12)
    hp = hkdf_expand_label(secret, b"quic hp", b"", 16)
    return key, iv, hp


def _find_pn_offset(packet_bytes):
    """Find the packet number offset in a QUIC Initial long header."""
    pos = 5
    dcid_len = packet_bytes[pos]
    pos += 1 + dcid_len
    scid_len = packet_bytes[pos]
    pos += 1 + scid_len
    token_len, consumed = _decode_varint(packet_bytes[pos:])
    pos += consumed + token_len
    _, consumed = _decode_varint(packet_bytes[pos:])
    pos += consumed
    return pos


def remove_header_protection(packet_bytes, hp_key):
    """Remove QUIC header protection to reveal the real packet number."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    pn_offset = _find_pn_offset(packet_bytes)
    sample_offset = pn_offset + 4
    sample = packet_bytes[sample_offset : sample_offset + 16]

    cipher = Cipher(algorithms.AES(hp_key), modes.ECB())
    encryptor = cipher.encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()

    header = bytearray(packet_bytes)
    header[0] ^= mask[0] & 0x0F
    pn_length = (header[0] & 0x03) + 1

    for i in range(pn_length):
        header[pn_offset + i] ^= mask[1 + i]

    pn = 0
    for i in range(pn_length):
        pn = (pn << 8) | header[pn_offset + i]

    return bytes(header), pn, pn_length


def decrypt_initial_payload(packet_bytes, pn, pn_length, pn_offset, key, iv):
    """Decrypt a QUIC Initial packet payload using AES-128-GCM."""
    nonce = bytearray(iv)
    pn_bytes = pn.to_bytes(len(nonce), "big")
    for i in range(len(nonce)):
        nonce[i] ^= pn_bytes[i]

    ad = packet_bytes[: pn_offset + pn_length]
    ciphertext = packet_bytes[pn_offset + pn_length :]

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(bytes(nonce), ciphertext, ad)


def extract_crypto_frames(plaintext):
    """Extract and reassemble CRYPTO frame data from decrypted QUIC payload.

    Single-datagram convenience: reassembles fragments from a single
    Initial packet's plaintext into a contiguous byte string, or returns
    None if no CRYPTO frames are present.
    """
    fragments = parse_crypto_frames(plaintext)
    if not fragments:
        return None
    return reassemble_crypto_fragments(fragments)


def parse_crypto_frames(plaintext):
    """Extract CRYPTO frame fragments from a decrypted QUIC Initial payload.

    Returns a list of (offset, data) tuples in the order they appear.
    Skips PADDING (0x00), PING (0x01), and ACK (0x02, 0x03) frames so
    multi-packet captures with intermixed ACKs still surface their
    CRYPTO fragments. Stops at the first unknown frame type.
    """
    fragments = []
    pos = 0
    while pos < len(plaintext):
        frame_type = plaintext[pos]

        if frame_type == 0x00 or frame_type == 0x01:
            pos += 1
            continue

        if frame_type == 0x06:  # CRYPTO
            pos += 1
            offset, consumed = _decode_varint(plaintext[pos:])
            pos += consumed
            length, consumed = _decode_varint(plaintext[pos:])
            pos += consumed
            if pos + length > len(plaintext):
                break
            fragments.append((offset, bytes(plaintext[pos : pos + length])))
            pos += length
            continue

        if frame_type == 0x02 or frame_type == 0x03:  # ACK
            pos += 1
            try:
                _, c = _decode_varint(plaintext[pos:])
                pos += c
                _, c = _decode_varint(plaintext[pos:])
                pos += c
                range_count, c = _decode_varint(plaintext[pos:])
                pos += c
                _, c = _decode_varint(plaintext[pos:])
                pos += c
                for _ in range(range_count):
                    _, c = _decode_varint(plaintext[pos:])
                    pos += c
                    _, c = _decode_varint(plaintext[pos:])
                    pos += c
                if frame_type == 0x03:
                    for _ in range(3):
                        _, c = _decode_varint(plaintext[pos:])
                        pos += c
            except (IndexError, ValueError):
                break
            continue

        # Unknown frame type — can't safely skip, stop here.
        break

    return fragments


def reassemble_crypto_fragments(fragments):
    """Reassemble offset-keyed CRYPTO fragments into a contiguous bytestring.

    Args:
        fragments: iterable of (offset, data) tuples (data may be bytes/bytearray)

    Returns:
        bytes (possibly empty if there are gaps that haven't been filled).
    """
    if not fragments:
        return b""
    # Deduplicate identical offsets (a fragment can appear in multiple Initials)
    by_offset = {}
    for offset, data in fragments:
        # Prefer the longest fragment seen for an offset (rare, but defensive).
        existing = by_offset.get(offset)
        if existing is None or len(data) > len(existing):
            by_offset[offset] = bytes(data)

    sorted_frags = sorted(by_offset.items())
    total_len = max(off + len(data) for off, data in sorted_frags)
    buf = bytearray(total_len)
    for off, data in sorted_frags:
        buf[off : off + len(data)] = data
    return bytes(buf)


def decrypt_quic_initial_crypto(udp_payload):
    """Decrypt a QUIC Initial packet and return its CRYPTO fragments.

    This is the multi-packet-friendly variant of parse_quic_initial:
    it returns the *fragments* and the DCID rather than trying to parse
    a ClientHello from a single datagram. Callers (e.g. JA4Fingerprinter)
    accumulate fragments per DCID across packets and try
    ``client_hello_from_crypto_fragments`` whenever new fragments arrive.

    Returns:
        (fragments, dcid) on success, or (None, None) if the packet is
        not a QUIC v1/v2 Initial (or decryption fails).

        ``fragments`` is a list of (offset, data) tuples.
    """
    if len(udp_payload) < 20:
        return None, None

    first_byte = udp_payload[0]
    if not (first_byte & 0x80):
        return None, None

    version = struct.unpack("!I", udp_payload[1:5])[0]
    if version == 0:
        return None, None

    packet_type = (first_byte & 0x30) >> 4
    is_v2 = version == 0x6B3343CF
    if is_v2:
        if packet_type != 0x01:
            return None, None
    else:
        if packet_type != 0x00:
            return None, None

    dcid_len = udp_payload[5]
    if 6 + dcid_len > len(udp_payload):
        return None, None
    dcid = bytes(udp_payload[6 : 6 + dcid_len])

    quic_version = 2 if is_v2 else 1
    client_secret, _ = derive_initial_secrets(dcid, quic_version)
    key, iv, hp_key = derive_key_iv_hp(client_secret)

    try:
        unprotected, pn, pn_length = remove_header_protection(udp_payload, hp_key)
        pn_offset = _find_pn_offset(udp_payload)
        plaintext = decrypt_initial_payload(unprotected, pn, pn_length, pn_offset, key, iv)
    except Exception as e:
        logger.debug(f"QUIC Initial decryption failed: {e}")
        return None, None

    return parse_crypto_frames(plaintext), dcid


def client_hello_from_crypto_fragments(fragments):
    """Reassemble fragments and try to parse a TLS ClientHello.

    Returns a tls_info dict (with is_quic=True) on success, or None if
    the assembled bytes don't form a complete ClientHello.
    """
    assembled = reassemble_crypto_fragments(fragments)
    if len(assembled) < 4:
        return None
    if assembled[0] != 0x01:  # ClientHello handshake type
        return None

    # The handshake message embeds a 24-bit length at bytes [1:4].
    msg_len = (assembled[1] << 16) | (assembled[2] << 8) | assembled[3]
    if 4 + msg_len > len(assembled):
        # Not yet complete — caller should keep accumulating fragments.
        return None

    fake_record = (
        bytes([0x16, 0x03, 0x01])
        + struct.pack("!H", min(len(assembled), 0xFFFF))
        + bytes(assembled)
    )

    from ja4plus.utils.tls_utils import parse_tls_handshake

    tls_info = parse_tls_handshake(fake_record)
    if tls_info:
        tls_info["is_quic"] = True
    return tls_info


def parse_quic_server_initial(udp_payload, client_dcid):
    """
    Parse a QUIC Server Initial packet and extract the TLS ServerHello.

    The client_dcid is the Destination Connection ID from the *client's*
    Initial packet, needed to derive the server's decryption keys.

    Args:
        udp_payload: Raw bytes of the UDP payload (server → client)
        client_dcid: bytes — the DCID the client sent in its Initial

    Returns:
        A tls_info dict with is_quic=True and handshake_type='server_hello',
        or None if the packet is not a QUIC Initial or decryption fails.
    """
    if len(udp_payload) < 5 or not client_dcid:
        return None

    first_byte = udp_payload[0]
    if not (first_byte & 0x80):
        return None  # short header

    version = struct.unpack("!I", udp_payload[1:5])[0]
    if version == 0:
        return None  # version negotiation

    quic_version = None
    packet_type = (first_byte & 0x30) >> 4
    is_v2 = version == 0x6B3343CF
    if is_v2:
        if packet_type != 0x01:
            return None
        quic_version = 2
    else:
        if packet_type != 0x00:
            return None
        quic_version = 1

    # Derive server keys using the CLIENT's original DCID
    _, server_secret = derive_initial_secrets(bytes(client_dcid), quic_version)
    key, iv, hp_key = derive_key_iv_hp(server_secret)

    try:
        unprotected, pn, pn_length = remove_header_protection(udp_payload, hp_key)
        pn_offset = _find_pn_offset(udp_payload)

        plaintext = decrypt_initial_payload(unprotected, pn, pn_length, pn_offset, key, iv)

        server_hello_bytes = extract_crypto_frames(plaintext)
        if not server_hello_bytes:
            return None

        # Must be a ServerHello (handshake type 0x02)
        if len(server_hello_bytes) < 1 or server_hello_bytes[0] != 0x02:
            return None

        sh_length = len(server_hello_bytes)
        fake_record = bytes([0x16, 0x03, 0x01]) + struct.pack("!H", sh_length) + server_hello_bytes

        from ja4plus.utils.tls_utils import parse_tls_handshake

        tls_info = parse_tls_handshake(fake_record)
        if tls_info:
            tls_info["is_quic"] = True
        return tls_info

    except Exception as e:
        logger.debug(f"QUIC server Initial parsing failed: {e}")
        return None


def parse_quic_initial(udp_payload):
    """Parse a QUIC Initial packet and extract the TLS ClientHello."""
    if len(udp_payload) < 20:
        return None

    first_byte = udp_payload[0]
    if not (first_byte & 0x80):
        return None

    version = struct.unpack("!I", udp_payload[1:5])[0]
    if version == 0:
        return None

    # Packet type is in bits 4-5 of the first byte.
    # QUIC v1: Initial = 0x00, QUIC v2 (RFC 9369): Initial = 0x01
    packet_type = (first_byte & 0x30) >> 4
    is_v2 = version == 0x6B3343CF
    if is_v2:
        if packet_type != 0x01:
            return None
    else:
        if packet_type != 0x00:
            return None

    dcid_len = udp_payload[5]
    dcid = udp_payload[6 : 6 + dcid_len]

    quic_version = 2 if is_v2 else 1
    client_secret, _ = derive_initial_secrets(dcid, quic_version)
    key, iv, hp_key = derive_key_iv_hp(client_secret)

    try:
        unprotected, pn, pn_length = remove_header_protection(udp_payload, hp_key)
        pn_offset = _find_pn_offset(udp_payload)

        plaintext = decrypt_initial_payload(unprotected, pn, pn_length, pn_offset, key, iv)

        client_hello_bytes = extract_crypto_frames(plaintext)
        if not client_hello_bytes:
            return None

        if len(client_hello_bytes) < 4 or client_hello_bytes[0] != 0x01:
            return None

        ch_length = len(client_hello_bytes)
        fake_record = bytes([0x16, 0x03, 0x01]) + struct.pack("!H", ch_length) + client_hello_bytes

        from ja4plus.utils.tls_utils import parse_tls_handshake

        tls_info = parse_tls_handshake(fake_record)
        if tls_info:
            tls_info["is_quic"] = True
        return tls_info

    except Exception as e:
        logger.debug(f"QUIC parsing failed: {e}")
        return None
