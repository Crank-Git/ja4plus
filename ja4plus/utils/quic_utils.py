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
    return HKDFExpand(
        algorithm=hashes.SHA256(), length=length, info=hkdf_label
    ).derive(secret)


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
    sample = packet_bytes[sample_offset:sample_offset + 16]

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

    ad = packet_bytes[:pn_offset + pn_length]
    ciphertext = packet_bytes[pn_offset + pn_length:]

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(bytes(nonce), ciphertext, ad)


def extract_crypto_frames(plaintext):
    """Extract and reassemble CRYPTO frame data from decrypted QUIC payload."""
    crypto_data = {}
    pos = 0
    while pos < len(plaintext):
        frame_type = plaintext[pos]

        if frame_type == 0x00:
            pos += 1
            continue
        if frame_type == 0x01:
            pos += 1
            continue

        if frame_type == 0x06:
            pos += 1
            offset, consumed = _decode_varint(plaintext[pos:])
            pos += consumed
            length, consumed = _decode_varint(plaintext[pos:])
            pos += consumed
            crypto_data[offset] = plaintext[pos:pos + length]
            pos += length
        else:
            break

    if not crypto_data:
        return None
    reassembled = bytearray()
    for offset in sorted(crypto_data.keys()):
        reassembled.extend(crypto_data[offset])
    return bytes(reassembled)


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
    dcid = udp_payload[6:6 + dcid_len]

    quic_version = 2 if is_v2 else 1
    client_secret, _ = derive_initial_secrets(dcid, quic_version)
    key, iv, hp_key = derive_key_iv_hp(client_secret)

    try:
        unprotected, pn, pn_length = remove_header_protection(udp_payload, hp_key)
        pn_offset = _find_pn_offset(udp_payload)

        plaintext = decrypt_initial_payload(
            unprotected, pn, pn_length, pn_offset, key, iv
        )

        client_hello_bytes = extract_crypto_frames(plaintext)
        if not client_hello_bytes:
            return None

        if len(client_hello_bytes) < 4 or client_hello_bytes[0] != 0x01:
            return None

        ch_length = len(client_hello_bytes)
        fake_record = (
            bytes([0x16, 0x03, 0x01])
            + struct.pack("!H", ch_length)
            + client_hello_bytes
        )

        from ja4plus.utils.tls_utils import parse_tls_handshake
        tls_info = parse_tls_handshake(fake_record)
        if tls_info:
            tls_info["is_quic"] = True
        return tls_info

    except Exception as e:
        logger.debug(f"QUIC parsing failed: {e}")
        return None
