"""A builder of QUIC Initial packets for the test suite.

A test of the JA4L QUIC path needs a server Initial packet that decrypts, because the
fingerprinter reads the ServerHello to find its measurement point. This module builds
one. RFC 9000 Section 17.2 gives the long header layout, and RFC 9001 Sections 5.2,
5.3 and 5.4 give the key derivation, the payload protection and the header protection.

The builder derives its keys with `ja4plus.utils.quic_utils`. The FoxIO vectors, not
this module, prove that the derivation is correct.
"""

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ja4plus.utils.quic_utils import derive_initial_secrets, derive_key_iv_hp

# The QUIC version 1 number, which RFC 9000 Section 15 gives as 0x00000001.
QUIC_VERSION_1 = 1

# The header protection sample starts four bytes past the packet number offset and is
# 16 bytes long. RFC 9001 Section 5.4.2 states both numbers.
SAMPLE_OFFSET = 4
SAMPLE_LENGTH = 16

# One ACK frame that acknowledges packet number 0 and holds no further range. RFC 9000
# Section 19.3 gives the four fields.
ACK_FRAME = b"\x02\x00\x00\x00\x00"


def encode_varint(value):
    """Return the QUIC variable-length form of one number.

    Args:
        value: A number from 0 to 1073741823.

    Returns:
        The encoded bytes. RFC 9000 Section 16 gives the four forms.

    Raises:
        ValueError: The number needs more than four bytes.
    """
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return struct.pack("!H", value | 0x4000)
    if value < 0x40000000:
        return struct.pack("!I", value | 0x80000000)
    raise ValueError("the builder encodes no number above 1073741823")


def crypto_frame(offset, data):
    """Return one CRYPTO frame that carries the data at the offset."""
    return b"\x06" + encode_varint(offset) + encode_varint(len(data)) + data


def server_hello(body_length=40):
    """Return one TLS ServerHello handshake message.

    The message holds a handshake type, a 24-bit length and a body of zero bytes. A
    JA4L test reads the type and the length only.

    Args:
        body_length: The number of body bytes.

    Returns:
        The message bytes.
    """
    return b"\x02" + body_length.to_bytes(3, "big") + b"\x00" * body_length


def client_initial(dcid, version=QUIC_VERSION_1):
    """Return the UDP payload of one QUIC client Initial packet.

    The packet carries no readable payload. A JA4L test needs the connection ID only,
    because the server Initial keys derive from it.

    Args:
        dcid: The destination connection ID the client chooses.
        version: The QUIC version number.

    Returns:
        The bytes of the UDP payload.
    """
    payload = b"\x00" * 32
    header = bytes([0xC0]) + struct.pack("!I", version)
    header += bytes([len(dcid)]) + dcid
    header += b"\x00"  # An empty source connection ID.
    header += b"\x00"  # An empty token.
    header += encode_varint(len(payload) + 1)
    header += b"\x00"  # The packet number.
    return header + payload


def server_initial(client_dcid, plaintext, packet_number=0, version=QUIC_VERSION_1, trailer=b""):
    """Return the UDP payload of one QUIC server Initial packet that decrypts.

    Args:
        client_dcid: The destination connection ID the client sent. The server Initial
            keys derive from it.
        plaintext: The QUIC frames the packet carries.
        packet_number: The packet number, which the builder encodes in one byte.
        version: The QUIC version number.
        trailer: Bytes the builder appends behind the Initial packet, so that a test
            reproduces a datagram that coalesces two QUIC packets.

    Returns:
        The bytes of the UDP payload.
    """
    _, server_secret = derive_initial_secrets(bytes(client_dcid), 1 if version == 1 else 2)
    key, iv, hp_key = derive_key_iv_hp(server_secret)

    header = bytes([0xC0]) + struct.pack("!I", version)
    header += b"\x00"  # An empty destination connection ID.
    header += b"\x00"  # An empty source connection ID.
    header += b"\x00"  # An empty token.

    ciphertext_length = len(plaintext) + 16  # AES-128-GCM appends a 16-byte tag.
    header += encode_varint(ciphertext_length + 1)
    pn_offset = len(header)
    header += bytes([packet_number])

    nonce = bytearray(iv)
    packet_number_bytes = packet_number.to_bytes(len(nonce), "big")
    for index in range(len(nonce)):
        nonce[index] ^= packet_number_bytes[index]
    ciphertext = AESGCM(key).encrypt(bytes(nonce), plaintext, header)

    packet = bytearray(header + ciphertext)
    sample_start = pn_offset + SAMPLE_OFFSET
    sample = bytes(packet[sample_start : sample_start + SAMPLE_LENGTH])
    encryptor = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()
    packet[0] ^= mask[0] & 0x0F
    packet[pn_offset] ^= mask[1]
    return bytes(packet) + trailer
