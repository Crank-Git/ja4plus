"""A builder of QUIC Initial packets for the test suite.

A test of the JA4L QUIC path needs a server Initial packet that decrypts, because the
fingerprinter reads the ServerHello to find its measurement point. This module builds
one. A test of the QUIC version 2 client path needs a client Initial packet that
decrypts, because a packet the reader rejects and a packet the reader fails to decrypt
both produce nothing. RFC 9000 Section 17.2 gives the long header layout. RFC 9001
Sections 5.2, 5.3 and 5.4 give the key derivation, the payload protection, and the
header protection. RFC 9369 Sections 3.1 and 3.2 give the version 2 number and the
version 2 packet type codes.

The builder derives its keys with `ja4plus.utils.quic_utils`. The FoxIO vectors, not
this module, prove that the derivation is correct.
"""

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ja4plus.utils.quic_utils import QUIC_HANDSHAKE, derive_initial_secrets, derive_key_iv_hp

# The QUIC version 1 number, which RFC 9000 Section 15 gives as 0x00000001.
QUIC_VERSION_1 = 1

# The QUIC version 2 number, which RFC 9369 Section 3.1 gives as 0x6b3343cf.
QUIC_VERSION_2 = 0x6B3343CF

# Version 2 gives an Initial packet the long-header type code 1, and version 1 gives it
# the code 0. RFC 9369 Section 3.2 states both codes.
INITIAL_TYPE_CODES = {QUIC_VERSION_1: 0, QUIC_VERSION_2: 1}

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
        value: A number from 0 to 4611686018427387903.

    Returns:
        The encoded bytes. RFC 9000 Section 16 gives the four forms.

    Raises:
        ValueError: The number needs more than eight bytes.
    """
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return struct.pack("!H", value | 0x4000)
    if value < 0x40000000:
        return struct.pack("!I", value | 0x80000000)
    if value < 0x4000000000000000:
        return struct.pack("!Q", value | 0xC000000000000000)
    raise ValueError("the builder encodes no number above 4611686018427387903")


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


def handshake_packet(payload_length=32, version=QUIC_VERSION_1):
    """Return the UDP payload of one QUIC Handshake packet.

    The packet carries no readable frame. A JA4L test reads the packet type only.
    RFC 9001 Section 5.4.1 protects the low four bits of the first byte. It leaves bits
    4 and 5 clear, so a reader states the packet type without any key.

    Args:
        payload_length: The number of protected payload bytes.
        version: The QUIC version number.

    Returns:
        The bytes of the UDP payload.
    """
    header = bytes([0xC0 | (QUIC_HANDSHAKE << 4)]) + struct.pack("!I", version)
    header += b"\x00"  # An empty destination connection ID.
    header += b"\x00"  # An empty source connection ID.
    header += encode_varint(payload_length + 1)
    header += b"\x00"  # The packet number.
    return header + b"\x00" * payload_length


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

    return _protect(header, plaintext, packet_number, key, iv, hp_key) + trailer


def _protect(header, plaintext, packet_number, key, iv, hp_key):
    """Return one protected QUIC packet.

    The builder appends the length field and the packet number to the header, encrypts
    the payload, and then protects the header. RFC 9001 Sections 5.3 and 5.4 give the
    two steps and their order.

    Args:
        header: The long-header bytes up to the token field, and no further.
        plaintext: The QUIC frames the packet carries.
        packet_number: The packet number, which the builder encodes in one byte.
        key: The AES-128-GCM payload key.
        iv: The payload nonce base.
        hp_key: The header protection key.

    Returns:
        The bytes of one QUIC packet.
    """
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
    return bytes(packet)


def client_hello(sni_hostname="example.com"):
    """Return one TLS ClientHello handshake message.

    The message holds one cipher suite and one server name extension, which is the
    least a QUIC test needs `parse_tls_handshake` to read.

    Args:
        sni_hostname: The server name the extension carries.

    Returns:
        The message bytes, which start with the handshake type 0x01.
    """
    hostname = sni_hostname.encode()
    name_entry = b"\x00" + len(hostname).to_bytes(2, "big") + hostname
    name_list = len(name_entry).to_bytes(2, "big") + name_entry
    extension = b"\x00\x00" + len(name_list).to_bytes(2, "big") + name_list

    body = bytearray()
    body += b"\x03\x03"  # The legacy version field, which TLS 1.3 holds at 0x0303.
    body += b"\x00" * 32  # The random field.
    body += b"\x00"  # An empty session ID.
    body += b"\x00\x02\x13\x01"  # One cipher suite, TLS_AES_128_GCM_SHA256.
    body += b"\x01\x00"  # One compression method, which is the null method.
    body += len(extension).to_bytes(2, "big") + extension
    return b"\x01" + len(body).to_bytes(3, "big") + bytes(body)


def client_initial_crypto(dcid, plaintext, packet_number=0, version=QUIC_VERSION_1, type_code=None):
    """Return the UDP payload of one QUIC client Initial packet that decrypts.

    `client_initial` builds a packet with no readable payload. This builder encrypts the
    frames a caller gives, so that a test measures what the reader extracts.

    Args:
        dcid: The destination connection ID the client chooses. The Initial keys derive
            from it.
        plaintext: The QUIC frames the packet carries.
        packet_number: The packet number, which the builder encodes in one byte.
        version: The QUIC version number.
        type_code: The long-header type code the builder writes. The default is the code
            the version gives an Initial packet. A test states another code to build a
            packet that carries Initial keys under a type that is no Initial type.

    Returns:
        The bytes of the UDP payload.
    """
    if type_code is None:
        type_code = INITIAL_TYPE_CODES[version]
    client_secret, _ = derive_initial_secrets(bytes(dcid), 1 if version == QUIC_VERSION_1 else 2)
    key, iv, hp_key = derive_key_iv_hp(client_secret)

    header = bytes([0xC0 | (type_code << 4)]) + struct.pack("!I", version)
    header += bytes([len(dcid)]) + bytes(dcid)
    header += b"\x00"  # An empty source connection ID.
    header += b"\x00"  # An empty token.
    return _protect(header, plaintext, packet_number, key, iv, hp_key)
