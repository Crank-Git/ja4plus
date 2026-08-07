"""No parser trusts a length field it read from the packet.

`FR-correctness-audit-8` and `FR-correctness-audit-10` state the contract. Each case
mutates one length field of a real ClientHello and reads the result.
"""

import pytest
from scapy.all import Raw

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

# `badcurveball.pcap` carries this ClientHello. The unmutated case pins the value, so
# every mutated case below proves that the parser reads the mutated bytes.
RECORDED_JA4 = "t13d1615h2_46e7e9700bed_45f260be83e2"

# The offsets of a TLS record header and a handshake header, from the first byte of the
# record. RFC 8446 section 5.1 gives the record header, and section 4 gives the
# handshake header.
RECORD_LENGTH_OFFSET = 3
HANDSHAKE_LENGTH_OFFSET = 6


def read_ja4(packet, load):
    """Return the JA4 fingerprint of the packet, with the payload replaced.

    Args:
        packet: The packet to copy.
        load: The payload bytes the copy carries.

    Returns:
        The fingerprint, or None when the parser reads nothing.

    Raises:
        Exception: The fingerprinter raised. Every case treats a raise as a failure.
    """
    copy = packet.copy()
    copy[Raw].load = load
    return JA4Fingerprinter().process_packet(copy)


def extensions_length_offset(load):
    """Return the offset of the extension-list length field in a ClientHello.

    The walk repeats the parser's own steps, because a length field has no fixed
    offset. Each variable field precedes the extension list.

    Args:
        load: The ClientHello bytes, from the first byte of the record.

    Returns:
        The offset of the two-byte extension-list length field.
    """
    # 5 record header bytes, 4 handshake header bytes, 2 version bytes, 32 random bytes.
    position = 11 + 32
    position += 1 + load[position]  # The session identifier.
    position += 2 + ((load[position] << 8) | load[position + 1])  # The cipher list.
    position += 1 + load[position]  # The compression list.
    return position


@pytest.fixture
def client_hello_load(client_hello_packet):
    """Return the ClientHello payload bytes."""
    return bytes(client_hello_packet[Raw].load)


def test_the_unmutated_client_hello_produces_the_recorded_fingerprint(
    client_hello_packet, client_hello_load
):
    """The parser reads this packet, so every mutated case below can fail."""
    assert read_ja4(client_hello_packet, client_hello_load) == RECORDED_JA4


def test_the_record_declares_more_bytes_than_the_cases_below_supply(client_hello_load):
    """The record header declares 512 bytes, so a shorter payload contradicts it."""
    declared = (client_hello_load[RECORD_LENGTH_OFFSET] << 8) | client_hello_load[
        RECORD_LENGTH_OFFSET + 1
    ]

    assert declared == 512
    assert len(client_hello_load) == declared + 5


@pytest.mark.parametrize("kept", [12, 64, 256, 516])
def test_a_record_that_declares_more_bytes_than_the_packet_produces_no_fingerprint(
    client_hello_packet, client_hello_load, kept
):
    """The cut keeps every length field, so the record declares more bytes than it holds."""
    assert read_ja4(client_hello_packet, client_hello_load[:kept]) is None


def test_a_handshake_length_larger_than_the_packet_produces_no_fingerprint(
    client_hello_packet, client_hello_load
):
    """The handshake length bounds the hello, so an inflated value reads past the packet."""
    mutated = bytearray(client_hello_load)
    mutated[HANDSHAKE_LENGTH_OFFSET : HANDSHAKE_LENGTH_OFFSET + 3] = b"\xff\xff\xff"

    assert read_ja4(client_hello_packet, bytes(mutated)) is None


def test_a_record_length_larger_than_the_packet_produces_no_exception(
    client_hello_packet, client_hello_load
):
    """The record length bounds a group of messages, not one hello.

    A TLS 1.2 server coalesces several handshake messages into one record, and #151
    names the three FoxIO streams the record bound rejected. The hello therefore still
    parses, and the inflated record length reaches no read.
    """
    mutated = bytearray(client_hello_load)
    mutated[RECORD_LENGTH_OFFSET : RECORD_LENGTH_OFFSET + 2] = b"\xff\xff"

    assert read_ja4(client_hello_packet, bytes(mutated)) == RECORDED_JA4


def test_an_extension_list_that_declares_more_extensions_produces_no_exception(
    client_hello_packet, client_hello_load
):
    """The parser bounds the extension walk on the payload length, not on the declaration.

    The fingerprint stays equal to the recorded value, so the walk read the extensions
    the packet carries and stopped at the last one.
    """
    offset = extensions_length_offset(client_hello_load)
    declared = (client_hello_load[offset] << 8) | client_hello_load[offset + 1]
    assert declared == len(client_hello_load) - offset - 2

    mutated = bytearray(client_hello_load)
    mutated[offset : offset + 2] = b"\xff\xff"

    assert read_ja4(client_hello_packet, bytes(mutated)) == RECORDED_JA4


def test_an_extension_that_declares_more_bytes_than_the_packet_produces_no_exception(
    client_hello_packet, client_hello_load
):
    """An inflated extension length moves the walk past the payload, and the walk stops.

    The result differs from the recorded value, because the walk reads one extension
    and reaches no other. A different value proves the parser read the mutated field.
    """
    # The first extension header follows the two-byte extension-list length field. Its
    # own length field follows its two-byte type field.
    offset = extensions_length_offset(client_hello_load) + 2 + 2

    mutated = bytearray(client_hello_load)
    mutated[offset : offset + 2] = b"\xff\xff"

    produced = read_ja4(client_hello_packet, bytes(mutated))

    assert produced is not None
    assert produced != RECORDED_JA4
