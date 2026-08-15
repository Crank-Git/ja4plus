"""The quoted-header reader raises no exception on a crafted ICMP error message.

#610 reads the TCP header that an ICMP error message quotes. The quoted bytes carry four
length fields, and each one names bytes the message need not hold: the IP header length,
the IP total length, the TCP data offset and the TCP option list.

Every case reads what the reader produced, because a case that asserts "no exception"
alone passes where no parser runs. `tests/fuzz/README.md` states that rule, and `spy_on`
proves the reader read the bytes.

Every packet is hostile input. A parser that cannot read a packet returns nothing, and it
does not raise.
"""

import random
import struct

import pytest
from scapy.all import ICMP, IP, TCP, Ether, Raw

import ja4plus.utils.icmp_quoted as icmp_quoted
from ja4plus.fingerprinters.ja4t import generate_ja4t
from ja4plus.utils.icmp_quoted import ICMP_ERROR_TYPES, read_quoted_header
from tests.fuzz.support import spy_on

DRAWS = 512
SEED = 610

# The three fields of the quoted IPv4 header that name a length or a shape, and the one
# field of the quoted TCP header that names a length.
IP_VERSION_BYTE = 0
IP_TOTAL_LENGTH_OFFSET = 2
IP_FRAGMENT_OFFSET = 6
IP_PROTOCOL_OFFSET = 9
TCP_DATA_OFFSET_BYTE = 32

DECLARED_LENGTHS = (0, 1, 2, 19, 20, 21, 51, 52, 53, 1500, 65535)
VERSION_BYTES = (0x00, 0x40, 0x44, 0x45, 0x4F, 0x54, 0x65, 0xFF)
DATA_OFFSET_BYTES = (0x00, 0x40, 0x50, 0x60, 0x80, 0x90, 0xF0)


def well_formed_quote() -> bytes:
    """Return the bytes of one IPv4 SYN packet with a whole option list.

    Returns:
        A 52-byte datagram: a 20-byte IPv4 header and a 32-byte TCP header.
    """
    syn = IP(src="172.16.225.48", dst="10.244.39.47") / TCP(
        sport=57361,
        dport=5000,
        flags="S",
        window=64240,
        options=[
            ("MSS", 1460),
            ("NOP", None),
            ("WScale", 8),
            ("NOP", None),
            ("NOP", None),
            ("SAckOK", b""),
        ],
    )
    return bytes(syn)


def message(quoted: bytes, icmp_type: int = 3) -> Ether:
    """Return one ICMP error message that quotes the argument.

    Args:
        quoted: The bytes the message reports.
        icmp_type: The ICMP type.

    Returns:
        One frame, read back from its own bytes so that every layer dissects.
    """
    frame = (
        Ether()
        / IP(src="10.128.128.128", dst="172.16.225.48")
        / ICMP(type=icmp_type)
        / Raw(load=quoted)
    )
    return Ether(bytes(frame))


def read(frame: Ether) -> str | None:
    """Return the JA4T value of one frame, and raise whatever the reader raises.

    Args:
        frame: The frame the case built.

    Returns:
        The fingerprint, or None.
    """
    return generate_ja4t(frame)


class TestTheReaderStopsOnADeclaredLength:
    """A declared length that the message does not hold produces no value and no error."""

    @pytest.mark.parametrize("declared", DECLARED_LENGTHS)
    def test_reads_a_crafted_ip_total_length(self, declared: int, monkeypatch) -> None:
        """The IP total length names the end of the quoted datagram."""
        counter = spy_on(monkeypatch, icmp_quoted, "read_quoted_header")
        quoted = bytearray(well_formed_quote())
        quoted[IP_TOTAL_LENGTH_OFFSET : IP_TOTAL_LENGTH_OFFSET + 2] = declared.to_bytes(2, "big")
        result = read(message(bytes(quoted)))
        assert counter.calls == 1
        assert result is None or isinstance(result, str)

    @pytest.mark.parametrize("version", VERSION_BYTES)
    def test_reads_a_crafted_version_and_header_length(self, version: int, monkeypatch) -> None:
        """The low half of byte 0 names the IP header length, in 32-bit words."""
        counter = spy_on(monkeypatch, icmp_quoted, "read_quoted_header")
        quoted = bytearray(well_formed_quote())
        quoted[IP_VERSION_BYTE] = version
        result = read(message(bytes(quoted)))
        assert counter.calls == 1
        assert result is None or isinstance(result, str)

    @pytest.mark.parametrize("data_offset", DATA_OFFSET_BYTES)
    def test_reads_a_crafted_tcp_data_offset(self, data_offset: int, monkeypatch) -> None:
        """The high half of byte 12 of the TCP header names the data offset."""
        counter = spy_on(monkeypatch, icmp_quoted, "read_quoted_header")
        quoted = bytearray(well_formed_quote())
        quoted[TCP_DATA_OFFSET_BYTE] = data_offset
        result = read(message(bytes(quoted)))
        assert counter.calls == 1
        assert result is None or isinstance(result, str)

    @pytest.mark.parametrize("protocol", [0, 1, 6, 17, 47, 132, 255])
    def test_reads_a_crafted_ip_protocol(self, protocol: int, monkeypatch) -> None:
        """Byte 9 of the quoted IPv4 header names the transport protocol."""
        counter = spy_on(monkeypatch, icmp_quoted, "read_quoted_header")
        quoted = bytearray(well_formed_quote())
        quoted[IP_PROTOCOL_OFFSET] = protocol
        result = read(message(bytes(quoted)))
        assert counter.calls == 1
        assert result == ("64240_2-1-3-1-1-4_1460_8" if protocol == 6 else None)

    @pytest.mark.parametrize("flags", [0x0000, 0x2000, 0x4000, 0x0001, 0x1FFF, 0xFFFF])
    def test_reads_a_crafted_fragment_offset(self, flags: int, monkeypatch) -> None:
        """The low 13 bits of bytes 6 and 7 name the fragment offset."""
        counter = spy_on(monkeypatch, icmp_quoted, "read_quoted_header")
        quoted = bytearray(well_formed_quote())
        quoted[IP_FRAGMENT_OFFSET : IP_FRAGMENT_OFFSET + 2] = flags.to_bytes(2, "big")
        result = read(message(bytes(quoted)))
        assert counter.calls == 1
        later_fragment = flags & 0x1FFF != 0
        assert result == (None if later_fragment else "64240_2-1-3-1-1-4_1460_8")

    @pytest.mark.parametrize("length", [0, 1, 2, 3, 40, 200, 255])
    def test_reads_a_crafted_option_length(self, length: int, monkeypatch) -> None:
        """An option length byte names the byte count of that one option."""
        counter = spy_on(monkeypatch, icmp_quoted, "read_quoted_header")
        quoted = bytearray(well_formed_quote())
        quoted[20 + 20 + 1] = length
        result = read(message(bytes(quoted)))
        assert counter.calls == 1
        assert result is None or isinstance(result, str)


class TestTheReaderReadsEveryTruncation:
    """A message that quotes part of a datagram produces no value and no error."""

    @pytest.mark.parametrize("keep", list(range(0, 53)))
    def test_reads_a_quote_of_every_length(self, keep: int) -> None:
        """RFC 792 asks for 8 bytes of the transport header, and JA4T needs 20."""
        result = read(message(well_formed_quote()[:keep]))
        if keep < 52:
            assert result is None
        else:
            assert result == "64240_2-1-3-1-1-4_1460_8"


class TestTheReaderReadsRandomBytes:
    """A random payload under an ICMP error type produces no value and no error."""

    def test_reads_every_random_draw(self, monkeypatch) -> None:
        """The reader returns a string or None for each of 512 random payloads."""
        counter = spy_on(monkeypatch, icmp_quoted, "read_quoted_header")
        generator = random.Random(SEED)
        values = 0
        for _ in range(DRAWS):
            size = generator.randrange(0, 80)
            payload = bytes(generator.getrandbits(8) for _ in range(size))
            icmp_type = generator.choice(sorted(ICMP_ERROR_TYPES))
            result = read(message(payload, icmp_type=icmp_type))
            assert result is None or isinstance(result, str)
            if result is not None:
                values += 1
        assert counter.calls == DRAWS
        # A random payload reaches no whole IPv4 header of a TCP SYN, so this corpus
        # measures the refusal alone. `test_reads_every_byte_flip_of_one_whole_quote`
        # measures the other side, and it reads 47 values.
        assert values == 0

    def test_reads_every_byte_flip_of_one_whole_quote(self) -> None:
        """One flipped byte of a whole quote produces a string or None, and no error."""
        base = well_formed_quote()
        values = 0
        for index in range(len(base)):
            quoted = bytearray(base)
            quoted[index] ^= 0xFF
            result = read(message(bytes(quoted)))
            assert result is None or isinstance(result, str)
            if result is not None:
                values += 1
        # 5 of the 52 bytes carry the version, the header length, the protocol, the
        # fragment offset or the data offset, and a flip of one of those five stops the
        # reader. The other 47 reach a value.
        assert values == 47


class TestTheReaderCallsNoScapyDissector:
    """`TCP(bytes)` raises `struct.error` on a truncated option, and the reader avoids it."""

    def test_reads_a_header_that_the_scapy_dissector_refuses(self) -> None:
        """One measured option region raises `struct.error` in `scapy`, and #610 reads it.

        `generate_ja4t` catches `ValueError`, `TypeError`, `IndexError` and
        `AttributeError`, and `struct.error` is none of those. A run of 200000 random
        20-byte to 60-byte headers through `TCP(bytes)` raised it 9 times, and the region
        below comes from that run. `read_quoted_header` returns the bytes instead, so no
        `scapy` dissector reads them. `readQuotedTCPFields` of `Crank-Git/ja4plus-go`
        declines `DecodeFromBytes` for the matching defect of `gopacket`, which
        `Crank-Git/ja4plus-go#510` records.
        """
        quoted = bytearray(well_formed_quote())
        quoted[40:52] = bytes.fromhex("7909326e6f18d4fed11dae08")
        with pytest.raises(struct.error, match="unpack requires a buffer of 1 bytes"):
            TCP(bytes(quoted[20:]))
        assert read_quoted_header(bytes(quoted)) is not None
        assert read(message(bytes(quoted))) == "64240_121_00_00"
