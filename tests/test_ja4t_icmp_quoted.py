"""The JA4T reader reads the TCP header that an ICMP error message quotes.

The maintainer ruled split T1 on 2026-08-14, under `Crank-Git/ja4plus-go#484`, and
`Crank-Git/ja4plus-go#494` built the Go half. #610 carries this half.
`wireshark/source/packet-ja4.c:1261` matches the field abbreviation `tcp.flags` anywhere
in the protocol tree, so the dissector writes a JA4T value for such a frame.

`scapy` decodes the quoted header as `IPerror` and `TCPerror`, so `haslayer(TCP)` reports
false and the reader before #610 produced nothing.

Every packet is hostile input. The quoted bytes carry four length fields, and each case
below states which one it moves.
"""

from __future__ import annotations

import pytest
from scapy.all import ICMP, IP, TCP, Ether, Raw

from ja4plus.fingerprinters.ja4t import JA4TFingerprinter, generate_ja4t
from ja4plus.utils.icmp_quoted import quoted_tcp_header

# The option list of the 31 quoted SYN frames of `ssh2.pcapng`, in wire order. It writes
# part b as `2-1-3-1-1-4`.
SSH2_OPTIONS = [
    ("MSS", 1460),
    ("NOP", None),
    ("WScale", 8),
    ("NOP", None),
    ("NOP", None),
    ("SAckOK", b""),
]

# The value that `tests/foxio_vectors/wireshark_expected/ssh2.pcapng.json` holds for each
# of those frames.
SSH2_VALUE = "64240_2-1-3-1-1-4_1460_8"


def quoted_syn(
    src: str = "172.16.225.48",
    dst: str = "10.244.39.47",
    sport: int = 57361,
    dport: int = 5000,
) -> bytes:
    """Return the bytes of one IPv4 SYN packet that an ICMP message quotes.

    Args:
        src: The address of the client.
        dst: The address of the server.
        sport: The port of the client.
        dport: The port of the server.

    Returns:
        The IPv4 datagram, header and TCP header together.
    """
    syn = IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags="S", window=64240, options=SSH2_OPTIONS
    )
    return bytes(syn)


def icmp_error(quoted: bytes, icmp_type: int = 3, code: int = 13) -> Ether:
    """Return one ICMP error message that quotes the argument.

    Args:
        quoted: The bytes of the packet the message reports.
        icmp_type: The ICMP type.
        code: The ICMP code.

    Returns:
        One frame, read back from its own bytes so that every layer dissects.
    """
    frame = (
        Ether()
        / IP(src="10.128.128.128", dst="172.16.225.48")
        / ICMP(type=icmp_type, code=code)
        / Raw(load=quoted)
    )
    return Ether(bytes(frame))


class TestTheReaderReadsTheQuotedHeader:
    """The reader produces the JA4T value of the connection the message reports."""

    def test_produces_the_ssh2_value_for_a_quoted_syn(self) -> None:
        """A destination-unreachable message that quotes a SYN produces its JA4T value."""
        frame = icmp_error(quoted_syn())
        assert generate_ja4t(frame) == SSH2_VALUE

    def test_reports_no_tcp_layer_on_such_a_frame(self) -> None:
        """`haslayer(TCP)` reports false, which is the cause #610 repairs."""
        frame = icmp_error(quoted_syn())
        assert not frame.haslayer(TCP)

    @pytest.mark.parametrize("icmp_type", [3, 4, 5, 11, 12])
    def test_reads_every_icmp_error_type(self, icmp_type: int) -> None:
        """RFC 792 gives the quoted header to these five types alone."""
        frame = icmp_error(quoted_syn(), icmp_type=icmp_type, code=0)
        assert generate_ja4t(frame) == SSH2_VALUE

    @pytest.mark.parametrize("icmp_type", [0, 8, 13, 14, 15, 16])
    def test_reads_no_informational_icmp_type(self, icmp_type: int) -> None:
        """An informational message carries an identifier in place of a quoted header."""
        frame = icmp_error(quoted_syn(), icmp_type=icmp_type, code=0)
        assert generate_ja4t(frame) is None

    def test_reads_no_quoted_syn_ack(self) -> None:
        """JA4T reads a SYN alone, and the quoted header follows that same gate."""
        syn_ack = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags="SA", window=64240)
        assert generate_ja4t(icmp_error(bytes(syn_ack))) is None

    def test_reads_no_quoted_ack(self) -> None:
        """Frame 197 of `ssh2.pcapng` quotes an ACK, and it produces no value."""
        ack = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags="A", window=64240)
        assert generate_ja4t(icmp_error(bytes(ack))) is None

    def test_keys_the_connection_on_the_quoted_header(self) -> None:
        """The quoted header names the connection, and the outer addresses name a router.

        The message travels from the router to the client, so the outer address pair
        names no endpoint of the connection the value describes.
        """
        fingerprinter = JA4TFingerprinter()
        assert fingerprinter.process_packet(icmp_error(quoted_syn())) == SSH2_VALUE
        # The real SYN of that same connection reaches the reader second, and the
        # connection already produced its one value.
        real = (
            Ether()
            / IP(src="172.16.225.48", dst="10.244.39.47")
            / TCP(sport=57361, dport=5000, flags="S", window=64240, options=SSH2_OPTIONS)
        )
        assert fingerprinter.process_packet(Ether(bytes(real))) is None

    def test_reads_no_second_message_of_one_connection(self) -> None:
        """A retransmitted SYN produces one more ICMP message and no second value."""
        fingerprinter = JA4TFingerprinter()
        assert fingerprinter.process_packet(icmp_error(quoted_syn())) == SSH2_VALUE
        assert fingerprinter.process_packet(icmp_error(quoted_syn())) is None


class TestTheReaderTrustsNoLengthField:
    """Every packet is hostile input, so the reader bounds four length fields."""

    def test_returns_nothing_for_an_ip_header_length_below_twenty(self) -> None:
        """An IHL of 4 words names 16 bytes, which holds no whole IPv4 header."""
        quoted = bytearray(quoted_syn())
        quoted[0] = 0x44
        assert quoted_tcp_header(icmp_error(bytes(quoted))) is None

    def test_returns_nothing_for_an_ip_header_length_past_the_message(self) -> None:
        """An IHL of 15 words names 60 bytes, and the message quotes 52."""
        quoted = bytearray(quoted_syn())
        quoted[0] = 0x4F
        assert quoted_tcp_header(icmp_error(bytes(quoted))) is None

    def test_reads_the_carried_length_where_the_total_length_declares_more(self) -> None:
        """A declared total length above the carried length names bytes nobody quotes."""
        quoted = bytearray(quoted_syn())
        quoted[2:4] = (4000).to_bytes(2, "big")
        assert generate_ja4t(icmp_error(bytes(quoted))) == SSH2_VALUE

    def test_returns_nothing_where_the_total_length_ends_the_tcp_header(self) -> None:
        """A declared total length of 30 bytes leaves 10 bytes for a 32-byte header."""
        quoted = bytearray(quoted_syn())
        quoted[2:4] = (30).to_bytes(2, "big")
        assert quoted_tcp_header(icmp_error(bytes(quoted))) is None

    def test_returns_nothing_for_a_data_offset_past_the_quoted_bytes(self) -> None:
        """A data offset of 15 words names 60 bytes, and the message quotes 32."""
        quoted = bytearray(quoted_syn())
        quoted[20 + 12] = 0xF0
        assert quoted_tcp_header(icmp_error(bytes(quoted))) is None

    def test_returns_nothing_for_a_data_offset_below_five(self) -> None:
        """A data offset of 4 words names 16 bytes, which holds no whole TCP header."""
        quoted = bytearray(quoted_syn())
        quoted[20 + 12] = 0x40
        assert quoted_tcp_header(icmp_error(bytes(quoted))) is None

    def test_stops_on_an_option_length_past_the_option_field(self) -> None:
        """An option that declares 200 bytes stops the reader, and it raises nothing.

        `read_options` stops before it records the kind, so the first option of the list
        reaches part b nowhere and part b writes `00`.
        """
        quoted = bytearray(quoted_syn())
        quoted[20 + 20 + 1] = 200
        assert generate_ja4t(icmp_error(bytes(quoted))) == "64240_00_00_00"

    def test_returns_nothing_for_a_truncated_quote(self) -> None:
        """RFC 792 asks for 8 bytes of the transport header, and JA4T needs 20."""
        assert quoted_tcp_header(icmp_error(quoted_syn()[:28])) is None

    def test_returns_nothing_for_an_empty_quote(self) -> None:
        """A message that quotes nothing holds no IPv4 header."""
        assert quoted_tcp_header(icmp_error(b"")) is None

    def test_returns_nothing_for_a_protocol_other_than_tcp(self) -> None:
        """A quoted UDP datagram carries no TCP header at the header offset."""
        quoted = bytearray(quoted_syn())
        quoted[9] = 17
        assert quoted_tcp_header(icmp_error(bytes(quoted))) is None

    def test_returns_nothing_for_an_ip_version_other_than_four(self) -> None:
        """The reader reads an IPv4 header alone."""
        quoted = bytearray(quoted_syn())
        quoted[0] = 0x65
        assert quoted_tcp_header(icmp_error(bytes(quoted))) is None

    def test_returns_nothing_for_a_later_fragment(self) -> None:
        """A later fragment of the quoted datagram carries no transport header."""
        quoted = bytearray(quoted_syn())
        quoted[6:8] = (0x0001).to_bytes(2, "big")
        assert quoted_tcp_header(icmp_error(bytes(quoted))) is None

    def test_reads_the_first_fragment(self) -> None:
        """A fragment offset of zero holds the transport header, and the more-fragments
        flag moves it nowhere."""
        quoted = bytearray(quoted_syn())
        quoted[6:8] = (0x2000).to_bytes(2, "big")
        assert generate_ja4t(icmp_error(bytes(quoted))) == SSH2_VALUE
