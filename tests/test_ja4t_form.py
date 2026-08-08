"""The JA4T and JA4TS form the user decided on 2026-08-08.

#215 carries five readings. `docs/specs/foxio/JA4T.md` states each one, and the user
ruled on D1, D2 and D4 against the measurement #216 and #242 built. D3 and D5 are plain
defects and the issue body records why.

| Reading | The rule |
|---|---|
| D1 | An empty option list, an absent maximum segment size and a zero window scale each take the two-digit form. |
| D2 | The parser reads the raw TCP option bytes, so each End of Option List byte adds one entry. |
| D3 | Part b holds every option kind, and not the six kinds a name list holds. |
| D4 | One connection produces one JA4T value, from its first SYN. |
| D5 | A repeated option keeps the first value, and not the last. |

**D1 diverges from the FoxIO Rust implementation.** `packet-ja4.c:664` and
`zeek/ja4t/main.zeek:195-211` write the two-digit form, and `rust/ja4/src/tcp.rs` writes
one digit. Two of the three FoxIO forms agree, and the user follows them. The
`Divergence register` in `docs/specs/spec.md` records the cost.

Every case below fails on the base commit of #215.
"""

import pytest
from scapy.all import IP, TCP, rdpcap

from ja4plus.fingerprinters.ja4t import JA4TFingerprinter, generate_ja4t
from ja4plus.fingerprinters.ja4ts import generate_ja4ts
from ja4plus.utils.tcp_options import option_bytes, read_options, tcp_prefix

VECTORS = "tests/foxio_vectors"

# The option bytes of the SYN of `chrome-cloudflare-quic-with-secrets.pcapng`. The last
# two bytes are the pair of End of Option List bytes that D2 counts as two entries.
CHROME_OPTION_BYTES = bytes.fromhex("020405a0010303060101080a88d73b2c0000000004020000")


def syn_with_option_bytes(data, window=65535, sport=54321, dport=443, flags="S"):
    """Return a dissected TCP packet whose option field holds the exact bytes.

    A scapy option list re-serializes, so it cannot express a repeated option or an
    option kind scapy does not name. This helper writes the data offset itself and then
    dissects the header, which gives the packet the raw bytes a capture carries.

    Args:
        data: The raw TCP option bytes. The length is a multiple of four.
        window: The TCP window size.
        sport: The source port.
        dport: The destination port.
        flags: The TCP flag string.

    Returns:
        One IP packet that carries the TCP layer.
    """
    header = bytes(TCP(sport=sport, dport=dport, flags=flags, window=window))[:20]
    data_offset = (20 + len(data)) // 4
    header = header[:12] + bytes([(data_offset << 4) | (header[12] & 0x0F)]) + header[13:]
    return IP(src="10.0.0.1", dst="10.0.0.2") / TCP(header + data)


class TestD1TheTwoDigitForm:
    """D1 — an empty option list, an absent segment size and a zero scale take `00`."""

    def test_a_syn_with_no_option_writes_the_two_digit_form(self):
        packet = syn_with_option_bytes(b"", window=8192)
        assert generate_ja4t(packet) == "8192_00_00_00"

    def test_a_syn_ack_with_no_option_writes_the_two_digit_form(self):
        packet = syn_with_option_bytes(b"", window=8192, flags="SA")
        assert generate_ja4ts(packet) == "8192_00_00_00"

    def test_an_absent_maximum_segment_size_writes_two_digit_part_c(self):
        # One No Operation byte and three End of Option List pad bytes.
        packet = syn_with_option_bytes(bytes.fromhex("01000000"))
        assert generate_ja4t(packet).split("_")[2] == "00"

    def test_an_absent_window_scale_writes_two_digit_part_d(self):
        # Maximum Segment Size 1460, and no Window Scale option.
        packet = syn_with_option_bytes(bytes.fromhex("020405b4"))
        assert generate_ja4t(packet) == "65535_2_1460_00"

    def test_a_window_scale_of_zero_writes_two_digit_part_d(self):
        # Maximum Segment Size 1460, Window Scale 0, and one pad byte.
        packet = syn_with_option_bytes(bytes.fromhex("020405b403030000"))
        assert generate_ja4t(packet).split("_")[3] == "00"

    def test_a_window_scale_above_zero_keeps_one_digit(self):
        # Maximum Segment Size 1460, Window Scale 6, and one pad byte.
        packet = syn_with_option_bytes(bytes.fromhex("020405b403030600"))
        assert generate_ja4t(packet) == "65535_2-3-0_1460_6"

    def test_the_tunneled_vector_produces_the_decided_value(self):
        """`gre-erspan-vxlan.pcap` is the one vector whose SYN carries no option.

        The FoxIO Rust snapshot holds `8192__0_0`. The user chose the two-digit form on
        2026-08-08, so this value diverges from that snapshot on purpose. The register
        entry `gre-erspan-vxlan.pcap/0:65174/JA4T.1` records the divergence.
        """
        values = [
            generate_ja4t(packet)
            for packet in rdpcap("{}/gre-erspan-vxlan.pcap".format(VECTORS))
            if generate_ja4t(packet)
        ]
        assert values == ["8192_00_00_00"]


class TestD2TheRawOptionBytes:
    """D2 — one End of Option List byte adds one entry to part b."""

    def test_two_pad_bytes_add_two_entries(self):
        packet = syn_with_option_bytes(CHROME_OPTION_BYTES)
        assert generate_ja4t(packet) == "65535_2-1-3-1-1-8-4-0-0_1440_6"

    def test_the_chrome_vector_produces_the_rust_value(self):
        """`chrome-cloudflare-quic-with-secrets.pcapng` moves to the Rust value.

        The FoxIO Rust snapshot holds `65535_2-1-3-1-1-8-4-0-0_1440_6`, and version
        0.6.0 published `65535_2-1-3-1-1-8-4-0_1440_6`.
        """
        capture = "{}/chrome-cloudflare-quic-with-secrets.pcapng".format(VECTORS)
        values = [generate_ja4t(packet) for packet in rdpcap(capture)]
        assert "65535_2-1-3-1-1-8-4-0-0_1440_6" in values
        assert "65535_2-1-3-1-1-8-4-0_1440_6" not in values

    def test_a_syn_ack_counts_each_pad_byte_too(self):
        packet = syn_with_option_bytes(CHROME_OPTION_BYTES, flags="SA")
        assert generate_ja4ts(packet) == "65535_2-1-3-1-1-8-4-0-0_1440_6"


class TestD3EveryOptionKind:
    """D3 — part b holds every option kind the packet carries."""

    def test_part_b_holds_an_option_kind_no_name_list_holds(self):
        # Maximum Segment Size 1460, then kind 30 with a length of four.
        packet = syn_with_option_bytes(bytes.fromhex("020405b41e04ffff"))
        assert generate_ja4t(packet).split("_")[1] == "2-30"

    def test_part_b_holds_the_selective_acknowledgement_kind(self):
        # Kind 5 with a length of ten, then two pad bytes.
        packet = syn_with_option_bytes(bytes.fromhex("050a00000000000000000000"))
        assert generate_ja4t(packet).split("_")[1] == "5-0-0"


class TestD4OneValuePerConnection:
    """D4 — the first SYN of a connection produces the one value the connection holds."""

    def test_a_repeated_syn_produces_no_second_value(self):
        fingerprinter = JA4TFingerprinter()
        packet = syn_with_option_bytes(bytes.fromhex("020405b4"))
        assert fingerprinter.process_packet(packet) is not None
        assert fingerprinter.process_packet(packet) is None
        assert len(fingerprinter.get_fingerprints()) == 1

    def test_a_second_connection_produces_a_second_value(self):
        fingerprinter = JA4TFingerprinter()
        first = syn_with_option_bytes(bytes.fromhex("020405b4"), sport=54321)
        second = syn_with_option_bytes(bytes.fromhex("020405b4"), sport=54322)
        fingerprinter.process_packet(first)
        fingerprinter.process_packet(second)
        assert len(fingerprinter.get_fingerprints()) == 2

    def test_the_ssh2_vector_produces_one_value_for_each_connection(self):
        """`ssh2.pcapng` holds 19 connections and repeated SYN packets on 10 of them.

        The FoxIO Rust snapshot holds 19 JA4T values. Version 0.6.0 produced 44.
        """
        fingerprinter = JA4TFingerprinter()
        for packet in rdpcap("{}/ssh2.pcapng".format(VECTORS)):
            fingerprinter.process_packet(packet)
        assert len(fingerprinter.get_fingerprints()) == 19

    def test_cleanup_connection_lets_a_later_syn_produce_a_value(self):
        fingerprinter = JA4TFingerprinter()
        packet = syn_with_option_bytes(bytes.fromhex("020405b4"))
        fingerprinter.process_packet(packet)
        fingerprinter.cleanup_connection("10.0.0.1", 54321, "10.0.0.2", 443, "tcp")
        assert fingerprinter.process_packet(packet) is not None

    def test_cleanup_connection_reads_the_reverse_direction_too(self):
        fingerprinter = JA4TFingerprinter()
        packet = syn_with_option_bytes(bytes.fromhex("020405b4"))
        fingerprinter.process_packet(packet)
        fingerprinter.cleanup_connection("10.0.0.2", 443, "10.0.0.1", 54321, "tcp")
        assert fingerprinter.process_packet(packet) is not None

    def test_reset_lets_a_later_syn_produce_a_value(self):
        fingerprinter = JA4TFingerprinter()
        packet = syn_with_option_bytes(bytes.fromhex("020405b4"))
        fingerprinter.process_packet(packet)
        fingerprinter.reset()
        assert fingerprinter.process_packet(packet) is not None

    def test_a_syn_the_reader_cannot_read_leaves_the_connection_open(self, monkeypatch):
        """A packet that produces no value must not mark its connection.

        The gate runs after the reader for that reason. A gate that ran first would
        consume the connection on a packet the reader failed on, and the SYN that
        follows would then produce nothing either.
        """
        import ja4plus.fingerprinters.ja4t as module

        fingerprinter = JA4TFingerprinter()
        packet = syn_with_option_bytes(bytes.fromhex("020405b4"))

        def raise_once(tcp):
            raise ValueError("the reader cannot read this packet")

        monkeypatch.setattr(module, "tcp_prefix", raise_once)
        assert fingerprinter.process_packet(packet) is None
        monkeypatch.undo()

        assert fingerprinter.process_packet(packet) == "65535_2_1460_00"

    def test_a_syn_ack_still_produces_one_value_for_each_packet(self):
        """D4 reaches JA4T alone. R12 states that a JA4TS value grows with each SYN-ACK."""
        first = syn_with_option_bytes(bytes.fromhex("020405b4"), flags="SA")
        first.time = 1000.0
        second = syn_with_option_bytes(bytes.fromhex("020405b4"), flags="SA")
        second.time = 1001.0
        from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter

        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(first)
        fingerprinter.process_packet(second)
        assert len(fingerprinter.get_fingerprints()) == 2


class TestD5TheFirstRepeatedOption:
    """D5 — a repeated option keeps the first value."""

    def test_a_repeated_maximum_segment_size_keeps_the_first(self):
        # Maximum Segment Size 1460, then Maximum Segment Size 536.
        packet = syn_with_option_bytes(bytes.fromhex("020405b402040218"))
        assert generate_ja4t(packet) == "65535_2-2_1460_00"

    def test_a_repeated_window_scale_keeps_the_first(self):
        # Window Scale 7, Window Scale 2, and two pad bytes.
        packet = syn_with_option_bytes(bytes.fromhex("0303070303020000"))
        assert generate_ja4t(packet).split("_")[3] == "7"


class TestTheOptionReaderTrustsNoLengthField:
    """Every packet is hostile input, so the reader trusts no length it reads."""

    def test_a_data_offset_past_the_packet_reads_no_option(self):
        packet = syn_with_option_bytes(bytes.fromhex("020405b4"))
        raw = bytes(packet[TCP])
        broken = raw[:12] + bytes([0xF0 | (raw[12] & 0x0F)]) + raw[13:]
        assert option_bytes(TCP(broken)) == b""

    def test_a_length_below_two_stops_the_reader(self):
        kinds, mss, window_scale = read_options(bytes.fromhex("020405b40501"))
        assert kinds == [2]
        assert mss == 1460

    def test_a_length_past_the_option_field_stops_the_reader(self):
        kinds, _, _ = read_options(bytes.fromhex("020405b40520"))
        assert kinds == [2]

    def test_a_kind_byte_with_no_length_byte_stops_the_reader(self):
        kinds, _, _ = read_options(bytes.fromhex("020405b405"))
        assert kinds == [2]

    def test_a_data_offset_below_five_reads_no_option(self):
        packet = syn_with_option_bytes(bytes.fromhex("020405b4"))
        raw = bytes(packet[TCP])
        broken = raw[:12] + bytes([0x40 | (raw[12] & 0x0F)]) + raw[13:]
        assert option_bytes(TCP(broken)) == b""

    @pytest.mark.parametrize("data", [b"", b"\x02", b"\x02\x04", b"\x02\x04\x05"])
    def test_a_truncated_maximum_segment_size_raises_nothing(self, data):
        kinds, mss, window_scale = read_options(data)
        assert mss == 0
        assert window_scale == 0
        assert kinds in ([], [2])


class TestTheSharedPrefix:
    """JA4T and JA4TS read one reader, so one repair covers both methods."""

    def test_the_two_methods_write_one_prefix(self):
        syn = syn_with_option_bytes(CHROME_OPTION_BYTES)
        syn_ack = syn_with_option_bytes(CHROME_OPTION_BYTES, flags="SA")
        assert tcp_prefix(syn[TCP]) == tcp_prefix(syn_ack[TCP])
        assert generate_ja4t(syn) == generate_ja4ts(syn_ack)
