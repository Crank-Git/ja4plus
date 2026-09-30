"""Measure the SYN frame the scanner builds, and the parser that reads each response.

S2 and S3 of `docs/specs/foxio/JA4TScan.md` state the header values and the option
bytes of the FoxIO SYN. FR-active-scan-25 states that the scanner sends the SYN as a
link-layer frame. The source port, the sequence number and the timestamp value vary
between runs, so each case names them and compares every other byte.

Every response is hostile input, so the parser cases feed malformed frames and require
None with no exception.
"""

from __future__ import annotations

import struct

import pytest
from scapy.all import IP, TCP, Ether

from ja4plus.fingerprinters.ja4t import generate_ja4t
from ja4plus.scan.frames import Reply, build_syn, parse_frame

SCANNER_MAC = bytes.fromhex("020000000001")
GATEWAY_MAC = bytes.fromhex("020000000002")
SCANNER = "198.51.100.1"
TARGET = "192.0.2.10"


def syn(**overrides: object) -> bytes:
    """Return a SYN frame with fixed values for the fields that vary between runs."""
    fields: dict[str, object] = {
        "src_mac": SCANNER_MAC,
        "dst_mac": GATEWAY_MAC,
        "src_ip": SCANNER,
        "dst_ip": TARGET,
        "src_port": 40112,
        "dst_port": 443,
        "sequence": 0x01020304,
        "timestamp": 0x0A0B0C0D,
    }
    fields.update(overrides)
    return build_syn(**fields)  # type: ignore[arg-type]


def checksum(data: bytes) -> int:
    """Return the ones' complement sum that RFC 1071 states, folded to 16 bits."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


class TestTheSynFrame:
    def test_the_frame_opens_with_an_ethernet_header_for_ipv4(self):
        frame = syn()
        assert frame[:6] == GATEWAY_MAC
        assert frame[6:12] == SCANNER_MAC
        assert frame[12:14] == b"\x08\x00"
        assert len(frame) == 14 + 20 + 40

    def test_the_ip_header_carries_the_identification_54321_and_the_time_to_live_255(self):
        ip = syn()[14:34]
        assert ip[0] == 0x45
        assert struct.unpack("!H", ip[2:4])[0] == 60
        assert struct.unpack("!H", ip[4:6])[0] == 54321
        assert ip[6:8] == b"\x00\x00"
        assert ip[8] == 255
        assert ip[9] == 6
        assert ip[12:16] == bytes([198, 51, 100, 1])
        assert ip[16:20] == bytes([192, 0, 2, 10])
        assert checksum(ip) == 0xFFFF

    def test_the_tcp_header_carries_syn_alone_and_the_window_65535(self):
        tcp = syn()[34:]
        assert struct.unpack("!HH", tcp[0:4]) == (40112, 443)
        assert struct.unpack("!I", tcp[4:8])[0] == 0x01020304
        assert struct.unpack("!I", tcp[8:12])[0] == 0
        assert tcp[12] >> 4 == 10
        assert tcp[13] == 0x02
        assert struct.unpack("!H", tcp[14:16])[0] == 65535
        assert tcp[18:20] == b"\x00\x00"

    def test_the_tcp_checksum_covers_the_pseudo_header(self):
        frame = syn()
        tcp = frame[34:]
        pseudo = frame[26:34] + struct.pack("!BBH", 0, 6, len(tcp))
        assert checksum(pseudo + tcp) == 0xFFFF

    def test_the_options_are_the_foxio_bytes_then_the_timestamp_then_one_zero_byte(self):
        options = syn()[54:]
        assert options[:11] == bytes.fromhex("020405b4 030307 0402 080a")
        assert options[11:15] == bytes.fromhex("0a0b0c0d")
        assert options[15:19] == bytes(4)
        assert options[19:] == b"\x00"

    def test_this_project_reads_the_foxio_ja4t_of_the_syn(self):
        # S3 of `docs/specs/foxio/JA4TScan.md` records the value a measurement read.
        assert generate_ja4t(Ether(syn())) == "65535_2-3-4-8-0_1460_7"

    def test_the_timestamp_value_wraps_to_32_bits(self):
        options = syn(timestamp=2**32 + 5)[54:]
        assert options[11:15] == bytes.fromhex("00000005")


def syn_ack_frame(**overrides: object) -> bytes:
    """Return an Ethernet frame that carries a SYN-ACK from the target to the scanner."""
    tcp = TCP(
        sport=overrides.get("sport", 443),
        dport=overrides.get("dport", 40112),
        seq=77,
        ack=overrides.get("ack", 0x01020305),
        flags=overrides.get("flags", "SA"),
        window=overrides.get("window", 64240),
        options=[("MSS", 1460), ("NOP", None), ("WScale", 8)],
    )
    return bytes(Ether(dst=SCANNER_MAC, src=GATEWAY_MAC) / IP(src=TARGET, dst=SCANNER) / tcp)


class TestTheResponseParser:
    def test_a_syn_ack_frame_produces_every_field_the_scanner_reads(self):
        reply = parse_frame(syn_ack_frame())
        assert reply == Reply(
            src_ip=TARGET,
            dst_ip=SCANNER,
            src_port=443,
            dst_port=40112,
            acknowledgment=0x01020305,
            flags=0x12,
            window=64240,
            options=bytes.fromhex("020405b4 01 030308"),
        )

    def test_a_frame_shorter_than_an_ethernet_header_produces_nothing(self):
        assert parse_frame(syn_ack_frame()[:13]) is None

    def test_an_empty_frame_produces_nothing(self):
        assert parse_frame(b"") is None

    def test_a_frame_that_carries_no_ipv4_produces_nothing(self):
        frame = syn_ack_frame()
        assert parse_frame(frame[:12] + b"\x86\xdd" + frame[14:]) is None

    def test_an_ip_version_other_than_4_produces_nothing(self):
        frame = bytearray(syn_ack_frame())
        frame[14] = 0x65
        assert parse_frame(bytes(frame)) is None

    @pytest.mark.parametrize("ihl", [0, 4, 15])
    def test_an_ip_header_length_below_20_bytes_or_past_the_frame_produces_nothing(self, ihl):
        frame = bytearray(syn_ack_frame())
        frame[14] = 0x40 | ihl
        assert parse_frame(bytes(frame)) is None

    def test_an_ip_total_length_below_the_ip_header_produces_nothing(self):
        frame = bytearray(syn_ack_frame())
        frame[16:18] = struct.pack("!H", 19)
        assert parse_frame(bytes(frame)) is None

    def test_an_ip_total_length_past_the_frame_produces_nothing(self):
        frame = bytearray(syn_ack_frame())
        frame[16:18] = struct.pack("!H", 1500)
        assert parse_frame(bytes(frame)) is None

    def test_a_fragment_produces_nothing(self):
        frame = bytearray(syn_ack_frame())
        frame[20:22] = struct.pack("!H", 0x2000)
        assert parse_frame(bytes(frame)) is None

    def test_a_protocol_other_than_tcp_produces_nothing(self):
        frame = bytearray(syn_ack_frame())
        frame[23] = 1
        assert parse_frame(bytes(frame)) is None

    def test_a_tcp_header_cut_short_produces_nothing(self):
        frame = syn_ack_frame()
        cut = bytearray(frame[:14 + 20 + 12])
        cut[16:18] = struct.pack("!H", 32)
        assert parse_frame(bytes(cut)) is None

    @pytest.mark.parametrize("offset", [0, 4, 15])
    def test_a_tcp_data_offset_below_20_bytes_or_past_the_segment_produces_nothing(self, offset):
        frame = bytearray(syn_ack_frame())
        frame[46] = (offset << 4) | (frame[46] & 0x0F)
        assert parse_frame(bytes(frame)) is None

    def test_trailing_ethernet_padding_stays_out_of_the_options(self):
        frame = syn_ack_frame() + bytes(6)
        reply = parse_frame(frame)
        assert reply is not None
        assert reply.options == bytes.fromhex("020405b4 01 030308")

    def test_every_truncation_of_a_syn_ack_frame_raises_nothing(self):
        frame = syn_ack_frame()
        for end in range(len(frame)):
            parse_frame(frame[:end])
