"""Measure the JA4TScan value that a list of responses produces.

`docs/specs/features/12-active-scan.md` states the form. Part a to part d are the JA4TS
parts of the first response, and part e follows the JA4TS delay rule. The maintainer
ruled that form on 2026-09-30, at
https://github.com/Crank-Git/ja4plus/issues/775#issuecomment-5921253786.

FoxIO publishes no JA4TScan capture. Each case therefore builds the responses that the
eight example values of `ja4tscan/README.md:21-28` describe, and
`docs/specs/foxio/JA4TScan.md` holds the reading of each value.
"""

from __future__ import annotations

import pytest
from scapy.all import IP, TCP

from ja4plus.fingerprinters.ja4ts import generate_ja4ts
from ja4plus.scan.value import RST_ACK_VALUE, Response, ja4tscan_value

SYN_ACK = 0x12
RST = 0x04
RST_ACK = 0x14

# The option bytes the examples need. Each constant holds one option in wire form.
EOL = b"\x00"
NOP = b"\x01"
SACK_PERMITTED = b"\x04\x02"
TIMESTAMP = b"\x08\x0a" + bytes(8)


def mss(value: int) -> bytes:
    """Return a Maximum Segment Size option that carries the value."""
    return b"\x02\x04" + value.to_bytes(2, "big")


def window_scale(value: int) -> bytes:
    """Return a Window Scale option that carries the value."""
    return b"\x03\x03" + bytes([value])


def responses(window: int, options: bytes, delays: list[int], rst_delay: int | None = None):
    """Return a SYN-ACK, one retransmission after each delay, and an optional RST.

    Args:
        window: The window field of every SYN-ACK.
        options: The option bytes of every SYN-ACK.
        delays: The seconds between each response and the one before it.
        rst_delay: The seconds between the last SYN-ACK and a RST, or None for no RST.
    """
    now = 1000.0
    sequence = [Response(now, SYN_ACK, window, options)]
    for delay in delays:
        now += delay
        sequence.append(Response(now, SYN_ACK, window, options))
    if rst_delay is not None:
        sequence.append(Response(now + rst_delay, RST, 0, b""))
    return sequence


# Each row names one example of `ja4tscan/README.md:21-28`, the responses that produce
# it, and the value this project writes. The F5 Big IP row writes part d as `00`, and
# `docs/specs/features/12-active-scan.md` states why the published `0` stays unmatched.
EXAMPLES = [
    (
        "Windows 10",
        responses(64240, mss(1460) + NOP + window_scale(8) + NOP + NOP + SACK_PERMITTED,
                  [1, 2, 4, 8], rst_delay=6),
        "64240_2-1-3-1-1-4_1460_8_1-2-4-8-R6",
    ),
    (
        "Windows 2003",
        responses(16384, mss(1460) + NOP + window_scale(0) + NOP + NOP + TIMESTAMP + NOP
                  + NOP + SACK_PERMITTED, [2, 7]),
        "16384_2-1-3-1-1-8-1-1-4_1460_00_2-7",
    ),
    (
        "Amazon AWS Linux 2",
        responses(62727, mss(8961) + SACK_PERMITTED + TIMESTAMP + NOP + window_scale(7),
                  [1, 2, 4, 8, 16]),
        "62727_2-4-8-1-3_8961_7_1-2-4-8-16",
    ),
    (
        "Mac OSX / iPhone",
        responses(65535, mss(1460) + NOP + window_scale(6) + NOP + NOP + TIMESTAMP
                  + SACK_PERMITTED + EOL + EOL, [1, 2, 4, 8, 16, 32, 12]),
        "65535_2-1-3-1-1-8-4-0-0_1460_6_1-2-4-8-16-32-12",
    ),
    (
        "HP ILO",
        responses(5840, mss(1460), [3, 6, 12, 24, 48, 60, 60, 60, 60, 60]),
        "5840_2_1460_00_3-6-12-24-48-60-60-60-60-60",
    ),
    (
        "Epson Printer",
        responses(28960, mss(1460) + SACK_PERMITTED + TIMESTAMP + NOP + window_scale(3),
                  [1, 4, 8, 16]),
        "28960_2-4-8-1-3_1460_3_1-4-8-16",
    ),
    (
        "Ubiquiti Router",
        responses(43440, mss(1460) + SACK_PERMITTED + TIMESTAMP + NOP + window_scale(12),
                  [1, 2, 4, 8, 17]),
        "43440_2-4-8-1-3_1460_12_1-2-4-8-17",
    ),
    (
        "F5 Big IP",
        responses(4380, mss(1460) + SACK_PERMITTED + TIMESTAMP, [3, 6, 12]),
        "4380_2-4-8_1460_00_3-6-12",
    ),
]


@pytest.mark.parametrize(
    ("system", "sequence", "expected"), EXAMPLES, ids=[row[0] for row in EXAMPLES]
)
def test_the_responses_of_each_published_example_produce_its_value(system, sequence, expected):
    assert ja4tscan_value(sequence) == expected, system


def test_the_f5_example_writes_a_zero_scale_as_two_digits_and_not_as_published():
    f5 = next(row for row in EXAMPLES if row[0] == "F5 Big IP")
    value = ja4tscan_value(f5[1])
    assert value == "4380_2-4-8_1460_00_3-6-12"
    assert value != "4380_2-4-8_1460_0_3-6-12"


def test_two_end_of_option_list_bytes_write_two_zero_kinds():
    value = ja4tscan_value([Response(0.0, SYN_ACK, 1024, mss(1460) + EOL + EOL)])
    part_b = value.split("_")[1]
    assert part_b.endswith("0-0")


def test_a_retransmission_one_and_a_half_seconds_later_writes_the_delay_two():
    sequence = [
        Response(10.0, SYN_ACK, 1024, mss(1460)),
        Response(11.5, SYN_ACK, 1024, mss(1460)),
    ]
    assert ja4tscan_value(sequence) == "1024_2_1460_00_2"


def test_each_delay_counts_from_the_previous_response_of_the_target():
    sequence = [
        Response(10.0, SYN_ACK, 1024, mss(1460)),
        Response(11.0, SYN_ACK, 1024, mss(1460)),
        Response(14.0, SYN_ACK, 1024, mss(1460)),
    ]
    assert ja4tscan_value(sequence) == "1024_2_1460_00_1-3"


def test_one_syn_ack_produces_four_parts_and_no_part_e():
    value = ja4tscan_value([Response(0.0, SYN_ACK, 29200, mss(1460))])
    assert value == "29200_2_1460_00"
    assert len(value.split("_")) == 4


def test_a_first_response_that_carries_rst_produces_the_rst_ack_value():
    assert ja4tscan_value([Response(0.0, RST, 0, b"")]) == "0_rst-ack"
    assert RST_ACK_VALUE == "0_rst-ack"


def test_a_first_response_that_carries_rst_and_ack_with_a_window_produces_rst_ack():
    assert ja4tscan_value([Response(0.0, RST_ACK, 512, b"")]) == "0_rst-ack"


def test_a_response_after_a_first_rst_changes_nothing():
    sequence = [Response(0.0, RST_ACK, 0, b""), Response(3.0, SYN_ACK, 1024, mss(1460))]
    assert ja4tscan_value(sequence) == "0_rst-ack"


def test_a_response_after_a_later_rst_changes_nothing():
    sequence = responses(1024, mss(1460), [1], rst_delay=2)
    sequence.append(Response(sequence[-1].seconds + 5, SYN_ACK, 1024, mss(1460)))
    assert ja4tscan_value(sequence) == "1024_2_1460_00_1-R2"


def test_part_e_counts_ten_retransmissions_and_no_more():
    sequence = responses(1024, mss(1460), [1] * 12)
    assert ja4tscan_value(sequence) == "1024_2_1460_00_" + "-".join(["1"] * 10)


def test_a_rst_after_ten_retransmissions_counts_from_the_tenth():
    sequence = responses(1024, mss(1460), [1] * 12, rst_delay=4)
    # The two uncounted retransmissions arrive 1 and 2 seconds after the tenth, so the RST
    # arrives 6 seconds after the tenth.
    assert ja4tscan_value(sequence).endswith("-1-R6")


def test_no_response_produces_no_value():
    assert ja4tscan_value([]) is None


def test_an_option_length_past_the_end_stops_part_b_and_raises_nothing():
    options = mss(1460) + b"\x03\x09\x07"
    assert ja4tscan_value([Response(0.0, SYN_ACK, 1024, options)]) == "1024_2_1460_00"


def test_a_scan_value_holds_the_parts_a_to_d_of_the_passive_ja4ts_value():
    options = [("MSS", 1460), ("NOP", None), ("WScale", 7), ("SAckOK", b""), ("EOL", None)]
    packet = IP(src="192.0.2.10", dst="198.51.100.1") / TCP(
        sport=443, dport=40000, flags="SA", window=65160, options=options
    )
    tcp = TCP(bytes(packet[TCP]))
    passive = generate_ja4ts(packet)
    header = bytes(tcp)
    scan = ja4tscan_value(
        [Response(0.0, int(tcp.flags), tcp.window, header[20 : tcp.dataofs * 4])]
    )
    assert passive is not None
    assert scan == passive
