"""Measure part e of JA4TS, the time since the last SYN-ACK.

The deleted FoxIO file `technical_details/JA4T.md` heads its form
`JA4TS and JA4TScan Fingerprint formats:` and writes
`WindowSize_TCPOptions_MSSValue_WindowScale_TimeSinceLastSYNACK`. It states two further
rules that these cases measure: a fingerprint omits part e when it sees no
retransmission, and part e holds the delay between each SYN-ACK in whole seconds.
`docs/specs/foxio/JA4T.md` records the reading and names the three FoxIO sources.
"""

import unittest
from pathlib import Path

from scapy.all import IP, TCP, rdpcap

from ja4plus.processor import Processor
from ja4plus.fingerprinters.ja4ts import (
    MAX_SYN_ACK_DELAYS,
    MAX_TRACKED_CONNECTIONS,
    SYN_ACK_TIMEOUT_SECONDS,
    JA4TSFingerprinter,
    generate_ja4ts,
)

# The SYN-ACK of the example screenshot of the deleted file. Every case below sends this
# packet, so part a through part d never changes and part e alone carries the reading.
SERVER = "10.0.0.1"
CLIENT = "10.0.0.2"
# The deleted file writes `62727_2_8961_00` for these four parts, with the two-digit
# window scale the user decided on 2026-08-08. #215 records the reading as D1.
PARTS_A_TO_D = "62727_2_8961_00"


def syn_ack(time, server=SERVER, client=CLIENT, sport=443, dport=50000):
    """Return one SYN-ACK packet that arrives at the given capture time."""
    packet = IP(src=server, dst=client) / TCP(
        flags="SA", window=62727, sport=sport, dport=dport, options=[("MSS", 8961)]
    )
    packet.time = time
    return packet


class TestPartEOmission(unittest.TestCase):
    """The fingerprint omits part e when the server answers once."""

    def test_a_connection_the_server_answered_once_carries_no_part_e(self):
        fingerprinter = JA4TSFingerprinter()
        self.assertEqual(fingerprinter.process_packet(syn_ack(1000.0)), PARTS_A_TO_D)

    def test_a_fingerprint_without_a_tracker_carries_no_part_e(self):
        """`generate_ja4ts` reads one packet, and one packet names no retransmission."""
        self.assertEqual(generate_ja4ts(syn_ack(1000.0)), PARTS_A_TO_D)

    def test_two_connections_hold_separate_delay_lists(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0, dport=50000))
        self.assertEqual(fingerprinter.process_packet(syn_ack(1001.0, dport=50001)), PARTS_A_TO_D)


class TestPartEDelays(unittest.TestCase):
    """Part e holds the delay between each SYN-ACK of one connection."""

    def test_a_second_syn_ack_writes_the_delay_in_part_e(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        self.assertEqual(fingerprinter.process_packet(syn_ack(1001.0)), PARTS_A_TO_D + "_1")

    def test_a_third_syn_ack_appends_a_second_delay_to_part_e(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.process_packet(syn_ack(1001.0))
        self.assertEqual(fingerprinter.process_packet(syn_ack(1003.0)), PARTS_A_TO_D + "_1-2")

    def test_the_deleted_foxio_example_builds_its_stated_delay_list(self):
        """The five retransmissions of the deleted file build `1-2-4-8-16`.

        The file lists the capture times of the example screenshot, and it states the
        fingerprint that each SYN-ACK produces.
        """
        times = [15.621983, 16.626151, 18.642179, 22.738154, 30.930163, 47.058146]
        expected = [
            PARTS_A_TO_D,
            PARTS_A_TO_D + "_1",
            PARTS_A_TO_D + "_1-2",
            PARTS_A_TO_D + "_1-2-4",
            PARTS_A_TO_D + "_1-2-4-8",
            PARTS_A_TO_D + "_1-2-4-8-16",
        ]
        fingerprinter = JA4TSFingerprinter()
        produced = [fingerprinter.process_packet(syn_ack(time)) for time in times]
        self.assertEqual(produced, expected)

    def test_part_e_rounds_the_delay_to_the_nearest_whole_second(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        self.assertEqual(fingerprinter.process_packet(syn_ack(1002.6)), PARTS_A_TO_D + "_3")

    def test_part_e_rounds_a_half_second_delay_away_from_zero(self):
        """The Wireshark dissector calls C `round`, which carries a half away from zero.

        The Python built-in `round` carries a half to the even number, so it writes `0`
        where the dissector writes `1`.
        """
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        self.assertEqual(fingerprinter.process_packet(syn_ack(1000.5)), PARTS_A_TO_D + "_1")

    def test_part_e_rounds_a_negative_half_second_delay_away_from_zero(self):
        """A capture that holds a SYN-ACK out of order produces a negative delay.

        The C `round` carries a negative half away from zero and writes `-1`.
        `math.floor(delay + 0.5)` carries it towards zero and writes `0`.
        """
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        self.assertEqual(fingerprinter.process_packet(syn_ack(999.5)), PARTS_A_TO_D + "_-1")

    def test_part_e_writes_zero_for_a_delay_below_half_a_second(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        self.assertEqual(fingerprinter.process_packet(syn_ack(1000.006)), PARTS_A_TO_D + "_0")


class TestPartEBounds(unittest.TestCase):
    """The delay list and the connection table both hold a bound."""

    def test_the_module_holds_the_three_bounds_that_foxio_states(self):
        """A case that reads a bound from the module cannot measure the bound itself.

        The deleted file states ten retransmissions and a timeout of two minutes.
        `MAX_TRACKED_CONNECTIONS` is this project's own bound, and
        `MAX_HANDSHAKE_CONNECTIONS` in `ja4plus/fingerprinters/ja4ssh.py` holds the same
        value.
        """
        self.assertEqual(MAX_SYN_ACK_DELAYS, 10)
        self.assertEqual(SYN_ACK_TIMEOUT_SECONDS, 120)
        self.assertEqual(MAX_TRACKED_CONNECTIONS, 1000)

    def test_part_e_counts_ten_delays_and_no_more(self):
        """The deleted file states a maximum of ten retransmissions counted.

        `zeek/ja4t/main.zeek:185` stops at ten delays and corroborates the count.
        `MAX_SYN_ACK_TIMES` in `wireshark/source/packet-ja4.c:234` stores ten
        timestamps, which holds nine delays, so the dissector reads one fewer.
        """
        fingerprinter = JA4TSFingerprinter()
        fingerprint = None
        for step in range(16):
            fingerprint = fingerprinter.process_packet(syn_ack(1000.0 + step))
        self.assertEqual(fingerprint, PARTS_A_TO_D + "_1-1-1-1-1-1-1-1-1-1")

    def test_a_connection_older_than_the_timeout_starts_a_new_delay_list(self):
        """The deleted file states a timeout of two minutes after the last SYN-ACK."""
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        self.assertEqual(fingerprinter.process_packet(syn_ack(1121.0)), PARTS_A_TO_D)

    def test_a_connection_inside_the_timeout_keeps_its_delay_list(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        self.assertEqual(fingerprinter.process_packet(syn_ack(1119.0)), PARTS_A_TO_D + "_119")

    def test_the_connection_table_holds_a_maximum_entry_count(self):
        """A monitor reads a SYN-ACK for every connection on the wire."""
        fingerprinter = JA4TSFingerprinter()
        for port in range(1100):
            fingerprinter.process_packet(syn_ack(1000.0, dport=10000 + port))
        self.assertLessEqual(len(fingerprinter.syn_ack_times.times), 1000)

    def test_a_capture_with_decreasing_timestamps_bounds_the_connection_table(self):
        """The two bounds are independent, and every packet is hostile input.

        The timeout reads the capture timestamp of the packet, so a capture whose
        timestamps decrease never ages an entry out. The entry count still bounds the
        table.
        """
        fingerprinter = JA4TSFingerprinter()
        for step in range(5000):
            fingerprinter.process_packet(syn_ack(1e9 - step, dport=10000 + step % 50000))
        self.assertLessEqual(len(fingerprinter.syn_ack_times.times), 1000)

    def test_one_connection_stores_eleven_timestamps_at_most(self):
        """Ten delays need eleven timestamps, and a flood adds no more."""
        fingerprinter = JA4TSFingerprinter()
        for step in range(5000):
            fingerprinter.process_packet(syn_ack(1000.0 + step, dport=40000))
        stored = sum(len(v) for v in fingerprinter.syn_ack_times.times.values())
        self.assertEqual(stored, 11)


class TestPartEOnTheVectorSet(unittest.TestCase):
    """One vector measures the value that part e changed.

    `tests/foxio_vectors/ssh2.pcapng` holds the one connection of the whole vector set
    that the server answered twice. It is the only capture where part e appears, so it
    is the only capture that measures the rule against real traffic.

    Each index below counts from 0, because `enumerate` reads the packet list from 0. A
    one-based reader such as Wireshark numbers the same two packets 370 and 373.
    """

    CAPTURE = Path(__file__).parent / "foxio_vectors" / "ssh2.pcapng"
    SERVER = "184.150.157.177"
    CLIENT = "172.16.225.48"

    def setUp(self):
        if not self.CAPTURE.exists():
            self.skipTest(f"{self.CAPTURE} is absent")
        processor = Processor()
        self.values = []
        for index, packet in enumerate(rdpcap(str(self.CAPTURE))):
            for result in processor.process_packet(packet):
                if result.type == "ja4ts":
                    self.values.append((index, result.fingerprint))

    def test_the_retransmitted_syn_ack_carries_part_e(self):
        """Index 372 answers a connection that index 369 already answered."""
        self.assertIn((372, "64240_2-1-1-4-1-3_1460_7_0"), self.values)

    def test_the_first_syn_ack_of_that_connection_carries_no_part_e(self):
        self.assertIn((369, "64240_2-1-1-4-1-3_1460_7"), self.values)

    def test_one_value_of_the_capture_carries_part_e(self):
        """Every other connection of the capture holds one SYN-ACK."""
        with_part_e = [value for _, value in self.values if value.count("_") == 4]
        self.assertEqual(with_part_e, ["64240_2-1-1-4-1-3_1460_7_0"])

    def test_the_capture_produces_nine_ja4ts_values(self):
        """A value that appears or disappears changes this count."""
        self.assertEqual(len(self.values), 9)


class TestPartEStateRelease(unittest.TestCase):
    """The delay state answers `reset` and `cleanup_connection`."""

    def test_reset_clears_the_delay_state(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.reset()
        self.assertEqual(fingerprinter.process_packet(syn_ack(1001.0)), PARTS_A_TO_D)

    def test_cleanup_connection_drops_the_delay_state(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.cleanup_connection(SERVER, 443, CLIENT, 50000, "tcp")
        self.assertEqual(fingerprinter.process_packet(syn_ack(1001.0)), PARTS_A_TO_D)

    def test_cleanup_connection_reads_the_client_side_address_pair(self):
        """The caller names either direction of the connection."""
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.cleanup_connection(CLIENT, 50000, SERVER, 443, "tcp")
        self.assertEqual(fingerprinter.process_packet(syn_ack(1001.0)), PARTS_A_TO_D)


if __name__ == "__main__":
    unittest.main()
