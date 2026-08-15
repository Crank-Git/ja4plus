"""Measure the JA4TS value that a RST produces.

The deleted FoxIO file `technical_details/JA4T.md` states three rules that these cases
measure. A RST appends `R` and its delay to part e. The delay is the interval since the
last SYN-ACK, in whole seconds. A RST packet carries no window size and no option, so the
reader restores part a through part d from the connection.

`docs/specs/foxio/JA4T.md` records the reading as R13 and names both corroborations.
"""

import tempfile
import unittest
from pathlib import Path

from scapy.all import IP, TCP, rdpcap

from ja4plus.fingerprinters.ja4ts import (
    SYN_ACK_TIMEOUT_SECONDS,
    JA4TSFingerprinter,
    generate_ja4ts,
)
from ja4plus.processor import Processor

# The connection of the example screenshot of the deleted file. Every constructed case
# below sends this SYN-ACK, so part a through part d never changes.
SERVER = "10.0.0.1"
CLIENT = "10.0.0.2"
PARTS_A_TO_D = "65535_2-1-3-1-1-4_65495_8"

SERVER_OPTIONS = [
    ("MSS", 65495),
    ("NOP", None),
    ("WScale", 8),
    ("NOP", None),
    ("NOP", None),
    ("SAckOK", b""),
]


def syn_ack(time, server=SERVER, client=CLIENT, sport=443, dport=50000):
    """Return one SYN-ACK packet that arrives at the given capture time."""
    packet = IP(src=server, dst=client) / TCP(
        flags="SA", window=65535, sport=sport, dport=dport, options=SERVER_OPTIONS
    )
    packet.time = time
    return packet


def reset(time, server=SERVER, client=CLIENT, sport=443, dport=50000, flags="R"):
    """Return one RST packet that the server sends at the given capture time.

    A RST packet carries no window size and no option, so this packet carries neither.
    """
    packet = IP(src=server, dst=client) / TCP(flags=flags, window=0, sport=sport, dport=dport)
    packet.time = time
    return packet


class TestTheResetSuffix(unittest.TestCase):
    """A RST appends `R` and its delay to part e."""

    def test_a_reset_after_one_retransmission_appends_its_delay(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.process_packet(syn_ack(1001.0))
        self.assertEqual(fingerprinter.process_packet(reset(1004.0)), PARTS_A_TO_D + "_1-R3")

    def test_the_reset_delay_reads_the_last_syn_ack_and_not_the_first(self):
        """`wireshark/source/packet-ja4.c:694` subtracts `syn_ack_times[count - 1]`."""
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.process_packet(syn_ack(1002.0))
        self.assertEqual(fingerprinter.process_packet(reset(1005.0)), PARTS_A_TO_D + "_2-R3")

    def test_the_reset_delay_rounds_to_the_nearest_whole_second(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.process_packet(syn_ack(1001.0))
        self.assertEqual(fingerprinter.process_packet(reset(1007.6)), PARTS_A_TO_D + "_1-R7")

    def test_the_reset_delay_rounds_a_half_second_away_from_zero(self):
        """The Wireshark dissector calls C `round`, which carries a half away from zero.

        The Python built-in `round` carries a half to the even number, so it writes `6`
        where the dissector writes `7`.
        """
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.process_packet(syn_ack(1001.0))
        self.assertEqual(fingerprinter.process_packet(reset(1007.5)), PARTS_A_TO_D + "_1-R7")

    def test_a_reset_that_carries_ack_produces_the_same_value(self):
        """`zeek/ja4t/main.zeek:167` tests the RST bit alone.

        `wireshark/source/packet-ja4.c:1296` tests `tcp_flags == 0x004`, so the dissector
        reads no RST that carries ACK. The deleted file writes "a RST packet" and names
        no flag combination, so this project reads the bit. R13 records the reading.
        """
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.process_packet(syn_ack(1001.0))
        self.assertEqual(
            fingerprinter.process_packet(reset(1004.0, flags="RA")),
            PARTS_A_TO_D + "_1-R3",
        )

    def test_the_deleted_foxio_example_builds_its_stated_value(self):
        """The five SYN-ACK packets and the RST of the example build the six values.

        The deleted file lists the capture times of its third example screenshot, and it
        states the fingerprint that each packet produces.
        """
        times = [16.681435, 17.683799, 19.691548, 23.703045, 31.714762]
        expected = [
            PARTS_A_TO_D,
            PARTS_A_TO_D + "_1",
            PARTS_A_TO_D + "_1-2",
            PARTS_A_TO_D + "_1-2-4",
            PARTS_A_TO_D + "_1-2-4-8",
        ]
        fingerprinter = JA4TSFingerprinter()
        produced = [fingerprinter.process_packet(syn_ack(time)) for time in times]
        produced.append(fingerprinter.process_packet(reset(37.723966)))
        self.assertEqual(produced, expected + [PARTS_A_TO_D + "_1-2-4-8-R6"])


class TestTheResetReadsTheStoredConnection(unittest.TestCase):
    """The RST value reads part a through part d from the stored connection."""

    def test_the_reset_value_carries_the_window_size_of_the_syn_ack(self):
        """The RST packet holds a window of 0, and the value holds 65535."""
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.process_packet(syn_ack(1001.0))
        value = fingerprinter.process_packet(reset(1004.0))
        self.assertEqual(value.split("_")[0], "65535")

    def test_the_reset_value_carries_the_option_list_of_the_syn_ack(self):
        """The RST packet carries no option, and the value holds `2-1-3-1-1-4`."""
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.process_packet(syn_ack(1001.0))
        value = fingerprinter.process_packet(reset(1004.0))
        self.assertEqual(value.split("_")[1:4], ["2-1-3-1-1-4", "65495", "8"])

    def test_the_reset_value_reads_the_first_syn_ack_of_the_connection(self):
        """`zeek/ja4t/main.zeek:177-178` stores the parts on the first SYN-ACK only.

        A retransmission repeats the SYN-ACK, so the two readings agree on real traffic.
        This case sends a second SYN-ACK that differs, which separates them.
        """
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        second = syn_ack(1001.0)
        second["TCP"].window = 4096
        fingerprinter.process_packet(second)
        value = fingerprinter.process_packet(reset(1004.0))
        self.assertEqual(value.split("_")[0], "65535")


class TestTheResetOfAOneSynAckConnection(unittest.TestCase):
    """A RST on a connection that holds one SYN-ACK produces the stored four-part value.

    The maintainer ruled the question on 2026-08-14, at `Crank-Git/ja4plus-go#484`.
    `wireshark/source/packet-ja4.c:1599-1608` copies the window size, the maximum segment
    size, the window scale and the option list from the stored connection, and it writes
    `hf_ja4ts` outside the delay guard. `wireshark/source/packet-ja4.c:684` guards the
    delay list and the reset letter on `conn->syn_ack_count > 1`.
    """

    def test_a_reset_on_a_connection_the_server_answered_once_produces_the_stored_parts(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        self.assertEqual(fingerprinter.process_packet(reset(1004.0)), PARTS_A_TO_D)

    def test_that_value_carries_no_delay_and_no_reset_letter(self):
        """The delay list and the reset letter stay behind the two-SYN-ACK guard."""
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        value = fingerprinter.process_packet(reset(1004.0))
        self.assertEqual(len(value.split("_")), 4)
        self.assertNotIn("R", value)

    def test_that_value_reads_the_window_size_of_the_syn_ack_and_not_of_the_reset(self):
        """The RST packet holds a window of 0, and the value holds 65535."""
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        value = fingerprinter.process_packet(reset(1004.0))
        self.assertEqual(value.split("_")[0], "65535")

    def test_a_second_reset_of_that_connection_produces_the_same_value(self):
        """The RST packet records no time, so two RST packets read one connection."""
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        first = fingerprinter.process_packet(reset(1004.0))
        second = fingerprinter.process_packet(reset(1005.0))
        self.assertEqual(first, PARTS_A_TO_D)
        self.assertEqual(second, PARTS_A_TO_D)


class TestTheResetWithoutADelay(unittest.TestCase):
    """A RST that reaches no stored connection produces no value.

    Both implementations nest the delay list inside the delay branch.
    `wireshark/source/packet-ja4.c:693` reads `rst_time` only when `syn_ack_count > 1`,
    and `zeek/ja4t/main.zeek:233` reads `rst_ts` only when the delay list holds a value.
    """

    def test_a_reset_on_a_connection_with_no_syn_ack_produces_no_value(self):
        """The case reads the tracker too, because `generate_ja4ts` catches a crash.

        `generate_ja4ts` catches `TypeError`, so a tracker that raises on an absent
        connection still returns None through `process_packet`. The tracker call states
        the behaviour the fingerprinter hides.
        """
        fingerprinter = JA4TSFingerprinter()
        self.assertIsNone(fingerprinter.process_packet(reset(1004.0)))
        self.assertIsNone(
            fingerprinter.syn_ack_times.reset_value((SERVER, 443, CLIENT, 50000), 1004.0)
        )

    def test_a_reset_the_client_sends_produces_no_value(self):
        """Every SYN-ACK travels from the server, so the client RST reverses the key."""
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.process_packet(syn_ack(1001.0))
        from_client = reset(1004.0, server=CLIENT, client=SERVER, sport=50000, dport=443)
        self.assertIsNone(fingerprinter.process_packet(from_client))

    def test_a_reset_on_another_connection_produces_no_value(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0, dport=50000))
        fingerprinter.process_packet(syn_ack(1001.0, dport=50000))
        self.assertIsNone(fingerprinter.process_packet(reset(1004.0, dport=50001)))

    def test_a_reset_with_no_tracker_produces_no_value(self):
        """`generate_ja4ts` reads one packet, and one packet names no connection."""
        self.assertIsNone(generate_ja4ts(reset(1004.0)))


class TestTheResetBounds(unittest.TestCase):
    """The RST value reads the same two bounds that part e reads."""

    def test_a_reset_after_the_timeout_produces_no_value(self):
        """`zeek/ja4t/main.zeek:162` drops the connection before it reads the RST."""
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.process_packet(syn_ack(1001.0))
        late = reset(1001.0 + SYN_ACK_TIMEOUT_SECONDS + 1.0)
        self.assertIsNone(fingerprinter.process_packet(late))

    def test_a_reset_inside_the_timeout_produces_a_value(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.process_packet(syn_ack(1001.0))
        early = reset(1001.0 + SYN_ACK_TIMEOUT_SECONDS - 1.0)
        self.assertEqual(fingerprinter.process_packet(early), PARTS_A_TO_D + "_1-R119")

    def test_a_reset_after_ten_delays_reads_the_eleventh_syn_ack(self):
        """The delay list stops at ten, and the RST still reads the last SYN-ACK.

        `wireshark/source/packet-ja4.c:693` appends the RST whatever the count holds.
        """
        fingerprinter = JA4TSFingerprinter()
        for step in range(16):
            fingerprinter.process_packet(syn_ack(1000.0 + step))
        value = fingerprinter.process_packet(reset(1013.0))
        self.assertEqual(value, PARTS_A_TO_D + "_1-1-1-1-1-1-1-1-1-1-R3")

    def test_the_stored_parts_hold_one_entry_for_each_tracked_connection(self):
        """The stored parts live in the bounded connection table and add no table."""
        fingerprinter = JA4TSFingerprinter()
        for port in range(1100):
            fingerprinter.process_packet(syn_ack(1000.0, dport=10000 + port))
        table = fingerprinter.syn_ack_times
        self.assertLessEqual(len(table.prefixes), 1000)
        self.assertEqual(sorted(table.prefixes), sorted(table.times))


class TestTheResetStateRelease(unittest.TestCase):
    """The stored parts answer `reset` and `cleanup_connection`."""

    def test_reset_clears_the_stored_parts(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.process_packet(syn_ack(1001.0))
        fingerprinter.reset()
        self.assertEqual(fingerprinter.syn_ack_times.prefixes, {})
        self.assertIsNone(fingerprinter.process_packet(reset(1004.0)))

    def test_cleanup_connection_drops_the_stored_parts(self):
        fingerprinter = JA4TSFingerprinter()
        fingerprinter.process_packet(syn_ack(1000.0))
        fingerprinter.process_packet(syn_ack(1001.0))
        fingerprinter.cleanup_connection(CLIENT, 50000, SERVER, 443, "tcp")
        self.assertEqual(fingerprinter.syn_ack_times.prefixes, {})
        self.assertIsNone(fingerprinter.process_packet(reset(1004.0)))


class TestTheResetCapture(unittest.TestCase):
    """A capture measures the rule against a packet list and not against a packet.

    `tests/build_ja4ts_rst.py` writes the capture from the six capture times that the
    deleted file lists. `.gitignore` commits no capture other than the FoxIO vectors, so
    this case writes the file and reads it back.
    `tests/test_ja4ssh_message_count.py` reads `tests/build_ssh_retransmission.py` the
    same way. Run the builder to write `tests/data/ja4ts-rst.pcap` for a reader.
    """

    def setUp(self):
        from scapy.all import wrpcap

        from tests.build_ja4ts_rst import build

        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        path = Path(self.directory.name) / "ja4ts-rst.pcap"
        wrpcap(str(path), build())

        processor = Processor()
        self.values = []
        for packet in rdpcap(str(path)):
            for result in processor.process_packet(packet):
                if result.type == "ja4ts":
                    self.values.append(result.fingerprint)

    def test_the_capture_produces_the_six_values_the_deleted_file_states(self):
        self.assertEqual(
            self.values,
            [
                PARTS_A_TO_D,
                PARTS_A_TO_D + "_1",
                PARTS_A_TO_D + "_1-2",
                PARTS_A_TO_D + "_1-2-4",
                PARTS_A_TO_D + "_1-2-4-8",
                PARTS_A_TO_D + "_1-2-4-8-R6",
            ],
        )

    def test_the_last_value_of_the_capture_is_the_example_of_the_deleted_file(self):
        self.assertEqual(self.values[-1], "65535_2-1-3-1-1-4_65495_8_1-2-4-8-R6")


if __name__ == "__main__":
    unittest.main()
