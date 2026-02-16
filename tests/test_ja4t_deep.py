"""
Deep tests for JA4T (TCP SYN) and JA4TS (TCP SYN-ACK) fingerprinting.

Covers option ordering preservation, all TCP option types, flag filtering,
window sizes, MSS/WScale extraction, and format validation.
"""

import unittest
from scapy.all import IP, TCP

from ja4plus.fingerprinters.ja4t import JA4TFingerprinter, generate_ja4t
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter, generate_ja4ts


# ===========================================================================
# JA4T (TCP SYN) deep tests
# ===========================================================================

class TestJA4TOptionOrderPreservation(unittest.TestCase):
    """CRITICAL: TCP options must preserve original order (never sorted)."""

    def test_mss_nop_wscale_order(self):
        packet = IP() / TCP(
            sport=54321, dport=443, flags="S", window=65535,
            options=[("MSS", 1460), ("NOP", None), ("WScale", 7)]
        )
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[1], "2-1-3")

    def test_nop_mss_wscale_order(self):
        """Different order should produce different options string."""
        packet = IP() / TCP(
            sport=54321, dport=443, flags="S", window=65535,
            options=[("NOP", None), ("MSS", 1460), ("WScale", 7)]
        )
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[1], "1-2-3")

    def test_wscale_sackok_mss_order(self):
        packet = IP() / TCP(
            sport=54321, dport=443, flags="S", window=65535,
            options=[("WScale", 7), ("SAckOK", ""), ("MSS", 1460)]
        )
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[1], "3-4-2")

    def test_full_linux_option_set(self):
        """Standard Linux: MSS, SAckOK, Timestamp, NOP, WScale."""
        packet = IP() / TCP(
            sport=54321, dport=443, flags="S", window=29200,
            options=[
                ("MSS", 1460), ("SAckOK", ""), ("Timestamp", (0, 0)),
                ("NOP", None), ("WScale", 7)
            ]
        )
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[1], "2-4-8-1-3")

    def test_full_windows_option_set(self):
        """Standard Windows: NOP, NOP, MSS, WScale, NOP, SAckOK."""
        packet = IP() / TCP(
            sport=54321, dport=443, flags="S", window=65535,
            options=[
                ("NOP", None), ("NOP", None), ("MSS", 1460),
                ("WScale", 8), ("NOP", None), ("SAckOK", "")
            ]
        )
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[1], "1-1-2-3-1-4")

    def test_different_orderings_produce_different_fingerprints(self):
        """Same options in different order must produce different fingerprints."""
        opts_a = [("MSS", 1460), ("NOP", None), ("WScale", 7)]
        opts_b = [("NOP", None), ("MSS", 1460), ("WScale", 7)]
        pkt_a = IP() / TCP(sport=54321, dport=443, flags="S", window=65535, options=opts_a)
        pkt_b = IP() / TCP(sport=54321, dport=443, flags="S", window=65535, options=opts_b)
        self.assertNotEqual(generate_ja4t(pkt_a), generate_ja4t(pkt_b))


class TestJA4TAllOptionTypes(unittest.TestCase):
    """Test all recognized TCP option types."""

    def test_mss_option(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535,
                            options=[("MSS", 1460)])
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[1], "2")
        self.assertEqual(fp.split("_")[2], "1460")

    def test_nop_option(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535,
                            options=[("NOP", None)])
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[1], "1")

    def test_wscale_option(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535,
                            options=[("WScale", 7)])
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[1], "3")
        self.assertEqual(fp.split("_")[3], "7")

    def test_sackok_option(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535,
                            options=[("SAckOK", "")])
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[1], "4")

    def test_timestamp_option(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535,
                            options=[("Timestamp", (0, 0))])
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[1], "8")

    def test_eol_option(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535,
                            options=[("EOL", None)])
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[1], "0")


class TestJA4TWindowSizes(unittest.TestCase):
    """Test various TCP window sizes."""

    def test_common_windows(self):
        windows = [65535, 29200, 14600, 16384, 8192, 0]
        for win in windows:
            with self.subTest(window=win):
                packet = IP() / TCP(sport=54321, dport=443, flags="S",
                                    window=win, options=[])
                fp = generate_ja4t(packet)
                self.assertEqual(fp.split("_")[0], str(win))

    def test_max_window(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S",
                            window=65535, options=[])
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[0], "65535")


class TestJA4TMSSValues(unittest.TestCase):
    """Test MSS extraction."""

    def test_standard_mss(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535,
                            options=[("MSS", 1460)])
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[2], "1460")

    def test_jumbo_mss(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535,
                            options=[("MSS", 9000)])
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[2], "9000")

    def test_small_mss(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535,
                            options=[("MSS", 536)])
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[2], "536")

    def test_no_mss_gives_zero(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535,
                            options=[("NOP", None)])
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[2], "0")


class TestJA4TWScaleValues(unittest.TestCase):
    """Test window scale extraction."""

    def test_common_wscale_values(self):
        for wscale in [0, 1, 7, 8, 14]:
            with self.subTest(wscale=wscale):
                packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535,
                                    options=[("WScale", wscale)])
                fp = generate_ja4t(packet)
                self.assertEqual(fp.split("_")[3], str(wscale))

    def test_no_wscale_gives_zero(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535,
                            options=[("NOP", None)])
        fp = generate_ja4t(packet)
        self.assertEqual(fp.split("_")[3], "0")


class TestJA4TFlagFiltering(unittest.TestCase):
    """Test that JA4T only accepts SYN (not SYN-ACK or other flags)."""

    def test_syn_accepted(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535)
        fp = generate_ja4t(packet)
        self.assertIsNotNone(fp)

    def test_synack_rejected(self):
        packet = IP() / TCP(sport=443, dport=54321, flags="SA", window=14600)
        self.assertIsNone(generate_ja4t(packet))

    def test_ack_rejected(self):
        packet = IP() / TCP(sport=443, dport=54321, flags="A", window=14600)
        self.assertIsNone(generate_ja4t(packet))

    def test_rst_rejected(self):
        packet = IP() / TCP(sport=443, dport=54321, flags="R")
        self.assertIsNone(generate_ja4t(packet))

    def test_fin_rejected(self):
        packet = IP() / TCP(sport=443, dport=54321, flags="F")
        self.assertIsNone(generate_ja4t(packet))

    def test_push_ack_rejected(self):
        packet = IP() / TCP(sport=443, dport=54321, flags="PA")
        self.assertIsNone(generate_ja4t(packet))


class TestJA4TFormat(unittest.TestCase):
    """Test JA4T fingerprint format: window_options_mss_wscale."""

    def test_format_four_parts(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535,
                            options=[("MSS", 1460), ("WScale", 7)])
        fp = generate_ja4t(packet)
        parts = fp.split("_")
        self.assertEqual(len(parts), 4)

    def test_no_options_format(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535,
                            options=[])
        fp = generate_ja4t(packet)
        parts = fp.split("_")
        self.assertEqual(parts[0], "65535")
        self.assertEqual(parts[1], "0")
        self.assertEqual(parts[2], "0")
        self.assertEqual(parts[3], "0")


class TestJA4TFingerprinterClass(unittest.TestCase):
    """Test JA4TFingerprinter class."""

    def test_collect_multiple(self):
        fpr = JA4TFingerprinter()
        for i in range(5):
            packet = IP() / TCP(sport=54321 + i, dport=443, flags="S",
                                window=65535, options=[("MSS", 1460)])
            fpr.process_packet(packet)
        self.assertEqual(len(fpr.get_fingerprints()), 5)

    def test_reset(self):
        fpr = JA4TFingerprinter()
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535)
        fpr.process_packet(packet)
        fpr.reset()
        self.assertEqual(len(fpr.get_fingerprints()), 0)


# ===========================================================================
# JA4TS (TCP SYN-ACK) deep tests
# ===========================================================================

class TestJA4TSFlagFiltering(unittest.TestCase):
    """Test that JA4TS only accepts SYN-ACK."""

    def test_synack_accepted(self):
        packet = IP() / TCP(sport=443, dport=54321, flags="SA", window=14600,
                            options=[("MSS", 1460)])
        fp = generate_ja4ts(packet)
        self.assertIsNotNone(fp)

    def test_syn_rejected(self):
        packet = IP() / TCP(sport=54321, dport=443, flags="S", window=65535)
        self.assertIsNone(generate_ja4ts(packet))

    def test_ack_rejected(self):
        packet = IP() / TCP(sport=443, dport=54321, flags="A", window=14600)
        self.assertIsNone(generate_ja4ts(packet))

    def test_rst_rejected(self):
        packet = IP() / TCP(sport=443, dport=54321, flags="R")
        self.assertIsNone(generate_ja4ts(packet))


class TestJA4TSOptionPreservation(unittest.TestCase):
    """JA4TS options must also preserve original order."""

    def test_order_preserved(self):
        packet = IP() / TCP(
            sport=443, dport=54321, flags="SA", window=14600,
            options=[("MSS", 1460), ("NOP", None), ("WScale", 0),
                     ("SAckOK", b""), ("NOP", None), ("NOP", None)]
        )
        fp = generate_ja4ts(packet)
        self.assertEqual(fp.split("_")[1], "2-1-3-4-1-1")

    def test_different_order_different_fp(self):
        opts_a = [("MSS", 1460), ("NOP", None), ("WScale", 0)]
        opts_b = [("NOP", None), ("WScale", 0), ("MSS", 1460)]
        pkt_a = IP() / TCP(sport=443, dport=54321, flags="SA", window=14600, options=opts_a)
        pkt_b = IP() / TCP(sport=443, dport=54321, flags="SA", window=14600, options=opts_b)
        self.assertNotEqual(generate_ja4ts(pkt_a), generate_ja4ts(pkt_b))


class TestJA4TSServerResponses(unittest.TestCase):
    """Test realistic server response fingerprints."""

    def test_f5_bigip_to_windows(self):
        packet = IP() / TCP(
            flags="SA", window=14600,
            options=[("MSS", 1460), ("NOP", None), ("WScale", 0),
                     ("SAckOK", b""), ("NOP", None), ("NOP", None)]
        )
        fp = generate_ja4ts(packet)
        self.assertEqual(fp, "14600_2-1-3-4-1-1_1460_0")

    def test_f5_bigip_to_linux(self):
        packet = IP() / TCP(
            flags="SA", window=14600,
            options=[("MSS", 1460), ("NOP", None), ("WScale", 0),
                     ("SAckOK", b""), ("Timestamp", (0, 0))]
        )
        fp = generate_ja4ts(packet)
        self.assertEqual(fp, "14600_2-1-3-4-8_1460_0")

    def test_minimal_synack(self):
        packet = IP() / TCP(flags="SA", window=8192, options=[])
        fp = generate_ja4ts(packet)
        self.assertEqual(fp, "8192_0_0_0")


class TestJA4TSFormat(unittest.TestCase):
    """Test JA4TS format: window_options_mss_wscale."""

    def test_four_parts(self):
        packet = IP() / TCP(flags="SA", window=14600,
                            options=[("MSS", 1460)])
        fp = generate_ja4ts(packet)
        parts = fp.split("_")
        self.assertEqual(len(parts), 4)

    def test_large_mss(self):
        """All MSS values recorded as-is per spec."""
        packet = IP() / TCP(flags="SA", window=22000,
                            options=[("MSS", 65495), ("NOP", None), ("WScale", 7)])
        fp = generate_ja4ts(packet)
        self.assertEqual(fp, "22000_2-1-3_65495_7")


class TestJA4TSFingerprinterClass(unittest.TestCase):
    """Test JA4TSFingerprinter class."""

    def test_collect(self):
        fpr = JA4TSFingerprinter()
        for i in range(3):
            packet = IP() / TCP(sport=443, dport=54321 + i, flags="SA",
                                window=14600, options=[("MSS", 1460)])
            fpr.process_packet(packet)
        self.assertEqual(len(fpr.get_fingerprints()), 3)

    def test_reset(self):
        fpr = JA4TSFingerprinter()
        packet = IP() / TCP(flags="SA", window=14600, options=[("MSS", 1460)])
        fpr.process_packet(packet)
        fpr.reset()
        self.assertEqual(len(fpr.get_fingerprints()), 0)


if __name__ == "__main__":
    unittest.main()
