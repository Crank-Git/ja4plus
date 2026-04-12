"""Tests for JA4D DHCP fingerprinting."""
import struct
import unittest

from scapy.all import IP, UDP, Raw

from ja4plus.fingerprinters.ja4d import (
    JA4DFingerprinter,
    build_option_list,
    build_param_list,
    generate_ja4d,
    DHCP_MESSAGE_TYPES,
    DHCP_SKIP_OPTIONS,
)


# ---------------------------------------------------------------------------
# Helpers to build raw DHCPv4 packets
# ---------------------------------------------------------------------------

DHCP_MAGIC = b'\x63\x82\x53\x63'


def _build_dhcp_payload(msg_type, options=None, max_msg_size=None,
                        request_ip=None, fqdn=False, param_request=None):
    """Build a minimal DHCPv4 UDP payload (BOOTP + DHCP options)."""
    # Minimal BOOTP fixed header (236 bytes)
    bootp = bytearray(236)
    bootp[0] = 1  # op = BOOTREQUEST
    # Add the DHCP magic cookie
    payload = bytes(bootp) + DHCP_MAGIC

    # Build options
    opts = bytearray()

    # Option 53: Message Type
    opts += bytes([53, 1, msg_type])

    # Option 57: Maximum DHCP Message Size
    if max_msg_size is not None:
        opts += bytes([57, 2]) + struct.pack('!H', max_msg_size)

    # Option 50: Requested IP Address (flag only — 4 zero bytes)
    if request_ip:
        opts += bytes([50, 4, 0, 0, 0, 0])

    # Option 81: Client FQDN (flag only — minimal 3-byte data)
    if fqdn:
        opts += bytes([81, 3, 0, 0, 0])

    # Option 55: Parameter Request List
    if param_request:
        opts += bytes([55, len(param_request)]) + bytes(param_request)

    # Extra options
    if options:
        for opt_code in options:
            if opt_code not in (53, 57, 50, 81, 55, 255):
                opts += bytes([opt_code, 0])  # zero-length option

    # End option
    opts += bytes([255])

    return payload + bytes(opts)


def _make_dhcp_packet(msg_type, src_ip="192.168.1.100", dst_ip="255.255.255.255",
                      sport=68, dport=67, **kwargs):
    """Build a Scapy packet wrapping a DHCPv4 payload."""
    raw = _build_dhcp_payload(msg_type, **kwargs)
    return IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / Raw(load=raw)


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestDHCPMessageTypes(unittest.TestCase):
    """All 18 message type abbreviations must be exactly 5 characters."""

    def test_all_18_types_present(self):
        for code in range(1, 19):
            self.assertIn(code, DHCP_MESSAGE_TYPES, f"Missing message type {code}")

    def test_all_abbreviations_are_5_chars(self):
        for code, abbrev in DHCP_MESSAGE_TYPES.items():
            self.assertEqual(len(abbrev), 5,
                             f"Type {code} abbreviation '{abbrev}' is not 5 chars")

    def test_known_mappings(self):
        expected = {
            1: "disco", 2: "offer", 3: "reqst", 4: "decln",
            5: "dpack", 6: "dpnak", 7: "relse", 8: "infor",
            9: "frenw", 10: "lqery", 18: "dhtls",
        }
        for code, abbrev in expected.items():
            self.assertEqual(DHCP_MESSAGE_TYPES[code], abbrev)


class TestBuildOptionList(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(build_option_list([]), "00")

    def test_all_skipped(self):
        self.assertEqual(build_option_list([53, 255, 50, 81]), "00")

    def test_single_option(self):
        self.assertEqual(build_option_list([53, 61, 255]), "61")

    def test_multiple_options(self):
        self.assertEqual(
            build_option_list([53, 61, 57, 60, 12, 55, 255]),
            "61-57-60-12-55"
        )

    def test_with_skipped_mixed(self):
        self.assertEqual(build_option_list([53, 50, 61, 81, 57, 255]), "61-57")

    def test_skip_set_respected(self):
        # Option 57 (max msg size) is NOT in the skip set, so it should appear
        self.assertIn("57", build_option_list([53, 57, 61, 255]))


class TestBuildParamList(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(build_param_list([]), "00")

    def test_single(self):
        self.assertEqual(build_param_list([1]), "1")

    def test_multiple(self):
        self.assertEqual(
            build_param_list([1, 3, 6, 15, 26, 28, 51, 58, 59]),
            "1-3-6-15-26-28-51-58-59"
        )


class TestGenerateJA4D(unittest.TestCase):
    """Tests for the generate_ja4d() function."""

    def test_discover_no_extras(self):
        """DHCPDISCOVER with no optional fields."""
        pkt = _make_dhcp_packet(msg_type=1)
        result = generate_ja4d(pkt)
        self.assertIsNotNone(result)
        # Section a: disco + 0000 (no max size) + n (no req IP) + n (no FQDN)
        parts = result.split('_')
        self.assertEqual(len(parts), 3)
        self.assertTrue(parts[0].startswith("disco"))
        self.assertEqual(parts[0][5:9], "0000")  # no max msg size
        self.assertEqual(parts[0][9], "n")        # no requested IP
        self.assertEqual(parts[0][10], "n")       # no FQDN

    def test_discover_with_max_size(self):
        pkt = _make_dhcp_packet(msg_type=1, max_msg_size=1500)
        result = generate_ja4d(pkt)
        self.assertIsNotNone(result)
        parts = result.split('_')
        self.assertEqual(parts[0][5:9], "1500")

    def test_discover_with_request_ip_flag(self):
        pkt = _make_dhcp_packet(msg_type=1, request_ip=True)
        result = generate_ja4d(pkt)
        self.assertIsNotNone(result)
        parts = result.split('_')
        self.assertEqual(parts[0][9], "i")

    def test_discover_with_fqdn_flag(self):
        pkt = _make_dhcp_packet(msg_type=1, fqdn=True)
        result = generate_ja4d(pkt)
        self.assertIsNotNone(result)
        parts = result.split('_')
        self.assertEqual(parts[0][10], "d")

    def test_offer_message_type(self):
        pkt = _make_dhcp_packet(msg_type=2, sport=67, dport=68)
        result = generate_ja4d(pkt)
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("offer"))

    def test_request_message_type(self):
        pkt = _make_dhcp_packet(msg_type=3)
        result = generate_ja4d(pkt)
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("reqst"))

    def test_param_request_list_in_section_c(self):
        params = [1, 3, 6, 15]
        pkt = _make_dhcp_packet(msg_type=1, param_request=params)
        result = generate_ja4d(pkt)
        self.assertIsNotNone(result)
        parts = result.split('_')
        self.assertEqual(parts[2], "1-3-6-15")

    def test_no_param_request_section_c_is_00(self):
        pkt = _make_dhcp_packet(msg_type=1)
        result = generate_ja4d(pkt)
        self.assertIsNotNone(result)
        parts = result.split('_')
        self.assertEqual(parts[2], "00")

    def test_extra_options_appear_in_section_b(self):
        pkt = _make_dhcp_packet(msg_type=1, options=[61, 12])
        result = generate_ja4d(pkt)
        self.assertIsNotNone(result)
        parts = result.split('_')
        self.assertIn("61", parts[1])
        self.assertIn("12", parts[1])

    def test_skip_options_absent_from_section_b(self):
        pkt = _make_dhcp_packet(msg_type=1, options=[61])
        result = generate_ja4d(pkt)
        parts = result.split('_')
        # 53 (msg type), 255 (end) are added by the builder but must not appear
        self.assertNotIn("53", parts[1].split('-'))
        self.assertNotIn("255", parts[1].split('-'))

    def test_max_msg_size_capped_at_9999(self):
        pkt = _make_dhcp_packet(msg_type=1, max_msg_size=65535)
        result = generate_ja4d(pkt)
        parts = result.split('_')
        self.assertEqual(parts[0][5:9], "9999")

    def test_non_dhcp_port_returns_none(self):
        raw = _build_dhcp_payload(msg_type=1)
        pkt = IP() / UDP(sport=1234, dport=5678) / Raw(load=raw)
        self.assertIsNone(generate_ja4d(pkt))

    def test_tcp_packet_returns_none(self):
        from scapy.all import TCP
        pkt = IP() / TCP(sport=68, dport=67)
        self.assertIsNone(generate_ja4d(pkt))

    def test_unknown_message_type_uses_numeric(self):
        pkt = _make_dhcp_packet(msg_type=99)
        result = generate_ja4d(pkt)
        self.assertIsNotNone(result)
        # Unknown type: zero-padded to 5 digits
        self.assertTrue(result.startswith("00099"))


class TestJA4DFingerprinter(unittest.TestCase):
    def setUp(self):
        self.fp = JA4DFingerprinter()

    def test_process_packet_returns_fingerprint(self):
        pkt = _make_dhcp_packet(msg_type=1)
        result = self.fp.process_packet(pkt)
        self.assertIsNotNone(result)
        self.assertEqual(len(self.fp.get_fingerprints()), 1)

    def test_reset_clears_state(self):
        pkt = _make_dhcp_packet(msg_type=1)
        self.fp.process_packet(pkt)
        self.fp.reset()
        self.assertEqual(len(self.fp.get_fingerprints()), 0)

    def test_non_dhcp_returns_none(self):
        from scapy.all import TCP
        pkt = IP() / TCP(sport=12345, dport=443)
        result = self.fp.process_packet(pkt)
        self.assertIsNone(result)

    def test_cleanup_connection_is_noop(self):
        """JA4D is stateless — cleanup should not raise."""
        self.fp.cleanup_connection("1.2.3.4", 68, "255.255.255.255", 67, "udp")


if __name__ == '__main__':
    unittest.main()
