"""Tests for IPv4/IPv6 packet utility helpers."""

import unittest
from scapy.all import IP, TCP, Raw, IPv6


class TestGetIPLayer(unittest.TestCase):

    def test_ipv4_packet(self):
        from ja4plus.utils.packet_utils import get_ip_layer
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP()
        layer = get_ip_layer(pkt)
        self.assertIsNotNone(layer)
        self.assertEqual(layer.src, "1.2.3.4")

    def test_ipv6_packet(self):
        from ja4plus.utils.packet_utils import get_ip_layer
        pkt = IPv6(src="::1", dst="::2") / TCP()
        layer = get_ip_layer(pkt)
        self.assertIsNotNone(layer)
        self.assertEqual(layer.src, "::1")

    def test_no_ip_returns_none(self):
        from ja4plus.utils.packet_utils import get_ip_layer
        pkt = TCP()
        layer = get_ip_layer(pkt)
        self.assertIsNone(layer)

    def test_ipv4_preferred_when_both(self):
        from ja4plus.utils.packet_utils import get_ip_layer
        pkt = IPv6(src="::1", dst="::2") / IP(src="1.2.3.4") / TCP()
        layer = get_ip_layer(pkt)
        self.assertIsNotNone(layer)


class TestGetTTL(unittest.TestCase):

    def test_ipv4_ttl(self):
        from ja4plus.utils.packet_utils import get_ttl
        pkt = IP(ttl=128) / TCP()
        self.assertEqual(get_ttl(pkt), 128)

    def test_ipv6_hlim(self):
        from ja4plus.utils.packet_utils import get_ttl
        pkt = IPv6(hlim=64) / TCP()
        self.assertEqual(get_ttl(pkt), 64)

    def test_no_ip_returns_none(self):
        from ja4plus.utils.packet_utils import get_ttl
        pkt = TCP()
        self.assertIsNone(get_ttl(pkt))


if __name__ == "__main__":
    unittest.main()
