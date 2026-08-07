"""Tests for the tunnel helpers in `ja4plus/utils/tunnels.py`."""

from scapy.all import GRE, IP, IPv6, TCP, UDP, Ether

from ja4plus.utils.tunnels import innermost_layer, register_tunnel_dissectors


class TestRegisterTunnelDissectors:
    """The dissector import reports the modules the installed scapy ships."""

    def test_the_registration_returns_a_tuple_of_module_names(self):
        loaded = register_tunnel_dissectors()
        assert isinstance(loaded, tuple)
        assert all(name.startswith("scapy.") for name in loaded)


class TestInnermostLayer:
    """`innermost_layer` reads the deepest layer of one class."""

    def test_the_helper_returns_the_inner_address_layer_of_a_tunnel(self):
        packet = Ether() / IP(src="10.0.0.1") / GRE() / IP(src="192.168.0.1") / TCP()
        assert innermost_layer(packet, (IP, IPv6)).src == "192.168.0.1"

    def test_the_helper_returns_the_only_address_layer_of_a_plain_packet(self):
        packet = Ether() / IP(src="10.0.0.1") / TCP()
        assert innermost_layer(packet, (IP, IPv6)).src == "10.0.0.1"

    def test_the_helper_returns_the_inner_port_layer_of_a_tunnel(self):
        packet = Ether() / IP() / UDP(sport=4789) / IP() / TCP(sport=1234)
        assert innermost_layer(packet, (TCP, UDP)).sport == 1234

    def test_the_helper_reads_an_address_layer_of_each_version(self):
        packet = Ether() / IP() / GRE() / IPv6(src="2001:db8::1") / TCP()
        assert innermost_layer(packet, (IP, IPv6)).src == "2001:db8::1"

    def test_the_helper_returns_none_when_the_packet_holds_no_such_layer(self):
        assert innermost_layer(Ether() / IP() / TCP(), (UDP,)) is None
