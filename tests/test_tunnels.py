"""Tests for the tunnel helpers in `ja4plus/utils/tunnels.py`."""

from scapy.all import GRE, IP, IPv6, TCP, UDP, Ether

from ja4plus.utils.tunnels import innermost_layer, register_tunnel_dissectors


# The three dissector modules `ja4plus/utils/tunnels.py` imports. The names are written
# here as literals, so a mutation of `TUNNEL_MODULES` changes one side of the comparison
# alone. A case that reads the constant compares the constant against itself, and #412
# measured that: three mutations of `TUNNEL_MODULES` left this case green.
EXPECTED_TUNNEL_MODULES = ("scapy.contrib.geneve", "scapy.layers.vxlan", "scapy.contrib.erspan")


def scapy_ships(name: str) -> bool:
    """Report whether the installed scapy holds the named module.

    Args:
        name: A dotted module name.

    Returns:
        True when the import succeeds. An older scapy ships no `erspan` module, and the
        docstring of `ja4plus/utils/tunnels.py` states that the absence is no defect.
    """
    import importlib

    try:
        importlib.import_module(name)
    except ImportError:
        return False
    return True


class TestRegisterTunnelDissectors:
    """The dissector import reports the modules the installed scapy ships."""

    def test_the_registration_returns_a_tuple_of_module_names(self):
        loaded = register_tunnel_dissectors()
        assert isinstance(loaded, tuple)
        assert all(name.startswith("scapy.") for name in loaded)

    def test_the_registration_names_every_tunnel_module_the_scapy_release_ships(self):
        expected = tuple(name for name in EXPECTED_TUNNEL_MODULES if scapy_ships(name))
        assert register_tunnel_dissectors() == expected


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
