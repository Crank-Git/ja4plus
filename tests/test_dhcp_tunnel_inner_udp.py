"""The JA4D and JA4D6 branches read the innermost UDP layer of a packet.

`Packet.getlayer` counts a layer from the outside, so it returns the UDP header of the
tunnel on a tunneled packet. `ja4plus/utils/tunnels.py:50` publishes `innermost_layer`
for that reason, and `ja4plus/utils/packet_utils.py:107` already reads the port pair
through it. #646 carries the reading and #594 made the same repair on the QUIC branches.

**The defect shape of these two methods is an absent value, and it is not a wrong one.**
Each method reads a port range before it reads the payload. `ja4d.py` matches 67, 68 and
4011, and `ja4d6.py` matches 546 and 547. A tunnel port is none of those five, so the
outer header fails the port test and the method returns None. The QUIC branches held no
port test, so they decoded the tunnel bytes instead.

No capture of the FoxIO corpus carries DHCP inside a tunnel, so no vector separates the
two behaviours and every packet of this module is constructed. A replay of the 38
committed captures produced 4 JA4D values and 6 JA4D6 values before the change and after
it.

Each case compares the tunneled packet against the untunneled packet that carries the
same DHCP bytes. A tunnel moves no fingerprint, so the two values agree. The untunneled
value is stated as a literal as well, so that two absent values pass no case.
"""

import struct

from scapy.all import IP, IPv6, UDP, Ether, Raw
from scapy.layers.vxlan import VXLAN

from ja4plus.fingerprinters.ja4d import JA4DFingerprinter, generate_ja4d
from ja4plus.fingerprinters.ja4d6 import JA4D6Fingerprinter, generate_ja4d6

# The magic cookie that opens the option field of a DHCPv4 message. RFC 2131 Section 3
# states it.
DHCP_MAGIC = b"\x63\x82\x53\x63"

CLIENT_IP = "192.168.1.100"
BROADCAST_IP = "255.255.255.255"
CLIENT_PORT = 68
SERVER_PORT = 67

CLIENT_IPV6 = "fe80::1"
RELAY_IPV6 = "ff02::1:2"
CLIENT_PORT_V6 = 546
SERVER_PORT_V6 = 547

# The outer addresses and the outer ports of the tunnel. A reader that takes the outer
# UDP header reads 40000 and 4789, and it reads neither DHCP port pair. Those two ports
# stand outside the five the two methods match, so such a reader produces no value at
# all.
TUNNEL_CLIENT_IP = "100.20.9.2"
TUNNEL_SERVER_IP = "100.20.9.1"
TUNNEL_SOURCE_PORT = 40000
VXLAN_PORT = 4789
VXLAN_IDENTIFIER = 100

# The inner Ethernet header names both addresses. An `Ether` layer that names neither one
# makes scapy resolve a MAC address, and that read opens `/dev/bpf0` and needs a grant no
# runner holds.
INNER_SOURCE_MAC = "02:00:00:00:00:01"
INNER_DESTINATION_MAC = "02:00:00:00:00:02"

# The JA4D value of the DHCPv4 Discover below. Part a reads message type 1, the maximum
# message size 1500, option 50 and option 81. Part b lists options 57 and 55, which are
# the two the option list holds. Part c lists the parameter request list.
EXPECTED_JA4D = "disco1500id_57-55_1-3-6-15"

# The JA4D6 value of the DHCPv6 Solicit below. Part a reads message type 1 and the DUID
# length 14. Part b lists options 1, 4, 39 and 6, and part c lists the two option codes
# that option 6 requests.
EXPECTED_JA4D6 = "solct0014id_1-4-39-6_23-24"


def _dhcpv4_discover():
    """Return the UDP payload of one DHCPv4 Discover message.

    The message carries option 53, option 57, option 50, option 81 and option 55, so
    every one of the six JA4D inputs reads a value the message states rather than a
    default. `tests/test_ja4d.py` builds the same shape.

    Returns:
        The UDP payload bytes, the BOOTP fixed header first.
    """
    bootp = bytearray(236)
    bootp[0] = 1  # BOOTREQUEST.
    options = bytearray()
    options += bytes([53, 1, 1])  # Message type: Discover.
    options += bytes([57, 2]) + struct.pack("!H", 1500)  # Maximum message size.
    options += bytes([50, 4, 0, 0, 0, 0])  # Requested address.
    options += bytes([81, 7, 0, 0, 0]) + b"host"  # Client FQDN, one name after 3 bytes.
    options += bytes([55, 4]) + bytes([1, 3, 6, 15])  # Parameter request list.
    options += bytes([255])  # End.
    return bytes(bootp) + DHCP_MAGIC + bytes(options)


def _dhcpv6_solicit():
    """Return the UDP payload of one DHCPv6 Solicit message.

    Option 4 carries its 4-byte identifier and no sub-option, because `_walk_options`
    reads a sub-option field and a zero byte there would reach the option list as
    option 0.

    Returns:
        The UDP payload bytes, the message type first.
    """
    message = bytes([1]) + b"\x11\x22\x33"  # Solicit, then the transaction identifier.
    duid = b"\x00\x01\x00\x01" + b"\xaa" * 10  # 14 bytes, which part a reports.
    message += struct.pack("!HH", 1, len(duid)) + duid  # Client identifier.
    message += struct.pack("!HH", 4, 4) + b"\x00\x00\x00\x07"  # IA_TA, the `i` flag.
    message += struct.pack("!HH", 39, 5) + b"\x00" + b"host"  # Client FQDN.
    message += struct.pack("!HH", 6, 4) + struct.pack("!HH", 23, 24)  # Option request.
    return message


def _plain(inner, source_port, destination_port, payload):
    """Return one packet that carries the payload and holds no tunnel.

    Args:
        inner: The inner address layer, which the caller builds.
        source_port: The source port.
        destination_port: The destination port.
        payload: The UDP payload bytes.

    Returns:
        A scapy packet.
    """
    return inner / UDP(sport=source_port, dport=destination_port) / Raw(load=payload)


def _tunneled(inner, source_port, destination_port, payload):
    """Return the same packet inside one VXLAN tunnel.

    The builder writes the bytes and reads them again, so scapy dissects the tunnel the
    way it dissects a captured packet. A packet the builder assembles in memory carries
    the layers the caller named, and it proves no dissection.

    Args:
        inner: The inner address layer, which the caller builds.
        source_port: The inner source port.
        destination_port: The inner destination port.
        payload: The UDP payload bytes of the inner packet.

    Returns:
        A scapy packet whose layer list holds two UDP layers.
    """
    outer = (
        IP(src=TUNNEL_CLIENT_IP, dst=TUNNEL_SERVER_IP)
        / UDP(sport=TUNNEL_SOURCE_PORT, dport=VXLAN_PORT)
        / VXLAN(vni=VXLAN_IDENTIFIER)
    )
    encapsulated = Ether(src=INNER_SOURCE_MAC, dst=INNER_DESTINATION_MAC) / _plain(
        inner, source_port, destination_port, payload
    )
    return IP(bytes(outer / encapsulated))


def _dhcpv4_packet(build):
    """Return the DHCPv4 Discover packet one builder gives."""
    return build(IP(src=CLIENT_IP, dst=BROADCAST_IP), CLIENT_PORT, SERVER_PORT, _dhcpv4_discover())


def _dhcpv6_packet(build):
    """Return the DHCPv6 Solicit packet one builder gives."""
    return build(
        IPv6(src=CLIENT_IPV6, dst=RELAY_IPV6), CLIENT_PORT_V6, SERVER_PORT_V6, _dhcpv6_solicit()
    )


def test_the_builder_puts_two_udp_layers_in_a_tunneled_dhcp_packet():
    """The tunneled packet holds an outer UDP header that names no DHCP port.

    Every other case of this module rests on that shape. A packet whose outer header
    already names port 67 measures nothing. The case reads the six layers of the tunnel
    and it names no layer after them, because scapy dissects the DHCP message itself and
    the layer count of that dissection is no statement of this issue.
    """
    packet = _dhcpv4_packet(_tunneled)

    assert [layer.__name__ for layer in packet.layers()][:6] == [
        "IP",
        "UDP",
        "VXLAN",
        "Ether",
        "IP",
        "UDP",
    ]
    assert packet.getlayer(UDP).sport == TUNNEL_SOURCE_PORT
    assert packet.getlayer(UDP).dport == VXLAN_PORT
    assert packet.getlayer(UDP, 2).sport == CLIENT_PORT
    assert packet.getlayer(UDP, 2).dport == SERVER_PORT


def test_the_builder_puts_two_udp_layers_in_a_tunneled_dhcpv6_packet():
    """The tunneled DHCPv6 packet holds an outer UDP header that names no DHCPv6 port."""
    packet = _dhcpv6_packet(_tunneled)

    assert [layer.__name__ for layer in packet.layers()][:6] == [
        "IP",
        "UDP",
        "VXLAN",
        "Ether",
        "IPv6",
        "UDP",
    ]
    assert packet.getlayer(UDP).dport == VXLAN_PORT
    assert packet.getlayer(UDP, 2).sport == CLIENT_PORT_V6
    assert packet.getlayer(UDP, 2).dport == SERVER_PORT_V6


def test_the_ja4d_fingerprinter_reads_the_dhcp_layer_of_a_tunneled_packet():
    """JA4D gives one tunneled Discover the value it gives the untunneled one."""
    assert generate_ja4d(_dhcpv4_packet(_plain)) == EXPECTED_JA4D
    assert generate_ja4d(_dhcpv4_packet(_tunneled)) == EXPECTED_JA4D


def test_the_ja4d6_fingerprinter_reads_the_dhcpv6_layer_of_a_tunneled_packet():
    """JA4D6 gives one tunneled Solicit the value it gives the untunneled one."""
    assert generate_ja4d6(_dhcpv6_packet(_plain)) == EXPECTED_JA4D6
    assert generate_ja4d6(_dhcpv6_packet(_tunneled)) == EXPECTED_JA4D6


def test_the_ja4d_fingerprinter_reports_a_tunneled_message_on_the_inner_ports():
    """JA4D reports the outer address pair and the inner port pair of a tunneled message.

    `ja4plus/utils/packet_utils.py:85-86` states that rule. #242 decided the address half
    and #646 moves the port half alone. The outer ports 40000 and 4789 reach no field.
    """
    fingerprinter = JA4DFingerprinter()
    fingerprinter.process_packet(_dhcpv4_packet(_tunneled))

    assert fingerprinter.get_fingerprints() == [
        {
            "fingerprint": EXPECTED_JA4D,
            "src": TUNNEL_CLIENT_IP,
            "dst": TUNNEL_SERVER_IP,
            "srcport": CLIENT_PORT,
            "dstport": SERVER_PORT,
        }
    ]


def test_the_ja4d6_fingerprinter_reports_a_tunneled_message_on_the_inner_ports():
    """JA4D6 reports the outer address pair and the inner port pair of a tunneled message.

    The outer address layer of this packet is the IPv4 header of the tunnel, and the
    inner address layer is an IPv6 header. `get_ip_layer` reads IPv4 first, so it reads
    the outer layer, which is the layer the rule names.
    """
    fingerprinter = JA4D6Fingerprinter()
    fingerprinter.process_packet(_dhcpv6_packet(_tunneled))

    assert fingerprinter.get_fingerprints() == [
        {
            "fingerprint": EXPECTED_JA4D6,
            "src": TUNNEL_CLIENT_IP,
            "dst": TUNNEL_SERVER_IP,
            "srcport": CLIENT_PORT_V6,
            "dstport": SERVER_PORT_V6,
        }
    ]
