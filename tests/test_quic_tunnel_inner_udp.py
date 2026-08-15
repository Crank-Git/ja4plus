"""The JA4 and JA4S QUIC branches read the innermost UDP layer of a packet.

`Packet.getlayer` counts from the outside, so it returns the UDP header of the tunnel
on a tunneled packet. The QUIC decoder then reads the tunnel header bytes instead of
the QUIC long header, and it produces no value. `ja4plus/utils/tunnels.py:50` publishes
`innermost_layer` for that reason, and `ja4plus/utils/packet_utils.py:107` already reads
the port pair through it.

No capture of the FoxIO corpus carries QUIC inside a tunnel, so every packet of this
module is constructed. The Initial keys of QUIC version 1 come from the destination
connection identifier and from a fixed salt, so a constructed packet needs no key
exchange. RFC 9001 Section 5.2 states that derivation, and `tests/quic_builder.py`
applies it.

Each case compares the tunneled packet against the untunneled packet that carries the
same QUIC bytes. A tunnel moves no fingerprint, so the two values agree. The untunneled
value is stated as a literal as well, so that two absent values pass no case. Issue #594
carries the reading.
"""

import struct

from scapy.all import IP, UDP, Ether, Raw
from scapy.layers.vxlan import VXLAN

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

from tests.quic_builder import (
    client_hello,
    client_initial,
    client_initial_crypto,
    crypto_frame,
    server_initial,
)

CLIENT_IP = "192.168.1.50"
SERVER_IP = "10.0.0.1"
CLIENT_PORT = 50280
SERVER_PORT = 443
CLIENT_DCID = bytes.fromhex("203f9e9f68698274")

# The outer addresses and the outer port of the tunnel. A reader that takes the outer
# UDP header reads port 4789 and never port 443.
TUNNEL_CLIENT_IP = "100.20.9.2"
TUNNEL_SERVER_IP = "100.20.9.1"
TUNNEL_SOURCE_PORT = 40000
VXLAN_PORT = 4789
VXLAN_IDENTIFIER = 100

# One tunnel endpoint stands at each side, so the return direction carries the outer
# addresses in the opposite order. A mirror that sends both directions from one outer
# address is a different shape, and #242 owns the key form that reads it.
OUTER_ADDRESSES = {
    CLIENT_IP: (TUNNEL_CLIENT_IP, TUNNEL_SERVER_IP),
    SERVER_IP: (TUNNEL_SERVER_IP, TUNNEL_CLIENT_IP),
}

# The inner Ethernet header names both addresses. An `Ether` layer that names neither one
# makes scapy resolve a MAC address, and that read opens `/dev/bpf0` and needs a grant no
# runner holds.
INNER_SOURCE_MAC = "02:00:00:00:00:01"
INNER_DESTINATION_MAC = "02:00:00:00:00:02"

CLIENT_KEY = "{}:{}-{}:{}".format(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

# The connection key of the tunneled handshake. `ja4plus/utils/packet_utils.py:85-86`
# states the rule this form follows: the address pair names the outer address layer, and
# the port pair names the innermost port layer. The port half is what this issue moves.
TUNNELED_KEY = "{}:{}-{}:{}".format(TUNNEL_CLIENT_IP, CLIENT_PORT, TUNNEL_SERVER_IP, SERVER_PORT)

# The JA4S value of the ServerHello below. `tests/test_ja4s_quic_direction.py` derives it
# from the FoxIO `chrome-cloudflare-quic-with-secrets` material, where the same TLS
# version, the same cipher and the same two extensions give `t130200_1301_234ea6891581`.
# Only the transport letter differs.
EXPECTED_JA4S = "q130200_1301_234ea6891581"

# The JA4 value of the ClientHello that `tests/quic_builder.py` builds. The message names
# one cipher and one server name extension, so the count section reads `0101`.
EXPECTED_JA4 = "q12d010100_0f2cb44170f4_000000000000"

SNI_HOSTNAME = "tunnel.example.com"


def _extension(identifier, data):
    """Return one TLS extension with the identifier and the data."""
    return struct.pack("!HH", identifier, len(data)) + data


def _server_hello():
    """Return one TLS 1.3 ServerHello that JA4S reads.

    The message names cipher `1301`, and it carries extension `0033` before extension
    `002b`. `tests/test_ja4s_quic_direction.py` builds the same message.

    Returns:
        The handshake message bytes.
    """
    key_share = _extension(0x0033, struct.pack("!HH", 0x001D, 32) + b"\x11" * 32)
    supported_versions = _extension(0x002B, struct.pack("!H", 0x0304))
    extensions = key_share + supported_versions
    body = struct.pack("!H", 0x0303) + b"\x22" * 32
    body += b"\x00"  # An empty session identifier.
    body += struct.pack("!H", 0x1301)
    body += b"\x00"  # The null compression method.
    body += struct.pack("!H", len(extensions)) + extensions
    return b"\x02" + len(body).to_bytes(3, "big") + body


def _plain(source_ip, destination_ip, source_port, destination_port, payload):
    """Return one packet that carries the payload and holds no tunnel.

    Args:
        source_ip: The source address.
        destination_ip: The destination address.
        source_port: The source port.
        destination_port: The destination port.
        payload: The UDP payload bytes.

    Returns:
        A scapy packet.
    """
    return (
        IP(src=source_ip, dst=destination_ip)
        / UDP(sport=source_port, dport=destination_port)
        / Raw(load=payload)
    )


def _tunneled(source_ip, destination_ip, source_port, destination_port, payload):
    """Return the same packet inside one VXLAN tunnel.

    The builder writes the bytes and reads them again, so scapy dissects the tunnel the
    way it dissects a captured packet. A packet the builder assembles in memory carries
    the layers the caller named, and it proves no dissection.

    Args:
        source_ip: The inner source address.
        destination_ip: The inner destination address.
        source_port: The inner source port.
        destination_port: The inner destination port.
        payload: The UDP payload bytes of the inner packet.

    Returns:
        A scapy packet whose layer list holds two IP layers and two UDP layers.
    """
    outer_source, outer_destination = OUTER_ADDRESSES[source_ip]
    outer = (
        IP(src=outer_source, dst=outer_destination)
        / UDP(sport=TUNNEL_SOURCE_PORT, dport=VXLAN_PORT)
        / VXLAN(vni=VXLAN_IDENTIFIER)
    )
    inner = Ether(src=INNER_SOURCE_MAC, dst=INNER_DESTINATION_MAC) / _plain(
        source_ip, destination_ip, source_port, destination_port, payload
    )
    return IP(bytes(outer / inner))


def _server_hello_packet():
    """Return the UDP payload of one server Initial packet that carries the ServerHello."""
    return server_initial(CLIENT_DCID, crypto_frame(0, _server_hello()))


def _split_client_hello():
    """Return the two client Initial payloads that split one ClientHello.

    A ClientHello that one datagram carries reaches `extract_tls_info`, which reads the
    innermost `Raw` layer and finds the QUIC bytes whatever the tunnel does. The split
    message is the shape that reaches `_try_quic_multi_packet`, which is the branch this
    module measures.

    Returns:
        The pair of UDP payload byte strings, in send order.
    """
    message = client_hello(SNI_HOSTNAME)
    half = len(message) // 2
    first = client_initial_crypto(CLIENT_DCID, crypto_frame(0, message[:half]))
    second = client_initial_crypto(CLIENT_DCID, crypto_frame(half, message[half:]), packet_number=1)
    return first, second


def _ja4_over(build):
    """Return the JA4 value the split ClientHello gives under one packet builder.

    Args:
        build: A callable that takes the five arguments of `_plain` and returns a packet.

    Returns:
        The JA4 value of the second datagram, or None.
    """
    first, second = _split_client_hello()
    fingerprinter = JA4Fingerprinter()
    fingerprinter.process_packet(build(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, first))
    return fingerprinter.process_packet(
        build(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, second)
    )


def _ja4s_over(build):
    """Return the JA4S value the QUIC handshake gives under one packet builder.

    Args:
        build: A callable that takes the five arguments of `_plain` and returns a packet.

    Returns:
        The JA4S value of the server Initial packet, or None.
    """
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(
        build(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, client_initial(CLIENT_DCID))
    )
    return fingerprinter.process_packet(
        build(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, _server_hello_packet())
    )


def test_the_builder_puts_two_udp_layers_in_a_tunneled_packet():
    """The tunneled packet holds an outer UDP header that names no QUIC port.

    Every other case of this module rests on that shape. A packet whose outer header
    already names port 443 measures nothing.
    """
    packet = _tunneled(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, client_initial(CLIENT_DCID))

    assert [layer.__name__ for layer in packet.layers()] == [
        "IP",
        "UDP",
        "VXLAN",
        "Ether",
        "IP",
        "UDP",
        "Raw",
    ]
    assert packet.getlayer(UDP).dport == VXLAN_PORT


def test_the_ja4s_fingerprinter_reads_the_quic_layer_of_a_tunneled_packet():
    """JA4S gives one tunneled QUIC handshake the value it gives the untunneled one."""
    assert _ja4s_over(_plain) == EXPECTED_JA4S
    assert _ja4s_over(_tunneled) == EXPECTED_JA4S


def test_the_ja4s_fingerprinter_keys_a_tunneled_connection_on_the_inner_ports():
    """JA4S stores the connection ID of a tunneled client under the inner port pair.

    The key holds the outer address pair and the inner port pair, which is the rule
    `ja4plus/utils/packet_utils.py:85-86` states. This issue moves the port half alone,
    and #242 owns the address half.
    """
    fingerprinter = JA4SFingerprinter()
    fingerprinter.process_packet(
        _tunneled(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, client_initial(CLIENT_DCID))
    )

    assert fingerprinter._quic_dcids == {TUNNELED_KEY: CLIENT_DCID}


def test_the_ja4_fingerprinter_reads_a_split_client_hello_inside_a_tunnel():
    """JA4 gives one tunneled split ClientHello the value it gives the untunneled one."""
    assert _ja4_over(_plain) == EXPECTED_JA4
    assert _ja4_over(_tunneled) == EXPECTED_JA4


def test_the_ja4_fingerprinter_keys_a_tunneled_connection_on_the_inner_ports():
    """JA4 records the inner port pair of a tunneled connection it still collects.

    The fingerprinter releases the entry when the ClientHello completes, so this case
    sends the first datagram alone and reads the table while the entry stands. The key
    holds the outer address pair and the inner port pair, which is the rule
    `ja4plus/utils/packet_utils.py:85-86` states.
    """
    first, _ = _split_client_hello()
    fingerprinter = JA4Fingerprinter()
    fingerprinter.process_packet(_tunneled(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, first))

    assert fingerprinter._quic_dcid_to_tuple == {CLIENT_DCID.hex(): TUNNELED_KEY}
