"""JA4L QUIC direction tests.

The QUIC form reads the direction of a flow from port 443, as the reference does. The
lexicographic order of the two addresses decides the internal connection key, and it
must not decide which endpoint is the client. An earlier defect made the timing path
report nothing when the client address sorted after the server address.
"""

from scapy.all import IP, UDP, Raw

from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.utils.quic_utils import QUIC_HANDSHAKE, QUIC_INITIAL

# A QUIC version 1 long header: the first byte, the version, and a zero-length
# destination connection identifier. RFC 9000 Section 17.2 gives the layout.
QUIC_VERSION_1 = b"\x00\x00\x00\x01"


def _quic_packet(src_ip, dst_ip, sport, dport, packet_type, t=0.0):
    """Build a UDP packet that carries one QUIC long header."""
    first_byte = bytes([0xC0 | (packet_type << 4)])
    payload = first_byte + QUIC_VERSION_1 + b"\x00" * 16
    packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / Raw(load=payload)
    packet.time = t
    return packet


def test_the_server_value_appears_when_the_client_address_sorts_first():
    """The fingerprinter reports the server value for a client address that sorts first."""
    fingerprinter = JA4LFingerprinter()
    fingerprinter.process_packet(
        _quic_packet("10.0.0.1", "10.0.0.2", 50000, 443, QUIC_INITIAL, t=0.0)
    )
    result = fingerprinter.process_packet(
        _quic_packet("10.0.0.2", "10.0.0.1", 443, 50000, QUIC_INITIAL, t=0.001)
    )
    assert result == "JA4L-S=500_64"


def test_the_server_value_appears_when_the_client_address_sorts_last():
    """The fingerprinter reports the server value for a client address that sorts last."""
    fingerprinter = JA4LFingerprinter()
    fingerprinter.process_packet(
        _quic_packet("10.0.0.99", "10.0.0.1", 50000, 443, QUIC_INITIAL, t=0.0)
    )
    result = fingerprinter.process_packet(
        _quic_packet("10.0.0.1", "10.0.0.99", 443, 50000, QUIC_INITIAL, t=0.002)
    )
    assert result == "JA4L-S=1000_64"


def test_the_client_value_measures_the_two_handshake_packets():
    """The client value measures the last server Handshake packet to the first client one."""
    fingerprinter = JA4LFingerprinter()
    initial_client = fingerprinter.process_packet(
        _quic_packet("192.168.1.50", "10.0.0.1", 50000, 443, QUIC_INITIAL, t=0.0)
    )
    initial_server = fingerprinter.process_packet(
        _quic_packet("10.0.0.1", "192.168.1.50", 443, 50000, QUIC_INITIAL, t=0.002)
    )
    handshake_server = fingerprinter.process_packet(
        _quic_packet("10.0.0.1", "192.168.1.50", 443, 50000, QUIC_HANDSHAKE, t=0.004)
    )
    handshake_client = fingerprinter.process_packet(
        _quic_packet("192.168.1.50", "10.0.0.1", 50000, 443, QUIC_HANDSHAKE, t=0.006)
    )

    assert initial_client is None
    assert initial_server == "JA4L-S=1000_64"
    assert handshake_server is None
    assert handshake_client == "JA4L-C=1000_64"


def test_the_fingerprinter_reports_nothing_for_a_udp_flow_that_carries_no_quic():
    """A UDP flow that carries no QUIC long header produces no JA4L value."""
    fingerprinter = JA4LFingerprinter()
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=50000, dport=53) / Raw(load=b"\x00")
    packet.time = 0.0
    assert fingerprinter.process_packet(packet) is None
    assert fingerprinter.get_fingerprints() == []
