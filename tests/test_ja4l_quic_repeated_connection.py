"""Tests for the JA4L QUIC measurement points across a repeated connection.

#123 asks the QUIC path to restart its measurement points when a client repeats the
handshake over one address pair and port pair. It also asks the path to complete the
server value when a server Initial packet leads its client Initial packet.

The FoxIO Rust implementation is the only FoxIO implementation that reads a QUIC
handshake, so it decides both cases. A measurement of it rejects both changes.

`tests/build_quic_ja4l_captures.py` writes the two captures the measurement reads, and
these tests read the same packets from the same builder. The reference ran at commit
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`, which `tests/download_test_vectors.py`
pins:

    $ ja4 quic_repeat.pcap
      ja4l_c: 500_64
      ja4l_s: 5000_56
    $ ja4 quic_mirrored.pcap
    []

The first capture holds two complete handshakes over one address pair and port pair.
The reference reports one value pair, so it restarts on neither handshake. The second
capture holds one server Initial packet before its client Initial packet. The
reference reports no value at all, so it completes no server value.

`rust/ja4/src/time/udp.rs` states the mechanism. The state machine holds a terminal
`Done` state that ignores every later packet. Its `Handshake` state discards a later
`ClientInitial`, and its first state discards a `ServerInitial`.

These tests hold `ja4plus` against those two measurements, so that a restart cannot
land without a vector.
"""

from tests.build_quic_ja4l_captures import (
    FIRST_DCID,
    SECOND_DCID,
    handshake_round,
    mirrored_round,
)

from ja4plus.fingerprinters.ja4l import JA4LFingerprinter


def _read(packets):
    """Return the JA4L values one fingerprinter reports for the packets."""
    fingerprinter = JA4LFingerprinter()
    for packet in packets:
        fingerprinter.process_packet(packet)
    return [entry["fingerprint"] for entry in fingerprinter.get_fingerprints()]


def test_a_repeated_quic_handshake_reports_one_value_pair():
    """The fingerprinter reports one value pair for two handshakes on one port pair.

    The reference reports `ja4l_c: 500_64` and `ja4l_s: 5000_56` for this capture, and
    `ja4plus` reports the same pair. A restart on the second client Initial packet
    would report a second pair that no FoxIO implementation reports.
    """
    packets = handshake_round(FIRST_DCID, 1000.0) + handshake_round(SECOND_DCID, 1001.0)

    assert _read(packets) == ["JA4L-S=5000_56", "JA4L-C=500_64"]


def test_a_leading_server_initial_packet_gives_no_value():
    """The fingerprinter reports no value for a server Initial packet that leads.

    The reference reports no value at all for this capture. It discards the leading
    server Initial packet, so it reaches neither the server point nor the client point.

    #123 measured the reference and left the client value as a divergence. #156 closes
    it. The QUIC client value needs the server Initial point, exactly as the TCP client
    value needs the SYN-ACK.
    """
    values = _read(mirrored_round(FIRST_DCID, 2000.0))

    assert values == []
