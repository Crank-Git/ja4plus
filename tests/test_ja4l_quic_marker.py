"""JA4L marker tests for a QUIC connection.

The FoxIO specification image labels three parts, and `ja4plus` writes two timing parts.
#225 holds the ruling. The user decided on 2026-08-08 that JA4L keeps two timing
parts, and that a QUIC connection carries a protocol marker as the third part.

**The marker spells `quic`.** Two FoxIO implementations write a marker, and they spell it
differently.

- `wireshark/source/packet-ja4.c:1441` and `wireshark/source/packet-ja4.c:1447` write
  `"%d_%d_quic"`. `wireshark/test/testdata/` publishes the spelling on 9 of the 44
  `ja4.ja4l` values and on 9 of the 44 `ja4.ja4ls` values.
- `zeek/ja4l/main.zeek:233` and `zeek/ja4l/main.zeek:252` append the literal `q`.

`.claude/rules/external-apis.md:124` reads "Read no JA4L or JA4LS value of a Zeek baseline
as a reference value", and `.claude/rules/external-apis.md:130` names the `q` marker as
one of the three Zeek divergences. The rule therefore declines the Zeek spelling, and the
Wireshark spelling is the one published reading that remains.

A TCP connection carries no marker, because no reference value in this repository can
verify a third part on a TCP connection.
"""

from pathlib import Path

import pytest
from scapy.all import IP, UDP, Raw, rdpcap

from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from tests.quic_builder import handshake_packet

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"

CLOUDFLARE_QUIC = "udp_2001:db8:1::1:50280_2606:4700:10::6816:826:443"
TLS3_QUIC_CLIENT = "udp_172.253.122.95:443_192.168.1.169:62481"
BADCURVEBALL_TCP = "tcp_172.130.128.76:55318_54.226.182.138:443"


def values_on(capture_name, connection_key):
    """Return the JA4L values one capture produces on one connection.

    Args:
        capture_name: The file name of a capture under `tests/foxio_vectors`.
        connection_key: The connection key the fingerprinter reports.

    Returns:
        The values on that connection, in the order the fingerprinter emitted them.
    """
    fingerprinter = JA4LFingerprinter()
    for packet in rdpcap(str(VECTORS_DIR / capture_name)):
        fingerprinter.process_packet(packet)
    return [
        entry["fingerprint"]
        for entry in fingerprinter.get_fingerprints()
        if entry["connection"] == connection_key
    ]


@pytest.mark.skipif(
    not (VECTORS_DIR / "badcurveball.pcap").exists(), reason="FoxIO vectors are absent"
)
class TestTheQUICMarker:
    """Measure the protocol marker on a QUIC connection and its absence on a TCP one."""

    def test_a_quic_server_value_ends_with_the_quic_marker(self):
        # chrome-cloudflare-quic-with-secrets.pcapng stream 0, port 50280.
        assert "JA4L-S=10990_56_quic" in values_on(
            "chrome-cloudflare-quic-with-secrets.pcapng", CLOUDFLARE_QUIC
        )

    def test_a_quic_client_value_ends_with_the_quic_marker(self):
        # chrome-cloudflare-quic-with-secrets.pcapng stream 0, port 50280.
        assert "JA4L-C=113_64_quic" in values_on(
            "chrome-cloudflare-quic-with-secrets.pcapng", CLOUDFLARE_QUIC
        )

    def test_a_quic_connection_that_completes_the_handshake_after_the_capture_ends(self):
        """The server value carries the marker on the packet that fills point `D`.

        ssh2.pcapng stream 33 carries a client Initial packet and a server Initial
        packet, and it ends before a Handshake packet moves. The reference publishes
        the server value on the packet that fills point `D`, so the capture alone
        gives no value. Two packets built here, past the end of the capture, complete
        the handshake and prove the value the capture's two Initial packets gave.
        """
        connection_key = "udp_142.251.32.74:443_172.16.225.48:51810"
        fingerprinter = JA4LFingerprinter()
        last_moment = 0.0
        for packet in rdpcap(str(VECTORS_DIR / "ssh2.pcapng")):
            fingerprinter.process_packet(packet)
            if hasattr(packet, "time"):
                last_moment = max(last_moment, float(packet.time))
        assert [
            entry
            for entry in fingerprinter.get_fingerprints()
            if entry["connection"] == connection_key
        ] == []

        server_handshake = (
            IP(src="142.251.32.74", dst="172.16.225.48")
            / UDP(sport=443, dport=51810)
            / Raw(load=handshake_packet())
        )
        server_handshake.time = last_moment + 0.001
        fingerprinter.process_packet(server_handshake)

        client_handshake = (
            IP(src="172.16.225.48", dst="142.251.32.74")
            / UDP(sport=51810, dport=443)
            / Raw(load=handshake_packet())
        )
        client_handshake.time = last_moment + 0.002
        result = fingerprinter.process_packet(client_handshake)

        assert result == "JA4L-S=16192_57_quic"

    def test_both_values_of_one_quic_connection_carry_the_marker(self):
        assert values_on("tls3.pcapng", TLS3_QUIC_CLIENT) == [
            "JA4L-S=4213_59_quic",
            "JA4L-C=59_128_quic",
        ]

    def test_a_tcp_value_carries_no_marker(self):
        # The image labels a third part, and no reference value in this repository can
        # verify one on a TCP connection. `.claude/rules/conformance.md` states the rule.
        produced = values_on("badcurveball.pcap", BADCURVEBALL_TCP)
        assert produced == ["JA4L-S=781_238", "JA4L-C=2181_64"]

    def test_no_tcp_value_of_any_vector_holds_a_third_part(self):
        """Fail when a TCP connection gains a third part.

        The ruling moves a QUIC value alone. This case reads every capture, so a
        marker that reaches the TCP branch fails here and not in one named case.
        """
        offenders = []
        for capture in sorted(VECTORS_DIR.glob("*.pcap")) + sorted(VECTORS_DIR.glob("*.pcapng")):
            fingerprinter = JA4LFingerprinter()
            for packet in rdpcap(str(capture)):
                fingerprinter.process_packet(packet)
            for entry in fingerprinter.get_fingerprints():
                if entry["connection"].startswith("tcp_"):
                    value = entry["fingerprint"].split("=", 1)[1]
                    if len(value.split("_")) != 2:
                        offenders.append((capture.name, entry["fingerprint"]))
        assert offenders == []
