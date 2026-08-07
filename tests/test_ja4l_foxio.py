"""JA4L value tests derived from the FoxIO vectors.

Each test names one vector, one stream and the value the FoxIO expected-output file
holds. The vectors live under `tests/foxio_vectors`, and `tests/foxio_vectors/NOTICE`
names the upstream commit.

The reference computes a TCP JA4L value from three measurement points:

- `A` is the first TCP SYN, and it carries the client TTL.
- `B` is the first TCP SYN-ACK, and it carries the server TTL.
- `C` is the last TCP packet that carries the relative sequence number 1 and the
  relative acknowledgement number 1, and that holds no complete HTTP request.

The QUIC form reads the Initial packets and the Handshake packets instead.

`JA4L-S` is half the time from `A` to `B`. `JA4L-C` is half the time from `B` to `C`.
"""

from pathlib import Path

import pytest
from scapy.all import rdpcap

from ja4plus.fingerprinters.ja4l import JA4LFingerprinter

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"


def values_of(capture_name):
    """Return the JA4L values one capture produces, grouped by connection key.

    Args:
        capture_name: The file name of a capture under `tests/foxio_vectors`.

    Returns:
        A map of connection key to the list of values, in the order the fingerprinter
        emitted them.
    """
    fingerprinter = JA4LFingerprinter()
    for packet in rdpcap(str(VECTORS_DIR / capture_name)):
        fingerprinter.process_packet(packet)
    produced = {}
    for entry in fingerprinter.get_fingerprints():
        produced.setdefault(entry["connection"], []).append(entry["fingerprint"])
    return produced


def values_on(capture_name, connection_key):
    """Return the values one capture produces on one connection."""
    return values_of(capture_name).get(connection_key, [])


BADCURVEBALL = "tcp_172.130.128.76:55318_54.226.182.138:443"
BROWSERS_X509 = "tcp_13.107.21.239:443_172.27.7.31:54524"
LATEST_HTTP = "tcp_172.16.225.48:52939_23.43.242.57:80"
EMPTY_USERAGENT = "tcp_::1:9200_::1:57722"
GRE_SAMPLE = "tcp_172.27.1.66:40264_66.59.109.137:22"
SSH2_QUIC = "udp_142.251.41.46:443_172.16.225.48:61861"


@pytest.mark.skipif(
    not (VECTORS_DIR / "badcurveball.pcap").exists(), reason="FoxIO vectors are absent"
)
class TestJA4LAgainstTheFoxIOVectors:
    """Compare the JA4L values of one vector against the FoxIO expected output."""

    def test_the_server_value_holds_half_the_time_from_the_syn_to_the_syn_ack(self):
        # badcurveball.pcap: SYN at +0 us, SYN-ACK at +1563 us, server TTL 238.
        assert "JA4L-S=781_238" in values_on("badcurveball.pcap", BADCURVEBALL)

    def test_the_client_value_measures_to_the_first_client_data_packet(self):
        # browsers-x509.pcapng stream 0: SYN-ACK at +3815 us, Client Hello at +4371 us.
        # The bare ACK at +3927 us gives 56, and the reference holds 278.
        assert "JA4L-C=278_128" in values_on("browsers-x509.pcapng", BROWSERS_X509)

    def test_a_complete_http_request_does_not_move_the_client_point(self):
        # latest.pcapng stream 6 carries one complete GET request. The reference keeps
        # the measurement point at the bare ACK.
        assert "JA4L-C=32_128" in values_on("latest.pcapng", LATEST_HTTP)

    def test_a_partial_http_request_moves_the_client_point(self):
        # http-empty-useragent.pcap sends the request line, the header and the blank
        # line in three packets. The reference measures to the request line.
        assert "JA4L-C=177863_64" in values_on("http-empty-useragent.pcap", EMPTY_USERAGENT)

    def test_the_fingerprinter_reads_the_outer_address_layer_of_a_gre_capture(self):
        # gre-sample.pcap holds a TCP session inside GRE. The reference reads the
        # address and the TTL of the outer layer, and the port of the inner layer.
        produced = values_on("gre-sample.pcap", GRE_SAMPLE)
        assert "JA4L-S=22952_236" in produced
        assert "JA4L-C=26150_255" in produced

    def test_the_quic_form_reads_the_initial_and_the_handshake_packets(self):
        # ssh2.pcapng stream 36 is QUIC. JA4L-S measures the two Initial packets, and
        # JA4L-C measures the last server Handshake packet to the first client one.
        produced = values_on("ssh2.pcapng", SSH2_QUIC)
        assert "JA4L-S=5389_57" in produced
        assert "JA4L-C=169_128" in produced

    def test_the_fingerprinter_emits_one_client_value_for_one_connection(self):
        produced = values_on("badcurveball.pcap", BADCURVEBALL)
        client_values = [value for value in produced if value.startswith("JA4L-C=")]
        assert client_values == ["JA4L-C=2181_64"]
