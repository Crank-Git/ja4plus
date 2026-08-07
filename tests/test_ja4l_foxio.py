"""JA4L value tests derived from the FoxIO material.

The FoxIO JA4L slide states that field `a` holds the "One-way TCP latency in us".
`https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4L.png` holds the
slide. The FoxIO reference program halves every round-trip time, at
`https://github.com/FoxIO-LLC/ja4/blob/main/python/common.py` line 182:

    return int((dt2-dt1).microseconds/2)

The same program picks the measurement points, at
`https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py` lines 560 to 587.

Each test below names one vector, one stream and one reference value. The reference
value comes from `tests/foxio_vectors/<capture>.json`, which FoxIO generates.
"""

from pathlib import Path

import pytest

VECTORS = Path(__file__).parent / "foxio_vectors"

pytestmark = pytest.mark.skipif(not VECTORS.exists(), reason="FoxIO vectors not downloaded")


def values_of(capture, port):
    """Return the JA4L values of one stream, keyed by method name.

    Args:
        capture: The file name of a capture under `tests/foxio_vectors`.
        port: The client port of the stream, as an integer.

    Returns:
        A map of method name to the list of values the fingerprinter produced, in
        production order.
    """
    from scapy.all import TCP, UDP, rdpcap

    from ja4plus.fingerprinters.ja4l import JA4LFingerprinter

    fingerprinter = JA4LFingerprinter()
    for packet in rdpcap(str(VECTORS / capture)):
        layer = packet.getlayer(TCP) or packet.getlayer(UDP)
        if layer is None or port not in (int(layer.sport), int(layer.dport)):
            continue
        fingerprinter.process_packet(packet)

    values = {}
    for entry in fingerprinter.get_fingerprints():
        method, _, value = entry["fingerprint"].partition("=")
        values.setdefault(method, []).append(value)
    return values


def test_the_server_latency_of_badcurveball_is_half_the_round_trip_time():
    # SYN at +0 us, SYN-ACK at +1563 us. The reference holds 1563 / 2.
    assert values_of("badcurveball.pcap", 55318)["JA4L-S"] == ["781_238"]


def test_the_client_latency_of_badcurveball_measures_to_the_first_client_data():
    # SYN-ACK at +1563 us, bare ACK at +5918 us, client data at +5925 us. The
    # reference holds (5925 - 1563) / 2, so the bare ACK is not the measurement point.
    assert values_of("badcurveball.pcap", 55318)["JA4L-C"] == ["2181_64"]


def test_the_server_latency_of_browsers_x509_is_half_the_round_trip_time():
    assert values_of("browsers-x509.pcapng", 54524)["JA4L-S"] == ["1907_112"]


def test_the_client_latency_of_browsers_x509_measures_to_the_client_hello():
    # SYN-ACK at +3815 us, bare ACK at +3927 us, Client Hello at +4371 us. The
    # reference holds (4371 - 3815) / 2 = 278, and not (3927 - 3815) / 2 = 56.
    assert values_of("browsers-x509.pcapng", 54524)["JA4L-C"] == ["278_128"]


def test_the_client_latency_of_gre_sample_reads_a_server_packet():
    # The last packet that carries relative sequence 1 and relative acknowledgement 1
    # comes from the server, at +10062093 us. The SYN-ACK is at +10009792 us, and the
    # reference holds (10062093 - 10009792) / 2 = 26150. The TTL is the client TTL of
    # 255, and not the TTL of 236 that the packet itself carries.
    assert values_of("gre-sample.pcap", 40264)["JA4L-C"] == ["26150_255"]


def test_the_server_latency_of_gre_sample_reads_the_outer_address_layer():
    assert values_of("gre-sample.pcap", 40264)["JA4L-S"] == ["22952_236"]


def test_the_quic_server_latency_measures_to_the_server_hello():
    # The server sends two Initial packets, at +5497206 us and at +5500617 us. Only
    # the second one carries the ServerHello. The client Initial is at +5478636 us,
    # and the reference holds (5500617 - 5478636) / 2 = 10990.
    capture = "chrome-cloudflare-quic-with-secrets.pcapng"
    assert values_of(capture, 50280)["JA4L-S"] == ["10990_56"]


def test_the_quic_client_latency_measures_between_the_handshake_packets():
    # The last server Handshake packet before the first client Handshake packet is at
    # +5501254 us, and the first client Handshake packet is at +5501480 us. The
    # reference holds (5501480 - 5501254) / 2 = 113.
    capture = "chrome-cloudflare-quic-with-secrets.pcapng"
    assert values_of(capture, 50280)["JA4L-C"] == ["113_64"]


def test_one_connection_produces_one_client_latency_value():
    """The reference overwrites the client value, so one connection holds one value."""
    assert len(values_of("badcurveball.pcap", 55318)["JA4L-C"]) == 1
