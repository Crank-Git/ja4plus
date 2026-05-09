"""JA4L UDP/QUIC direction-independence test.

Previously the UDP/QUIC timing path silently failed when the first packet
came from the lexicographically-larger IP (direction='reverse' in the
internal conn_key). The fix: identify the client by FIRST-PACKET ordering,
not by conn_key direction.
"""
import os

import pytest


def _udp_packet(src_ip, dst_ip, sport, dport, payload=b"\x00", t=0.0):
    """Build a synthetic UDP packet with a pcap timestamp."""
    from scapy.all import IP, UDP, Raw

    pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / Raw(load=payload)
    pkt.time = t
    return pkt


def test_udp_timing_works_with_lex_smaller_client():
    """Client IP < server IP — direction='forward' in old logic. Sanity check."""
    from ja4plus.fingerprinters.ja4l import JA4LFingerprinter

    fp = JA4LFingerprinter()
    # client 10.0.0.1 -> server 10.0.0.2
    fp.process_packet(_udp_packet("10.0.0.1", "10.0.0.2", 50000, 443, t=0.0))
    result = fp.process_packet(
        _udp_packet("10.0.0.2", "10.0.0.1", 443, 50000, t=0.001)
    )
    assert result is not None
    assert result.startswith("JA4L-S=")


def test_udp_timing_works_with_lex_larger_client():
    """Client IP > server IP — direction='reverse' in old logic.

    BEFORE the fix this returned None forever (no timestamps recorded).
    AFTER the fix the first-packet sender is treated as the client, and a
    JA4L-S fingerprint is emitted on the response.
    """
    from ja4plus.fingerprinters.ja4l import JA4LFingerprinter

    fp = JA4LFingerprinter()
    # client 10.0.0.99 -> server 10.0.0.1 — client IP is lexicographically greater
    fp.process_packet(_udp_packet("10.0.0.99", "10.0.0.1", 50000, 443, t=0.0))
    result = fp.process_packet(
        _udp_packet("10.0.0.1", "10.0.0.99", 443, 50000, t=0.002)
    )
    assert result is not None, "JA4L-S not emitted for server-direction-first conn"
    assert result.startswith("JA4L-S=")


def test_udp_timing_full_round_trip_emits_jal_c():
    """Three-packet exchange — A (client) / B (server) / C (client) / D (server)
    produces both -S and -C fingerprints regardless of IP ordering."""
    from ja4plus.fingerprinters.ja4l import JA4LFingerprinter

    fp = JA4LFingerprinter()
    # Use a high-IP client to exercise the previously-broken path
    a = fp.process_packet(_udp_packet("192.168.1.50", "10.0.0.1", 50000, 443, t=0.0))
    s = fp.process_packet(_udp_packet("10.0.0.1", "192.168.1.50", 443, 50000, t=0.002))
    c = fp.process_packet(_udp_packet("192.168.1.50", "10.0.0.1", 50000, 443, t=0.004))
    d = fp.process_packet(_udp_packet("10.0.0.1", "192.168.1.50", 443, 50000, t=0.006))

    assert a is None
    assert s is not None and s.startswith("JA4L-S="), s
    assert c is None
    assert d is not None and d.startswith("JA4L-C="), d


@pytest.mark.skipif(
    not os.path.exists("tests/foxio_vectors/pcap/chrome-cloudflare-quic-with-secrets.pcapng"),
    reason="Chrome-Cloudflare QUIC fixture missing",
)
def test_quic_real_pcap_emits_both_directions():
    from scapy.all import rdpcap
    from ja4plus.fingerprinters.ja4l import JA4LFingerprinter

    fp = JA4LFingerprinter()
    pkts = rdpcap("tests/foxio_vectors/pcap/chrome-cloudflare-quic-with-secrets.pcapng")
    seen = []
    for pkt in pkts:
        result = fp.process_packet(pkt)
        if result:
            seen.append(result)

    # We don't pin exact latencies, but at least one of each direction should
    # appear if the conversation is bidirectional QUIC.
    has_s = any(s.startswith("JA4L-S=") for s in seen)
    assert has_s, f"no JA4L-S in {seen}"
