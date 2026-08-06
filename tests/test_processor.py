"""Tests for ja4plus.processor.Processor.

Mirrors the surface area of ja4plus-go's ja4plus.Processor:
process_packet, reset, cleanup_connection, get_shard_key.
"""

import os

import pytest


def test_processor_constructs_with_all_ten_fingerprinters():
    from ja4plus import Processor

    p = Processor()
    expected = {
        "ja4",
        "ja4s",
        "ja4h",
        "ja4t",
        "ja4ts",
        "ja4l",
        "ja4x",
        "ja4ssh",
        "ja4d",
        "ja4d6",
    }
    assert set(p.fingerprinters.keys()) == expected


def test_processor_attribute_access_to_fingerprinters():
    """processor.ja4d returns the underlying JA4DFingerprinter."""
    from ja4plus import Processor
    from ja4plus.fingerprinters.ja4d import JA4DFingerprinter

    p = Processor()
    assert isinstance(p.ja4d, JA4DFingerprinter)


def test_processor_process_packet_runs_all_fingerprinters():
    """For a DHCP packet we should get a JA4D fingerprint and nothing else."""
    from ja4plus import Processor
    from scapy.all import IP, UDP, Raw

    # Build a minimal DHCP DISCOVER packet (53=msgtype + end)
    bootp = bytearray(236)
    bootp[0] = 1
    payload = bytes(bootp) + b"\x63\x82\x53\x63" + bytes([53, 1, 1, 255])
    pkt = IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(load=payload)

    p = Processor()
    results = p.process_packet(pkt)
    types = [r["type"] for r in results]
    assert "ja4d" in types
    # Each result should expose canonical structure
    for r in results:
        assert "fingerprint" in r
        assert "type" in r
        assert "src_ip" in r
        assert "dst_ip" in r
        assert "src_port" in r
        assert "dst_port" in r
        assert "raw" in r
        assert "raw_original_order" in r


def test_processor_reset_clears_all_state():
    from ja4plus import Processor
    from scapy.all import IP, UDP, Raw

    bootp = bytearray(236)
    bootp[0] = 1
    payload = bytes(bootp) + b"\x63\x82\x53\x63" + bytes([53, 1, 1, 255])
    pkt = IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(load=payload)

    p = Processor()
    p.process_packet(pkt)
    assert len(p.ja4d.get_fingerprints()) >= 1

    p.reset()
    assert p.ja4d.get_fingerprints() == []
    assert p.ja4.last_raw is None


def test_processor_cleanup_connection_propagates():
    from ja4plus import Processor

    p = Processor()
    # Manually plant some state in one of the stateful fingerprinters
    p.ja4ssh.connections["1.2.3.4:22-5.6.7.8:55000"] = {
        "client_ip": "5.6.7.8",
        "server_ip": "1.2.3.4",
        "ssh_packets": {"client": [], "server": []},
        "bare_acks": {"client": 0, "server": 0},
    }
    # Cleanup should remove it (key is checked in both directions)
    p.cleanup_connection("5.6.7.8", 55000, "1.2.3.4", 22, "tcp")
    assert "1.2.3.4:22-5.6.7.8:55000" not in p.ja4ssh.connections


def test_processor_get_shard_key_is_direction_independent():
    """Both directions of the same connection map to the same shard key."""
    from ja4plus import Processor
    from scapy.all import IP, TCP

    p = Processor()
    pkt_a = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=443)
    pkt_b = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=443, dport=50000)
    assert p.get_shard_key(pkt_a) == p.get_shard_key(pkt_b)
    assert p.get_shard_key(pkt_a).startswith("tcp:")


def test_processor_get_shard_key_handles_udp():
    from ja4plus import Processor
    from scapy.all import IP, UDP

    p = Processor()
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=50000, dport=443)
    assert p.get_shard_key(pkt).startswith("udp:")


def test_processor_get_shard_key_returns_empty_for_non_ip():
    from ja4plus import Processor
    from scapy.all import Ether

    p = Processor()
    pkt = Ether()
    assert p.get_shard_key(pkt) == ""
