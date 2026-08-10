"""Tests for ja4plus.processor.Processor.

Mirrors the surface area of ja4plus-go's ja4plus.Processor:
process_packet, reset, cleanup_connection, get_shard_key.
"""


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
    from ja4plus import FingerprintResult, Processor
    from scapy.all import IP, UDP, Raw

    # Build a minimal DHCP DISCOVER packet (53=msgtype + end)
    bootp = bytearray(236)
    bootp[0] = 1
    payload = bytes(bootp) + b"\x63\x82\x53\x63" + bytes([53, 1, 1, 255])
    pkt = IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(load=payload)

    p = Processor()
    results = p.process_packet(pkt)
    types = [r.type for r in results]
    assert "ja4d" in types
    # #45 returns a `FingerprintResult` in place of a dict, so the case reads the
    # attribute. Item access still works, and it emits a `DeprecationWarning`.
    for r in results:
        assert isinstance(r, FingerprintResult)
        assert r.fingerprint
        assert r.type
        assert r.src_ip == "0.0.0.0"
        assert r.dst_ip == "255.255.255.255"
        assert r.src_port == 68
        assert r.dst_port == 67


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


def test_processor_close_open_windows_emits_the_held_ja4ssh_window():
    """The processor closes the open window of every fingerprinter when the packet
    source ends. Only JA4SSH holds a window, and #214 decided that it emits it."""
    import struct

    from ja4plus import Processor
    from scapy.all import IP, TCP, Raw

    payload = struct.pack(">I", 32) + bytes([4, 94]) + b"A" * 30

    p = Processor()
    for index in range(11):
        if index % 2 == 0:
            packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=22, flags="PA")
        else:
            packet = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=22, dport=50000, flags="PA")
        p.process_packet(packet / Raw(load=payload))

    results = p.close_open_windows()
    assert [r["type"] for r in results] == ["ja4ssh"]
    assert results[0]["fingerprint"] == "c36s36_c6s5_c0s0"
    assert results[0]["connection"] == "10.0.0.1:50000-10.0.0.2:22"


def test_processor_close_open_windows_declines_a_window_with_no_ssh_packet():
    """A port scan builds a connection that holds no SSH packet. #97 declines the value
    `c0s0` that such a window would carry, and the processor must not report it."""
    from ja4plus import Processor
    from scapy.all import IP, TCP

    p = Processor()
    for _ in range(20):
        p.process_packet(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=22, flags="A"))

    assert p.ja4ssh.connections, "the state table holds the connection the scan built"
    assert p.close_open_windows() == []


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
