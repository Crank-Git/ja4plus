"""FoxIO reference vector validation for JA4D6 (DHCPv6).

Compares ja4plus output against the canonical Wireshark dissector
expected values stored in tests/foxio_vectors/ja4_expected/.
"""

import json
import os

import pytest

PCAP_PATH = "tests/foxio_vectors/pcap/dhcpv6.pcap"
EXPECTED_PATH = "tests/foxio_vectors/ja4_expected/dhcpv6.pcap.ja4d.json"


pytestmark = pytest.mark.skipif(
    not (os.path.exists(PCAP_PATH) and os.path.exists(EXPECTED_PATH)),
    reason="FoxIO test fixtures not available (download to tests/foxio_vectors/)",
)


def _load_expected():
    with open(EXPECTED_PATH) as f:
        data = json.load(f)
    out = {}
    for entry in data:
        layers = entry["_source"]["layers"]
        frame = int(layers["frame.number"][0])
        out[frame] = layers["ja4.ja4d"][0]
    return out


def test_ja4d6_matches_foxio_dhcpv6_pcap():
    from scapy.all import rdpcap
    from ja4plus.fingerprinters.ja4d6 import generate_ja4d6

    expected = _load_expected()
    pkts = rdpcap(PCAP_PATH)

    actual = {}
    for i, pkt in enumerate(pkts, start=1):
        fp = generate_ja4d6(pkt)
        if fp:
            actual[i] = fp

    for frame, want in expected.items():
        assert frame in actual, f"missing JA4D6 for frame {frame}"
        assert actual[frame] == want, f"frame {frame}: got {actual[frame]!r}, want {want!r}"


def test_message_type_table_completeness():
    from ja4plus.fingerprinters.ja4d6 import DHCPV6_MESSAGE_TYPES

    # Every entry must be exactly 5 chars
    for code, abbrev in DHCPV6_MESSAGE_TYPES.items():
        assert len(abbrev) == 5, f"DHCPv6 type {code} abbrev {abbrev!r} not 5 chars"

    # All 37 types must be present (1..37 from the spec)
    for code in range(1, 38):
        assert code in DHCPV6_MESSAGE_TYPES, f"missing DHCPv6 type {code}"


def test_unknown_message_type_uses_numeric_format():
    from scapy.all import IP, IPv6, UDP, Raw
    from ja4plus.fingerprinters.ja4d6 import generate_ja4d6

    # msgtype = 200 (unknown), 3-byte txid, no options
    payload = bytes([200, 0, 0, 0])
    pkt = IPv6() / UDP(sport=546, dport=547) / Raw(load=payload)
    fp = generate_ja4d6(pkt)
    assert fp is not None
    assert fp.startswith("00200")  # %05u of 200


def test_non_dhcpv6_port_returns_none():
    from scapy.all import IP, UDP, Raw
    from ja4plus.fingerprinters.ja4d6 import generate_ja4d6

    pkt = IP() / UDP(sport=1234, dport=5678) / Raw(load=bytes([1, 0, 0, 0]))
    assert generate_ja4d6(pkt) is None


def test_fingerprinter_class_collects_results():
    from scapy.all import rdpcap
    from ja4plus.fingerprinters.ja4d6 import JA4D6Fingerprinter

    fp = JA4D6Fingerprinter()
    pkts = rdpcap(PCAP_PATH)
    for pkt in pkts:
        fp.process_packet(pkt)

    assert len(fp.get_fingerprints()) == 6
    fp.reset()
    assert len(fp.get_fingerprints()) == 0
