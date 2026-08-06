"""FoxIO reference vector validation for JA4D (PR #267 + #270).

Compares ja4plus output against the canonical Wireshark dissector
expected values stored in tests/foxio_vectors/ja4_expected/.
"""

import json
import os

import pytest

PCAP_PATH = "tests/foxio_vectors/pcap/dhcp.pcapng"
EXPECTED_PATH = "tests/foxio_vectors/ja4_expected/dhcp.pcapng.ja4d.json"


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


def test_ja4d_matches_foxio_dhcp_pcapng():
    from scapy.all import rdpcap
    from ja4plus.fingerprinters.ja4d import generate_ja4d

    expected = _load_expected()
    pkts = rdpcap(PCAP_PATH)

    actual = {}
    for i, pkt in enumerate(pkts, start=1):
        fp = generate_ja4d(pkt)
        if fp:
            actual[i] = fp

    for frame, want in expected.items():
        assert frame in actual, f"missing JA4D for frame {frame}"
        assert actual[frame] == want, f"frame {frame}: got {actual[frame]!r}, want {want!r}"
