"""Compare the JA4D output of `ja4plus` against the FoxIO reference values.

The FoxIO Python implementation emits no JA4D, so `tests/foxio_vectors/dhcp.pcapng.json`
holds an empty array. The reference values come from the FoxIO Wireshark dissector.
`docs/implementation_notes.md` records why this method reads that file.
"""

import json
from pathlib import Path

from scapy.all import rdpcap

from ja4plus.fingerprinters.ja4d import generate_ja4d

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"
PCAP_PATH = VECTORS_DIR / "dhcp.pcapng"
EXPECTED_PATH = VECTORS_DIR / "wireshark_expected" / "dhcp.pcapng.json"


def _load_expected():
    """Return the reference fingerprint of every frame the expected-output file names.

    Returns:
        A map of frame number to the `ja4.ja4d` value.

    Raises:
        FileNotFoundError: The expected-output file is absent.
        AssertionError: The expected-output file names no frame.
    """
    with open(EXPECTED_PATH) as handle:
        entries = json.load(handle)
    expected = {}
    for entry in entries:
        layers = entry["_source"]["layers"]
        expected[int(layers["frame.number"][0])] = layers["ja4.ja4d"][0]
    # An empty map compares no value, and every assertion below passes on it. Without
    # this check, the file would report a pass on nothing.
    assert expected, "{} names no frame".format(EXPECTED_PATH)
    return expected


def test_ja4d_matches_foxio_dhcp_pcapng():
    expected = _load_expected()

    actual = {}
    for number, packet in enumerate(rdpcap(str(PCAP_PATH)), start=1):
        fingerprint = generate_ja4d(packet)
        if fingerprint:
            actual[number] = fingerprint

    # A method that emits more fingerprints than the reference is a defect, and so is
    # one that emits fewer. Only the whole map compares both directions.
    assert actual == expected
