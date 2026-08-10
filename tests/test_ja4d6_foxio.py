"""Compare the JA4D6 output of `ja4plus` against the FoxIO reference values.

The FoxIO Python implementation emits no JA4D6, so `tests/foxio_vectors/dhcpv6.pcap.json`
holds an empty array. The reference values come from the FoxIO Wireshark dissector.
`docs/implementation_notes.md` records why this method reads that file.
"""

import json
from pathlib import Path

from scapy.all import IP, IPv6, UDP, Raw, rdpcap

from ja4plus.fingerprinters.ja4d6 import (
    DHCPV6_MESSAGE_TYPES,
    JA4D6Fingerprinter,
    generate_ja4d6,
)

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"
PCAP_PATH = VECTORS_DIR / "dhcpv6.pcap"
EXPECTED_PATH = VECTORS_DIR / "wireshark_expected" / "dhcpv6.pcap.json"


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


def test_ja4d6_matches_foxio_dhcpv6_pcap():
    expected = _load_expected()

    actual = {}
    for number, packet in enumerate(rdpcap(str(PCAP_PATH)), start=1):
        fingerprint = generate_ja4d6(packet)
        if fingerprint:
            actual[number] = fingerprint

    # A method that emits more fingerprints than the reference is a defect, and so is
    # one that emits fewer. Only the whole map compares both directions.
    assert actual == expected


def test_message_type_table_completeness():
    # Every abbreviation holds five characters, because the first section of the
    # fingerprint has a fixed width.
    for code, abbrev in DHCPV6_MESSAGE_TYPES.items():
        assert len(abbrev) == 5, f"DHCPv6 type {code} abbrev {abbrev!r} not 5 chars"

    for code in range(1, 38):
        assert code in DHCPV6_MESSAGE_TYPES, f"missing DHCPv6 type {code}"


def test_unknown_message_type_uses_numeric_format():
    # The message type is 200, which the table does not hold. The transaction
    # identifier is three bytes, and the message carries no option.
    payload = bytes([200, 0, 0, 0])
    packet = IPv6() / UDP(sport=546, dport=547) / Raw(load=payload)
    fingerprint = generate_ja4d6(packet)
    assert fingerprint is not None
    assert fingerprint.startswith("00200")


def test_non_dhcpv6_port_returns_none():
    packet = IP() / UDP(sport=1234, dport=5678) / Raw(load=bytes([1, 0, 0, 0]))
    assert generate_ja4d6(packet) is None


def test_fingerprinter_class_collects_results():
    expected = _load_expected()

    fingerprinter = JA4D6Fingerprinter()
    for packet in rdpcap(str(PCAP_PATH)):
        fingerprinter.process_packet(packet)

    assert len(fingerprinter.get_fingerprints()) == len(expected)
    fingerprinter.reset()
    assert len(fingerprinter.get_fingerprints()) == 0
