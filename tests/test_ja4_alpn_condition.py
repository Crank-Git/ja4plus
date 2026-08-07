"""The condition that makes the JA4 ALPN value read `99`.

#127 settled the value. #141 settles the condition, and it settles it by measurement.
`tests/build_alpn_condition_capture.py` builds `alpn-condition.pcap`, and both FoxIO
implementations at the commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` ran against
it. `docs/implementation_notes.md` holds the commands and the full table.

The measurement settles one rule: a byte that is ASCII reaches the value without a
change, and the alphanumeric test the FoxIO prose states is not the condition. Both
FoxIO implementations agree on every input whose first byte and last byte are ASCII,
and they agree on an input whose two bytes are outside ASCII.

The measurement settles no rule for a value that holds a byte outside ASCII in any
position other than the first. The FoxIO Python implementation and the FoxIO Rust
implementation disagree there, so `ja4plus` keeps `99` and #141 asks the user.
"""

import json
from pathlib import Path

import pytest

from ja4plus.fingerprinters.ja4 import compute_alpn_value

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"
CAPTURE_PATH = VECTORS_DIR / "alpn-condition.pcap"
EXPECTED_PATH = VECTORS_DIR / "alpn-condition.pcap.json"


@pytest.mark.parametrize(
    "alpn_bytes,expected",
    [
        # Both FoxIO implementations write `h ` and ` h`. `alpn-condition.pcap` holds
        # both inputs, and the FoxIO prose writes `60` and `28` for them.
        (b"h\x20", "h "),
        (b"\x20h", " h"),
        # Both FoxIO implementations write `h2`, because only the first byte and the
        # last byte reach the value.
        (b"h\x20\x20\x32", "h2"),
        # Both FoxIO implementations write `99`, and `tls-non-ascii-alpn.pcapng` holds
        # this input.
        (b"\xba\xad", "99"),
    ],
)
def test_an_ascii_byte_reaches_the_alpn_value_without_a_change(alpn_bytes, expected):
    assert compute_alpn_value(alpn_bytes) == expected


@pytest.mark.parametrize(
    "alpn_bytes",
    [
        b"h\xab",  # FoxIO Python writes `h�`. FoxIO Rust writes `h9`.
        b"\xabh",  # FoxIO Python writes `99`. FoxIO Rust writes `9h`.
        b"\x30\x31\xab\xcd",  # FoxIO Python writes `0�`. FoxIO Rust writes `09`.
    ],
)
def test_a_byte_outside_ascii_keeps_the_value_99_while_the_references_disagree(alpn_bytes):
    """The two FoxIO implementations disagree, so `ja4plus` changes nothing here."""
    assert compute_alpn_value(alpn_bytes) == "99"


def test_the_capture_produces_the_two_measured_reference_values():
    """`alpn-condition.pcap` produces the JA4 values both FoxIO implementations write."""
    from scapy.all import rdpcap

    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    with open(EXPECTED_PATH) as handle:
        entries = json.load(handle)
    expected = [entry["JA4.1"] for entry in entries]

    fingerprinter = JA4Fingerprinter()
    produced = []
    for packet in rdpcap(str(CAPTURE_PATH)):
        fingerprint = fingerprinter.process_packet(packet)
        if fingerprint:
            produced.append(fingerprint)

    assert produced == expected


def test_the_capture_carries_the_two_separating_alpn_values():
    """The two streams of `alpn-condition.pcap` hold `h\\x20` and `\\x20h`."""
    from scapy.all import Raw, rdpcap

    from ja4plus.utils.tls_utils import parse_tls_handshake

    first_values = []
    for packet in rdpcap(str(CAPTURE_PATH)):
        if not packet.haslayer(Raw):
            continue
        info = parse_tls_handshake(bytes(packet[Raw].load))
        if info and info.get("type") == "client_hello":
            first_values.append(info["alpn_raw"][0])

    assert first_values == [b"h\x20", b"\x20h"]
