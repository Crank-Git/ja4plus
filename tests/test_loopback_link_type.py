"""Tests that a loopback capture dissects as IPv6 on every host.

A capture whose link type is `DLT_NULL` starts each frame with a four-byte address
family value. libpcap writes the value of the host that captured the frame. The value
of `AF_INET6` is 24 on NetBSD and OpenBSD, 28 on FreeBSD, and 30 on Darwin.

scapy binds one of those values, `socket.AF_INET6`. That value is 30 on Darwin and 10
on Linux. No capture holds 10, so a loopback capture that carries IPv6 dissects on
Darwin and returns raw bytes on Linux. These tests hold the reading host out of the
result.
"""

import json
import pathlib

import pytest
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Loopback
from scapy.packet import Raw

# The `ja4plus` package binds the loopback address family values when a caller imports
# it. The import states that a user of the library needs no further call.
import ja4plus  # noqa: F401

VECTOR_DIRECTORY = pathlib.Path(__file__).parent / "foxio_vectors"

# The address family value each BSD family writes into a `DLT_NULL` frame. scapy names
# all three as IPv6 in `LOOPBACK_TYPES`.
BSD_AF_INET6_VALUES = (0x18, 0x1C, 0x1E)


@pytest.mark.parametrize("family_value", BSD_AF_INET6_VALUES)
def test_dissects_every_bsd_address_family_value_as_ipv6(family_value):
    """The IPv6 layer of a loopback frame reaches a reader on every host."""
    from scapy.layers.inet import TCP

    frame = bytes(
        Loopback(type=family_value) / IPv6(src="::1", dst="::2") / TCP(sport=1, dport=443)
    )

    packet = Loopback(frame)

    assert IPv6 in packet, "a loopback frame with family {} holds no IPv6 layer".format(
        hex(family_value)
    )
    assert packet[IPv6].dst == "::2"
    assert Raw not in packet


def test_the_ipv6_vector_produces_the_reference_ja4_fingerprint():
    """The `ipv6.pcapng` vector produces the JA4 value the reference names."""
    from scapy.all import rdpcap

    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    capture = VECTOR_DIRECTORY / "ipv6.pcapng"
    expected = json.loads((VECTOR_DIRECTORY / "ipv6.pcapng.json").read_text())[0]["JA4.1"]

    fingerprinter = JA4Fingerprinter()
    for packet in rdpcap(str(capture)):
        fingerprinter.process_packet(packet)

    produced = [entry["fingerprint"] for entry in fingerprinter.get_fingerprints()]

    assert produced == [expected]
