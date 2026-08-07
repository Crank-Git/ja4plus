"""Fixtures for the malformed-input suite."""

from pathlib import Path

import pytest
from scapy.all import Raw

from ja4plus.utils.tls_utils import parse_tls_handshake
from tests.fuzz.support import read_capture

# `badcurveball.pcap` carries a TLS handshake with a malformed curve list. Its
# ClientHello is the packet the length-field cases mutate.
CLIENT_HELLO_CAPTURE = "badcurveball.pcap"


@pytest.fixture(scope="session")
def vector_dir():
    """Return the directory that holds the committed FoxIO captures."""
    return Path(__file__).resolve().parent.parent / "foxio_vectors"


@pytest.fixture(scope="session")
def client_hello_packet(vector_dir):
    """Return the first packet of `badcurveball.pcap` that carries a ClientHello.

    Raises:
        AssertionError: The capture carries no ClientHello.
    """
    for packet in read_capture(vector_dir, CLIENT_HELLO_CAPTURE):
        if Raw not in packet:
            continue
        info = parse_tls_handshake(bytes(packet[Raw].load))
        if info and info.get("type") == "client_hello":
            return packet
    raise AssertionError(f"{CLIENT_HELLO_CAPTURE} carries no ClientHello.")
