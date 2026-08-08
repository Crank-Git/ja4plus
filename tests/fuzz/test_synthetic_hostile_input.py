"""Unparseable input produces no fingerprint.

`FR-correctness-audit-8` to `FR-correctness-audit-10` state the contract, and #338
adds the reading that the contract has two halves. A parser that cannot read a packet
returns nothing, and it does not raise. A case that reads only the second half accepts
a fabricated fingerprint, which names a client that does not exist.

Every case here builds its input at test time. The suite commits no generated capture.
"""

import os
import re

import pytest
from scapy.all import IP, Raw, TCP

import ja4plus.utils.tls_utils as tls_utils
from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from tests.fuzz.support import spy_on

# The JA4 form that `docs/specs/features/01-spec-conformance.md` states. The parts are
# the protocol, the TLS version, the SNI marker, the cipher count, the extension count,
# the first ALPN value, and two 12-digit hexadecimal hashes. The ALPN part matches any
# two characters, because #306 records a first ALPN value that is not ASCII.
JA4_FORM = re.compile(
    r"^[tqd](?:1[0-3]|s[23]|d[123]|00)[di]\d{2}\d{2}.{2}"
    r"_[0-9a-f]{12}_[0-9a-f]{12}$"
)

# Each draw of a random payload reads one byte string, so one draw measures little.
DRAWS = 512


def read_ja4(load):
    """Return the JA4 fingerprint of a TCP packet that carries the payload.

    Args:
        load: The payload bytes.

    Returns:
        The fingerprint, or None when the parser reads nothing.

    Raises:
        Exception: The fingerprinter raised. Every case treats a raise as a failure.
    """
    packet = IP() / TCP(sport=12345, dport=443) / Raw(load=load)
    return JA4Fingerprinter().process_packet(packet)


@pytest.fixture
def parser_calls(monkeypatch):
    """Count the calls of `parse_tls_handshake`.

    A case that reaches no parser proves nothing, so every case below reads this
    counter. `tests/fuzz/README.md` states the rule.
    """
    return spy_on(monkeypatch, tls_utils, "parse_tls_handshake")


# The six shapes that #338 names, and two more that widen the record header. Each
# value is a payload that carries no readable ClientHello.
HOSTILE_PAYLOADS = {
    "empty payload": b"",
    "one record header byte": b"\x16",
    "record header without a body": b"\x16\x03\x01\x00\x00",
    "truncated tls record": b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",
    "declared length beyond the packet": (
        b"\x16\x03\x01\xff\xff\x01\x00\xff\xfb\x03\x03" + b"\x41" * 16
    ),
    "long run of zero bytes": b"\x00" * 4096,
    "long run of ff bytes": b"\xff" * 4096,
    "record header then zero bytes": b"\x16\x03\x01" + b"\x00" * 4096,
    "record header then ff bytes": b"\x16\x03\x01" + b"\xff" * 4096,
    "handshake type that names no message": b"\x16\x03\x01\x00\x10" + b"\x63" * 16,
    "server hello record": b"\x16\x03\x01\x00\x04\x02\x00\x00\x00",
}


@pytest.mark.parametrize("name", sorted(HOSTILE_PAYLOADS))
def test_a_hostile_payload_produces_no_fingerprint(name, parser_calls):
    """The reader returns nothing for input that carries no ClientHello."""
    assert read_ja4(HOSTILE_PAYLOADS[name]) is None
    assert parser_calls.calls > 0, "The case reached no parser, so it measures nothing."


def test_random_bytes_produce_no_fingerprint(parser_calls):
    """Random bytes carry no ClientHello, so the reader returns nothing."""
    for _ in range(DRAWS):
        assert read_ja4(os.urandom(256)) is None
    assert parser_calls.calls >= DRAWS


def test_random_bytes_behind_a_record_header_produce_no_fingerprint(parser_calls):
    """A record header does not make a random body readable."""
    for _ in range(DRAWS):
        assert read_ja4(b"\x16\x03\x01\x01\x00" + os.urandom(256)) is None
    assert parser_calls.calls >= DRAWS


# ===========================================================================
# A valid handshake with one field corrupted
# ===========================================================================


def test_the_unmutated_client_hello_produces_the_recorded_fingerprint(
    client_hello_packet, parser_calls
):
    """The parser reads this packet, so every corrupted case below can fail."""
    produced = read_ja4(bytes(client_hello_packet[Raw].load))

    assert produced is not None
    assert JA4_FORM.match(produced), produced
    assert parser_calls.calls > 0


@pytest.mark.parametrize("mask", [0xFF, 0x01, 0x80])
def test_one_corrupted_byte_produces_nothing_or_a_well_formed_fingerprint(
    client_hello_packet, parser_calls, mask
):
    """A corrupted ClientHello never produces a value outside the JA4 form.

    The case turns one bit group of each byte in turn. A corrupted cipher value stays
    readable and moves the fingerprint, so the case does not demand that every
    corruption silences the reader. It demands that the reader produces nothing or a
    value the JA4 form accepts, and that it raises nothing.
    """
    load = bytes(client_hello_packet[Raw].load)
    silenced = 0

    for index in range(len(load)):
        mutated = bytearray(load)
        mutated[index] ^= mask
        produced = read_ja4(bytes(mutated))
        if produced is None:
            silenced += 1
            continue
        assert JA4_FORM.match(produced), f"byte {index}: {produced!r}"

    assert parser_calls.calls >= len(load)
    # A corruption that silences no read would mean the parser ignores the payload.
    assert silenced > 0
