"""The ALPN characters of JA4 part a and of JA4S part a, under the ruling of #789.

**The maintainer ruled on 2026-10-01 UTC, and the ruling binds both repositories.**
`Crank-Git/ja4plus-go#801` holds the Go half, and the Go library ships it in `v1.3.0`.

- Q1: each end byte of `0x80` or higher writes `9`, one per end. `68 ff` writes `h9`, and
  `ff 68` writes `9h`.
- Q2: a one-byte value that is printable ASCII writes that byte twice. `2d` writes `--`.
- A control byte below `0x20`, or the byte `0x7F`, at either end still writes `99`. The
  second comment of #789 states that rule.

The ruling follows `python/ja4.py:156-157` and `rust/ja4/src/tls.rs:635-647` at the FoxIO
commit `16b96d95c220762cf658f67d678cda2aac95c81e`. It reverses #127, #141 and #162 for
the inputs that the two rules name. `tls-non-ascii-alpn.pcapng` holds the first ALPN value
`ba ad`, and that value still writes `99`, because both ends are `0x80` or higher.

Each case below builds the packet that separates the old rule from the new rule, once for
JA4 and once for JA4S. The Go table of `ja4_alpn_ruling_test.go` holds the same inputs at
`v1.3.0`, so the two libraries write one value for each input. The cases name the port issue
`Crank-Git/ja4plus-go#801` for the reversal path of the Go half.
"""

import pytest
from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter, compute_alpn_value
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
from tests.build_alpn_condition_capture import _alpn_extension, hello_packet

# One row for each input of the ruling. Each row holds the first ALPN value and the two
# characters that JA4 and JA4S write for it.
RULING_CASES = (
    # A one-byte alphanumeric value writes the byte twice, as before the ruling.
    pytest.param(b"\x68", "hh", id="68-alphanumeric-one-byte"),
    # Q2: a one-byte printable value that is not alphanumeric writes the byte twice.
    pytest.param(b"\x2d", "--", id="2d-printable-one-byte"),
    pytest.param(b"\x20", "  ", id="20-space-one-byte"),
    # A one-byte control value writes `99`, as before the ruling.
    pytest.param(b"\x01", "99", id="01-control-one-byte"),
    # A one-byte value of `0x80` or higher writes `9` at each end.
    pytest.param(b"\xff", "99", id="ff-high-one-byte"),
    # Q1: each end byte of `0x80` or higher writes `9`, one per end.
    pytest.param(b"\x68\xff", "h9", id="68ff-high-last"),
    pytest.param(b"\xff\x68", "9h", id="ff68-high-first"),
    # `tls-non-ascii-alpn.pcapng` holds this value, and it still writes `99`.
    pytest.param(b"\xba\xad", "99", id="baad-the-foxio-vector"),
    # An empty first ALPN value writes `00`, as before the ruling.
    pytest.param(b"", "00", id="empty"),
    # A two-byte alphanumeric value writes both bytes, as before the ruling.
    pytest.param(b"\x68\x32", "h2", id="6832-alphanumeric"),
    # A control byte at one end writes `99`, as `Crank-Git/ja4plus#162` states.
    pytest.param(b"\x68\x1f", "99", id="681f-control-last"),
    pytest.param(b"\x01\x68", "99", id="0168-control-first"),
    pytest.param(b"\x68\x7f", "99", id="687f-delete-last"),
    # A control byte at one end and a high byte at the other end writes `99`.
    pytest.param(b"\xff\x01", "99", id="ff01-high-and-control"),
)

CLIENT_PORT = 44501
SERVER_IP = "10.1.0.2"
CLIENT_IP = "10.1.0.1"


def _server_hello(alpn):
    """Return one TLS record that carries a ServerHello with one selected ALPN value.

    Args:
        alpn: The bytes of the ALPN value the server selects.

    Returns:
        The bytes of one TLS handshake record.
    """
    extensions = _alpn_extension((alpn,))
    body = (
        b"\x03\x03"  # The server version.
        + b"\x00" * 32  # The random field. A fingerprint reads none of it.
        + b"\x00"  # The session ID is empty.
        + b"\xc0\x2f"  # The selected cipher suite.
        + b"\x00"  # The null compression method.
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def _ja4_alpn(alpn):
    """Return the two ALPN characters of the JA4 value of one ClientHello packet."""
    fingerprint = JA4Fingerprinter().process_packet(hello_packet(alpn, CLIENT_PORT, 1000.0))
    assert fingerprint is not None
    # Part a holds ten characters, and the ALPN characters are the last two.
    return fingerprint.split("_")[0][8:10]


def _ja4s_alpn(alpn):
    """Return the two ALPN characters of the JA4S value of one ServerHello packet."""
    packet = (
        IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(sport=443, dport=CLIENT_PORT, flags="PA", seq=1, ack=1)
        / Raw(load=_server_hello(alpn))
    )
    fingerprint = JA4SFingerprinter().process_packet(packet)
    assert fingerprint is not None
    # Part a holds seven characters, and the ALPN characters are the last two.
    return fingerprint.split("_")[0][5:7]


@pytest.mark.parametrize("alpn,expected", RULING_CASES)
def test_compute_alpn_value_writes_the_ruled_characters(alpn, expected):
    assert compute_alpn_value(alpn) == expected


@pytest.mark.parametrize("alpn,expected", RULING_CASES)
def test_ja4_writes_the_ruled_alpn_characters(alpn, expected):
    assert _ja4_alpn(alpn) == expected


@pytest.mark.parametrize("alpn,expected", RULING_CASES)
def test_ja4s_writes_the_ruled_alpn_characters(alpn, expected):
    assert _ja4s_alpn(alpn) == expected
