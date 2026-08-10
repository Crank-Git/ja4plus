"""The JA4 ALPN value.

#127 settled one input. `tls-non-ascii-alpn.pcapng` holds the first ALPN value
`0xba 0xad`, and this project writes `99` for it, as the FoxIO Python implementation
and the FoxIO Rust implementation do.

#127 settled no other input. The rules disagree, and no FoxIO vector separates them.
#141 built `tests/foxio_vectors/alpn-condition.pcap` and ran both FoxIO
implementations at commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` against it. The
table below holds that measurement, and `docs/implementation_notes.md` holds the two
commands.

| Input | The prose | `python/ja4.py` | `rust/tls.rs` | `ja4plus` |
|---|---|---|---|---|
| `b"\\xab"` | `ab` | `99` | `90` | `99` |
| `b"\\x20"` | `20` | `' '` | `' 0'` | `99` |
| `b"\\xab\\xcd"` | `ad` | `99` | `99` | `99` |
| `b"\\x20\\x61"` | `21` | `' a'` | `' a'` | `' a'` |
| `b"\\x30\\xab"` | `3b` | `0?` | `09` | `99` |
| `b"\\x61\\x20"` | `60` | `'a '` | `'a '` | `'a '` |
| `b"\\x30\\x31\\xab\\xcd"` | `3d` | `0?` | `09` | `99` |
| `b"\\x30\\xab\\xcd\\x31"` | `01` | `01` | `01` | `01` |
| `b"\\xba\\xad"` | `bd` | `99` | `99` | `99` |

No single rule produces the prose value for `b"\\xab\\xcd"` and `99` for
`b"\\xba\\xad"`. The two inputs hold two bytes each, and both bytes of each fall
outside the alphanumeric ranges, so a function of the bytes cannot separate them. The
FoxIO prose and the FoxIO vector therefore contradict each other.

#141 settled the ASCII part of the condition, so `ja4plus` now passes an ASCII byte
through. A case the two FoxIO implementations dispute keeps the value `ja4plus` wrote
before #141. A case that only the FoxIO prose produces carries a strict `xfail`.
"""

import json
from pathlib import Path

import pytest

from ja4plus.fingerprinters.ja4 import compute_alpn_value

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"
CAPTURE_PATH = VECTORS_DIR / "tls-non-ascii-alpn.pcapng"
EXPECTED_PATH = VECTORS_DIR / "tls-non-ascii-alpn.pcapng.json"


def _disputed(alpn_bytes, prose_value):
    """Return a parameter that holds the FoxIO prose value and expects a failure.

    Args:
        alpn_bytes: The bytes of the first ALPN value.
        prose_value: The value the FoxIO PR #277 examples publish.

    Returns:
        A `pytest.param` that carries a strict `xfail`.
    """
    return pytest.param(
        alpn_bytes,
        prose_value,
        marks=pytest.mark.xfail(
            strict=True,
            reason=(
                "The FoxIO prose publishes this value, and the #141 measurement shows "
                "that no FoxIO implementation produces it."
            ),
        ),
    )


@pytest.mark.parametrize(
    "alpn_bytes,expected",
    [
        # The FoxIO PR #277 examples. The four rules disagree on all seven, the vector
        # set reaches none of them, and the module docstring holds the measurement.
        _disputed(b"\xab", "ab"),
        _disputed(b"\x20", "20"),
        _disputed(b"\xab\xcd", "ad"),
        _disputed(b"\x20\x61", "21"),
        _disputed(b"\x30\xab", "3b"),
        _disputed(b"\x61\x20", "60"),
        _disputed(b"\x30\x31\xab\xcd", "3d"),
        # The eighth PR #277 example. Every FoxIO source and this project agree.
        (b"\x30\xab\xcd\x31", "01"),
        # `python/ja4.py`, `rust/tls.rs` and this project agree on these four.
        (b"", "00"),
        (b"h2", "h2"),
        (b"http/1.1", "h1"),
        (b"h3", "h3"),
        # TODO(#141): the measurement confirms that `python/ja4.py` gives `h` and that
        # `rust/tls.rs` gives `h0`, so no FoxIO source produces `hh`. The two
        # implementations disagree, so this project holds the value it wrote before.
        (b"h", "hh"),
    ],
)
def test_compute_alpn_value(alpn_bytes, expected):
    assert compute_alpn_value(alpn_bytes) == expected


def test_the_pcap_vector_alpn_value_is_99():
    """The first ALPN value `0xba 0xad` produces `99`, which two FoxIO sources give."""
    assert compute_alpn_value(b"\xba\xad") == "99"


def test_compute_alpn_value_none_returns_00():
    assert compute_alpn_value(None) == "00"


def test_compute_alpn_via_generate_ja4():
    """A tls_info dictionary that holds the vector ALPN bytes produces `99`."""
    from ja4plus.fingerprinters.ja4 import generate_ja4

    info = {
        "handshake_type": "client_hello",
        "type": "client_hello",
        "version": 0x0303,
        "is_quic": False,
        "is_dtls": False,
        "ciphers": [0x1301],
        "extensions": [],
        "alpn_protocols": [""],  # ascii decode dropped non-ascii bytes
        "alpn_raw": [b"\xba\xad"],  # but raw bytes are preserved
        "signature_algorithms": [],
        "supported_versions": [],
        "sni": None,
    }
    fp = generate_ja4(info)
    assert fp is not None
    # part_a: t12i0100<alpn>
    part_a = fp.split("_")[0]
    # The vector `tls-non-ascii-alpn.pcapng` holds these two bytes, and the FoxIO
    # Python implementation and the FoxIO Rust implementation both give `99`.
    assert part_a.endswith("99"), f"got {part_a!r}"


def _reference_ja4():
    """Return the JA4 value the FoxIO expected-output file holds for the capture.

    Returns:
        The `JA4.1` value of the first stream.

    Raises:
        FileNotFoundError: The expected-output file is absent.
        AssertionError: The expected-output file names no stream.
    """
    with open(EXPECTED_PATH) as handle:
        entries = json.load(handle)
    # An empty file holds no reference value. This check names that cause, because the
    # index below raises IndexError instead.
    assert entries, "{} names no stream".format(EXPECTED_PATH)
    return entries[0]["JA4.1"]


def _produced_ja4():
    """Return every JA4 value the fingerprinter produces from the FoxIO capture."""
    from scapy.all import rdpcap

    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    fingerprinter = JA4Fingerprinter()
    produced = []
    for packet in rdpcap(str(CAPTURE_PATH)):
        fingerprint = fingerprinter.process_packet(packet)
        if fingerprint:
            produced.append(fingerprint)
    return produced


def test_the_foxio_capture_carries_a_first_alpn_value_that_is_not_ascii():
    """The first ALPN value of `tls-non-ascii-alpn.pcapng` is the two bytes `0xba 0xad`."""
    from scapy.all import Raw, rdpcap

    from ja4plus.utils.tls_utils import parse_tls_handshake

    client_hellos = []
    for packet in rdpcap(str(CAPTURE_PATH)):
        if not packet.haslayer(Raw):
            continue
        info = parse_tls_handshake(bytes(packet[Raw].load))
        if info and info.get("type") == "client_hello":
            client_hellos.append(info)

    assert len(client_hellos) == 1
    # The parser keeps the ALPN bytes, because the ASCII decode drops the first value.
    assert client_hellos[0]["alpn_raw"] == [b"\xba\xad", b"http/1.1"]
    assert client_hellos[0]["alpn_protocols"] == ["", "http/1.1"]


def test_the_foxio_capture_produces_the_reference_ja4_value():
    """`tls-non-ascii-alpn.pcapng` produces the JA4 value the FoxIO reference holds."""
    assert _produced_ja4() == [_reference_ja4()]
