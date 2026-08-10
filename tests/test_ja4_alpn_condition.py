"""The condition that makes the JA4 ALPN value read `99`.

#127 settled the value. #141 settles the condition, and it settles it by measurement.
`tests/build_alpn_condition_capture.py` builds `alpn-condition.pcap`, and both FoxIO
implementations at the commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` ran against
it. `docs/implementation_notes.md` holds the commands and the full table.

The measurement settles one rule: a printable ASCII byte reaches the value without a
change, and the alphanumeric test the FoxIO prose states is not the condition. Both
FoxIO implementations agree on every input whose first byte and last byte fall inside
`0x20-0x7E`, and they agree on an input whose two bytes fall outside ASCII.

The measurement settles no rule outside that range. The FoxIO Rust implementation reads
a control byte as the tshark escape text, so it reads `h\\x1f` as five characters and
writes `hf`. The FoxIO Python implementation reads the byte. The two also disagree on a
byte above `0x7E` and on a one-byte value.

#162 records the user decision of 2026-08-07: the values outside the range stay as they
are. The capture now carries the disputed inputs as well as the agreed ones, so the
divergence is a comparison that runs. `STREAMS` holds the measured value of both FoxIO
implementations and the produced value, one row per stream. The tests below compare all
three against the capture and against the expected-output file.
"""

import json
from pathlib import Path
from typing import NamedTuple, Optional

import pytest

from ja4plus.fingerprinters.ja4 import compute_alpn_value
from tests.foxio_deviations import load_register, value_key

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"
CAPTURE_PATH = VECTORS_DIR / "alpn-condition.pcap"
EXPECTED_PATH = VECTORS_DIR / "alpn-condition.pcap.json"

# The issue that records the decision, and the first client port of the capture.
DECISION_ISSUE = 162
FIRST_CLIENT_PORT = 44401

# Every method of the expected-output file that carries the ALPN characters.
ALPN_METHODS = ("JA4", "JA4_o", "JA4_r", "JA4_ro")


class Stream(NamedTuple):
    """One stream of `alpn-condition.pcap`, and the three values measured on it.

    Attributes:
        alpn: The first ALPN value the client hello of the stream carries.
        foxio_python: The ALPN characters the FoxIO Python implementation writes.
        foxio_rust: The ALPN characters the FoxIO Rust implementation writes, or None
            when it writes no value at all.
        produced: The ALPN characters `ja4plus` writes.
    """

    alpn: bytes
    foxio_python: str
    foxio_rust: Optional[str]
    produced: str

    @property
    def disputed(self):
        """True when the produced value matches neither FoxIO implementation."""
        return self.produced not in (self.foxio_python, self.foxio_rust)


# The streams of `alpn-condition.pcap`, in wire order. The first two are the agreed
# inputs #141 measured. The rest are the disputed inputs #162 records, and their values
# come from the two tables of `docs/implementation_notes.md`. Nothing here derives a value.
STREAMS = (
    Stream(b"h\x20", "h ", "h ", "h "),
    Stream(b"\x20h", " h", " h", " h"),
    Stream(b"h\xab", "h�", "h9", "99"),
    Stream(b"\xabh", "99", "9h", "99"),
    Stream(b"h\x1f", "h\x1f", "hf", "99"),
    Stream(b"h\x0a", "h\n", None, "99"),
    Stream(b"h", "h", "h0", "hh"),
)

DISPUTED_STREAMS = tuple(index for index, stream in enumerate(STREAMS) if stream.disputed)


def _stream_id(index):
    """Return the parameter identifier of one stream, which names its ALPN value."""
    return "stream{}-{}".format(index, STREAMS[index].alpn.hex())


def alpn_characters(fingerprint):
    """Return the ALPN characters of one JA4 value or one JA4 raw value.

    The characters sit between the eight-character prefix and the first underscore. This
    function reads the field by position, not by length, because the FoxIO Python
    implementation writes one character for a one-byte ALPN value.

    Args:
        fingerprint: One JA4, JA4_r, JA4_o or JA4_ro value.

    Returns:
        The ALPN characters, as a string.
    """
    return fingerprint.split("_")[0][8:]


def load_expected():
    """Return the expected records of `alpn-condition.pcap`, in stream order."""
    with open(EXPECTED_PATH) as handle:
        return sorted(json.load(handle), key=lambda entry: entry["stream"])


def produced_ja4_values():
    """Return the JA4 value `ja4plus` produces for each stream, in wire order."""
    from scapy.all import rdpcap

    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    fingerprinter = JA4Fingerprinter()
    produced = []
    for packet in rdpcap(str(CAPTURE_PATH)):
        fingerprint = fingerprinter.process_packet(packet)
        if fingerprint:
            produced.append(fingerprint)
    return produced


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
        # The two ends of the printable range. Both FoxIO implementations write these.
        (b"h\x21", "h!"),
        (b"h\x7e", "h~"),
    ],
)
def test_a_printable_ascii_byte_reaches_the_alpn_value_without_a_change(alpn_bytes, expected):
    assert compute_alpn_value(alpn_bytes) == expected


@pytest.mark.parametrize(
    "alpn_bytes",
    [
        b"h\x00",  # FoxIO Python writes `h`. FoxIO Rust writes `h0`.
        b"h\x01",  # FoxIO Python writes `h\x01`. FoxIO Rust writes `h1`.
        b"h\x0a",  # FoxIO Python writes `h\n`. FoxIO Rust writes no value.
        b"h\x1f",  # FoxIO Python writes `h\x1f`. FoxIO Rust writes `hf`.
        b"h\x7f",  # FoxIO Python writes `h\x7f`. FoxIO Rust writes `hf`.
        b"\x01h",  # FoxIO Python writes `\x01h`. FoxIO Rust writes `\h`.
        b"\x00\x01",  # FoxIO Python writes no value. FoxIO Rust writes `00`.
    ],
)
def test_a_control_byte_keeps_the_value_99_while_the_references_disagree(alpn_bytes):
    """The FoxIO Rust implementation reads a control byte as the tshark escape text.

    The two implementations therefore disagree on every control byte, so `ja4plus`
    changes nothing here. `docs/implementation_notes.md` holds the measurement.
    """
    assert compute_alpn_value(alpn_bytes) == "99"


def test_the_tab_byte_keeps_the_value_99_although_the_references_agree():
    """`0x09` is the one byte outside `0x20-0x7E` where both FoxIO sources write a tab.

    That agreement is an accident of the tshark text form and not a rule, because `0x0A`
    beside it makes the FoxIO Rust implementation write no value. #141 declines it and
    asks the user, so this project holds the value it wrote before #141.
    """
    assert compute_alpn_value(b"h\x09") == "99"


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


def test_the_capture_carries_every_alpn_value_the_measurement_names():
    """`alpn-condition.pcap` holds the first ALPN value of every row of `STREAMS`."""
    from scapy.all import Raw, rdpcap

    from ja4plus.utils.tls_utils import parse_tls_handshake

    first_values = []
    for packet in rdpcap(str(CAPTURE_PATH)):
        if not packet.haslayer(Raw):
            continue
        info = parse_tls_handshake(bytes(packet[Raw].load))
        if info and info.get("type") == "client_hello":
            first_values.append(info["alpn_raw"][0])

    assert first_values == [stream.alpn for stream in STREAMS]


def test_the_capture_produces_the_alpn_characters_the_table_records():
    """The produced JA4 value of each stream carries the ALPN characters of its row."""
    produced = produced_ja4_values()

    assert [alpn_characters(value) for value in produced] == [stream.produced for stream in STREAMS]


def test_the_expected_file_holds_the_foxio_python_alpn_characters():
    """The expected-output file is the FoxIO Python measurement, on every method."""
    entries = load_expected()

    for method in ALPN_METHODS:
        characters = [alpn_characters(entry["{}.1".format(method)]) for entry in entries]
        assert characters == [stream.foxio_python for stream in STREAMS], method


def test_the_expected_file_holds_one_entry_for_each_stream():
    """Each stream of the capture reaches the expected-output file, on its own port."""
    entries = load_expected()

    assert [entry["stream"] for entry in entries] == list(range(len(STREAMS)))
    assert [entry["srcport"] for entry in entries] == [
        str(FIRST_CLIENT_PORT + index) for index in range(len(STREAMS))
    ]


def test_every_stream_differs_from_the_others_in_the_alpn_characters_alone():
    """The hash halves are the same on every stream, so the ALPN field is the variable.

    The seven client hellos carry the same ciphers and the same extensions, so the JA4
    prefix and both hashes are invariant. That invariance is what lets a reader compare
    the expected values of two streams directly.
    """
    entries = load_expected()

    for method in ALPN_METHODS:
        values = [entry["{}.1".format(method)] for entry in entries]
        prefixes = {value.split("_")[0][:8] for value in values}
        remainders = {value.split("_", 1)[1] for value in values}
        assert prefixes == {"t13d0304"}, method
        assert len(remainders) == 1, method


@pytest.mark.parametrize("index", DISPUTED_STREAMS, ids=_stream_id)
def test_the_produced_value_matches_neither_foxio_implementation(index):
    """Each disputed stream produces a value that neither FoxIO implementation holds.

    The produced value comes from the capture. The FoxIO Python value comes from the
    expected-output file. This comparison therefore reads two artifacts, not one table.
    """
    stream = STREAMS[index]
    produced = alpn_characters(produced_ja4_values()[index])
    expected = alpn_characters(load_expected()[index]["JA4.1"])

    assert produced == stream.produced
    assert expected == stream.foxio_python
    assert produced != expected
    assert produced != stream.foxio_rust


def test_the_agreed_streams_produce_the_reference_value():
    """Every stream the two FoxIO implementations agree on still matches the reference.

    #162 records a divergence. It moves no value the measurement settled, so a stream
    that conformed before it must conform after it.
    """
    produced = produced_ja4_values()
    entries = load_expected()

    agreed = [index for index in range(len(STREAMS)) if index not in DISPUTED_STREAMS]
    assert [produced[index] for index in agreed] == [entries[index]["JA4.1"] for index in agreed]


@pytest.mark.parametrize("index", DISPUTED_STREAMS, ids=_stream_id)
def test_the_deviation_register_holds_each_disputed_stream(index):
    """Every disputed stream carries a decided register entry that #162 owns.

    The register entry is what makes the conformance suite report the divergence. An
    unregistered disputed stream would fail the suite, and a stream that stops
    diverging fails it too, because the entry is strict.
    """
    register = load_register()
    port = FIRST_CLIENT_PORT + index

    for method in ALPN_METHODS:
        key = value_key(CAPTURE_PATH.name, index, port, method, 1)
        assert key in register, key
        assert register[key].issue == DECISION_ISSUE, key
        assert register[key].decided is True, key


@pytest.mark.parametrize("index", DISPUTED_STREAMS, ids=_stream_id)
def test_each_register_entry_states_the_output_of_both_foxio_implementations(index):
    """The cause text of each disputed entry names both measured FoxIO values."""
    register = load_register()
    stream = STREAMS[index]
    cause = register[value_key(CAPTURE_PATH.name, index, FIRST_CLIENT_PORT + index, "JA4", 1)].cause

    assert "FoxIO Python" in cause
    assert "FoxIO Rust" in cause
    if stream.foxio_rust is not None:
        assert stream.foxio_rust in cause


def test_the_agreed_streams_carry_no_register_entry():
    """A stream the reference agrees with holds no entry, because it does not fail."""
    register = load_register()

    for index, stream in enumerate(STREAMS):
        if stream.disputed:
            continue
        key = value_key(CAPTURE_PATH.name, index, FIRST_CLIENT_PORT + index, "JA4", 1)
        assert key not in register, key
