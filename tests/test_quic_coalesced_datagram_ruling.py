"""The coalesced QUIC datagram the divergence register records under #613.

JA4L reads the first QUIC packet of a UDP datagram and no other packet of it. A server
datagram that coalesces an Initial packet and a Handshake packet therefore fills point
`B`, and it fills no point `C`. RFC 9000 Section 12.2 permits that datagram.

**A ruling that lives only in a closed issue is a ruling the next reader reverses by
accident.** These cases hold the register row against the code it describes. A read of
the second packet of a datagram fails a case here, and so does a deletion of the row.
"""

from pathlib import Path
import json
import re

from scapy.all import IP, UDP, Raw

from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.utils.quic_utils import QUIC_HANDSHAKE, QUIC_INITIAL, long_header_packet_type

from tests.quic_builder import (
    client_initial,
    crypto_frame,
    handshake_packet,
    server_hello,
    server_initial,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

PARSER = REPO_ROOT / "ja4plus" / "utils" / "quic_utils.py"

FINGERPRINTER = REPO_ROOT / "ja4plus" / "fingerprinters" / "ja4l.py"

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

# The heading of the register, and the line that closes it.
# `tests/test_ja4ssh_packet_selection_ruling.py` reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The QUIC packets of one datagram that JA4L reads"

# The line of the parser that reads the first byte, and the text it holds.
FIRST_BYTE_LINE = 65
FIRST_BYTE_TEXT = "first_byte = udp_payload[0]"

# The line of the fingerprinter that reads the packet type, and the text it holds.
PACKET_TYPE_LINE = 563
PACKET_TYPE_TEXT = "packet_type = long_header_packet_type(udp_payload)"

# The addresses and the ports of the one QUIC connection the synthetic cases read.
CLIENT_IP = "192.168.1.50"
SERVER_IP = "10.0.0.1"
CLIENT_PORT = 50000
SERVER_PORT = 443

CLIENT_DCID = bytes.fromhex("203f9e9f68698274")

# The server value the synthetic connection gives, at the timestamps below.
SERVER_VALUE = "JA4L-S=5000_64_quic"

# The client value a connection gives where two datagrams carry the two server packets.
CLIENT_VALUE = "JA4L-C=5000_64_quic"

# The capture time of each packet of the synthetic connection, in seconds.
CLIENT_INITIAL_MOMENT = 0.0
SERVER_MOMENT = 0.010
SERVER_HANDSHAKE_MOMENT = 0.020
CLIENT_HANDSHAKE_MOMENT = 0.030

# The frame of each capture that carries a coalesced server datagram, and the frame that
# holds the JA4L value the Wireshark dissector writes for it.
COALESCED_FRAMES = {"ssh2.pcapng": ("1042", "1046"), "tls3.pcapng": ("295", "297")}

# The per-packet value the Wireshark dissector writes on the frame that answers each
# coalesced datagram. `wireshark/source/packet-ja4.c:1408` reads every QUIC packet.
DISSECTOR_VALUES = {"ssh2.pcapng": "279_128_quic", "tls3.pcapng": "271_128_quic"}

# The stream of each capture that carries the coalesced server datagram, and the JA4L-S
# value the FoxIO Python implementation writes for it. That file holds no JA4L-C value
# for either stream, which is the reading this project already holds.
PYTHON_STREAMS = {"ssh2.pcapng": (33, "16192_57"), "tls3.pcapng": (25, "3583_57")}


def _register_row() -> str:
    """Return the register row that records the coalesced QUIC datagram.

    Returns:
        The whole text of the row.

    Raises:
        AssertionError: The page holds no register, or the register holds no such row.
    """
    page = SPECIFICATION.read_text(encoding="utf-8")
    assert REGISTER_HEADING in page, f"the specification holds no {REGISTER_HEADING!r}"
    section = page[page.index(REGISTER_HEADING) : page.index(REGISTER_END)]
    for line in section.splitlines():
        if not line.startswith("|") or REGISTER_SEPARATOR.match(line):
            continue
        if line.split("|")[1].strip() == RULING_ITEM:
            return line
    raise AssertionError(f"the divergence register holds no row named {RULING_ITEM!r}")


def _to_server(payload: bytes, moment: float) -> Raw:
    """Return one client packet that carries the payload at the moment.

    Args:
        payload: The bytes of the UDP payload.
        moment: The capture time, in seconds.

    Returns:
        The packet.
    """
    packet = (
        IP(src=CLIENT_IP, dst=SERVER_IP)
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / Raw(load=payload)
    )
    packet.time = moment
    return packet


def _from_server(payload: bytes, moment: float) -> Raw:
    """Return one server packet that carries the payload at the moment.

    Args:
        payload: The bytes of the UDP payload.
        moment: The capture time, in seconds.

    Returns:
        The packet.
    """
    packet = (
        IP(src=SERVER_IP, dst=CLIENT_IP)
        / UDP(sport=SERVER_PORT, dport=CLIENT_PORT)
        / Raw(load=payload)
    )
    packet.time = moment
    return packet


def _server_initial() -> bytes:
    """Return the UDP payload of one QUIC server Initial packet that completes point B.

    Returns:
        The bytes of the payload.
    """
    return server_initial(CLIENT_DCID, crypto_frame(0, server_hello()))


def _coalesced_connection() -> list[str | None]:
    """Return the value each packet gives where one datagram carries two server packets.

    The server datagram coalesces its Initial packet and its Handshake packet, which
    RFC 9000 Section 12.2 permits.

    Returns:
        The three results, in packet order.
    """
    fingerprinter = JA4LFingerprinter()
    return [
        fingerprinter.process_packet(
            _to_server(client_initial(CLIENT_DCID), CLIENT_INITIAL_MOMENT)
        ),
        fingerprinter.process_packet(
            _from_server(_server_initial() + handshake_packet(), SERVER_MOMENT)
        ),
        fingerprinter.process_packet(_to_server(handshake_packet(), CLIENT_HANDSHAKE_MOMENT)),
    ]


def _separate_connection() -> list[str | None]:
    """Return the value each packet gives where two datagrams carry the server packets.

    This connection is the control of `_coalesced_connection`. It carries the same four
    QUIC packets, and it puts the server Handshake packet in a datagram of its own.

    Returns:
        The four results, in packet order.
    """
    fingerprinter = JA4LFingerprinter()
    return [
        fingerprinter.process_packet(
            _to_server(client_initial(CLIENT_DCID), CLIENT_INITIAL_MOMENT)
        ),
        fingerprinter.process_packet(_from_server(_server_initial(), SERVER_MOMENT)),
        fingerprinter.process_packet(_from_server(handshake_packet(), SERVER_HANDSHAKE_MOMENT)),
        fingerprinter.process_packet(_to_server(handshake_packet(), CLIENT_HANDSHAKE_MOMENT)),
    ]


def test_the_register_holds_a_row_for_the_quic_packets_of_one_datagram() -> None:
    """The divergence register holds the row that records the coalesced datagram."""
    assert RULING_ITEM in _register_row()


def test_the_register_names_the_two_lines_that_read_the_first_packet() -> None:
    """The row names the line of the parser and the line of the fingerprinter."""
    row = _register_row()
    absent = [
        citation
        for citation in (
            "`ja4plus/utils/quic_utils.py:65`",
            "`ja4plus/fingerprinters/ja4l.py:563`",
        )
        if citation not in row
    ]
    assert absent == [], f"the row names none of these lines: {absent}"


def test_the_register_names_the_three_foxio_references_that_split() -> None:
    """The row names the line of each FoxIO implementation that reads a packet type."""
    row = _register_row()
    absent = [
        citation
        for citation in (
            "`python/ja4.py:403-404`",
            "`rust/ja4/src/time/udp.rs:278`",
            "`wireshark/source/packet-ja4.c:1408`",
        )
        if citation not in row
    ]
    assert absent == [], f"the row names none of these references: {absent}"


def test_the_register_names_the_two_frames_that_carry_a_coalesced_datagram() -> None:
    """The row names each capture frame the dissector reads and this project does not."""
    row = _register_row()
    absent = [statement for statement in DISSECTOR_VALUES.values() if statement not in row]
    assert absent == [], f"the row states none of these values: {absent}"


def test_the_register_names_the_records_that_hold_the_ruling() -> None:
    """The row names this issue and the issue of the port that holds the other half."""
    row = _register_row()
    absent = [
        citation for citation in ("#613", "`Crank-Git/ja4plus-go#449`") if citation not in row
    ]
    assert absent == [], f"the row names none of these records: {absent}"


def test_the_register_row_reads_parity_rule_one() -> None:
    """The row states rule 1, because FoxIO governs the behaviour of a fingerprinter."""
    assert _register_row().split("|")[4].strip() == "1"


def test_the_register_row_states_that_the_two_libraries_agree() -> None:
    """The row records a reference split and no divergence from the port."""
    assert "this row records no divergence from the port" in _register_row()


def test_the_register_row_states_that_the_ruling_is_reversible() -> None:
    """The row states that a reversal reads every QUIC packet of a datagram."""
    assert "The ruling is reversible" in _register_row()


def test_the_parser_reads_the_first_byte_at_the_cited_line() -> None:
    """The line the row names holds the read of the first byte of the datagram."""
    lines = PARSER.read_text(encoding="utf-8").splitlines()
    assert lines[FIRST_BYTE_LINE - 1].strip() == FIRST_BYTE_TEXT


def test_the_fingerprinter_reads_the_packet_type_at_the_cited_line() -> None:
    """The line the row names holds the one read of the packet type of a datagram."""
    lines = FINGERPRINTER.read_text(encoding="utf-8").splitlines()
    assert lines[PACKET_TYPE_LINE - 1].strip() == PACKET_TYPE_TEXT


def test_the_parser_reads_the_type_of_the_first_packet_of_a_coalesced_datagram() -> None:
    """A datagram of an Initial packet and a Handshake packet reports the Initial type."""
    initial = _server_initial()
    handshake = handshake_packet()
    assert long_header_packet_type(initial) == QUIC_INITIAL
    assert long_header_packet_type(handshake) == QUIC_HANDSHAKE
    assert long_header_packet_type(initial + handshake) == QUIC_INITIAL


def test_a_coalesced_server_datagram_fills_point_b() -> None:
    """The coalesced datagram gives the server value, because its first packet is Initial."""
    assert _coalesced_connection()[1] == SERVER_VALUE


def test_a_coalesced_server_datagram_fills_no_point_c() -> None:
    """The client Handshake packet gives no client value after a coalesced datagram."""
    assert _coalesced_connection()[2] is None


def test_two_server_datagrams_fill_point_c() -> None:
    """A server Handshake packet in a datagram of its own gives the client value."""
    results = _separate_connection()
    assert results[1] == SERVER_VALUE
    assert results[3] == CLIENT_VALUE


def test_the_dissector_writes_a_value_on_the_frame_that_answers_each_datagram() -> None:
    """The per-packet vector set holds the value the reading of every packet gives."""
    for capture, value in DISSECTOR_VALUES.items():
        path = VECTORS / "wireshark_expected" / f"{capture}.json"
        records = json.loads(path.read_text(encoding="utf-8"))
        held = {
            layers["frame.number"][0]: layers.get("ja4.ja4l", [None])[0]
            for layers in (record["_source"]["layers"] for record in records)
        }
        coalesced, answer = COALESCED_FRAMES[capture]
        assert held.get(coalesced) is None, f"{capture} frame {coalesced} holds a JA4L value"
        assert held.get(answer) == value


def test_the_foxio_python_file_holds_no_client_value_for_either_stream() -> None:
    """The FoxIO Python implementation writes the server value alone on both streams."""
    for capture, (stream, server_value) in PYTHON_STREAMS.items():
        records = json.loads((VECTORS / f"{capture}.json").read_text(encoding="utf-8"))
        held = [record for record in records if record.get("stream") == stream]
        assert len(held) == 1, f"{capture} holds {len(held)} entries for stream {stream}"
        assert held[0].get("JA4L-S") == server_value
        assert "JA4L-C" not in held[0]
