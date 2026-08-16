"""The QUIC point eviction the divergence register declines under #595.

The QUIC path of JA4L evicts no measurement point at point `D`. A four-tuple that two
QUIC connections reuse therefore reports one client value and one server value, and the
later connection reports none. `ja4plus-go` holds the same behaviour, so the two
libraries agree.

**A ruling that lives only in a closed issue is a ruling the next reader reverses by
accident.** These cases hold the register row against the code it describes. A call to
`_restart_connection` from the QUIC path fails a case here, and so does a deletion of
the row.
"""

import ast
from pathlib import Path
import re

from scapy.all import IP, TCP, UDP, Raw

from ja4plus.fingerprinters import ja4l
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter

from tests.quic_builder import (
    client_initial,
    crypto_frame,
    handshake_packet,
    server_hello,
    server_initial,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

FINGERPRINTER = REPO_ROOT / "ja4plus" / "fingerprinters" / "ja4l.py"

# The heading of the register, and the line that closes it.
# `tests/test_ja4t_emission_model_ruling.py` reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The JA4L measurement points a QUIC connection holds at point D"

# The name of the function that drops every measurement point of one connection.
RESTART = "_restart_connection"

# The addresses and the ports of the one four-tuple both connections reuse.
CLIENT_IP = "192.168.1.50"
SERVER_IP = "10.0.0.1"
CLIENT_PORT = 50000
SERVER_PORT = 443

CLIENT_DCID = bytes.fromhex("203f9e9f68698274")

# The value the first QUIC connection gives, at the timestamps `_quic_connection` uses.
FIRST_SERVER_VALUE = "JA4L-S=5000_64_quic"
FIRST_CLIENT_VALUE = "JA4L-C=5000_64_quic"


def _register_row() -> str:
    """Return the register row that records the QUIC point eviction.

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


def _function(name: str) -> ast.FunctionDef:
    """Return the definition of one function of the JA4L module.

    Args:
        name: The name of the function.

    Returns:
        The syntax tree of that function.

    Raises:
        AssertionError: The module holds no function of that name.
    """
    tree = ast.parse(FINGERPRINTER.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{FINGERPRINTER} holds no function named {name!r}")


def _call_lines(node: ast.AST, name: str) -> list[int]:
    """Return the line of each call to one function inside one syntax tree.

    Args:
        node: The syntax tree to read.
        name: The name of the function the caller counts.

    Returns:
        The line number of every call, in source order.
    """
    return sorted(
        call.lineno
        for call in ast.walk(node)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == name
    )


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


def _quic_connection(fingerprinter: JA4LFingerprinter, start: float) -> list[str | None]:
    """Return the value each packet of one whole QUIC handshake gives.

    The four packets move the four measurement points.

    - The client Initial packet moves point `A`.
    - The server Initial packet that completes the ServerHello moves point `B`.
    - The server Handshake packet moves point `C`.
    - The client Handshake packet moves point `D`.

    Args:
        fingerprinter: The fingerprinter that reads the packets.
        start: The capture time of the client Initial packet, in seconds.

    Returns:
        The four results, in packet order.
    """
    return [
        fingerprinter.process_packet(_to_server(client_initial(CLIENT_DCID), start)),
        fingerprinter.process_packet(
            _from_server(
                server_initial(CLIENT_DCID, crypto_frame(0, server_hello())), start + 0.010
            )
        ),
        fingerprinter.process_packet(_from_server(handshake_packet(), start + 0.020)),
        fingerprinter.process_packet(_to_server(handshake_packet(), start + 0.030)),
    ]


def test_the_register_holds_a_row_for_the_quic_point_eviction() -> None:
    """The divergence register holds the row that records the declined eviction."""
    assert RULING_ITEM in _register_row()


def test_the_register_names_the_one_call_site_of_the_restart() -> None:
    """The row names the line of `ja4plus` that drops the points of a connection."""
    row = _register_row()
    absent = [
        citation
        for citation in (
            "`ja4plus/fingerprinters/ja4l.py:439`",
            "`ja4plus/fingerprinters/ja4l.py:469`",
            "`ja4plus/fingerprinters/ja4l.py:585-656`",
        )
        if citation not in row
    ]
    assert absent == [], f"the row names none of these lines: {absent}"


def test_the_register_names_the_records_that_hold_the_ruling() -> None:
    """The row names this issue, the port ruling and the question that stays open."""
    row = _register_row()
    absent = [
        citation
        for citation in ("#595", "#623", "`Crank-Git/ja4plus-go#229`")
        if citation not in row
    ]
    assert absent == [], f"the row names none of these records: {absent}"


def test_the_register_names_the_four_references_that_split() -> None:
    """The row cites the two references that keep the points and the two that evict."""
    row = _register_row()
    absent = [
        citation
        for citation in (
            "`python/ja4.py:585-588`",
            "`python/common.py:85-88`",
            "`wireshark/source/packet-ja4.c:1409`",
            "`rust/ja4/src/stream.rs:206-211`",
            "`zeek/ja4l/main.zeek:198`",
        )
        if citation not in row
    ]
    assert absent == [], f"the row cites none of these references: {absent}"


def test_the_register_row_reads_parity_rule_one() -> None:
    """The row states rule 1, because FoxIO governs the behaviour of a fingerprinter."""
    assert _register_row().split("|")[4].strip() == "1"


def test_the_module_holds_one_call_site_of_the_restart() -> None:
    """`_restart_connection` holds one call site in the whole JA4L module."""
    tree = ast.parse(FINGERPRINTER.read_text(encoding="utf-8"))
    assert _call_lines(tree, RESTART) == [469]


def test_the_tcp_path_holds_that_one_call_site() -> None:
    """`_tcp_ja4l` holds the one call that drops the points of a connection."""
    assert _call_lines(_function("_tcp_ja4l"), RESTART) == [469]


def test_the_quic_path_drops_the_points_of_a_connection_nowhere() -> None:
    """`_quic_ja4l` calls `_restart_connection` nowhere."""
    assert _call_lines(_function("_quic_ja4l"), RESTART) == []


def test_the_first_quic_connection_reports_one_server_value_and_one_client_value() -> None:
    """One QUIC handshake gives both values on the packet that fills point D."""
    fingerprinter = JA4LFingerprinter()
    results = _quic_connection(fingerprinter, 0.0)
    assert results == [None, None, None, FIRST_SERVER_VALUE]
    assert fingerprinter.last_extra_fingerprints == [FIRST_CLIENT_VALUE]


def test_a_second_quic_connection_on_one_four_tuple_reports_no_value() -> None:
    """The later QUIC connection of one four-tuple reports no value of its own."""
    fingerprinter = JA4LFingerprinter()
    _quic_connection(fingerprinter, 0.0)
    assert _quic_connection(fingerprinter, 1.0) == [None, None, None, None]


def test_the_point_d_packet_leaves_every_measurement_point_in_place() -> None:
    """The connection state holds points A, B, C and D after point D completes."""
    fingerprinter = JA4LFingerprinter()
    _quic_connection(fingerprinter, 0.0)
    states = [conn for conn in fingerprinter.connections.values() if "D" in conn["timestamps"]]
    assert len(states) == 1
    assert sorted(states[0]["timestamps"]) == ["A", "B", "C", "D"]


def test_a_second_tcp_connection_on_one_four_tuple_reports_its_own_server_value() -> None:
    """The TCP path drops the points of a closed connection, and the QUIC path does not."""
    fingerprinter = JA4LFingerprinter()
    values = []
    for start, sequence in ((0.0, 1000), (1.0, 5000)):
        syn = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(
            sport=CLIENT_PORT, dport=443, flags="S", seq=sequence
        )
        syn.time = start
        syn_ack = IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(
            sport=443, dport=CLIENT_PORT, flags="SA", seq=sequence + 7, ack=sequence + 1
        )
        syn_ack.time = start + 0.010
        fingerprinter.process_packet(syn)
        values.append(fingerprinter.process_packet(syn_ack))
    assert values[0] is not None
    assert values[1] == values[0]


def test_the_restart_reaches_no_quic_state_of_the_connection() -> None:
    """`_restart_connection` drops the points, and it holds no rule of its own for QUIC."""
    conn = {
        "timestamps": {"A": 0, "B": 1, "C": 2, "D": 3},
        "ttls": {"client": 64},
        "isns": {},
        "quic_dcid": CLIENT_DCID,
    }
    ja4l._restart_connection(conn)
    assert conn["timestamps"] == {}
    assert conn["quic_dcid"] == CLIENT_DCID
