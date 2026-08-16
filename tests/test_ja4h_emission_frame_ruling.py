"""The JA4H emission frame the divergence register records under #607.

JA4H emits as soon as the header block ends, and it reads no `Content-Length` header. A
request that declares a body and carries none therefore produces a value here. The port
gates the emission on the complete body, so it produces none for the same bytes.

**A ruling that lives only in a closed issue is a ruling the next reader reverses by
accident.** These cases hold the register row against the code it describes. A body gate
in `process_packet` fails a case here, and so does a deletion of the row.
"""

import ast
from pathlib import Path
import re

from scapy.all import IP, TCP, Raw

from ja4plus.fingerprinters.ja4h import JA4HFingerprinter

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

FINGERPRINTER = REPO_ROOT / "ja4plus" / "fingerprinters" / "ja4h.py"

# The heading of the register, and the line that closes it.
# `tests/test_ja4l_quic_eviction_ruling.py` reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The frame that emits a JA4H value"

# The name of the function that reports where the header block ends.
BLOCK_END = "header_block_end"

# The addresses and the ports of the one connection every case below reads.
CLIENT_IP = "192.168.1.50"
SERVER_IP = "10.0.0.1"
CLIENT_PORT = 50000
SERVER_PORT = 80

# The first sequence number of the request.
FIRST_SEQUENCE = 1000

# The header block of a request that declares a body of 100 bytes.
DECLARED_BODY_HEADERS = (
    b"POST /upload HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: probe/1.0\r\n"
    b"Accept-Language: en-US\r\n"
    b"Content-Length: 100\r\n"
    b"\r\n"
)

# The body that request declares.
DECLARED_BODY = b"x" * 100

# The whole request of a method that declares no body.
NO_DECLARED_BODY = (
    b"GET /index.html HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: probe/1.0\r\n"
    b"Accept-Language: en-US\r\n"
    b"\r\n"
)

# The value the header block of `DECLARED_BODY_HEADERS` gives.
DECLARED_BODY_VALUE = "po11nn04enus_5b576c474cee_000000000000_000000000000"

# The value `NO_DECLARED_BODY` gives.
NO_DECLARED_BODY_VALUE = "ge11nn03enus_ea59799162d6_000000000000_000000000000"


def _register_row() -> str:
    """Return the register row that records the JA4H emission frame.

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


def _client_packet(payload: bytes, sequence: int, moment: float) -> Raw:
    """Return one client packet that carries the payload at the moment.

    Args:
        payload: The bytes of the TCP payload.
        sequence: The sequence number of the first byte.
        moment: The capture time, in seconds.

    Returns:
        The packet.
    """
    packet = (
        IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="PA", seq=sequence)
        / Raw(load=payload)
    )
    packet.time = moment
    return packet


def test_the_register_holds_a_row_for_the_ja4h_emission_frame() -> None:
    """The divergence register holds the row that records the emission frame."""
    assert RULING_ITEM in _register_row()


def test_the_register_names_the_lines_of_this_project_that_emit() -> None:
    """The row names the line that reads the header block end and the line that returns."""
    row = _register_row()
    absent = [
        citation
        for citation in (
            "`ja4plus/fingerprinters/ja4h.py:154`",
            "`ja4plus/fingerprinters/ja4h.py:175`",
            "`ja4plus/utils/http_utils.py:105`",
        )
        if citation not in row
    ]
    assert absent == [], f"the row names none of these lines: {absent}"


def test_the_register_names_the_body_gate_of_the_port() -> None:
    """The row names the gate of the port and both call sites of its packet path."""
    row = _register_row()
    absent = [
        citation
        for citation in (
            "`internal/parser/http.go:185`",
            "`ja4h.go:130`",
            "`ja4h.go:174`",
        )
        if citation not in row
    ]
    assert absent == [], f"the row names none of these lines: {absent}"


def test_the_register_names_the_records_that_hold_the_ruling() -> None:
    """The row names this issue and the issue of the port that carries the other half."""
    row = _register_row()
    absent = [
        citation for citation in ("#607", "`Crank-Git/ja4plus-go#455`") if citation not in row
    ]
    assert absent == [], f"the row names none of these records: {absent}"


def test_the_register_names_the_four_references_that_state_a_trigger() -> None:
    """The row cites the trigger of each FoxIO implementation of the method."""
    row = _register_row()
    absent = [
        citation
        for citation in (
            "`zeek/ja4h/main.zeek:186`",
            "`wireshark/source/packet-ja4.c:1634`",
            "`wireshark/source/packet-ja4.c:1149`",
            "`rust/ja4/src/http.rs:64-68`",
            "`python/ja4h.py:17`",
        )
        if citation not in row
    ]
    assert absent == [], f"the row cites none of these references: {absent}"


def test_the_register_row_reads_parity_rule_one() -> None:
    """The row states rule 1, because FoxIO governs the behavior of a fingerprinter."""
    assert _register_row().split("|")[4].strip() == "1"


def test_the_register_row_states_that_the_ruling_is_reversible() -> None:
    """The row states that a vector which separates the two frames reopens the ruling."""
    assert "The ruling is reversible" in _register_row()


def test_the_module_reads_the_header_block_end_at_the_cited_line() -> None:
    """`process_packet` holds one call that reads where the header block ends."""
    tree = ast.parse(FINGERPRINTER.read_text(encoding="utf-8"))
    assert _call_lines(tree, BLOCK_END) == [154]


def test_the_module_returns_the_fingerprint_at_the_cited_line() -> None:
    """The line the row names returns the value the header block produced."""
    lines = FINGERPRINTER.read_text(encoding="utf-8").splitlines()
    assert lines[174].strip() == "return fingerprint"


def test_the_module_reads_no_content_length_header() -> None:
    """The JA4H module names the `Content-Length` header nowhere."""
    source = FINGERPRINTER.read_text(encoding="utf-8").lower()
    assert "content-length" not in source
    assert "content_length" not in source


def test_a_request_that_declares_a_body_and_carries_none_produces_a_value() -> None:
    """The header block alone produces a value, and the declared body reaches nothing."""
    fingerprinter = JA4HFingerprinter()
    value = fingerprinter.process_packet(_client_packet(DECLARED_BODY_HEADERS, FIRST_SEQUENCE, 0.0))
    assert value == DECLARED_BODY_VALUE


def test_the_body_of_a_request_produces_no_second_value() -> None:
    """The segment that completes the declared body produces no value of its own."""
    fingerprinter = JA4HFingerprinter()
    fingerprinter.process_packet(_client_packet(DECLARED_BODY_HEADERS, FIRST_SEQUENCE, 0.0))
    second = fingerprinter.process_packet(
        _client_packet(DECLARED_BODY, FIRST_SEQUENCE + len(DECLARED_BODY_HEADERS), 0.010)
    )
    assert second is None


def test_a_request_that_carries_its_whole_body_produces_one_value() -> None:
    """One packet that holds the header block and the whole body gives the same value."""
    fingerprinter = JA4HFingerprinter()
    value = fingerprinter.process_packet(
        _client_packet(DECLARED_BODY_HEADERS + DECLARED_BODY, FIRST_SEQUENCE, 0.0)
    )
    assert value == DECLARED_BODY_VALUE


def test_a_request_that_declares_no_body_produces_a_value() -> None:
    """A request with no `Content-Length` header produces its value at the header block."""
    fingerprinter = JA4HFingerprinter()
    value = fingerprinter.process_packet(_client_packet(NO_DECLARED_BODY, FIRST_SEQUENCE, 0.0))
    assert value == NO_DECLARED_BODY_VALUE
