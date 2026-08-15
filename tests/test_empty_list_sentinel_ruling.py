"""The empty-list sentinel that the divergence register records under #653.

JA4 and JA4S write `000000000000` for an empty list, and JA4X and JA4H hash it. The
maintainer ruled on 2026-08-15 that the split is correct. Three readings support it: the
text specification of JA4, four vectors that hold the JA4 sentinel, and the agreement of
all four references on JA4S.

**A ruling that lives only in a closed issue is a ruling the next reader reverses by
accident.** These cases hold the register row against the code it describes. A hash in
place of the sentinel fails a case here, and so does a deletion of the row.

`Crank-Git/ja4plus-go` writes the same sentinel through `internal/parser/hash.go`. A
reversal therefore changes both repositories.
"""

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from ja4plus.fingerprinters.ja4 import generate_ja4
from ja4plus.fingerprinters.ja4s import _generate_ja4s_from_tls_info

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

# The heading of the register, and the line that closes it.
# `tests/test_ja4t_syn_selection_ruling.py` reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The zero sentinel of an empty list in JA4 and in JA4S"

SENTINEL = "000000000000"

# The first 12 characters of the SHA-256 hash of the empty string. JA4X and JA4H write
# this value for an empty list, and JA4 and JA4S never write it.
EMPTY_HASH = "e3b0c44298fc"

# A key of the form `JA4` or `JA4.1`. The `_r`, `_o` and `_ro` forms are a raw form or an
# original-order form, so neither one is a JA4 value.
JA4_KEY = re.compile(r"^JA4(\.\d+)?$")
JA4S_KEY = re.compile(r"^JA4S(\.\d+)?$")

# The measurement the register row states, over the FoxIO Python expected-output files.
MEASURED_JA4_VALUES = 167
MEASURED_JA4S_VALUES = 84
MEASURED_SENTINEL_VALUE = "t10d230100_6a57a6f57151_000000000000"
MEASURED_SENTINEL_FILES = {
    "https3-301-get.pcap.json": 1,
    "socks-https-example.pcap.json": 3,
}

# Each line of `ja4plus` that writes the sentinel, and the expression it holds. The row
# cites all three, so a line that moves fails a case here and the row stays true.
SENTINEL_LINES = (
    ("ja4plus/fingerprinters/ja4.py", 202, 'cipher_hash = "000000000000"'),
    ("ja4plus/fingerprinters/ja4.py", 229, 'ext_hash = "000000000000"'),
    ("ja4plus/fingerprinters/ja4s.py", 303, 'extensions_hash = "000000000000"'),
)

# Each line of `ja4plus` that hashes an empty list. The row states this contrast, so a
# sentinel added to either method fails a case here.
HASHING_LINES = (
    (
        "ja4plus/fingerprinters/ja4x.py",
        75,
        "issuer_hash = hashlib.sha256(issuer_str.encode()).hexdigest()[:12]",
    ),
    (
        "ja4plus/fingerprinters/ja4h.py",
        534,
        "part_b = hashlib.sha256(headers_str.encode()).hexdigest()[:12]",
    ),
)


def _register_row() -> str:
    """Return the register row that records the empty-list sentinel.

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


def _source_line(relative: str, number: int) -> str:
    """Return one line of a tracked file, without its indentation.

    Args:
        relative: The path of the file, from the repository root.
        number: The one-based line number.

    Returns:
        The text of that line, stripped of leading and trailing space.
    """
    lines = (REPO_ROOT / relative).read_text(encoding="utf-8").splitlines()
    assert number <= len(lines), f"{relative} holds {len(lines)} lines"
    return lines[number - 1].strip()


def _client_hello(ciphers: list[int], extensions: list[int]) -> dict[str, Any]:
    """Return one parsed ClientHello that drives `generate_ja4` directly.

    Args:
        ciphers: The cipher suite list.
        extensions: The extension list.

    Returns:
        The parsed record.
    """
    return {
        "handshake_type": "client_hello",
        "type": "client_hello",
        "version": 0x0303,
        "is_quic": False,
        "is_dtls": False,
        "ciphers": ciphers,
        "extensions": extensions,
        "alpn_protocols": [],
        "signature_algorithms": [],
        "supported_versions": [],
        "sni": None,
    }


def _server_hello(extensions: list[int]) -> dict[str, Any]:
    """Return one parsed ServerHello that drives the JA4S generator directly.

    Args:
        extensions: The extension list.

    Returns:
        The parsed record.
    """
    return {
        "type": "server_hello",
        "handshake_type": "server_hello",
        "version": 0x0303,
        "supported_versions": [],
        "cipher": 0xC030,
        "extensions": extensions,
        "alpn_protocols": [],
    }


def _vector_values(pattern: re.Pattern[str]) -> list[tuple[str, str]]:
    """Return every value of the FoxIO Python expected-output files that the key names.

    Args:
        pattern: The key pattern.

    Returns:
        One pair of a file name and a value for each match.
    """
    found: list[tuple[str, str]] = []
    for path in sorted(VECTORS.glob("*.json")):
        loaded = json.loads(path.read_text(encoding="utf-8"))
        rows = loaded if isinstance(loaded, list) else [loaded]
        for row in rows:
            if not isinstance(row, dict):
                continue
            for key, value in row.items():
                if pattern.match(key) and isinstance(value, str):
                    found.append((path.name, value))
    return found


def test_the_register_holds_a_row_for_the_empty_list_sentinel() -> None:
    """The divergence register holds the row that records the sentinel."""
    assert RULING_ITEM in _register_row()


def test_the_register_names_each_line_of_this_project_that_writes_the_sentinel() -> None:
    """The row cites the three lines of `ja4plus` that write the sentinel."""
    row = _register_row()
    absent = [
        f"`{relative}:{number}`"
        for relative, number, _ in SENTINEL_LINES
        if f"`{relative}:{number}`" not in row
    ]
    assert absent == [], f"the row cites none of these lines: {absent}"


def test_each_line_the_register_cites_writes_the_sentinel() -> None:
    """Each cited line of `ja4plus` holds the assignment that writes the sentinel."""
    for relative, number, expression in SENTINEL_LINES:
        assert _source_line(relative, number) == expression, f"{relative}:{number} moved"


def test_the_register_cites_each_of_the_four_references() -> None:
    """The row cites the four FoxIO references that write the JA4S sentinel."""
    row = _register_row()
    absent = [
        citation
        for citation in (
            "`python/ja4.py:186-188`",
            "`rust/ja4/src/lib.rs:179-186`",
            "`rust/ja4/src/tls.rs:466`",
            "`wireshark/source/packet-ja4.c:573`",
            "`zeek/utils/common.zeek:62-65`",
            "`zeek/ja4s/main.zeek:171`",
        )
        if citation not in row
    ]
    assert absent == [], f"the row cites none of these references: {absent}"


def test_the_register_names_the_text_specification_of_ja4_and_its_two_rule_lines() -> None:
    """The row names the pinned text specification and the two lines that hold the rule."""
    row = _register_row()
    assert "`technical_details/JA4.md`" in row
    assert "`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`" in row
    assert "Line 121" in row
    assert "line 176" in row


def test_the_register_names_the_transcription_that_holds_the_ja4s_image_rule() -> None:
    """The row rests the JA4S image quotation on the transcription of this repository."""
    row = _register_row()
    assert "`docs/specs/foxio/JA4S.md:49`" in row
    quoted = "Truncated SHA256 hash of the Extensions, in the order they appear"
    assert quoted in row
    assert quoted in _source_line("docs/specs/foxio/JA4S.md", 49)


def test_the_register_attributes_the_ja4_image_reading_to_the_issue() -> None:
    """The row names the source of the one quotation this round did not re-take.

    This repository holds no JA4 transcription, so a reader must know that the
    `JA4.png` reading rests on #653 and not on a read of this round.
    """
    assert "The `JA4.png` reading rests on #653 alone" in _register_row()


def test_the_register_states_the_reason_the_specification_gives() -> None:
    """The row quotes the reason FoxIO states beside the rule."""
    quoted = (
        "We do this rather than running a sha256 hash of nothing as this makes it "
        "clear to the user when a field has no values."
    )
    assert quoted in _register_row()


def test_the_register_names_the_date_of_the_ruling() -> None:
    """The row states the date the maintainer ruled the split."""
    row = _register_row()
    assert "The maintainer ruled on 2026-08-15 that the split is correct." in row


def test_the_register_states_the_two_citations_this_round_moved() -> None:
    """The row names each wrong citation and the line that replaces it."""
    row = _register_row()
    for citation in (
        "`wireshark/source/packet-ja4.c:640`",
        "`wireshark/source/packet-ja4.c:629-630`",
        "`ja4plus/fingerprinters/ja4h.py:483`",
        "`ja4plus/fingerprinters/ja4h.py:534`",
    ):
        assert citation in row, f"the row names no {citation}"


def test_each_hashing_line_the_register_cites_holds_no_sentinel() -> None:
    """Each cited line of JA4X and JA4H hashes the list, and it writes no sentinel."""
    for relative, number, expression in HASHING_LINES:
        line = _source_line(relative, number)
        assert line == expression, f"{relative}:{number} moved"
        assert SENTINEL not in line


def test_the_register_states_the_measured_value_counts() -> None:
    """The row states the JA4 value count and the JA4S value count of the vector set."""
    row = _register_row()
    assert f"{MEASURED_JA4_VALUES} JA4 values" in row
    assert f"{MEASURED_JA4S_VALUES} JA4S values" in row


def test_an_empty_cipher_list_writes_the_sentinel_in_part_b() -> None:
    """JA4 writes the sentinel in part b when the cipher list is empty."""
    fingerprint = generate_ja4(_client_hello(ciphers=[], extensions=[0x000B]))
    assert fingerprint is not None
    assert fingerprint.split("_")[1] == SENTINEL


def test_an_empty_extension_list_writes_the_sentinel_in_part_c() -> None:
    """JA4 writes the sentinel in part c when the extension list is empty."""
    fingerprint = generate_ja4(_client_hello(ciphers=[0x1301], extensions=[]))
    assert fingerprint is not None
    assert fingerprint.split("_")[2] == SENTINEL


def test_an_empty_ja4s_extension_list_writes_the_sentinel_in_part_c() -> None:
    """JA4S writes the sentinel in part c when the extension list is empty."""
    fingerprint = _generate_ja4s_from_tls_info(_server_hello(extensions=[]))
    assert fingerprint is not None
    assert fingerprint.split("_")[2] == SENTINEL


def test_neither_method_writes_the_hash_of_the_empty_string() -> None:
    """JA4 and JA4S write no part that holds the hash of the empty string."""
    assert hashlib.sha256(b"").hexdigest()[:12] == EMPTY_HASH
    ja4 = generate_ja4(_client_hello(ciphers=[], extensions=[]))
    ja4s = _generate_ja4s_from_tls_info(_server_hello(extensions=[]))
    assert ja4 is not None
    assert ja4s is not None
    assert EMPTY_HASH not in ja4
    assert EMPTY_HASH not in ja4s


def test_the_vector_set_holds_the_measured_count_of_each_method() -> None:
    """The FoxIO Python expected-output files hold 167 JA4 values and 84 JA4S values."""
    assert len(_vector_values(JA4_KEY)) == MEASURED_JA4_VALUES
    assert len(_vector_values(JA4S_KEY)) == MEASURED_JA4S_VALUES


def test_four_ja4_values_of_the_vector_set_hold_the_sentinel_in_part_c() -> None:
    """Four published JA4 values require the sentinel, and the row names both captures."""
    row = _register_row()
    counts: dict[str, int] = {}
    for name, value in _vector_values(JA4_KEY):
        if value.split("_")[2:3] == [SENTINEL]:
            assert value == MEASURED_SENTINEL_VALUE, f"{name} gives {value}"
            counts[name] = counts.get(name, 0) + 1
    assert counts == MEASURED_SENTINEL_FILES
    assert f"`{MEASURED_SENTINEL_VALUE}`" in row
    for name in MEASURED_SENTINEL_FILES:
        assert f"`{name}`" in row, f"the row names no {name}"


def test_each_stream_that_holds_the_sentinel_holds_it_in_the_original_order_form_too() -> None:
    """The `JA4_o` value of each of the four streams carries the sentinel as well.

    One stream therefore fails two conformance cases under a hash, and the row states
    eight rather than four.
    """
    original_order = re.compile(r"^JA4_o(\.\d+)?$")
    counts: dict[str, int] = {}
    for name, value in _vector_values(original_order):
        if value.split("_")[2:3] == [SENTINEL]:
            counts[name] = counts.get(name, 0) + 1
    assert counts == MEASURED_SENTINEL_FILES
    assert "fails eight conformance cases" in _register_row()


def test_no_ja4_value_of_the_vector_set_holds_the_sentinel_in_part_b() -> None:
    """No published JA4 value carries an empty cipher list."""
    holders = [
        name for name, value in _vector_values(JA4_KEY) if value.split("_")[1:2] == [SENTINEL]
    ]
    assert holders == []


def test_no_ja4s_value_of_the_vector_set_holds_the_sentinel() -> None:
    """No vector measures the JA4S rule, so the references alone decide it."""
    holders = [
        name for name, value in _vector_values(JA4S_KEY) if value.split("_")[2:3] == [SENTINEL]
    ]
    assert holders == []
