"""Tests that the divergence register records the key-material interface of the port.

`Crank-Git/ja4plus-go` exports eight names that carry key material into a fingerprint,
and this project exports none of them. #593 records the answer of this project, and #621
records the capability decline the answer follows.

**An interface that carries key material has no consumer while the capability stays
declined.** The row therefore declines the eight names, and it states the same two-part
reversal condition as the #621 row.

**Warning: the reversal condition of 2026-08-15 is spent, and the row states it nowhere
as pending.** https://github.com/Crank-Git/ja4plus/issues/621#issuecomment-5306066957
holds the replacement. A case here reads the spent sentence out of the row.

Four measurements stand behind the row, and a case here holds each one. The port names,
the `scapy` reading of a Decryption Secrets Block, the decryption this project already
holds, and the key material the corpus carries.

These cases read prose, one capture and the installed `scapy`. They build no fingerprint,
and they import no file of the port.
"""

from pathlib import Path
import re
import struct

import scapy.utils

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

DEVIATIONS = REPO_ROOT / "tests" / "foxio_deviations.json"

# The heading of the register, and the line that closes it.
# `tests/test_decryption_non_goal_ruling.py` reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The key-material interface that the port ships first"

# The issue that records the interface, and the issue that records the capability.
INTERFACE_ISSUE = "#593"
CAPABILITY_ISSUE = "#621"

# The eight names the port exports, each beside the line of `types.go` that states it.
# A read of 2026-08-16 took every line from the `dev` branch of the port, from its
# `master` branch, and from its `v1.0.0` tag. All three hold the same eight lines.
#
# **Warning: this repository edits no file of the port, and no case here reads one.**
# The row carries the reading, and these constants hold the row to it.
PORT_NAMES = (
    ("ErrNoSecret", "types.go:111"),
    ("KeyLog", "types.go:126"),
    ("ParseKeyLog", "types.go:139"),
    ("ReadKeyLogFromCapture", "types.go:157"),
    ("Secret", "types.go:201"),
    ("ClientRandoms", "types.go:218"),
    ("Len", "types.go:239"),
    ("DecryptQUICPacket", "types.go:256"),
)

# The release of the port that already carries all eight names, and the moment the port
# published it.
PORT_RELEASE = "v1.0.0"
PORT_RELEASE_MOMENT = "2026-08-15T16:56:36Z"

# The sentence the spent condition gave. The row of #621 quotes it, and this row states
# it nowhere as pending.
SPENT_CONDITION = "Read this ruling again when"

# The date of the ruling that replaced the spent condition.
SECOND_RULING = "2026-08-16"

# Each part of the new reversal condition, as the row states it.
FIRST_PART = "the port cuts a release that carries the capability"
SECOND_PART = "against its own corpus"

# The version of `scapy` the reading measured, and the pin of this project.
SCAPY_VERSION = "scapy 2.7.0"
SCAPY_PIN = "scapy>=2.4.0"

# The pcapng block type that carries key material, and the secrets type of a key log.
DSB_BLOCK_TYPE = 10
KEY_LOG_SECRETS_TYPE = 0x544C534B

# The two citations of `scapy` that the row states. A line number belongs to one version,
# so the row names the version beside them and no case here reads either line.
SCAPY_CITATIONS = ("scapy/utils.py:1645", "scapy/utils.py:1958")

# The module the port reads a capture with, and the two lines that read the block. A read
# of 2026-08-16 took both from the module cache of this machine. No case here reads a Go
# file, because parity rule 3 bars a test that reads the port.
PORT_CAPTURE_MODULE = "github.com/gopacket/gopacket v1.7.1"
PORT_CAPTURE_CITATIONS = ("pcapgo/pcapng.go:43", "pcapgo/ngread.go:360")

# The capture of the corpus that carries key material, and what its one block holds.
SECRETS_CAPTURE = "chrome-cloudflare-quic-with-secrets.pcapng"
SECRETS_BLOCK_COUNT = 1
SECRETS_LINE_COUNT = 10
SECRETS_CONNECTION_COUNT = 2

# The warning `scapy` writes for that capture, because this project loads no TLS session.
SCAPY_WARNING = "PcapNg: TLS Key Log available, but the TLS layer is not loaded!"

# The three citations of this project that the row states, each beside the text of the
# line. A case reads every one of them, so a move of the code fails a case here.
PROJECT_CITATIONS = (
    ("ja4plus/utils/quic_utils.py", 96, "def derive_initial_secrets("),
    ("ja4plus/utils/quic_utils.py", 208, "def decrypt_initial_payload("),
    ("ja4plus/cli.py", 527, "from scapy.utils import PcapReader"),
    ("ja4plus/__init__.py", 116, "__all__ = ["),
    ("pyproject.toml", 46, '"scapy>=2.4.0",'),
)


def _register_row() -> str:
    """Return the register row that records the key-material interface.

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


def test_the_register_holds_a_row_for_the_key_material_interface() -> None:
    """The divergence register holds the row that records the interface."""
    assert RULING_ITEM in _register_row()


def test_the_register_names_the_interface_issue_and_the_capability_issue() -> None:
    """The row names the issue of the interface and the issue of the capability."""
    row = _register_row()
    assert INTERFACE_ISSUE in row
    assert CAPABILITY_ISSUE in row


def test_the_register_names_every_exported_name_of_the_port() -> None:
    """The row names all eight names the port exports."""
    row = _register_row()
    absent = [name for name, _ in PORT_NAMES if f"`{name}`" not in row]
    assert absent == [], f"the row names none of these: {absent}"


def test_the_register_states_the_line_of_each_exported_name() -> None:
    """The row states the file and the line of each of the eight names."""
    row = _register_row()
    absent = [citation for _, citation in PORT_NAMES if f"`{citation}`" not in row]
    assert absent == [], f"the row states none of these citations: {absent}"


def test_the_register_states_that_a_release_of_the_port_carries_the_names() -> None:
    """The row states the release of the port that already carries the eight names."""
    row = _register_row()
    assert PORT_RELEASE in row
    assert PORT_RELEASE_MOMENT in row


def test_the_register_declines_the_eight_names() -> None:
    """The row records a decline of the eight names."""
    row = _register_row()
    assert "declines the eight names" in row


def test_the_register_states_the_first_part_of_the_reversal_condition() -> None:
    """The row states part 1 of the reversal condition that #621 gives."""
    assert FIRST_PART in _register_row()


def test_the_register_states_the_second_part_of_the_reversal_condition() -> None:
    """The row states part 2 of the reversal condition that #621 gives."""
    assert SECOND_PART in _register_row()


def test_the_register_states_the_spent_condition_nowhere_as_pending() -> None:
    """The row repeats no part of the reversal condition of 2026-08-15.

    The condition of 2026-08-15 fired on 2026-08-16, before a reader of this project
    read it. A row that states it as pending reads wrong to the next reader.
    """
    row = _register_row()
    assert SPENT_CONDITION not in row
    assert SECOND_RULING in row


def test_the_register_states_the_scapy_reading_of_a_secrets_block() -> None:
    """The row states that `scapy` surfaces a Decryption Secrets Block."""
    row = _register_row()
    assert SCAPY_VERSION in row
    assert f"`{SCAPY_PIN}`" in row
    absent = [citation for citation in SCAPY_CITATIONS if f"`{citation}`" not in row]
    assert absent == [], f"the row states none of these citations: {absent}"


def test_the_register_states_the_capture_module_the_port_reads_today() -> None:
    """The row states the module the port reads a capture with, and its two lines.

    The issue body of #593 reads `github.com/google/gopacket` at `v1.1.19`, which
    surfaces no Decryption Secrets Block. The port moved to another module, so the row
    records the module it pins today.
    """
    row = _register_row()
    assert f"`{PORT_CAPTURE_MODULE}`" in row
    absent = [citation for citation in PORT_CAPTURE_CITATIONS if f"`{citation}`" not in row]
    assert absent == [], f"the row states none of these citations: {absent}"


def test_the_installed_scapy_reads_the_block_type_that_carries_key_material() -> None:
    """The installed `scapy` maps the pcapng block type of key material to a reader.

    A line number belongs to one version of `scapy`, so this case reads the reader by
    name. The row carries the two line numbers, beside the version they belong to.
    """
    assert hasattr(scapy.utils.RawPcapNgReader, "_read_block_dsb")


def test_the_register_states_the_decryption_this_project_already_holds() -> None:
    """The row states that this project decrypts a QUIC Initial packet today."""
    row = _register_row()
    assert "reads no key material" in row
    assert "Initial packet" in row


def test_the_register_states_each_citation_of_this_project() -> None:
    """The row states the file and the line of each measurement of this project."""
    row = _register_row()
    absent = [
        f"{path}:{number}"
        for path, number, _ in PROJECT_CITATIONS
        if f"`{path}:{number}`" not in row
    ]
    assert absent == [], f"the row states none of these citations: {absent}"


def test_each_citation_of_this_project_reads_the_line_the_row_states() -> None:
    """Each line the row cites holds the text the measurement read."""
    wrong = []
    for path, number, text in PROJECT_CITATIONS:
        lines = (REPO_ROOT / path).read_text(encoding="utf-8").splitlines()
        if number > len(lines) or not lines[number - 1].strip().startswith(text):
            wrong.append(f"{path}:{number}")
    assert wrong == [], f"these lines hold other text than the row states: {wrong}"


def _secrets_blocks() -> list[bytes]:
    """Return the body of every Decryption Secrets Block of the secrets capture.

    Returns:
        One byte string for each block of type 10, without the block header and without
        the trailing length field.

    Raises:
        AssertionError: The capture holds no Section Header Block.
    """
    data = (VECTORS / SECRETS_CAPTURE).read_bytes()
    assert data[:4] == b"\x0a\x0d\x0d\x0a", f"{SECRETS_CAPTURE} opens with no Section Header Block"

    endian = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    blocks: list[bytes] = []
    offset = 0
    while offset + 12 <= len(data):
        block_type, block_length = struct.unpack(endian + "II", data[offset : offset + 8])
        if block_length < 12 or offset + block_length > len(data):
            break
        if block_type == DSB_BLOCK_TYPE:
            blocks.append(data[offset + 8 : offset + block_length - 4])
        offset += block_length
    return blocks


def test_the_corpus_capture_holds_the_secrets_block_the_row_states() -> None:
    """The secrets capture holds one Decryption Secrets Block of the key log type."""
    blocks = _secrets_blocks()
    assert len(blocks) == SECRETS_BLOCK_COUNT
    secrets_type, secrets_length = struct.unpack("<II", blocks[0][:8])
    assert secrets_type == KEY_LOG_SECRETS_TYPE
    secrets = blocks[0][8 : 8 + secrets_length]
    lines = secrets.splitlines()
    assert len(lines) == SECRETS_LINE_COUNT

    # The second field of a line of the NSS key log format holds the client random, and
    # one client random names one connection. The row states the connection count, so a
    # case reads it here.
    randoms = {line.split()[1] for line in lines if len(line.split()) > 1}
    assert len(randoms) == SECRETS_CONNECTION_COUNT


def test_the_register_states_what_the_corpus_capture_carries() -> None:
    """The row states the capture that carries key material, and what its block holds."""
    row = _register_row()
    assert SECRETS_CAPTURE in row
    assert SCAPY_WARNING in row
    assert f"{SECRETS_LINE_COUNT} lines" in row
    assert f"{SECRETS_CONNECTION_COUNT} connections" in row


def test_the_capture_the_row_names_stands_in_the_vector_directory() -> None:
    """The vector directory holds the capture the row names."""
    assert (VECTORS / SECRETS_CAPTURE).is_file()


def test_this_project_exports_none_of_the_eight_names() -> None:
    """The public interface of this project holds none of the eight names of the port."""
    import ja4plus

    present = [name for name, _ in PORT_NAMES if name in ja4plus.__all__]
    assert present == [], f"this project exports these names of the port: {present}"


def test_the_register_states_that_the_row_moves_no_fingerprint_value() -> None:
    """The row states that it moves no fingerprint value and no register entry."""
    row = _register_row()
    assert "moves no fingerprint value" in row
    assert "`tests/foxio_deviations.json`" in row


def test_the_register_names_the_module_that_holds_it() -> None:
    """The row names the test module that holds every measurement it states."""
    assert "`tests/test_key_log_interface_ruling.py`" in _register_row()
