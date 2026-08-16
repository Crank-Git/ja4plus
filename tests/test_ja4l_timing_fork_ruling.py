"""The permanent JA4L timing fork the divergence register records under #622.

`chrome-cloudflare-quic-with-secrets.pcapng` stream `0:50280` carries four FoxIO
readings of one `JA4L-S` value, and they split two against two. FoxIO Python and the
FoxIO Zeek package read 10990. The Wireshark dissector and the FoxIO Rust snapshot read
9285. `ja4plus` matches the first pair and `Crank-Git/ja4plus-go` matches the second.

**A ruling that lives only in a closed issue is a ruling the next reader reverses by
accident.** These cases hold the register row against the four readings it states. A
vector refresh that moves one reading fails a case here, and so does a deletion of the
row.

The maintainer ruled on 2026-08-15 that this project declines to converge. The fork is
permanent, and a reversal changes both repositories.
"""

from pathlib import Path
import json
import re

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

# The heading of the register, and the line that closes it.
# `tests/test_ja4t_syn_selection_ruling.py` reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The JA4L-S timing part where the two FoxIO vector sets disagree"

# The capture and the source port that name the ruled connection.
CAPTURE = "chrome-cloudflare-quic-with-secrets.pcapng"
RULED_PORT = "50280"

# The value `ja4plus` publishes for that connection, and the value the port publishes.
LOCAL_VALUE = "JA4L-S=10990_56_quic"
PORT_VALUE = "9285_56_quic"

# Each FoxIO reading of the ruled value, beside the file this repository reads it from.
# The Zeek reading sits in prose, so the tuple names its page and the other three name a
# machine-readable file.
READINGS = (
    ("10990_56", "FoxIO Python"),
    ("10990_56_q", "FoxIO Zeek"),
    ("9285_0_quic", "Wireshark"),
    ("9285_56", "FoxIO Rust"),
)

# The register entry that already declines the value, and the issue that owns it.
DEVIATION_KEY = "chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4L-S.1"
DEVIATION_ISSUE = 225


def _register_row() -> str:
    """Return the register row that records the timing fork.

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


def test_the_register_holds_a_row_for_the_timing_fork() -> None:
    """The divergence register holds the row that records the fork."""
    assert RULING_ITEM in _register_row()


def test_the_register_states_the_value_each_port_publishes() -> None:
    """The row states the value of this project and the value of the port."""
    row = _register_row()
    assert f"`{LOCAL_VALUE}`" in row
    assert f"`{PORT_VALUE}`" in row


def test_the_register_states_all_four_foxio_readings() -> None:
    """The row states each of the four readings that split two against two."""
    row = _register_row()
    absent = [value for value, _ in READINGS if f"`{value}`" not in row]
    assert absent == [], f"the row states none of these readings: {absent}"


def test_the_register_names_the_ruling_and_the_issue_of_the_port() -> None:
    """The row names the date of the ruling and the issue the ruling makes permanent."""
    row = _register_row()
    assert "2026-08-15" in row
    assert "`Crank-Git/ja4plus-go#249`" in row


def test_the_register_names_the_scope_one_move_of_this_project_reaches() -> None:
    """The row names the function that fills the server measurement point."""
    assert "`_quic_server_initial`" in _register_row()


def test_the_foxio_python_file_holds_the_reading_the_row_states() -> None:
    """The FoxIO Python expected-output file reads `10990_56` for the ruled connection."""
    records = json.loads((VECTORS / f"{CAPTURE}.json").read_text(encoding="utf-8"))
    values = [
        record["JA4L-S"]
        for record in records
        if record.get("srcport") == RULED_PORT and "JA4L-S" in record
    ]
    assert values == ["10990_56"]


def test_the_wireshark_file_holds_the_reading_the_row_states() -> None:
    """The Wireshark expected-output file reads `9285_0_quic` for the ruled connection."""
    text = (VECTORS / "wireshark_expected" / f"{CAPTURE}.json").read_text(encoding="utf-8")
    assert '"9285_0_quic"' in text


def test_the_rust_snapshot_holds_the_reading_the_row_states() -> None:
    """The FoxIO Rust snapshot reads `9285_56` for the ruled connection."""
    snapshot = VECTORS / "rust_expected" / f"ja4__insta@{CAPTURE}.snap"
    assert "ja4l_s: 9285_56" in snapshot.read_text(encoding="utf-8")


def test_the_zeek_page_holds_the_reading_the_row_states() -> None:
    """`docs/specs/foxio/zeek.md` reads `10990_56_q` for a QUIC connection."""
    page = REPO_ROOT / "docs" / "specs" / "foxio" / "zeek.md"
    assert "`10990_56_q`" in page.read_text(encoding="utf-8")


def test_the_four_readings_split_two_against_two() -> None:
    """Two readings carry the timing part 10990 and two carry 9285."""
    parts = [value.split("_")[0] for value, _ in READINGS]
    assert parts.count("10990") == 2
    assert parts.count("9285") == 2


def test_the_deviation_register_declines_the_value_under_the_earlier_ruling() -> None:
    """`tests/foxio_deviations.json` already declines the value, and #225 owns it."""
    register = json.loads(
        (REPO_ROOT / "tests" / "foxio_deviations.json").read_text(encoding="utf-8")
    )
    assert register[DEVIATION_KEY]["issue"] == DEVIATION_ISSUE
    assert register[DEVIATION_KEY]["decided"] is True
    assert register[DEVIATION_KEY]["capability"] is False


def test_a_case_of_the_rust_parity_module_reads_the_ja4l_snapshot_value() -> None:
    """`SNAPSHOT_METHODS` names both JA4L methods, so a case reads the Rust reading.

    #638 held the finding that the Rust reading reached no case, and it closed on
    2026-08-15. A reader who removes either method from the tuple leaves the reading
    unread again, and this case names that loss.
    """
    module = (REPO_ROOT / "tests" / "test_foxio_rust_parity.py").read_text(encoding="utf-8")
    assert 'SNAPSHOT_LATENCY_METHODS = (("JA4L-C", "ja4l_c"), ("JA4L-S", "ja4l_s"))' in module
    assert "*SNAPSHOT_LATENCY_METHODS)" in module
