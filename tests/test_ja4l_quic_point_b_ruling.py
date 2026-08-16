"""The QUIC point B ruling the divergence register records under #625.

The four FoxIO references state four mechanisms for the packet that fills point B of a
QUIC connection, and no two of the four state the same one. Two read the first server
Initial packet, one reads the Initial packet that completes the ServerHello, and one
reads every server Initial packet so that the last one stands.

**A ruling a later round re-reads must rest on a measurement that reproduces.** The
ruling of 2026-08-15 recorded two abstentions, a read of 2026-08-16 measured that neither
reference abstains, and the maintainer ruled again on 2026-08-16. These cases hold the
register row against every mechanism it states, so a row that returns to the abstentions
fails a case here.

The outcome is unchanged: no majority carries a change, and `ja4plus` keeps the Initial
packet that completes the ServerHello.
"""

from pathlib import Path
import json
import re

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

FINGERPRINTER = REPO_ROOT / "ja4plus" / "fingerprinters" / "ja4l.py"

# The heading of the register, and the line that closes it.
# `tests/test_ja4l_timing_fork_ruling.py` reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The QUIC packet that fills JA4L point B"

# Each reference, beside the citation the row states for its mechanism. The row states
# four mechanisms and no abstention, because a read of 2026-08-16 found none.
MECHANISM_CITATIONS = (
    ("FoxIO Python", "`python/ja4.py:580-581`"),
    ("FoxIO Rust", "`rust/ja4/src/time/udp.rs:287-291`"),
    ("FoxIO Rust", "`rust/ja4/src/time/udp.rs:107-122`"),
    ("FoxIO Rust", "`rust/ja4/src/time/udp.rs:156-158`"),
    ("FoxIO Zeek", "`zeek/ja4l/main.zeek:213-234`"),
    ("Wireshark", "`wireshark/source/packet-ja4.c:1418-1422`"),
)

# The Zeek analyzer raises one event for each Initial packet, and that reading is what
# makes the Zeek mechanism a third one rather than an abstention.
ZEEK_EVENT_CITATION = "`src/analyzer/protocol/quic/QUIC.evt:13`"

# The sentence the ruling of 2026-08-15 stated as its reason. The row quotes it, because
# `.claude/rules/ste.md` bars a rewrite of a record.
SUPERSEDED_SENTENCE = "One reference against one reference is not a majority."

# The three citations of `ja4plus/fingerprinters/ja4l.py` the row states.
FINGERPRINTER_CITATIONS = (
    "`ja4plus/fingerprinters/ja4l.py:516-556`",
    "`ja4plus/fingerprinters/ja4l.py:548-549`",
    "`ja4plus/fingerprinters/ja4l.py:554-556`",
)

# The transcription gap that let two live mechanisms enter the ruling table of
# 2026-08-15 as abstentions.
TRANSCRIPTION_GAP_PAGE = "`docs/specs/foxio/JA4L.md`"

# The connection where the two readings disagree, and the connection where a reader
# expects a disagreement and the measurement finds none.
FORKED_CAPTURE = "tls3.pcapng"
FORKED_PORT = "61884"
FORKED_LOCAL_VALUE = "3583_57_quic"
FORKED_PYTHON_VALUE = "3583_57"
FORKED_WIRESHARK_VALUE = "3051_57_quic"

AGREEING_CAPTURE = "ssh2.pcapng"
AGREEING_PORT = "51810"
AGREEING_PYTHON_VALUE = "16192_57"
AGREEING_WIRESHARK_VALUE = "16192_57_quic"


def _register_row() -> str:
    """Return the register row that records the QUIC point B ruling.

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


def _python_vector_value(capture: str, source_port: str) -> str | None:
    """Return the `JA4L-S` value the FoxIO Python file holds for one connection.

    Args:
        capture: The file name of the capture.
        source_port: The client port that names the connection.

    Returns:
        The value, or None where the file holds none.
    """
    records = json.loads((VECTORS / f"{capture}.json").read_text(encoding="utf-8"))
    for record in records:
        if record.get("srcport") == source_port and "JA4L-S" in record:
            return str(record["JA4L-S"])
    return None


def test_the_register_holds_a_row_for_the_point_b_ruling() -> None:
    """The divergence register holds the row that records the ruling."""
    assert RULING_ITEM in _register_row()


def test_the_register_states_a_mechanism_for_every_reference() -> None:
    """The row cites the mechanism of all four references, and it records no abstention."""
    row = _register_row()
    absent = [
        f"{reference} {citation}"
        for reference, citation in MECHANISM_CITATIONS
        if citation not in row
    ]
    assert absent == [], f"the row cites no mechanism for these: {absent}"


def test_the_register_names_the_zeek_event_that_fires_once_per_packet() -> None:
    """The row cites the Zeek event definition, which makes Zeek a third mechanism.

    A reader who drops this citation loses the reason the Zeek reading is a mechanism
    rather than an abstention, which is the defect the ruling of 2026-08-16 repaired.
    """
    assert ZEEK_EVENT_CITATION in _register_row()


def test_the_register_quotes_the_superseded_reason_rather_than_deleting_it() -> None:
    """The row quotes the sentence the ruling of 2026-08-15 gave as its reason."""
    assert SUPERSEDED_SENTENCE in _register_row()


def test_the_register_names_both_ruling_dates() -> None:
    """The row names the date of the first ruling and the date of the correction."""
    row = _register_row()
    assert "2026-08-15" in row
    assert "2026-08-16" in row


def test_the_register_states_that_no_majority_carries_a_change() -> None:
    """The row states the reason the reading stands, and it names the plurality."""
    row = _register_row()
    assert "plurality" in row
    assert "majority" in row


def test_the_register_carries_the_three_measured_fingerprinter_citations() -> None:
    """The row cites the function, the ServerHello test and the emission."""
    row = _register_row()
    absent = [citation for citation in FINGERPRINTER_CITATIONS if citation not in row]
    assert absent == [], f"the row states none of these citations: {absent}"


def test_the_register_names_the_transcription_gap_of_the_ja4l_page() -> None:
    """The row names the page that transcribes no QUIC point B rule."""
    assert TRANSCRIPTION_GAP_PAGE in _register_row()


def test_the_register_states_that_the_ruling_decides_nothing_about_the_emission() -> None:
    """The row names #606 and bars a reader from taking this row as a decision about it."""
    assert "#606" in _register_row()


def test_the_fingerprinter_fills_point_b_on_the_serverhello_packet() -> None:
    """`_quic_server_initial` returns while the ServerHello is incomplete.

    The row cites the three line ranges of this file, and a change above them moves every
    one. This case reads the statement rather than the line, so it names the loss.
    """
    lines = FINGERPRINTER.read_text(encoding="utf-8").splitlines()
    assert lines[547].strip() == "if not server_hello_is_complete(collected):"
    assert lines[548].strip() == "return None"
    assert lines[551].strip() == 'timestamps["B"] = now'


def test_the_two_vector_sets_disagree_on_the_connection_the_row_names() -> None:
    """The FoxIO Python file and the Wireshark file read different packets on `tls3.pcapng`."""
    assert _python_vector_value(FORKED_CAPTURE, FORKED_PORT) == FORKED_PYTHON_VALUE
    wireshark = (VECTORS / "wireshark_expected" / f"{FORKED_CAPTURE}.json").read_text(
        encoding="utf-8"
    )
    assert f'"{FORKED_WIRESHARK_VALUE}"' in wireshark


def test_the_two_vector_sets_agree_on_the_second_quic_connection_of_ssh2() -> None:
    """The two files read one packet on `ssh2.pcapng` stream 33, so no value moves there.

    The ruling of 2026-08-16 names this connection among the two a move would reach. The
    row records the measurement instead, because the timing part of the two files agrees.
    """
    assert _python_vector_value(AGREEING_CAPTURE, AGREEING_PORT) == AGREEING_PYTHON_VALUE
    wireshark = (VECTORS / "wireshark_expected" / f"{AGREEING_CAPTURE}.json").read_text(
        encoding="utf-8"
    )
    assert f'"{AGREEING_WIRESHARK_VALUE}"' in wireshark


def test_the_register_states_the_value_this_project_writes_on_the_forked_connection() -> None:
    """The row states the value `ja4plus` writes where the two readings disagree."""
    assert f"`JA4L-S={FORKED_LOCAL_VALUE}`" in _register_row()
