"""Tests that the divergence register records the decryption non-goal of #129.

The maintainer ruled on 2026-08-15 that the non-goal stands, and that ruling named one
reversal condition. `Crank-Git/ja4plus-go` met that condition on 2026-08-16, about two
hours before a worker read it. The maintainer ruled again on the same date, and the
second ruling keeps the non-goal and replaces the condition.

**A reversal condition that fires without a reader is a record that lies to the next
reader.** The row therefore states the measurement that fired it, and it states a
condition a reader can measure. These cases hold the row against both.

**Warning: the row records a capability decline and never a decline of all decryption.**
`ja4plus/utils/quic_utils.py` decrypts a QUIC packet today. The gap is a record
decryptor for TLS over TCP. A case here reads that sentence out of the row, because a
reader who loses it reads the whole non-goal wrong.
"""

from pathlib import Path
import json
import re

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

DEVIATIONS = REPO_ROOT / "tests" / "foxio_deviations.json"

# The heading of the register, and the line that closes it.
# `tests/test_ja4l_quic_point_b_ruling.py` reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The decryption capability the non-goal of #129 declines"

# The issue that holds the non-goal, and the issue that measures the three gaps.
NON_GOAL_ISSUE = "#129"
MEASUREMENT_ISSUE = "#702"

# The three issues of the port that the spent condition names, each beside the moment it
# closed. A read of 2026-08-16 took every timestamp from the tracker.
SPENT_CONDITION_ISSUES = (
    ("Crank-Git/ja4plus-go#492", "2026-08-16T01:50:02Z"),
    ("Crank-Git/ja4plus-go#529", "2026-08-16T01:50:05Z"),
    ("Crank-Git/ja4plus-go#164", "2026-08-16T01:13:03Z"),
)

# The count of register keys the port closes, and the count the spent condition weighed.
PORT_KEY_YIELD = "72"
WEIGHED_COUNT = "about 90"

# The newest release of the port, and the moment the port published it. Every closure
# above postdates it, so no release of the port carries the capability.
PORT_RELEASE = "v1.0.0"
PORT_RELEASE_MOMENT = "2026-08-15T16:56:36Z"

# The module that decrypts a QUIC packet in this project today.
QUIC_MODULE = "ja4plus/utils/quic_utils.py"

# The count of values the port measures behind the record decryptor, and the split of
# that count over the two captures that hold a protected certificate frame.
#
# **Warning: each part of the split is one digit, so a bare substring reads a date and a
# count elsewhere in the row.** The tuple therefore holds the whole phrase.
DECRYPTOR_VALUES = "11 values"
DECRYPTOR_SPLIT = ("holds 9 of them", "holds 2 of them")

# The two captures that hold a protected certificate frame.
DECRYPTOR_CAPTURES = (
    "http2-with-cookies.pcapng",
    "chrome-cloudflare-quic-with-secrets.pcapng",
)

# The issue of this repository that records the interface, and that runs after this row.
INTERFACE_ISSUE = "#593"

# The issue of the port that built the route carrying key material to a fingerprinter,
# beside the moment it closed. #621 requires that the row name it.
ROUTE_ISSUE = "Crank-Git/ja4plus-go#661"
ROUTE_MOMENT = "2026-08-15T06:43:52Z"

# The date of each ruling. The first one stands on the non-goal and the second one
# replaces the reversal condition.
FIRST_RULING = "2026-08-15"
SECOND_RULING = "2026-08-16"


def _register_row() -> str:
    """Return the register row that records the decryption non-goal.

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


def test_the_register_holds_a_row_for_the_decryption_non_goal() -> None:
    """The divergence register holds the row that records the non-goal."""
    assert RULING_ITEM in _register_row()


def test_the_register_names_the_non_goal_and_the_measurement_issue() -> None:
    """The row names the issue that holds the non-goal and the issue that measures it."""
    row = _register_row()
    assert NON_GOAL_ISSUE in row
    assert MEASUREMENT_ISSUE in row


def test_the_register_names_each_port_issue_of_the_spent_condition() -> None:
    """The row names all three port issues the superseded condition names."""
    row = _register_row()
    absent = [issue for issue, _ in SPENT_CONDITION_ISSUES if f"`{issue}`" not in row]
    assert absent == [], f"the row names none of these issues: {absent}"


def test_the_register_states_the_moment_each_port_issue_closed() -> None:
    """The row states the closure moment of each of the three port issues."""
    row = _register_row()
    absent = [moment for _, moment in SPENT_CONDITION_ISSUES if moment not in row]
    assert absent == [], f"the row states none of these moments: {absent}"


def test_the_register_states_that_the_spent_condition_is_replaced() -> None:
    """The row states that the earlier condition fired in form, and that this row replaces it."""
    row = _register_row()
    assert "in form and not in substance" in row
    assert "replaces" in row


def test_the_register_quotes_the_spent_condition_rather_than_deletes_it() -> None:
    """The row quotes the superseded condition, because the standard bars a rewrite.

    `.claude/rules/ste.md` reproduces a quote verbatim. A row that deletes the condition
    leaves a reader with no way to tell which condition the maintainer replaced.
    """
    row = _register_row()
    quoted = (
        "Read this ruling again when `Crank-Git/ja4plus-go#492`, `#529` and `#164` "
        "have shipped and measured their yield."
    )
    assert quoted in row


def test_the_register_states_the_first_part_of_the_new_condition() -> None:
    """The row requires a release of the port, and it bars a merge into a branch.

    **A row that states the release and omits the bar reads the opposite way to a
    reader of the port**, because the port merges into an integration branch weekly.
    This case therefore reads the exclusion and never the word `release` alone.
    """
    row = _register_row()
    assert "published tag" in row
    assert "A merge into an integration branch meets no part of this condition." in row


def test_the_register_states_the_second_part_of_the_new_condition() -> None:
    """The row requires a second measurement against the corpus of this project."""
    row = _register_row()
    assert PORT_KEY_YIELD in row
    assert f"{register_keys()} keys" in row
    assert f"{capture_count()} captures" in row


def test_the_register_states_the_count_the_spent_condition_weighed() -> None:
    """The row states the count the earlier ruling weighed against the measured one."""
    assert WEIGHED_COUNT in _register_row()


def test_the_register_states_that_no_release_of_the_port_carries_the_capability() -> None:
    """The row names the newest release of the port and the moment it published it."""
    row = _register_row()
    assert f"`{PORT_RELEASE}`" in row
    assert PORT_RELEASE_MOMENT in row


def test_the_register_states_that_this_project_decrypts_a_quic_packet() -> None:
    """The row names the module that decrypts a QUIC packet today.

    A reader who takes the non-goal as a decline of all decryption reads it wrong, and
    this sentence is the one guard against that reading.
    """
    assert f"`{QUIC_MODULE}`" in _register_row()


def test_the_module_that_decrypts_a_quic_packet_exists() -> None:
    """`ja4plus/utils/quic_utils.py` stands where the row names it."""
    assert (REPO_ROOT / QUIC_MODULE).is_file()


def test_the_register_states_the_three_gaps_the_measurement_issue_holds() -> None:
    """The row names the record decryptor, the HPACK decoder and the QPACK decoder."""
    row = _register_row()
    assert "HPACK" in row
    assert "QPACK" in row
    assert "record decryptor" in row


def test_the_register_states_the_count_behind_the_record_decryptor() -> None:
    """The row states 11 values, and it splits them over the two captures."""
    row = _register_row()
    assert DECRYPTOR_VALUES in row
    for part in DECRYPTOR_SPLIT:
        assert part in row
    for capture in DECRYPTOR_CAPTURES:
        assert f"`{capture}`" in row


def test_each_capture_the_row_names_stands_in_the_vector_directory() -> None:
    """Both captures the row names hold a file under `tests/foxio_vectors/`."""
    absent = [name for name in DECRYPTOR_CAPTURES if not (VECTORS / name).is_file()]
    assert absent == [], f"the vector directory holds none of these captures: {absent}"


def test_the_register_names_both_rulings_by_date() -> None:
    """The row names the ruling that stands and the ruling that replaces the condition."""
    row = _register_row()
    assert FIRST_RULING in row
    assert SECOND_RULING in row


def test_the_register_names_the_port_issue_that_built_the_route() -> None:
    """The row names the port issue that carries key material to a fingerprinter.

    #621 requires this name, because that issue is where the port crossed the boundary
    #129 holds. A row that omits it states a capability gap and names no cause.
    """
    row = _register_row()
    assert f"`{ROUTE_ISSUE}`" in row
    assert ROUTE_MOMENT in row


def test_the_register_leaves_the_interface_to_the_issue_that_records_it() -> None:
    """The row names the issue that records the interface, and it writes no interface."""
    assert INTERFACE_ISSUE in _register_row()


def register_keys() -> int:
    """Return the count of entries the FoxIO deviation register holds.

    Returns:
        The count of keys of `tests/foxio_deviations.json`.
    """
    register = json.loads(DEVIATIONS.read_text(encoding="utf-8"))
    return len(register)


def capture_count() -> int:
    """Return the count of FoxIO captures this project holds.

    Returns:
        The count of `.pcap` files and `.pcapng` files under `tests/foxio_vectors/`.
    """
    return len(list(VECTORS.glob("*.pcap"))) + len(list(VECTORS.glob("*.pcapng")))


def test_every_entry_of_the_non_goal_records_a_capability_decline() -> None:
    """Each register entry that names #129 carries `"capability": true`.

    A capability decline records a scope this project chose. No implementation change
    closes one, so the reversal condition of this row is the one path that removes them.
    """
    register = json.loads(DEVIATIONS.read_text(encoding="utf-8"))
    owned = [key for key, entry in register.items() if entry.get("issue") == 129]
    assert owned != [], "no entry of the deviation register names #129"
    wrong = [key for key in owned if register[key].get("capability") is not True]
    assert wrong == [], f"these entries of #129 record no capability decline: {wrong}"


def test_the_register_states_the_count_of_entries_the_non_goal_owns() -> None:
    """The row states the count of deviation entries that name #129."""
    register = json.loads(DEVIATIONS.read_text(encoding="utf-8"))
    owned = [key for key, entry in register.items() if entry.get("issue") == 129]
    assert f"{len(owned)} entries" in _register_row()
