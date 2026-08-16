"""Hold `docs/specs/foxio/JA4SSH.md` against the parity harness the repository runs today.

**A page that records an absence goes wrong on the day the suite fills it, and no reader
reported that before this file.** `docs/specs/foxio/JA4SSH.md` carried a section named
`Why the parity harness never compared this value`. #671 built that comparison, and
`tests/test_foxio_rust_parity.py` has held `TestTheJa4sshValuesTheRustSnapshotHolds` since
round 242. The section therefore stated a fact the repository no longer held.

**The section also carried a citation that named a comment.** It cited line 72 of
`tests/test_foxio_rust_parity.py` for the `SNAPSHOT_METHODS` declaration, and #216 moved
that declaration when it added `JA4T`.

**This reader answers a question `tests/foxio_citation_lines.py` does not.** That reader
asks whether the cited lines hold a statement. This one asks whether the page cites the
line that holds the named statement, so a move of either declaration fails a case here
rather than leaving the page to name the wrong line.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

PAGE = REPO_ROOT / "docs" / "specs" / "foxio" / "JA4SSH.md"

PARITY_MODULE = REPO_ROOT / "tests" / "test_foxio_rust_parity.py"

PARITY_MODULE_PATH = "tests/test_foxio_rust_parity.py"

# The heading of the retired section. #683 removed it, and a page that carries it again
# claims an absence the suite fills.
RETIRED_HEADING = "### Why the parity harness never compared this value"

# The class that compares both JA4SSH values of the FoxIO Rust snapshot.
COMPARISON_CLASS = "class TestTheJa4sshValuesTheRustSnapshotHolds:"

# The declaration the retired citation named. The page cites the line that holds it today.
METHOD_TUPLE = "SNAPSHOT_METHODS = ("


def _line_that_opens(prefix: str) -> int:
    """Return the one line number of the parity module whose text opens with the prefix.

    Args:
        prefix: The text the line starts with, after this reader strips it.

    Returns:
        The line number, counted from 1.

    Raises:
        AssertionError: The module holds no such line, or it holds more than one.
    """
    lines = PARITY_MODULE.read_text(encoding="utf-8").splitlines()
    found = [number for number, line in enumerate(lines, 1) if line.strip().startswith(prefix)]
    assert len(found) == 1, f"{PARITY_MODULE_PATH} holds {len(found)} lines that open {prefix!r}"
    return found[0]


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def test_the_page_claims_no_absence_of_the_ja4ssh_comparison():
    """The page holds no heading that states the harness compares neither value."""
    assert RETIRED_HEADING not in _page()


def test_the_page_cites_the_line_that_holds_the_comparison_class():
    """The page names the line of `TestTheJa4sshValuesTheRustSnapshotHolds`."""
    line = _line_that_opens(COMPARISON_CLASS)
    assert f"`{PARITY_MODULE_PATH}:{line}`" in _page()


def test_the_page_cites_the_line_that_holds_the_compared_method_tuple():
    """The page names the line of `SNAPSHOT_METHODS`, which #216 moved off line 72."""
    line = _line_that_opens(METHOD_TUPLE)
    assert f"`{PARITY_MODULE_PATH}:{line}`" in _page()


def test_the_page_cites_no_line_of_the_parity_module_that_holds_no_statement():
    """Every line the page cites of the parity module holds something other than a comment."""
    lines = PARITY_MODULE.read_text(encoding="utf-8").splitlines()
    cited = re.findall(rf"`{re.escape(PARITY_MODULE_PATH)}:(\d+)(?:-(\d+))?`", _page())
    assert cited, "the page cites no line of the parity module"
    for first, last in cited:
        span = lines[int(first) - 1 : int(last or first)]
        held = [text for text in (line.strip() for line in span) if text]
        assert any(not text.startswith("#") for text in held), f"line {first} holds no statement"


def test_the_page_names_the_round_that_ended_the_absence():
    """The page names #671 and round 242, which the Changelog of `docs/specs/spec.md` holds."""
    page = _page()
    assert "#671" in page
    assert "round 242" in page
