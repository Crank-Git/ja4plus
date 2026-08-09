"""Tests that a functional requirement scoped to a feature set names the cases it binds.

A feature set holds cases of several kinds, and a rule written over all of them binds
cases it was never written for. `FR-pre-release-validation-26` was such a rule. It read
`No case of this feature set opens a network connection.`, and it came from #414, where
the rule is correct and narrow: a case that asserts that `ja4plus/ja4db.py` sends no
request must not itself send one. The install cases of the same feature set install the
built package into a clean environment, so `pip` resolves the shipped dependency list
from a package index. **Every install case therefore had to violate the rule.** #408
found the conflict, #409 measured it, and #419 repaired it.

**The check reads a necessary condition and not a sufficient one.** No parser reads which
cases a sentence means. A requirement that scopes itself to a feature set therefore has
to name at least one path under `tests/` inside backticks. A writer who names the case
file has decided which cases the rule binds, and a reader follows the path. A writer who
names none has left the scope to the reader, which is the defect this file catches.

The three cases below the first one hold the repaired rule in place. #414 depends on it,
so a later writer who drops the recorded transport or the address of the lookup service
from the requirement text fails a case here rather than a review.

These cases read prose. They import nothing from `ja4plus` and they produce no
fingerprint.
"""

from pathlib import Path
import re

REPO_ROOT = Path(__file__).resolve().parent.parent

FEATURES = REPO_ROOT / "docs" / "specs" / "features"

PRE_RELEASE_VALIDATION = FEATURES / "11-pre-release-validation.md"

# A functional requirement opens its own line, as `FR-pre-release-validation-26 — ...`.
# The identifier carries an optional letter, because #411 added `FR-pre-release-validation-16a`.
REQUIREMENT = re.compile(r"^(FR-[a-z0-9-]+-\d+[a-z]?) — (.*)$")

# The scope forms that reach every case of a feature set. `this feature set` is the form
# `FR-pre-release-validation-26` carried. The second form drops the noun phrase and states
# the same scope, as `No case opens a network connection`.
# **The plural reaches the same scope, and the first form of this pattern missed it.** A
# writer who rewrites the repaired rule as `No cases open a network connection` states the
# defect again, so `cases?` carries the pattern. The self-review of #419 found the gap.
SET_SCOPE = re.compile(r"this feature set|\b(?:no|every|each) cases?\b", re.IGNORECASE)

# The named scope: one path under `tests/`, inside backticks.
TEST_PATH = re.compile(r"`tests/[A-Za-z0-9_./-]+`")

# The stand-in of `tests/test_db_offline.py` that records every call a lookup makes. A
# case that asserts that no request happened reads it in place of `requests`.
RECORDED_TRANSPORT = "RecordingRequests"

# The address of the lookup service. `ja4plus/ja4db.py` sends a request to it only for a
# client the operator built with `allow_remote=True`.
LOOKUP_SERVICE_ADDRESS = "ja4db.com"

# The feature documents held this many functional requirements when #419 landed. The base
# commit held 200, and #419 adds `FR-pre-release-validation-26a`, `-26b` and `-26c`. A
# parser that reads nothing passes every case below on an empty list, so the floor fails
# such a parser.
MINIMUM_REQUIREMENTS = 203


def _requirements(page: Path) -> dict[str, str]:
    """Return the identifier and the whole text of every functional requirement of a page.

    Args:
        page: One feature document under `docs/specs/features/`.

    Returns:
        One entry for each requirement, keyed by its identifier. The text joins every
        wrapped line of the requirement into one string.
    """
    found: dict[str, str] = {}
    identifier = ""
    for line in page.read_text(encoding="utf-8").splitlines():
        match = REQUIREMENT.match(line)
        if match:
            identifier = match.group(1)
            found[identifier] = match.group(2).strip()
            continue
        if not identifier:
            continue
        if not line.strip():
            identifier = ""
            continue
        found[identifier] = f"{found[identifier]} {line.strip()}"
    return found


def _every_requirement() -> dict[str, str]:
    """Return every functional requirement of every feature document.

    Returns:
        One entry for each requirement, keyed by its identifier.

    Raises:
        AssertionError: The parser read fewer requirements than the recorded floor.
    """
    found: dict[str, str] = {}
    for page in sorted(FEATURES.glob("*.md")):
        found.update(_requirements(page))
    assert len(found) >= MINIMUM_REQUIREMENTS, (
        f"the parser read {len(found)} requirements, and the floor is {MINIMUM_REQUIREMENTS}"
    )
    return found


def test_a_requirement_scoped_to_a_feature_set_names_a_case_file() -> None:
    """A requirement that binds a whole feature set names one path under `tests/`."""
    unnamed = sorted(
        identifier
        for identifier, text in _every_requirement().items()
        if SET_SCOPE.search(text) and not TEST_PATH.search(text)
    )
    assert unnamed == [], f"these requirements bind a feature set and name no case file: {unnamed}"


def test_the_network_rule_names_the_recorded_transport() -> None:
    """The requirements of Epic 11 name the recorded transport a lookup case reads."""
    text = " ".join(_requirements(PRE_RELEASE_VALIDATION).values())
    assert RECORDED_TRANSPORT in text, (
        f"no requirement of {PRE_RELEASE_VALIDATION.name} names {RECORDED_TRANSPORT}"
    )


def test_the_network_rule_names_the_address_of_the_lookup_service() -> None:
    """The requirements of Epic 11 name the address a lookup case must not reach."""
    text = " ".join(_requirements(PRE_RELEASE_VALIDATION).values())
    assert LOOKUP_SERVICE_ADDRESS in text, (
        f"no requirement of {PRE_RELEASE_VALIDATION.name} names {LOOKUP_SERVICE_ADDRESS}"
    )


def test_a_requirement_permits_the_package_index_for_the_install_cases() -> None:
    """One requirement of Epic 11 permits the install cases to reach a package index."""
    permitting = sorted(
        identifier
        for identifier, text in _requirements(PRE_RELEASE_VALIDATION).items()
        if "package index" in text and "`tests/test_installed_wheel.py`" in text
    )
    assert permitting != [], (
        f"no requirement of {PRE_RELEASE_VALIDATION.name} permits the package index for the "
        "cases of `tests/test_installed_wheel.py`"
    )
