"""Tests that an acceptance criterion which states a count states the count measured today.

An acceptance criterion is the definition of done. A criterion that states a count nobody
measures goes stale the moment the repository changes, and a reader who runs it reads a
failure. That reader then learns to disregard the page. #424 and #426 repaired the same
failure mode for the suite, and #393 found it again on two criteria of
`docs/specs/features/*.md`. This project has corrected a stale count in prose more than
seven times, so the repair here is a case and not a corrected count.

**A criterion holds one of two kinds, and this file reads both.** A built criterion states
the count this repository holds today. Its stated count must equal the measured count. A
pending criterion states an end state that an open issue builds. Its stated count must
differ from the measured count. A pending criterion therefore fails here on the day its
issue lands, and that failure instructs a writer to drop the end-state marker.

`tests/test_requirement_scope.py` and `tests/test_specification_changelog.py` set the shape
these cases follow. They read specification text as text.

These cases read prose. They import nothing from `ja4plus` and they produce no fingerprint.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional
import re
import subprocess

REPO_ROOT = Path(__file__).resolve().parent.parent

FEATURES = REPO_ROOT / "docs" / "specs" / "features"

# An acceptance criterion opens its own line, as `- [ ] ...`. A writer ticks the box on a
# built criterion, so the pattern accepts both states.
CRITERION = re.compile(r"^- \[[ x]\] (.*)$")

# The feature pages wrap a criterion at six spaces of indent. A wrapped line joins the
# criterion above it.
CONTINUATION = re.compile(r"^ {6}(\S.*)$")

CRITERIA_HEADING = "## Acceptance criteria"

# Any heading closes the criteria section. `docs/specs/features/09-release.md` puts a
# sub-heading inside that section, and a reader that watched for `## ` alone would carry on
# past it and read a later list as criteria.
HEADING = re.compile(r"^#{1,6} ")

# The feature pages held this many criteria across eleven documents when #456 landed. A
# parser that reads nothing passes every comparison below on an empty list, so the floor
# fails such a parser.
MINIMUM_CRITERIA = 151

# The version string of the released package. `docs/specs/features/09-release.md` states a
# criterion against it, and #67 owns the work that reduces the count.
RELEASED_VERSION = re.compile(r"0\.6\.0")

# A criterion writes a small count as a word and a large one as a digit. The reader accepts
# both forms. A reader that accepted the digit alone would force a digit into a sentence
# the writing standard keeps readable.
NUMBER_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
}


def _tracked(*pathspecs: str) -> List[str]:
    """Return the tracked path of every file the pathspecs match.

    Args:
        pathspecs: One or more pathspecs for `git ls-files`.

    Returns:
        One path for each tracked file, relative to the repository root.

    Raises:
        AssertionError: The read of the repository failed.
    """
    result = subprocess.run(
        ["git", "ls-files", *pathspecs],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"`git ls-files {' '.join(pathspecs)}` exited {result.returncode}: {result.stderr.strip()}"
    )
    return [line for line in result.stdout.splitlines() if line]


def _vector_files() -> List[str]:
    """Return every tracked file under `tests/foxio_vectors`.

    Returns:
        One path for each file the conformance suite reads.
    """
    return _tracked("tests/foxio_vectors")


def _version_files() -> List[str]:
    """Return every tracked file of `pyproject.toml` and `ja4plus/` that holds the version.

    The criterion of `docs/specs/features/09-release.md` names `grep -rn`. This reader takes
    the file list from `git ls-files` instead. `grep -r` also reads an untracked build
    artifact and a compiled module, so its count depends on what a previous command left in
    the working tree.

    Returns:
        One path for each file whose text holds the released version string.
    """
    holders = []
    for path in _tracked("pyproject.toml", "ja4plus/"):
        text = (REPO_ROOT / path).read_bytes().decode("utf-8", errors="ignore")
        if RELEASED_VERSION.search(text):
            holders.append(path)
    return holders


@dataclass(frozen=True)
class MeasuredCriterion:
    """One acceptance criterion whose count this file measures.

    **The locator identifies the criterion and it carries no count.** A reader that held a
    copy of the sentence would compare that copy against the measurement. The page could
    then state any count. The count therefore comes from the page.

    Attributes:
        page: The file name of the feature document that states the criterion.
        locator: The text that identifies the criterion on the page. It holds no count.
        stated: The pattern that reads the count out of the criterion text, in group 1.
        measure: The reader that returns the things the criterion counts.
        pending_issue: The issue that builds the end state, or None for a built criterion.
    """

    page: str
    locator: str
    stated: "re.Pattern[str]"
    measure: Callable[[], List[str]]
    pending_issue: Optional[str]


MEASURED_CRITERIA = (
    MeasuredCriterion(
        page="00-foundation.md",
        locator="`git ls-files tests/foxio_vectors | wc -l`",
        stated=re.compile(r"reports (\w+) files"),
        measure=_vector_files,
        pending_issue=None,
    ),
    MeasuredCriterion(
        page="09-release.md",
        locator='`grep -rn "0\\.6\\.0" pyproject.toml ja4plus/`',
        stated=re.compile(r"finds the version in (\w+) file"),
        measure=_version_files,
        pending_issue="#67",
    ),
)


def _criteria(page: Path) -> List[str]:
    """Return every acceptance criterion of one feature document, in file order.

    Args:
        page: One feature document under `docs/specs/features/`.

    Returns:
        One string for each criterion. A wrapped criterion joins into one string.
    """
    found: List[str] = []
    inside = False
    for line in page.read_text(encoding="utf-8").splitlines():
        if HEADING.match(line):
            inside = line.strip() == CRITERIA_HEADING
            continue
        if not inside:
            continue
        match = CRITERION.match(line)
        if match:
            found.append(match.group(1).strip())
            continue
        wrapped = CONTINUATION.match(line)
        if wrapped and found:
            found[-1] = f"{found[-1]} {wrapped.group(1).strip()}"
    return found


def _every_criterion() -> List[str]:
    """Return every acceptance criterion of every feature document.

    Returns:
        One string for each criterion.

    Raises:
        AssertionError: The parser read fewer criteria than the recorded floor.
    """
    found: List[str] = []
    for page in sorted(FEATURES.glob("*.md")):
        found.extend(_criteria(page))
    assert len(found) >= MINIMUM_CRITERIA, (
        f"the parser read {len(found)} criteria, and the floor is {MINIMUM_CRITERIA}"
    )
    return found


def _located(entry: MeasuredCriterion) -> str:
    """Return the criterion of the feature page that the locator identifies.

    Args:
        entry: One row of `MEASURED_CRITERIA`.

    Returns:
        The criterion, joined into one string.

    Raises:
        AssertionError: The page holds no such criterion, or it holds more than one.
    """
    matching = [text for text in _criteria(FEATURES / entry.page) if entry.locator in text]
    assert len(matching) == 1, (
        f"{entry.page} holds {len(matching)} criteria for `{entry.locator}`, and one is right"
    )
    return matching[0]


def _stated_count(entry: MeasuredCriterion) -> int:
    """Return the count the criterion states on its feature page.

    Args:
        entry: One row of `MEASURED_CRITERIA`.

    Returns:
        The number the `stated` pattern reads out of the criterion.

    Raises:
        AssertionError: The pattern read no count, or the word names no number.
    """
    text = _located(entry)
    match = entry.stated.search(text)
    assert match is not None, f"{entry.page}: no count reads out of `{entry.locator}`"
    written = match.group(1)
    if written.isdigit():
        return int(written)
    assert written in NUMBER_WORDS, f"{entry.page}: `{written}` names no number"
    return NUMBER_WORDS[written]


def test_the_parser_reads_at_least_the_recorded_floor_of_criteria() -> None:
    """The feature pages hold at least as many acceptance criteria as the recorded floor."""
    found = _every_criterion()
    assert len(found) >= MINIMUM_CRITERIA, (
        f"the parser read {len(found)} criteria, and the floor is {MINIMUM_CRITERIA}"
    )


def test_every_measured_criterion_reaches_the_feature_page_that_states_it() -> None:
    """Each measured criterion appears once on the feature page the table names."""
    wrong = sorted(
        f"{entry.page} holds {len(matching)} criteria for `{entry.locator}`"
        for entry in MEASURED_CRITERIA
        for matching in [[t for t in _criteria(FEATURES / entry.page) if entry.locator in t]]
        if len(matching) != 1
    )
    assert wrong == [], f"these pages state no single criterion for their locator: {wrong}"


def test_every_measurement_reads_at_least_one_file() -> None:
    """Each measurement returns a file, so no comparison below runs over an empty set."""
    empty = sorted(entry.page for entry in MEASURED_CRITERIA if entry.measure() == [])
    assert empty == [], f"these measurements read no file: {empty}"


def test_a_built_criterion_states_the_count_the_repository_holds() -> None:
    """A built criterion states the count its own measurement reports."""
    disagreeing = sorted(
        f"{entry.page} states {_stated_count(entry)} and the repository holds "
        f"{len(entry.measure())}"
        for entry in MEASURED_CRITERIA
        if entry.pending_issue is None and _stated_count(entry) != len(entry.measure())
    )
    assert disagreeing == [], (
        f"these criteria state a count the repository contradicts: {disagreeing}"
    )


def test_a_pending_criterion_names_the_issue_that_builds_its_end_state() -> None:
    """A pending criterion names the end state and names the issue that builds it."""
    unnamed = sorted(
        entry.page
        for entry in MEASURED_CRITERIA
        if entry.pending_issue is not None
        and not ("end state" in _located(entry) and entry.pending_issue in _located(entry))
    )
    assert unnamed == [], f"these criteria state an end state and name no issue: {unnamed}"


def test_a_pending_criterion_states_a_count_the_repository_does_not_hold() -> None:
    """A pending criterion states a count this repository does not report.

    On the day the named issue lands, the two counts agree and this case fails. That
    failure instructs a writer to drop the end-state marker. The writer then records the
    criterion as a built criterion.
    """
    reached = sorted(
        f"{entry.page} states {_stated_count(entry)} and {entry.pending_issue} has landed"
        for entry in MEASURED_CRITERIA
        if entry.pending_issue is not None and _stated_count(entry) == len(entry.measure())
    )
    assert reached == [], f"these criteria state an end state the repository now holds: {reached}"
