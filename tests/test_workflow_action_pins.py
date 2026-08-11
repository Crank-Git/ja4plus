"""Tests that a workflow pin names a commit, and that the prose beside it names that version.

A workflow of this repository pins every third-party action to a commit, because a tag
moves and a moved tag runs code that nobody read. A commit tells a reader no version, so
each `uses:` line carries a version comment beside it.

**A sentence goes stale where a pin moves and the prose stays.** #577 met that state on
three bumps. `.github/workflows/docs-build.yml` named the pair `upload-pages-artifact` v3
with `deploy-pages` v4, `.github/workflows/docs.yml` named the same two numbers, and
`.github/workflows/test.yml` cited `download-artifact/tree/v7.0.0`. Two interface
registers carried `actions/deploy-pages` v4 beside them. Each of those sentences reads as a
measurement, so a reader who trusts one opens the release note of the wrong version.

`tests/test_documentation_publish.py` holds the commit rule over one workflow. These cases
hold it over every workflow, and they add the agreement between a pin and the prose around
it.

## What a case here cannot test

**A case here reads a number and never a release.** A pin that names commit `abc` under the
comment `# v9.9.9` passes every case below, because no case reaches the provider. The
provider holds the true mapping between a tag and a commit, and a worker resolves each pin
there before it writes the line.

**A case here reads a citation against the pins of the whole repository, and never against
the pins of one file.** The first form read one file at a time, and its floor reported that
it collected 3 citations of the 5 this repository holds. `.github/workflows/docs.yml` names
`upload-pages-artifact` and pins it nowhere, and `.github/workflows/docs-build.yml` names
`deploy-pages` and pins it nowhere. Those two sentences are the pair that #577 found stale,
so the reader that missed them was the wrong reader.

**An action that two workflows pin at two major versions reaches no citation case.** No
action of this repository holds that state today. `repository_majors` leaves such an action
out, and it reads neither of the two numbers as the right one.

**A citation that spells the version out reaches no case, and #577 declines the reader that
would catch it.** `stale_citations` matches the form `v5` and never the form `version 5`. A
wider pattern reads a correct sentence as a finding, because a comment of this repository
reports the version another project names. `.github/workflows/docs-build.yml` holds such a
sentence: the usage example of the upstream page still names version 3 of
`actions/upload-pages-artifact`, and this project pins 5.0.0 on purpose.

These cases read configuration and prose. They import nothing from `ja4plus` and they
produce no fingerprint.
"""

from pathlib import Path
import re
from typing import Dict, List, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

WORKFLOW_DIRECTORY = REPO_ROOT / ".github" / "workflows"

# An action reference, as `uses: actions/checkout@3d3c42e...  # v7.0.1`. The version comment
# is optional in the pattern, so a line that carries none reaches
# `test_every_action_of_every_workflow_pins_a_commit_and_names_its_version` as a finding
# rather than as no match at all.
#
# **A local reference reads `uses: ./.github/workflows/docs-build.yml`**, which names no
# owner and no commit. That form moves with the checkout, so this pattern passes over it.
PINNED_ACTION = re.compile(
    r"uses:\s+(?P<name>[A-Za-z0-9][\w.-]*(?:/[\w.-]+)+)@(?P<reference>\S+)"
    r"(?:[^\S\n]+#[^\S\n]*(?P<version>\S+))?"
)

COMMIT = re.compile(r"^[0-9a-f]{40}$")

# A version comment reads `v3`, `v4.0.5` or `v8.0.1`.
VERSION_COMMENT = re.compile(r"^v(\d+)(?:\.\d+)*$")

# The count of characters a citation may hold between the name of an action and the version
# it states. A comment of this repository writes the two together, as
# `download-artifact/tree/v7.0.0` or ``` `deploy-pages` v4 ```. A wider window reads a
# version that belongs to the next sentence.
CITATION_WINDOW = 100

# The floors that fail a reader which collected nothing. A read of 2026-08-10 counts 31
# pinned actions across the five workflows and 6 version citations in their comments. The
# same read names seven actions: `checkout`, `setup-python`, `upload-artifact`,
# `download-artifact`, `upload-pages-artifact`, `deploy-pages` and `gh-action-pypi-publish`.
MINIMUM_PINNED_ACTIONS = 25

MINIMUM_VERSION_CITATIONS = 5

# The workflow that pins the deployment action. `.github/workflows/docs.yml` publishes the
# site, and #66 owns it.
PUBLISH_WORKFLOW = "docs.yml"

DEPLOY_ACTION = "actions/deploy-pages"

# The two records that name an external interface and the version this project pins.
# `.claude/rules/external-apis.md` states the rule and
# `docs/specs/features/08-documentation.md` states the same row for the documentation
# feature.
REGISTER_PATHS = (
    "docs/specs/features/08-documentation.md",
    ".claude/rules/external-apis.md",
)

REGISTER_ROW = re.compile(
    r"\|\s*GitHub Pages deployment\s*\|\s*`actions/deploy-pages`\s*v(\d+)\s*\|"
)


def workflow_files() -> List[Path]:
    """Return every workflow file of this repository, in name order.

    Returns:
        The paths under `.github/workflows/` whose name ends in `.yml`.
    """
    return sorted(WORKFLOW_DIRECTORY.glob("*.yml"))


def pins_of(text: str) -> List[Tuple[str, str, str]]:
    """Return the pinned actions of one workflow.

    Args:
        text: The text of the workflow.

    Returns:
        One triple for each pinned action: the name with its owner, the reference the line
        names, and the version comment. The version reads as an empty string where the line
        carries no comment.
    """
    return [
        (match.group("name"), match.group("reference"), match.group("version") or "")
        for match in PINNED_ACTION.finditer(text)
    ]


def short_name(name: str) -> str:
    """Return the repository part of an action name.

    Args:
        name: The action name with its owner, as `actions/deploy-pages`.

    Returns:
        The repository part, as `deploy-pages`. A comment of this repository writes that
        part alone as often as it writes the whole name.
    """
    return name.split("/")[1]


def major_of(version: str) -> int:
    """Return the major number of a version comment.

    Args:
        version: The version comment, as `v4.0.5`.

    Returns:
        The major number, as 4.

    Raises:
        AssertionError: The comment states no version.
    """
    match = VERSION_COMMENT.match(version)
    assert match is not None, f"{version!r} states no version"
    return int(match.group(1))


def pinned_majors(text: str) -> Dict[str, Set[int]]:
    """Return the major versions each action of one workflow pins.

    Args:
        text: The text of the workflow.

    Returns:
        The short name of each action against the major numbers of its version comments. An
        action whose line carries no version comment reaches no entry, because
        `test_every_action_of_every_workflow_pins_a_commit_and_names_its_version` holds
        that condition.
    """
    majors: Dict[str, Set[int]] = {}
    for name, _, version in pins_of(text):
        if VERSION_COMMENT.match(version):
            majors.setdefault(short_name(name), set()).add(major_of(version))
    return majors


def repository_majors(texts: List[str]) -> Dict[str, int]:
    """Return the one major version each action holds across every workflow.

    Args:
        texts: The text of each workflow.

    Returns:
        The short name of each action against its major number. An action that two
        workflows pin at two major versions reaches no entry, because neither number
        refuses the other.
    """
    collected: Dict[str, Set[int]] = {}
    for text in texts:
        for name, majors in pinned_majors(text).items():
            collected.setdefault(name, set()).update(majors)
    return {name: majors.pop() for name, majors in collected.items() if len(majors) == 1}


def comment_lines(text: str) -> List[str]:
    """Return every whole-line comment of one workflow.

    A version comment sits on the `uses:` line, and `pins_of` reads that one. This reader
    therefore takes the lines that open with the comment marker, so no case reads one pin
    twice.

    Args:
        text: The text of the workflow.

    Returns:
        The lines whose first character other than a space is `#`.
    """
    return [line for line in text.splitlines() if line.lstrip().startswith("#")]


def stale_citations(text: str, majors: Dict[str, int]) -> Tuple[List[str], int]:
    """Return the comment citations of one workflow that disagree with the pins.

    Args:
        text: The text of the workflow.
        majors: The major version each action holds across every workflow.

    Returns:
        One sentence for each citation that names another major version, and the count of
        citations the reader collected.
    """
    findings: List[str] = []
    read = 0
    for name, major in majors.items():
        citation = re.compile(re.escape(name) + r"[^\n]{0," + str(CITATION_WINDOW) + r"}?\bv(\d+)")
        for line in comment_lines(text):
            for cited in citation.findall(line):
                read += 1
                if int(cited) != major:
                    findings.append(
                        f"a comment names {name} v{cited} against the pin v{major}: {line.strip()}"
                    )
    return findings, read


def test_every_action_of_every_workflow_pins_a_commit_and_names_its_version() -> None:
    """A third-party action of a workflow names a 40-character commit and a version comment.

    A tag moves, and a moved tag runs code that nobody read. The commit states no version,
    so the comment beside it names the release the pin holds.
    """
    findings: List[str] = []
    read = 0
    for workflow in workflow_files():
        for name, reference, version in pins_of(workflow.read_text(encoding="utf-8")):
            read += 1
            if not COMMIT.match(reference):
                findings.append(f"{workflow.name} pins {name} to {reference}, which is no commit")
            elif not VERSION_COMMENT.match(version):
                findings.append(f"{workflow.name} pins {name} under the comment {version!r}")
    assert read >= MINIMUM_PINNED_ACTIONS, (
        f"the reader collected {read} pinned actions, and the floor is {MINIMUM_PINNED_ACTIONS}"
    )
    assert findings == [], f"these pins name no commit or no version: {findings}"


def test_one_version_of_one_action_names_one_commit() -> None:
    """Two workflows that pin one version of one action name the same commit.

    A pair that disagrees means that one of the two lines names the wrong commit, and a
    reader of either line cannot tell which.
    """
    commits: Dict[Tuple[str, str], Set[str]] = {}
    for workflow in workflow_files():
        for name, reference, version in pins_of(workflow.read_text(encoding="utf-8")):
            commits.setdefault((name, version), set()).add(reference)
    split = [
        f"{name} {version} names {sorted(references)}"
        for (name, version), references in sorted(commits.items())
        if len(references) > 1
    ]
    assert split == [], f"these versions name more than one commit: {split}"


def test_no_comment_of_a_workflow_names_another_version_of_an_action_it_pins() -> None:
    """A comment of a workflow names the major version that the same workflow pins.

    A bump moves the pin, and a comment that keeps the old number sends a reader to the
    release note of a version this project no longer runs.
    """
    texts = [workflow.read_text(encoding="utf-8") for workflow in workflow_files()]
    majors = repository_majors(texts)
    findings: List[str] = []
    read = 0
    for workflow, text in zip(workflow_files(), texts):
        stale, count = stale_citations(text, majors)
        findings.extend(f"{workflow.name}: {finding}" for finding in stale)
        read += count
    assert read >= MINIMUM_VERSION_CITATIONS, (
        f"the reader collected {read} citations, and the floor is {MINIMUM_VERSION_CITATIONS}"
    )
    assert findings == [], f"these comments name a version the workflow does not pin: {findings}"


def test_every_interface_register_names_the_deploy_pages_version_the_workflow_pins() -> None:
    """The two interface registers name the `actions/deploy-pages` version `docs.yml` pins.

    `.claude/rules/external-apis.md` asks a worker to read the documentation of the version
    this project pins. A register row that names another version sends that worker to the
    wrong page.
    """
    text = (WORKFLOW_DIRECTORY / PUBLISH_WORKFLOW).read_text(encoding="utf-8")
    versions = {name: version for name, _, version in pins_of(text)}
    assert DEPLOY_ACTION in versions, f"{PUBLISH_WORKFLOW} pins no {DEPLOY_ACTION}"
    major = major_of(versions[DEPLOY_ACTION])
    findings: List[str] = []
    for path in REGISTER_PATHS:
        row = REGISTER_ROW.search((REPO_ROOT / path).read_text(encoding="utf-8"))
        assert row is not None, f"{path} holds no GitHub Pages deployment row"
        if int(row.group(1)) != major:
            findings.append(f"{path} names v{row.group(1)} against the pin v{major}")
    assert findings == [], f"these registers name another version: {findings}"


def test_the_reader_returns_a_tag_that_a_pin_names_in_place_of_a_commit() -> None:
    """The reader returns the tag of a `uses:` line, and `COMMIT` refuses that tag."""
    assert pins_of("      - uses: actions/checkout@v5  # v5") == [("actions/checkout", "v5", "v5")]
    assert not COMMIT.match("v5")


def test_the_reader_reports_a_pin_that_carries_no_version_comment() -> None:
    """The reader returns an empty version for a `uses:` line that carries no comment."""
    assert pins_of("      - uses: actions/checkout@" + "a" * 40) == [
        ("actions/checkout", "a" * 40, "")
    ]


def test_the_reader_passes_over_a_local_workflow_reference() -> None:
    """The reader collects no pin from a reference to a workflow of this repository."""
    assert pins_of("    uses: ./.github/workflows/docs-build.yml") == []


def test_the_reader_reports_a_comment_that_names_an_older_major_version() -> None:
    """The reader reports a comment that states a major version the pin does not hold."""
    workflow = (
        "        # The pair reads `deploy-pages` v4 today.\n"
        "        uses: actions/deploy-pages@" + "b" * 40 + "  # v5.0.0\n"
    )
    findings, read = stale_citations(workflow, repository_majors([workflow]))
    assert read == 1
    assert len(findings) == 1
    assert "v4 against the pin v5" in findings[0]


def test_the_reader_passes_a_comment_that_names_the_pinned_major_version() -> None:
    """The reader reports nothing where the comment and the pin state one major version."""
    workflow = (
        "        # The pair reads `deploy-pages` v5 today.\n"
        "        uses: actions/deploy-pages@" + "b" * 40 + "  # v5.0.0\n"
    )
    findings, read = stale_citations(workflow, repository_majors([workflow]))
    assert read == 1
    assert findings == []


def test_an_action_two_workflows_pin_at_two_major_versions_reaches_no_citation_case() -> None:
    """The reader leaves out an action whose major version differs between two workflows."""
    first = "    uses: actions/deploy-pages@" + "b" * 40 + "  # v4.0.5\n"
    second = "    uses: actions/deploy-pages@" + "c" * 40 + "  # v5.0.0\n"
    assert repository_majors([first, second]) == {}
    assert repository_majors([first]) == {"deploy-pages": 4}
