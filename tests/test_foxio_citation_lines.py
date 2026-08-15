"""The repository-owned line citations of `docs/specs/foxio/`, read in their two classes.

**A citation of a file this repository owns goes stale on every change above the cited
line, and nothing reported it before #668.** #600 moved one line of `ja4h.py` and its
review lens found one falsified citation, because the lens read the diff. The other 281
reached no reader at all.

**The maintainer ruled on 2026-08-15 that the pins of these pages stand.** 250 of the 282
citations are true at the commit their own section declares, and zero agree with the
working tree, which is the correct state of a pinned citation. A reader that held every
citation against the tree would fail all 250.

`tests/foxio_citation_lines.py` holds the reader and this file holds the cases.
`docs/specs/spec.md` records the round.

**Warning: this file reads no FoxIO citation.** `tests/test_ja4t_citation_lines.py` reads
those, at the FoxIO pin and against a recorded source line, because this repository holds
no copy of `wireshark/source/packet-ja4.c`. **The two readers stand beside each other and
neither one replaces the other.** They answer two questions: this file asks whether a file
of this repository holds a cited line at a commit of this repository, and that file asks
whether a FoxIO file holds one at the FoxIO pin. A reader that merged them would read a
FoxIO path against a commit of this repository, which resolves nothing, and it would read a
path of this repository against the FoxIO pin, which resolves nothing either.
"""

from __future__ import annotations

import re

import pytest

from tests import foxio_citation_lines as reader

WORKFLOW = reader.REPO_ROOT / ".github" / "workflows" / "test.yml"

# The reference the workflow writes for one pin. A change to either name breaks the runner
# alone, and no case of a full clone would report it, so one case holds the pair.
WORKFLOW_REFERENCE = re.compile(r"refs/ja4plus/citation-pin-([0-9a-f]{7,40})")

# The count of citations a failure names. A page carries up to 64, and a message that lists
# every one of them buries the count that follows it.
NAMED_LIMIT = 8


def test_every_repository_owned_citation_names_a_line_its_file_holds() -> None:
    """This is the guard. Each citation reads the commit its own section declares."""
    wrong = reader.wrong_citations()
    named = [
        f"{citation.page}:{citation.page_line} {citation.written} read against "
        f"{citation.read_against} — {why}"
        for citation, why in wrong[:NAMED_LIMIT]
    ]
    assert wrong == [], (
        f"{len(wrong)} citations of docs/specs/foxio/ name a line the file does not hold. "
        "Read each one at the commit its section declares, and never at the working tree: "
        f"{named}"
    )


def test_the_reader_finds_a_citation_on_every_page_that_carries_one() -> None:
    """A reader that matches nothing reports a clean corpus over every page."""
    pages = {citation.page for citation in reader.all_citations()}
    assert "JA4H.md" in pages and "JA4T.md" in pages and "JA4D.md" in pages, (
        f"the reader found citations on {sorted(pages)}, and #668 measured them on seven "
        "pages of docs/specs/foxio/"
    )


def test_the_reader_holds_both_classes() -> None:
    """The two classes each hold citations, so the section decides and the file does not."""
    citations = reader.all_citations()
    pinned = [citation for citation in citations if citation.pin]
    unpinned = [citation for citation in citations if not citation.pin]
    assert pinned and unpinned, (
        f"the reader found {len(pinned)} pinned and {len(unpinned)} unpinned citations, and "
        "a reader that holds one class alone reads the other class against the wrong tree"
    )


def test_every_pin_the_pages_declare_resolves_to_one_commit() -> None:
    """A pin no reader can resolve puts its whole section outside this guard."""
    unresolved = [
        pin
        for pin in reader.declared_pins()
        if reader._git("rev-parse", "--verify", f"{pin}^{{commit}}").returncode != 0
        and reader._git(
            "rev-parse", "--verify", reader.PIN_REFERENCE.format(pin=pin)
        ).returncode
        != 0
    ]
    assert unresolved == [], (
        f"a page names a pin no commit of this repository holds: {unresolved}"
    )


def test_the_workflow_fetches_every_commit_the_pages_pin() -> None:
    """The clone of the runner holds depth 1, so it reaches a pin the workflow omits."""
    carried = set(WORKFLOW_REFERENCE.findall(WORKFLOW.read_text(encoding="utf-8")))
    missing = sorted(set(reader.declared_pins()) - carried)
    assert missing == [], (
        "the clone of the runner holds depth 1 and it reaches no commit outside it, so "
        "`.github/workflows/test.yml` must fetch every pin the pages declare. It fetches "
        f"none of these: {missing}"
    )


def test_the_workflow_fetches_the_whole_identifier_of_every_pin_it_carries() -> None:
    """git resolves no abbreviation at the remote, which #528 measured."""
    text = WORKFLOW.read_text(encoding="utf-8")
    for pin in reader.declared_pins():
        whole = reader._git("rev-parse", pin).stdout.strip()
        if not whole:
            continue
        assert f"+${{{whole}" not in text
        assert whole in text, (
            f"the workflow names the pin {pin} and it must fetch the whole identifier "
            f"{whole}, because git answers `couldn't find remote ref` for an abbreviation"
        )


def test_the_reader_reads_no_foxio_citation() -> None:
    """A FoxIO path resolves against the FoxIO pin, which this reader never reads."""
    foreign = [
        citation for citation in reader.all_citations() if citation.path.startswith(reader.FOXIO_PREFIXES)
    ]
    assert foreign == [], (
        "this reader took a FoxIO path, and `tests/test_ja4t_citation_lines.py` holds that "
        f"class: {[citation.written for citation in foreign]}"
    )


def test_a_declaration_names_a_path_this_repository_tracks() -> None:
    """A declaration that names an untracked path pins nothing, and it reads as a pin."""
    tracked = set(reader.tracked_python_files())
    unknown: list[str] = []
    for page in sorted(reader.PAGE_DIRECTORY.glob("*.md")):
        for _, subjects, _ in reader.page_declarations(page.name):
            unknown.extend(f"{page.name}: {path}" for path in subjects if path not in tracked)
    assert unknown == [], f"a pin declaration names a path this repository does not track: {unknown}"


# The two reversals below prove the guard discriminates, one in each class. A guard nobody
# reversed is a guard that may assert nothing at all.

REVERSAL_PINNED = """## The comparison against this project

The comparison below reads `ja4plus/fingerprinters/ja4h.py` at commit `1a87f45`.

| Field | Rule | `ja4h.py` | Reading |
|---|---|---|---|
| A field | R1 | `ja4h.py:99999` | Agrees. |
"""

REVERSAL_UNPINNED = """## A section that declares no pin

The reading names `ja4plus/fingerprinters/ja4h.py:99999`, and no pin stands above it.
"""

CONTROL_PINNED = REVERSAL_PINNED.replace("ja4h.py:99999", "ja4h.py:356")

CONTROL_UNPINNED = REVERSAL_UNPINNED.replace("ja4h.py:99999", "ja4h.py:534")


@pytest.mark.parametrize(
    ("name", "text", "expect_pin"),
    [("pinned", REVERSAL_PINNED, True), ("unpinned", REVERSAL_UNPINNED, False)],
)
def test_the_guard_refuses_a_wrong_citation_in_each_class(
    name: str, text: str, expect_pin: bool
) -> None:
    """A citation past the end of the file fails, under a pin and under none."""
    citations = reader.read_text(f"reversal-{name}.md", text)
    assert len(citations) == 1, f"the reader read {len(citations)} citations of the {name} reversal"
    assert bool(citations[0].pin) is expect_pin, (
        f"the {name} reversal reached the wrong class, and it read {citations[0].read_against}"
    )
    wrong = reader.wrong_citations(citations)
    assert len(wrong) == 1, (
        f"the guard passed a citation of line 99999 in the {name} class, so it refuses "
        "nothing there"
    )


@pytest.mark.parametrize(
    ("name", "text", "expect_pin"),
    [("pinned", CONTROL_PINNED, True), ("unpinned", CONTROL_UNPINNED, False)],
)
def test_the_guard_passes_a_right_citation_in_each_class(
    name: str, text: str, expect_pin: bool
) -> None:
    """A guard that refuses everything proves nothing, so each class holds a control."""
    citations = reader.read_text(f"control-{name}.md", text)
    assert len(citations) == 1
    assert bool(citations[0].pin) is expect_pin
    assert reader.wrong_citations(citations) == [], (
        f"the guard refused a citation the file holds in the {name} class"
    )


def test_a_cell_that_names_a_commit_overrides_the_pin_of_its_section() -> None:
    """R19 of `docs/specs/foxio/JA4H.md` rests on this rule, so one case holds it."""
    row = (
        "| b, no header | R19 | `ja4h.py:484` at commit `dcb43fc` | The cell names the "
        "nearer commit. |"
    )
    citations = reader.read_text("override.md", f"{REVERSAL_PINNED}{row}\n")
    override = [citation for citation in citations if citation.first == 484]
    assert len(override) == 1, "the reader read no citation of the overriding cell"
    assert override[0].pin == "dcb43fc", (
        f"the cell names `dcb43fc` and the reader read {override[0].read_against}"
    )


def test_the_census_reports_one_row_for_every_page() -> None:
    """A sweep that names what it found alone cannot be told from one that never ran."""
    census = reader.census()
    for page in sorted(reader.PAGE_DIRECTORY.glob("*.md")):
        assert f"| `{page.name}` |" in census, (
            f"the census omits {page.name}, so a reader cannot tell a clean page from an "
            "unread one"
        )
