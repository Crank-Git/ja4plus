"""Tests that the specification records the JA4TScan reversal of 2026-09-30.

#197 declined JA4TScan on 2026-08-08. The maintainer reversed the decline on 2026-09-30,
in #775, and ruled on the firewall and on the packaging. #775 moved each document that
stated the decline, and it quoted the superseded text rather than rewriting it. These
cases hold the moved documents in place, so a later edit that restores the decline or
drops the quotation fails here.

These cases read prose. They import nothing from `ja4plus` and they produce no fingerprint.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"
TRANSCRIPTION = REPO_ROOT / "docs" / "specs" / "foxio" / "JA4TScan.md"
INVENTORY = REPO_ROOT / "docs" / "specs" / "foxio" / "README.md"
FEATURE = REPO_ROOT / "docs" / "specs" / "features" / "12-active-scan.md"
EXTERNAL_APIS = REPO_ROOT / ".claude" / "rules" / "external-apis.md"

# The commit of `FoxIO-LLC/ja4tscan` that the transcription reads.
PINNED_COMMIT = "d01bfec4e64366d37ae95982a5068a5b41ca43b0"

# The six files the pinned commit holds.
SOURCE_FILES = (
    "module_ja4tscan.c",
    "ja4tscan.py",
    "README.md",
    "probe_modules.c",
    "build.sh",
    "LICENSE",
)

# The opening words of the superseded `Non-goals` bullet. A quotation line opens with `>`.
SUPERSEDED_DECLINE = "> **JA4TScan is declined.**"


def _read(path: Path) -> str:
    """Return the text of one document."""
    return path.read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    """Return the body of one `## ` section, up to the next `## ` heading."""
    start = text.index(f"\n{heading}\n")
    end = text.find("\n## ", start + len(heading) + 2)
    return text[start : end if end != -1 else len(text)]


def test_the_transcription_reads_the_commit_the_interface_table_pins() -> None:
    """`JA4TScan.md` and `.claude/rules/external-apis.md` name one commit of the scanner."""
    assert PINNED_COMMIT in _read(EXTERNAL_APIS), "the interface table pins another commit"
    assert f"| Pinned commit | `{PINNED_COMMIT}` |" in _read(TRANSCRIPTION), (
        "the transcription pins no commit, or pins another one"
    )


def test_the_transcription_inventory_names_every_file_of_the_pinned_commit() -> None:
    """The inventory holds one row, with a byte count and a hash, for each source file."""
    inventory = _section(_read(TRANSCRIPTION), "## The inventory")
    missing = [name for name in SOURCE_FILES if f"| `{name}` |" not in inventory]
    assert missing == [], f"the inventory holds no row for {missing}"


def test_the_inventory_page_lists_the_transcription() -> None:
    """`docs/specs/foxio/README.md` names the JA4TScan page among the transcriptions."""
    transcriptions = _section(_read(INVENTORY), "## The transcriptions")
    assert "`docs/specs/foxio/JA4TScan.md`" in transcriptions, (
        "the transcription table names no JA4TScan page"
    )


def test_the_non_goals_quote_the_superseded_decline_and_name_the_reversal() -> None:
    """`Non-goals` quotes the decline of 2026-08-08 and names the issue that reversed it."""
    non_goals = _section(_read(SPECIFICATION), "## Non-goals")
    assert SUPERSEDED_DECLINE in non_goals, "the section quotes no superseded decline"
    assert "#775" in non_goals, "the section names no issue for the reversal"
    live = [line for line in non_goals.splitlines() if not line.lstrip().startswith(">")]
    assert not any("**JA4TScan is declined.**" in line for line in live), (
        "a line outside the quotation still states the decline"
    )


def test_the_divergence_register_records_the_firewall_ruling() -> None:
    """The register holds a row for the firewall state, citing the FoxIO wrapper rules."""
    register = _read(SPECIFICATION)
    rows = [line for line in register.splitlines() if line.startswith("| The firewall state")]
    assert len(rows) == 1, f"the register holds {len(rows)} firewall rows"
    assert "`ja4tscan/ja4tscan.py:13-25`" in rows[0], "the row cites no FoxIO wrapper rule"
    assert "#775" in rows[0], "the row names no ruling issue"


def test_the_divergence_register_records_each_module_difference_the_form_ruling_keeps() -> None:
    """The register holds one row for each of S6, S8 and S10 of the transcription."""
    rows = [
        line
        for line in _read(SPECIFICATION).splitlines()
        if line.startswith("|") and "`module_ja4tscan.c`, by ruling." in line
    ]
    for rule in ("S6", "S8", "S10"):
        cited = [row for row in rows if f"{rule} of `docs/specs/foxio/JA4TScan.md`" in row]
        assert len(cited) == 1, f"the register holds {len(cited)} rows for {rule}"


def test_the_feature_page_holds_no_open_question() -> None:
    """The four questions of 2026-09-30 carry a ruling, so the section reads `None.`."""
    feature = _read(FEATURE)
    open_questions = _section(feature, "## Open questions")
    assert "\nNone." in open_questions, "the feature page still holds an open question"
    rulings = _section(feature, "## The rulings on the four open questions")
    assert "issuecomment-5921253786" in feature, "the page cites no ruling comment"
    assert rulings.count("\n> ") == 4, "the section quotes no four rulings"


def test_the_feature_page_states_both_rulings_of_the_reversal() -> None:
    """The feature page states the firewall ruling and the packaging ruling."""
    purpose = _section(_read(FEATURE), "## Purpose")
    assert "**Firewall state: document, don't touch.**" in purpose, "no firewall ruling"
    assert "**Packaging: optional extra plus subcommand.**" in purpose, "no packaging ruling"
