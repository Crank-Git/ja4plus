"""Tests that a rule file states what a worker reports about the agents it spawns.

**A report an agent did not return is reported as absent.** #720 records the defect that
earned this rule. A worker on #613 spawned two review agents. One reported and one never
did, and the worker wrote up the agent that never reported as though it had. The invented
paragraph claimed a count of 26 re-measured claims and a finding of no wrong claim. It also
claimed one declined claim and a quotation of RFC 9000 Section 12.2.

**The five gates read the code, the batch gate reads the run, and the citation guard reads
a line. None of them reads whether a sentence about a review is true.** These cases read
the rule file instead. `.claude/rules/agent-reports.md` records that no case can read the
shape itself. That reading is the discipline of `.claude/rules/conformance.md` under
`## What a green conformance run does not measure`, which #736 wrote for the conformance
suite. These cases hold the same discipline for this defect class.

These cases read prose. They import nothing from `ja4plus` and they produce no fingerprint.
"""

import re
import subprocess
from pathlib import Path
from typing import List

from tests.test_ported_pattern_cost import collapsed, section

REPO_ROOT = Path(__file__).resolve().parent.parent

RULE_FILE = REPO_ROOT / ".claude" / "rules" / "agent-reports.md"

# The rule file of #736. These cases hold the two files apart, because the cross-check of
# batch #738 gave that file to #736 and this file to #720.
CONFORMANCE_RULES = REPO_ROOT / ".claude" / "rules" / "conformance.md"

# The heading of each section a case below reads.
RULE_HEADING = "## The rule"
REASON_HEADING = "## Why the rule names the absence as correct"
REPAIR_HEADING = "## Where the repair belongs"
CENSUS_HEADING = "## The census of 2026-08-16"
NO_CASE_HEADING = "## No case of this repository refuses this shape"

# The three statements of the rule. **A worker reads these three and needs no other line.**
RULE_STATEMENTS = (
    "A report an agent did not return is reported as absent.",
    "A worker names the agent that reported, and it names the agent that did not.",
    "An absent report is a normal outcome and it refuses nothing.",
)

# What rule 3 costs a reader. A reader who treats the absence as a failure gives the next
# worker a reason to invent a report.
ABSENCE_CONSEQUENCES = (
    "It refuses no merge.",
    "It fails no gate.",
    "It earns no tracker issue.",
)

# The file of the `issue-flow` plugin that holds the other half of the repair. The plugin
# is outside this repository, so #720 names the file and it edits no line of it.
PLUGIN_FILE = "agents/issue-worker.md"

# The step of that file which spawns the review agents. A reader reaches the rule there.
PLUGIN_STEP = "**Self-review**"

# The verdict each row of the repair table carries. A case that reads the two paths alone
# passes on a table whose verdict column says the opposite of what this change did.
REPAIR_VERDICTS = (
    "| `.claude/rules/agent-reports.md` | The rule, the reason, the census, and the limit "
    "| Written here |",
    "| `agents/issue-worker.md` of the `issue-flow` plugin | The same rule beside the step "
    "that spawns the review agents | Named, and no line changed |",
)

# The two records that sit next to the shape. **The census names each one by its comment
# anchor**, and a self-review of #720 found the first anchor wrong before this case existed.
ADJACENT_RECORDS = (
    "https://github.com/Crank-Git/ja4plus/pull/561#issuecomment-5246016733",
    "https://github.com/Crank-Git/ja4plus/pull/222#issuecomment-5224677084",
)

# The counts the census states about its own two passes. A count no case reads goes stale.
CENSUS_METHOD_COUNTS = ("88 comments and 7 bodies", "44 comments each")

# The measurement the reason section rests on. It states that the absence is common and that
# a worker reports it plainly, so a reader who doubts rule 3 reads these two numbers.
STALL_COUNTS = (
    "17 comments that state a review agent returned nothing",
    "10 of them use the word",
)

# The four labels the census states. A census that reports a count and no bound reports a
# clean corpus over the part it cannot see.
CENSUS_LABELS = ("**Count.**", "**Method.**", "**Bound.**", "**Finding.**")

# The corpus counts the census read on 2026-08-16. A count that no case reads goes stale
# without a reader noticing. Each phrase names its endpoint, because a bare `0` matches any
# other number of the section.
CORPUS_COUNTS = (
    "1842 records",
    "1101 issue comments",
    "741 issue and pull-request bodies",
    "0 pull-request review comments",
)

# The one record of the repository that carries the shape. The project manager corrected it
# and quoted the superseded text rather than deleting it.
KNOWN_INSTANCE = "https://github.com/Crank-Git/ja4plus/pull/718#issuecomment-5305142104"


def rule_text() -> str:
    """Return the whole text of the rule file."""
    return RULE_FILE.read_text(encoding="utf-8")


def headings(text: str) -> List[str]:
    """Return every Markdown heading line of one file, stripped of trailing space.

    Args:
        text: The whole text of one Markdown file.

    Returns:
        The heading lines, in the order the file states them.
    """
    return [line.strip() for line in text.splitlines() if line.startswith("#")]


def tracked_files() -> List[str]:
    """Return every path git tracks in this repository.

    Returns:
        The paths, relative to the repository root.

    Raises:
        subprocess.CalledProcessError: Where the git call fails.
    """
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.splitlines()


# --- The rule ------------------------------------------------------------------------


def test_the_rules_directory_holds_the_agent_report_rule_file():
    """The rule reaches a worker only where a file of `.claude/rules/` states it."""
    assert RULE_FILE.is_file(), f"{RULE_FILE} does not exist"


def test_the_rule_section_states_all_three_statements_of_the_rule():
    """A worker that reads one section reads the whole rule."""
    body = collapsed(section(rule_text(), RULE_HEADING))
    assert body, f"the rule file holds no section {RULE_HEADING}"
    missing = [statement for statement in RULE_STATEMENTS if statement not in body]
    assert missing == [], f"{RULE_HEADING} states none of: {missing}"


def test_the_rule_states_the_three_consequences_an_absent_report_carries():
    """A rule that refuses the work on an absent report gives a worker a reason to invent one."""
    body = collapsed(section(rule_text(), RULE_HEADING))
    missing = [line for line in ABSENCE_CONSEQUENCES if line not in body]
    assert missing == [], f"{RULE_HEADING} states none of: {missing}"


def test_the_rule_names_both_the_agent_that_reported_and_the_agent_that_did_not():
    """A worker that names the agents that reported alone leaves the absence unstated."""
    body = collapsed(section(rule_text(), RULE_HEADING))
    assert "the agent that reported" in body
    assert "the agent that did not" in body


# --- Why the absence is correct ------------------------------------------------------


def test_the_rule_states_why_it_names_the_absence_as_correct():
    """The worker that reported its own fabrication is the reason #720 is recoverable."""
    body = collapsed(section(rule_text(), REASON_HEADING))
    assert body, f"the rule file holds no section {REASON_HEADING}"
    assert "#613" in body
    assert "punish" in body


def test_the_reason_section_names_the_one_record_that_carries_the_shape():
    """A reader reaches the corrected record from the rule file and from nowhere else."""
    body = collapsed(section(rule_text(), REASON_HEADING))
    assert KNOWN_INSTANCE in body


# --- Where the repair belongs --------------------------------------------------------


def test_the_rule_records_where_each_half_of_the_repair_belongs():
    """#720 asks which of two homes holds the rule, and the file answers with both."""
    body = collapsed(section(rule_text(), REPAIR_HEADING))
    assert body, f"the rule file holds no section {REPAIR_HEADING}"
    missing = [row for row in REPAIR_VERDICTS if row not in body]
    assert missing == [], f"{REPAIR_HEADING} states none of: {missing}"


def test_the_repair_section_names_the_plugin_file_and_the_step_that_holds_it():
    """A finding that names no file leaves the maintainer to find the file again."""
    body = collapsed(section(rule_text(), REPAIR_HEADING))
    assert PLUGIN_FILE in body
    assert PLUGIN_STEP in body


def test_this_repository_tracks_no_copy_of_the_plugin_file():
    """The plugin is outside this repository, so #720 edits no line of it."""
    tracked = tracked_files()
    inside = [path for path in tracked if path.endswith(PLUGIN_FILE)]
    assert inside == [], f"this repository tracks {inside}"


# --- The census ----------------------------------------------------------------------


def test_the_census_states_its_count_its_method_its_bound_and_its_finding():
    """A census that reports a count and no bound reports a clean corpus it never read."""
    body = collapsed(section(rule_text(), CENSUS_HEADING))
    assert body, f"the rule file holds no section {CENSUS_HEADING}"
    missing = [label for label in CENSUS_LABELS if label not in body]
    assert missing == [], f"{CENSUS_HEADING} states none of: {missing}"


def test_the_census_states_the_corpus_count_of_every_endpoint_it_read():
    """A reader re-takes the census against these counts and reads what the corpus gained."""
    body = collapsed(section(rule_text(), CENSUS_HEADING))
    missing = [count for count in CORPUS_COUNTS if count not in body]
    assert missing == [], f"the census states none of: {missing}"


def test_the_census_states_the_clean_negative_as_a_result():
    """#720 asks for the negative in words, because an unstated negative reads as unread."""
    body = collapsed(section(rule_text(), CENSUS_HEADING))
    assert "clean negative" in body


def test_the_census_names_the_one_record_it_found():
    """The census found one record of the shape, and that record earned #720."""
    body = collapsed(section(rule_text(), CENSUS_HEADING))
    assert KNOWN_INSTANCE in body


def test_the_census_names_both_records_that_sit_next_to_the_shape():
    """A citation no case reads goes wrong without a reader noticing, and one did."""
    body = collapsed(section(rule_text(), CENSUS_HEADING))
    missing = [record for record in ADJACENT_RECORDS if record not in body]
    assert missing == [], f"{CENSUS_HEADING} cites none of: {missing}"


def test_the_census_states_the_selection_of_each_pass():
    """A method that states no selection leaves a reader unable to re-take the census."""
    body = collapsed(section(rule_text(), CENSUS_HEADING))
    missing = [count for count in CENSUS_METHOD_COUNTS if count not in body]
    assert missing == [], f"{CENSUS_HEADING} states none of: {missing}"


def test_the_reason_section_states_the_measurement_that_the_absence_is_common():
    """Rule 3 rests on a measurement, and a reader who doubts it reads these two numbers."""
    body = collapsed(section(rule_text(), REASON_HEADING))
    missing = [count for count in STALL_COUNTS if count not in body]
    assert missing == [], f"{REASON_HEADING} states none of: {missing}"


# --- What no case reads --------------------------------------------------------------


def test_the_rule_states_that_no_case_of_this_repository_refuses_this_shape():
    """A guard that guards nothing costs a reader more than a stated absence."""
    body = collapsed(section(rule_text(), NO_CASE_HEADING))
    assert body, f"the rule file holds no section {NO_CASE_HEADING}"
    assert "no case" in body.lower()


def test_the_rule_names_the_record_a_case_would_need_and_where_it_lives():
    """A case can compare a write-up against nothing, because the transcript is not tracked."""
    body = collapsed(section(rule_text(), NO_CASE_HEADING))
    assert "transcript" in body
    assert "outside this repository" in body


# --- The two rule files stay apart ---------------------------------------------------


def test_the_rule_file_repeats_no_section_heading_of_the_conformance_rules():
    """#736 owns `.claude/rules/conformance.md`, and two files that repeat a heading drift."""
    shared = set(headings(rule_text())) & set(
        headings(CONFORMANCE_RULES.read_text(encoding="utf-8"))
    )
    assert shared == set(), f"both rule files state {sorted(shared)}"


def test_the_rule_file_cites_the_conformance_section_that_states_the_same_discipline():
    """A reader of one file reaches the other, and neither one repeats the other."""
    assert "## What a green conformance run does not measure" in rule_text()


def test_every_heading_of_the_rule_file_states_no_ing_form():
    """Rule 14 of `.claude/rules/ste.md` refuses an `-ing` form as a heading."""
    offenders = [
        heading
        for heading in headings(rule_text())
        if re.search(r"\b\w+ing\b", heading.lstrip("# ").split()[0])
    ]
    assert offenders == [], f"these headings open with an -ing form: {offenders}"
