"""Tests that the batch-gate rule states the branch protection the provider now holds.

`.claude/rules/batch-gate.md` is a rule a reader follows, and it is not a dated record.
#459 wrote its section on branch protection from a read of 2026-08-09, which reported
`404`, `Branch not protected`. #468 turned the rule on, so a reader who follows the
2026-08-09 wording concludes that nothing at the provider refuses an ungated merge, and
that conclusion is false. #480 re-took the measurement and these cases hold the repair.

## The two readings

A read of 2026-08-10 reports eleven required contexts, an empty ruleset list,
`enforce_admins` false and `strict` false. The 2026-08-09 reading stays in the file as the
dated record it is. **A dated record of a past measurement is quoted and not rewritten**,
so `readable_text` cuts a quotation and a paragraph that marks itself superseded.

## Why a case reads the provider

Prose carries no other gate. A case that read the file twice would pass on a file that
contradicts the provider, so `protection_reading` takes
`gh api repos/Crank-Git/ja4plus/branches/dev/protection` and the two live cases compare
the file against it.

**Where the call cannot be made, a live case skips and it does not pass.** A runner that
holds no `gh`, a token that carries no scope and a host that reaches no network each
produce that state. An aggregate over an unreachable provider that passes is the defect
this repository has recorded more than eighteen times, so
`test_the_live_context_case_skips_where_the_provider_returns_no_reading` drives the live
case with a reader that returns nothing and requires a skip.

**Every live case reads its floor before it reads the provider.** The floor runs with no
network, so a file that lists no context fails the case rather than comparing two empty
sets.

## The application of a required context

`.claude/rules/batch-gate.md`, `CHANGELOG.md` and the round 174 row of
`docs/specs/spec.md` each state that every required context carries `app_id` 15368. #511
found that no case read the number, because `provider_contexts` reads
`required_status_checks.contexts` and that field holds the context names alone. The
provider holds the application under `required_status_checks.checks[]`, so
`check_applications` reads that list and `test_the_provider_carries_the_stated_application_on_every_context`
holds the file against it.

## The prose defects #511 repairs

Three cases hold the wording the same issue repaired. The opening claim of the protection
section names the `enforce_admins` reading, because an administrator merge reaches `dev`
with no run. The steps of that section read the provider and change nothing, and the intro
states that. No live sentence of the file carries a floating date, because a floating word
turns a dated reading into a standing fact.

## What these cases cannot test

A case here reads the state of the provider on the day it runs. It proves no statement
about the day the file was written, and it proves nothing about a merge an administrator
makes, because `enforce_admins` reads false.

These cases read prose and the provider. They import nothing from `ja4plus` and they
produce no fingerprint.
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

RULE_FILE = REPO_ROOT / ".claude" / "rules" / "batch-gate.md"

# The heading of the section #480 repairs. #459 headed it `The strongest shape needs the
# user`, which stated a shape the repository did not hold.
PROTECTION_HEADING = "## The provider refuses an ungated merge"

# The date of the read #480 took. A case requires it beside the live claim, so a later
# reader knows how old the reading is.
LIVE_READ_DATE = "2026-08-10"

# The date of the read #459 took. The file keeps it and marks it superseded.
SUPERSEDED_READ_DATE = "2026-08-09"

# The command the live cases run. `gh` reads the authentication of the host.
PROTECTION_COMMAND = ("gh", "api", "repos/Crank-Git/ja4plus/branches/dev/protection")

# The application that publishes every required context. The provider holds this number
# under `required_status_checks.checks[]` and never under `contexts`, which is a list of
# names alone. A context of another application would satisfy the rule with a run this
# project never wrote, so a case reads the number rather than the name.
REQUIRED_APP_ID = 15368

# The read of 2026-08-10 reports these eleven contexts, each carrying `app_id` 15368.
# A live case compares the provider against the list the file carries, and this tuple
# holds the file to the reading where no provider answers.
REQUIRED_CONTEXTS = (
    "lint",
    "test (ubuntu-latest, 3.9)",
    "test (ubuntu-latest, 3.10)",
    "test (ubuntu-latest, 3.11)",
    "test (ubuntu-latest, 3.12)",
    "test (ubuntu-latest, 3.13)",
    "test (macos-latest, 3.12)",
    "fuzz",
    "samples",
    "installed-wheel",
    "conformance",
)

# The check the required list leaves out. `.github/workflows/docs-build.yml` filters four
# paths, so a batch that touches none of them creates no run of it.
UNREQUIRED_CONTEXT = "build"

# The two limits the same call returned. A live case reads each one against the provider.
STATED_LIMITS = ("enforce_admins", "strict")

# The word that marks a quoted past measurement. A paragraph that carries it states a
# reading of a past date, so the sweep passes over it.
SUPERSEDED_MARKER = "superseded"

# A Markdown heading. The space is part of the form, and an issue reference such as
# `#468` at the start of a line therefore reaches no match.
HEADING_LINE = re.compile(r"^(#{1,6})\s")

# A sentence that names one of these terms makes a claim about branch protection. **The
# term is not the phrase `required status check` alone.** A self-review wrote
# `This repository holds no required check.` and the first form of this pattern read
# nothing in it.
CHECK_TERM = re.compile(
    r"required status check(?:s)?|required check(?:s)?|branch protection",
    re.IGNORECASE,
)

# A sentence that names a check term and one of these states that no such check exists.
# **The pattern reads a shape and no phrase**, because #211 and #449 each proved that one
# forbidden phrase guards one spelling. A self-review drove the first form with fifteen
# candidate sentences and eight reached no match, so each of those eight added its verb.
NEGATION = re.compile(
    r"holds none|holds no\b|carries none|carries no\b|has none|has no\b"
    r"|there is no\b|there are no\b|not protected|unprotected"
    r"|no required status check|no required check"
    r"|\blacks\b|without a\b|without any\b|requires no\b"
    r"|never added|never configured|never turned on"
    r"|is absent|are absent|is empty|is off\b",
    re.IGNORECASE,
)

# A second shape of the same claim, which names no check term. A sentence that states the
# provider refuses nothing means the same thing to a reader.
PROVIDER_REFUSES_NOTHING = re.compile(
    r"nothing (?:at |inside |in )?the provider refuses|the provider refuses nothing"
    r"|the provider refuses no\b",
    re.IGNORECASE,
)

# A third shape, which names the branch rather than the check. `The branch `dev` is
# unprotected.` states the same claim and it names no check at all.
BRANCH_TERM = re.compile(r"\bdev\b|\bbranch\b|\brepository\b", re.IGNORECASE)
UNPROTECTED = re.compile(r"\bunprotected\b|\bnot protected\b", re.IGNORECASE)

# A sentence that names a check term and one of these states that the check exists.
AFFIRMATION = re.compile(r"\bcarries\b|\bholds\b|\breads\b", re.IGNORECASE)

# The `app_id` the rule file states, as `` `app_id` 15368 ``.
APP_ID_STATEMENT = re.compile(r"`app_id` (\d+)")

# A numbered step of the rule file, as `1. Open ...`. The first word is the verb the step
# gives the reader.
NUMBERED_STEP = re.compile(r"^\s*\d+\.\s+(\S+)")

# The verbs a read step takes. A step that opens a page and a step that reads a field each
# leave the provider as it stands.
READ_VERBS = ("Open", "Read")

# A promise that the steps below change the rule. #511 measured the defect: the intro read
# `the exact steps to read the rule or to change it` and the four steps were four reads.
CHANGE_PROMISE = re.compile(r"steps?\s+to\s+[^.]*\bchange\b|to change it", re.IGNORECASE)

# A word that dates a sentence against the day a reader reads it. This file exists because
# a dated reading was quoted as a standing fact, so a floating word is the defect it
# records. `\bnow\b` matches no `nowhere`, because the boundary needs the word to end.
FLOATING_DATE = re.compile(
    r"\btoday\b|\byesterday\b|\btomorrow\b|\bnow\b|\bcurrently\b|\brecently\b"
    r"|\blately\b|at present|at the moment|these days|as of now",
    re.IGNORECASE,
)


def documentation_files() -> List[Path]:
    """Return every prose file that may state a claim about branch protection.

    `CHANGELOG.md` is a dated record rather than a rule, so it stays out. Its entries
    quote the 2026-08-09 reading and a reader repairs no entry of a past round.

    Returns:
        The Markdown pages under `docs/` and `.claude/rules/`, the rendered
        `docs/specs/spec.html`, `CLAUDE.md` and `README.md`.
    """
    files = sorted((REPO_ROOT / "docs").rglob("*.md"))
    files += sorted((REPO_ROOT / ".claude" / "rules").glob("*.md"))
    files.append(REPO_ROOT / "docs" / "specs" / "spec.html")
    files.append(REPO_ROOT / "CLAUDE.md")
    files.append(REPO_ROOT / "README.md")
    return [path for path in files if path.is_file()]


def cut_changelog(text: str) -> str:
    """Return the page with its `## Changelog` section removed.

    `docs/specs/spec.md` records round 165, which quotes the 2026-08-09 reading word for
    word. A dated record of a past measurement is quoted and not rewritten.

    Args:
        text: The whole page.

    Returns:
        The page up to the `## Changelog` heading, joined to the text after that section.
    """
    lines = text.splitlines()
    kept: List[str] = []
    inside = False
    for line in lines:
        if line.strip() == "## Changelog":
            inside = True
            continue
        if inside:
            if line.startswith("## "):
                inside = False
            else:
                continue
        kept.append(line)
    return "\n".join(kept)


def readable_text(text: str) -> str:
    """Return the paragraphs of a page that state a live rule.

    Three shapes hold a past measurement rather than a rule, and each one drops out.

    Args:
        text: The whole page.

    Returns:
        The remaining paragraphs, joined by a blank line.
    """
    kept: List[str] = []
    for block in cut_changelog(text).split("\n\n"):
        lines = [line for line in block.splitlines() if line.strip()]
        if not lines:
            continue
        if all(line.lstrip().startswith(">") for line in lines):
            continue
        if SUPERSEDED_MARKER in block.lower():
            continue
        kept.append(block)
    return "\n\n".join(kept)


def sentences(text: str) -> List[str]:
    """Return the sentences of one text, with every line break replaced by a space.

    Args:
        text: A page, a section or a paragraph.

    Returns:
        One entry for each sentence, in the order the text holds them.
    """
    joined = " ".join(text.split())
    parts = re.split(r"(?<=[.!?])\s+", joined)
    return [part.strip() for part in parts if part.strip()]


def superseded_claims(text: str) -> List[str]:
    """Return every live sentence that states the repository holds no required check.

    Args:
        text: The whole page.

    Returns:
        The offending sentences, which is empty where the page states no such claim.
    """
    found: List[str] = []
    for sentence in sentences(readable_text(text)):
        if CHECK_TERM.search(sentence) and NEGATION.search(sentence):
            found.append(sentence)
        elif PROVIDER_REFUSES_NOTHING.search(sentence):
            found.append(sentence)
        elif BRANCH_TERM.search(sentence) and UNPROTECTED.search(sentence):
            found.append(sentence)
    return found


def live_claims(text: str) -> List[str]:
    """Return every live sentence that states the provider holds a required check.

    Args:
        text: The whole page or one section of it.

    Returns:
        The affirming sentences, which is empty where the page states no such claim.
    """
    found: List[str] = []
    for sentence in sentences(readable_text(text)):
        if not CHECK_TERM.search(sentence) or NEGATION.search(sentence):
            continue
        if AFFIRMATION.search(sentence):
            found.append(sentence)
    return found


def section(text: str, heading: str) -> str:
    """Return the body of one Markdown section, including every subsection of it.

    **The body ends at the next heading of the same level or of a higher one.** A reader
    that ended at the next heading of any level dropped every subsection, and the first
    form of this file did exactly that: a `###` subheading cut the list of check names out
    of the section and four cases read a body that stopped early.

    **A heading needs a space after its `#` characters, and an issue reference does not.**
    The second form read `#468 turned the rule on` as a first-level heading and returned
    one paragraph. `HEADING_LINE` therefore requires the space.

    Args:
        text: The whole page.
        heading: The heading line, including its `#` characters.

    Returns:
        The text after the heading and before the next heading of that level or higher.

    Raises:
        AssertionError: The page holds no line equal to the heading, or more than one.
    """
    level = len(heading) - len(heading.lstrip("#"))
    lines = text.splitlines()
    starts = [number for number, line in enumerate(lines) if line.strip() == heading]
    assert starts, f"{RULE_FILE.name} holds no {heading!r} heading"
    assert len(starts) == 1, f"{RULE_FILE.name} holds {len(starts)} {heading!r} headings"
    body: List[str] = []
    for line in lines[starts[0] + 1 :]:
        found = HEADING_LINE.match(line)
        if found is not None and len(found.group(1)) <= level:
            break
        body.append(line)
    return "\n".join(body)


def fenced_block(text: str) -> List[str]:
    """Return the lines of the first fenced code block of one section.

    Args:
        text: The body of one section.

    Returns:
        The lines between the first pair of fence lines.

    Raises:
        AssertionError: The section holds no closed fenced block.
    """
    lines = text.splitlines()
    opens = [number for number, line in enumerate(lines) if line.strip() == "```"]
    assert len(opens) >= 2, "the section holds no closed fenced block"
    return [line.strip() for line in lines[opens[0] + 1 : opens[1]] if line.strip()]


def stated_limit(text: str, field: str) -> Optional[bool]:
    """Return the value the file states for one field of the protection reading.

    Args:
        text: The whole page.
        field: The field name, as the provider spells it.

    Returns:
        The stated value, or None where the file states none.
    """
    match = re.search(rf"`{re.escape(field)}` reads `(true|false)`", text)
    if match is None:
        return None
    return match.group(1) == "true"


def protection_reading(timeout: int = 60) -> Optional[Dict[str, object]]:
    """Return the branch-protection reading of `dev`, or None where no call is possible.

    A host that holds no `gh`, a token that carries no scope and a host that reaches no
    network each return None, so the caller skips rather than passes.

    Args:
        timeout: The number of seconds to wait for the command.

    Returns:
        The parsed response body, or None where the call cannot be made.
    """
    try:
        completed = subprocess.run(
            list(PROTECTION_COMMAND),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    try:
        body = json.loads(completed.stdout)
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    return body


def reading_or_skip() -> Dict[str, object]:
    """Return the branch-protection reading, or skip the case where none is possible.

    Returns:
        The parsed response body.
    """
    reading = protection_reading()
    if reading is None:
        pytest.skip(f"{' '.join(PROTECTION_COMMAND)} returned no reading on this host")
    return reading


def required_status_checks(reading: Dict[str, object]) -> Dict[str, object]:
    """Return the `required_status_checks` object of one protection reading.

    Args:
        reading: The parsed response body.

    Returns:
        The object the provider holds under that key.

    Raises:
        AssertionError: The reading holds no such object.
    """
    checks = reading.get("required_status_checks")
    assert isinstance(checks, dict), (
        f"{RULE_FILE} states that `dev` carries a required status check, and the provider "
        f"holds no `required_status_checks` object: {sorted(reading)}"
    )
    return checks


def provider_contexts(reading: Dict[str, object]) -> List[str]:
    """Return the required contexts of one protection reading.

    Args:
        reading: The parsed response body.

    Returns:
        The context names the provider requires.
    """
    contexts = required_status_checks(reading).get("contexts")
    assert isinstance(contexts, list), "the provider holds no `contexts` list"
    return [str(name) for name in contexts]


def provider_checks(reading: Dict[str, object]) -> List[Dict[str, object]]:
    """Return the `checks` entries of one protection reading.

    `contexts` holds the context names alone, so the application of a context reaches a
    reader through this list and through no other field.

    Args:
        reading: The parsed response body.

    Returns:
        The objects the provider holds under `required_status_checks.checks`.

    Raises:
        AssertionError: The reading holds no `checks` list, or an entry of it is no object.
    """
    checks = required_status_checks(reading).get("checks")
    assert isinstance(checks, list), "the provider holds no `checks` list"
    entries = [entry for entry in checks if isinstance(entry, dict)]
    assert len(entries) == len(checks), (
        f"the provider holds a `checks` entry that is no object: {checks}"
    )
    return entries


def check_applications(reading: Dict[str, object]) -> Dict[str, object]:
    """Return the application of each required context, by context name.

    Args:
        reading: The parsed response body.

    Returns:
        One entry for each required context, holding the `app_id` the provider states.

    Raises:
        AssertionError: A `checks` entry names no context.
    """
    found: Dict[str, object] = {}
    for entry in provider_checks(reading):
        context = entry.get("context")
        assert isinstance(context, str), f"a `checks` entry names no context: {entry}"
        found[context] = entry.get("app_id")
    return found


def stated_application(text: str) -> Optional[int]:
    """Return the `app_id` the rule file states, or None where it states none.

    Args:
        text: The whole page or one section of it.

    Returns:
        The stated number, or None where the text states no `app_id`.
    """
    match = APP_ID_STATEMENT.search(text)
    if match is None:
        return None
    return int(match.group(1))


def opening_paragraph(body: str) -> str:
    """Return the first paragraph of one section body.

    Args:
        body: The body of one section.

    Returns:
        The first block that holds text, which carries the claim the section opens with.
    """
    for block in body.split("\n\n"):
        if block.strip():
            return block
    return ""


def numbered_steps(body: str) -> List[str]:
    """Return the first word of each numbered step of one section body.

    Args:
        body: The body of one section.

    Returns:
        One verb for each numbered step, in the order the body holds them.
    """
    return [
        match.group(1)
        for match in (NUMBERED_STEP.match(line) for line in body.splitlines())
        if match is not None
    ]


def steps_intro(body: str) -> str:
    """Return the paragraph that stands in front of the numbered steps of one section.

    Args:
        body: The body of one section.

    Returns:
        The last block before the first numbered step, or an empty string where the body
        holds no step.
    """
    previous = ""
    for block in body.split("\n\n"):
        if numbered_steps(block):
            return previous
        if block.strip():
            previous = block
    return ""


def floating_sentences(text: str) -> List[str]:
    """Return every live sentence that dates itself against the day a reader reads it.

    Args:
        text: The whole page.

    Returns:
        The offending sentences, which is empty where every sentence names its date.
    """
    return [
        sentence for sentence in sentences(readable_text(text)) if FLOATING_DATE.search(sentence)
    ]


def listed_contexts() -> List[str]:
    """Return the check names the rule file lists.

    Returns:
        The lines of the first fenced block of the protection section.
    """
    return fenced_block(section(RULE_FILE.read_text(), PROTECTION_HEADING))


# --- The rule file states the live reading -------------------------------------------


def test_the_rule_file_states_that_the_provider_holds_a_required_status_check() -> None:
    """The protection section states that `dev` carries a required status check."""
    body = section(RULE_FILE.read_text(), PROTECTION_HEADING)
    claims = live_claims(body)
    assert claims, (
        f"{RULE_FILE} states no live claim that `dev` carries a required status check; "
        f"the section reads: {body[:300]!r}"
    )


def test_the_rule_file_dates_the_live_reading() -> None:
    """The protection section names the date of the read that reports the live rule."""
    body = section(RULE_FILE.read_text(), PROTECTION_HEADING)
    assert re.search(rf"read of {LIVE_READ_DATE}", body), (
        f"{RULE_FILE} states no `read of {LIVE_READ_DATE}` in its protection section"
    )


def test_the_rule_file_states_no_live_claim_that_the_repository_holds_no_check() -> None:
    """No live sentence of the rule file states that the repository holds no check."""
    claims = superseded_claims(RULE_FILE.read_text())
    assert claims == [], f"{RULE_FILE} states the superseded claim: {claims}"


def test_the_rule_file_states_the_application_of_the_required_contexts() -> None:
    """The protection section names the `app_id` that every required context carries."""
    body = section(RULE_FILE.read_text(), PROTECTION_HEADING)
    assert stated_application(body) == REQUIRED_APP_ID, (
        f"{RULE_FILE} states `app_id` {stated_application(body)!r} and the read of "
        f"{LIVE_READ_DATE} reports {REQUIRED_APP_ID}"
    )


def test_the_opening_claim_of_the_protection_section_names_its_condition() -> None:
    """The opening claim names the administrator limit the same section measures."""
    opening = opening_paragraph(section(RULE_FILE.read_text(), PROTECTION_HEADING))
    assert "enforce_admins" in opening, (
        f"{RULE_FILE} opens its protection section with a refusal that names no "
        "`enforce_admins` reading, and that reading is the condition on the refusal"
    )
    assert "administrator" in opening.lower(), (
        f"{RULE_FILE} opens its protection section with a refusal that names no "
        "administrator, and an administrator merge passes the provider with no run"
    )


def test_the_steps_of_the_protection_section_read_the_rule_and_change_nothing() -> None:
    """Every numbered step of the protection section reads, and its intro promises a read."""
    body = section(RULE_FILE.read_text(), PROTECTION_HEADING)
    verbs = numbered_steps(body)
    assert verbs, f"{RULE_FILE} holds no numbered step in its protection section"
    unread = [verb for verb in verbs if verb not in READ_VERBS]
    assert unread == [], (
        f"{RULE_FILE} states the steps {unread} in its protection section, and a change to "
        "branch protection is the user's, so every step here reads"
    )
    intro = steps_intro(body)
    assert CHANGE_PROMISE.search(intro) is None, (
        f"{RULE_FILE} promises a change of the rule and the {len(verbs)} steps below it "
        f"read: {intro!r}"
    )
    assert "read" in intro.lower(), (
        f"{RULE_FILE} states what the steps below it do nowhere: {intro!r}"
    )


def test_no_live_sentence_of_the_rule_file_dates_itself_against_the_reader() -> None:
    """No live sentence of the rule file carries a floating date."""
    floating = floating_sentences(RULE_FILE.read_text())
    assert floating == [], (
        f"{RULE_FILE} dates these sentences against the day a reader reads them, and this "
        f"file records the cost of a reading quoted as a standing fact: {floating}"
    )


# --- The 2026-08-09 reading survives as a dated record --------------------------------


def test_the_rule_file_keeps_the_superseded_reading() -> None:
    """The rule file holds the 2026-08-09 reading, with its exact result."""
    text = RULE_FILE.read_text()
    assert SUPERSEDED_READ_DATE in text, (
        f"{RULE_FILE} deletes the {SUPERSEDED_READ_DATE} reading, and a dated record of a "
        "past measurement is quoted rather than rewritten"
    )
    assert "Branch not protected" in text, (
        f"{RULE_FILE} holds no `Branch not protected`, which is the result the "
        f"{SUPERSEDED_READ_DATE} read returned"
    )


def test_the_rule_file_marks_the_superseded_reading() -> None:
    """The rule file marks the 2026-08-09 reading superseded rather than live."""
    body = section(RULE_FILE.read_text(), PROTECTION_HEADING)
    marked = [
        block
        for block in body.split("\n\n")
        if SUPERSEDED_READ_DATE in block and SUPERSEDED_MARKER in block.lower()
    ]
    assert marked, (
        f"{RULE_FILE} holds no paragraph that names both {SUPERSEDED_READ_DATE} and "
        f"{SUPERSEDED_MARKER!r}, so a reader reads the past reading as the live one"
    )


# --- The two limits -------------------------------------------------------------------


@pytest.mark.parametrize("field", STATED_LIMITS)
def test_the_rule_file_states_each_limit_of_the_reading(field: str) -> None:
    """The rule file states the value the provider returned for one limit."""
    stated = stated_limit(RULE_FILE.read_text(), field)
    assert stated is not None, f"{RULE_FILE} states no `{field}` reads `true` or `false`"


def test_the_rule_file_states_that_the_rule_binds_no_administrator() -> None:
    """The rule file names the administrator the `enforce_admins` reading leaves out."""
    body = section(RULE_FILE.read_text(), PROTECTION_HEADING)
    assert "administrator" in body.lower(), (
        f"{RULE_FILE} states no limit on who the rule binds, and `enforce_admins` reads "
        "false, so the rule binds a contributor and not a repository administrator"
    )


def test_the_rule_file_states_why_the_strict_reading_suits_the_batch_model() -> None:
    """The rule file states the cost `strict` true would put on an integration branch."""
    body = section(RULE_FILE.read_text(), PROTECTION_HEADING)
    assert "`strict: true`" in body, (
        f"{RULE_FILE} states no reason the `strict` reading suits the batch model"
    )
    assert "integration branch" in body, (
        f"{RULE_FILE} names no integration branch in the `strict` reason, and that branch "
        "is what `strict: true` would send back to `dev` after another batch lands"
    )


# --- The list of check names ----------------------------------------------------------


def test_the_rule_file_lists_the_eleven_required_check_names() -> None:
    """The rule file lists exactly the eleven contexts the read of 2026-08-10 reports."""
    listed = listed_contexts()
    assert listed == list(REQUIRED_CONTEXTS), (
        f"{RULE_FILE} lists {listed}, and the read of {LIVE_READ_DATE} reports "
        f"{list(REQUIRED_CONTEXTS)}"
    )


def test_the_rule_file_leaves_the_unrequired_check_out_of_the_list() -> None:
    """The rule file lists no `build` context, which a path filter can leave absent."""
    assert UNREQUIRED_CONTEXT not in listed_contexts(), (
        f"{RULE_FILE} lists {UNREQUIRED_CONTEXT!r}, which belongs to a workflow that "
        "filters four paths, so a required entry would block every batch that touches none"
    )


def test_the_rule_file_keeps_the_warning_that_a_check_name_is_no_job_name() -> None:
    """The rule file keeps the warning that separates a check name from a job name."""
    body = section(RULE_FILE.read_text(), PROTECTION_HEADING)
    assert "a check name is not a job name" in body.lower(), (
        f"{RULE_FILE} drops the warning that a check name is not a job name, and the "
        "`test` job runs a matrix, so a required check named `test` matches nothing"
    )


def test_the_rule_file_keeps_the_warning_that_bars_the_unrequired_check() -> None:
    """The rule file keeps the reason `build` stays out of the required list."""
    body = section(RULE_FILE.read_text(), PROTECTION_HEADING)
    assert "docs-build.yml" in body, (
        f"{RULE_FILE} names no `docs-build.yml` in the protection section, so it states "
        f"no reason to leave {UNREQUIRED_CONTEXT!r} out of the required list"
    )


def test_the_rule_file_keeps_the_local_gate_command() -> None:
    """The rule file keeps the command that reads the same condition before the merge."""
    assert "python -m tests.batch_gate --pr" in RULE_FILE.read_text(), (
        f"{RULE_FILE} drops `python -m tests.batch_gate --pr <number>`, which reads the "
        "condition before the merge rather than at it"
    )


def test_the_rule_file_states_that_a_configuration_change_needs_the_user() -> None:
    """The rule file keeps the rule that the user changes the repository configuration."""
    body = section(RULE_FILE.read_text(), PROTECTION_HEADING)
    assert "no agent makes it" in body, (
        f"{RULE_FILE} drops the rule that the user changes branch protection"
    )


# --- The whole corpus -----------------------------------------------------------------


def test_the_sweep_reads_more_than_one_document() -> None:
    """The sweep reads a non-empty file set, because an aggregate over an empty set passes."""
    files = documentation_files()
    assert len(files) > 1, f"the sweep reads {len(files)} files"
    for required in (RULE_FILE, REPO_ROOT / "CLAUDE.md"):
        assert required in files, f"the sweep reads no {required}"


def test_no_document_states_that_the_repository_holds_no_required_status_check() -> None:
    """No live sentence of the corpus states the superseded claim."""
    offenders: Dict[str, List[str]] = {}
    for path in documentation_files():
        claims = superseded_claims(path.read_text())
        if claims:
            offenders[str(path.relative_to(REPO_ROOT))] = claims
    assert offenders == {}, f"these documents state the superseded claim: {offenders}"


def test_claude_md_names_the_rule_file() -> None:
    """`CLAUDE.md` keeps the pointer to the rule file a merge reader follows."""
    text = (REPO_ROOT / "CLAUDE.md").read_text()
    assert ".claude/rules/batch-gate.md" in text, "CLAUDE.md names no batch-gate rule file"


# --- The readers, driven in both directions -------------------------------------------


SUPERSEDED_PHRASINGS = (
    "A required status check refuses the merge inside the provider, and this repository "
    "holds none.",
    "This repository holds no required status check.",
    "`dev` carries no required status check.",
    "The provider holds no required status check for `dev`.",
    "There is no required status check on the integration branch.",
    "A required status check is the strongest shape, and this repository has none.",
    # The eight a self-review wrote, which the first form of the pattern read nothing in.
    "The repository lacks a required status check.",
    "`dev` runs without a required status check.",
    "The required status checks were never added.",
    "A required status check is absent from this repository.",
    "The branch `dev` is unprotected.",
    "This repository holds no required check.",
    "Branch protection is off for `dev`.",
    "The required status check list is empty.",
    "Nothing at the provider refuses an ungated merge.",
)

LIVE_PHRASINGS = (
    "`dev` carries a required status check, and the provider refuses a merge that no "
    "successful run covers.",
    "The provider holds a required status check on `dev`.",
    "A read of 2026-08-10 reports that `dev` carries eleven required status checks.",
)

CONTROL_SENTENCES = (
    "The provider holds no run for the head commit.",
    "A run of the head commit has not finished.",
    "`gh pr checks` writes 'no checks reported' where the event created nothing.",
    "A member commit ends with the keyword and it names the keyword nowhere else.",
    # The widened pattern names `required check` and `branch protection`, so these four
    # true sentences of the repaired file prove that it reports no correct statement.
    "A required check that never reports blocks the merge.",
    "The required status checks hold no `build` context.",
    "A change to branch protection changes the repository configuration.",
    "The rule binds a contributor, and it binds no repository administrator.",
)


@pytest.mark.parametrize("sentence", SUPERSEDED_PHRASINGS)
def test_the_reader_reads_the_superseded_claim_of_every_wording(sentence: str) -> None:
    """The reader reports each plausible wording of the superseded claim."""
    assert superseded_claims(sentence) == [sentence]


@pytest.mark.parametrize("sentence", LIVE_PHRASINGS)
def test_the_reader_reads_no_superseded_claim_in_a_live_sentence(sentence: str) -> None:
    """The reader reports no live statement of the rule as a superseded claim."""
    assert superseded_claims(sentence) == []


@pytest.mark.parametrize("sentence", LIVE_PHRASINGS)
def test_the_live_reader_reads_each_live_wording(sentence: str) -> None:
    """The live reader reports each wording that states the rule is on."""
    assert live_claims(sentence) == [sentence]


@pytest.mark.parametrize("sentence", CONTROL_SENTENCES)
def test_neither_reader_reads_a_sentence_about_a_run(sentence: str) -> None:
    """A sentence about a workflow run reaches neither reader."""
    assert superseded_claims(sentence) == []
    assert live_claims(sentence) == []


@pytest.mark.parametrize("sentence", SUPERSEDED_PHRASINGS)
def test_a_quoted_superseded_claim_reaches_no_case(sentence: str) -> None:
    """A claim inside a quotation is a past measurement, so the reader passes over it."""
    assert superseded_claims(f"> {sentence}") == []


@pytest.mark.parametrize("sentence", SUPERSEDED_PHRASINGS)
def test_a_marked_superseded_claim_reaches_no_case(sentence: str) -> None:
    """A claim in a paragraph that marks itself superseded reaches no case."""
    paragraph = f"This reading is superseded. {sentence}"
    assert superseded_claims(paragraph) == []


def test_an_unmarked_superseded_claim_of_a_neighbouring_paragraph_reaches_a_case() -> None:
    """The marker covers one paragraph, so the next paragraph carries no exemption."""
    page = (
        "A read of 2026-08-09 is superseded.\n\n"
        "A required status check refuses the merge, and this repository holds none.\n"
    )
    assert superseded_claims(page) != []


def test_the_changelog_cut_removes_a_claim_of_the_changelog_section() -> None:
    """`readable_text` cuts the `## Changelog` section, which quotes a past reading."""
    page = "## Changelog\n\nThis repository holds no required status check.\n"
    assert superseded_claims(page) == []


def test_the_changelog_cut_removes_no_claim_of_the_section_that_follows_it() -> None:
    """The cut ends at the next second-level heading, so a later section still reads."""
    page = (
        "## Changelog\n\nA past round.\n\n"
        "## Branch model\n\nThis repository holds no required status check.\n"
    )
    assert superseded_claims(page) != []


def test_the_stated_limit_reader_reads_each_value() -> None:
    """The limit reader reads `true` and `false` apart."""
    assert stated_limit("`strict` reads `false`.", "strict") is False
    assert stated_limit("`strict` reads `true`.", "strict") is True
    assert stated_limit("`strict` is off.", "strict") is None


def test_the_section_reader_keeps_a_subsection_of_the_section() -> None:
    """The section reader keeps a `###` subsection, which holds part of the rule."""
    page = "## One\n\nfirst\n\n### Inside\n\nsecond\n\n## Two\n\nthird\n"
    body = section(page, "## One")
    assert "first" in body
    assert "second" in body


def test_the_section_reader_stops_at_the_next_heading_of_the_same_level() -> None:
    """The section reader drops the section that follows, whose rule is another rule."""
    page = "## One\n\nfirst\n\n## Two\n\nthird\n"
    assert "third" not in section(page, "## One")


def test_the_section_reader_reads_an_issue_reference_as_no_heading() -> None:
    """An issue reference at the start of a line ends no section, because it is no heading."""
    page = "## One\n\n#468 turned the rule on.\n\nsecond\n\n## Two\n\nthird\n"
    body = section(page, "## One")
    assert "second" in body
    assert "third" not in body


FLOATING_SENTENCES = (
    "The read of 2026-08-10 reports no `build` context, so the rule holds this warning today.",
    "A keyword-free head is the one head that now starts one.",
    "The provider currently holds eleven required contexts.",
    "The ruleset list is empty at the moment.",
)

DATED_SENTENCES = (
    "The read of 2026-08-10 reports no `build` context, so this warning follows that read.",
    "A read of 2026-08-09 returned a different result, and this record supersedes it.",
    # The boundary of `\bnow\b` ends the word, so `nowhere` reaches no match.
    "A member commit ends with the keyword, and it names the keyword nowhere else.",
)


@pytest.mark.parametrize("sentence", FLOATING_SENTENCES)
def test_the_floating_date_reader_reads_each_sentence_that_names_no_date(
    sentence: str,
) -> None:
    """The reader reports each sentence that dates itself against its reader."""
    assert floating_sentences(sentence) == [sentence]


@pytest.mark.parametrize("sentence", DATED_SENTENCES)
def test_the_floating_date_reader_reads_no_sentence_that_names_its_date(
    sentence: str,
) -> None:
    """The reader reports no sentence that names the date of its reading."""
    assert floating_sentences(sentence) == []


def test_the_steps_intro_reader_reads_the_promise_of_a_change() -> None:
    """The reader parts a promise of a change from a statement of a read."""
    assert CHANGE_PROMISE.search("These are the exact steps to read the rule or to change it.")
    assert (
        CHANGE_PROMISE.search(
            "These four steps read the rule at the provider, and they change nothing."
        )
        is None
    )


def test_the_step_reader_reads_the_verb_of_every_numbered_step() -> None:
    """The step reader returns the first word of each numbered step."""
    assert numbered_steps("text\n\n1. Open the page.\n2. Read the rule.\n") == [
        "Open",
        "Read",
    ]


def test_the_steps_intro_reader_returns_the_block_in_front_of_the_steps() -> None:
    """The intro reader returns the last paragraph before the first numbered step."""
    assert steps_intro("first\n\nthe intro\n\n1. Open the page.\n") == "the intro"


def test_the_opening_paragraph_reader_returns_the_first_block_that_holds_text() -> None:
    """The opening reader passes over a blank block and returns the first paragraph."""
    assert opening_paragraph("\n\nfirst\n\nsecond\n") == "first"


def test_the_application_reader_reads_the_number_the_file_states() -> None:
    """The application reader reads an `app_id` statement and an absent one apart."""
    assert stated_application("Each context carries `app_id` 15368.") == REQUIRED_APP_ID
    assert stated_application("Each context carries one application.") is None


def test_the_check_reader_reads_the_application_of_every_context() -> None:
    """The check reader returns the `app_id` the provider states for each context."""
    reading = {"required_status_checks": {"checks": [{"context": "lint", "app_id": 15368}]}}
    assert check_applications(reading) == {"lint": REQUIRED_APP_ID}


def test_the_check_reader_reports_a_context_of_another_application() -> None:
    """The check reader reports the `app_id` of a context another application publishes."""
    reading = {"required_status_checks": {"checks": [{"context": "lint", "app_id": 99}]}}
    assert check_applications(reading) == {"lint": 99}


def test_the_check_reader_reports_a_reading_that_holds_no_check_list() -> None:
    """The check reader fails a reading that holds `contexts` and no `checks`."""
    with pytest.raises(AssertionError):
        provider_checks({"required_status_checks": {"contexts": ["lint"]}})


def test_the_fenced_block_reader_reads_the_first_block_alone() -> None:
    """The block reader returns the lines of the first fenced block and stops there."""
    body = "```\nlint\nfuzz\n```\n\ntext\n\n```\nbuild\n```\n"
    assert fenced_block(body) == ["lint", "fuzz"]


# --- The provider ---------------------------------------------------------------------


def test_the_provider_reader_returns_no_reading_where_the_command_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reader returns None where the host holds no `gh`."""

    def absent(*args: object, **kwargs: object) -> object:
        raise FileNotFoundError("gh")

    monkeypatch.setattr(subprocess, "run", absent)
    assert protection_reading() is None


def test_the_provider_reader_returns_no_reading_where_the_call_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reader returns None where `gh` exits non-zero."""

    def refused(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(list(PROTECTION_COMMAND), 1, "", "gh: not logged in")

    monkeypatch.setattr(subprocess, "run", refused)
    assert protection_reading() is None


def test_the_provider_reader_returns_no_reading_where_the_body_is_no_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reader returns None where the response body is not a JSON object."""

    def html(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(list(PROTECTION_COMMAND), 0, "<html>", "")

    monkeypatch.setattr(subprocess, "run", html)
    assert protection_reading() is None


def test_the_provider_reader_returns_the_body_of_a_successful_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reader returns the parsed body where the call succeeds."""

    def answered(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
        body = json.dumps({"required_status_checks": {"contexts": ["lint"], "strict": False}})
        return subprocess.CompletedProcess(list(PROTECTION_COMMAND), 0, body, "")

    monkeypatch.setattr(subprocess, "run", answered)
    reading = protection_reading()
    assert reading is not None
    assert provider_contexts(reading) == ["lint"]


def test_the_live_context_case_skips_where_the_provider_returns_no_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The live case skips where no call is possible, and it does not pass."""
    monkeypatch.setattr(subprocess, "run", _refuse_every_call)
    with pytest.raises(pytest.skip.Exception):
        test_the_provider_requires_the_contexts_the_rule_file_lists()


def _refuse_every_call(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
    """Return a refused call, so `protection_reading` returns None.

    Returns:
        A completed process that exited 1.
    """
    return subprocess.CompletedProcess(list(PROTECTION_COMMAND), 1, "", "refused")


def test_the_provider_requires_the_contexts_the_rule_file_lists() -> None:
    """The provider requires the eleven contexts the rule file lists."""
    listed: Sequence[str] = listed_contexts()
    # The floor reads with no network. Two empty sets compare equal, so a file that lists
    # no context would otherwise pass this case against any provider.
    assert len(listed) == len(REQUIRED_CONTEXTS), (
        f"{RULE_FILE} lists {len(listed)} contexts and the reading holds {len(REQUIRED_CONTEXTS)}"
    )
    reading = reading_or_skip()
    held = provider_contexts(reading)
    assert held, "the provider requires no context, and the rule file states eleven"
    assert sorted(held) == sorted(listed), (
        f"the provider requires {sorted(held)} and {RULE_FILE} lists {sorted(listed)}"
    )


def test_the_application_case_skips_where_the_provider_returns_no_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The application case skips where no call is possible, and it does not pass."""
    monkeypatch.setattr(subprocess, "run", _refuse_every_call)
    with pytest.raises(pytest.skip.Exception):
        test_the_provider_carries_the_stated_application_on_every_context()


def test_the_provider_carries_the_stated_application_on_every_context() -> None:
    """The provider publishes every required context from the application the file states."""
    stated = stated_application(section(RULE_FILE.read_text(), PROTECTION_HEADING))
    listed: Sequence[str] = listed_contexts()
    # The floor reads with no network. An empty map compares equal to an empty list of
    # listed contexts, so a file that lists none would otherwise pass against any provider.
    assert stated == REQUIRED_APP_ID, (
        f"{RULE_FILE} states `app_id` {stated!r} and the read of {LIVE_READ_DATE} reports "
        f"{REQUIRED_APP_ID}"
    )
    assert len(listed) == len(REQUIRED_CONTEXTS), (
        f"{RULE_FILE} lists {len(listed)} contexts and the reading holds {len(REQUIRED_CONTEXTS)}"
    )
    reading = reading_or_skip()
    held = check_applications(reading)
    assert held, "the provider holds no `checks` entry, and the rule file lists eleven contexts"
    assert sorted(held) == sorted(listed), (
        f"the provider publishes {sorted(held)} and {RULE_FILE} lists {sorted(listed)}"
    )
    other = {name: found for name, found in held.items() if found != stated}
    assert other == {}, (
        f"the provider publishes these contexts from another application, and {RULE_FILE} "
        f"states `app_id` {stated}: {other}"
    )


@pytest.mark.parametrize("field", STATED_LIMITS)
def test_the_provider_holds_each_limit_the_rule_file_states(field: str) -> None:
    """The provider holds the value the rule file states for one limit."""
    stated = stated_limit(RULE_FILE.read_text(), field)
    assert stated is not None, f"{RULE_FILE} states no value for `{field}`"
    reading = reading_or_skip()
    if field == "strict":
        held = required_status_checks(reading).get("strict")
    else:
        entry = reading.get(field)
        assert isinstance(entry, dict), f"the provider holds no `{field}` object"
        held = entry.get("enabled")
    assert held is stated, (
        f"the provider reads `{field}` {held!r} and {RULE_FILE} states {stated!r}"
    )
