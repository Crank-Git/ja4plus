"""Tests that the documentation states the FoxIO image count the inventory measures.

`docs/specs/foxio/README.md` holds the inventory of `technical_details/` at the pinned
commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`. The directory holds twelve files:
three text files and nine images. One method of twelve holds a complete text
specification, and that method is JA4.

#195 corrected four files and left three that kept the superseded count. #211 corrects
the three and adds these cases, so that a later reader finds the contradiction here
rather than in a review.

## Why the first form of this file caught nothing

The user states the rule. **"A check that a rewording defeats is not a check."**

#211 wrote the constant `SUPERSEDED_COUNT = "seven of the twelve"`. It searched each line
of each page for that one phrase. `docs/specs/spec.html` writes `Seven of twelve FoxIO
methods are specified only as images.`, and that sentence carries no `the`. The page
therefore held the superseded count for 97 rounds while the case passed. #449 measured the
defect and this file now reads a shape.

Two properties follow, and each closes one half of the hole.

1. **The reader reads a count, and it forbids no phrase.** `image_count_claims` matches a
   count that binds to the word `method`, followed by a claim about an image or about a
   complete text specification. A document passes when its count equals the count the
   inventory measures, so a rewording that keeps the wrong number still fails.
2. **The count comes out of the inventory.** `measured_image_count` reads the file table
   and the numbered statements of `docs/specs/foxio/README.md`. A case that restated
   eleven would pass on the day FoxIO publishes a thirteenth method.

## What a case here does not read

**A dated record of a past measurement is quoted, not rewritten.** The `## Changelog`
section of `docs/specs/spec.md` records the state of the project at the time of writing,
and round 162 quotes the defective sentence of `docs/specs/spec.html` word for word.
`readable_text` cuts that section, so a correction here destroys no record. `CHANGELOG.md`
reaches no case here at all, because `_documentation_files` never held it.

**A count of another thing stands.** `docs/specs/foxio/JA4T.md` states `7 of the 12 moved
values are of that shape`, and `docs/specs/foxio/README.md` states that FoxIO published a
text specification for seven methods. Neither sentence claims an image count.
`test_the_reader_reads_no_wrong_count_where_a_sentence_counts_another_thing` holds eight
such sentences against the reader.

## The holes this reader keeps, which a review of #449 measured

A shape reads more spellings than a phrase reads, and it reads no sentence at all. These
spellings state a count and reach no case here. Each one is recorded and none is closed.

- **A complement.** `All but one FoxIO method is specified only as an image` states the
  true count as the number it excludes. `COMPLEMENT_COUNT` skips such a count, so
  `All but five` states a wrong count and passes.
- **A sentence with no count.** `Every FoxIO method except JA4 is specified only as an
  image` holds no number to read.
- **A long aside.** More than two words, or an aside inside two dashes, breaks the bond
  between the count and the word `method`.
- **A wide clause.** `CLAIM_WINDOW` is 40 characters, so a claim further than that from
  the noun reaches no pattern.
- **A synonym.** `technique` and `approach` reach nothing. `.claude/rules/ste.md` forbids
  a synonym of a term, so a compliant page writes `method`.
- **A count of another noun.** `Seven diagrams are the only specification FoxIO gives`
  counts diagrams and not methods.

These cases read prose. They import nothing from `ja4plus` and they produce no
fingerprint.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# The page that measures `technical_details/` at the pinned commit. Every count a case
# here compares against comes out of this page.
INVENTORY = REPO_ROOT / "docs" / "specs" / "foxio" / "README.md"

# The count word this project writes for each number. A claim states its count as a word
# or as a digit, and the reader accepts both forms.
NUMBER_WORDS: Dict[str, int] = {
    "zero": 0,
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

# `technical_details/README.md` lists these twelve methods at the pinned commit.
FOXIO_METHODS = (
    "JA4",
    "JA4S",
    "JA4H",
    "JA4L",
    "JA4LS",
    "JA4X",
    "JA4SSH",
    "JA4T",
    "JA4TS",
    "JA4TScan",
    "JA4D",
    "JA4D6",
)

CONFORMANCE_FEATURE = REPO_ROOT / "docs" / "specs" / "features" / "01-spec-conformance.md"

# An HTML tag, which the reader drops before it splits `docs/specs/spec.html` into
# sentences. A tag inside a sentence otherwise hides the words on each side of it.
HTML_TAG = re.compile(r"<[^>]+>")

# The end of a sentence. The reader binds a count to the claim of its own sentence,
# because one paragraph states the image count beside a count of another thing.
SENTENCE_END = re.compile(r"(?<=[.!?])\s+")

# One count, as a word or as a digit.
COUNT = r"(?P<count>" + "|".join(NUMBER_WORDS) + r"|\d+)"

# The noun a count binds to. `of them` and `of the twelve` carry the noun of the clause
# before them, as in `The FoxIO methods number twelve, and seven of them are images`.
COUNTED_NOUN = r"(?:(?:\s+[\w+/-]+){0,2}\s+methods?|\s+of\s+(?:them|the\s+twelve|twelve))\b"

# A count that binds to the word `method`. The optional `of the twelve` carries the whole
# set, and up to two words stand between the count and the noun, as in `Seven of twelve
# FoxIO methods`.
COUNT_PHRASE = (
    r"\b" + COUNT + r"\b"
    r"(?:\s+(?:of|out\s+of)\s+(?:the\s+|its\s+)?(?:twelve|12))?" + COUNTED_NOUN
)

# The claim that makes a count an image count. FoxIO publishes a method as an image, or
# the method carries no complete text specification. A sentence that states neither counts
# another thing.
IMAGE_CLAIM = (
    r"(?:"
    r"as\s+(?:an?\s+)?images?"
    r"|only\s+in\s+(?:an?\s+)?images?"
    r"|image-only"
    r"|(?:carry|carries|hold|holds|have|has)\s+no\s+complete\s+text\s+specification"
    r"|lacks?\s+(?:any\s+|a\s+)?complete\s+text\s+specification"
    r")"
)

# **Warning: the window between the noun and the claim is 40 characters.** A longer window
# reaches the claim of a neighbouring clause and reports a count that sentence never made.
CLAIM_WINDOW = r"[^.]{0,40}?"

# The word order that states the claim first and the count last, as in `The count of FoxIO
# methods specified only as images is seven` and `FoxIO methods specified only as images:
# seven`. #449 found four such spellings, and the first form of the reader read none.
TRAILING_COUNT_CLAIM = (
    r"\bmethods?\b" + CLAIM_WINDOW + IMAGE_CLAIM + r"[^.]{0,20}?(?:\bis\b|:)\s+" + COUNT + r"\b"
)

# The word order that opens with the count and names the noun after the claim, as in
# `Seven is the count of FoxIO methods specified only as images`.
LEADING_COUNT_CLAIM = (
    r"\b" + COUNT + r"\s+is\s+the\s+(?:count|number)\s+of" + CLAIM_WINDOW + r"\bmethods?\b"
    r"[^.]{0,40}?" + IMAGE_CLAIM
)

IMAGE_COUNT_CLAIMS = (
    re.compile(COUNT_PHRASE + CLAIM_WINDOW + IMAGE_CLAIM, re.IGNORECASE),
    re.compile(TRAILING_COUNT_CLAIM, re.IGNORECASE),
    re.compile(LEADING_COUNT_CLAIM, re.IGNORECASE),
)

# A count that states the complement of the set, as in `All but one FoxIO method is
# specified only as an image`. **The count of such a sentence is the count it excludes**,
# so the reader skips it rather than report one where the inventory measures eleven.
# **The hole is deliberate**: a page that writes `All but five` states a wrong count and
# reaches no case here.
COMPLEMENT_COUNT = re.compile(r"\ball\s+(?:but|except)\s*$", re.IGNORECASE)

# The fixed phrase #211 forbade. It stands here as the record of the defect #449 measured,
# and no case searches a document for it.
SUPERSEDED_PHRASE = "seven of the twelve"

# The heading of the section that records a state of the project at the time of writing.
# `readable_text` cuts it out of `docs/specs/spec.md`.
RECORD_SECTION = "## Changelog"

# The row of the inventory table that names one file of `technical_details/`.
INVENTORY_ROW = re.compile(r"^\|\s*`(?P<name>[\w.]+)`\s*\|\s*(?P<bytes>\d+)\s*\|")

# The statement of `## What the inventory states` that counts the files of the directory.
FILE_COUNT_STATEMENT = re.compile(
    r"directory\s+holds\s+(?P<files>\w+)\s+files:\s*"
    r"(?P<text>\w+)\s+text\s+files\s+and\s+(?P<images>\w+)\s+images",
    re.IGNORECASE,
)

# The statement of `## What the inventory states` that counts the complete text
# specifications. The measured image count is the method count less this number.
TEXT_SPECIFICATION_STATEMENT = re.compile(
    r"\b(?P<count>\w+)\s+methods?\s+of\s+twelve\s+(?:holds?|carries|carry)\s+"
    r"a\s+complete\s+text\s+specification",
    re.IGNORECASE,
)

# The extension of an image of `technical_details/`.
IMAGE_SUFFIX = ".png"


def _plain(text: str) -> str:
    """Return the text with no HTML tag and one space between words.

    A line break splits a sentence of `docs/specs/spec.html`, so a reader that reads one
    line at a time misses a claim the page wraps.

    Args:
        text: The text of one document.

    Returns:
        The text as one line.
    """
    return " ".join(HTML_TAG.sub(" ", text).split())


def image_count_claims(text: str) -> List[Tuple[int, str]]:
    """Return every claim about the count of methods FoxIO publishes as an image.

    Args:
        text: The text of one document, or one passage of it.

    Returns:
        The count and the matching phrase of each claim, in the order the text holds them.
        A phrase that `all but` opens states the complement of the count, and the reader
        returns nothing for it.
    """
    found: List[Tuple[int, str]] = []
    for sentence in SENTENCE_END.split(_plain(text)):
        # Two patterns match one sentence where the claim carries two word orders, so the
        # reader reports each count of one sentence once.
        counted: List[int] = []
        for pattern in IMAGE_COUNT_CLAIMS:
            for match in pattern.finditer(sentence):
                if COMPLEMENT_COUNT.search(sentence[: match.start("count")]):
                    continue
                word = match.group("count").lower()
                count = NUMBER_WORDS[word] if word in NUMBER_WORDS else int(word)
                if count not in counted:
                    counted.append(count)
                    found.append((count, match.group(0)))
    return found


def readable_text(path: Path, text: str) -> str:
    """Return the text of one document with the section that records a past state removed.

    Args:
        path: The path of the document.
        text: The whole text of the document.

    Returns:
        The text a case reads. `docs/specs/spec.md` loses its `## Changelog` section.
    """
    if path.name != "spec.md":
        return text
    start = text.find(f"\n{RECORD_SECTION}")
    if start == -1:
        return text
    end = text.find("\n## ", start + 1)
    return text[:start] + (text[end:] if end != -1 else "")


def inventory_files() -> Dict[str, int]:
    """Return the files of `technical_details/` the inventory table records.

    Returns:
        The byte count of each file, keyed by file name.

    Raises:
        AssertionError: The table holds no row.
    """
    files = {}
    for line in INVENTORY.read_text(encoding="utf-8").splitlines():
        match = INVENTORY_ROW.match(line)
        if match:
            files[match.group("name")] = int(match.group("bytes"))
    assert files, "the inventory table holds no row"
    return files


def complete_text_specification_count() -> int:
    """Return the count of methods that hold a complete text specification.

    Returns:
        The number the numbered statements of the inventory state.

    Raises:
        AssertionError: The inventory states no such count.
    """
    match = TEXT_SPECIFICATION_STATEMENT.search(_plain(INVENTORY.read_text(encoding="utf-8")))
    assert match, "the inventory counts no complete text specification"
    return NUMBER_WORDS[match.group("count").lower()]


def measured_image_count() -> int:
    """Return the count of methods that carry no complete text specification.

    A restated number goes stale on the day FoxIO publishes another method, so the count
    comes out of the inventory and out of the method list.

    Returns:
        The method count less the count of complete text specifications.
    """
    return len(FOXIO_METHODS) - complete_text_specification_count()


def _documentation_files() -> list[Path]:
    """Return every prose file that may state the FoxIO image count.

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


def _section(text: str, heading: str) -> str:
    """Return the body of one Markdown section, up to the next heading of any level.

    Args:
        text: The whole page.
        heading: The heading line, including its `#` characters.

    Returns:
        The text after the heading and before the next line that starts with `#`.

    Raises:
        AssertionError: The page holds no line equal to the heading.
    """
    # A paragraph quotes a heading, so a search of the whole page reaches the quotation
    # first and returns the wrong body. Match the heading as a whole line instead.
    page = text.splitlines()
    starts = [number for number, line in enumerate(page) if line.strip() == heading]
    assert starts, f"the page holds no {heading!r} heading"
    assert len(starts) == 1, f"the page holds {len(starts)} {heading!r} headings"
    lines: list[str] = []
    for line in page[starts[0] + 1 :]:
        if line.startswith("#"):
            break
        lines.append(line)
    return "\n".join(lines)


def _first_table(section: str) -> list[str]:
    """Return the rows of the first Markdown table of one section.

    A section holds more than one table, so a case that reads every row of the section
    passes on a name another table carries.

    Args:
        section: The body of one section.

    Returns:
        The lines of the first table, header row first.

    Raises:
        AssertionError: The section holds no table.
    """
    rows: list[str] = []
    for line in section.splitlines():
        if line.startswith("|"):
            rows.append(line)
        elif rows:
            break
    assert rows, "the section holds no table"
    return rows


def _bullet(section: str, subject: str) -> list[str]:
    """Return every line of the one bullet that opens with the subject.

    A bullet wraps over several lines, so a case that reads one line misses the rest.

    Args:
        section: The body of one section.
        subject: The word the bullet opens with.

    Returns:
        The lines of the bullet, or an empty list when the section holds no such bullet.
    """
    lines: list[str] = []
    for line in section.splitlines():
        if line.startswith(f"- {subject}"):
            lines.append(line)
        # The next bullet and a blank line each end this bullet. A search that stops on
        # the next bullet alone swallows the prose that follows the last bullet.
        elif lines and (line.startswith("- ") or not line.strip()):
            break
        elif lines:
            lines.append(line)
    return lines


def test_the_inventory_table_records_twelve_files() -> None:
    """The inventory table of `technical_details/` holds one row for each of twelve files."""
    assert len(inventory_files()) == 12, f"the table records {len(inventory_files())} files"


def test_the_inventory_table_records_nine_images_and_three_text_files() -> None:
    """The inventory table records nine images and three text files."""
    files = inventory_files()
    images = [name for name in files if name.endswith(IMAGE_SUFFIX)]
    assert len(images) == 9, f"the table records {len(images)} images"
    assert len(files) - len(images) == 3, f"the table records {len(files) - len(images)} text files"


def test_the_inventory_statement_states_the_count_its_own_table_records() -> None:
    """The numbered statement of the inventory counts the files its own table records."""
    match = FILE_COUNT_STATEMENT.search(_plain(INVENTORY.read_text(encoding="utf-8")))
    assert match, "the inventory states no file count"
    files = inventory_files()
    images = [name for name in files if name.endswith(IMAGE_SUFFIX)]
    stated = (
        NUMBER_WORDS[match.group("files").lower()],
        NUMBER_WORDS[match.group("text").lower()],
        NUMBER_WORDS[match.group("images").lower()],
    )
    assert stated == (len(files), len(files) - len(images), len(images)), (
        f"the statement counts {stated} and the table records "
        f"{(len(files), len(files) - len(images), len(images))}"
    )


def test_the_inventory_counts_one_complete_text_specification() -> None:
    """The inventory states that one method of twelve holds a complete text specification."""
    assert complete_text_specification_count() == 1, (
        f"the inventory counts {complete_text_specification_count()} complete text "
        "specifications, and `JA4.md` is the one file the table records as complete"
    )


def test_the_measured_image_count_is_the_method_count_less_the_text_specifications() -> None:
    """The measured image count is eleven, and each half of it comes out of a document."""
    assert measured_image_count() == len(FOXIO_METHODS) - complete_text_specification_count()
    assert measured_image_count() == 11, f"the inventory measures {measured_image_count()}"


def test_every_document_states_the_image_count_the_inventory_measures() -> None:
    """Every image count of the corpus equals the count the inventory measures."""
    measured = measured_image_count()
    offenders = []
    for path in _documentation_files():
        text = readable_text(path, path.read_text(encoding="utf-8"))
        for count, phrase in image_count_claims(text):
            if count != measured:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {phrase!r}")
    assert offenders == [], f"these claims state an image count that is not {measured}: {offenders}"


def test_the_rendered_specification_page_states_one_image_count() -> None:
    """`docs/specs/spec.html` states one image count and it contradicts itself nowhere."""
    page = REPO_ROOT / "docs" / "specs" / "spec.html"
    claims = image_count_claims(page.read_text(encoding="utf-8"))
    assert claims, "the page states no image count"
    counts = {count for count, _ in claims}
    assert len(counts) == 1, f"the page states the counts {sorted(counts)} in {claims}"


# The spellings the page could plausibly carry for the superseded count. #211 forbade one
# of them and the page carried another, so the reader is proved against the set.
SUPERSEDED_PHRASINGS = (
    "Seven of twelve FoxIO methods are specified only as images.",
    "Seven of the twelve FoxIO methods are specified only as images.",
    "seven of the twelve methods are published as an image.",
    "Seven of the 12 FoxIO methods are published as an image.",
    "7 of 12 FoxIO methods carry no complete text specification.",
    "Seven FoxIO methods are specified only as images.",
    "FoxIO publishes seven of its twelve methods only as images.",
    "Seven methods of the twelve are specified only as images.",
    "Seven of the twelve JA4+ methods hold no complete text specification.",
    "FoxIO publishes seven methods as images at the pinned commit.",
    "The FoxIO methods number twelve, and seven of them are specified only as images.",
    "The count of FoxIO methods specified only as images is seven.",
    "Seven is the count of FoxIO methods specified only as images.",
    "FoxIO methods specified only as images: seven.",
    "Seven of the twelve FoxIO methods lack a complete text specification.",
    "Seven of the twelve FoxIO methods are image-only.",
)


@pytest.mark.parametrize("sentence", SUPERSEDED_PHRASINGS)
def test_the_reader_reads_the_superseded_count_in_each_plausible_phrasing(sentence: str) -> None:
    """The reader reports seven for each spelling of the superseded count."""
    counts = [count for count, _ in image_count_claims(sentence)]
    assert counts == [7], f"the reader reads {counts} in {sentence!r}"


# The sentences that pair a count with an image or with a method and claim no wrong image
# count. The first six come out of the corpus and the last two state the true count as a
# complement. A reader that reports a wrong count for one of these matches every page and
# proves nothing.
CONTROL_SENTENCES = (
    "7 of the 12 moved values are of that shape, and the prose alone covers them.",
    "FoxIO published a text specification for seven methods, and commit `b6f3ff4` deleted"
    " all seven.",
    "Three methods hold no image at all: JA4LS, JA4TS and JA4TScan.",
    "The table of twelve methods, the nine image links, and the license note.",
    "The deleted `JA4H.md` states the nine request methods it counts.",
    "Eleven of the twelve FoxIO methods carry no complete text specification, and JA4 is"
    " the one method that holds one.",
    "All but one FoxIO method is specified only as an image.",
    "All except one of the twelve methods is specified only as an image.",
)


@pytest.mark.parametrize("sentence", CONTROL_SENTENCES)
def test_the_reader_reads_no_wrong_count_where_a_sentence_counts_another_thing(
    sentence: str,
) -> None:
    """The reader reports no wrong count for a sentence that states a true count or another.

    A reader that reported one of these would fail every page and prove nothing, so each
    count it reads here must equal the count the inventory measures.
    """
    counts = [count for count, _ in image_count_claims(sentence)]
    assert all(count == measured_image_count() for count in counts), (
        f"the reader reads {counts} in {sentence!r}"
    )


def test_the_reader_reads_a_claim_that_a_line_break_splits() -> None:
    """The reader reads one claim that a line break splits across three lines."""
    wrapped = "<li><strong>Seven of\ntwelve FoxIO methods are\nspecified only as images.</strong>"
    assert [count for count, _ in image_count_claims(wrapped)] == [7]


def test_the_fixed_phrase_matches_no_part_of_the_phrasing_the_rendered_page_carried() -> None:
    """The phrase #211 forbade matches nothing in the sentence `docs/specs/spec.html` held.

    This case is the record of the defect. The fixed phrase misses the page and the shape
    reads it, so the two halves stand beside each other.
    """
    carried = "Seven of twelve FoxIO methods are specified only as images."
    assert SUPERSEDED_PHRASE not in carried.lower(), (
        "the fixed phrase now matches the sentence, and this case records the opposite"
    )
    assert [count for count, _ in image_count_claims(carried)] == [7]


def test_the_reader_reads_the_quoted_count_of_a_changelog_round_and_a_case_does_not() -> None:
    """The reader reads the count round 162 quotes, and `readable_text` cuts that round."""
    specification = REPO_ROOT / "docs" / "specs" / "spec.md"
    whole = specification.read_text(encoding="utf-8")
    assert 7 in [count for count, _ in image_count_claims(whole)], (
        "the `## Changelog` section quotes no superseded count, so this case proves nothing"
    )
    counts = [count for count, _ in image_count_claims(readable_text(specification, whole))]
    assert 7 not in counts, f"`readable_text` cut no record, and the counts read {counts}"


@pytest.mark.parametrize("method", FOXIO_METHODS)
def test_the_conformance_interface_table_names_every_foxio_method(method: str) -> None:
    """The `Interfaces` table of the conformance feature names all twelve methods."""
    interfaces = _section(CONFORMANCE_FEATURE.read_text(encoding="utf-8"), "## Interfaces")
    names = {
        cell.strip().strip("`")
        for row in _first_table(interfaces)
        for cell in row.split("|")[1].split(",")
    }
    assert method in names, f"the table names no row for {method}"


def test_the_conformance_feature_states_the_ja4tscan_decline() -> None:
    """The `Out of scope` section records the JA4TScan decline, not an open question."""
    out_of_scope = _section(CONFORMANCE_FEATURE.read_text(encoding="utf-8"), "## Out of scope")
    ja4tscan = _bullet(out_of_scope, "JA4TScan")
    assert ja4tscan, "the section names no JA4TScan bullet"
    text = "\n".join(ja4tscan)
    assert "open question" not in text, "the bullet still calls JA4TScan an open question"
    assert "#197" in text, "the bullet cites no issue for the decline"
