"""Tests that every documented count of `tests/foxio_vectors/wireshark_expected/` is live.

#611 found two false sentences of `docs/specs/foxio/JA4L.md`. Each one states that the
directory holds two files and that neither carries a JA4L key. #116 added the two files,
and #531 raised the directory to 26 files, so the corpus grew under a sentence that stated
its size as a standing fact.

**A count stated as a standing fact goes stale on the day the corpus grows, and no reader
catches it.** A case that restated 26 would go stale the same way. Each case here therefore
measures the tree and requires the document to state the measured number, so the next
growth of the corpus fails a run.

## What a case here reads

`file_count` counts the JSON files of the directory. `files_that_carry_a_ja4l_key` counts
the files that hold the key `ja4.ja4l`, which the Wireshark dissector writes.
`ja4l_values` collects every value under that key.

`local_ja4l_value_count` counts the `JA4L-C` and `JA4L-S` values of
`tests/foxio_vectors/*.json`, which is the count R4 of the same document decided D1 on.

**The sweep of #611 found the same class on two more pages, and cases here hold both.**
`docs/specs/foxio/JA4X.md` stated 10 local Rust snapshots against 11 in the tree, and
`docs/specs/foxio/JA4SSH.md` stated ten JA4SSH register entries under three issues against
14 under four.

## What a case here does not read

**A dated record of a past measurement is quoted, not rewritten.** `CHANGELOG.md` records
one past round in every entry, and the `## Changelog` table of `docs/specs/spec.md` holds
one row for each round. `docs/specs/foxio/JA4L.md` quotes the two superseded sentences
under a block quote, and no case here reads a quoted line.
"""

import json
import re
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parent.parent
WIRESHARK_EXPECTED = REPO_ROOT / "tests" / "foxio_vectors" / "wireshark_expected"
FOXIO_VECTORS = REPO_ROOT / "tests" / "foxio_vectors"
RUST_EXPECTED = FOXIO_VECTORS / "rust_expected"
REGISTER_PATH = REPO_ROOT / "tests" / "foxio_deviations.json"
JA4L_PAGE = REPO_ROOT / "docs" / "specs" / "foxio" / "JA4L.md"
JA4X_PAGE = REPO_ROOT / "docs" / "specs" / "foxio" / "JA4X.md"
JA4SSH_PAGE = REPO_ROOT / "docs" / "specs" / "foxio" / "JA4SSH.md"

# The key the Wireshark dissector writes for a JA4L value. The FoxIO Python reference
# writes `JA4L-C` and `JA4L-S` instead, so a reader of one key finds none of the other.
DISSECTOR_JA4L_KEY = "ja4.ja4l"

# The two method keys the FoxIO Python reference writes into a vector file.
REFERENCE_JA4L_METHODS = ("JA4L-C", "JA4L-S")


def expected_output_files() -> List[Path]:
    """Return every expected-output file of the Wireshark directory, sorted by name."""
    return sorted(WIRESHARK_EXPECTED.glob("*.json"))


def collect_values(node: object, key: str, found: List[str]) -> None:
    """Append every value the document holds under the key, at any depth.

    Args:
        node: A decoded JSON value.
        key: The object key to collect.
        found: The list each value goes into.
    """
    if isinstance(node, dict):
        for name, value in node.items():
            if name == key:
                for one in value if isinstance(value, list) else [value]:
                    found.append(str(one))
            collect_values(value, key, found)
    elif isinstance(node, list):
        for item in node:
            collect_values(item, key, found)


def files_that_carry_a_ja4l_key() -> List[Path]:
    """Return every expected-output file that holds at least one `ja4.ja4l` value."""
    carriers = []
    for path in expected_output_files():
        found: List[str] = []
        collect_values(json.loads(path.read_text()), DISSECTOR_JA4L_KEY, found)
        if found:
            carriers.append(path)
    return carriers


def dissector_ja4l_values() -> List[str]:
    """Return every `ja4.ja4l` value the Wireshark directory holds."""
    found: List[str] = []
    for path in expected_output_files():
        collect_values(json.loads(path.read_text()), DISSECTOR_JA4L_KEY, found)
    return found


def local_ja4l_value_count() -> int:
    """Return the count of `JA4L-C` and `JA4L-S` values of `tests/foxio_vectors/*.json`."""
    total = 0
    for path in sorted(FOXIO_VECTORS.glob("*.json")):
        document = json.loads(path.read_text())
        if not isinstance(document, list):
            continue
        for stream in document:
            if not isinstance(stream, dict):
                continue
            for key in stream:
                if key.split(".")[0] in REFERENCE_JA4L_METHODS:
                    total += 1
    return total


def ja4ssh_register_entries() -> dict:
    """Return every register entry whose method name starts with `JA4SSH`."""
    register = json.loads(REGISTER_PATH.read_text())
    return {
        key: entry
        for key, entry in register.items()
        if key.split("/")[-1].split(".")[0].startswith("JA4SSH")
    }


def live_text(page: Path) -> str:
    """Return the page with every quoted line removed.

    A quoted line records superseded wording, so a case that read one would demand a
    rewrite of the record on the day the corpus grows.

    Args:
        page: The path of the document to read.

    Returns:
        The text of the page, without any line that opens a block quote.
    """
    lines = [line for line in page.read_text().splitlines() if not line.startswith(">")]
    return "\n".join(lines)


def live_page_text() -> str:
    """Return `docs/specs/foxio/JA4L.md` with every quoted line removed."""
    return live_text(JA4L_PAGE)


class TestTheDocumentStatesTheMeasuredCounts:
    def test_the_page_states_the_file_count_the_directory_holds(self):
        count = len(expected_output_files())
        text = live_page_text().replace("\n", " ")
        claim = "`tests/foxio_vectors/wireshark_expected/` holds {} files".format(count)
        assert text.count(claim) == 2, claim

    def test_the_page_states_how_many_files_carry_a_dissector_ja4l_key(self):
        count = len(files_that_carry_a_ja4l_key())
        text = live_page_text().replace("\n", " ")
        assert "of which {} carry a `ja4.ja4l` key".format(count) in text, count
        assert "{} of them carry a".format(count) in text, count

    def test_the_page_states_how_many_dissector_ja4l_values_the_directory_holds(self):
        values = dissector_ja4l_values()
        text = live_page_text().replace("\n", " ")
        assert "hold {} `ja4.ja4l` values".format(len(values)) in text, len(values)

    def test_every_dissector_ja4l_value_carries_three_parts(self):
        """The page states that the directory is a local route to a three-part value."""
        for value in dissector_ja4l_values():
            assert len(value.split("_")) == 3, value

    def test_the_page_states_the_local_ja4l_value_count_that_decided_d1(self):
        count = local_ja4l_value_count()
        text = live_page_text().replace("\n", " ")
        assert "Every one of the {} JA4L values in".format(count) in text, count


class TestTheDocumentRefusesTheSupersededCounts:
    def test_no_live_sentence_states_that_the_directory_holds_two_files(self):
        """#611 corrected both sentences, and each one stays under a block quote."""
        text = live_page_text().replace("\n", " ")
        assert "wireshark_expected/` holds two files" not in text

    def test_the_page_quotes_both_superseded_sentences(self):
        quoted = "\n".join(
            line for line in JA4L_PAGE.read_text().splitlines() if line.startswith(">")
        ).replace("\n", " ")
        assert "holds two files that carry no JA4L key" in quoted
        assert "holds two files today, and neither carries a" in quoted


class TestTheOtherPagesStateTheMeasuredCounts:
    """#611 swept `docs/specs/foxio/` for the class and found two more false counts."""

    def test_the_ja4x_page_states_the_snapshot_count_the_directory_holds(self):
        count = len(list(RUST_EXPECTED.glob("*.snap")))
        text = live_text(JA4X_PAGE).replace("\n", " ")
        assert "`tests/foxio_vectors/rust_expected/` holds {} of the".format(count) in text
        assert "| Local Rust snapshots | {} |".format(count) in text

    def test_the_ja4ssh_page_states_the_register_family_it_reads(self):
        entries = ja4ssh_register_entries()
        issues = {entry["issue"] for entry in entries.values()}
        text = live_text(JA4SSH_PAGE).replace("\n", " ")
        assert "holds {} JA4SSH entries under four issues".format(len(entries)) in text
        assert len(issues) == 4, sorted(issues)

    def test_the_ja4ssh_page_states_the_entry_count_of_each_issue_it_reads(self):
        entries = ja4ssh_register_entries()
        text = live_text(JA4SSH_PAGE).replace("\n", " ")
        for issue in (96, 97, 105):
            count = len([e for e in entries.values() if e["issue"] == issue])
            assert "#{} holds {} entries".format(issue, count) in text, issue


class TestTheRegisterCitesTheLineThatDeletesTheKey:
    def test_no_tracked_document_cites_the_if_line_as_the_deleting_line(self):
        """Line 339 holds the `if` and line 340 holds the `delete_keys` call.

        `CHANGELOG.md` and the `## Changelog` table of `docs/specs/spec.md` each record a
        past round, so this case reads neither one.
        """
        register = (REPO_ROOT / "tests" / "foxio_deviations.json").read_text()
        assert "python/ja4.py:339` runs" not in register
        assert register.count("python/ja4.py:340") == 10

    def test_the_page_cites_both_lines_of_the_two_line_block(self):
        text = live_page_text().replace("\n", " ")
        assert "`python/ja4.py:339` reads `if 'ja4l' not in output_types:`" in text
        assert re.search(r"`python/ja4\.py:340` reads\s+`delete_keys", text) is not None
