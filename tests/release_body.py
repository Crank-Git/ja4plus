"""Build the body of a GitHub release from the changelog section of that version.

`FR-release-14` asks the GitHub release body to hold the changelog section for that
version. The publish job of `.github/workflows/publish.yml` runs this module and writes the
result with `gh release edit`, and that step stands in front of the publish step. A
changelog with no section for the version therefore fails the release, and it publishes
nothing.

**The provider refuses a body of more than 125000 characters.** It answers `422` and it
names the limit. This module reads the length in front of the write, so the workflow stops
at a named step rather than at the provider. `BODY_LIMIT` holds the count.

**The body holds a named part of the section, and a link carries the rest.** The user ruled
on 2026-08-10, because the version 1.0.0 section is 242778 characters. The named part is
the summary and the two breaking-change tables, and the link names `CHANGELOG.md` at the
tag of the release. `named_part` and `changelog_link` build the two halves.

**This module truncates nothing.** A truncated changelog section is a body that reads as
complete and is not, and the choice of what to drop belongs to the maintainer. The module
reports a fault instead, and `docs/specs/features/09-release.md` states the state of
version 1.0.0 against this limit.

`ja4plus/__init__.py` is the one version declaration. This module reads it through
`tests/version_gate.py`, so no argument states a version and no second reader of the
declaration exists.

`tests/test_release_body.py` holds the cases against these readers, and
`tests/test_publish_workflow.py` holds the step order of the workflow that runs them.

Verified against https://docs.github.com/en/rest/releases/releases (retrieved 2026-08-10)
for the `body` field, and against https://cli.github.com/manual/gh_release_edit (retrieved
2026-08-10) for the `--notes-file` option.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from typing import Iterator, List, Optional, Tuple

from tests.version_gate import package_version

# The description the command line reports.
#
# **`python -OO` sets `__doc__` to None on every module.** A parser that read the module
# docstring here raised `AttributeError` under that interpreter, and it read no argument at
# all. `test_the_module_runs_where_the_interpreter_strips_every_docstring` holds the reader
# against that run.
DESCRIPTION = "Build the body of a GitHub release from the changelog section of that version."

# The longest body the provider accepts. A longer body answers `422` with
# `body is too long (maximum is 125000 characters)`.
BODY_LIMIT = 125000

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
CHANGELOG = REPOSITORY_ROOT / "CHANGELOG.md"
PACKAGE = REPOSITORY_ROOT / "ja4plus" / "__init__.py"

# The heading that opens any version section, as `## [0.6.0] - 2026-05`.
SECTION_HEADING = re.compile(r"^## \[", re.MULTILINE)

# The heading that opens the breaking-change tables of a section.
#
# **The named part ends where the breaking-change tables end.** The user ruled on
# 2026-08-10 that the body holds the summary and these two tables, and that a link carries
# the rest. A reader that named `### Added` instead would follow the entry list, and the
# entry list is the part that does not fit.
#
# **The reader matches a whole line, and it reads no line of a code block.** A summary
# paragraph that names the heading in prose, and a code block that quotes the heading, would
# each otherwise end the named part above the tables it exists to carry. **Such a reader
# reports no fault**, because it returns a part that reads as complete, so the self-review
# of #70 raised both cases rather than a run.
BREAKING_HEADING = "### The breaking changes"

# The heading of a part below the version heading, as `### Added`. The `####` heading of a
# breaking-change table holds one more mark, so this reader passes over it.
PART_HEADING = re.compile(r"^### ", re.MULTILINE)

# The line that opens one code block and the line that closes it. Markdown accepts three
# marks or more, and it accepts the tilde beside the backtick.
CODE_FENCE = re.compile(r"^\s*(?:`{3,}|~{3,})")

# The repository the link names. `docs/specs/spec.md` records this project at that address.
REPOSITORY_URL = "https://github.com/Crank-Git/ja4plus"

# The tag of a release, as the release skill writes it.
TAG_FORM = "v{version}"

# One inline Markdown link, as `[text](target)`.
#
# **The reader passes over an image, which the leading mark names.** An image needs the raw
# host, and every URL this module writes names `blob`, so a rewritten image target would
# render nothing. The named part holds no image today.
#
# The target holds no space, so a link that carries a title reaches the reader unchanged.
# Such a link stays relative, and `relative_link_targets` reports it rather than passes it.
LINK = re.compile(r"(?<!!)\[([^\]\n]*)\]\(([^)\s]+)\)")

# The opening of a target that already names an address, as `https:` or `mailto:`.
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")


def unfenced_lines(text: str) -> Iterator[Tuple[str, bool]]:
    """Return each line of the text beside the state of the code fence.

    A fence line reads as fenced, so no reader writes into the line that opens a block.

    Args:
        text: Any Markdown text.

    Returns:
        One pair for each line: the line, and True where the line stands in a code block.
    """
    fenced = False
    for line in text.splitlines(True):
        if CODE_FENCE.match(line):
            fenced = not fenced
            yield line, True
        else:
            yield line, fenced


def absolute_target(target: str, tag: str) -> str:
    """Return the address a reader outside the repository resolves for one link target.

    **A release body carries no base**, so a relative target resolves against nothing there.
    An anchor is the one relative form the body itself answers, because the body holds the
    heading it names.

    Args:
        target: The target of one Markdown link.
        tag: The tag of the release, as `v1.0.0`.

    Returns:
        The target unchanged where it names an anchor or an address, and the absolute URL
        of that path at the tag in every other case.
    """
    if target.startswith("#"):
        return target
    if target.startswith("//") or SCHEME.match(target):
        return target
    if target.startswith("/"):
        return f"{REPOSITORY_URL}/blob/{tag}{target}"
    return f"{REPOSITORY_URL}/blob/{tag}/{target}"


def link_targets(text: str) -> List[str]:
    """Return the target of every Markdown link the text holds outside a code block.

    Args:
        text: Any Markdown text.

    Returns:
        One target for each link, in the order the text holds them.
    """
    return [
        match.group(2)
        for line, fenced in unfenced_lines(text)
        if not fenced
        for match in LINK.finditer(line)
    ]


def relative_link_targets(text: str) -> List[str]:
    """Return every link target of the text that names no address a release page carries.

    The reader states the condition once, so this report and `absolute_links` never
    disagree. The tag it passes reaches no result, because a target the reader keeps is a
    target no tag changes.

    Args:
        text: Any Markdown text.

    Returns:
        One target for each relative link, in the order the text holds them.
    """
    return [target for target in link_targets(text) if absolute_target(target, "v0.0.0") != target]


def absolute_links(text: str, tag: str) -> str:
    """Return the text with an absolute URL in place of every relative link target.

    **The reader writes into no code block.** A rewrite there changes an example a reader
    copies, and `breaking_heading_end` reads the same fence for the same reason.

    Args:
        text: Any Markdown text.
        tag: The tag of the release, as `v1.0.0`.

    Returns:
        The text, with each relative target written against the repository and the tag.
    """

    def written(match: "re.Match[str]") -> str:
        return f"[{match.group(1)}]({absolute_target(match.group(2), tag)})"

    return "".join(
        line if fenced else LINK.sub(written, line) for line, fenced in unfenced_lines(text)
    )


def changelog_section(changelog_text: str, version: str) -> str:
    """Return the changelog section of one version.

    The reader matches the whole version between the brackets. `1.0` is the prefix of
    `1.0.0`, and a reader that matched a prefix would return the wrong section.

    Args:
        changelog_text: The text of `CHANGELOG.md`.
        version: The version the package declares.

    Returns:
        The section text, from its heading to the heading of the next version.

    Raises:
        RuntimeError: The file holds no section for the version, or the section holds no
            line below its heading.
    """
    opening = re.search(rf"^## \[{re.escape(version)}\]", changelog_text, re.MULTILINE)
    if opening is None:
        held = re.findall(r"^## \[([^\]]+)\]", changelog_text, re.MULTILINE)
        raise RuntimeError(f"`CHANGELOG.md` holds no `## [{version}]` section, and it holds {held}")
    following = SECTION_HEADING.search(changelog_text, opening.end())
    end = following.start() if following else len(changelog_text)
    section = changelog_text[opening.start() : end].strip()
    if not any(line.strip() for line in section.splitlines()[1:]):
        raise RuntimeError(f"the `## [{version}]` section of `CHANGELOG.md` holds no line")
    return section


def breaking_heading_end(section: str) -> Optional[int]:
    """Return the offset just past the breaking-change heading of one section.

    The reader takes a whole line, and it reads no line of a code block. A section that
    quotes the heading inside a code block therefore reaches the real heading below it.

    Args:
        section: One whole changelog section.

    Returns:
        The offset just past the heading line, or None where the section holds no such
        heading outside a code block.
    """
    offset = 0
    fenced = False
    for line in section.splitlines(True):
        if CODE_FENCE.match(line):
            fenced = not fenced
        elif not fenced and line.strip() == BREAKING_HEADING:
            return offset + len(line)
        offset += len(line)
    return None


def named_part(section: str) -> str:
    """Return the summary and the breaking-change tables of one changelog section.

    The part runs from the version heading to the heading that follows the
    breaking-change tables. **A `####` heading of a table carries one more mark than a part
    heading**, so the reader passes over both tables and stops at the entry list.

    **A section that names no breaking change is the named part in whole.** The reader sets
    nothing aside there, and `body_fault` still holds the whole part against the limit. The
    `## [0.6.0]` section of `CHANGELOG.md` is such a section.

    **The reader matches a whole heading line, and it reads no line of a code block.** A
    summary paragraph that names the heading in prose, and a code block that quotes it,
    each reach no match. `breaking_heading_end` holds that reading.

    Args:
        section: One whole changelog section, as `changelog_section` returns it.

    Returns:
        The section text from its heading to the end of the breaking-change tables, or the
        whole section where it names no breaking change.
    """
    heading = breaking_heading_end(section)
    if heading is None:
        return section.strip()
    following = PART_HEADING.search(section, heading)
    end = following.start() if following else len(section)
    return section[:end].strip()


def changelog_link(version: str) -> str:
    """Return the sentence that carries a reader to the whole changelog section.

    The link names the tag of the release, so it reads the file as that release shipped it.
    A link to the default branch would move under the reader after the next merge.

    Args:
        version: The version the package declares.

    Returns:
        Two sentences that state what the body holds and where the rest stands.
    """
    tag = TAG_FORM.format(version=version)
    return (
        f"This body holds the summary and the breaking-change tables of version {version}. "
        f"Read [`CHANGELOG.md` at {tag}]({REPOSITORY_URL}/blob/{tag}/CHANGELOG.md) for the "
        "entries under `### Added`, `### Changed`, `### Fixed` and `### Removed`."
    )


def body_fault(body: str) -> Optional[str]:
    """Return the reason the provider refuses one release body.

    **A length check passes on a blank body**, so the reader holds both floors. A release
    with an empty body meets `FR-release-14` in form and not in fact.

    Args:
        body: The text a release would carry.

    Returns:
        One sentence that states the fault, or None where the provider accepts the body.
    """
    if not body.strip():
        return "the release body holds no text"
    if len(body) > BODY_LIMIT:
        return (
            f"the release body holds {len(body)} characters, and the provider accepts "
            f"{BODY_LIMIT} at most"
        )
    return None


def release_body(changelog_text: str, package_text: str) -> str:
    """Return the release body of the version the package declares.

    **The body holds a named part and a link, and it holds no whole section.** The user
    ruled on 2026-08-10, because the version 1.0.0 section is 242778 characters and the
    provider accepts 125000. The named part is the summary and the breaking-change tables.
    The link carries a reader to `CHANGELOG.md` at the tag for the rest.

    **The reader still refuses a body above the limit, and it truncates nothing.** A named
    part that grows past the limit fails the release at a named step.

    **The body names every link absolutely, and `CHANGELOG.md` keeps its relative links.** A
    reader of the repository follows a relative link and a reader of the stored body does
    not. `absolute_links` writes the copy, and this module edits no line of the record.

    Args:
        changelog_text: The text of `CHANGELOG.md`.
        package_text: The text of `ja4plus/__init__.py`.

    Returns:
        The named part of that version, and the link below it.

    Raises:
        RuntimeError: The package declares no version, the changelog holds no section for
            it, the section holds no breaking-change heading, or the provider refuses the
            body.
    """
    version = package_version(package_text)
    if version is None:
        raise RuntimeError("`ja4plus/__init__.py` declares no `__version__`")
    section = changelog_section(changelog_text, version)
    part = absolute_links(named_part(section), TAG_FORM.format(version=version))
    body = f"{part}\n\n{changelog_link(version)}"
    fault = body_fault(body)
    if fault is not None:
        raise RuntimeError(f"{fault}, and the named part of `## [{version}]` is the body")
    return body


def main(argv: Optional[List[str]] = None) -> int:
    """Write the release body to a file, or report the fault that refuses it.

    **The module writes the file after both floors pass.** A step that wrote the file and
    then reported a failure would leave a body that a later step reads.

    Args:
        argv: The command-line arguments, or None to read `sys.argv`.

    Returns:
        Zero where the module wrote the body, one where it reported a fault.
    """
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("--changelog", type=pathlib.Path, default=CHANGELOG)
    parser.add_argument("--package", type=pathlib.Path, default=PACKAGE)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        body = release_body(
            arguments.changelog.read_text(encoding="utf-8"),
            arguments.package.read_text(encoding="utf-8"),
        )
    except RuntimeError as fault:
        print(f"the release body is not ready: {fault}", file=sys.stderr)
        return 1
    arguments.output.write_text(body + "\n", encoding="utf-8")
    print(f"wrote {len(body)} characters to {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
