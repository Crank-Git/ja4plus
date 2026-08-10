"""Build the body of a GitHub release from the changelog section of that version.

`FR-release-14` asks the GitHub release body to hold the changelog section for that
version. The publish job of `.github/workflows/publish.yml` runs this module and writes the
result with `gh release edit`, and that step stands in front of the publish step. A
changelog with no section for the version therefore fails the release, and it publishes
nothing.

**The provider refuses a body of more than 125000 characters.** It answers `422` and it
names the limit. This module reads the length in front of the write, so the workflow stops
at a named step rather than at the provider. `BODY_LIMIT` holds the count.

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
from typing import List, Optional

from tests.version_gate import package_version

# The longest body the provider accepts. A longer body answers `422` with
# `body is too long (maximum is 125000 characters)`.
BODY_LIMIT = 125000

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
CHANGELOG = REPOSITORY_ROOT / "CHANGELOG.md"
PACKAGE = REPOSITORY_ROOT / "ja4plus" / "__init__.py"

# The heading that opens any version section, as `## [0.6.0] - 2026-05`.
SECTION_HEADING = re.compile(r"^## \[", re.MULTILINE)


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

    Args:
        changelog_text: The text of `CHANGELOG.md`.
        package_text: The text of `ja4plus/__init__.py`.

    Returns:
        The changelog section of that version.

    Raises:
        RuntimeError: The package declares no version, the changelog holds no section for
            it, or the provider refuses the section.
    """
    version = package_version(package_text)
    if version is None:
        raise RuntimeError("`ja4plus/__init__.py` declares no `__version__`")
    section = changelog_section(changelog_text, version)
    fault = body_fault(section)
    if fault is not None:
        raise RuntimeError(f"{fault}, and the `## [{version}]` section is the body")
    return section


def main(argv: Optional[List[str]] = None) -> int:
    """Write the release body to a file, or report the fault that refuses it.

    **The module writes the file after both floors pass.** A step that wrote the file and
    then reported a failure would leave a body that a later step reads.

    Args:
        argv: The command-line arguments, or None to read `sys.argv`.

    Returns:
        Zero where the module wrote the body, one where it reported a fault.
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
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
