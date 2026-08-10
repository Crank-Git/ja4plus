"""Readers that hold the version declaration of this project against its two records.

`docs/specs/features/09-release.md` puts the version number in one place, and
`ja4plus/__init__.py` is that place. `pyproject.toml` reads the value from
`ja4plus.__version__` through the `dynamic` mechanism of `setuptools`. A build therefore
resolves the version the package declares, and the two records cannot disagree.

**#67 declines `importlib.metadata` for this, and it measured three reasons.** The
feature page proposed that `__init__.py` read the version with
`importlib.metadata.version`. That call reads the metadata of an installed distribution
and it does not read the source tree.

1. A source checkout that carries no install raises `PackageNotFoundError`, so
   `__version__` needs a literal fallback. A fallback is a second declaration, and
   FR-release-1 allows one.
2. An editable install freezes its metadata at install time. A read of 2026-08-10
   reported `0.6.0` while `pyproject.toml` declared `0.7.0`.
3. The metadata of an editable install resolves through `ja4plus.egg-info` of the working
   directory, so the answer follows the directory a command runs in.

**A gate that reads the version out of an install compares a value against itself.**
Continuous integration installs the project from `pyproject.toml`, so the metadata always
equals the file the gate reads. The readers below take both values from tracked text
instead, and the two texts are independent inputs.

Python 3.9 carries no `tomllib`, and the test matrix holds Python 3.9, so each reader
matches a line rather than parsing the file.

`tests/test_version_gate.py` holds the cases against these readers, and
`tests/test_installed_wheel.py` reads `package_version` to name the version the built
artifacts must carry.
"""

from pathlib import Path
from typing import List, Optional
import re
import subprocess

# The one declaration. `ja4plus/__init__.py` declares it at the top level of the module.
# `setuptools` therefore reads it from the syntax tree and imports no dependency.
PACKAGE_DECLARATION = re.compile(r'^__version__ = "([^"]+)"$', re.MULTILINE)

# A static version, as `version = "0.6.0"`. The derived form writes
# `version = {attr = ...}` instead, and this pattern reads no such line.
PROJECT_DECLARATION = re.compile(r'^version = "([^"]+)"$', re.MULTILINE)

# The `dynamic` list, which names each field a build resolves.
PROJECT_DYNAMIC = re.compile(r"^dynamic = \[([^\]]*)\]$", re.MULTILINE)

# The attribute a `[tool.setuptools.dynamic]` table reads the version from.
PROJECT_VERSION_ATTRIBUTE = re.compile(r'^version = \{\s*attr = "([^"]+)"\s*\}$', re.MULTILINE)

# One table of `pyproject.toml`, from its own header to the next header. **A reader that
# searched the whole file would take a `version` key of another table for the project
# version.** A `[tool]` table that carried `version = "0.6.0"` beside a `dynamic` list
# that named the wrong attribute would then read as agreement, and the gate would report
# nothing. #67 records the finding, and a case holds the reader against it.
PROJECT_TABLE = re.compile(r"^\[project\]\s*$(.*?)(?=^\[|\Z)", re.MULTILINE | re.DOTALL)
DYNAMIC_TABLE = re.compile(
    r"^\[tool\.setuptools\.dynamic\]\s*$(.*?)(?=^\[|\Z)", re.MULTILINE | re.DOTALL
)

# A version section of `CHANGELOG.md`, as `## [0.6.0] - 2026-05`.
CHANGELOG_SECTION = re.compile(r"^## \[([^\]]+)\]", re.MULTILINE)

# One release heading of `CHANGELOG.md`, which holds the version and the text behind it.
# The reader keeps that text, because `changelog_release_date` reads it for a date.
CHANGELOG_HEADING = re.compile(r"^## \[([^\]]+)\][ \t]*-?[ \t]*(.*)$", re.MULTILINE)

# The release date of a section, as `2026-08-10`.
RELEASE_DATE = re.compile(r"^\d{4}-\d{2}(-\d{2})?$")

# One `Development Status` classifier of the `classifiers` list, as
# `    "Development Status :: 3 - Alpha",`.
CLASSIFIER_DECLARATION = re.compile(r'^\s*"(Development Status :: [^"]+)",?\s*$', re.MULTILINE)

# The classifier a version below 1.0.0 states. #69 ruled that this line holds until the
# release commit of version 1.0.0 writes the stable one.
ALPHA_CLASSIFIER = "Development Status :: 3 - Alpha"

# The classifier FR-release-12 names. A version of 1.0.0 or later promises a stable
# interface, and this line is that promise.
STABLE_CLASSIFIER = "Development Status :: 5 - Production/Stable"

# The attribute `pyproject.toml` reads the version from.
VERSION_ATTRIBUTE = "ja4plus.__version__"

# The pathspecs the acceptance criterion of `docs/specs/features/09-release.md` names.
DECLARATION_PATHSPECS = ("pyproject.toml", "ja4plus/")


def package_version(package_text: str) -> Optional[str]:
    """Return the version that `ja4plus/__init__.py` declares.

    Args:
        package_text: The text of `ja4plus/__init__.py`.

    Returns:
        The version string, or None where the text declares no `__version__`.
    """
    match = PACKAGE_DECLARATION.search(package_text)
    return match.group(1) if match else None


def _table_body(table: "re.Pattern[str]", pyproject_text: str) -> Optional[str]:
    """Return the lines of one table of `pyproject.toml`.

    Args:
        table: The pattern that matches the table header and its lines.
        pyproject_text: The text of `pyproject.toml`.

    Returns:
        The lines below the header, or None where the file holds no such table.
    """
    match = table.search(pyproject_text)
    return match.group(1) if match else None


def project_version(pyproject_text: str) -> Optional[str]:
    """Return the static version that the `[project]` table declares.

    **The reader searches that table alone.** A `version` key of another table declares no
    project version, and a reader of the whole file would take one for the project version.

    Args:
        pyproject_text: The text of `pyproject.toml`.

    Returns:
        The version string, or None where the table declares no static version.
    """
    body = _table_body(PROJECT_TABLE, pyproject_text)
    if body is None:
        return None
    match = PROJECT_DECLARATION.search(body)
    return match.group(1) if match else None


def project_version_attribute(pyproject_text: str) -> Optional[str]:
    """Return the attribute that `[tool.setuptools.dynamic]` reads the version from.

    The `dynamic` list comes from the `[project]` table, and the attribute comes from the
    `[tool.setuptools.dynamic]` table. Each reader searches its own table alone.

    Args:
        pyproject_text: The text of `pyproject.toml`.

    Returns:
        The attribute path, or None where the file names `version` in no `dynamic` list
        or reads it from no attribute.
    """
    project = _table_body(PROJECT_TABLE, pyproject_text)
    if project is None:
        return None
    dynamic = PROJECT_DYNAMIC.search(project)
    if dynamic is None or "version" not in dynamic.group(1):
        return None
    body = _table_body(DYNAMIC_TABLE, pyproject_text)
    if body is None:
        return None
    match = PROJECT_VERSION_ATTRIBUTE.search(body)
    return match.group(1) if match else None


def version_disagreement(pyproject_text: str, package_text: str) -> Optional[str]:
    """Return the reason `pyproject.toml` and `ja4plus/__init__.py` state two versions.

    FR-release-2 fails continuous integration on such a disagreement. The reader accepts
    two shapes. `pyproject.toml` reads the version from `ja4plus.__version__`, which is
    the shape this repository holds. `pyproject.toml` also passes where it declares a
    static version equal to the package version. A repository that reverts the derived
    form therefore still gets the comparison FR-release-2 names.

    Args:
        pyproject_text: The text of `pyproject.toml`.
        package_text: The text of `ja4plus/__init__.py`.

    Returns:
        One sentence that states the disagreement, or None where the two agree.
    """
    declared = package_version(package_text)
    if declared is None:
        return "`ja4plus/__init__.py` declares no `__version__`"
    static = project_version(pyproject_text)
    if static is not None:
        if static != declared:
            return (
                f"`pyproject.toml` declares {static} and `ja4plus/__init__.py` declares {declared}"
            )
        return None
    attribute = project_version_attribute(pyproject_text)
    if attribute is None:
        return f"`pyproject.toml` declares no version, and it reads none from `{VERSION_ATTRIBUTE}`"
    if attribute != VERSION_ATTRIBUTE:
        return f"`pyproject.toml` reads the version from `{attribute}` and not from `{VERSION_ATTRIBUTE}`"
    return None


def changelog_disagreement(changelog_text: str, version: str) -> Optional[str]:
    """Return the reason `CHANGELOG.md` holds no section for the version.

    FR-release-3 fails continuous integration where the section is absent.

    Args:
        changelog_text: The text of `CHANGELOG.md`.
        version: The version the package declares.

    Returns:
        One sentence that states what the changelog holds, or None where it holds the
        section.
    """
    sections = CHANGELOG_SECTION.findall(changelog_text)
    if not sections:
        return "`CHANGELOG.md` holds no version section"
    if version not in sections:
        return f"`CHANGELOG.md` holds no `## [{version}]` section, and it holds {sections}"
    return None


def changelog_release_date(changelog_text: str, version: str) -> Optional[str]:
    """Return the text that stands behind the version in its release heading.

    Args:
        changelog_text: The text of `CHANGELOG.md`.
        version: The version the package declares.

    Returns:
        The text behind the version, or None where the file holds no heading for it. The
        heading `## [1.0.0] - 2026-08-10` returns `2026-08-10`.
    """
    for found, trailer in CHANGELOG_HEADING.findall(changelog_text):
        if found == version:
            return trailer.strip()
    return None


def release_date_disagreement(changelog_text: str, version: str) -> Optional[str]:
    """Return the reason the section of the declared version carries no release date.

    **A section the package declares is a released section, and it states a date.** The
    heading reads `unreleased` while the project builds toward that version, and the bump
    of #543 writes the date. A reader who meets the declared version under the word
    `unreleased` reads a contradiction.

    Args:
        changelog_text: The text of `CHANGELOG.md`.
        version: The version the package declares.

    Returns:
        One sentence that states what the heading holds, or None where it holds a date.
    """
    trailer = changelog_release_date(changelog_text, version)
    if trailer is None:
        return f"`CHANGELOG.md` holds no `## [{version}]` heading"
    if not RELEASE_DATE.match(trailer):
        return (
            f"`CHANGELOG.md` heads the declared version {version} with {trailer!r}, "
            "and a declared version carries a release date"
        )
    return None


def expected_classifier(version: str) -> str:
    """Return the development-status classifier that one version states.

    FR-release-12 names the stable classifier, and #69 ruled that the alpha classifier
    holds until version 1.0.0. The major number therefore decides the line.

    Args:
        version: The version the package declares.

    Returns:
        The classifier that version promises.
    """
    major = version.split(".")[0]
    if major.isdigit() and int(major) >= 1:
        return STABLE_CLASSIFIER
    return ALPHA_CLASSIFIER


def project_classifiers(pyproject_text: str) -> List[str]:
    """Return every `Development Status` classifier that the `[project]` table declares.

    The reader searches that table alone, for the reason `project_version` states.

    Args:
        pyproject_text: The text of `pyproject.toml`.

    Returns:
        One string for each classifier, in file order.
    """
    body = _table_body(PROJECT_TABLE, pyproject_text)
    if body is None:
        return []
    return CLASSIFIER_DECLARATION.findall(body)


def classifier_disagreement(pyproject_text: str, version: str) -> Optional[str]:
    """Return the reason the classifier and the declared version state two promises.

    **The classifier is a promise about the interface, so it follows the version.** A
    version of 2.0.0 that carried the alpha classifier would withdraw that promise and no
    other record would report it.

    Args:
        pyproject_text: The text of `pyproject.toml`.
        version: The version the package declares.

    Returns:
        One sentence that states the disagreement, or None where the two agree.
    """
    found = project_classifiers(pyproject_text)
    if not found:
        return "`pyproject.toml` declares no `Development Status` classifier"
    if len(found) > 1:
        return f"`pyproject.toml` declares {len(found)} `Development Status` classifiers: {found}"
    wanted = expected_classifier(version)
    if found[0] != wanted:
        return f"`pyproject.toml` declares `{found[0]}`, and version {version} states `{wanted}`"
    return None


def declaration_files(repository_root: Path) -> List[str]:
    """Return every tracked file of `pyproject.toml` and `ja4plus/` that declares a version.

    FR-release-1 allows one such file. The reader takes the file list from `git ls-files`
    rather than from `grep -r`. `grep -r` also reads an untracked build artifact and a
    compiled module.

    **This reader searches no single table**, and `project_version` does. A `version` key
    of any table counts here, so a second key fails the one-file case rather than pass it.

    Args:
        repository_root: The root of the checkout to read.

    Returns:
        One tracked path for each file that holds a version declaration, in file order.

    Raises:
        AssertionError: The read of the repository failed.
    """
    result = subprocess.run(
        ["git", "ls-files", *DECLARATION_PATHSPECS],
        cwd=repository_root,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"`git ls-files` exited {result.returncode}: {result.stderr.strip()}"
    )
    holders = []
    for path in result.stdout.splitlines():
        if not path:
            continue
        text = (repository_root / path).read_bytes().decode("utf-8", errors="ignore")
        if PACKAGE_DECLARATION.search(text) or PROJECT_DECLARATION.search(text):
            holders.append(path)
    return holders
