"""Readers that hold the version declaration of this project against its two records.

`docs/specs/features/09-release.md` puts the version number in one place, and
`ja4plus/__init__.py` is that place. `pyproject.toml` reads the value from
`ja4plus.__version__` through the `dynamic` mechanism of `setuptools`, so a build states
the version the package states and the two cannot disagree.

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

# The one declaration. `ja4plus/__init__.py` states it at the top level of the module, so
# `setuptools` reads it from the syntax tree and imports no dependency at build time.
PACKAGE_DECLARATION = re.compile(r'^__version__ = "([^"]+)"$', re.MULTILINE)

# A static version of the `[project]` table, as `version = "0.6.0"`. The derived form
# writes `version = {attr = ...}` instead, and this pattern reads no such line.
PROJECT_DECLARATION = re.compile(r'^version = "([^"]+)"$', re.MULTILINE)

# The `dynamic` list of the `[project]` table, which names each field a build resolves.
PROJECT_DYNAMIC = re.compile(r"^dynamic = \[([^\]]*)\]$", re.MULTILINE)

# The attribute that `[tool.setuptools.dynamic]` reads the version from.
PROJECT_VERSION_ATTRIBUTE = re.compile(r'^version = \{\s*attr = "([^"]+)"\s*\}$', re.MULTILINE)

# A version section of `CHANGELOG.md`, as `## [0.6.0] - 2026-05`.
CHANGELOG_SECTION = re.compile(r"^## \[([^\]]+)\]", re.MULTILINE)

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


def project_version(pyproject_text: str) -> Optional[str]:
    """Return the static version that the `[project]` table declares.

    Args:
        pyproject_text: The text of `pyproject.toml`.

    Returns:
        The version string, or None where the table declares no static version.
    """
    match = PROJECT_DECLARATION.search(pyproject_text)
    return match.group(1) if match else None


def project_version_attribute(pyproject_text: str) -> Optional[str]:
    """Return the attribute that `[tool.setuptools.dynamic]` reads the version from.

    Args:
        pyproject_text: The text of `pyproject.toml`.

    Returns:
        The attribute path, or None where the file names `version` in no `dynamic` list
        or reads it from no attribute.
    """
    dynamic = PROJECT_DYNAMIC.search(pyproject_text)
    if dynamic is None or "version" not in dynamic.group(1):
        return None
    match = PROJECT_VERSION_ATTRIBUTE.search(pyproject_text)
    return match.group(1) if match else None


def version_disagreement(pyproject_text: str, package_text: str) -> Optional[str]:
    """Return the reason `pyproject.toml` and `ja4plus/__init__.py` state two versions.

    FR-release-2 fails continuous integration on such a disagreement. The reader accepts
    two shapes. `pyproject.toml` reads the version from `ja4plus.__version__`, which is
    the shape this repository holds. `pyproject.toml` also passes where it declares a
    static version equal to the package version, so a repository that reverts the derived
    form still gets the comparison FR-release-2 names.

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


def declaration_files(repository_root: Path) -> List[str]:
    """Return every tracked file of `pyproject.toml` and `ja4plus/` that declares a version.

    FR-release-1 allows one such file. The reader takes the file list from
    `git ls-files` rather than from `grep -r`, because `grep -r` also reads an untracked
    build artifact and a compiled module.

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
