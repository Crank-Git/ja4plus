"""Tests that one file declares the version, and that the changelog holds a section for it.

`docs/specs/features/09-release.md` states three requirements, and these cases hold all
three.

- FR-release-1 puts the version number in one place in the repository.
- FR-release-2 fails continuous integration where `pyproject.toml` and
  `ja4plus/__init__.py` state different versions.
- FR-release-3 fails continuous integration where the version has no matching section in
  `CHANGELOG.md`.

**A comparison that is never made reads as a comparison that passes.** Each gate below
therefore carries a control case that feeds it a contradicting pair and reads the message
it returns. A gate that returned nothing on every input would pass the repository cases
and report no defect, and this project records that failure mode more than eighteen times.

**The reader of an absent version fails.** An aggregate over an empty set passes, so a
gate that finds no version returns a message rather than agreement.

These cases read text. They import nothing from `ja4plus` and they produce no
fingerprint.
"""

from pathlib import Path

from tests.version_gate import (
    VERSION_ATTRIBUTE,
    changelog_disagreement,
    declaration_files,
    package_version,
    version_disagreement,
)

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

PYPROJECT = REPOSITORY_ROOT / "pyproject.toml"
PACKAGE = REPOSITORY_ROOT / "ja4plus" / "__init__.py"
CHANGELOG = REPOSITORY_ROOT / "CHANGELOG.md"

# A `pyproject.toml` that reads the version from the package attribute. The control cases
# below change one line of this text and read what the gate returns.
DERIVED_PROJECT = """[project]
name = "ja4plus"
dynamic = ["version"]

[tool.setuptools.dynamic]
version = {attr = "ja4plus.__version__"}
"""

PACKAGE_TEXT = '__version__ = "0.6.0"\n'


# --- FR-release-1, the one place ------------------------------------------------------


def test_one_tracked_file_declares_the_version() -> None:
    """One tracked file of `pyproject.toml` and `ja4plus/` declares the version."""
    holders = declaration_files(REPOSITORY_ROOT)
    assert holders == ["ja4plus/__init__.py"], (
        f"these tracked files declare a version, and one is right: {holders}"
    )


def test_the_package_declares_a_version() -> None:
    """`ja4plus/__init__.py` states a version, so no gate below reads an absent value."""
    assert package_version(PACKAGE.read_text(encoding="utf-8")) is not None, (
        f"{PACKAGE} declares no `__version__`, and every gate here reads that value"
    )


# --- FR-release-2, the two records agree ----------------------------------------------


def test_the_project_metadata_and_the_package_state_one_version() -> None:
    """`pyproject.toml` and `ja4plus/__init__.py` state no contradicting version."""
    found = version_disagreement(
        PYPROJECT.read_text(encoding="utf-8"), PACKAGE.read_text(encoding="utf-8")
    )
    assert found is None, found


def test_the_gate_reports_a_project_version_that_contradicts_the_package() -> None:
    """The gate reports a static project version that the package contradicts."""
    pyproject = '[project]\nname = "ja4plus"\nversion = "0.7.0"\n'
    found = version_disagreement(pyproject, PACKAGE_TEXT)
    assert found is not None, "the gate accepted 0.7.0 against 0.6.0"
    assert "0.7.0" in found and "0.6.0" in found, found


def test_the_gate_accepts_a_project_version_that_matches_the_package() -> None:
    """The gate accepts a static project version that equals the package version."""
    pyproject = '[project]\nname = "ja4plus"\nversion = "0.6.0"\n'
    assert version_disagreement(pyproject, PACKAGE_TEXT) is None


def test_the_gate_accepts_project_metadata_that_reads_the_package_attribute() -> None:
    """The gate accepts project metadata that reads the version from the package."""
    assert version_disagreement(DERIVED_PROJECT, PACKAGE_TEXT) is None


def test_the_gate_reports_project_metadata_that_reads_another_attribute() -> None:
    """The gate reports project metadata that reads the version from another attribute."""
    pyproject = DERIVED_PROJECT.replace(VERSION_ATTRIBUTE, "ja4plus.cli.__version__")
    found = version_disagreement(pyproject, PACKAGE_TEXT)
    assert found is not None, "the gate accepted a version read from another attribute"
    assert VERSION_ATTRIBUTE in found, found


def test_the_gate_reads_the_version_of_the_project_table_alone() -> None:
    """The gate reads no `version` key of a table other than `[project]`.

    A self-review of #67 found this silent pass. The `[tool.other]` table below carries a
    `version` key that equals the package version, and the `dynamic` list names the wrong
    attribute. A reader of the whole file took that key for the project version and
    returned agreement, so the wrong attribute reached no report.
    """
    pyproject = DERIVED_PROJECT.replace(VERSION_ATTRIBUTE, "ja4plus.cli.__version__")
    pyproject += '\n[tool.other]\nversion = "0.6.0"\n'
    found = version_disagreement(pyproject, PACKAGE_TEXT)
    assert found is not None, "the gate read a `version` key of another table"
    assert VERSION_ATTRIBUTE in found, found


def test_the_gate_reports_project_metadata_that_declares_no_version() -> None:
    """The gate reports project metadata that declares no version and reads none."""
    pyproject = '[project]\nname = "ja4plus"\n'
    found = version_disagreement(pyproject, PACKAGE_TEXT)
    assert found is not None, "the gate accepted project metadata that states no version"


def test_the_gate_reports_a_package_that_declares_no_version() -> None:
    """The gate reports a package that declares no version."""
    found = version_disagreement(DERIVED_PROJECT, "__author__ = 'ja4plus contributors'\n")
    assert found is not None, "the gate accepted a package that declares no version"


# --- FR-release-3, the changelog holds the section ------------------------------------


def test_the_changelog_holds_a_section_for_the_declared_version() -> None:
    """`CHANGELOG.md` holds a section for the version the package declares."""
    version = package_version(PACKAGE.read_text(encoding="utf-8"))
    assert version is not None
    found = changelog_disagreement(CHANGELOG.read_text(encoding="utf-8"), version)
    assert found is None, found


def test_the_gate_reports_a_version_that_the_changelog_omits() -> None:
    """The gate reports a version that no changelog section names."""
    changelog = "# Changelog\n\n## [0.5.0] - 2026-01\n"
    found = changelog_disagreement(changelog, "0.6.0")
    assert found is not None, "the gate accepted a version that the changelog omits"
    assert "0.6.0" in found, found


def test_the_gate_accepts_a_version_that_the_changelog_names() -> None:
    """The gate accepts a version that a changelog section names."""
    changelog = "# Changelog\n\n## [0.6.0] - 2026-05\n"
    assert changelog_disagreement(changelog, "0.6.0") is None


def test_the_gate_reports_a_changelog_that_holds_no_section() -> None:
    """The gate reports a changelog that holds no version section."""
    found = changelog_disagreement("# Changelog\n", "0.6.0")
    assert found is not None, "the gate accepted a changelog that holds no section"
