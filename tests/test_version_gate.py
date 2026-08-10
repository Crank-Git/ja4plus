"""Tests that one file declares the version, and that the changelog holds a section for it.

`docs/specs/features/09-release.md` states three requirements, and these cases hold all
three.

- FR-release-1 puts the version number in one place in the repository.
- FR-release-2 fails continuous integration where `pyproject.toml` and
  `ja4plus/__init__.py` state different versions.
- FR-release-3 fails continuous integration where the version has no matching section in
  `CHANGELOG.md`.

**#543 adds two readings that follow the declaration.** The bump to version 1.0.0 wrote
both records, and a case here holds each one against the declaration rather than against a
literal version.

- FR-release-12 states `Development Status :: 5 - Production/Stable`. The classifier is a
  promise about the interface, so a version of 1.0.0 or later carries it and a version
  below 1.0.0 carries `Development Status :: 3 - Alpha`. **A later 2.0.0 that returned to
  the alpha classifier fails a case here**, and no other record reports that state.
- The `CHANGELOG.md` section of the declared version carries a release date. A section
  reads `unreleased` while the project builds toward that version, and the bump writes the
  date.

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
    ALPHA_CLASSIFIER,
    STABLE_CLASSIFIER,
    VERSION_ATTRIBUTE,
    changelog_disagreement,
    classifier_disagreement,
    declaration_files,
    expected_classifier,
    package_version,
    project_classifiers,
    release_date_disagreement,
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


def test_the_gate_reports_a_computed_version_assignment() -> None:
    """The gate reports a `__version__` that a call computes.

    `setuptools` reads the attribute from the syntax tree, so a computed value makes a
    build import the package and every dependency it loads. #67 measured that.
    """
    computed = "from importlib.metadata import version\n\n__version__ = version('ja4plus')\n"
    assert package_version(computed) is None, "the reader read a computed assignment"
    found = version_disagreement(DERIVED_PROJECT, computed)
    assert found is not None, "the gate accepted a computed version assignment"


# --- The release date of the declared version -----------------------------------------


def test_the_changelog_dates_the_section_of_the_declared_version() -> None:
    """`CHANGELOG.md` heads the declared version with a release date."""
    version = package_version(PACKAGE.read_text(encoding="utf-8"))
    assert version is not None
    found = release_date_disagreement(CHANGELOG.read_text(encoding="utf-8"), version)
    assert found is None, found


def test_the_gate_reports_a_declared_version_that_reads_unreleased() -> None:
    """The gate reports a declared version whose heading reads `unreleased`."""
    changelog = "# Changelog\n\n## [1.0.0] - unreleased\n"
    found = release_date_disagreement(changelog, "1.0.0")
    assert found is not None, "the gate accepted a declared version that reads unreleased"
    assert "unreleased" in found, found


def test_the_gate_accepts_a_declared_version_that_carries_a_date() -> None:
    """The gate accepts a declared version whose heading carries a release date."""
    changelog = "# Changelog\n\n## [1.0.0] - 2026-08-10\n\n## [0.6.0] - 2026-05\n"
    assert release_date_disagreement(changelog, "1.0.0") is None
    assert release_date_disagreement(changelog, "0.6.0") is None


def test_the_gate_reports_a_declared_version_the_changelog_omits() -> None:
    """The gate reports a declared version that heads no section."""
    found = release_date_disagreement("# Changelog\n\n## [0.6.0] - 2026-05\n", "1.0.0")
    assert found is not None, "the gate accepted a version that heads no section"


# --- FR-release-12, the classifier follows the version --------------------------------


def test_the_classifier_states_the_promise_of_the_declared_version() -> None:
    """`pyproject.toml` declares the classifier that the declared version states."""
    version = package_version(PACKAGE.read_text(encoding="utf-8"))
    assert version is not None
    found = classifier_disagreement(PYPROJECT.read_text(encoding="utf-8"), version)
    assert found is None, found


def test_the_project_declares_one_development_status_classifier() -> None:
    """`pyproject.toml` declares one `Development Status` classifier, so no gate reads none."""
    found = project_classifiers(PYPROJECT.read_text(encoding="utf-8"))
    assert len(found) == 1, f"pyproject.toml declares these classifiers: {found}"


def test_a_version_of_one_or_more_states_the_stable_classifier() -> None:
    """A version of 1.0.0 or later states `Development Status :: 5 - Production/Stable`."""
    assert expected_classifier("1.0.0") == STABLE_CLASSIFIER
    assert expected_classifier("2.0.0") == STABLE_CLASSIFIER
    assert expected_classifier("1.1.0") == STABLE_CLASSIFIER


def test_a_version_below_one_states_the_alpha_classifier() -> None:
    """A version below 1.0.0 states `Development Status :: 3 - Alpha`, which #69 ruled."""
    assert expected_classifier("0.6.0") == ALPHA_CLASSIFIER
    assert expected_classifier("0.7.0") == ALPHA_CLASSIFIER


def test_the_gate_reports_a_stable_version_that_carries_the_alpha_classifier() -> None:
    """The gate reports version 2.0.0 that returns to the alpha classifier."""
    pyproject = f'[project]\nname = "ja4plus"\nclassifiers = [\n    "{ALPHA_CLASSIFIER}",\n]\n'
    found = classifier_disagreement(pyproject, "2.0.0")
    assert found is not None, "the gate accepted a 2.0.0 that reads Alpha"
    assert ALPHA_CLASSIFIER in found, found


def test_the_gate_reports_a_prerelease_version_that_carries_the_stable_classifier() -> None:
    """The gate reports version 0.6.0 that carries the stable classifier."""
    pyproject = f'[project]\nname = "ja4plus"\nclassifiers = [\n    "{STABLE_CLASSIFIER}",\n]\n'
    found = classifier_disagreement(pyproject, "0.6.0")
    assert found is not None, "the gate accepted a 0.6.0 that reads Production/Stable"


def test_the_gate_reports_project_metadata_that_declares_no_classifier() -> None:
    """The gate reports project metadata that declares no `Development Status` classifier."""
    found = classifier_disagreement('[project]\nname = "ja4plus"\n', "1.0.0")
    assert found is not None, "the gate accepted metadata that declares no classifier"


def test_the_gate_reports_two_development_status_classifiers() -> None:
    """The gate reports two `Development Status` classifiers, which state two promises."""
    pyproject = (
        f'[project]\nname = "ja4plus"\nclassifiers = [\n'
        f'    "{ALPHA_CLASSIFIER}",\n    "{STABLE_CLASSIFIER}",\n]\n'
    )
    found = classifier_disagreement(pyproject, "1.0.0")
    assert found is not None, "the gate accepted two Development Status classifiers"


def test_the_classifier_reader_reads_the_project_table_alone() -> None:
    """The reader reads no `Development Status` line of a later table."""
    pyproject = (
        f'[project]\nname = "ja4plus"\nclassifiers = [\n    "{STABLE_CLASSIFIER}",\n]\n'
        f'\n[tool.example]\nclassifiers = [\n    "{ALPHA_CLASSIFIER}",\n]\n'
    )
    assert project_classifiers(pyproject) == [STABLE_CLASSIFIER]
