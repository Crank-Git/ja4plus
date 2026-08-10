---
id: release
feature: Release
epic: "Epic 9: Release"
status: issued
issues: [20, 67, 68, 69, 70]
mockups: []
---

## Purpose

Version 0.6.0 is on PyPI. The publish workflow exists and uses trusted publishing,
so no token is stored. What is missing is the check that runs between the build and
the publish: nothing confirms that the built package installs and runs before it
reaches PyPI.

This feature set publishes version 1.0.0, and adds the checks that make the publish
safe to repeat.

## User stories

- As a maintainer, I want the release to fail before publishing when the wheel is
  broken, so that I do not yank a release.
- As a user, I want the version on PyPI to match the version in the changelog, so
  that I know what I installed.
- As a maintainer, I want one command to cut a release, so that I do not forget a
  step.

## Functional requirements

FR-release-1 — The version number appears in one place in the repository.

FR-release-2 — Continuous integration fails when the version in `pyproject.toml`
does not match the version in `ja4plus/__init__.py`.

FR-release-3 — Continuous integration fails when the version has no matching
section in `CHANGELOG.md`.

FR-release-4 — The publish workflow builds a source distribution and a wheel.

FR-release-5 — The publish workflow installs the built wheel into a clean
environment.

FR-release-6 — The publish workflow runs the command-line program from that
installation.

FR-release-7 — The publish workflow runs the conformance suite against that
installation.

FR-release-8 — The publish workflow publishes only when every check passes.

FR-release-9 — The publish workflow runs `twine check` on the built files.

FR-release-10 — The wheel contains the mapping file and the `py.typed` marker.

FR-release-11 — The wheel does not contain the test suite, the examples, or the
vectors.

FR-release-11b — The wheel contains no file under the documentation tree and no file
under the assets tree.

FR-release-11c — The source distribution contains the documentation tree and the assets
tree.

FR-release-11d — The wheel declares `ja4plus` as its only top-level name.

FR-release-12 — The project classifier reads `Development Status :: 5 -
Production/Stable`.

FR-release-13 — The release publishes to TestPyPI first when the maintainer asks for
a dry run.

FR-release-14 — The GitHub release body holds the changelog section for that
version.

## User flows

**A maintainer cuts version 1.0.0.**

1. The maintainer merges the last epic into the live branch.
2. The maintainer updates the version and the changelog in one pull request.
3. Continuous integration confirms the version and the changelog agree.
4. The maintainer creates a GitHub release tagged `v1.0.0`.
5. The publish workflow builds, verifies, and publishes to PyPI.

**A maintainer runs a dry run.**

1. The maintainer runs the publish workflow by hand with the dry-run input set.
2. The workflow builds and verifies.
3. The workflow publishes to TestPyPI.
4. The maintainer installs from TestPyPI and checks the package.

## Screens & states

| Screen | Purpose | States |
|---|---|---|
| Workflow summary | Show the release result. | Built; verified; published; failed at a named step. |
| PyPI project page | Show the published package. | Version 1.0.0 listed. |

## Behaviour rules

- The version lives in `ja4plus/__init__.py`. `pyproject.toml` names `version` in its
  `dynamic` list and reads it from `ja4plus.__version__`, so the two cannot disagree.
  **#67 measured this shape against the `importlib.metadata` form this page proposed
  first, and `### Why the version lives in the package` records the three readings.**
- The publish workflow triggers on a published GitHub release, as it does now.
- The verification step installs the wheel in a fresh virtual environment that has
  no source tree on its path, so an import cannot resolve to the working copy.
- The conformance suite runs against the installed package by pointing `pytest` at
  the test directory while the package resolves from site-packages.
- The release is not published when any verification step fails. A partial publish
  cannot be undone on PyPI.
- Version 1.0.0 states that the interface is stable. A breaking change after this
  release needs version 2.0.0.

## Data touched

- Changed file `pyproject.toml`.
- Changed file `ja4plus/__init__.py`.
- Changed file `CHANGELOG.md`.
- Changed file `.github/workflows/publish.yml`.
- New file `tests/test_packaging.py`.
- New file `tests/version_gate.py` and new file `tests/test_version_gate.py`.

**#67 added no workflow file and no job.** The cases of `tests/test_version_gate.py` run
inside `pytest tests/ -m "not spec_validation"`, which the `test` job of
`.github/workflows/test.yml` runs on every entry of the matrix. Each of those six entries
is a required status check of `dev`, so a disagreement fails continuous integration.
`.claude/rules/batch-gate.md` lists the eleven required contexts, and a new job would add
a twelfth context that the rule does not require.

### Why the version lives in the package

**This page proposed that `ja4plus/__init__.py` read the version with
`importlib.metadata.version`, and #67 declines that reader.** The call reads the metadata
of an installed distribution, and it does not read the source tree. Three readings of
2026-08-10 state the reason.

1. A source checkout that carries no install raises `PackageNotFoundError`. A reader
   therefore needs a literal fallback, and a fallback is the second declaration that
   FR-release-1 bars.
2. An editable install freezes its metadata at install time. With `pyproject.toml`
   changed to `0.7.0` and no reinstall, `importlib.metadata.version("ja4plus")` returned
   `0.6.0`.
3. The metadata of an editable install resolves through `ja4plus.egg-info` of the working
   directory, so the answer follows the directory a command runs in.

**A gate that reads the version out of an install compares a value against itself.**
Continuous integration installs the project from `pyproject.toml`, so the metadata always
equals the file the gate reads. FR-release-2 then names a comparison that reports nothing.
The `dynamic` shape holds two independent texts against each other instead:
`ja4plus/__init__.py` declares the version and `pyproject.toml` states where a build reads
it.

**`setuptools` resolves the attribute from the syntax tree and imports no module.** The
declaration is a plain string assignment at the top level of `ja4plus/__init__.py`, so a
build needs neither `scapy` nor `cryptography`. A read of 2026-08-10 built
`ja4plus-0.6.0-py3-none-any.whl` in an isolated build environment that holds neither
dependency. Verified against
https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html#dynamic-metadata,
retrieved 2026-08-10.

## Interfaces

| Service | What it does | Documentation |
|---|---|---|
| PyPI trusted publishing | Publishes without a stored token. | https://docs.pypi.org/trusted-publishers/ |
| `pypa/gh-action-pypi-publish` | The action the workflow already uses. | https://github.com/pypa/gh-action-pypi-publish |
| TestPyPI | Receives the dry-run publish. | https://test.pypi.org/ |

Verified against the pages above, retrieved 2026-08-06.

Trusted publishing needs the `id-token: write` permission and a configured
environment. `.github/workflows/publish.yml` already declares both. TestPyPI needs
its own trusted-publisher configuration, which is a separate setup step on the
TestPyPI site.

## Edge cases & failures

| Case | What happens |
|---|---|
| The version already exists on PyPI. | The publish step fails. PyPI refuses to replace a file. |
| The wheel omits the mapping file. | The verification step fails, because a lookup returns an empty database. |
| The wheel omits `py.typed`. | The packaging test fails. |
| The wheel carries a file under `docs/`. | `test_the_wheel_carries_no_file_under_the_documentation_tree` fails. #455 records the defect and the exclusion rule that repairs it. |
| The wheel carries a file under `assets/`. | `test_the_wheel_carries_no_file_under_the_assets_tree` fails. `assets/logo.png` holds 2423363 bytes, and `README.md` is its one reader. |
| The wheel carries a tree that the exclusion list does not name. | `test_the_wheel_carries_no_file_outside_the_package_and_its_metadata` fails, and `test_the_wheel_declares_one_top_level_name` fails where the tree is a discovered package. |
| The exclusion rule reaches the source distribution as well. | `test_the_source_distribution_carries_the_documentation_tree` and `test_the_source_distribution_carries_the_assets_tree` fail. A source distribution is the project at one revision. |
| The changelog has no section for the version. | The version-check job fails before a release is created. |
| The conformance suite fails against the installed wheel. | The workflow stops and does not publish. |
| The maintainer creates a release from a branch other than the live branch. | The workflow runs against that reference. The version-check job is the guard. |
| TestPyPI is not configured. | The dry run fails and names the missing configuration. It does not fall back to PyPI. |

## Acceptance criteria

- [x] `grep -rnE '^(__version__|version) = "' pyproject.toml ja4plus/` finds the version
      declaration in one file only. **The closing quote is part of the command**, because
      `[tool.setuptools.dynamic]` writes `version = {attr = ...}` and that line declares no
      version. `tests/test_criterion_counts.py` reads this number and measures it.
- [x] A pull request that changes the version without changing the changelog fails
      continuous integration.
- [ ] The publish workflow builds a source distribution and a wheel.
- [ ] `twine check dist/*` reports `PASSED` for both files.
- [ ] The workflow installs the wheel into a clean environment and runs
      `ja4plus --version`.
- [ ] The workflow runs the conformance suite against the installed wheel and it
      passes.
- [ ] `unzip -l dist/*.whl` lists `ja4plus/data/ja4plus-mapping.csv` and
      `ja4plus/py.typed`.
- [ ] `unzip -l dist/*.whl` lists no file under `tests/`, `examples/`, `docs/` or
      `assets/`.
- [ ] `unzip -l dist/*.whl` lists every file below `ja4plus/` or below the
      `.dist-info` directory, and no other file.
- [ ] The `top_level.txt` of the wheel names `ja4plus` alone.
- [ ] `pyproject.toml` declares `Development Status :: 5 - Production/Stable`.
- [ ] A dry run publishes to TestPyPI and not to PyPI.
- [ ] Version 1.0.0 appears on PyPI.
- [ ] `pip install ja4plus==1.0.0` in a clean environment runs
      `ja4plus analyze` on a committed capture.
- [ ] The GitHub release body holds the `1.0.0` changelog section.

### The version count, measured on 2026-08-09 and settled on 2026-08-10

**The first criterion counted files and not declarations until #67, and the two differ.**
A read of `git ls-files pyproject.toml ja4plus/` on 2026-08-09 reported seven files that
hold the text `0.6.0`.

| File | What it holds |
|---|---|
| `pyproject.toml` | The version declaration at line 7. |
| `ja4plus/__init__.py` | The version declaration at line 94. |
| `ja4plus/cli.py` | Five lines of prose that state what version 0.6.0 did. |
| `ja4plus/ja4db.py` | Three lines of prose that state what version 0.6.0 returned. |
| `ja4plus/output.py` | Two lines of prose that state what version 0.6.0 wrote. |
| `ja4plus/types.py` | Two lines of prose that state what version 0.6.0 used. |
| `ja4plus/watch.py` | Two lines of prose that state what version 0.6.0 called. |

**Two files declared the version and five name it in prose.** #67 removed one
declaration, so a count of the text `0.6.0` reads six files today. The prose records the
released behaviour, and a reader of `docs/migration-0.6-to-1.0.md` needs it. #456 measured
this and #67 took the decision: the criterion counts the declaration, and the prose stays.

**The criterion therefore names a command that matches a declaration line.** A read of
2026-08-10 reports one file, `ja4plus/__init__.py`. `declaration_files` of
`tests/version_gate.py` is the reader, and it takes the file list from `git ls-files`
rather than from `grep -r`. `grep -r` also reads an untracked build artifact.

## Out of scope

- Signing the artifacts.
- Publishing to a package index other than PyPI and TestPyPI.
- A release-candidate series.
- Automatic version bumping from commit messages.

## Open questions

- Whether TestPyPI trusted publishing is configured for this project. If it is not,
  the dry-run requirement needs a one-time setup step that only the repository owner
  can perform.
