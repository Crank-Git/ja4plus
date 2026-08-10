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

FR-release-14 — The GitHub release body holds the summary and the breaking-change tables
of the changelog section for that version, and it links `CHANGELOG.md` at the tag for the
rest.

**The user restated `FR-release-14` on 2026-08-10.** The earlier form asked the body to
hold the whole changelog section. That form cannot hold, because the `## [1.0.0]` section
of `CHANGELOG.md` is 242778 characters and the provider accepts 125000.
`### The release body of version 1.0.0` records the measurement and the ruling.

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
- `tests/release_verification.py` holds every command of the verification step, and
  `.github/workflows/publish.yml` runs that module in one step.
  `tests/test_publish_workflow.py` holds the cases against both.
- **The test directory the verification step reads is a copy outside the checkout.**
  `python -m` puts the working directory on `sys.path`, and `pytest` inserts the parent
  of the `tests` package there as well. Both paths name the checkout, and the checkout
  holds `ja4plus/`, so a run that starts there reads the source tree.
  `tests/test_publish_workflow.py::test_the_repository_root_resolves_the_source_tree`
  measures that state.
- The verification step reads the case list of the checkout and the case list of the
  clean environment. It refuses a run that collected fewer cases.
- The verification step refuses a conformance run that passed no case. A status of zero is
  not a passing run, because `pytest` reports a run of nothing but skips as a success.
  `tests/test_publish_workflow.py` holds both floors.
- The clean environment installs the shipped dependency list first, and it gains the
  test runner after that. The runner is the `pytest` entry of the `dev` extra, so one
  record states the version.
- **The publish workflow holds two events and two jobs, and each job accepts one event.**
  The published-release event runs the `publish` job, which names the `pypi` environment
  and states no repository URL. The manual event runs the `dry-run` job, which names the
  `testpypi` environment and states the TestPyPI repository URL. `### The two paths of the
  publish workflow` states the guardrail and `tests/test_publish_workflow.py` holds it.
- **The manual trigger declares no input.** The event selects the job, and each job names
  its environment as a literal. No value that a caller chooses reaches either name.
- The dry run runs the same verification as the release. A dry run that skipped the check
  proves the publisher and not the artifact.
- `tests/release_body.py` reads the `## [<version>]` section of `CHANGELOG.md` for the
  version that `ja4plus/__init__.py` declares. It returns the summary and the
  breaking-change tables of that section, and a link to `CHANGELOG.md` at the tag. The
  publish job writes that body with `gh release edit`, and that step stands in front of the
  publish step. `tests/test_release_body.py` holds the cases against the reader.
- **The provider refuses a release body of more than 125000 characters.** The reader
  reports a fault rather than truncate the part, so the workflow stops at a named step.
  `### The release body of version 1.0.0` states what this repository measures today.
- The release is not published when any verification step fails. A partial publish
  cannot be undone on PyPI.
- Version 1.0.0 states that the interface is stable. A breaking change after this
  release needs version 2.0.0.

## Data touched

- Changed file `pyproject.toml`.
- Changed file `ja4plus/__init__.py`.
- Changed file `CHANGELOG.md`.
- Changed file `.github/workflows/publish.yml`.
- New file `tests/release_verification.py`.
- New file `tests/test_publish_workflow.py`.
- New file `tests/test_packaging.py`.
- New file `tests/version_gate.py` and new file `tests/test_version_gate.py`.

**#67 added no workflow file and no job.** The cases of `tests/test_version_gate.py` run
inside `pytest tests/ -m "not spec_validation"`, which the `test` job of
`.github/workflows/test.yml` runs on every entry of the matrix. Each of those six entries
is a required status check of `dev`, so a disagreement fails continuous integration.
`.claude/rules/batch-gate.md` lists the twelve required contexts, and a new job would add
a thirteenth context that the rule does not require.

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

### The commit that writes the stable classifier

**The user ruled on 2026-08-10, on #69. The project holds
`Development Status :: 3 - Alpha` until the maintainer tags version 1.0.0.** These are the
words of the ruling.

> **The classifier is a promise about the interface, so it is written by the commit that makes
> the promise true.**

The interface may still move before 1.0.0. A classifier that runs ahead of the version
states a promise the project cannot yet hold. `FR-release-12` therefore stayed open, and the
release commit of 1.0.0 writes the line. **#69 built `FR-release-10` and `FR-release-11`,
and it changed no classifier.**

**#543 is that release commit, and it wrote the line on 2026-08-10.** The same commit moved
`ja4plus/__init__.py:101` to `1.0.0` and dated the `## [1.0.0]` section of `CHANGELOG.md`,
so the classifier and the version reached the repository together.

**A case now reads the classifier against the declaration, and a later version cannot
return to the alpha classifier without a failure.**
`classifier_disagreement` of `tests/version_gate.py` holds the rule. A version of 1.0.0 or
later states `Development Status :: 5 - Production/Stable`. A version below 1.0.0 states
`Development Status :: 3 - Alpha`. The reader takes the version from
`ja4plus/__init__.py` and never from a literal, so the rule follows every later bump.
`test_the_gate_reports_a_stable_version_that_carries_the_alpha_classifier` measures the
direction that matters, against version 2.0.0.

### The two paths of the publish workflow

**A manual trigger on a publish workflow creates a path to PyPI.** The project manager
stated this guardrail on #70, and it is not optional. The dry run reaches TestPyPI alone,
and the separation is structural rather than a value a caller selects.

| Path | Event | Job | Environment | Repository URL |
|---|---|---|---|---|
| Release | `release: published` | `publish` | `pypi` | none, so the action uploads to PyPI |
| Dry run | `workflow_dispatch` | `dry-run` | `testpypi` | `https://test.pypi.org/legacy/` |

Four properties hold the separation, and a case reads each one.

1. Each job carries the condition of its own event and no second one. A job with no
   condition runs on both events.
2. Each job names its environment as a literal. An environment that came from an
   expression follows a value chosen at run time.
3. The `publish` job names the TestPyPI host in no line, and it states no repository URL.
4. The manual trigger declares no input, so a caller selects nothing.

**One file holds both paths, and two files were the alternative.** The trusted publisher
of TestPyPI names a workflow filename, and the project manager recorded that name as
`publish.yml` on #70. A second file would carry a second filename, which the configured
publisher does not name. One file therefore holds both jobs.

**A mutation proves both directions.** #70 wrote four mutations of
`.github/workflows/publish.yml`, measured the failing case of each one, and restored the
file. `### The mutations that prove the guardrail` records them.

### The mutations that prove the guardrail

**A case that passes on the repaired file proves nothing about the direction it fails
in.** These six mutations of 2026-08-10 each name the one case that caught it. Each
mutation was written to disk, measured, and restored, and the file compared equal by
digest after the restore. The digest is
`36941ecb201aed94a19d8c63ee920144beafbda00e205e6c55059f7f5d0916d1`.

| Mutation | The one case that failed |
|---|---|
| The `dry-run` job takes the environment `pypi`. | `test_each_job_of_the_publish_workflow_names_its_environment_as_a_literal` |
| The `dry-run` job reads its repository URL from an input. | `test_the_manual_path_of_the_publish_workflow_reaches_no_real_index` |
| The `publish` job takes the TestPyPI repository URL. | `test_the_release_path_of_the_publish_workflow_reaches_no_test_index` |
| Both jobs lose their `if:` condition. | `test_each_job_of_the_publish_workflow_accepts_one_event` |
| The manual trigger declares an input. | `test_the_manual_trigger_of_the_publish_workflow_declares_no_input` |
| The `publish` job loses the release-body step. | `test_the_publish_job_writes_the_release_body_before_it_publishes` |

### The release body of version 1.0.0

**The whole version 1.0.0 section does not fit the release body.** A read of 2026-08-10
reports the three counts.

| Read | Result |
|---|---|
| The `## [1.0.0]` section of `CHANGELOG.md` | 242778 characters |
| The body `tests/release_body.py` builds for version 1.0.0 | 4727 characters |
| The longest body the provider accepts | 125000 characters |

The provider answers `422` with `body is too long (maximum is 125000 characters)`.
Verified against https://docs.github.com/en/rest/releases/releases and
https://github.com/cli/cli/issues/7705, both retrieved 2026-08-10.

**The user ruled on 2026-08-10, and the body holds a named part.** The named part is the
summary and the two breaking-change tables. A link carries a reader to `CHANGELOG.md` at
the tag for the rest. `CHANGELOG.md` keeps every row it holds, no round entry moves, and
this project rewrites nothing.

`named_part` of `tests/release_body.py` reads the part, and `changelog_link` writes the
link. The part runs from the version heading to the heading that follows the
breaking-change tables. **A `####` heading of a table carries one more mark than a part
heading**, so the reader keeps both tables and stops at the entry list. A section that
names no breaking change reaches the body in whole, and the `## [0.6.0]` section is such a
section.

**The reader matches a whole heading line, and it reads no line of a code block.** A summary
paragraph that names `### The breaking changes` in prose, and a code block that quotes the
heading, would each end the named part above the tables it exists to carry. **Such a reader
reports no fault**, because it returns a part that reads as complete and is not, which is
the failure this project records many times.

The self-review of #70 raised both cases, and a run raised neither.
`breaking_heading_end` tracks the code fence, and two cases hold the two readings.

| Reader | The case that fails |
|---|---|
| A substring match. | `test_the_named_part_reader_passes_over_the_heading_named_inside_a_paragraph` and the case below |
| A whole-line match that reads the code fence not at all. | `test_the_named_part_reader_passes_over_the_heading_quoted_in_a_code_block` |

**`tests/release_body.py` truncates nothing.** A truncated changelog section reads as
complete and is not, and the choice of what to drop belongs to the maintainer. A named
part above the limit fails the reader, the step fails, and the release publishes nothing.

Three cases hold the three readings.

1. `test_the_whole_version_1_0_0_section_stands_above_the_provider_limit` records the
   reason for the named part, and it fails where that reason ends.
2. `test_the_release_body_of_this_repository_stands_below_the_provider_limit` reads the
   real body of version 1.0.0 and requires it below the limit.
3. `test_the_release_body_reader_refuses_a_named_part_above_the_limit` holds the refusal
   against a named part that grows past the limit.

**The link names the tag and never the default branch.** A link to the default branch
moves under the reader after the next merge, so a reader of an old release would reach a
file that release never shipped.

### How `tests/test_packaging.py` reads the wheel

`tests/test_packaging.py` holds `FR-release-10` and `FR-release-11` against the built
wheel. It reads three states. A reader of a new packaging rule starts there.

1. The wheel lists `ja4plus/data/ja4plus-mapping.csv` and `ja4plus/py.typed`.
2. The wheel lists no entry under `tests/`, `examples/` or `docs/`.
3. The wheel lists at least 30 entries. **An aggregate over an empty set passes**, so this
   floor stands in front of the exclusion rule.

**A mutation proves each direction.** The file takes four steps.

1. It copies the built wheel.
2. It removes one required entry from the copy.
3. It adds one entry under `tests/` to the copy.
4. It reads the copy again.

The copy carries the mutation, and the built wheel keeps its bytes. A digest measures that
second fact.

`tests/test_installed_wheel.py` reads the assets tree, the top-level name and the whole
payload. #69 repeats none of those readings, and it imports `build_artifacts` and
`wheel_entry_names` from that file. **The mapping file and the documentation tree stand in
both files**, because each of the two requirements names them beside another entry and a
case reads a whole requirement.

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
| The wheel omits `py.typed`. | `test_the_wheel_lists_the_two_entries_the_release_requires` of `tests/test_packaging.py` fails. A caller who runs `mypy` reads no annotation of such an install. |
| The wheel carries a file under `tests/` or under `examples/`. | `test_the_wheel_lists_no_file_under_an_excluded_tree` fails. |
| The wheel lists no entry at all. | `test_the_wheel_lists_at_least_the_minimum_entry_count` fails. **An aggregate over an empty set passes**, so every exclusion rule reads an empty archive as correct. |
| The wheel carries a file under `docs/`. | `test_the_wheel_carries_no_file_under_the_documentation_tree` fails. #455 records the defect and the exclusion rule that repairs it. |
| The wheel carries a file under `assets/`. | `test_the_wheel_carries_no_file_under_the_assets_tree` fails. `assets/logo.png` holds 2423363 bytes, and `README.md` is its one reader. |
| The wheel carries a tree that the exclusion list does not name. | `test_the_wheel_carries_no_file_outside_the_package_and_its_metadata` fails, and `test_the_wheel_declares_one_top_level_name` fails where the tree is a discovered package. |
| The exclusion rule reaches the source distribution as well. | `test_the_source_distribution_carries_the_documentation_tree` and `test_the_source_distribution_carries_the_assets_tree` fail. A source distribution is the project at one revision. |
| The changelog has no section for the version. | The version-check job fails before a release is created. |
| The conformance suite fails against the installed wheel. | The workflow stops and does not publish. |
| The conformance run starts in the checkout. | The run imports the source tree, so it measures the working copy. `verification_root` of `tests/release_verification.py` removes that state, and `test_the_repository_root_resolves_the_source_tree` measures it. |
| The conformance run collects no case. | `compare_collections` raises, because a run of zero cases reports zero failures. |
| Every case of the conformance run skips. | `passing_summary` raises. `pytest` reports that run as a success, and a vector tree the copy missed produces it. |
| `twine check` reads no file. | `twine_check` raises. A check over no file reports no failure. |
| A built file holds no archive. | `twine check` reports a non-zero status and the check raises. `test_the_release_check_refuses_a_built_file_that_twine_rejects` proves it. |
| The clean environment holds no test runner. | `install_test_runner` adds the `pytest` entry of the `dev` extra, after the wheel install measured the shipped dependency list. |
| The maintainer creates a release from a branch other than the live branch. | The workflow runs against that reference. The version-check job is the guard. |
| TestPyPI is not configured. | The dry run fails and names the missing configuration. It does not fall back to PyPI. The `dry-run` job states the TestPyPI repository URL as a literal, so it reaches PyPI in no case. |
| A caller starts the workflow by hand and wants PyPI. | The manual event runs the `dry-run` job alone. `test_each_job_of_the_publish_workflow_accepts_one_event` fails where a condition names a second event. |
| A later change reads the environment from an expression. | `test_each_job_of_the_publish_workflow_names_its_environment_as_a_literal` fails. A value chosen at run time lets the manual path reach `pypi`. |
| A later change adds an input to the manual trigger. | `test_the_manual_trigger_of_the_publish_workflow_declares_no_input` fails. An input that selects the index is the hazard the separation removes. |
| A later change adds a third job. | `test_the_publish_workflow_holds_the_two_jobs_of_the_two_events` fails. A job the guardrail cases do not name reaches neither direction. |
| The changelog section is longer than the release body the provider accepts. | The body holds the summary and the breaking-change tables, and it links `CHANGELOG.md` at the tag for the rest. `named_part` of `tests/release_body.py` reads that part. **The reader truncates nothing.** `### The release body of version 1.0.0` records the counts. |
| The named part itself is longer than the release body the provider accepts. | `body_fault` of `tests/release_body.py` returns the fault, the step fails, and nothing publishes. `test_the_release_body_reader_refuses_a_named_part_above_the_limit` holds the refusal. |
| The changelog section names no breaking change. | `named_part` returns the whole section, because it sets nothing aside. `body_fault` still holds that section against the limit. The `## [0.6.0]` section is such a section. |
| The changelog section holds a heading and no line. | `changelog_section` raises. **A section of one heading passes a search for that heading**, so the floor stands in the reader. |
| The dry run edits a release. | It cannot. The `dry-run` job declares no `contents: write` and it runs no `gh release edit`. The manual event names no release, so such a job would edit the release the maintainer published last. |

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
- [x] `unzip -l dist/*.whl` lists `ja4plus/data/ja4plus-mapping.csv` and
      `ja4plus/py.typed`.
- [x] `unzip -l dist/*.whl` lists no file under `tests/`, `examples/`, `docs/` or
      `assets/`.
- [ ] `unzip -l dist/*.whl` lists every file below `ja4plus/` or below the
      `.dist-info` directory, and no other file.
- [ ] The `top_level.txt` of the wheel names `ja4plus` alone.
- [x] `pyproject.toml` declares `Development Status :: 5 - Production/Stable`.
- [ ] A dry run publishes to TestPyPI and not to PyPI.
- [ ] Version 1.0.0 appears on PyPI.
- [ ] `pip install ja4plus==1.0.0` in a clean environment runs
      `ja4plus analyze` on a committed capture.
- [ ] The GitHub release body holds the summary and the breaking-change tables of the
      `1.0.0` changelog section, and it links `CHANGELOG.md` at the tag for the rest.

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
this and #67 took the ruling: the criterion counts the declaration, and the prose stays.

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

**The release body question is answered, and this list holds no open question today.** The
user ruled on 2026-08-10 that the body holds the summary and the breaking-change tables,
and that a link carries the rest. `### The release body of version 1.0.0` records the
ruling and the three counts.

### The TestPyPI publisher, and what proves it

**The GitHub half is configured, and a read of 2026-08-10 reports it.**

| Read | Result |
|---|---|
| `gh api repos/Crank-Git/ja4plus/environments` | `github-pages`, `pypi`, `testpypi` |
| Deployments to `testpypi` | 0 |

**The TestPyPI half is unreadable by any agent.** A trusted publisher stands on
`test.pypi.org`, against this repository, `publish.yml` and the environment `testpypi`,
and that page needs the account of the owner.

**The first dry run is the measurement.** A dry run against an absent publisher fails at
the publish step and it uploads nothing, so no guess is needed. #70 built the two paths
and it started no run, because a run of this workflow publishes.

**The index names the failure `invalid-publisher`, and the upload fails.** The index reads
the OIDC token, finds that it matches no known publisher, and refuses to mint a token. The
upload therefore fails before it sends one byte of an artifact. A mismatched repository
owner, repository name, workflow filename or environment produces the same failure, so the
message names the configuration the dry run needs. Verified against
https://docs.pypi.org/trusted-publishers/troubleshooting/ (retrieved 2026-08-10).

**The exact message text is unmeasured, and the first dry run measures it.** The
`pypa/gh-action-pypi-publish` README states no failure text for this case, and no agent
reads the TestPyPI publisher page. Verified against
https://github.com/pypa/gh-action-pypi-publish (retrieved 2026-08-10).

**The dry run reaches PyPI in no case, whatever the publisher state is.** The `dry-run` job
states `repository-url: https://test.pypi.org/legacy/` as a literal of the file, so no
value chosen at run time moves it. `test_the_manual_path_of_the_publish_workflow_reaches_no_real_index`
holds that reading, and a mutation that reads the URL from an input fails it.
