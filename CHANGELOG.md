# Changelog

All notable changes to ja4plus are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - unreleased

Version 0.6.0 is the released version on PyPI. Version 1.0.0 is not released yet, and the
date of this section arrives with the promotion of `dev` to `master`.

`FR-documentation-13` asks this file to record every breaking change of the release. The
two tables below name each one and cite the round that records it. The entries under
`### Added`, `### Changed`, `### Fixed` and `### Removed` hold the whole detail.
[`docs/migration-0.6-to-1.0.md`](docs/migration-0.6-to-1.0.md) states the old form, the new
form and the reason for each change, so read that page before you upgrade.

**Warning: a fingerprint of version 0.6.0 and a fingerprint of version 1.0.0 are not always
comparable.** Read [The fingerprints that move](#the-fingerprints-that-move) before you
compare two sets of results. That table holds eight rows. Seven of them move a value a tool
may have stored, and #214 adds a value that version 0.6.0 never produced.

`tests/test_release_notes.py` holds the two tables against the record. A change that
`CHANGELOG.md` marks `**BREAKING`, and a change that the migration page records, reaches a
row below or fails a case. A list that a reader keeps by hand goes stale on the day the
next breaking change lands, and a case does not.

### The breaking changes

#### The interface changes

| Change | Record |
|---|---|
| `Processor.process_packet` returns a list of `FingerprintResult` objects, and no longer a list of dictionaries. | Round 90, #45 |
| `JA4DBClient.lookup` returns a frozen `LookupResult`, and no longer a dictionary. | Round 122, #59 |
| Item access on a `LookupResult` works for one major version, and it raises a `DeprecationWarning`. | Round 123, #364 |
| `JA4DBClient()` reaches no network, and `JA4DBClient(allow_remote=True)` opts in. | Round 117, #57 |
| `allow_remote` is the first argument of `JA4DBClient`, so `JA4DBClient(100)` raises a `TypeError`. | Round 117, #57 |
| `ja4plus db update` writes the cache directory of the platform, and no longer the installed package. | Round 121, #61 |
| `ja4plus watch` reads an interface, and `ja4plus live` stays as an alias of it. | Round 101, #53 |
| The `ja4plus.collector` module leaves the package, so `import ja4plus.collector` raises a `ModuleNotFoundError`. | Round 71, #191 |
| The `json` format and the `csv` format write four address fields, and no longer one composite `source` field. | Round 96, #49 |
| The command writes every result to standard output and every diagnostic to standard error. | Round 95, #52 |
| The monitor opens the capture socket to test the privilege, and no longer reads `os.geteuid()`. | Round 104, #56 |
| `compute_ja4x_from_pem` and `compute_ja4x_from_der` raise where an unreadable input returned `None`. | Round 133, #319 |
| `requires-python` moves from `>=3.8` to `>=3.9`. | Round 135, #76 |

#### The fingerprints that move

| Change | Record |
|---|---|
| JA4SSH emits one fingerprint for every 200 SSH packets, and no longer one for every 10. | Round 9, #28 |
| JA4SSH counts an SSH message, and no longer a TCP segment that carries a payload. | #98 |
| JA4SSH counts a true bare ACK alone. | #92 |
| JA4SSH emits every window a connection leaves open, so a capture produces one more value. | #214 |
| JA4L and JA4LS report a one-way latency, and no longer a round-trip time. | #88 |
| The JA4L QUIC server point reads the Initial packet whose TLS handshake type is `2`. | #102 |
| Both JA4S raw fields hold the extension list in wire order. | #108 |
| JA4 and JA4S write `s2` for the version `0x0002`, and FoxIO retracted the earlier reading. | #227 |

**Two further changes narrow the published interface, and the sweep of #395 judged each one
marginal.** `ja4plus.__all__` names 25 entries, so a `from ja4plus import *` that read a
name outside the 25 loses it, under Round 90, #47. `import ja4plus` registers the tunnel
dissectors of scapy for the whole process, under Round 12, #94.

**The record and the migration page name the same breaking changes.** #319 narrowed
`compute_ja4x_from_pem` and `compute_ja4x_from_der`, and #397 recorded the change. The
interface table above carries the row, and #66 found that `docs/migration-0.6-to-1.0.md`
held none. #66 edited no page of another issue. #399 added the row, and #403 corrected
this paragraph.
`tests/test_release_notes.py::test_every_breaking_change_of_the_record_reaches_the_migration_page`
holds every breaking change of this record against a row of that page.

### Added

- **The publish workflow builds the release and verifies it in a clean environment before it
  publishes** (#68). Round 188. `FR-release-4` to `FR-release-9` state the checks, and
  `.github/workflows/publish.yml` held two steps before this round: `python -m build` and the
  upload. **Nothing stood between the build and PyPI, and a publish to PyPI cannot be
  undone.** New file `tests/release_verification.py` holds the whole check, and the workflow
  runs it in one step in front of the upload step. It builds both artifacts, reads them with
  `twine check`, installs the wheel into a clean environment, runs the console script of that
  environment, and runs the conformance suite against the installed package. **The
  conformance suite lives under `tests/`, and #455 removed `tests/` from the wheel**, so the
  suite comes from the checkout and the package comes from the environment. **A run that
  starts in the repository root reads the source tree and proves nothing about the wheel.**
  `python -m` puts the working directory on `sys.path`, and `pytest` inserts the parent of the
  `tests` package there as well, and both paths hold `ja4plus/`. `verification_root` copies
  the suite and `pyproject.toml` to a directory that holds no package source, and the check
  reads `ja4plus.__file__` from that directory before it runs one case. A measurement of
  2026-08-10 reports both directions from one clean environment: the copied root resolves
  `<site-packages>/ja4plus/__init__.py` and the repository root resolves the checkout.
  **This round rewrites no part of the repair #408 built.** It imports `build_artifacts`,
  `create_clean_environment`, `package_file_of` and `run_probe` of
  `tests/test_installed_wheel.py`, which scrub `PYTHONPATH`, set `PYTHONNOUSERSITE` and assert
  that `pip` wrote the package into `site-packages`. **An aggregate over an empty set passes**,
  so three floors stand in the check: `twine check` refuses an empty file list, the `PASSED`
  count reads 2 against two files, and `compare_collections` refuses a clean environment whose
  case list differs from the checkout. The clean environment collected 1809 cases against 1809
  in the checkout, and the run reported 1532 passed, 143 skipped and 134 xfailed, which are the
  three counts the checkout reports. **A fourth floor came from the self-review, and it is the
  one that mattered.** The first form of the check read the exit status of the conformance run
  alone, and `pytest` reports a run whose every case skipped as a success. A vector tree the
  copy missed would then have printed `release check: PASSED`. `passing_summary` now reads the
  summary line, refuses a passed count of zero and refuses a summary that names a failure, and
  `verify` keeps the line it read. A run reduced to a collection refuses the release with
  `RuntimeError: the conformance run wrote no passed count: '1809 tests collected in 0.23s'`.
  New file `tests/test_publish_workflow.py` holds 28 cases, 10 of them under the
  `installed_wheel` marker. **The cases came first**, and the whole file
  failed to collect against the base commit `589c5ee` with
  `ModuleNotFoundError: No module named 'tests.release_verification'`. **Three mutations prove
  the cases bite, and each one was restored.** The workflow of the base commit fails 2 cases,
  one reading `publish.yml runs 'python -m tests.release_verification' in 0 steps`. A check
  that reads `ja4plus.__file__` from the repository root fails 1 case, which reports the
  checkout path against the `site-packages` path. A file list cut to its first entry refuses
  the release with `the clean environment collected 202 cases against 1809 in the checkout`.
  **A workflow step that never runs cannot fail**, and no case here starts the publish
  workflow, because a run of it would publish. The cases read the step order as text and run
  the check itself. The `installed-wheel` job of `.github/workflows/test.yml` now runs the
  marker over `tests/` rather than over one file, because a command that names one file runs
  none of the cases this round adds. The `dev` extra of `pyproject.toml` gains
  `twine==6.2.0`. **7.0.0 is the newest release and this pin declines it**, because it
  requires Python 3.10 and the matrix runs Python 3.9, which is the reading #446 records for
  `pytest` and `build`. `.claude/skills/release/SKILL.md` held the same trap in step 5 and it
  now runs the same command. `docs/specs/features/09-release.md` gains six behaviour rules,
  six edge cases and two file entries. No file under `ja4plus/` changes and no fingerprint
  moves. The conformance suite reports 1532 passed, 143 skipped and 134 xfailed on the base
  commit and the same three counts after. Coverage holds at 94% with 4292 statements and 273
  misses.

- **The publish workflow reaches TestPyPI on a manual event, and the release body holds the
  summary and the breaking-change tables of the version** (#70).
  Round 191. `FR-release-13` and `FR-release-14` state the two requirements, and
  `.github/workflows/publish.yml` held one event and one job before this round. **A manual
  trigger on a publish workflow creates a path to PyPI**, so the project manager ruled that
  the dry run must be structurally incapable of reaching the real index. The file now holds
  two events and two jobs, and each job accepts one event. The published-release event runs
  the `publish` job, which names the `pypi` environment and states no repository URL. The
  manual event runs the `dry-run` job, which names the `testpypi` environment and states
  `https://test.pypi.org/legacy/`. **The manual trigger declares no input**, because an
  input that selected the index is the hazard the separation removes. Each environment name
  and the repository URL are literals of the file, so no value a caller chooses reaches
  either one. **The dry run runs the same verification as the release**, because a dry run
  that skipped the check would prove the publisher and not the artifact. `FR-release-14`
  puts the changelog record of the version in the release body, and new file
  `tests/release_body.py` builds it. **The whole `## [1.0.0]` section is 242778 characters
  and the provider accepts 125000**, so the requirement as first written cannot hold. The
  user ruled on 2026-08-10 that the body holds a named part and links `CHANGELOG.md` at the
  tag for the rest, and the named part is the summary and the two breaking-change tables.
  `CHANGELOG.md` keeps every row it holds, no round entry moves, and this round rewrites
  nothing. The body a release of version 1.0.0 carries measures 4727 characters.
  **The reader truncates nothing**, because a truncated section reads as complete and is
  not, and the choice of what to drop belongs to the maintainer. A named part above the
  limit fails the reader, the step fails, and the release publishes nothing. **A `####`
  heading of a breaking-change table carries one more mark than a part heading**, so the
  reader keeps both tables and stops at the entry list. A section that names no breaking
  change reaches the body in whole, and the `## [0.6.0]` section is such a section. **The
  reader matches a whole heading line, and it reads no line of a code block.** The
  self-review raised both cases and a run raised neither. A summary paragraph that names
  `### The breaking changes` in prose, and a code block that quotes the heading, would each
  end the named part above the tables it exists to carry, and **such a reader reports no
  fault**, because it returns a part that reads as complete and is not. A line anchor alone
  does not close the second case, because a line inside a code block opens a line of the
  file like any other, so `breaking_heading_end` tracks the code fence. The
  link names the tag and never the default branch, because a link to the default branch
  moves under the reader after the next merge. **The release-body step stands in front of
  the publish step**, so a changelog that holds no section for the version fails the release
  and publishes nothing. **The value of a case here is the direction it fails in**, so six
  mutations of the workflow and seven of the reader prove both directions, and each one was
  written to disk, measured and restored. The workflow compared equal by digest
  `36941ecb201aed94a19d8c63ee920144beafbda00e205e6c55059f7f5d0916d1` after the restore. A
  `dry-run` job that takes the environment `pypi` fails
  `test_each_job_of_the_publish_workflow_names_its_environment_as_a_literal`. A `dry-run`
  job that reads its repository URL from an input fails
  `test_the_manual_path_of_the_publish_workflow_reaches_no_real_index`. A `publish` job that
  takes the TestPyPI repository URL fails
  `test_the_release_path_of_the_publish_workflow_reaches_no_test_index`. Two jobs that lose
  their condition fail `test_each_job_of_the_publish_workflow_accepts_one_event`. A manual
  trigger that declares an input fails
  `test_the_manual_trigger_of_the_publish_workflow_declares_no_input`. A `publish` job that
  loses the release-body step fails
  `test_the_publish_job_writes_the_release_body_before_it_publishes`. A reader that returns
  the whole section fails `test_the_release_body_of_this_repository_stands_below_the_provider_limit`,
  a `named_part` that keeps the entry list fails
  `test_the_named_part_holds_no_entry_of_the_entry_list`, a link that names the default
  branch fails `test_the_link_names_the_changelog_at_the_tag_of_the_release`, a
  `body_fault` that reads no limit fails three cases, a substring match of the
  breaking-change heading fails
  `test_the_named_part_reader_passes_over_the_heading_named_inside_a_paragraph` and the case
  below it, and a whole-line match that reads the code fence not at all fails
  `test_the_named_part_reader_passes_over_the_heading_quoted_in_a_code_block` alone. **One defect of the recovered work
  reached the repair, and `pyright` found it before a run did.** `main` read the module
  docstring for the description of its argument parser, and **`python -OO` sets `__doc__` to
  None on every module**, so the command raised `AttributeError: 'NoneType' object has no
  attribute 'splitlines'` before it read one argument. The case came first and it failed on
  that message. `DESCRIPTION` is now a literal of the module, and
  `test_the_module_runs_where_the_interpreter_strips_every_docstring` holds the reader
  against `python -OO`. #513 records the same pattern at `tests/mutation_cover.py:211` and
  `tests/mutation_sweep.py:520`, which this round leaves alone. **The second reported
  `pyright` diagnostic does not reproduce.** `tests/release_body.py:38` imports
  `tests.version_gate`, which `tests/release_verification.py:47` imports in the same form,
  and `pyright` reports no diagnostic against either file from the repository root or from
  `tests/`. **A workflow step that never runs cannot fail**, and no case here starts the
  publish workflow, because a run of it would publish. **No dry run has run.** The
  `testpypi` environment exists at the provider, it holds no protection rule and it carries
  zero deployments, and no agent reads the TestPyPI publisher page. An absent publisher
  fails the index at `invalid-publisher`, the upload sends no artifact, and the literal
  repository URL keeps the job away from PyPI whatever the publisher state is. The first dry
  run is the measurement, and this round started none. `python -m tests.release_verification
  --dist dist` ran on this host against a real build and reported
  `release check: PASSED. The release is ready to publish.`, with 1809 cases collected and
  `1532 passed, 143 skipped, 134 xfailed`. #512 records the stale step 1 of
  `.claude/skills/release/SKILL.md`, which still names `pyproject.toml` as the version
  declaration that #67 removed, and this round leaves it alone. No file under `ja4plus/`
  changes and no fingerprint moves. The whole gate ran on this host. The conformance suite
  reports 1532 passed, 143 skipped and 134 xfailed, which are the three counts round 189
  reports. The unit suite reports 3990 passed, 4 skipped and 8 xfailed, and
  `pytest tests/ -m installed_wheel` reports 43 passed. **Coverage holds at 94%**, with 273
  misses of 4292 statements, which is the reading round 143 records. `mypy --strict` finds
  no issue in 31 source files, and `ruff check` and `ruff format --check` pass on 214 files.

- **The built wheel carries the mapping file and the `py.typed` marker, and it carries no test,
  example or documentation file** (#69). Round 189. `FR-release-10` and `FR-release-11` state
  the two requirements, and new file `tests/test_packaging.py` holds nine cases against the
  built wheel. **#455 already repaired the wheel these cases read**, so this round measures a
  state that holds and it changes no packaging rule. A read of 2026-08-10 reports 39 entries
  and 155900 bytes, and #455 reports the same entry count. **The value of a case here is the
  direction it fails in**, so four mutation cases prove both directions on a copy of the
  wheel: a copy without `ja4plus/py.typed`, a copy without `ja4plus/data/ja4plus-mapping.csv`,
  a copy that gains one entry under `tests/`, and an archive that lists no entry at all.
  **An aggregate over an empty set passes**, so `packaging_faults` reads the entry count
  before it reads the exclusion rule, and the floor stands at 30 entries. **A mutation writes
  a copy and it edits no byte of the built wheel**, which `test_the_mutation_leaves_the_built_wheel_unchanged`
  measures by digest. **A second read of 2026-08-10 states which mechanism ships each required
  entry, and it corrects a plausible reading.** With `[tool.setuptools.package-data]` cut to
  `ja4plus = ["data/*.csv"]` and the exclusion list cut to `["examples", "assets", "assets.*"]`,
  the build still listed `ja4plus/py.typed`. `include-package-data` is true by default and the
  file finder of `setuptools-scm` reports every tracked file, so a tracked file below the
  package ships whatever the package-data list holds. That weakened build listed 376 entries
  and 337 of them lay under `tests/`, `examples/` and `docs/`, and the excluded-tree case
  failed with `the wheel carries 337 of its 376 entries under ['tests/', 'examples/',
  'docs/']`. The measurement restored `pyproject.toml`, and `git status` reported the file
  unchanged after the restore. **This round repeats one reading of that file for the mapping
  file and one for the documentation tree**, because `FR-release-10` and `FR-release-11` each
  name them beside another entry and a case reads a whole requirement. **It repeats no other
  reading of `tests/test_installed_wheel.py`**, which holds the assets tree, the top-level
  name and the whole payload; the new file imports `build_artifacts` and `wheel_entry_names`
  from it. **The user ruled on 2026-08-10 that the project holds
  `Development Status :: 3 - Alpha` until the maintainer tags version 1.0.0.** The classifier
  is a promise about the interface, and the release commit of 1.0.0 makes that promise true.
  `FR-release-12` therefore stays open, and this round changes no line of `pyproject.toml`.
  **The ruling declines the third acceptance criterion of #69**, so this round builds no part
  of it. `docs/specs/features/09-release.md` gains two sections, three edge cases and two
  ticked criteria. No file under `ja4plus/` changes and no fingerprint moves. The unit suite
  reports 3950 passed, 4 skipped and 8 xfailed, the conformance suite reports 1532 passed,
  143 skipped and 134 xfailed, and the `installed_wheel` marker reports 43 passed. Coverage
  holds at 94% with 4292 statements and 273 misses.

- **The divergence register records the JA4 ALPN ruling** (#522). Round TBD. **The user
  ruled on 2026-08-10 that the form of `ja4plus` stands.** A first ALPN value that is not
  alphanumeric writes `99`, and a first ALPN value of one byte writes `hh`. The conformance
  audit of the same date named this the one condition where `ja4plus` matches no FoxIO
  implementation. **The two references disagree with each other**, and each one reads its
  own tooling rather than the packet. `ja4plus` reads the packet bytes, and it writes `99`
  or `hh`. FoxIO Python writes `U+FFFD`, which is a replacement character that no packet
  byte holds. FoxIO Rust writes `h9`, which is the escape text of `tshark`. **A match with
  either reference copies an artifact of that reference tool into the fingerprint**, and
  the user declines that. **No FoxIO reading is available to adopt here**, so the new row
  states the ruling rather than a value to adopt. #141 holds the measurement of the
  disputed inputs and #162 records the readings of 2026-08-07, and the two rows those
  issues wrote stay as they are. **This round moves no fingerprint and it repairs no
  defect.** New file `tests/test_alpn_ruling_register.py` holds eight cases, and seven of
  them failed before the row landed. **Four mutations prove that the cases bite.** A row
  that drops the ruling reports ``AssertionError: the ruling row holds no 'the form of
  `ja4plus` stands'``. A row that gives FoxIO Rust the value `hh` reports
  ``AssertionError: the sentence that names FoxIO Rust states no value `h9` ``. A row that
  renames the item reports `AssertionError: the divergence register holds no row named
  'The JA4 ALPN form that matches no FoxIO implementation'`. A row that moves the date out
  of the ruling sentence into the sentence after it reports `AssertionError: the sentence
  that states the ruling names no date 2026-08-10`. **The self-review found that fourth
  reading, because the ruling sentence closed its bold mark after the period and the reader
  therefore read it together with the sentence after it.** The row now closes the bold mark
  before the period, so the reader holds the date against the ruling alone. The run
  restored each mutation, and `git diff --stat` then reported one insertion. **A floor
  refuses a reader that found no row**, because an aggregate over an empty set passes.
  `MINIMUM_REGISTER_ROWS` reads 30, which is the row count before this round. **The sixteen entries
  of `tests/foxio_deviations.json` that name #162 stand**, and one case reads that count.
  The deviation register holds 134 keys before and after, and the conformance suite reports
  1532 passed, 143 skipped and 134 xfailed before and after. **No file under `ja4plus/`
  changes.** The unit suite reports 4076 passed, 6 skipped and 8 xfailed, and the eight new
  cases stand among them. **All six skips read the platform or the host**: two name the
  Linux cache convention, three name the `AF_PACKET` sockets of Linux, and one names the
  capture privilege of this account. Coverage holds at 94% with 4316 statements and 273
  misses.

- **The divergence register carries the FoxIO License 1.1 contradiction** (#466). Round 182.
  **Three FoxIO records at the pinned commit
  `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` name a different set of methods.**
  `License FAQ.md:5` names twelve, the FoxIO `README.md:293` names nine, and `LICENSE:3`
  names thirteen. `LICENSE:3` spells the scanner `JA4SScan`, and it names a `JA4E` that
  neither other record names. **This round read all three lines again**, from a checkout
  outside this repository, because #388 measured them on 2026-08-09. All three counts
  hold. **No statement of equality with FoxIO's list can be true**, so the subset wording
  of `README.md` stands and the file does not change. **The user ruled on 2026-08-10.**
  The register carries the record, because a measurement that lives only in a closed issue
  is a measurement the next reader repeats. **This is a candidate reference defect outside
  the two shapes `.claude/rules/conformance.md` declines**, because it moves no
  fingerprint. That rule sends such a case to the user. **The register quotes each
  FoxIO line verbatim**, because `.claude/rules/ste.md` bars a rewording of text copied
  from the FoxIO material. **A second row records `JA4Scan` as not implemented, with no
  decision taken.** That is the true state, and the row writes no reason for a decline
  because no round holds one. **JA4TScan keeps its existing entry** under `Non-goals`.
  `README.md:42` states that it sends crafted packets, so it reaches a network the
  operator did not capture. That decision is unrelated to the license. New file
  `tests/test_foxio_license_register.py` holds seven cases against the two rows, and all
  seven failed before the rows landed. **A floor refuses a reader that found no row**,
  because an aggregate over an empty set passes. One case bars a decline phrase from the
  `JA4Scan` row, so a later writer cannot turn a recorded absence into a recorded
  decision. No file under `ja4plus/` changes and no fingerprint moves.

- **A change set that records no round fails a case** (#429). Round 156. New file
  `tests/test_round_entry_existence.py` reads the change set of the branch and requires one
  new round entry in `CHANGELOG.md` and one new Changelog row in `docs/specs/spec.md`. The
  three cases of `tests/test_changelog_round_agreement.py` hold the two records against
  each other, and **two absent records agree**, so all three passed the change set of #412:
  eleven sweeps, two repairs, a new test file, no entry and no row. The project manager
  read the diff at the merge gate and caught it, and that is not a check. **The reference
  point is the merge base of `HEAD` and the integration branch**, which `git merge-base`
  reads against `origin/dev` and then `dev`. The change set joins two readings:
  `git diff --name-only <merge base>`, which reports an uncommitted change to a tracked
  file, and `git ls-files --others --exclude-standard`, which reports the new file that
  #412 shipped. A change set of `CHANGELOG.md` and `docs/specs/spec.md` alone demands no
  entry, because the round assignment of the project manager edits those two files alone.
  **The case counts an unassigned entry and a numbered entry alike**, because the project
  manager assigns the number at the batch gate on one batch and hands the number to the
  worker on another, and a case that demanded `TBD` would fail on the second. **Where the
  change set cannot be read, the case skips and the reason names the state.** A shallow
  clone carries no `origin/dev` ref, and the `actions/checkout` step of
  `.github/workflows/test.yml` makes such a clone, so the case skips on the GitHub runner
  and runs on the local gate of a worker. #438 owns the ref the runner needs. **The case
  was proved in both directions on this repository.** With this entry absent it reported
  `the change set holds these paths outside the two records: tests/test_round_entry_existence.py. CHANGELOG.md holds 68 round entries against 68 at the reference commit`,
  and with this entry and its row present it passed. **One case reads the change set of
  #412 itself.** It reads commit `46aa502` against its parent and reports
  `the change set holds these paths outside the two records: .claude/rules/conformance.md, docs/mutation_reports/412-utils.json, docs/mutation_settlements/412-utils.json and 3 more. CHANGELOG.md holds 64 round entries against 64 at the reference commit`,
  so the new case fails the change set the whole unit gate passed. Thirteen more cases build
  a scratch repository with `git init` and prove the same pair over a committed change, an
  uncommitted change, an entry that reaches one record alone, a change set of each record
  alone, a file an ignore rule covers, a repository that holds no integration branch and a
  directory that holds no repository.
  **A case here cannot test that an entry is true**, only that one exists. Three more
  limits reach the docstring of the module, and the widest one is that the count reads the
  whole branch, so an integration branch whose members each recorded a round satisfies a
  member that recorded none. No file under `ja4plus/` changes, no fingerprint moves, and
  the register holds 134 keys against 134 xfailed.
- **The package states a measured packet throughput** (#415). Round 151. New file
  `tests/throughput_run.py` feeds one `Processor` a stated packet run in an interpreter of
  its own. It writes one JSON object, and the object holds `packets`, `connections`,
  `elapsed_seconds`, `packets_per_second`, `fingerprints`, `python_version`, `platform`
  and `commit`. New file `tests/test_throughput.py` reads that object. New page
  `docs/performance.md` publishes the measurements, and `mkdocs.yml` lists it.
  **The clock covers `process_packet` and nothing else.** The traffic build and the
  capture parse sit outside it, so the rate reads this package and not scapy.
  **The synthetic run reads 1000000 packets across 100000 connections at 2006 packets for
  each second.** It took 498.39 seconds and produced 400000 fingerprints. The host is this
  laptop, `macOS-26.6.1-arm64-arm-64bit-Mach-O`, Python 3.14.3, commit `be91cc4`. The run
  ran beside a mutation sweep, and the load average read 8.88 before it and 12.78 after it.
  Read the rate as a lower bound. **The capture run reads all 38 captures on both hosts.**
  The two agree on the result and differ on the time. Each read 9062 packets and produced
  777 fingerprints, at 1857 packets for each second on `bigboy` and 2183 on this laptop.
  **The one-million-packet synthetic run has one host only.** `bigboy` is shared, it
  carries an Elasticsearch node, and #410 already spent a memory ceiling run there. The
  project manager therefore gave it the capture run alone. `docs/performance.md` states
  that gap and its reason, and no Linux figure for the synthetic run exists.
  **The measurement carries three controls, and #415 proved each one able to fail.** A
  timing case that measures the wrong thing reads as a fast package. The packet count
  control fails when the run feeds half the packets. The work control fails when the clock
  reads a constant rather than the traffic. The result control fails when the run counts no
  fingerprint, because a processor that produces nothing reads the highest rate of all.
  Each defect turned its own control red on `bigboy`, and the restored file turned it green.
  **The issue names the manifest as a premise, and the count contradicts the doubt.**
  `tests/foxio_vector_manifest.json` holds the same 38 names the directory holds, so the
  manifest is complete and the capture set is every file under `tests/foxio_vectors/`.
  **This entry sets no target and adds no job.** `Non-goals` states that wire-speed
  performance is out of scope, `grep -rn "packets_per_second" .github/workflows/` finds
  nothing, and `test_no_workflow_names_the_rate_field` holds that. **The measurement
  becomes no floor**, because a floor derived from it cannot detect a fault in it.
  **Two statements about throughput are not checkable, and the page marks each one.** It
  reports neither as true. No check tells a slow package from a slow host, and no check
  states whether a rate is adequate. No file under `ja4plus/` changes and no fingerprint
  moves.
- **The granted Linux host measured the gates for the first time** (#410). Round 149.
  The host is `bigboy`, Ubuntu 24.10, kernel `6.11.0-29-generic`, 56 cores, 137 GiB and
  `python3.12` only. It holds a checkout at `/home/e/ja4plus-verify`, which
  `.issue-flow.json` recorded nowhere, and the run created
  `/home/e/ja4plus-verify/.venv` on `Python 3.12.7`. The checkout held
  `3991712f08fbb11996fad69a3b457150d585463b`, the head of
  `epic/406-pre-release-validation`. #410 holds every transcript verbatim.
  **The gates report no failure.** The unit suite reads
  `2547 passed, 3 skipped, 1825 deselected, 8 xfailed, 16 warnings in 393.15s (0:06:33)`.
  Coverage reads 94 percent against the `COVERAGE_FLOOR` of 70. The conformance suite reads
  `1532 passed, 143 skipped, 2574 deselected, 134 xfailed, 1 warning in 16.21s` against
  the 134 keys of `tests/foxio_deviations.json`, which matches the premise the issue
  states. `ruff check` reads `All checks passed!`, `ruff format --check` reads
  `183 files already formatted`, and `mypy --strict ja4plus/` reads
  `Success: no issues found in 31 source files`. The fuzz job reads `127 passed`.
  `TestTheStatedMemoryCeiling` reads `4 passed`, and
  `tests/memory_ceiling_run.py --packets 30000 --connections 3000 --bound 0` writes
  `peak_mib` 115.37 against the stated 512 MiB ceiling.
  **The installed-wheel marker took 71.56 s on Linux against the 23 s #408 measured on
  macOS.** That case builds an artifact and installs it, so its cost follows the host.
  **The caveat binds every measurement above.** The host verifies a Linux code path. It
  predicts no `ubuntu-latest` result, because the runner holds another kernel, another
  processor count, another memory size and another Python version. The host measures
  `python3.12` alone, so the 3.9, the 3.10, the 3.11 and the 3.13 rows of the matrix get
  no measurement here. **Three statements of #410 are not checkable, and each names its
  reason.** No check confirms that a transcript came from that host. No check confirms
  that no load generator ran. No check turns a Linux pass into an `ubuntu-latest`
  prediction. `docs/specs/features/11-pre-release-validation.md` states the caveat, states
  the version gap, and settles the open question about the checkout path. **This entry
  adds no continuous-integration job.** **No file under `ja4plus/` changes, no file under
  `tests/foxio_vectors/` changes, and no fingerprint moves.**
- **One case fingerprints a capture from the installed source distribution** (#409).
  Round 148. `tests/test_installed_wheel.py` gains nine cases, and no new file appears.
  #408 wrote four functions that take the artifact as a parameter: the build, the
  clean-environment creation, the probe run and the comparison. This entry passes the
  source distribution to the same four. The run repeats the three paths of #408 against
  that artifact.
  - `ja4plus --version`.
  - `ja4plus analyze --format json`.
  - One script that imports `ja4plus` and drives a `Processor`.

  **`pip install <the sdist>` must build the source distribution and not resolve a
  wheel.** A run that resolves a wheel measures the artifact of #408 again and reports a
  pass. The install passes `--no-binary ja4plus`, and
  `test_pip_built_the_package_from_the_source_distribution` reads the recorded output for
  three facts.
  - `pip` names the source distribution as the input.
  - `pip` writes `Building wheel for ja4plus`.
  - `pip` writes no `Downloading ja4plus-<version>.whl` and no
    `Using cached ja4plus-<version>.whl`.

  **The option alone does not settle it.** The pip documentation states "Do not download
  binary packages. Cached binary packages may still be used." A mutation that installs
  `artifacts["wheel"]` proved the case fails:
  `AssertionError: pip read another input than .../ja4plus-0.6.0.tar.gz`. **The mapping
  file is the likeliest failure**, so two cases read it. One compares the byte count of
  `ja4plus/data/ja4plus-mapping.csv` in the clean environment against the byte count in
  the repository. One looks a named fingerprint up, because a present file is not a read
  file. **The control case is not optional.** It removes the mapping file from a second
  clean environment. It reads one probe twice: `70 True` before the removal, and
  `0 False` after it.

  **The evidence contradicts one premise of #409, and this entry works around it.** #409
  states that a package-data rule carries the mapping file. A mutation that removed
  `data/*.csv` from `[tool.setuptools.package-data]` still shipped the file in both
  artifacts. A mutation that added `[tool.setuptools.exclude-package-data]` shipped it
  too. `include-package-data` defaults to true for a `pyproject.toml` project, and the
  `setuptools-scm` file finder lists every tracked file. A second rule therefore carries
  the same file. Only `include-package-data = false` beside the removal dropped it, and
  both cases then failed live. **The source distribution carries the test material.** It
  lists 396 members, and `tests/foxio_deviations.json` is one of them.
  `test_the_source_distribution_lists_the_deviation_register` reads that listing.
  `tests/test_installed_wheel_selection.py` raises `EXPECTED_CASE_COUNT` from 7 to 16.
  **The marked run costs about 26 s on macOS with a warm `pip` cache**, against about
  23 s for the wheel alone. Two more clean environments install the artifact, and that is
  the whole difference. This entry changes no file under `ja4plus/` and it moves no
  fingerprint.
  Verified against: https://pip.pypa.io/en/stable/cli/pip_install/ and
  https://build.pypa.io/en/stable/reference/cli.html (retrieved 2026-08-09).
- **One case fingerprints a capture from the installed wheel** (#408). Round 146. New
  file `tests/test_installed_wheel.py`, and the new `installed_wheel` marker in
  `pyproject.toml`. The case builds both artifacts with `python -m build`, and it installs
  the wheel into a clean environment. It reads three paths from that environment:
  `ja4plus --version`, `ja4plus analyze --format json`, and one script that imports
  `ja4plus` and drives a `Processor`. The output of the last two equals the output of the
  source tree, byte for byte. **A run that resolves the working copy proves nothing.**
  Every other job of `.github/workflows/test.yml` installs with `pip install -e ".[dev]"`,
  which puts the source tree on the import path. A case that only imports `ja4plus`
  therefore measures the checkout. This case reads `ja4plus.__file__` of the clean
  environment. It fails when that path is not below the `site-packages` directory of that
  environment.
  **A check that cannot fail measures nothing**, so
  `test_the_import_check_fails_for_the_source_tree` holds the same check against the
  interpreter that runs the suite and asserts that it rejects that path. **The control
  case is not optional**, because the byte-for-byte comparison passes on any wheel that
  imports. It removes `ja4plus/data/ja4plus-mapping.csv` from a second clean environment
  and reads one probe twice: `70 True` before the removal, and `0 False` after it.
  `.github/workflows/test.yml` gains the `installed-wheel` job, which names the marker, so
  a failure is visible without a log search. **That job is the only runner of the marker.**
  New file `tests/conftest.py` deselects the marker from a run that does not name it, and
  the `conformance` job holds the same relation to `spec_validation`. The unit gate
  therefore builds no wheel and reaches no index. **A `-m` expression on the command line
  replaces the one in `addopts`, so `addopts` cannot hold that rule.** A measurement of
  2026-08-09 proved it: with `addopts = "-m 'not installed_wheel'"` and the gate command
  `-m "not spec_validation"`, `pytest --collect-only` still collected all seven cases. New
  file `tests/test_installed_wheel_selection.py` holds the rule against three commands, so
  a rename of the marker fails a case rather than removing the wheel cases from the gate
  in silence. **`build` joins the `dev` extra**, because the dedicated job and a local run
  each need `python -m build`. #409 installs the source distribution. The build,
  the environment creation and the comparison each take the artifact as a parameter, so
  #409 passes another artifact to the same three functions. **The case costs wall-clock
  time on every gate run.** Four consecutive runs on macOS with a warm `pip` cache
  measured 40.39 s, 24.25 s, 24.40 s and 22.22 s, so the settled figure is about 23 s. A
  runner starts with a cold `pip` cache and takes longer. This entry changes no file under
  `ja4plus/` and it moves no fingerprint.
- **Every sweep candidate of the twelve fingerprinter modules is settled** (#413).
  Round 154. New files `docs/mutation_reports/413-fingerprinters.json` and
  `docs/mutation_settlements/413-fingerprinters.json`. Twelve single-module sweeps read
  `ja4plus/fingerprinters/` with `--max-per-module 0`, one for each module, over **1569
  mutations**: `ja4ssh.py` 265, `ja4l.py` 239, `ja4.py` 203, `ja4d6.py` 194, `ja4h.py` 169,
  `ja4s.py` 134, `ja4x.py` 130, `ja4d.py` 128, `ja4ts.py` 56, `ja4t.py` 31, `base.py` 11 and
  `__init__.py` 9. The sweeps killed 891 mutations, 675 survived and 3 passed the time
  limit. The union of the twelve candidate sets is **394 candidates**, and the record
  settles every one with the verdict `correct` and the reason. **No file under `ja4plus/`
  changes**, because `CLAUDE.md` rule 1 binds every change there to a vector.
  **The scope is the minimal cover.** The rule "name every test file that reads the module"
  measured **43.86 hours** for this module group, eleven times the four-hour ceiling, and
  the cover measured **0.69 hours** against 1569 mutations. The three limits of #412 hold
  here without change, and the record states them under its `scope` key.
  **The default coverage core of Python 3.14 records almost no test context.** A minimal
  cover reads a run that tags each line with the case that ran it, and `coverage` 7.15.4
  selects the `sysmon` core on Python 3.14.3. One whole-suite run over 4112 passing cases
  recorded **294 contexts over 74 test files**, where the same run under
  `COVERAGE_CORE=ctrace` recorded one context for each case and raised the reader set of
  this module group from 47 test files to 95. **A cover built on the first run names too few
  test files**, so the record states the command that produces correct data.
  **94 of the 675 surviving mutations sit inside a type annotation, and no case can ever
  fail for one.** Every module of `ja4plus/fingerprinters/` carries
  `from __future__ import annotations`, so Python holds each annotation as a string and
  evaluates none of them. The sweep already skips a docstring and a logger argument for the
  same reason, and #431 records the finding.
  **`ja4plus/fingerprinters/__init__.py` reported 9 survived of 9, and the record states the
  reason rather than a new case.** The module holds nine export names and no case reads
  `__all__`, so no name is measured. The nine survivors are correct as they stand.
  **Three mutations of `ja4plus/fingerprinters/ja4x.py` make a record scan run with no
  progress**, at line 243 and twice at line 284, and each run stopped at the 180-second
  limit #412 added. A run that never finished measured nothing, so each carries the status
  `timeout` and the candidate list over-reports rather than under-reports.
  **Eight candidates cannot fail**, because the unmutated suite state reports them as
  xfailed: seven of `tests/test_ja4_alpn.py` and one of `tests/test_ja4h_spec.py`. No
  candidate is skipped. **No fingerprint moves.**
- **Every sweep candidate of the seven interface modules is settled** (#414). Round 155.
  New files `docs/mutation_reports/414-interface.json`,
  `docs/mutation_settlements/414-interface.json` and
  `tests/test_settlement_procedure.py`. Seven single-module sweeps read the seven Python modules of the top directory of the package, which `tests/mutation_sweep.py --module 'ja4plus/*.py'` selects with `Path.glob`,
  with `--max-per-module 0`, over **556 mutations**:
  `cli.py` 226, `watch.py` 97, `ja4db.py` 68, `output.py` 68, `processor.py` 54,
  `__init__.py` 32 and `types.py` 11. **The cost was measured before the run and not
  estimated.** The minimal cover of each module, timed as a whole `pytest` command, gives a
  product of **1.27 hours** against the four-hour ceiling, so the stop condition of
  Amendment 3 did not fire. The seven runs took 4188.7 s and reported **340 killed, 279
  survived, 4 timeout and 0 unusable**. The candidate sets hold 307 rows over the seven
  modules and **236 distinct cases**, which is the union the settlement record holds.
  **Do not compare 236 against the 976 of #206 or the 205 of #412**; the three count
  different sets. **Coverage with one context for each case splits the 307 rows**: 301 run
  no mutated line of their module inside a function body, and 6 run one. Each of the 6 was
  proved live with `inspect.getsource` in both directions, and **two of them are repairs**.
  `tests/test_documentation_samples.py` asserted the type of the error a `raises` sample
  block produces and never the line it came from, so the mutation `not in` -> `in` at
  `ja4plus/types.py:74` moved the raise from the second line of
  `docs/api_reference.md:284` to the first, kept the type `KeyError`, and left the case
  green. The harness now reads the line the error came from, so a sample whose earlier line
  raises fails. `tests/test_db_offline.py::TestTheConstructorRefusesAnAmbiguousCall::test_a_value_that_is_no_bool_raises_type_error`
  read the type of the error and no message, so the mutation of the message at
  `ja4plus/ja4db.py:294` changed nothing it compared. **The first repair was itself unable
  to fail**: `pytest.raises(match=...)` searches rather than compares, and
  `allow_remote takes True or False_mutated` holds the unanchored pattern, so the mutation
  still passed. The pattern now carries both anchors, and the mutation fails all four
  parameters. **The census assertion is proved in both readings**: the census names 236
  candidates of sweep `414-interface`, and one row removed from the record makes it name
  that candidate as unclaimed. **`FR-pre-release-validation-23` is split.** It stated a
  procedure a worker follows, no check could test it, and the list of statements the
  document declares uncheckable did not name it. The artefact of the procedure keeps a
  check, and `FR-pre-release-validation-23` now states it: a `repaired` verdict names a
  case the suite collects, which `tests/test_settlement_procedure.py` reads. The procedure
  itself becomes `FR-pre-release-validation-23a` and joins the uncheckable list as its
  third entry, because no case observes a worker. **The condition is necessary and not
  sufficient**, and both the requirement and the file say so. **The cover rule holds a
  defect this round records and does not repair.** It drops the lines the import runs, and
  95 of the 279 survivors sit on such a line. `ja4plus/__init__.py` measures the cost: the
  cover the rule builds is `tests/test_parity.py` at 1 killed and 31 survived, while the
  same 32 mutations against `tests/test_public_interface.py` read 25 killed and 7 survived,
  so 24 survivors are over-reported. #433 carries it. **`tests/test_cli.py` runs all 27
  reachable mutation lines of `ja4plus/output.py` on its own**, so the cover of that module
  holds it alone and no case of `tests/test_output_schema.py` or of
  `tests/test_cli_output_option.py` is measured against that module. A case the cover drops
  is unmeasured and not clean, and the record states it. No file under `ja4plus/` changes,
  no file under `tests/foxio_vectors/` changes, and no fingerprint moves.
- **Every sweep candidate of the eleven protocol parsing modules is settled** (#412).
  Round 153. New files `docs/mutation_reports/412-utils.json` and
  `docs/mutation_settlements/412-utils.json`. Eleven single-module sweeps read
  `ja4plus/utils/` with `--max-per-module 0`, one for each module, over **1420 mutations**:
  `tls_utils.py` 335, `quic_utils.py` 315, `ssh_utils.py` 252, `x509_utils.py` 173,
  `http_utils.py` 103, `tcp_stream.py` 80, `tcp_options.py` 63, `state_table.py` 55,
  `packet_utils.py` 35, `loopback.py` 5 and `tunnels.py` 4. `ja4plus/utils/__init__.py`
  holds no expression a mutation can change. The union of the eleven candidate sets is
  **205 candidates**, and the record settles every one: **203 read `correct` with the
  reason and 2 read `repaired` with the case**.
  **The scope is the minimal cover, and the user ruled it on 2026-08-09.** The rule "name
  every test file that reads the module" measured **32.18 hours**, eight times the
  four-hour ceiling, so the stop condition fired and no sweep started until the ruling
  arrived. The minimal cover is the smallest test-file set that still runs every mutation
  line of the module, and it measures **0.52 hours** for the same 1420 mutations.
  **Three limits hold wherever that result is read.** Every mutation keeps a reader, so a
  mutation that no case kills is still found and the surviving-mutation signal is
  preserved. The cover is conservative in the safe direction: a test file it drops might
  have killed a mutation, so it **over-reports survivors and never under-reports them**.
  The candidate set shrinks, 97 cases for `quic_utils.py` against 2268 under the wider
  rule, and **a case the cover drops stays unmeasured against that module** rather than
  measured clean. The record holds the cover of each module under its `scope` key.
  **Two cases are repaired.** `ja4plus/utils/tunnels.py:27` held three module-name strings
  that no case read: `tests/test_tunnels.py` asserted `startswith("scapy.")` alone, so a
  wrong module name left it green, and a new case names the three modules as literals.
  `ja4plus/utils/loopback.py:23` held the address family value 30, and
  `tests/test_loopback_link_type.py` measured nothing for it on Darwin, because scapy binds
  `socket.AF_INET6` itself and that value is 30 there. **The case was vacuous on this host
  and would have failed on Linux**, and it now asserts that `ja4plus` wrote the bind.
  **One mutation can turn a loop bound into a loop that never ends, and the sweep had no
  time limit.** `ja4plus/utils/ssh_utils.py:284` holds that bound: the sweep reads
  `while position < len(payload)` as `while position <= len(payload)`, and
  `SSHMessageTracker.process_payload` then loops with no progress. The sweep stopped for
  good three times before the cause was read from the mutated file.
  `tests/mutation_sweep.py` gains `--timeout`, and a run that passes the limit records the
  status `timeout` and the sweep continues. **A mutation that times out is not a
  survivor**, because a run that never finished measured nothing. The limit is off by
  default. New file `tests/test_mutation_sweep_timeout.py` holds six cases. Seven mutations
  of this module set reached the limit: three of `tls_utils.py`, two of `ssh_utils.py`, one
  of `state_table.py` and one of `x509_utils.py`.
  **A criterion that reads "0 unsettled candidates" passes on an empty directory**, so a
  settlement issue must prove its census assertion is not vacuous.
  `tests/test_mutation_census.py` gains `TestTheRecordsOfThisRepository`, which states two
  readings: the census names at least one candidate, and it names an unclaimed candidate
  when one row leaves the record. `.claude/rules/conformance.md` records the `timeout`
  status, how to build a minimal cover from a measurement, and the non-vacuity rule.
  **No file under `ja4plus/` changes and no fingerprint moves.**
- **The sweep report names the commit it read, and a census counts the open candidates**
  (#411). Round 147. `tests/mutation_sweep.py` writes a `commit` key and a `Commit` row,
  read from `git rev-parse HEAD` before the first mutation lands.
  `FR-pre-release-validation-17` asks for it, and the report of 2026-08-07 states no
  commit. New file `tests/mutation_census.py` reads every `*.json` report of
  `docs/mutation_reports/`, counts the candidates of each test file, and reads every
  `*.json` record of `docs/mutation_settlements/`. **It opens no Markdown file**, because a
  Markdown report is one page and a count taken from its lines counts the page layout.
  **The census groups by test file and not by module**, because
  `tests/mutation_sweep.py:593` builds one flat candidate list over every swept module and
  no module owns a candidate. **The whole-package sweep is partitioned across #412, #413
  and #414.** `--dry-run --max-per-module 0` reads 3545 mutations over 31 modules, one
  suite run takes 72.75 seconds, and the product is 71.6 hours on one host.
  `.claude/rules/conformance.md` stated about 17 seconds, and it now carries the measured
  number and its date. **The union of the per-module sweeps is larger than the candidate
  set of one whole-package sweep, and the union is the correct input for settlement.**
  **`git ls-files 'ja4plus/**/*.py'` lists 24 files where the package holds 31**, because
  git reads `**` in a pathspec as one or more directories.
  `FR-pre-release-validation-16` now names `git ls-files 'ja4plus/*.py' 'ja4plus/*/*.py'`,
  and new file `tests/test_mutation_sweep_module_list.py` fails when the module list one
  sweep reads stops matching the tracked Python files of the package. **No file under
  `ja4plus/` changes and no fingerprint moves.**
- **The specification records Epic 11, pre-release validation** (#407). Round 145. New
  file `docs/specs/features/11-pre-release-validation.md`. It states 33 requirements, and
  every sub-issue of #406 quotes one. **The epic measures four statements that version
  1.0.0 makes and that nothing checks today.** No case runs the shipped package. Every
  Linux result comes from a continuous-integration runner. The sweep leaves 974 of its
  976 candidates unsettled. The package states no throughput. **The epic publishes
  nothing. It sets no throughput target, and it moves no fingerprint.**
  `docs/specs/spec.md` gains the feature entry, the `Feature map` row, the `Epics`
  section, both `Issue map` tables and five `Terms` rows. **The file number equals the
  epic number.** Epic 10 (#194) holds no feature document, so `features/10-*.md` does not
  exist and the sequence loses no file.
  `Terms` gains `mutation`, `sweep`, `candidate`, `clean environment` and `throughput`.
  **A count of the table read 67 rows, and the table held none of the five under any
  spelling.** No row of this round therefore rotates a synonym of an existing row. New
  file `tests/test_specification_terms.py` fails a term that two rows carry, and fails a
  row that bars no synonym. A reader who scrolls a 72-row table sees neither by eye.
  **The evidence contradicts two premises of the epic, and the feature document records
  both rather than a repair.** `tests/mutation_sweep.py:396` groups the
  `candidates` key of the report by test file and not by module. A candidate is a case
  that survived every mutation of every swept module, so no module owns one. The
  per-module census that #411 states therefore reads one sweep for each module group. The
  report of 2026-08-07 also holds a `Date` field and no commit field, so
  `FR-pre-release-validation-17` asks #411 to add one. This entry changes no file under
  `ja4plus/`.
- **The documentation site publishes to GitHub Pages, and this file holds the release
  notes of version 1.0.0** (#66). Round 142. New file `.github/workflows/docs.yml`. It
  fires on a push to `master`, which is the live branch, and a promotion from `dev` to
  `master` is a step the user approves. **The workflow builds nothing of its own.**
  `.github/workflows/docs-build.yml` already installs the committed `docs` pins into an
  empty environment and runs `mkdocs build --strict`, and a second recipe for one site
  drifts apart from the first in silence. That job gains a `workflow_call` trigger and one
  conditional step, so the publish workflow calls it and deploys the artifact it uploads.
  The input is absent on a `push` trigger and on a `pull_request` trigger, so a pull
  request uploads nothing. No pin and no build step changes, and #391 keeps both.
  **This repository holds no GitHub Pages site, and no run has ever deployed.**
  `gh api repos/Crank-Git/ja4plus` reports `has_pages: false`. The user decides whether to
  turn Pages on, because that change publishes a public website. The first job therefore
  reads `GET /repos/{owner}/{repo}/pages` and names the setting in the failure: a 404
  reports that the site is absent, a `build_type` other than `workflow` reports the wrong
  source, and any other status reports the status it read. **The deployment stays
  unverified until the user changes the setting**, and no case here claims otherwise.
  **The release notes name every breaking change the record holds**: thirteen interface
  changes and eight fingerprints that move. New file `tests/test_release_notes.py` holds
  the two tables against the `**BREAKING` entries of this file, against
  `docs/migration-0.6-to-1.0.md`, and against the Changelog table of `docs/specs/spec.md`.
  **The self-review then found a citation the first form of that file could not read.**
  The migration page cites one change under `Round 122` and names #364 beside #59, and
  round 123 is the row that records #364. A case that compared the two `Record` cells
  passed, because both files held one error. The case now reads the Changelog table, which
  is the authority both files copy, and #401 holds the repair of the page. Six mutations
  prove the cases discriminate, and each was restored. New file
  `tests/test_documentation_publish.py` reads the two workflows. `actionlint` 1.7.7 reports
  no finding on either one. No file under `ja4plus/` changes and no fingerprint moves.

- **Every code sample and every example script runs in continuous integration** (#63).
  Round 138. Nothing ran a sample before this round, so a sample that stopped working
  stopped working in silence. That is the shape this project records seventeen times: a
  comparison that never runs reads as a comparison that passes. **The reader finds 157
  fenced blocks across `README.md` and `docs/`, and a second reader agrees on every
  file.** `tests/documentation_samples.py` matches a fence grammar and tracks the fence
  width, and `_second_reader_block_count` uses string operations alone. **The two readers
  disagreed on the first run, and the disagreement was a real defect.** Four files of
  `docs/specs/foxio/` each hold an inline code span that opens a line with three
  backticks, and the second reader read each one as a fence. The floor was then set from
  the corrected reader, because #302 set its floor from a reader that skipped every
  wrapped row. **The census reads 43 blocks that run, 2 that raise a named error, 94 that
  the harness skips and 18 that carry output.** A `python` block and a `bash` block run
  by default. `<!-- sample: skip <reason> -->` states why a block runs never, and
  `<!-- sample: raises <error> <reason> -->` states the error a block raises on purpose.
  A skip reason shorter than four words fails a case, so no skip is silent. **14 samples
  carry a skip marker and 80 blocks of `docs/specs/` carry a directory reason**, because
  that directory holds the specification package and the verbatim FoxIO transcription.
  **No sample reaches the network**, and a fixture refuses every outbound connection
  while a Python sample runs. **Five scripts of `examples/` run under six command lines.**
  `examples/live_traffic_fingerprinting.py` gained a `--pcap` option that passes
  `offline` to `sniff`. **Four mutations prove the harness discriminates**, one for each
  of the README Python path, the README shell path, the `docs/` path and the `examples/`
  path, and each was restored. New files `tests/documentation_samples.py`,
  `tests/test_documentation_samples.py` and `tests/test_examples.py`, and a new `samples`
  job in `.github/workflows/test.yml`. **The merge with #64 exposed a hole in the first
  form of this harness.** `PYTHON_SAMPLE_FILES` read the keys of a table somebody
  maintained by hand, so a page absent from that table was read, counted and classified
  as runnable, and then never run. A probe page under `docs/reference/` holding a broken
  import proves it: the reader called the block runnable and the execution cases reported
  `3 passed`. **The file set now derives from the filesystem and the block counts stay
  measured by hand**, because the only tool that could derive a count is the reader the
  cases exist to check. `MINIMUM_BLOCKS_PER_PAGE` is a floor for each page and no longer
  an exact count. `test_the_execution_cases_reach_every_sample_the_reader_calls_runnable`
  compares the reader against the runner, so the two cannot drift apart again. The five
  pages #64 added hold `:::` directives and no fenced block, so both counts stay at 157.
  No file under `ja4plus/` changes and no fingerprint moves.

- **The `dropped` field of the statistics line reports the drop count of the capture
  socket on macOS** (#423). Round 186. #55 built the field, `MonitorStats` accepted a
  `dropped_source`, and `ja4plus/cli.py` passed none, so every monitor read `dropped=null`
  whatever the capture layer knew. `read_interface` now attaches the socket it opened to a
  `CaptureDropCount`, and `MonitorStats` calls that object for each line.
  `_L2bpfSocket.get_stats` reads the `BIOCGSTATS` ioctl at
  `scapy/arch/bpf/supersocket.py:297`, and `AsyncSniffer._run` holds the socket it opens in
  a local name at `scapy/sendrecv.py:1205`, so a caller reaches the socket through the
  `opened_socket` argument alone. **The reading came from a real capture socket of the
  development host, and #423 bars an injected one.** This project has recorded sixteen
  instances of a comparison that is never made reading as a comparison that passes, and a
  criterion marked met against a fake socket would be the seventeenth. The grant was
  measured at the moment of the run: `/dev/bpf0` through `/dev/bpf3` opened, `/dev/bpf4`
  answered `[Errno 13] Permission denied`, and `/dev/bpf5` and above answered
  `[Errno 2] No such file or directory`. **Each live case captures on the loopback
  interface and it generates every packet it reads.** A monitor on `lo0` read 4 packets of
  one TCP connection this run opened, over an `L2bpfListenSocket`, and reported
  `dropped=0`. **A count of 0 on a clean capture proves nothing**, because a field no code
  writes reads the same way. A second case therefore opens a real capture socket with a
  4096-byte kernel buffer, sends 50 UDP packets of 1400 bytes to the loopback address, and
  reads `received=55 dropped=46`. **Two mutations prove that case measures a real drop**:
  the whole 65535-byte buffer and a burst of one packet each fail it with
  `AssertionError: 0 not greater than 0`. **The `BIOCGSTATS` ioctl resets neither
  counter**, so the macOS monitor reports the count of the socket and accumulates nothing;
  two reads of one socket returned 29910 drops and then 59910 drops. That reading is the
  opposite of the Linux one, where `getsockopt(SOL_PACKET, PACKET_STATISTICS)` resets the
  counter as it reads, and #326 owns the Linux half. **`read_interface` reads the count
  once more before it closes the socket**, because the exit summary of FR-live-capture-8
  runs after the capture returned, and the kernel gives the file descriptor of a closed
  socket to the next file the process opens. New file `tests/test_watch_drop_count.py`
  holds 22 cases, and the whole file failed to collect before the change with
  `ImportError: cannot import name 'CaptureDropCount' from 'ja4plus.watch'`. **Where no
  `/dev/bpf` node opens, the two live cases skip and neither one passes**, and a probe that
  refused the device reported the skip reason
  `this host opened no capture socket on 'lo0': [Errno 13] Permission denied`. **Five more
  mutations prove the wiring**: a drop count that reports nothing fails 10 cases, a capture
  that attaches no socket fails 3, a capture that reads no count before the close fails 3,
  a command that passes no drop count fails 2, and a holder that keeps no last count fails
  4. Each mutation was restored. **The self-review found a race between the statistics
  thread and the close, and the class now holds a lock.** The statistics thread reads the
  socket while the capture closes it, and `SuperSocket.close` calls `os.close` and then
  sets `closed`, so a reader between the two statements reads a released file descriptor.
  `CaptureDropCount.release` holds the lock over the last read and over the drop of the
  socket, and `read_interface` calls it before the close. **Two of the three mutations that
  cover the guard passed against the first form of the cases**, which is the fault this
  project records sixteen times, and both cases were repaired until each mutation failed
  one. A socket that made every read wait blocked the release inside the ioctl rather than
  on the lock, so only the first read waits now. A case that read a closed socket could not
  see the difference between a release and a refresh, so it reopens the socket under
  another count and models the reused file descriptor. **The release now runs inside its
  own `try`**, because an exception there would leave the capture socket open for as long
  as the process runs. `docs/specs/features/06-live-capture.md` gains FR-live-capture-15
  and FR-live-capture-16, and the `## Terms` table gains `drop count`. The measurements ran
  on macOS 26.6.1, build 25G76, against `scapy` 2.7.0 and Python 3.14.3, on 2026-08-10.
  **No file under `ja4plus/fingerprinters/` changes and no fingerprint moves.** The
  conformance suite reports 1532 passed, 143 skipped and 134 xfailed before and after. The
  unit suite rises from 3827 passed to 3851 passed. Coverage holds at 94%, the total misses
  hold at 273 while the statement count rises from 4253 to 4292, and `ja4plus/watch.py`
  holds 99%. **Every count above measures this change against the base commit `cf77598`.**
  The branch then took the integration branch of batch #499, and the merged tree reports
  3901 passed and the same conformance counts.

- **The `dropped` field of the statistics line reports the drop count of the capture
  socket on Linux** (#326). Round 192. #423 closed the macOS half and it left the Linux
  half open, because no Linux host had run the reading. **`scapy` 2.7.0 calls `getsockopt`
  in no file**, which a `grep` over the installed package of the granted host confirms.
  The kernel reports a drop count, `scapy` reads it nowhere, and `ja4plus` now reads the
  socket option itself in `packet_statistics_drops`. That reader reaches the packet socket
  through `SuperSocket.ins`, which holds the `socket.socket` the Linux capture opened.
  **The Python `socket` module publishes neither constant**, and both names read `None`
  there, so `ja4plus/watch.py` defines them from the kernel headers of that host.
  `/usr/include/x86_64-linux-gnu/bits/socket.h:151` reads `SOL_PACKET 263` and
  `/usr/include/linux/if_packet.h:44` reads `PACKET_STATISTICS 6`. `struct tpacket_stats`
  at `/usr/include/linux/if_packet.h:77` holds `tp_packets` and then `tp_drops`, each one
  an `unsigned int` of the host byte order, so the reader unpacks eight bytes and takes
  the second field. A reader of the first field would report the received count as the
  drop count. **Warning: the kernel resets both counters as the read returns them.**
  `man 7 packet` of that host states the rule: `Receiving statistics resets the internal
  counters.` `CaptureDropCount` therefore adds each Linux reading to a running total,
  where the macOS reader reports the count of the socket and accumulates nothing.
  **The reset is a measurement here and not a premise.** One packet socket on `lo`, with a
  2304-byte receive buffer, answered `first=(100, 99)` and then answered `second=(0, 0)`,
  with no packet between the two reads. **Each live case captures on the loopback
  interface and it generates every packet it reads.** A monitor on `lo` read 4 packets of
  one TCP connection this run opened, over an `L2ListenSocket`, and reported `dropped=0`.
  **A count of 0 on a clean capture proves nothing**, because a field no code writes reads
  the same way. A second case therefore sends 50 UDP packets of 1400 bytes to the loopback
  address and reads a total of 99 drops, then sends 8 more packets and reads a total of
  115. **The second burst is far smaller than the first one**, so a monitor that reported
  the last reading would report a smaller count after it. **A mutation proves that the
  case bites**: `self._dropped = increment` in place of the sum fails 5 cases, among them
  the live one, which reports `AssertionError: 0 not greater than 0`. The mutation was
  restored. **The cases came first**, and the whole file failed to collect against the
  base implementation with `ImportError: cannot import name 'PACKET_STATISTICS' from
  'ja4plus.watch'`. **Where the host grants no `CAP_NET_RAW`, each live case skips and
  none of them passes.** `docs/specs/features/06-live-capture.md` gains
  FR-live-capture-17, one behaviour rule, two acceptance criteria and the section
  `## The Linux drop count`, and it now records no open question.
  `tests/test_watch_drop_count.py` rises from 22 cases to 38. **The live measurements ran
  on Linux 6.11.0-29-generic, against `scapy` 2.7.0 and Python 3.12.7, on 2026-08-10.**
  The host is shared, so the run read `uptime` before and after: `load average: 6.08` and
  then `load average: 5.91`, on 56 cores. The five gates ran on macOS 26.6.1, build 25G76,
  against `scapy` 2.7.0 and Python 3.14.3. **No file under `ja4plus/fingerprinters/`
  changes and no fingerprint moves.** The conformance suite reports 1532 passed, 143
  skipped and 134 xfailed before and after. The unit suite rises from 3950 passed and 4
  skipped to 3963 passed and 7 skipped, and the three new skips are the Linux cases on a
  macOS host. **Coverage holds at 94%**, the total misses hold at 273 while the statement
  count rises from 4292 to 4316, and `ja4plus/watch.py` holds 99%.

- **A case that skips on every job of the matrix fails the run** (#524). Round TBD. **A
  skip is not a pass, and a case that runs nowhere is not a case.** #438 measured that
  shape: `tests/test_round_entry_existence.py` reported a skip on every job of
  `.github/workflows/test.yml` from the day it was written, and every job stayed green
  while the case refused nothing. **One job reads no such case, because one job reads one
  environment.** A macOS case that skips on Linux is correct, and a Linux case that skips
  on macOS is correct. **The union of the six reports of the `test` job is the first
  reading that tells a correct skip from a case the suite runs nowhere.**
  `.github/workflows/test.yml` gains the job `skip-gate`, which depends on the `test` job,
  downloads the six `test-results-*` artifacts and fails a case that every report records
  as skipped. `tests/skip_gate.py` holds the condition and `tests/test_skip_gate.py` holds
  that file with 25 cases. **The reading takes no new dependency**: the workflow already
  writes one JUnit report for each matrix job with `pytest --junitxml`, and a `testcase`
  element with a `skipped` child names a case that job ran no assertion for. **An expected
  failure carries a `skipped` element too, and the first run of the gate measured that
  trap**: 8 of the 19 cases it named were `xfail` entries that every job runs. The element
  carries `type="pytest.xfail"` there, `reports_a_skip` reads that attribute, and a type the
  reader does not know still counts as a skip. `tests/universal_skips.json` holds the
  allowlist, each entry names the reason that stops its case, and the gate fails an entry
  that names no reason whatever the reports hold. **A report the download omits is not a
  passed job**, so the gate also fails a download smaller than the matrix. **The gate reads
  one download directory and never the checkout**, because #473 measured a reader that
  walked the repository root and picked up a worker worktree under `.claude/`.
  **The gate is proven on the runner in both directions**, on pull request #526 into
  `batch/523-conformance-and-claims`, which merged into nothing and closed with its branch
  deleted. **The red direction ran at
  https://github.com/Crank-Git/ja4plus/actions/runs/31408763259**, where every other job
  concluded `success` and `skip-gate` concluded `failure` on
  `tests.test_universal_skip_proof::test_the_case_that_skips_in_every_environment`.
  GREEN_RUN_PLACEHOLDER **The census classifies all 40 skip sites of `tests/` in
  the four forms `skipTest(`, `pytest.skip(`, `skipIf(` and `skipUnless(`: 28 of class a,
  10 of class b and 2 of class c.** The 10 of class b are one site of
  `tests/test_batch_gate_protection_rule.py`, which reads a branch-protection call that the
  provider grants to an administrator alone, and nine sites of
  `tests/test_watch_drop_count.py`, which open a real capture socket that no runner grants.
  **The 2 of class c are `tests/test_round_entry_existence.py:521` and `:525`**, whose case
  reads a commit that the clone of depth 1 does not hold, and #528 holds that finding. **One
  further class c site sits outside the four forms**: `tests/test_documentation_site.py:222`
  carries a `pytest.mark.skipif` and its case needs the `docs` extra that no job installs.
  #529 holds it. **The gate reads the six matrix jobs and no other job**, so a conformance
  case that skips everywhere reaches it nowhere, and #530 holds that reach.
  `docs/specs/features/11-pre-release-validation.md`
  gains `FR-pre-release-validation-35` through `FR-pre-release-validation-38` and three
  acceptance criteria, and `.claude/rules/batch-gate.md` gains the section
  `## A case that skips on every job fails the run`. **`skip-gate` is a twelfth check and
  the required list of `dev` holds eleven names**, so the branch protection rule reaches
  this check once the user adds the name to it. A red `skip-gate` fails the run whatever
  that rule holds, and the batch gate reads the run conclusion. **No file under `ja4plus/`
  changes and no fingerprint moves.**

### Fixed

- **The branch-protection claims of the batch-gate rule reach a case** (#511). Round
  TBD. `.claude/rules/batch-gate.md` states that each of the eleven required contexts
  carries `app_id` 15368, and `CHANGELOG.md` and the round 174 row of `docs/specs/spec.md`
  state it too. **No case read the number.** `provider_contexts` reads
  `required_status_checks.contexts`, which holds the context names alone, and the provider
  holds the application under `required_status_checks.checks[]`. The new reader
  `check_applications` reads that list, and
  `test_the_provider_carries_the_stated_application_on_every_context` requires `app_id`
  15368 on each of the eleven contexts. **The case reads its floor before it reads the
  provider**, so a file that states another number fails the case rather than compares two
  empty sets. A read of the provider on 2026-08-10 reports `app_id` 15368 on all eleven
  entries of `checks`. Where `gh` returns no reading, the case skips and it does not pass,
  and `test_the_application_case_skips_where_the_provider_returns_no_reading` measures that
  state. The same round repairs three statements of the rule file. The opening claim of
  `## The provider refuses an ungated merge` names the `enforce_admins` reading, which is
  `false`, so an administrator merge reaches `dev` with no run. The steps intro promised a
  change of the rule and the four steps below it are four reads, so it states what the
  steps do, and a case holds the verb of every step. One sentence dated its warning against the day a
  reader reads it, and it names the read of 2026-08-10 instead.
  `test_the_opening_claim_of_the_protection_section_names_its_condition`,
  `test_the_steps_of_the_protection_section_read_the_rule_and_change_nothing` and
  `test_no_live_sentence_of_the_rule_file_dates_itself_against_the_reader` hold the three
  repairs, and each reader runs in both directions.
  `tests/test_batch_gate_protection_rule.py` gains 26 cases and it holds 119. **No file
  under `ja4plus/` changes and no fingerprint moves.** The unit suite reports 4065 passed,
  7 skipped and 8 xfailed, and coverage holds at 94% with 4316 statements and 273 misses.

- **The sentence-length rule exempts the two records and no other document** (#457).
  Round 180. #393 found about twelve sentences of its own Changelog row past the 25-word
  limit, and that finding is correct against the letter of the rule. All 159 numbered rows
  read the same way, so a row written to the limit is a house-style change for the whole
  record. **The user ruled on 2026-08-10 that the record is exempt.** A dated record of a
  past measurement is quoted and not rewritten. A rewrite of the rows falsifies nothing they
  record, and it does mean that the text a past reader saw is not the text a future reader
  sees. `.claude/rules/ste.md` gains the section `## The one exemption`, which names the
  entries of `CHANGELOG.md` and the `## Changelog` table of `docs/specs/spec.md`. **The
  exemption names a path and never a class of files.** A blanket exemption for any file
  whose name holds the word `changelog` reaches `docs/CHANGELOG.md`, which this ruling never
  read. New file `tests/test_changelog_sentence_exemption.py` holds 27 cases.
  `exempt_records` reads the list of that section alone, `reaches` matches one document
  against one record, and `evaluate` reports three states: a record the ruling names
  nowhere, a document the exemption reaches outside the two records, and a document set
  below the floor of 40. The document set reads `git ls-files -z '*.md'`, which names 59
  pages, and an anchor case holds one page of each depth and of each root. **An aggregate
  over an empty set passes**, so a reading over no document fails there rather than
  reporting a green result. **The reader reads a path before a blanket word.** The first
  item holds the word `each` in the clause `which each record one round`, and the first form
  of the reader read that item as a class of files. **The sentence reader drops the emphasis
  marks first.** This project opens a paragraph with a bold sentence, the mark stands
  between the period and the space, and a reader that keeps the mark joins two sentences
  into one. **The cases came first and they bite**: against the unrepaired rule they failed
  5 of 27. **Two live mutations prove the failing direction.** A third record, the entries
  of `docs/CHANGELOG.md`, added to the shipped rule kills 2 cases, and one failure reads
  `the exemption reaches these documents outside the two records: ['docs/CHANGELOG.md']`. A
  blanket item that exempts any file whose name holds the word `changelog` kills 4 cases.
  Each mutation was restored and the 27 cases are green after each restore. **A self-review
  found a third widening and two cases now close it.** The first form of the reader kept the
  first path of an item alone, so the item
  that names the entries of `CHANGELOG.md` and `docs/CHANGELOG.md` reported nothing, and the
  exemption reached a third document. `exempt_records` now returns one record for each path of an
  item. **A case measures the two records, and it measures no other document of this
  repository.** The entries of `CHANGELOG.md` hold 191 sentences past the limit and the
  `## Changelog` table of the specification holds 787, so the exemption does work. Both
  counts include the entry and the row of this round. `.claude/rules/ste.md` holds
  no such sentence, and a case reads that file against the limit it states. **A sweep that
  measured every sentence of every page is separate work, and this ruling orders none.**
  Every other measurement here runs on a document the case writes. **A worker's self-review
  that reaches a Changelog row's
  sentence length now reads the exemption and records nothing.** #393 raised the second such
  finding and this round ends them. No file under `ja4plus/` changes and no fingerprint
  moves.

- **The exemption of the writing standard covers rule 3 as well as rule 1** (#502).
  Round 190. Rule 3 of `.claude/rules/ste.md` reads `One topic per paragraph, six
  sentences at most.` The self-review of #484 found its own Changelog row past that limit,
  and that finding is correct against the letter of the rule. **One row records one round,
  which is one topic**, so the sentence count of a row follows from how much that round
  measured. **The user ruled on 2026-08-10 that the exemption widens to rule 3 for the same
  two records**, the entries of this file and the `## Changelog` table of
  `docs/specs/spec.md`. #457 exempted rule 1 on that same reason and this round repeats it
  for rule 3. **The exemption covers rule 1 and rule 3, and it covers no other rule of the
  standard.** A read of 2026-08-10 reports 178 of the 190 rows of the specification table
  past six sentences, and 113 of the 136 entries of this file past six, so the exemption
  does work. Both counts include the entry and the row of this round. The section of the
  standard is now `## The exemption` rather than `## The one exemption`, and it names the
  rules it covers, the fourteen rules that reach both records, and the two rulings by
  issue. The checklist of the standard gains one item for the paragraph limit.
  **The reader holds the section against the numbered rule list rather than against a
  transcribed count.** `standard_rules` reads the 16 rules of `## The rules`, `exempt_rules`
  and `rules_that_reach_the_records` read the two placement sentences, and `rule_failures`
  reports five states: a rule set below the floor of 16, a covered set that is not rule 1
  and rule 3, a rule the section places on both sides, a rule the section places nowhere,
  and a rule the section names that the standard states nowhere. **A rule this project adds
  later therefore needs a reading before it ships.** `uncovered_failures` measures the
  exempt region of each record under every rule the exemption drops, so a record that
  breaks an uncovered rule fails a case. `paragraphs` and `record_units` read one entry and
  one table row as one paragraph. **A list is not a paragraph**, so the paragraph reader
  parts one item from the next, and a reader that joined them would report the 16 rules of
  the standard as one paragraph of 16 sentences. **The cases came first.** The 51 cases of
  `tests/test_changelog_sentence_exemption.py` failed 17 against the writing standard of
  the base commit, among them
  `test_the_exemption_covers_rule_one_and_rule_three`, which read
  `the ruling exempts the rules [1, 3], and the exemption covers []`. **Five mutations of
  the shipped standard prove that the cases bite in the failing direction**, and each one
  runs inside a case rather than against the working tree: an exemption that drops rule 3
  reports every long entry and every long row, an exemption that drops rule 1 reports every
  long sentence, an exemption that names rule 2 on both sides fails the placement, and an
  exemption that places rule 2 on neither side fails it too. `mutated_rule` refuses a mutation that matches no
  span, because a mutation that matches nothing proves nothing. **An aggregate over an empty
  set passes**, so the rule floor of 16 and the document floor of 40 each carry a case that
  feeds the reader nothing. **No other prose loses rule 3**: the standard itself, and a page
  outside the two records, each hold the paragraph limit under a case. **No file under
  `ja4plus/` changes and no fingerprint moves.** The unit suite reports 3974 passed, 4
  skipped and 8 xfailed, and the conformance suite reports 1532 passed, 143 skipped and 134
  xfailed, which are the three counts the base commit reports. **Coverage holds at 94%**
  with 4292 statements and 273 misses, which are the counts the base commit reports.
  `ruff check`, `ruff format --check` and `mypy --strict ja4plus/` each report no issue.

- **A member pull request reaches the round-entry check, and the runner reads its change
  set** (#438). Round 193. **The finding that outranks the rest of this round is that the
  check passed by construction.** The base-branch filter of `.github/workflows/test.yml`
  read `branches: [master, dev]`, and that filter matches the base branch of a pull request,
  so the only pull requests that reached the `test` job were the batch pull request and the
  promotion. A batch pull request reads its change set against the tip of `dev`, and every
  member of a batch has already recorded a round, so the check found an entry whatever one
  member did. **The member pull request is the change set the check exists to refuse, and
  the filter kept it away from the job.** The user ruled on 2026-08-10 that the filter
  widens, and it now reads `branches: [master, dev, "batch/**", "epic/**"]`. **The widened
  filter costs no run that the batch model saved**, because a member commit ends with a skip
  keyword and #459 measured that such a commit creates no run for any event. A keyword-free
  head is the one head that now starts one. `.claude/rules/batch-gate.md` gains the section
  `## Which pull request creates a run`, which states the two conditions that each stop a
  run, and it states this shape so that a reader holds the next check against it. #429 built
  `tests/test_round_entry_existence.py`, which fails a change set that edits a tracked file
  and records no round. **That case also skipped on every job of
  `.github/workflows/test.yml`, so it guarded the local gate of a worker and it guarded no
  pull request.** The
  `actions/checkout` step of that workflow names no `fetch-depth`, so it makes a clone of
  depth 1. That clone carries no `origin/dev` ref and no history behind the checked-out
  commit, and `git merge-base` fails on it. **The `test` job now fetches the base commit of
  the pull request at depth 1 and writes it into the `ROUND_ENTRY_REFERENCE` environment
  variable.** `environment_reference` reads that variable, `named_commit` resolves it
  against the repository, and `reference_commit` prefers it over the merge base. A name the
  repository cannot read reads as no name, so a stale value leaves the local gate of a
  worker exactly as it is. **`git diff` and `git show` read a commit that no history
  connects to `HEAD`, and `git merge-base` does not.** A diff compares two trees, so one
  extra commit is the whole requirement. A read of 2026-08-10 against a clone of depth 1
  reports that the diff and the show each answered and that `git merge-base` exited 1.
  **The measured cost decided the reading.** A clone of depth 1 holds 14844 KB, the extra
  fetch of one commit raises it to 15452 KB, and `fetch-depth: 0` raises it to 18728 KB, so
  this step costs 608 KB against 3884 KB on each of the six jobs of the matrix. The
  `fetch-depth: 0` cost also rises with every commit the project makes, and the cost of one
  commit does not. **#438 declined a second fetch of `dev` at depth 1 on a measurement**,
  because two shallow histories share no commit and `git merge-base` fails between them, so
  the case would skip exactly as before. **The base commit is a stricter reference than the
  merge base with `dev`**, because it reads the change set of one pull request rather than
  the change set of a whole integration branch. A push event carries no base commit, so the
  case skips there, and a push to the integration branch has no change set to read. **The
  fetch writes the ref `refs/ja4plus/round-entry-base`, because a commit that no ref reaches
  is unreachable.** A bare `git fetch origin <sha>` writes `FETCH_HEAD` and no ref, and a
  read of 2026-08-10 on a clone of depth 1 reports that the ref form survives
  `git gc --prune=now` and that `git diff` and `git show` still read the commit after it.
  **The self-review raised `continue-on-error` on the fetch step and #438 declined it**,
  because a failed fetch leaves the variable empty, the case skips, and a green job over a
  silent skip is the failure this round exists to remove. **The expression reaches the
  `env` block and never the `run` block**, because an expression inside a shell command is
  a script-injection path. **Twelve
  new cases hold the reading, and two of them hold the widened filter and the section of
  the rule file.** The self-review also found that `named_commit` rested on
  its one caller to drop the space around a name, and the reader now drops it itself. Two
  of the ten build an orphan branch, which reproduces the
  runner state where `git merge-base` reports nothing and the diff still answers, and two
  read `.github/workflows/test.yml` for the fetch step. **The cases came first**, and
  `test_the_test_job_fetches_the_base_commit_of_a_pull_request` failed against the workflow
  of the base commit with
  `AssertionError: assert 'BASE_SHA: ${{ github.event.pull_request.base.sha }}' in 'name: Tests\n\n# ...'`.
  **The runner read the check in both directions, on one pull request that landed in no
  branch.** The user approved one deliberately red pull request for this proof and no other
  issue of this project may open one. #520 targeted `batch/510-dry-run-and-gates`, it
  targeted neither `dev` nor `master`, and each of its two heads carried no skip keyword.
  **A green run alone proves nothing here**, because the case skipped before this round and
  a skip is not a pass. Head `8702322` edited three tracked files and recorded no round, and
  run https://github.com/Crank-Git/ja4plus/actions/runs/31402557575 concluded `failure` with
  `tests/test_round_entry_existence.py::test_the_change_set_of_this_branch_records_a_round`
  reported as `FAILED` rather than `SKIPPED`. The assertion read
  `the change set holds these paths outside the two records: .claude/rules/batch-gate.md, .github/workflows/test.yml, tests/test_round_entry_existence.py. CHANGELOG.md holds 105 round entries against 105 at the reference commit`.
  Head `ecd1677` added the entry and the row and changed nothing else, and run
  https://github.com/Crank-Git/ja4plus/actions/runs/31403217183 concluded `success` with the
  same case reported as `PASSED` on all six jobs of the matrix. #520 is closed and its
  branch is deleted. **GitHub read the widened filter from the merge commit of that pull
  request and not from the base branch, and the run itself is that measurement.**
  `batch/510-dry-run-and-gates` carries the old filter, and the run started anyway, so a
  filter change takes effect inside the pull request that carries it. The documentation
  states the same thing of `pull_request_target`: `This event runs in the context of the
  default branch of the base repository, rather than in the context of the merge commit, as
  the pull_request event does.` **#519 measured the older filter before the ruling**, with a
  keyword-free head into the same integration branch, and the provider held no run for it
  after 150 seconds. No file under `ja4plus/` changes and no fingerprint moves.

- **JA4TS reaches a FoxIO reference value** (#515). Round
  TBD. The conformance audit of 2026-08-10 read JA4TS as the one method of twelve that
  reached no FoxIO-produced expected output. It stood on transcribed prose of a file FoxIO
  deleted, plus a capture this project writes itself, and a self-generated capture proves
  the implementation against itself. **The finding that outranks the rest of this round is
  that this project recorded a wrong measurement, and that record is what hid the
  reference.** The table `The search for a reference value` in `docs/specs/foxio/JA4T.md`
  read `No ja4t value and no ja4ts value` for `wireshark/test/testdata/`. **That directory
  holds 118 `ja4.ja4t` values and 58 `ja4.ja4ts` values, in 24 of its 37 files.** The
  earlier search read the key `ja4t`, and the FoxIO Wireshark dissector writes the key
  `ja4.ja4t`, so the search matched nothing and the reader wrote a negative result.
  `## The search for a JA4TS reference value` in `docs/specs/spec.md` records every source
  this round read and what each one returned, so no later reader repeats the search.
  **`tests/foxio_vectors/wireshark_expected/` rises from 2 files to 26**, and new file
  `tests/test_foxio_wireshark_ja4ts.py` compares all 58 values. **52 match byte for byte
  and 6 reach the register.** The dissector names a frame rather than a stream, so the
  reader takes the frame out of the capture, reads the address pair and the port pair of
  that packet, and counts the occurrence in frame order. **A tunneled capture needs the
  `ja4plus` import before the read**, because `ja4plus` loads the scapy contrib layers that
  dissect ERSPAN, VXLAN and Geneve. A read of 2026-08-10 reports `gre-erspan-vxlan.pcap`
  frame 2 as `Ether / IP / GRE / Raw` without that import and as a chain that ends in `TCP`
  with it. **All 6 registered values are the RST decline that R13 of
  `docs/specs/foxio/JA4T.md` already records**, and #246 owns each one. The dissector writes
  a second JA4TS value on a RST packet of a connection with no delay, that value repeats
  the value the SYN-ACK produced, and `.claude/rules/conformance.md` declines a value that
  describes no packet of its own. **The decline stays proven rather than asserted.**
  `TestTheDifferencesAreTheRecordedResetDecline` reads the TCP flags of each of the six
  frames as `R`, reads each value against the value of the first SYN-ACK of that stream,
  and reads the `ja4plus` value count of the stream. **New directory
  `tests/foxio_vectors/zeek_expected/` holds all seven Zeek baselines**, which
  `docs/specs/foxio/zeek.md` asked a later issue to commit. New file
  `tests/test_foxio_zeek_ja4ts.py` compares 9 of their 10 JA4TS values, and `ja4plus`
  produces all nine. **The tenth is barred and the bar is measured.**
  `zeek/ja4t/main.zeek:66-68` returns an empty option record when the link layer is not
  Ethernet, the link type of `ipv6.pcapng` is `DLT_NULL`, and the Zeek baseline writes
  `65535_00_00_00` where `ja4plus` writes `65535_2-1-1-4-1-3_1346_10`. **The FoxIO
  Wireshark dissector writes the `ja4plus` value for that same connection**, so a second
  FoxIO implementation corroborates the bar and it rests on no reading of this project.
  **`tests/compare_zeek_baselines.py` ran by hand until this round and no gate read it**,
  because it needed a `FoxIO-LLC/ja4` checkout that a worktree holds none of. It now reads
  the committed baselines when it gets no path, and `TestTheCommittedBaselinesRunAsAGate`
  states the counts of the whole comparison. **The run against the committed copy reads 98
  rows, 63 matches and 35 differences, which are the three counts the run of #327 measured
  against a checkout**, so the committed copy reproduces the reference.
  `tests/conformance_index.py` gains the JA4TS fingerprinter, and `REPORTED_METHODS` in
  `tests/test_spec_validation.py` names neither JA4T nor JA4TS, so the addition adds no case
  there. **The cases came first**, and the ten comparison cases of
  `tests/test_foxio_zeek_ja4ts.py` failed against the base index with
  `assert () == ('65535_2-1-1-4-1-3_1346_10',)`. **One mutation of
  `ja4plus/fingerprinters/ja4ts.py` proves that the comparison bites, and the mutation was
  restored.** `return prefix + "x" + _part_e(packet, tracker, prefix)` in place of
  `return prefix + _part_e(packet, tracker, prefix)` moves every JA4TS value and no value
  of another method. It kills 62 cases: the 52 Wireshark comparisons, the 9 Zeek
  comparisons and the one case that reads the `ja4plus` value of the barred row. The six
  registered cases stay `xfailed` under it, which is correct, because a mutation moves no
  declined value onto the dissector value. **The self-review found one gap and it belongs
  to the FoxIO material.** A second mutation, of the delay-list separator from `"-".join`
  to `",".join`, killed no case of either new module, because no value of either source
  carries more than one delay. No capture of the vector set holds a connection the server
  answered three times, so `tests/test_ja4ts_part_e.py` keeps the constructed cases that
  measure the separator, the rounding rule and both bounds.
  `docs/specs/foxio/JA4T.md` records the reading as a warning. `tests/download_test_vectors.py` fetches
  and validates both new file sets and it rewrites `tests/foxio_vectors/NOTICE` with them,
  so a refresh at a newer commit carries them. A baseline that names no column and a
  baseline that holds no data row each fail the refresh. **No file under `ja4plus/` changes
  and no fingerprint moves.** `tests/foxio_deviations.json` rises from 134 keys to 140 and
  the conformance suite rises from 134 `xfailed` to 140, so the register invariant holds on
  both sides. The conformance suite reports 1635 passed where it reported 1532, and 143
  skipped on both.

- **The prose names the statistics thread by its controlled term** (#441). Round 183. The
  `## Terms` table of `docs/specs/spec.md` rejects the word `reporter` for the statistics
  thread, and the prose of the package used `the reporter` throughout. The self-review of
  #371 found the disagreement and declined the repair, because a repair inside that diff
  would have stood `the reporter` and `the statistics thread` in adjacent sentences of one
  paragraph. **The user ruled on 2026-08-10 that the prose changes and every identifier
  holds its name.** `.claude/rules/ste.md` exempts an identifier from the standard, so
  `StatisticsReporter`, `report_statistics` and `TheReporterWritesOneLinePerInterval` keep
  their names. **A rename of a published name is a breaking change this ruling does not
  make**, and the two published names reach a caller. **A dated record of a past
  measurement is quoted, not rewritten.** The Changelog rows of #55, #369 and #371 each
  name the rejected word, this round read all three, and it leaves all three exactly as
  they read. **The case is worth more than the edit, so the case came first.** New file
  `tests/test_statistics_thread_term.py` holds 283 cases at this commit. `rejected_words` reads the
  fourth column of the `## Terms` row, so a change to the row changes what every case
  forbids, and a case fails where the row stops rejecting the word. Two parametrized cases
  read the Markdown corpus of `git ls-files '*.md'` and the Python corpus of
  `git ls-files 'ja4plus/*.py' 'tests/*.py'`. The Markdown corpus holds
  `docs/specs/spec.html` beside the Markdown pages, because a writer edits that page by
  hand. `python_prose` of
  `tests/test_documented_method_count.py` extracts the comments and the docstrings of a
  Python file, so no line of code reaches a case. **The reader reads a whole word alone**,
  so no part of a compound identifier reaches a case, and six exempt identifiers hold that
  boundary. **It drops every fenced block and every code span first**, because the
  standard reproduces an identifier verbatim. **The reader drops a code span one line at a
  time**, because a search over a whole page pairs a backtick of one line with a backtick
  far below it. **An aggregate over an empty set passes**, so each corpus carries a floor
  and a case proves the floor fails a corpus of no file. `readable_prose` cuts
  `CHANGELOG.md`, the `## Changelog` table of the specification and the `## Terms`
  section, which is the authority the cases read. **The cases bite**: against the
  unrepaired prose they failed 3 cases and named `docs/api_reference.md`,
  `ja4plus/watch.py` and `tests/test_watch_statistics.py`. **This round read each paragraph
  whole after the change, and not line by line**, which is the defect rule 7 names. The repair
  removes 24 prose occurrences of the rejected word, across the docstrings of
  `ja4plus/watch.py`, one table cell and one paragraph of `docs/api_reference.md`, and the
  docstrings and the comments of `tests/test_watch_statistics.py`. Seventeen of them now
  read `the statistics thread`. The other seven read `the thread` or a pronoun, where the
  full term would repeat inside one sentence. One message of an assertion reads the term
  too. **A string literal that is no docstring reaches no case**, so that message is a
  hole this module records rather than closes. **The row rejects `timer` and `ticker`
  beside `reporter`, and no case forbids either one.** Two feature pages state that
  eviction runs on packet arrival and on no timer, each sentence names a general mechanism
  rather than the statistics thread, and the ruling names `reporter` alone. No file under
  `ja4plus/fingerprinters/` changes and no fingerprint moves.

- **The package prose counts fingerprinters where it counted methods** (#484).
  Round 184. Eight comments and docstrings under `ja4plus/` stated the count of
  fingerprinter classes as a count of methods. **FoxIO publishes twelve methods and this
  project implements eleven.** `JA4LFingerprinter` writes `JA4L-C=` and `JA4L-S=`, so ten
  fingerprinter classes carry eleven methods, and a count of classes read as a count of
  methods reads one short. #387 records the measurement and #450 built the reader.
  **This round re-measured the eight places rather than trusting the list.**
  `python_prose` and `class_counts_of_methods` of
  `tests/test_documented_method_count.py` report `ja4plus/__init__.py:113`,
  `ja4plus/cli.py:160`, `ja4plus/fingerprinters/base.py:76` and
  `ja4plus/processor.py:124`, `:264`, `:283`, `:295` and `:332`. Every line number of
  the issue holds. **The corpus came first, and it made the failure real.**
  `python_sources` read `tests/` alone, so no case reached the package. It now reads
  `ja4plus/` beside `tests/`, and
  `test_no_python_file_states_the_count_of_classes_as_a_count_of_methods` then failed
  4 of 4 new cases, one for each file, with
  `AssertionError: ja4plus/processor.py holds ['ten methods'], and ten counts the fingerprinter classes rather than the methods they carry`.
  **The suite alone meets `PYTHON_SOURCE_FLOOR`, so the package carries its own floor.**
  A read of 2026-08-10 counts 203 files in the corpus, 31 under `ja4plus/` and 172 under
  `tests/`, against a floor of 120. A corpus that dropped the package would meet that
  floor and read no package file. `PACKAGE_SOURCE_FLOOR` reads 25 and
  `test_the_python_corpus_holds_the_package` holds it. That case fails on the
  un-widened reader with
  `AssertionError: the corpus holds 0 package files, below the floor of 25, so a case over it proves little`.
  **`ProcessorStats.method` keeps its name, its docstring and every value it holds.** It
  is a published output field, a rename of one is a breaking change, and #450 records
  that the decision is the user's. **The Terms table decides each word.** `method name`
  names the lowercase token, `fingerprinter` names the class, and the report of
  `Processor.stats` holds one entry for each of the ten fingerprinters. **This round read
  each paragraph whole after the change, and not line by line**, which is the defect rule
  7 of `.claude/rules/ste.md` names and which raised #441. The `Processor.stats`
  docstring therefore reads `fingerprinter` in all four of its paragraphs, where two of
  them had rotated between `fingerprinter` and `method` for one thing. **The diff under
  `ja4plus/` touches comment and docstring lines alone.** No statement changes, no
  fingerprint moves, and the conformance counts hold.

- **One pass at the batch gate assigns every round number of a batch** (#482). Round 175.
  The project manager assigned a round number at each sub-merge. A sub-merge is an event of
  one batch, and the round sequence is global to the repository. One live integration branch
  hides that, because it is then the only writer. **Two live branches make the assignment a
  race**, and the project manager measured it on 2026-08-10 at the sub-merge gate of #456:
  `batch/470-sweep-tools-and-shard-bug` held 171 rows and assigned 168 to 171, while
  `batch/476-count-repairs` started from a `dev` of 167 rows and reported
  `the Changelog holds 169 rows and its highest round is 173`. **Neither member was at
  fault and the merged state of each member was correct.**
  `.claude/rules/batch-gate.md` now states where the assignment happens. One pass on the
  integration branch assigns it, immediately before the batch pull request, when the row
  count of `dev` is fixed. A member writes the literal `TBD` in both records and keeps it
  through every sub-merge. **One integration branch at a time also removes the race, and
  this project declines that order**, because it costs the concurrency the batch model
  exists to provide. **The rule alone leaves a shape that no case could read.**
  `row count == highest round` passes on a table that carries 168 twice and 170 nowhere.
  The count and the maximum both still read right under the wrong pairing.
  `tests/test_specification_changelog.py` gains
  `test_the_changelog_assigns_every_round_from_one_to_the_row_count`, which requires the
  rounds 1 to the row count, each on one row. **The shipped page proves the measurement,
  and a case keeps it.** A copy of `docs/specs/spec.md` whose round 170 reads 168
  failed the new case with
  `these round numbers open more than one row: [168]` and `these rounds from 1 to 171 open no row: [170]`,
  and `test_the_changelog_row_count_equals_the_highest_round_number` passed on that same
  page. `test_the_row_count_rule_passes_on_a_table_that_repeats_a_round` holds that
  measurement so that no later reader takes the older rule for a complete one.
  **A gap alone raises the maximum above the count**, so the older rule reads a pure gap.
  The shape that hides from the older rule carries a repeat beside the gap.
  **An aggregate over an empty list passes**, so the reader reports a table from which it
  read no numbered row. `MINIMUM_ROWS` holds the second floor at 124. Five more cases drive
  the reader over five fixed tables. One table repeats a round and one holds a gap. One
  assigns each round once, and one names no numbered row at all. One carries four numbered
  rows and two rows that read `TBD`, which an integration branch always carries and which
  stays legal.
  No file under `ja4plus/` changes and no fingerprint moves.

- **The batch-gate rule states the branch protection the provider now holds** (#480).
  Round 174. #459 wrote the protection section of `.claude/rules/batch-gate.md` from a read
  of 2026-08-09, which returned `404`, `Branch not protected`. #468 turned the rule on, so a
  reader who followed that wording concluded that nothing at the provider refuses an ungated
  merge. **This round re-took the measurement rather than quoting the issue body.** A read of
  2026-08-10 returns `200` with eleven required contexts, each carrying `app_id` 15368, and
  `gh api repos/Crank-Git/ja4plus/rulesets` returns `[]`. The eleven names match the eleven
  the file already listed, so no name moved, and no context reads `build` or the bare `test`.
  The reading agrees with the issue body on every field. **The section is renamed to
  `The provider refuses an ungated merge`**, because the earlier heading named a shape the
  repository did not hold. **A dated record of a past measurement is quoted and not
  rewritten**, so the 2026-08-09 sentence stays in the file as a quotation under a paragraph
  that marks it superseded, beside a table that holds both dates. **The same call returned
  two limits and the file states each one.** `enforce_admins` reads `false`, so the rule
  binds a contributor and binds no repository administrator, and an administrator merges past
  the eleven contexts with no run at all. `strict` reads `false`, so a branch merges where it
  is behind `dev`, and that reading suits the batch model: `strict: true` would demand that
  every integration branch take `dev` again after another batch lands, and the run that
  proved the batch would then not be a run of the head. `python -m tests.batch_gate --pr
  <number>` stays in the procedure, because it reads the same condition before the merge
  rather than at it. **A case reads the claim against the provider, because prose carries no
  other gate.** New file `tests/test_batch_gate_protection_rule.py` holds 93 cases.
  `protection_reading` runs `gh api repos/Crank-Git/ja4plus/branches/dev/protection`, and it
  returns nothing where the host holds no `gh`, where the command exits non-zero, or where
  the body is no JSON object. **Where the call cannot be made a live case skips, and it does
  not pass**, which `test_the_live_context_case_skips_where_the_provider_returns_no_reading`
  proves by driving the live case with a refused call and requiring the skip. **Every live
  case reads its floor before it reads the provider**, so a file that lists no context fails
  rather than comparing two empty sets. **The sweep reads a shape and no phrase.**
  `superseded_claims` pairs the term `required status check` with a negation over six
  spellings, and `readable_text` cuts a quotation, a paragraph that marks itself superseded,
  and the `## Changelog` section that quotes round 165. **An aggregate over an empty set
  passes**, so a case requires the file set to name both `.claude/rules/batch-gate.md` and
  `CLAUDE.md`. **The cases were written first and they bite**: against the unrepaired file
  they failed 18 of 59, and the sweep named exactly one document. **Two defects of the
  section reader were found by that first run and each is closed.** The reader ended a
  section at the next heading of any level, so a `###` subsection cut the list of check names
  out of the body. It then read `#468 turned the rule on` as a first-level heading and
  returned one paragraph, because a heading needs a space after its `#` characters and an
  issue reference does not. Three cases now hold the reader in both directions. **A
  self-review drove the sweep with fifteen candidate sentences and eight reached no match**,
  among them `The repository lacks a required status check.`, ``The branch `dev` is
  unprotected.`` and `Nothing at the provider refuses an ungated merge.` The pattern now
  reads three shapes: a check term paired with a negation, a sentence that states the
  provider refuses nothing, and a sentence that calls the branch unprotected. Nine evasions
  and four controls became cases, and the four controls are true sentences of the repaired
  file that the widened pattern reports nowhere. Against the unrepaired file the sweep now
  reports two statements where it reported one. **Two
  mutations prove the live cases discriminate.** Adding `build` to the listed names and
  writing `` `strict` reads `true` `` killed five cases, among them both provider cases, and
  deleting the superseded record killed two. Each mutation was restored. **No sentence of
  `CLAUDE.md` rested on the superseded reading**, which the sweep measures rather than
  asserts. No file under `ja4plus/` changes and no fingerprint moves.

- **Every statement of the vector-fallback rule names the reader the rule needs** (#477).
  Round 172. Round 49 corrected the rule on 2026-08-08: the fallback needs an image that a
  person read and found ambiguous, and an image nobody read is not a license to use it.
  `.claude/rules/external-apis.md` and `.claude/rules/conformance.md` carried the correction
  and three pages kept the superseded premise, which gives the decision to the
  expected-output files and names no reader. **The issue reported one occurrence and the
  sweep measured three.** `docs/specs/spec.html` held one in its `Open, but not blocking`
  card, 118 lines below the corrected form in its own `01 — Spec conformance` card, so the
  page contradicted itself. `docs/specs/features/01-spec-conformance.md` held one in its
  `Behaviour rules` list, and `docs/implementation_notes.md` held one in the paragraph that
  states why the file exists. All three now state the form
  `.claude/rules/external-apis.md` states. **The issue also stated two line numbers that a
  re-measurement disproved.** It named `docs/specs/spec.html:444` and `:316`, and the base
  commit `17858bf` carries the two statements at `:436` and `:317`. **The case reads a shape
  and no phrase**, because #211 and #449 each proved that one forbidden phrase guards one
  spelling. New file `tests/test_documentation_fallback_rule.py` holds 48 cases.
  `fallback_statements` matches a condition about an image that settles no question, bound
  to a sentence that gives the decision to the expected-output files, in four word orders.
  It then reports whether a reader premise stands inside a window of 600 characters before
  the statement and 200 after it. **A rewording that drops the reader therefore fails, and
  the words it chooses do not matter.** Twenty-two spellings of the superseded rule reach
  the reader, six spellings of the corrected rule pass it, and ten control sentences that
  name the fallback for one transcription rule reach no case. **An aggregate over an empty set
  passes**, so six pages are named and each one holds a statement the reader finds. **A
  dated record of a past measurement is quoted and not rewritten.** Round 49 of the
  Changelog table of `docs/specs/spec.md` records the superseded wording word for word, and
  the row of this round quotes the sentence this round corrects. `readable_text` cuts that
  section, and one case reads the cut in both directions. **A self-review drove the reader with
  sentences it had not seen.** It found seven evasions and two false reports. The evasions
  were the conjunctions `because`, `since`, `given that` and `unless`, a semicolon, the
  word `means`, and a passive sentence, so the pattern now needs no conjunction at all and
  it reads `decided by the expected-output files`. The false reports were a rendering
  fallback of an image and a sentence about a slide deck, so `REQUIREMENT_FORM` names the
  vector fallback and `AMBIGUOUS_IMAGE_FIRST` needs a verb of decision after a bare
  `vector`. Six evasions and two controls became cases. **The cases were written first and
  they bite**: against the unrepaired corpus they failed 2 of 48, and the failure named all
  three pages. No file under `ja4plus/` changes and no fingerprint moves.

- **The document set of the count cases reads the tracked file list** (#473). Round 173.
  `tests/test_documented_method_count.py` built `DOCUMENTS` from a walk of `docs/`,
  `.claude/`, `tests/` and the repository root. **The agent harness places a worker worktree
  at `.claude/worktrees/agent-<id>`, and that worktree is a whole checkout**, so the walk of
  `.claude/` read every document of every live worker. The reading counted the host and not
  the commit. **The cases passed on such a checkout, because a worktree holds a valid copy
  that agrees with the rule.** That is the shape this project records more than eighteen
  times: a comparison whose result does not depend on the thing under test. A measurement of
  2026-08-10 inside a worker worktree reports 153 collected cases with no worktree page
  present and 156 with one page of one worktree present, and two of the three extra cases
  failed on that page.
  **`documents()` now reads `git ls-files -z '*.md'`.** That list names the tracked pages
  alone, and it names no worktree copy, no ignored file and no build output.
  `tests/mutation_sweep.py` already carried this correction for its module list. **In a
  default git pathspec `*` crosses `/`**, so the one term reaches every depth and its plain
  reading equals what it matches. `FR-pre-release-validation-16` and
  `.claude/rules/conformance.md` state the rule that #436 repaired. A read of 2026-08-10
  reports three counts: `git ls-files '*.md'` lists 59 files, `git ls-files '**/*.md'` lists
  56, and `git ls-files ':(glob)*.md'` lists 3. **The tracked list and the walk name the same
  59 pages on a clean checkout**, so the runner reads the set it read before.
  **The repair is proven in both directions.**
  `test_the_reader_names_no_markdown_page_of_a_worktree` writes one page below
  `.claude/worktrees/`, and it removes the directory it created and no other. It fails
  against the walk with
  `AssertionError: .claude/worktrees/issue-473-qnt_uybr/docs/copy.md reaches a parametrized case`.
  Nine anchor cases name one page of each depth and one page of each root, and
  `test_the_anchor_set_fails_a_reader_that_names_one_depth_of_one_directory` proves the
  anchor set fails a reader that drops a root. **A floor fails the reader that names no
  document**, because an aggregate over an empty set passes. The collected count of the file
  reads 166 with a worktree page present and 166 with none. New `FR-documentation-16` and
  its four parts state the rule. No file under `ja4plus/` changes and no fingerprint moves.
- **A mutation of a module body keeps a reader in the cover rule** (#433). Round 169. Step 2
  of the cover procedure in `.claude/rules/conformance.md` subtracts the lines the import
  runs. Every mutation of a module body then lost the case that reads it, and the cost rule
  held the cheapest test file. #414 measured the outcome on `ja4plus/__init__.py`: the cover the cost
  rule builds is `tests/test_parity.py`, that sweep reads 1 killed and 31 survived, and all
  25 entries of `__all__` survive it.
  **The defect follows from the subtraction of step 2 and not from the cost measurement**,
  because that subtraction removes the whole line class at once. New step 4 names a reader by the value
  rather than by the cost. New file `tests/mutation_cover.py` reads the names a module body
  binds and the identifier strings those statements build, and it names the test file whose
  own source holds the most of those tokens. The module body of `ja4plus/__init__.py` holds
  28 tokens, and the tool names `tests/test_public_interface.py` at 26 of them against 15 for
  the next file. **The cost is a run and not an estimate.** At commit `00a0c42`, over all 32
  mutations of that module, the repaired cover reads 26 killed and 6 survived in 48.0
  seconds, against 1 killed and 31 survived, and it leaves no survivor on the 25 entries of
  `__all__`. One sweep of the reader alone costs 39.9 seconds. **The rule states a fourth
  limit.** The reader kills a mutation of the value it reads and no other mutation of the
  module body, so `__version__`, `__author__` and `__license__` survive it and the record
  says so. **Two cases prove the prose prover in the failing direction.** The rule text with
  every line naming `tests/mutation_cover.py` removed fails the reader case. The rule text
  with every line naming a second count removed fails the cost case. A reworded step
  passes both, so a rewording defeats neither. **A floor case reads the ranked list**, because
  an aggregate over an empty set passes, and two more cases read a module body that binds
  nothing and a module body that no test file reads.
  `docs/mutation_settlements/414-interface.json` keeps the numbers #414 measured, because
  that record states the sweeps that ran. No file under `ja4plus/` changes, no file under
  `tests/foxio_vectors/` changes, and no fingerprint moves.
- **The image count of `docs/specs/spec.html` states the count the FoxIO inventory measures**
  (#449). Round 176. The page held two image counts. Line 316 read `Eleven of the twelve
  FoxIO methods carry no complete text specification`. Line 436 read `Seven of twelve FoxIO
  methods are specified only as images`, 120 lines below it. **A case existed to forbid the
  second sentence, and a missing article defeated it.**
  `tests/test_documentation_image_count.py` held the fixed phrase `seven of the twelve` and
  searched each line for it. The page writes `Seven of twelve`, so it carried the superseded
  count for 97 rounds while the case passed. **This round re-measured `technical_details/` at
  the pinned commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` rather than quoting round
  70.** The directory holds twelve files: three text files of 1567, 9153 and 278 bytes, and
  nine images. The upstream `README.md` lists twelve methods and embeds nine image links.
  Every byte count reproduces `docs/specs/foxio/README.md`, so eleven is the measured count.
  **The case now reads a shape and no phrase.** `image_count_claims` matches a count that
  binds to the word `method`, followed by a claim about an image or about a complete text
  specification. It reads the whole page with the line breaks removed, so a claim that a
  line break splits reaches it. **The number comes out of the inventory.**
  `measured_image_count` is the method count less the count of complete text
  specifications, and it reads both halves out of `docs/specs/foxio/README.md`. A case that
  restated eleven would pass on the day the inventory moves. **Sixteen spellings of the
  superseded count reach the reader, and each one is a case.** They include `Seven of
  twelve`, `seven of the twelve`, `7 of 12`, `Seven FoxIO methods`, `publishes seven methods
  as images`, `the count of FoxIO methods specified only as images is seven` and
  `image-only`. **Eight control sentences reach no wrong count.** They include the `7 of the
  12 moved values` of `docs/specs/foxio/JA4T.md`, the seven deleted text files of
  `docs/specs/foxio/README.md` and `All but one FoxIO method is specified only as an image`.
  The reader therefore matches a claim and not a page. **A self-review drove the first form
  of the reader with more than 40 candidate sentences.** It found fourteen evasions and one
  false positive. Six evasions became spellings of the case set, and the false positive
  became the two complement controls. **The module docstring records the six holes that
  stay**, among them a synonym of `method` and a claim further than 40 characters from the
  noun. **A dated record of a past measurement is quoted and not rewritten.** Round
  162 of the Changelog table of `docs/specs/spec.md` quotes the defective sentence word for
  word. `readable_text` cuts that section, and
  `test_the_reader_reads_the_quoted_count_of_a_changelog_round_and_a_case_does_not` reads
  the cut in both directions. **The cases were written first and they bite**: against the
  unrepaired page they failed 2 of 47. Five more cases hold the inventory against itself, so
  a table that loses a row fails before any page does. **One premise of the issue body is
  false and the measurement disproves it.** The body states that the two counts sit 60 lines
  apart, and its own table names lines 314 and 434. No file under `ja4plus/` changes and no
  fingerprint moves.

- **A case measures the count an acceptance criterion states** (#456). Round 177. Two criteria
  of `docs/specs/features/*.md` stated a count this repository contradicts. #393 measured both
  on 2026-08-09. **Both premises of the issue were stale, and this round measured each one
  again.** `git ls-files tests/foxio_vectors | wc -l` reports 90, and
  `docs/specs/features/00-foundation.md` stated 75. The issue reported eight files that hold
  the text `0.6.0`. `git ls-files pyproject.toml ja4plus/` reports seven, and a read of the
  whole repository reports 35. **The criterion of `docs/specs/features/09-release.md` states an
  end state, and it is not a stale count.** Four facts settle it. #67 is open. Its own
  acceptance criterion is the same sentence. `FR-release-1` states that the version appears in
  one place. The page carries criteria that name version 1.0.0, which is unreleased. A page of
  an unbuilt feature states what that feature will hold, so that criterion keeps its count. It
  now states plainly that #67 builds it. **The command of that criterion counts files and not
  declarations, and #67 needs that reading.** Two of the seven files declare the version. Five
  name it in prose that records the released behaviour. The command therefore reads six files
  after #67 removes one declaration. `docs/specs/features/09-release.md` now holds the table of
  all seven, and #67 owns the decision. **New file `tests/test_criterion_counts.py`.** It reads
  each measured criterion from its feature page, takes the count out of that sentence, and
  compares it against a measurement. A built criterion states the measured count. A pending
  criterion states a count this repository does not hold, so a case fails on the day #67 lands.
  **The count comes from the page and never from a copy inside the case.** A reader that held a
  copy passed against the stale 75, and the shipped reader fails against it. **Eight mutations
  prove the six cases discriminate, and each file was restored.**
    - The stale 75 fails the built case alone.
    - A criterion that loses its command fails the locator case and the built case.
    - The end-state marker without `#67` fails the naming case alone.
    - That marker deleted fails the naming case alone.
    - A pending criterion raised to seven fails the end-state case alone.
    - A parser that reads no criterion fails five cases.
    - A measurement that reads no file fails the floor case and the built case.
    - A reader that holds a copy of the sentence fails nothing, which is the counterfactual.

  **A comparison over an empty set passes, so both floors are present.** `MINIMUM_CRITERIA`
  reads 151, and `test_every_measurement_reads_at_least_one_file` requires one file from each
  measurement. The `Terms` table of `docs/specs/spec.md` gains `end state`, `built criterion`
  and `pending criterion`. No file under `ja4plus/` changes and no fingerprint moves.

- **The prose under `tests/` counts fingerprinters where it counted methods** (#450). Round
  178. The word `method` carried two meanings and the two counts differ. FoxIO publishes
  twelve methods and this project implements eleven. The processor drives ten
  fingerprinters, because `JA4LFingerprinter` writes both `JA4L-C=` and `JA4L-S=`.
  **The user chose the prose repair and declined the rename.** `ProcessorStats.method`
  keeps its name, its docstring and every value it holds. It is a published output field,
  so a rename of it is a breaking change and the user owns that decision. **The ten places
  the issue body names are all present, and one line number moved.**
  `tests/test_thread_safety.py:372` reads 373 today. Ten docstrings and comments across six
  files under `tests/` now count fingerprinters. The four docstrings and comments of
  `ja4plus/watch.py` take the same repair, under the ruling the issue thread records.
  **`tests/test_documented_method_count.py` now reads Python source, and it found three
  more places.** `python_prose` extracts every comment with `tokenize` and every docstring
  with `ast`. **A docstring of one line sits inside quotation marks.** `_unquoted` drops the
  whole of it, so a search of the raw source read nothing in it. Three of the ten places
  hold that shape. A case fixture reaches no case, because it is a string literal and no
  docstring. A
  case runs over each of the 166 Python files under `tests/`, and it failed on seven of
  them before the repair. `PYTHON_SOURCE_FLOOR` refuses a corpus that shrank, because an
  aggregate over an empty set passes. The `Terms` table of `docs/specs/spec.md` gains
  `method name`, and the `method` row and the `fingerprinter` row now state the two counts.
  The eight places that remain under `ja4plus/` are #484. **No fingerprint moves and the
  conformance counts do not change.**
- **A case reads every stated state-table count against a live `Processor`** (#453). Round
  179. `docs/specs/features/03-concurrency-safety.md` stated sixteen state tables, 47400
  remembered keys and 8.5 MiB, and `docs/api_reference.md` stated seventeen, 57400 and
  10.2 MiB. **The code holds seventeen**, and this round re-measured it rather than quoting
  either page: `sum(len(report.tables) for report in Processor().stats().values())` reads
  17. **The two other numbers rest on the table count**, so a repair of the count alone
  leaves both wrong. The remembered-key count is the sum of `max_entries` over the same
  tables, which reads 57400. 57400 keys at the 187 bytes #41 measured cost 10.2 MiB.
  **The state-bound table of the feature file lost a row, and that row is the whole
  difference.** #215 added `JA4TFingerprinter.connections` at 10000 entries and 600
  seconds. The table never gained the row. 47400 plus 10000 is 57400. **A count in
  prose that nothing measures goes stale on the day the code moves.** New file
  `tests/test_documented_state_table_count.py` reads the three numbers out of a live
  `Processor`. It compares every Markdown page of the corpus against them, and it reads the
  state-bound table row by row. **Four reversals prove the cases fail.**
  The removed `JA4TFingerprinter.connections` row fails the two table cases with
  `states the bound of 16 state tables, and one processor holds 17`. The superseded
  sentence restored fails three cases, one for each number. The same mutation on
  `docs/api_reference.md` fails two. **Floors refuse a reader that matched nothing**,
  because an aggregate over an empty set passes. Eleven more cases prove the readers take
  each wording and take no count of another thing. **A dated record keeps its
  numbers.** `readable_text` cuts `CHANGELOG.md` and the two recording sections of
  `docs/specs/spec.md`, so round 85 keeps fifteen tables, 46400 keys and 8.3 MiB. The
  #279 reading of 40200 entries across the seventeen state tables stands unchanged. The
  `Terms` table gains `remembered key`, because this repair counts them in three places. No
  file under `ja4plus/` changes, no fingerprint moves, and the conformance counts do not
  change.
- **The fingerprint move count of the migration page states the row count of its own table**
  (#398). Round 167. `docs/migration-0.6-to-1.0.md` stated six twice and its table held seven
  rows. #395 measured the difference and filed the issue rather than repair it. **The count
  lived in prose and no case read it.** #399 added a row to the breaking-change table of the
  same page and #401 corrected a citation of it, and neither edit moved either sentence.
  **The record already stated seven, so the page is the half that is wrong.** This file reads
  "That table holds eight rows. Seven of them move a value a tool may have stored". Round 139
  of the Changelog table of `docs/specs/spec.md` reads "plus seven fingerprints that move".
  Both are dated records of a past measurement, so both keep their text and the repair is in
  the page. **The trailing paragraph adds a value and it moves none.**
  `Processor.close_open_windows` emits every window a connection left open under #214, so a
  capture produces one more JA4SSH value than version 0.6.0 produced. A reader who counts
  that paragraph as a move reaches eight. The page now states the decision rather than leave
  it to the reader. #214 is a row of the fingerprint table of these notes and a paragraph of
  the page, so the two tables differ by exactly that one row. **Three new cases in
  `tests/test_release_notes.py` read each count against the table that carries it.**
  `test_the_migration_page_states_the_count_its_own_fingerprint_table_holds` reads the page
  against its own table and never against a second copy of the sentence. Round 143 records a
  citation case that compared two copies of one claim and passed on the error it exists to
  catch. **The floor bars a reader that finds no sentence**, because a
  comparison over an empty set of sentences passes, and `MINIMUM_MIGRATION_FINGERPRINT_ROWS`
  bars a table that an edit empties. **The self-review found this entry building the second
  copy that round 143 warns about.** The paragraph above quotes the live count sentence of
  these notes verbatim as evidence, the first form of the notes case searched the whole
  version section, and `re.search` takes the first match. The live claim would therefore go
  and the quote would answer for it. `_release_notes_introduction` reads the text above the
  first third-level heading, so the case reads the claim where it lives. **Fourteen mutations
  prove the three cases discriminate, and each was restored.** Either sentence back to six
  fails the count case alone. It reports
  `the migration page states ['Six'] fingerprints that move, and its own table holds 7 rows`.
  The deletion of either sentence, the deletion of both, and a rewording the pattern misses
  each fail the sentence floor. One row removed from the table fails the row floor. Every data
  row removed fails it with
  `the fingerprint table of the migration page holds 0 rows, and the floor is 7`. The decision
  sentence deleted fails the trailing case alone. The count of these notes moved to nine rows,
  moved to six moves, and deleted, each fails the notes case alone. **Two mutations prove the
  scope.** The live claim deleted while the quote above stands fails with
  `the release notes state no row count for their fingerprint table`. The live claim moved to
  nine rows fails with
  `the release notes state 9 rows of moved fingerprints, and their table holds 8 rows`.
  **This branch merged the integration branch at `b0bab60` and at `ab73bd6`**, because #459 and
  #455 landed after the branch left `d4a1305` and each round appends an unassigned row to the
  Changelog table. Each resolution keeps both rows, and the earlier row stands first.
  **The whole gate ran on this host after both merges**: the unit
  suite reports 2865 passed, 4 skipped, 8 xfailed and 114 subtests, coverage holds at 94 with
  273 lines missed of 4232 statements, the conformance suite reports 1532 passed, 143 skipped
  and 134 xfailed against the 134 keys of `tests/foxio_deviations.json`, `mypy --strict` finds
  no issue in 31 source files, and `ruff check` and `ruff format --check` pass. No file under
  `ja4plus/` changes and no fingerprint moves.

- **The FoxIO License 1.1 list of the README names every method it covers** (#388). Round 164.
  The list named JA4S, JA4H, JA4T, JA4TS, JA4L, JA4X and JA4SSH. It named neither JA4LS, nor
  JA4D, nor JA4D6, and this project builds all three under that license. **A published
  statement about another party's license is the user's decision.** #62 therefore measured the
  difference and changed nothing. The user ruled on 2026-08-09 that the list follows FoxIO's
  list. **The premise of the issue is that `License FAQ.md:5` names ten methods, and the
  source names twelve.** Read at the pinned commit
  `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`, that line names JA4S, JA4L, JA4LS, JA4H, JA4X,
  JA4SSH, JA4T, JA4TS, JA4TScan, JA4Scan, JA4D and JA4D6. **Two of those names reach no row of
  this list.** This project builds neither JA4TScan nor JA4Scan. The list therefore holds the
  names the user named, and it is a subset of FoxIO's. **Three FoxIO records at that commit
  disagree with each other.** This round records the three readings and chooses among them for
  nothing. `License FAQ.md:5` names the twelve above. `README.md:293` omits JA4Scan, JA4D and
  JA4D6. `LICENSE:3` spells the scanner `JA4SScan`, beside a `JA4E` that the other two never
  name.
  **The list now cites the document and the commit**, so a reader checks it against the source
  without a second measurement. **The license list is not the implemented set.** This project
  implements eleven methods, and JA4 is one of them. FoxIO publishes JA4 under BSD-3-Clause and
  not under the FoxIO License 1.1. JA4 therefore reaches the method table and reaches no row of
  this list. **The case parses the paragraph and never searches for a name.** `JA4L` is a
  substring of `JA4LS`, so a substring reader reports JA4L on a paragraph that names JA4LS
  alone. **The first form of the reader lost `JA4S` for the opposite reason.** An underscore is
  a word character, so Markdown emphasis hid the name from the word boundary. The reader now
  removes the emphasis characters first. **The case derives the expected set from the
  `Implemented` column of the README method table**, without the BSD-3-Clause method. A name
  that table gains therefore reaches the list or fails the case, and
  `tests/test_documented_method_count.py` holds that table to `ja4plus/`. **No transcription
  under `docs/specs/foxio/` carries the license list.** The transcriptions cover
  `technical_details/`, and `docs/specs/foxio/README.md` bars a copy of FoxIO material into
  this repository. No case here therefore reads the FoxIO document itself. **Both new cases were
  proved in both directions on this host.** The removal of JA4D6 from the list fails the set
  case alone. The deletion of the whole paragraph fails both cases. Each run restored the file
  it moved. No file under `ja4plus/` changes and no fingerprint moves.
- **A batch merge fails where the pull-request event created no run** (#459). Round 165.
  **The failure mode is not a missing run. It is an absent run read as a passed run.**
  `gh pr checks` writes "no checks reported", which refuses no merge, so a reader takes the
  absence for a pass. The batch merged then carries members whose cases never ran on Linux,
  because every member commit carries a skip keyword by design. **The cause is measured, and
  it is not the throttled webhook path the workflow comment named.** A skip keyword anywhere
  in a commit message creates no run for that commit. GitHub reads five keywords, matches the
  subject and the body, and reads no intent. The head commit `2a589ca` of pull request #444
  and the head commit `b593de5` of pull request #458 each held the line
  ``This commit carries no `[skip ci]`, so it is the head that starts the full run``.
  **The sentence that states the absence of the keyword is the keyword.** **The correlation is
  perfect across four heads.** The two heads that hold the keyword created no run, and the two
  control heads `ec697c0e` and `b21604ce` hold none and both created their runs.
  **All four observations of the issue re-measured true, and one premise re-measured false.**
  `gh run list` reports `workflow_dispatch` runs alone on both batch branches, both green, and
  it reports the push runs on `dev` after each merge. The premise that neither head commit
  carries the keyword is false, and that premise is what ruled the documented skip path out.
  **New file `tests/batch_gate.py` holds the condition**, and
  `python -m tests.batch_gate --pr <number>` reads it. The command exits 0 where every
  required workflow holds a terminal successful run at the head commit, and where every other
  run of that commit concluded `success`. It exits 1 on an absent run, on a run that has not
  finished, on any other conclusion, and on a failed read of the provider.
  **`.github/workflows/test.yml` is the one required workflow**, because it accepts every pull
  request into `dev` and it filters no path. `.github/workflows/docs-build.yml` filters four
  paths, so an absent run of it proves nothing, and a red run of it still refuses the merge.
  **New file `tests/test_batch_gate.py` holds 48 cases and every one failed before the module
  existed.** They cover an absent run, a run of another commit, a queued run, a run in
  progress, four terminal conclusions that are not `success`, a `skipped` conclusion, a re-run
  that passed after a failure, a failure after a success, a red run of the unrequired
  workflow, an abbreviated commit identifier, and the head commit message of both measured
  pull requests against both controls. **The empty required set carries a case of its own,
  because an aggregate over an empty set passes.** **The gate names the cause it cannot
  otherwise show.** Where a required run is absent and the head commit message holds a
  keyword, the failure names the keyword and this issue. It names no keyword where a run
  exists and failed, because a red run has a cause in its log.
  **The self-review found three defects in the first form of this gate and each is closed.**
  **The first is the fault this project records most often, and it reached the gate itself.**
  One workflow holds two runs at one commit where a push event and a pull-request event both
  reach it, and two runs can carry one creation time. `max` returns the first of several equal
  keys, so a green run listed before a red one made the gate report a pass. A measurement
  proves it: on the unrepaired reader the order `success, failure` reads `PASSED` and the
  order `failure, success` reads `REFUSED`, on one input. **The verdict rested on the order of
  the response.** The reader now breaks that tie toward a refusal, and it refuses both orders.
  **The second is a check name that names no check.** The rule file listed the six job names
  of `.github/workflows/test.yml` as the required checks. The `test` job runs a matrix, so the
  provider publishes one check for each combination, and a read of commit `b593de5` reports
  `test (ubuntu-latest, 3.9)` and five more. A required check named `test` would have matched
  nothing. The rule now lists the eleven names, and it bars the `build` check of the
  path-filtered workflow, because a required `build` would block every batch that touches
  none of its four paths. `test_the_rule_names_every_job_of_the_required_workflow` reads the
  `jobs:` keys against the rule file. **The third is a reader that tested a region it never
  found.** The two path-filter cases sliced the file on the text `pull_request:`, and a slice
  that landed wrong would have satisfied `paths: not in trigger` on a claim nobody read. The
  reader now takes the `on:` block by indent, and it raises where the region it took holds no
  `branches:` key. Against `.github/workflows/publish.yml` it raises
  `accepts no pull-request event` rather than returning a region.
  **A caller that passed the upper form of a commit identifier read an absent run**, so the
  comparison now folds the case and a fourth new case reads it. **The procedure reaches the
  loop and not an issue alone.** New file `.claude/rules/batch-gate.md` states it, `CLAUDE.md`
  names that file under `## Branch model`, and `.issue-flow.json` replaces the note that read
  "A batch pull request into dev starts a run, so provider continuous integration is the batch
  gate". **The strongest shape needs the user.**
  `gh api repos/Crank-Git/ja4plus/branches/dev/protection` returns `404` with
  `Branch not protected`, and `gh api repos/Crank-Git/ja4plus/rulesets` returns `[]`, so this
  repository holds no required status check. The token carries the `repo` scope and both reads
  returned a determinate answer, so this is a measurement and no stated limit. A change to
  branch protection changes the repository configuration, so the user makes it, and the rule
  file names the four steps and the eleven check names. **Two limits stand.** A run of the branch
  head is no run of the merge result, and this gate reads a run rather than the code. No file
  under `ja4plus/` changes and no fingerprint moves.
- **The built wheel carries the `ja4plus` package alone** (#455). Round 166.
  `docs/specs/features/09-release.md:156` requires the wheel to carry no file under
  `docs/`. `python -m build` on the base commit `d94d8c1` produced a wheel of 96 entries.
  56 of those entries lay under `docs/`. #393 measured that state on 2026-08-09, and this
  round re-measured both counts on its own base and read the same two numbers. **Two
  defaults produced the defect together.** A `pyproject.toml` project reads implicit
  namespaces by default, so `docs` and every directory below it are discovered packages
  although none of them holds an `__init__.py`. `include-package-data` is true by default
  since `setuptools` 61. The file finder of `setuptools-scm` reports every file that git
  tracks. Each tracked file below a discovered package therefore shipped.
  `ja4plus-0.6.0.dist-info/top_level.txt`
  named `assets`, `docs` and `ja4plus`, which is the reading that proves the discovery.
  **The repair adds two entries to the one list that already excludes `tests/` and
  `examples/`**, and it adds no second mechanism beside it. The `exclude` key of
  `[tool.setuptools.packages.find]` now reads
  `["tests", "tests.*", "examples", "docs", "docs.*", "assets", "assets.*"]`. A pattern
  matches one package and no subpackage, so the entry `docs.*` carries `docs.specs` and
  `docs.specs.features`. The repository holds no `MANIFEST.in`. **The project manager
  widened this round to `assets/`, which is the same defect on another tree.** `assets/`
  holds one tracked file, `assets/logo.png` at 2423363 bytes. It holds no `__init__.py`, so
  cause 1 above discovered it, and cause 2 shipped it. `README.md` is its one reader, and a
  logo is no run-time dependency of a fingerprinting library. **`assets` carries the
  wildcard entry although it holds no subdirectory today**, because the requirement is that
  no file of the tree ever ships. `examples` keeps the bare name it already had, and
  `test_the_wheel_carries_no_file_outside_the_package_and_its_metadata` covers it.
  **The wheel falls from 96 entries to 39, and it carries the `ja4plus` package and the
  metadata directory alone.** The reading after the `docs/` repair was 40 entries, so the
  three counts are 96, 40 and 39. The file falls from 3139637 bytes to 2551426 and then to
  152780, which is 5% of the first reading. `top_level.txt` fell from `assets`, `docs` and
  `ja4plus` to `ja4plus` alone. The wheel still carries `ja4plus/data/ja4plus-mapping.csv`
  and `ja4plus/py.typed`. **The source distribution does not change, and that is the
  intended state.** It holds 417 members before the repair and 417 after. 64 of those
  members lie under `docs/`, and `assets/logo.png` is among the rest. The file finder adds
  every tracked file whatever the package list holds. `tests/` and `examples/` prove the
  same split: the list excludes both from the wheel and both ship in the source
  distribution. `FR-release-11b` and `FR-release-11c` name both trees, and `FR-release-11d`
  states the top-level name, because `FR-release-11` named the test suite, the examples and
  the vectors and named neither tree. The `Terms` table gains `documentation tree` and
  `assets tree`. **The tests came first.**
  `test_the_wheel_carries_no_file_under_the_documentation_tree` failed on the unrepaired
  tree with `AssertionError: the wheel carries 56 of its 96 entries under docs/, and it must
  carry none`. The three cases of the widened scope failed with
  `the wheel carries 1 of its 40 entries under assets/`, with
  `the wheel declares the top-level names ['assets', 'ja4plus'], and it must declare
  ['ja4plus']`, and with
  `the wheel carries 1 of its 40 entries outside ja4plus/ and the metadata directory`.
  **Each new case reads the artifact and never the working tree**, because the defect lives
  in what the build includes. **An assertion over an empty entry list passes**, so each
  wheel case holds `ja4plus/__init__.py` against the entry list before it reads the rest.
  `test_the_wheel_carries_the_mapping_file`,
  `test_the_source_distribution_carries_the_documentation_tree` and
  `test_the_source_distribution_carries_the_assets_tree` hold the states a wrong exclusion
  rule would produce. **Two cases hold the whole wheel rather than one named tree, and they
  fail on two different faults.** `test_the_wheel_declares_one_top_level_name` reads the
  declaration of `top_level.txt`, and
  `test_the_wheel_carries_no_file_outside_the_package_and_its_metadata` reads the payload. A
  file that ships outside `ja4plus/` under no discovered package reaches no `top_level.txt`,
  so the payload case catches what the declaration case cannot. **A legitimate new top-level
  package moves both cases, and that cost is intended**, because a new importable name
  changes what a user of the release can import. **A mutation proves the three new cases
  discriminate, and it isolates them.** The removal of the two `assets` entries from the
  exclusion list fails exactly those three and passes the other 20. The mutation was written
  to disk, measured, and restored, and the file compared equal by digest after the restore.
  `EXPECTED_CASE_COUNT` of `tests/test_installed_wheel_selection.py` moves from 16 to 23,
  and the `installed-wheel` job stays the only runner of the marker. **#462 filed the
  `assets` finding before the project manager widened this round, so #462 closes as absorbed
  and this round holds the repair.** No file under `ja4plus/` changes and no fingerprint
  moves.

- **The documentation behaviour rule names a command that runs, and a case holds every named
  command to a collection** (#393). Round 163. The Behaviour rules of
  `docs/specs/features/08-documentation.md` read **A code sample is tested by
  `pytest --doctest-glob`**, and the Acceptance criteria named
  `pytest --doctest-glob="*.md" README.md docs/`. **That command collects nothing.** It
  writes `no tests ran` and it exits with the status 5. `--doctest-glob` collects an
  interactive session, written as `>>>` lines above the expected output. Every code sample of
  this project is a fenced code block. The two forms share nothing, so the rule named no
  check at all, and a reader of the page believed the rule covered the samples.
  **The requirements themselves hold.** `tests/test_documentation_samples.py` runs 45
  samples for FR-documentation-4 and FR-documentation-5, and `tests/test_examples.py` runs
  the five scripts of `examples/` under nine cases for FR-documentation-6. #63 built that
  harness, met the requirements, and stopped at the rule rather than editing the
  specification inside a feature diff. **The project manager ruled that the criterion is
  amended and the samples stay fenced.** A rewrite of 44 fenced samples into doctest sessions
  would make several unrunnable, and it would buy no coverage the harness already provides. A
  token doctest added to make the command green would prove nothing. **The defect lived in a
  second file.** The Documentation row of the Testing strategy table of `docs/specs/spec.md`
  named the same command, so one rule stood in two records and this round repairs both.
  `CLAUDE.md` carries no doctest command, and its `## Commands` section holds none.
  **Three sentences of the feature page change and one row of the specification changes.**
  The Behaviour rules now name `pytest tests/test_documentation_samples.py` and
  `pytest tests/test_examples.py`. They state that `--doctest-glob` reads an interactive
  session and collects nothing here. They record that the samples stay fenced, because a
  fenced block is what a reader copies. The Edge cases row reads `The harness case fails`
  where it read `The doctest run fails`.
  **New file `tests/test_documentation_behaviour_rule.py` holds 20 cases in four groups.**
  The command cases run every backticked `pytest` command of the Behaviour rules under
  `--collect-only`, and each one must collect at least one case. The floor case requires two
  such commands. **An aggregate over an empty set passes**, so a deleted rule would satisfy
  the command cases in silence. The discrimination cases prove the measurement fails where it
  must. The doctest command collects 0 cases and exits 5, and the counter reads 0 for a file
  that holds no case. The reader cases prove that `stated_command` raises on an absent
  sentence, on a repeated sentence, and on the text the rules held before this round.
  **The reader parses the case count and never greps it.** A page that held the words
  `0 tests collected` would match a substring search, so the reader matches the summary line
  and reads the exit status beside it. **The recorded reason takes two clauses, and a case
  reads each one.** A reader of the first clause alone would accept a sentence that reverses
  the claim, because the words `collects an interactive session` refuse nothing.
  **Six cases failed on the unamended records, and seven mutations prove the new cases
  discriminate.** This round wrote each mutation to disk, measured it, and restored it, and
  the file compared equal after every restore. A mutation that deletes the sample rule fails
  two cases, and the floor is one of them. A mutation that names the doctest command in the
  rule sentence fails two. A mutation that names `tests/test_no_such_harness.py` fails the
  same two. A mutation that deletes the recorded reason fails one. A mutation that keeps the first
  clause of the reason and drops the consequence fails the consequence case alone. A mutation that reverts
  the row of `docs/specs/spec.md` fails one alone. A mutation that renames the
  `## Behaviour rules` heading fails five. **One premise of the issue was stale and this
  round re-measured it.** The issue reported 45 samples, which is right, and 14 samples
  carrying a marker, which is not. `disposition` reads 15 explicit `skip` markers today, and
  17 markers with the two `raises` markers of `docs/api_reference.md`. This round names no
  page as the fifteenth, because the marker set moved across several rounds of this epic.
  The four-word reason case reaches all 95 skipped blocks and not the marked ones alone.
  **The sweep read every command of `docs/specs/features/*.md`, and three findings reach no
  repair here.** Two acceptance criteria state counts the repository no longer holds.
  `00-foundation.md:214` expects 75 files under `tests/foxio_vectors/` where `git ls-files`
  reports 90. `09-release.md:144` expects the string `0.6.0` in one file where `grep -rn`
  reports eight. `09-release.md:156` requires the wheel to carry no file under `docs/`, and
  `python -m build` on this base produces a wheel of 96 entries that holds 56 of them. That
  third one is a defect rather than a stale count, and #69 already owns it, so this round
  files no duplicate and reports the measurement. **No file under `ja4plus/` changes, no
  fingerprint moves, and the register holds 134 keys against 134 xfailed.**

- **The precedence exception states the register key count the register holds, and a case
  holds it there** (#380). Round 160. `.claude/rules/external-apis.md` read **The exception
  reaches 6 rows of the 135 the register holds**, and the register holds 134 keys. #272
  removed `ssh2.pcapng/JA4L-S` on 2026-08-09, because the repair to
  `ja4plus/fingerprinters/ja4l.py` made the comparison pass, and the prose kept the earlier
  count. **The reach of 6 was correct, and the key count alone was stale.** The two new
  cases prove that split. The reach case passed on the unrepaired prose. The key-count case
  failed with `assert 135 == 134`. **A count that no case measures goes stale.** #345
  repaired this shape in `tests/foxio_deviations.py`, and this round repairs the second
  sentence of the pair. `stated_exception_reach_counts` in
  `tests/test_precedence_exception.py` reads both numbers out of the sentence, and
  `measured_exception_reach_counts` reads the same two counts out of the register.
  `TestTheExceptionReachCounts` holds the two against each other, and it follows the
  `TestTheMarkerRuleCounts` shape of #345. **The reader raises `ValueError` on a document that
  states the counts on no sentence, and on one that states them twice.** A rewording that
  removes the sentence therefore fails the gate. **A check that a rewording defeats is not
  a check**, and two further cases prove the reader in both of those directions. **Both
  counts were proved live**, with `PYTHONDONTWRITEBYTECODE=1` and a cleared `__pycache__`. A
  stale key count fails with `assert 135 == 134`. A stale reach fails with `assert 5 == 6`.
  A removed sentence fails with `ValueError: the rule states the reach counts on 0
  sentences, and it states them on one`.
  **The sweep read every count of register entries in `docs/`, `.claude/` and the root
  documents, and it changed one sentence.** Four other live claims state 134, and each one
  agrees with the register.
  - `docs/specs/spec.md:539`.
  - `docs/specs/features/11-pre-release-validation.md:172`, in
    `FR-pre-release-validation-33`.
  - `docs/specs/features/11-pre-release-validation.md:370`.
  - The marker rule of `tests/foxio_deviations.py:63`, which #345 already holds under a
    case.

  `.claude/rules/external-apis.md` states 43 capability entries and 37 decided value-form
  keys of #129, and the register measures both. **A dated record of a past
  measurement is quoted, not rewritten.** `tests/test_foxio_deviations.py:660` records what
  #341 measured. The module docstring of `tests/test_precedence_exception.py` records the
  135 keys the run of #334 read at the pinned commit. `docs/implementation_notes.md` and
  every page under `docs/specs/foxio/` record the readings of earlier issues. Every
  Changelog row that states a past count records that round. **A correction inside a record
  falsifies the record**, so all of them stay as they read. No file under `ja4plus/`
  changes, no fingerprint moves, and the register holds 134 keys against 134 xfailed.
- **Two timing cases read the work performed rather than the seconds elapsed** (#430).
  Round 158. Both cases compared wall-clock durations. Each one reported the load of the
  host beside the state of the package. #412 met both of them failing beside a mutation
  sweep.
  `tests/test_tcp_stream.py::TestTCPStreamReassembler::test_the_cost_of_a_segment_does_not_grow_with_the_segment_count`
  compared `elapsed(20000)` against `elapsed(5000) * 8`. **That case also passed the
  defect it exists to catch.** `DEFAULT_MAX_STREAM_SEGMENTS` stores 4096 segments and
  refuses the rest. Both readings therefore stopped at the same 4096 stored segments. A
  duplicate check that scans the stored segments read a ratio of 5.975 against the
  threshold of 8. The case now holds no clock. It raises the segment cap to the count it
  feeds. It counts the reads of the stored segments through a `CountingSegmentList`. The
  set of seen segments reads 0.0 segments for each segment at 5000 and at 20000. The scan
  reads 2499.5 and 9999.5. The bound is 4.
  `tests/test_throughput.py::TestTheWorkControl` keeps its clock, because the rise of the
  elapsed time is the property the control exists to prove. It now feeds 1000 packets and
  then 2000, three runs of each count. It compares the fastest run of one count against
  the fastest run of the other. A loaded host adds seconds to a run and removes none, so
  the fastest run of a count is the run the load moved least. The control states no
  tolerance. A runner that writes a constant elapsed time still fails it with
  `assert 1.0 > 1.0`. **A floor on the ratio of the two readings is declined.** The two
  fastest runs read a ratio of 1.219 under a load average of 20 on a ten-core laptop,
  against 1.96 on a quiet host, so a floor of 1.5 fails there. **A deliberate load
  reproduced the failure of #412.** One reading pair of the nine inverted, at 0.8261
  seconds for 1000 packets against 0.7926 for 2000, and the fastest runs kept the order.
  The 20000-packet run of the earlier form leaves the unit suite. No file under
  `ja4plus/` changes and no fingerprint moves.
- **The periodic statistics case states the schedule rather than samples it** (#371).
  Round 157.
  `tests/test_watch_statistics.py::TheStatisticsGoToStandardError::test_the_periodic_line_reaches_standard_error`
  ran `ja4plus watch` with `--stats-interval 0.05`, slept 0.3 seconds inside the capture,
  and asserted that at least 2 statistics lines reached standard error. That count measures
  how promptly the host schedules a thread, which is the fault #369 repaired inside
  `TheReporterWritesOneLinePerInterval`. **#369 could not reach this case with the seam it
  added**, because the case builds no reporter and reaches the reporter through
  `cmd_watch`. `report_statistics` now carries the same `wait` parameter and forwards it to
  `StatisticsReporter`. `ja4plus/cli.py` passes nothing, so the default still waits on the
  stop event and the shipped behaviour is unchanged. The case drives the command through
  `ScriptedReport`, which records the interval and the stream `cmd_watch` passed and carries
  a scripted wait to the reporter. It asserts an exact count of four statistics lines, three
  periodic and one exit summary, where the earlier form asserted a lower bound. It also
  asserts that the interval reaches the wait unchanged, and that the stream is standard
  error. The case therefore proves more of FR-live-capture-9 and FR-live-capture-10 than the
  earlier form proved, and it holds no sleep. **The repair keeps the one argument that
  carries a unique mutation kill.** The sweep of #414 recorded the mutation `0` to `1` at
  `ja4plus/cli.py:871` as killed, at a killed count of 1, and it named this case as the
  sample. That guard reads `seconds <= 0`, and `--stats-interval 0.05` is the one interval
  below one that any case of the suite passes. The repair therefore holds that argument.
- **Four more cases read ambient host state under no guard** (#426). Round 159. The sweep
  of #424 read all 154 files under `tests/` and found four cases of the shape it repaired.
  This round guards all four, and it deletes none of them. **Each case states a real
  requirement, so a guard skips where the host cannot answer and the reason names the
  state.** `the_filter_failure` of `tests/test_watch_capture.py` calls `compile_filter`,
  and `scapy` 2.7.0 raises `ImportError("libpcap is not available. Cannot compile filter !")`
  at `scapy/arch/common.py:87` where the loader cannot open `libpcap`. The call caught
  `Scapy_Exception` alone, so a host without `libpcap` ended four cases with an error
  rather than with a failure. A minimal Linux container is such a host. The helper now
  returns `None` there, and `the_filter_failure_or_skip` skips the four cases that read it.
  `the_absent_interface_failure` raised `AssertionError` where the host holds an interface
  named `nosuchif0`, and it now returns `None` and skips the four cases that read it.
  `test_the_interface_list_of_this_host_holds_a_name` required this host to hold one
  interface, and it now skips where the capture layer reports none.
  `test_three_hundred_calls_hold_the_open_descriptor_count` of `tests/test_watch_stop.py`
  read `os.listdir("/dev/fd")` under no platform guard, and Windows holds no such
  directory; `the_open_descriptor_count` now returns `None` there and the case skips.
  **A guard proved in one direction can skip on every host, and a case that always skips
  measures nothing.** Three new classes therefore run the guarded cases themselves and read
  both directions: `TheFilterCasesGuardOnTheAmbientLibpcap`,
  `TheAbsentInterfaceCasesGuardOnTheNameTheHostHolds` and
  `TheInterfaceListCaseGuardsOnTheListTheHostReports`, beside
  `TheDescriptorCountCaseGuardsOnTheDirectoryItReads` of `tests/test_watch_stop.py`.
  **The `libpcap` direction reaches the real `scapy` translation and no stand-in.** A
  finder on `sys.meta_path` raises `OSError` from the import of `scapy.libs.winpcapy`,
  which is the failure the loader reports, and `scapy` raises the `ImportError` itself.
  **Every run-direction prover reads the ambient state by a route that passes the guard
  it proves.** The first form read the state through the guard. A mutation that made the
  guard skip always then made the prover skip as well, so it measured nothing. The mutation
  now turns four subtests red. **The count case carried a second defect and this
  round repairs it too.** The reading covers every descriptor of the process, so another
  part of the run that opens one moved it, and the case compared for equality.
  `DESCRIPTOR_TOLERANCE` is 16 against the 600 descriptors the leak opens over 300 calls.
  `test_the_case_fails_where_the_monitor_leaks_a_descriptor_for_each_call` opens one
  descriptor inside each capture call and requires the count case to fail. **The tolerance
  states one limit.** A leak below it passes where the equality failed, and the case states
  that trade. No file under `ja4plus/` changes and no fingerprint moves.

- **The capture privilege case read a host that grants the privilege** (#424). Round 152.
  `tests/test_watch_capture.py::TheCommandNamesTheCapturePrivilege::test_the_message_reads_the_failure_this_host_reports`
  asks the real capture layer of the host for the failure it reports without the
  privilege. It guarded on `sys.platform` and on `os.geteuid()`, and it did not guard on
  the state it depends on: whether this host grants the capture privilege to this
  account. **The user ran `sudo chown $(whoami) /dev/bpf*` on 2026-08-09 for #423**, and
  the case then read `AssertionError: the host granted the capture privilege` at
  `tests/test_watch_capture.py:132` on the unchanged base. **A red gate that is normal is
  worse than no gate**, because the next real failure hides inside it. `the_privilege_failure`
  now returns `None` where the host grants the privilege, and the case calls `skipTest`
  with a reason that names the grant. **The case is not weakened and it is not deleted.**
  It stays the only case that reads the failure from the real capture layer, and it still
  runs and still asserts the message on a host that denies the privilege. New class
  `TheCapturePrivilegeCaseGuardsOnTheHostState` proves the guard in both directions,
  because a guard proved in one direction can skip on every host, and a case that always
  skips measures nothing. That class runs the guarded case itself against a patched
  `scapy.arch.bpf.core.get_dev_bpf`: the denial direction reports one case run, no
  failure and no skip, and the grant direction reports one skip whose reason names the
  grant. A third case proves that the probe closes the descriptor `get_dev_bpf` returns,
  which the earlier form leaked on every granting host. No file under `ja4plus/` changes,
  the privilege message does not move, and no fingerprint moves.
- **The network rule of Epic 11 bound every case, and every install case had to violate
  it** (#419). Round 150. `FR-pre-release-validation-26` read `No case of this feature set
  opens a network connection.` `pip install <the wheel>` resolves the shipped dependency
  list, so an install into a clean environment reaches a package index by construction.
  **A measurement of 2026-08-09 states it rather than infers it.** A clean environment that
  installed `ja4plus-0.6.0-py3-none-any.whl` read
  `Downloading scapy-2.7.0-py3-none-any.whl (2.6 MB)` and
  `Downloading cryptography-50.0.0-cp311-abi3-macosx_11_0_arm64.whl (4.0 MB)`.
  **The rule came from #414, where it is correct and narrow**, so this entry keeps it and
  names its scope. `FR-pre-release-validation-26` binds a case of `tests/test_db_offline.py`
  that asserts that `ja4plus/ja4db.py` sends no request, and it names the recorded
  transport `RecordingRequests`. `FR-pre-release-validation-26a` bars the address
  `https://ja4db.com`. `FR-pre-release-validation-26b` permits the package index for the
  install cases of `tests/test_installed_wheel.py`, and `FR-pre-release-validation-26c`
  names `scapy` and `cryptography` as the two dependencies that index resolves.
  **The rule is now a condition a case tests, and not prose alone.** New file
  `tests/test_requirement_scope.py` reads the requirement text of every document under
  `docs/specs/features/`. A requirement that scopes itself to a feature set names one path
  under `tests/` inside backticks. **The check reads a necessary condition and not a
  sufficient one**, because no parser reads which cases a sentence means. **The failing
  direction is proven live.** Against the base the case read
  `AssertionError: these requirements bind a feature set and name no case file: ['FR-pre-release-validation-26']`,
  an injected `FR-release-99` of the same shape read the same message, and the revert
  returned all four cases to green. **The self-review found one gap in the pattern and
  closed it.** The first form read `case` alone, so `No cases open a network connection`
  stated the defect again and passed. The pattern now reads `cases?`. **The sweep found one widened rule of the 200 the base
  holds, and no second one.** `FR-pre-release-validation-33` is the only other requirement
  scoped to a feature set, it binds the issues rather than the cases, and it names
  `tests/foxio_deviations.json`. **`FR-pre-release-validation-16` is untouched, because
  #411 owns it.** The `## Terms` table gains `recorded transport` and `package index`. No
  file under `ja4plus/` changes and no fingerprint moves.
- **The migration page cited round 122 for the item access, and it recorded the narrowed
  certificate readers not at all** (#399, #401, #403). Round 143. The page held eleven breaking
  changes and none recorded #319. That round narrowed `compute_ja4x_from_pem` and
  `compute_ja4x_from_der`, so an input that returned `None` in version 0.6.0 can now raise.
  The page also cited one row under `Round 122, #59 and #364`. The Changelog table of
  `docs/specs/spec.md` holds round 122 for #59 and round 123 for #364. **Both defects sit
  in a page this epic created, and #66 found both while it wrote the release notes.** The
  page now holds thirteen rows: the conflated row parts into two, and the certificate
  readers gain one. **The repair is the two cases that make the page answerable to the
  record.** `test_every_citation_of_the_migration_page_names_the_row_that_records_it` reads
  every `Round N, #M` citation of the page against the Changelog table of
  `docs/specs/spec.md`, and it reads no second file. The first citation case of #66
  compared the `Record` cell of the notes against the cell of the page. Both files held one
  error, so the two agreed and the case passed. That is the eighteenth recorded instance of
  a comparison that never runs.
  `test_every_breaking_change_of_the_record_reaches_the_migration_page` reads the direction
  #66 left open. The case that reads the other direction passes on a page that holds fewer
  changes than the record. **#403 is the sentence this repair falsified.** The release
  notes read "One breaking change reaches this record and reaches no row of the migration
  page", and the new row of #319 made that untrue. **No case read the paragraph**, so a
  reader found it and the suite did not.
  `test_the_release_notes_report_the_gap_the_record_shows_and_no_other` connects the prose
  to the measurement. It reads a present-tense gap claim against the set difference of the
  record and the page, and it fails in both directions: on a claim the record does not
  show, and on a gap the notes report not at all. Six mutations prove the three cases
  discriminate, and each was restored. The unit suite rises from 2499 passed to 2502, and
  coverage holds at 94. The conformance suite reports 134 xfailed against 134 register
  keys. This entry
  changes no file under `ja4plus/` and no fingerprint moves.
- **The memory ceiling control reads a block count, and a busy host no longer moves it**
  (#389). Round 144. `TestTheStatedMemoryCeiling::test_a_smaller_entry_count_holds_less_resident_memory`
  failed and then passed on an unchanged tree, and five workers reported it. The case is
  the control that proves the entry count bound holds the ceiling, and **a control that
  fails when nothing is wrong teaches a reader to disregard it.** The case now reads the
  count of memory blocks the run holds, and it carries the name
  `test_a_smaller_entry_count_holds_fewer_memory_blocks`. **Memory pressure is the
  mechanism, and processor contention is not.** A resident reading states what the host
  left in memory. A host under memory pressure reclaims the pages of a running process,
  and it reaches the run that holds the most memory first. The reclaim moves the two runs
  by different amounts, and it moves the growth ratio toward one. **The reproduction ran
  on one Ubuntu 24.10 host with 56 cores.** Each measurement run ran under `systemd-run
  --user --scope -p MemoryMax=<limit>`. The resident ratio read 0.434 at no limit, 0.962
  at 80 MiB and 0.786 at 75 MiB, and at 70 MiB both runs added 0.00 MiB. **The block ratio
  read 0.392 at every one of the four.** A deliberate processor load of 56 processes that
  hold a processor busy held the load average at 58 for three rounds, and it moved neither
  reading. **A rule that repeats the pair and takes the median repairs nothing.** Three
  rounds at the 80 MiB limit read 1.047, 0.885 and 1.045. The rule also costs three times
  the wall clock. The run collects the cyclic garbage before it counts the blocks. That
  collection moves the macOS ratio from 0.612 and 0.664 across two rounds to 0.398 at each
  of three. **`CONTROL_GROWTH_RATIO` stays 0.85**, and the mutation that raises the control
  bound to the shipped 10000 reads 1.361 on Linux and 1.367 on macOS. **The floor moves
  from 10.0 MiB to four blocks for each packet**, because a MiB floor is the reading the
  host moves. Under the 70 MiB limit the shipped run added 0.00 MiB and 376954 blocks. The
  measured rate is 12.37 blocks for each packet at the default size, so the reading sits
  3.1 times above the new floor. The retired MiB floor sat 2.9 times below its reading, so
  the new floor holds the strength the old one held. **No file under `ja4plus/` changes and
  no fingerprint moves.**

- **`generate_ja4` reads a TLS info dictionary, and the documentation stated a packet**
  (#63). Round 138. `README.md` and `docs/api_reference.md` each wrote
  `generate_ja4(packet)`, and the call raises `AttributeError: get`. The function reads
  the dictionary that `ja4plus.utils.tls_utils.extract_tls_info` returns. Eight of the
  nine other one-shot functions read a packet. `generate_ja4x` reads a dictionary that
  `docs/api_reference.md` already recorded. **The sample harness of #63 found this on its
  first green run, and no case reached it before**, because nothing ran the sample. This
  entry repairs the two documents and changes no signature.

- **Six documents stated a count of ten methods, and the count is eleven** (#387). Round
  162. `JA4LFingerprinter` writes `JA4L-S=` at `ja4plus/fingerprinters/ja4l.py:446` and
  `JA4L-C=` at `:482`, so ten fingerprinter classes carry eleven methods. **The measurement
  reproduces on the base commit `d123ab9` and it carries no number from the issue body.**
  `__all__` names ten `generate_` functions, the module of `generate_ja4l` writes both value
  prefixes, and `FOXIO_METHODS` holds twelve names, so eleven of twelve reach a generator
  and JA4TScan reaches none. **The issue named three documents and a sweep of the whole
  corpus found six.** `docs/specs/features/08-documentation.md` and `docs/specs/spec.html`
  held the implemented count of ten, and `docs/api_reference.md`, `docs/usage.md`,
  `docs/specs/features/03-concurrency-safety.md` and the `Data model` table of
  `docs/specs/spec.md` called the ten fingerprinters ten methods. **The prose now counts
  fingerprinters and values where it counted methods**, matching the
  `FingerprintResult.type` docstring that round 139 wrote. **The reason stands beside the
  number in every document that states it**, because a bare eleven invites the next reader
  to count the classes and correct it back. New file
  `tests/test_documented_method_count.py` holds 151 cases. It reads the method set out of
  `__all__` and out of the return lines of each generator's module. A case that restated
  eleven would pass on a document that contradicts the package. **The cases came first and
  they bite**: 10 failed against the unchanged documents and 128 passed. **Seven mutations
  prove they discriminate.** The first replaces `JA4L-S=` with `JA4L-X=` on the return lines
  of `ja4plus/fingerprinters/ja4l.py` and leaves the docstring that states the same format.
  It drops the count to ten and fails all five documents that state eleven. The second
  removes `generate_ja4d6` from `__all__`. The other five restate ten in one document, drop
  the reason from one document, and apply the class count to the word `method` on two pages.
  Each was restored, and `inspect.getsource` confirmed the live source in both directions.
  **The self-review found two defects in the reader and each is now closed.** The first read
  the whole module source for a value prefix, so the docstring of
  `ja4plus/fingerprinters/ja4l.py:6` satisfied the check on its own. A change that deleted
  every emitter would have kept the count at eleven, and the reader now reads the return
  lines alone. The second searched the joined page for a quoted passage. It paired a
  quotation mark of one line of `docs/usage.md` with a mark 40 lines below it, and it
  dropped every word between them, so the reader matched nothing on that page. It now drops
  a quotation one line at a time. **The review also proposed five rewordings that the first
  reader read nothing in**, among them "supports ten of FoxIO's methods" and "ten of twelve
  implemented". The reader now holds a set of claim verbs rather than the one verb
  `implement`, and it allows two words between the count and the noun.
  **Five findings reach no repair here.** #449 records that `docs/specs/spec.html` states
  "Seven of twelve FoxIO methods are specified only as images" where the same page states
  eleven, and that `SUPERSEDED_COUNT` of `tests/test_documentation_image_count.py` reads over
  it because the page writes no `the`. #450 records the ten files under `tests/` that call
  the ten fingerprinters ten methods, and it names the decision that `ProcessorStats.method`
  needs. **Four docstrings of `ja4plus/watch.py` carry the same counting error**, at lines
  13, 81, 115 and 518, and the criteria of #387 forbid a change under `ja4plus/`, so #450
  records them too. #453 records a separate stale number the sweep met:
  `docs/specs/features/03-concurrency-safety.md` states sixteen state tables where
  `docs/api_reference.md` states seventeen, and a live `Processor().stats()` reports
  seventeen. The body of #62 still states ten of the twelve, and it is a tracker record
  rather than a document of this repository. **No file under `ja4plus/` changes and no
  fingerprint moves.**

- **One reader reads the entries of a dependency block, and it reads no quoted substring**
  (#452). Round 185. `_dependency_block` of `tests/test_documentation_site.py` collected
  every double-quoted substring of a dependency block, so a comment inside the block read
  as an entry. **A reader that is correct only because of what its callers happen to read
  is the defect**, and #378 found it while it stopped importing the helper rather than
  change it. **The premise was re-measured against the current tree and it holds.** The
  unrepaired reader returns `['pytest==8.4.2', 'pytest-cov==7.1.0', 'ruff==0.16.2',
  'mypy>=1.11', 'not spec_validation', 'build==1.4.4']` for the `dev` extra, and
  `not spec_validation` is a fragment of the command inside the comment beside
  `build==1.4.4`. New file `tests/dependency_entries.py` holds `dependency_lines` and
  `dependency_entries`, and every caller now reads it. `_dependency_block` and the
  `_dev_lines` and `_dev_entries` of `tests/test_lint_gate_pin.py` parse nothing of their
  own. **#446 widened the hazard and answered it with a second reader inside that file**,
  because every entry of the extra now carries a comment above it, and two readers of one
  block can disagree. **The module reads lines and no TOML.** `tomllib` reaches the
  standard library at Python 3.11, `pyproject.toml` states `requires-python = ">=3.9"`, and
  `FR-foundation-13` runs the matrix from Python 3.9, so an import of `tomllib` would fail
  two jobs. The `dev` extra names no `tomli`. **A comment starts at a `#` that stands
  outside a string**, so one scan drops a comment line and a comment after an entry, and an
  entry that carries a fragment marker in a URL survives. **The tests came first**, and the
  unrepaired tree failed
  `tests/test_documentation_site.py::test_the_reader_returns_the_entries_of_the_dev_extra_and_no_comment_fragment`
  with `AssertionError: At index 4 diff: 'not spec_validation' != 'build==1.4.4'`. **Each
  case names the entries it expects**, because a repair that returns an empty list passes a
  case that reads the absence of the fragment alone. Three cases hold the `dev` extra, the
  runtime block and the `docs` extra by name, and new file
  `tests/test_dependency_entries.py` holds eleven cases against the shapes no block of
  `pyproject.toml` carries today. **The reader refuses a block that holds no entry**,
  because an aggregate over an empty set passes and a caller would read a clean block.
  **The self-review found one hole and the reader now closes it.** TOML holds a literal
  string in single quotes, the first form of the reader read the double-quoted form alone,
  and an entry of the other form would have disappeared with no offender reported. The
  reader now holds both forms, and it holds the quote that opened a string, so the
  apostrophe of an environment marker closes no basic string. **The reader reads no escape
  sequence, and a line that holds one raises.** A silent half of an entry is the worse
  result, so `"foo\"bar"` fails rather than returns `foo\`. **Five mutations prove the
  cases discriminate.** A reader that keeps every comment fails 4 cases, among them the
  `dev` extra case and `test_the_decision_covers_every_entry_of_the_dev_extra`. A reader
  that cuts a line at the first `#` fails the fragment-marker case alone. A reader without
  the floor fails the empty-block case alone. A reader of the double-quoted form alone
  fails the literal-string case alone. A reader without the open-string guard fails the
  escape case alone. Each mutation restored from a snapshot of the implemented tree, and
  the restored form passes 58 of 58 every time. The `Terms` table of `docs/specs/spec.md`
  gains `dependency block`, because that table already rejects `dependency list` as a
  synonym of `dependency record`. **No file under `ja4plus/` changes and no fingerprint
  moves.**

### Changed

- **One file declares the version, and two gates hold it against the project metadata and
  the changelog** (#67). Round 187. `pyproject.toml` declared `version = "0.6.0"` at line 7
  and `ja4plus/__init__.py` declared it again at line 94, so the two records could
  disagree. `ja4plus/__init__.py` is now the one declaration. `pyproject.toml` names
  `version` in its `dynamic` list and reads the value from `ja4plus.__version__`, so a
  build resolves the version the package declares. **This round declines the
  `importlib.metadata` reader that `docs/specs/features/09-release.md` proposed, and it
  measured three reasons on 2026-08-10.** That call reads the metadata of an installed
  distribution and it does not read the source tree. A checkout that carries no install
  raises `PackageNotFoundError`, so the reader needs a literal fallback, and a fallback is
  the second declaration `FR-release-1` bars. An editable install freezes its metadata at
  install time: with `pyproject.toml` changed to `0.7.0` and no reinstall,
  `importlib.metadata.version("ja4plus")` returned `0.6.0`. That metadata resolves through
  `ja4plus.egg-info` of the working directory, so the answer follows the directory a
  command runs in. **A gate that reads the version out of an install compares a value
  against itself**, because continuous integration installs the project from
  `pyproject.toml`. The two gates read tracked text instead, and the two texts are
  independent inputs. `version_disagreement` of `tests/version_gate.py` holds
  `pyproject.toml` against `ja4plus/__init__.py` for `FR-release-2`, and
  `changelog_disagreement` requires a `## [<version>]` section of `CHANGELOG.md` for
  `FR-release-3`. **Each gate carries a control case that feeds it a contradicting pair and
  reads the message it returns**, because a comparison that is never made reads as a
  comparison that passes. **`setuptools` resolves the attribute from the syntax tree and
  imports no module**, so a build needs neither `scapy` nor `cryptography`; a read of
  2026-08-10 built `ja4plus-0.6.0-py3-none-any.whl` in an isolated build environment that
  holds neither. **The acceptance criterion of `docs/specs/features/09-release.md` now
  counts the declaration and no longer the text `0.6.0`.** #456 measured seven files that
  hold that text and it handed the decision here: five of the seven state in prose what
  version 0.6.0 did, a reader of `docs/migration-0.6-to-1.0.md` needs that prose, and a
  count of the text can therefore never reach one. A read of 2026-08-10 reports one
  declaration file and six files that hold the text. **The closing quote is part of the
  command the criterion names.** `[tool.setuptools.dynamic]` writes
  `version = {attr = "ja4plus.__version__"}`, which states where a build reads the version
  and declares none, so a pattern without the quote reads two files where one declaration
  exists. This round wrote that pattern first and the re-measurement caught it. **A
  self-review of this round found one silent pass, and a case now holds the reader against
  it.** `project_version` searched the whole file for a `version = "..."` line, so a
  `[tool]` table that carried the package version beside a `dynamic` list naming the wrong
  attribute read as agreement and the gate reported nothing. `project_version` and
  `project_version_attribute` each search one table now.
  `test_the_gate_reads_the_version_of_the_project_table_alone` reproduces the state.
  `declaration_files` still searches no single table, on purpose: a second `version` key
  fails the one-file case of `FR-release-1` rather than pass it. **`MEASURED_CRITERIA` of
  `tests/test_criterion_counts.py` now holds no pending criterion**, so the two pending
  cases aggregate over an empty set; `PENDING_CONTROL` feeds the pending reader a criterion
  whose end state this tree holds. `tests/test_installed_wheel.py` reads the version from
  the package rather than from `pyproject.toml`, and a new case reads the version the build
  resolved into the wheel metadata.

- **The `dev` extra states one recorded shape for every entry, and one record holds every
  version** (#446). Round 181. #378 pinned `ruff` alone, so four entries of the `dev` extra
  still floated and two of them had drifted across a major line. **The user ruled the shape
  on 2026-08-10, and this round builds that ruling.** `build`, `pytest` and `pytest-cov`
  each carry an exact version beside `ruff==0.16.2`. `mypy` floats. `requirements.txt` is
  deleted. **`mypy` reads the opposite way from the four pins, on purpose.** A pinned type
  checker falls behind, and a frozen release hides a defect that a later release reports. A
  floating formatter turns a green tree red, which is noisy and safe. A frozen type checker
  keeps a red tree green, which is quiet and unsafe. **The pinned versions are a measurement
  of 2026-08-10 and not a copy of the issue body.** A clean environment that installed
  `pip install -e ".[dev]"` resolved `pytest` 9.1.1, `pytest-cov` 7.1.0, `build` 1.5.0,
  `mypy` 2.3.0 and `ruff` 0.16.2. **Two of those five versions would turn every Python 3.9
  job red, and the pin declines both.** `pytest` 9.1.1 states `requires_python` `>=3.10` and
  `build` 1.5.0 states the same, while `FR-foundation-13` runs the matrix from Python 3.9. A
  read of the PyPI interface reports the newest release of each distribution that carries a
  wheel for Python 3.9 through 3.13: `pytest` 8.4.2, `pytest-cov` 7.1.0 and `build` 1.4.4.
  The extra therefore reads `pytest==8.4.2`, `pytest-cov==7.1.0` and `build==1.4.4`.
  **The deletion left one instruction pointing at a deleted file, and this round repairs
  it.** A read of every tracked file found two: the `ruff` comment of `pyproject.toml` and
  the note under `FR-foundation-8c`. No workflow reads the file, no `Makefile` exists, no
  `tox.ini` exists and `README.md` names it nowhere. **`tests/test_lint_gate_pin.py` widens
  from 6 cases to 30**, because the Notes of #446 asked for one reader over the extra rather
  than a second one. The file keeps its name, because `pyproject.toml`,
  `docs/specs/features/00-foundation.md` and this file each name that path. **The tests came
  first**, and the unrepaired tree failed 18 of the 30, among them
  `AssertionError: the dev extra states no exact version for pytest: 'pytest>=7.0'` and
  `AssertionError: these files name requirements.txt: ['docs/specs/features/00-foundation.md', 'pyproject.toml']`.
  **Eight mutations prove the cases discriminate, and each one isolates to the case it
  targets.** The floating `pytest` specifier restored fails the pin case and the
  installed-release case. A `build` comment that drops `#446` fails the citation case
  alone. A `pytest` comment that drops the word `commit` fails the commit rule alone. A
  `mypy` comment that drops the word `hides` fails the hidden-defect case alone.
  `mypy==2.3.0` fails the floating case alone. A `tox>=4.0` entry appended to the extra
  fails the coverage case alone, at `Left contains one more item: 'tox'`. A restored
  `requirements.txt` fails three cases. An `Install with pip install -r` line appended to
  `README.md` fails the instruction case alone. Each mutation restored from a snapshot of
  the implemented tree, and the restored form passes 30 of 30 every time.
  **The reader reads dependency entries and never every quoted substring**, which is the
  defect #452 records. `_dev_entries` strips the comment lines of the list before it
  collects an entry, and each comment of this round quotes a version. **Two floors fail a
  reader that collected nothing**, because an aggregate over an empty set passes.
  `MINIMUM_DEV_ENTRIES` holds the extra at five entries and `MINIMUM_INSTRUCTION_FILES`
  holds the instruction set at ten files. **A case fails a `dev` entry whose shape no
  decision chose**, so an entry a later round appends reaches
  `test_the_decision_covers_every_entry_of_the_dev_extra` rather than the next install.
  **One statement here reaches no case, and the file states that.** No case reads whether a
  pinned version installs on Python 3.9, because that read needs the package index and this
  suite opens no network connection. `FR-foundation-8d` through `FR-foundation-8g` carry the
  four new requirements. No file under `ja4plus/` changes and no fingerprint moves.

- **`FR-pre-release-validation-16` names a pathspec whose plain reading equals what it
  matches** (#436). Round 170. The requirement named
  `git ls-files 'ja4plus/*.py' 'ja4plus/*/*.py'`, which lists all 31 modules of the
  package. Its first term alone lists all 31 too. **In a default git pathspec, `*` crosses
  `/`, and only `:(glob)` magic stops it at a separator.** A read of 2026-08-09 reports
  four counts: `git ls-files 'ja4plus/*.py'` lists 31, the pair lists 31,
  `git ls-files 'ja4plus/**/*.py'` lists 24, and `git ls-files ':(glob)ja4plus/*.py'`
  lists 7. **The count was right and the rule was not.** The second term read as proof
  that `*` stops at a separator, so the next writer who reasoned from the requirement
  reproduced the defect. #411 and #414 each met that reading, and #414 reported the
  contradiction. The requirement now names `git ls-files 'ja4plus/*.py'` alone, and it
  states the separator rule. New `FR-pre-release-validation-16b` binds the cases, and new
  `FR-pre-release-validation-16c` records the four counts.
  **`tests/test_mutation_sweep_module_list.py` reads the pathspec out of the requirement
  text and runs it.** A requirement that names a pathspec listing a different set than the
  sweep reads therefore fails a case. The file gains four cases. Two compare the file set
  of the stated pathspec against the module set the sweep reads and against the tracked
  Python files of the package. One fails where a term of the pathspec lists no file the
  other terms miss. One reads the separator rule out of the requirement. A floor case
  refuses a pathspec of no term and refuses an empty file set, because a set comparison
  over an empty set passes on its own. **Every case was proved in both directions.**
  Against the unrepaired requirement the redundancy case read
  `AssertionError: the term ja4plus/*/*.py lists no file the other terms miss`, and the
  separator case read that the requirement holds no such sentence. A `**` form restored
  into the requirement failed the two comparison cases, which named the seven
  top-directory modules as extra items, and the revert returned all nine cases to green.
  **`DEFAULT_MODULE_PATTERNS` keeps its two patterns.** It reaches `Path.glob`, where `*`
  stops at `/`, so the sweep needs the depth the requirement needs one term for.
  `.claude/rules/conformance.md` and the acceptance list of
  `docs/specs/features/11-pre-release-validation.md` state the same reading. No file under
  `ja4plus/` changes and no fingerprint moves.
- **A state table reads the clock of the thread that touches it** (#461). Round 171.
  Eight sharded threads wrote a JA4TS value that one thread does not write, and the
  reading is
  `At index 10 diff: '64240_2-1-1-4-1-3_1460_7' != '64240_2-1-1-4-1-3_1460_7_0'` on
  `test (macos-latest, 3.12)`, run `31342645430`, merge commit `d94d8c1` of batch #445.
  The sharded value lost part e, the delay list of the SYN-ACK retransmissions.
  **`BoundedStateTable` held one clock for every thread, and the age pass read every
  entry.** `SynAckTracker.times` runs one pass on every packet and holds a maximum age of
  120 seconds. On the concatenated timeline of `TestTheConcurrencyContract`, packet 578
  opens `('184.150.157.177', 80, '172.16.225.48', 57380)` at 19.2378 seconds and packet
  581 retransmits the SYN-ACK 5.8 milliseconds later. Packet 1773 belongs to another
  connection and another shard, and it stands at 151.678 seconds. It announced its
  timestamp to the shared clock, the pass read 132.44 seconds of age, and it evicted the
  connection. Packet 581 then found no entry, `SynAckTracker.record` returned an empty
  delay list, and `_part_e` wrote an empty string. **The reproduction is three packets on
  two threads and it holds no race**, so it fails every run rather than one run in four.
  **The repair scopes the clock and the pass to the thread.** `on_packet` writes the
  timestamp into a `threading.local`, each entry carries the identifier of the thread that
  read it last, and `evict_aged` passes over every entry of another thread. One thread
  owns every entry it stores, so a caller that runs one thread reads the pass this project
  always ran. **The entry of a thread that ends now stays until the entry count bound
  removes it**, and that bound is the one that holds the memory. **One wall clock serves
  every thread, so the pass still evicts an entry that the wall clock dated, whichever
  thread stored it.** `JA4DBClient` builds the one table that reads the wall clock, and
  its callers share every entry under one lock rather than owning whole connections. A
  self-review found that a pass scoped by thread alone would age out nothing there.
  `FR-concurrency-safety-8`, `FR-concurrency-safety-8a`, `FR-concurrency-safety-8b` and
  `FR-concurrency-safety-8c` state the rule. **`TestTheConcurrencyContract` passed 50 of
  50 consecutive runs on macOS**, against the one failure in four runs the issue records.
  **Nine new cases hold the repair and five live mutations prove them.** Every run cleared
  every `__pycache__` outside `.venv/` and set `PYTHONDONTWRITEBYTECODE=1`, and
  `inspect.getsource` read the loaded source in both directions. The shard filter of
  `evict_aged` removed reads 1 occurrence clean and 0 mutated, and it kills 2 cases. The
  thread clock of `on_packet` removed kills 1 case. The owner write of `__contains__`
  removed kills 1 case, and the owner write of `__getitem__` removed kills 1 case. The
  wall-clock exemption of the pass removed kills 1 case. Every case passes clean and after
  the restore. **No file under `ja4plus/fingerprinters/` changes and no fingerprint
  moves.** A
  replay of all 38 committed captures produced 783 values, and the SHA-256 of that output
  is `04014a1d7a1863bc3244e1348ce61b5f39f9805a988310af657a6a931a2d8907` before the change
  and after it. The conformance suite reports 1532 passed, 143 skipped and 134 xfailed
  against 134 register keys.
- **The mutation sweep builds no mutation inside a type annotation** (#431). Round 168.
  `tests/mutation_sweep.py` built one mutation for each `BinOp` node whose operator sits in
  `BINOP_SWAP`, and `ast.BitOr` is one of them. A type annotation written `str | None` holds
  a `BitOr`, so the sweep changed it to `str & None`. **28 of the 31 modules of `ja4plus/`
  carry `from __future__ import annotations`**, so Python holds each annotation as a string
  and evaluates none of them. A changed annotation reaches no run-time value, and no case can
  fail for it. The three modules that carry no such import hold one annotation node between
  them, the `-> None` of `ja4plus/utils/loopback.py`, and no operator sits in it.
  **#413 measured the cost.** 94 of the 675 surviving mutations of
  `ja4plus/fingerprinters/` sat inside an annotation, and all 94 survived. That is 14
  percent of the survivors of the module group. A reader reads each one and finds no case
  that it can ever fail. **New reader `_annotation_nodes` names the nodes of an argument
  annotation, of a return annotation and of an `AnnAssign` annotation**, in the shape
  `_docstring_nodes` and `_logging_argument_nodes` already set. `generate_mutations` reads
  it for every node kind, because the earlier `skip` set reaches the constant branch alone
  and an annotation holds a `BitOr` that the binop branch reads. **The reader removes 95
  mutations and not 94.** `ja4plus/fingerprinters/base.py:43` holds `-> Literal[False]:`,
  and that constant reaches no run-time value either. `--dry-run --max-per-module 0` over
  `ja4plus/fingerprinters/*.py` reported 1569 mutations before the reader and it reports
  1474 after it. **New file `tests/test_mutation_sweep_annotation_skip.py` holds nine cases
  and every one was proved in both directions.** The five reader cases failed with
  `AttributeError: module 'tests.mutation_sweep' has no attribute '_annotation_nodes'`
  before the reader existed. The three sweep cases failed against a control that reads an
  empty set in place of the reader, one with `assert 4 not in {4, 6, 7}` and one with
  `assert 4 == 1`. A `BitOr` outside every annotation still builds its mutation, so the
  change removes no real mutation. The floor case reads the four `BitOr` nodes of the
  fixture, so a reader that names nothing fails rather than passes an aggregate over an
  empty set. No file under `ja4plus/` changes and no fingerprint moves.
- **The `ruff` pin is exact, so the lint gate cannot change without a commit** (#378).
  Round 161. `pyproject.toml` declared `ruff>=0.6`. `pip` therefore resolved the newest
  release at the moment of each install, and the gate read a different tool on two days.
  The `dev` extra now states `ruff==0.16.2`. **#297 measured the drift on this
  repository.** Against `ruff` 0.14.5 it read 58 `F401` findings, 28 files and 82 `I001`
  findings. Against 0.16.2 it read 54, 27 and 76. The tree did not change and every number
  differed. #297 changed no pin, because the pin sat outside its scope. **The project
  manager ruled the exact pin.** It declined a compatible range and it declined the
  recorded drift. A gate whose result depends on the day it runs measures something other
  than what it names. **The pin moves what this gate installs today not at all.** That is a
  measurement and not an assumption. `pip index versions ruff` reports 0.16.2 as the newest
  release, so the floating specifier already resolved it. Both lint commands report no
  finding before the change and after it. **The pinned release therefore reports no finding
  the floating one did not**, which is the condition the plan asked a worker to report
  rather than repair. **The `dev` extra is the one place a tool reads the version from, and
  three readings state it.**

    1. No file under `.github/workflows/` names `ruff` with a version specifier.
    2. Every job of `.github/workflows/test.yml` installs the extra.
    3. The tracked `requirements.txt` names no `ruff`.

  **New file `tests/test_lint_gate_pin.py` holds 6 cases.** The entry is one exact pin. The
  comment beside it cites #378. That comment states that a version change is a commit. No
  workflow states a version. No second dependency file states one. The installed release
  equals the pin. **The tests came first.** The unrepaired tree failed 4 of the 6 with
  `AssertionError: the dev extra states no exact version for ruff: 'ruff>=0.6'`. **Eleven
  mutations prove the cases discriminate, and each one isolates to the case it targets.** A
  pin of 0.16.1 fails the installed-release case alone. A comment that drops `#378` fails
  the citation case alone. A comment that drops the word `commit` fails the commit rule
  alone. **The comment reader binds to the pin and not to the list.** The pin moved above
  its own comment gives the empty string, and it fails both comment cases. A workflow that
  appends a specifier fails the workflow case alone. A `ruff` line appended to
  `requirements.txt` fails the dependency-file case alone. A second `ruff` entry fails the
  pin case. The floating specifier restored fails the pin case and the installed-release
  case. **Each mutation restored from a snapshot of the implemented tree.** The first
  harness restored from the index instead, and it contaminated six of its own readings.
  **The self-review found three defects in the first form of this file, and three more
  mutations prove the repairs.** All three are the shape this project records most often: a
  case that cannot fail.
  - **A substring test read the comment of the wrong entry.** The reader matched the line
    that held `"ruff`. A decoy `ruff-lsp` entry above the pin, with a one-line comment of
    its own, satisfied both comment cases while the pin carried no comment. `_distribution`
    now compares the whole name, and the decoy fails both cases.
  - **The specifier pattern missed a one-character operator.** It read `[=<>!~]=` and
    demanded a trailing `=`, so `ruff>0.6` escaped it. That is the shape of the specifier
    this pin replaced. The pattern now reads `ruff>0.6`, `ruff===0.16.2` and
    `ruff[extra]==1.0`, and a workflow that appends `"ruff>0.6"` fails the workflow case.
  - **The shared list parser counted a string inside a comment.** `_dependency_block` of
    `tests/test_documentation_site.py` collects every double-quoted substring of the block,
    and the `dev` extra carries comments inside its brackets. It already returned
    `not spec_validation` from the comment beside `build>=1.0`. A comment that quoted
    `"ruff==0.14.5"` would have failed a case on the wording of a comment, which is a check
    a rewording defeats. `_dev_entries` strips the comment lines first, and such a comment
    now moves no case. `_dependency_block` stays correct where it is used, because the
    `docs` list and the runtime list carry no comment inside the brackets.

  **The case that reads the installed release catches a drifted environment.** It skips
  where the environment holds no `ruff`, so a reader of the skip sees the gap. **A case here
  reads no prose.** This entry quotes the pin inside backticks, and no tool installs from a
  record. **`FR-foundation-8b` and `FR-foundation-8c` carry the two requirements.** Two
  behaviour rules of `docs/specs/features/00-foundation.md` state the cost. A pinned tool
  falls behind, and a bump re-measures the lint gate and the `ignore` list of
  `[tool.ruff.lint]`. The `Terms` table gains `pin` and `lint gate`. **Two findings reach no
  repair here, because both sit outside the acceptance criteria of #378.** `mypy>=1.11`
  resolves 2.3.0 and `pytest>=7.0` resolves 9.1.1, so the same defect stands on the rest of
  the `dev` extra. The tracked `requirements.txt` states `pytest-cov>=3.0.0` against the
  `>=5.0` of `pyproject.toml`, and the comment beside that entry states why the coverage
  floor needs 5.0. #446 carries both, and it holds the `mypy` question open rather than pin
  by symmetry. **No file under `ja4plus/` changes and no fingerprint moves.**

- **The record names the two breaking changes it never captured** (#395). Round 141.
  #65 found both gaps while it wrote `docs/migration-0.6-to-1.0.md`, and it stated each one
  in a row rather than hide it. This round records them. **The removal of
  `ja4plus.collector` now holds an entry of this file under round 71**, which
  `docs/specs/spec.md` already carried. **The move of the Python floor holds the new round
  135 in both files**, because neither file recorded it. **A comparison between two records
  finds no change that is absent from both sides.** #302 holds `CHANGELOG.md` and
  `docs/specs/spec.md` to the same round for every entry that exists in both. The two files
  recorded the Python floor nowhere, so they agreed and both were wrong. **New file
  `tests/test_breaking_change_record.py` compares the record against the package instead.**
  It holds the 25 modules of version 0.6.0, which `git ls-tree -r --name-only v0.6.0
  ja4plus/` reports, and it reads each one with `importlib.util.find_spec`.
  `ja4plus.collector` is the one module the package drops. It reads `requires-python` out
  of `pyproject.toml`, and it requires both files to name the value. **Three of the six
  cases failed on the unchanged branch and three passed.** Two mutations prove the cases
  discriminate: a floor of `>=3.10` fails the two floor cases, and `ja4plus/collector.py`
  restored from the tag fails `test_a_removed_module_reaches_no_importer`. **A sweep of `v0.6.0..HEAD` found no
  third gap**, and the pull request holds the whole table. **No file under `ja4plus/`
  changes and no fingerprint moves.**

- **BREAKING — `requires-python` moves from `>=3.8` to `>=3.9`** (#76). Round 135.
  **This entry is the record that was missing.** Commit `02ee772` raised the floor on
  2026-08-06, and no round recorded the move. Round 4 covers Epic 0 and it names #27 alone.
  Python 3.8 reached its end of life in October 2024. **A user on Python 3.8 cannot install
  version 1.0.0**, because `pip` reads `requires-python` and refuses the distribution. The
  `Programming Language :: Python :: 3.8` classifier left `pyproject.toml` in the same
  commit, and `README.md` states the same floor. Continuous integration runs Python 3.9
  through Python 3.13. #65 found the gap while it wrote `docs/migration-0.6-to-1.0.md`, and
  #395 records it here. `tests/test_breaking_change_record.py` reads the value of
  `requires-python` and requires both files to name it.

- **The README states eleven of the twelve FoxIO methods, the two contracts and the four
  default bounds** (#62). Round 136. The README claimed "all ten JA4+ methods". FoxIO
  publishes twelve, and `technical_details/README.md:5-16` at the pinned commit lists
  JA4LS and JA4TScan as rows of their own. **The claim was false in two directions**: the
  project builds no JA4TScan, and it builds JA4LS, which the table never named. **The
  issue body and `docs/specs/features/08-documentation.md` each say ten of the twelve,
  and eleven is the number.** `JA4LFingerprinter` writes both `JA4L-C=` and `JA4L-S=`, so
  ten fingerprinters carry eleven methods, and the count of ten counts fingerprinters.
  `docs/specs/spec.md:42` already read eleven. The method table now holds twelve rows and
  an `Implemented` column, and JA4TScan alone reads `No`. **The README states the four
  default bounds in one table**: 10000 entries and 600 seconds for a state table, 10000
  connections and 300 seconds for the monitor. **The concurrency contract and the
  independent-implementation sentence were already present**, so two new cases record
  that rather than change prose. `tests/test_readme_contracts.py` holds fifteen case
  functions, and each reads its number out of `ja4plus/` instead of restating it. Four
  mutations prove them, and the mutation of `DEFAULT_MAX_CONNECTION_AGE` to 900 in the
  code is the one that proves the bound cases read the code. **The self-review then
  evaded three of the cases**, with a name left in a comment, a fresh wording of the
  coverage claim, and a sentence that undercuts itself while keeping the words. All
  three now fail, and two cases were added that tie the prose count to the table. No file under `ja4plus/`
  changes and no fingerprint moves.

- **Four QUIC and certificate readers name the errors they expect, and ten wide catches
  state why they stay wide** (#319). Round 133. `grep -rn "except Exception" ja4plus/`
  reads 14 sites across five files. **#319 is a reading of all fourteen, and it narrows
  the four that `CLAUDE.md` binds.** A parser that cannot read a packet returns nothing,
  and it does not raise. `decrypt_quic_initial_crypto`, `decrypt_quic_server_initial_crypto`
  and `parse_quic_initial` of `ja4plus/utils/quic_utils.py` now name `IndexError`,
  `ValueError` and `InvalidTag`. `compute_ja4x_from_pem` of `ja4plus/__init__.py` now
  names `ValueError` and `x509.InvalidVersion`. **`InvalidTag` and `InvalidVersion` each
  inherit `Exception` and not `ValueError`**, so a list of `ValueError` alone drops a real
  packet and a real certificate. A fuzz of 90000 datagrams and a second fuzz of 40005
  decrypted payloads measured the set. A bound of 16384 bytes on the reassembled
  ClientHello proves that `struct.error` reaches no site. **The three sites of
  `ja4plus/processor.py` hand each failure to the caller, and #45 decided that.** The five
  sites of `ja4plus/cli.py` and the two of `ja4plus/ja4db.py` report a failure and return.
  Each of those ten now carries a comment that states the reason.

- **The QUIC frame reader returns the frames it read when a CRYPTO frame is truncated**
  (#382, absorbed by #319). Round 133. The CRYPTO branch of `parse_crypto_frames` read a
  varint behind the frame type byte and guarded no index. A plaintext that ends on that
  byte made `_decode_varint` raise `IndexError`. **Two of the three callers call that
  reader outside their handler**, so the error reached the caller of a parser, which
  `CLAUDE.md` rule 2 forbids. **The defect is remotely triggerable by construction**,
  because the Initial keys derive from the destination connection ID that the packet
  carries in the clear. The branch now holds the guard its own ACK branch already used.
  The defect predates #319, and the same datagram raises the same error against the base
  commit. **No fingerprint moves, and the conformance suite reports 134 xfailed against
  134 register keys.**

- **JA4L emits one server value for one connection, and the six open JA4L register
  entries now hold a live owner** (#272). Round 130. `ja4plus/fingerprinters/ja4l.py`
  returned the server value on every SYN-ACK, so a retransmitted SYN-ACK repeated the
  value the first SYN-ACK gave. A retransmitted SYN-ACK moves neither the server
  measurement point nor the server TTL, so the repeat described no second measurement.
  **`ssh2.pcapng` stream 15 is the one vector that reaches the rule**: the FoxIO Python
  file holds `JA4L-S=6252_58` once, and `ja4plus` produced it twice. A replay of the 38
  committed captures moved exactly one value, and it is that duplicate. No JA4L value
  moved on any other capture. **#272 declines five of the six entries instead of
  repairing them, because the comparison is unreachable and not satisfied.**
  `CVE-2018-6794.pcap`, `https-connect.pcap` and `tls-handshake.pcapng` publish no JA4L
  key at all, because `python/ja4.py:339` runs
  `delete_keys(['JA4L-S','JA4L-C'], final)` when the generating run names another
  method. This project was never emitting more than the reference. The reference
  published nothing to compare. `tests/foxio_deviations.json` falls from 135 keys to
  134, and the conformance suite falls from 135 `xfailed` to 134.
- **`ruff` enforces the F401 rule, and 54 unused imports are gone** (#297). Round 131.
  `pyproject.toml` no longer holds `F401` in the `ignore` list of `[tool.ruff.lint]`.
  **Every count the issue recorded is stale.** The issue read 58 findings across 28
  files on `issue/47-py-typed` at `ruff 0.14.5`, and this round reads **54 findings
  across 27 files** on `batch/362-hygiene-three` at `ruff 0.16.2`. The `ignore` comment
  recorded 82 I001 findings, the rule reports 76, and the comment now states 76.
  **`ruff --fix` decides no removal here, because an unused import is not always
  unused.** This round classified all 54 first, against five shapes: a side-effect
  import, a re-export, a `TYPE_CHECKING` import, a test helper, and a genuinely unused
  name. All 54 are genuinely unused. No consumer imports a flagged name from a flagged
  module, and no file that holds a finding declares `__all__` or a `TYPE_CHECKING`
  block. **No import statement under `ja4plus/` loses every name**, so every
  `scapy.all` line keeps `Packet` and no module-level side effect disappears. 15
  findings sit under `ja4plus/fingerprinters/` and `ja4plus/utils/`, and the
  conformance suite proves each removal inert: 1531 passed, 143 skipped and 135 xfailed
  before the change and after it, against 135 register keys. The unit suite reports
  2212 passed, 2 skipped, 8 xfailed and 96 subtests before and after. Coverage holds at
  93, and the missed line count stays at 287. **No fingerprint moves.**

- **The lookup cache remembers no key it evicts, and it saves 16.06 MiB** (#359).
  Round 129. `StateTable` remembers the key of every entry it evicts, and that memory
  buys `returned_connections`. `Processor.stats` collects the state tables of the
  fingerprinters, and `JA4DBClient` is no fingerprinter, so nothing under `ja4plus/`
  reads the count for the lookup cache. `BoundedStateTable` now takes
  `track_evictions`, it defaults to True, and every existing caller keeps the statistic
  it had. The lookup cache is the one caller that states False. **A full lookup cache of
  100000 entries falls from 47.06 MiB to 31.00 MiB under `tracemalloc`.** It falls
  from 44.66 MiB to 28.60 MiB under `sys.getsizeof`. The two methods agree on the saving to
  0.00 MiB. The eviction count stands, so FR-concurrency-safety-12 holds for this table,
  and the invariant `inserts == entries + evictions + removals` holds. **#279 measured
  the 512 MiB ceiling case without a lookup cache**, so this saving moves none of its
  four runs. No file under `ja4plus/fingerprinters/` changes, no fingerprint moves, and
  the register holds 135 keys against 135 xfailed. **A first form of the new cases
  turned the resident-memory control of #279 red**, because each one loaded the whole
  mapping file into the session. The cases now patch `load_mapping_file` to an empty
  mapping. A deselect run proves that the production change causes none of it.

### Fixed

- **The documentation extra pins a `mkdocstrings` the site can build with** (#391).
  Round 140. `mkdocstrings==1.0.6` installed and the build then failed with
  `ModuleNotFoundError: No module named 'mkdocstrings.handlers'`.
  `mkdocstrings_handlers/python/handler.py` of the 1.x line imports that module, and
  `mkdocstrings` 1.0.0 removed it. The pin is now `mkdocstrings==0.30.1`, and no other
  version moves. **An exact pin can still be an incompatible pin**, which is why
  `test_every_documentation_dependency_pins_one_version` passed while the site did not
  build. **Two records measured the wrong artifact.** #64 built the site inside a virtual
  environment that an earlier resolution had already filled. The gate then repeated that
  measurement in the same environment. Nobody installed the committed set from
  scratch. `.github/workflows/docs-build.yml` installs the `docs` extra alone into an
  empty environment, runs `mkdocs build --strict`, and reads the `Processor` docstring
  and the ten one-shot functions back out of the generated HTML. It runs on a change to
  `pyproject.toml`, to `mkdocs.yml` or to `docs/`. **The steps of the job run red on
  `da2338d` and green on the repair**, on macOS with Python 3.11 and on Linux with Python
  3.12. `test_the_mkdocstrings_pin_holds_the_handler_module_its_handler_imports` states
  the upper bound as text, so a reader of `pyproject.toml` alone still sees it. No file
  under `ja4plus/` changed and no fingerprint moved.
- **Every entry of this file states the round its specification row states** (#302).
  Round 134. Eight entries read `Round TBD` while `docs/specs/spec.md` had already
  assigned their round. A reader who follows such an entry reaches nothing, and version
  1.0.0 is close. **Each entry names the round its row records, and this repair invents
  no number, adds no row and moves no number.** Three entries of Epic 4 name round 90,
  which is the Epic 4 shipment row and already records all three pieces of work in the
  words the entries use. #258 settled that shape, because a repair folds a detail into
  the shipment row and renumbers no row. The other five name rounds 122, 118, 122, 104
  and 102. **Each match reads what the two records state and not the issue number**,
  because #59 carries two entries against one round, and rounds 123 and 124 are the rival
  candidates and each is already taken, 123 by #364 and 124 by #368. **No prose of the
  eight entries changes**, and the eight lines differ by the round word alone.
  `tests/test_changelog_round_agreement.py` holds the invariant. **It bars no `TBD`.** A
  guard that barred the literal word would fail on every integration branch, because the
  batch model requires a member to write it and the project manager to assign the number
  at the batch gate. The guard instead compares the two files against each other, so the
  ten unassigned entries of this branch stay untouched. **Five of the eight orphans hid
  behind a defect in the guard itself.** The round pattern read a literal space, the file
  wraps at 90 columns, and `Round` therefore ends one line and `  TBD.` opens the next on
  five entries. The parser read 36 entries where 41 exist and skipped all five, so the
  guard reported green over the defect it exists to report. **A comparison that never
  runs reads as a comparison that passes**, and this project records that fault sixteen
  times. **The floor recorded the fault rather than the fault reporting the floor**: it
  read 36, which is the count the broken parser produced, so it could never fire. It now
  reads 41 from the corrected parser. Seven mutations prove the guard, and the two that
  wrap a round sentence are the pair the first five could not reach. No file under
  `ja4plus/` changes and no fingerprint moves.

- **The marker rule states the decided-entry count the register holds, and a case
  holds it there** (#345). Round 132. The `## The marker rule` section of
  `tests/foxio_deviations.py` read `38 of the 128 decided entries`. The register holds
  134 decided entries of 134 keys, measured on the base commit `f238c15`. **The
  denominator went stale twice**, because nothing measured it. #341 found the first
  drift at 129. #272 then removed one entry and decided five inside this batch. **The
  numerator of 38 was correct**, and the 38 are still the 34 entries of #138 and 4 of
  the 5 entries of #151. `TestTheMarkerRuleCounts` in `tests/test_foxio_deviations.py`
  now reads the two counts out of the prose and measures them against the register. The
  next move of the register therefore fails a case, where the count sat unmeasured in a
  docstring before. The case failed on the unchanged prose with `assert 128 == 134`.
  Three mutations prove that it fails when the register moves and the prose does not,
  and each run restored the file it moved. No register entry changed, no file under
  `ja4plus/` changed, and no fingerprint moved.
- **The `capability` field alone bars the rows of #129** (#347). Round 127.
  #341 shipped the field on all 135 register entries and reported that it could not
  prove the one thing it exists for. **The bar stood twice**: once in the field, and once
  in an absent measurement. #334 measured the 35 source values of #129 and left them out
  of `SOURCE_VALUES`, and `test_no_measured_row_records_a_capability_decline` asserted
  the exclusion. Flipping the field on a #129 entry therefore moved nothing, and no case
  failed. **This round measured the 35 rows against the pinned FoxIO checkout**
  `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` and put them in the table. It resolved every
  Wireshark frame number against its capture with `scapy` and read the 5-tuple, which is
  the method #334 recorded. **The reading corroborates itself**: all 16 Wireshark JA4H
  values and all 3 Wireshark JA4X values equal the FoxIO Python values at the same
  occurrence. Two of the 37 rows carry no source value, and they are
  `chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4X.1` and `JA4X.2`. Neither the
  Rust snapshot nor the Wireshark file holds a JA4X value for that capture.
  **The reach holds at 6 rows, and the measurement the field now permits reads 25.**
  With `capability` false on all 43 #129 entries, live on disk, the reach rises from 6 to
  25 and returns to 6 after the restore. On the base file the same flip reads 6 and 6.
  The 19 rows that enter are the 16 JA4H_ro rows and the 3 JA4X rows; the 16 JA4H rows
  stay out because the Rust value and the Wireshark value differ.
  `test_no_measured_row_records_a_capability_decline` is renamed to
  `test_every_measured_capability_row_names_the_issue_the_bar_exists_for`. The new name
  holds the one meaning the exclusion did not carry: a measured capability row names
  #129, and a row under another issue reaches a bar no measurement has read. No file
  under `ja4plus/` changes, no register entry changes, no fingerprint moves, and the
  register holds 135 keys against 135 xfailed.

- **Every Changelog round number of the specification names one row** (#258). Round 128.
  `docs/specs/spec.md` carried the number 9 on two rows, and a round number is a citation
  target. **The two rows are not two rounds.** One row records the shipment of Epic 1
  batch 1, and it names #80 as a member. The other row details #80 on the same date.
  **The repair folds the detail row into the shipment row, and it renumbers no row.** The
  fold preserves every sentence of the folded row. **A round number is an identifier, and
  it states no order.** The date column carries the order. Rounds 10 through 124 are all
  taken, so no free number sits beside the number 9. A renumber of the rows above it
  would break every citation of a round number. Those citations carry weight: round 67
  holds the #226 part e decision, and #215 and #226 cite it. **Three premises of the issue
  were stale, and this round measured all three again.** The ruling named `spec.md:542`
  and `:546`, and the rows were at 569 and 573. The ruling named 88 as the highest round,
  and the highest was 124. The ruling searched `[Rr]ound 9\b` and found no citation. That
  pattern misses the one citation that exists. Round 12 closed with "The rounds below hold
  two entries numbered 9". The fold makes that sentence false, so round 12 now records the
  repair. `tests/test_specification_changelog.py` holds the invariant. Both of its cases
  fail when the duplicate returns. No file under `ja4plus/` changes, no fingerprint moves,
  and the register holds 135 keys against 135 xfailed.

- **The example that a merge restored is absent again** (#368). Round 124.
  #56 removed `examples/monitoring_daemon.py` and added
  `tests/test_watch_capture.py::TheExampleDaemonIsAbsent`, which asserts that the file
  stays absent. `batch/322-hygiene-two` forked from `dev` before that case landed, so
  its own run never collected the case, and its merge `8b87c20` restored the file. **Both
  parents of the merge were green and the merged tree was not**, because the file and the
  case live in different directories. `dev` then ran red across `35bdfab` and `8ef8acc`.
  The case
  fails on the base commit `8ef8acc` and passes after the removal. `ja4plus watch` is
  the supported monitor, and `docs/usage.md` documents it. No file under `ja4plus/`
  changes, no fingerprint moves, and the register holds 135 keys against 135 xfailed.
- **The statistics interval cases state the schedule rather than sample it** (#369).
  Round 125. `TheReporterWritesOneLinePerInterval` started the reporter at a 0.05 second
  interval, slept a fraction of a second, and counted the lines that arrived. That count
  measures how promptly the host schedules a thread. The `macos-latest, 3.12` job of the
  run for `8ef8acc` read 2 lines where the case asked for 3, and `dev` went red on a
  package that holds no defect. `StatisticsReporter` gains a `wait` parameter, which
  receives the interval and returns True when the stop arrives. The default waits on the
  stop event, and `ja4plus watch` passes no other call, so the shipped behaviour is
  unchanged. Each case now drives the reporter from a scripted wait and reads an exact
  line count. The class asserts the interval the reporter passed to the wait, which is
  what FR-live-capture-9 states, and it sleeps not at all.

- **The Zeek reference page reads the current comparison** (#327). Round 113.
  `docs/specs/foxio/zeek.md` read as though #214 were open, in three places. #214 made
  JA4SSH emit the window a connection holds open when the capture ends, so `ssh2.pcapng`
  now produces `c36s52_c42s76_c51s2` as its second value, which the Zeek baseline holds.
  The re-run against the pinned FoxIO checkout prints 98 rows, of which 63 match and 35
  differ, where round 52 read 98 rows, 62 match and 36 differ. **The page now names the
  Changelog round of every run it cites**, so a reader can tell a stale count from a
  current one. **One value rating no longer follows from its evidence, and #327 leaves it
  `Undecided`**: the JA4SSH baseline was `Blocked` on #214, and the replacement rating is
  a precedence question the user decides. **#332 answers that question.** No file under
  `ja4plus/` changes, no fingerprint moves, and the register holds 135 keys against 135
  xfailed.

- **The Zeek baseline comparison script runs again, and a case now runs it** (#324).
  Round 112. `tests/compare_zeek_baselines.py` read the composite `source` field that
  #49 removed, so the script raised `KeyError` on the first output line it parsed. The
  reader now reads `src_ip`, `src_port`, `dst_ip` and `dst_port`, which
  `docs/output-schema.md` states, and `split_source` goes away because nothing needs it.
  The reader also reads `schema_version` first and stops on a version above 1, which the
  same page states. **The script is evidence-producing tooling, not dead code**:
  `docs/specs/foxio/zeek.md` rests on it, and #198, #226 and #276 reason from its
  readings. `tests/test_compare_zeek_baselines.py` runs the script end to end over
  `dhcp.pcapng`, so a later schema change fails a case instead of breaking the script in
  silence. No fingerprint moves, no output field changes, and the schema version stays 1.

### Changed

- **The package states a memory ceiling of 512 MiB** (#279). Round 126. One
  `Processor()` at the shipped defaults reads 1000000 packets across 100000 distinct
  connections and holds resident memory below 512 MiB. Four runs measured 383.47 MiB,
  388.25 MiB, 392.05 MiB and 394.94 MiB, and the highest is 77 percent of the ceiling.
  `README.md` and `docs/api_reference.md` each carried the sentence "This package states
  no memory ceiling", and each now states the number, the defaults the ceiling holds at,
  and the boundary of the claim.
  `docs/specs/features/03-concurrency-safety.md` states the whole measurement. **The
  ceiling covers that packet run and no longer run.** Each fingerprinter keeps every
  fingerprint it produces and that list holds no bound, so resident memory keeps rising
  after every state table settles, at about 23 MiB for each 100000 packets. The same
  traffic passes 512 MiB at 1500000 packets, where it reads 513.06 MiB. New file
  `tests/memory_ceiling_run.py` measures one packet run in an interpreter of its own,
  because `resource.getrusage(RUSAGE_SELF).ru_maxrss` reports the high-water mark of the
  whole process. No file under `ja4plus/` changes and no fingerprint moves.
  **The two controls beside the ceiling now read the current resident set, because two
  high-water marks subtract to no growth.** A mark rises and never falls, so the
  difference between two of them states `max(0, later mark - earlier mark)`. The import
  of scapy reaches a mark on Ubuntu that the traffic run then stays below, and the four
  Ubuntu jobs of pull request #384 read `idle_mib 154.7` and `peak_mib 154.7` for a run
  that allocated tens of MiB. The ceiling itself is a claim about the mark and it stands
  unchanged, and the run now also reports `idle_resident_mib` and `final_resident_mib`
  from `/proc/self/statm`, or from `ps` on Darwin. `traffic_growth_mib` refuses a
  high-water pair as a void measurement, and `TestTheGrowthReading` measures that refusal
  against the Ubuntu numbers on every platform.

- **The documentation states what a fingerprint is evidence of** (#343). Round 110.
  ja4plus adds no plausibility guard, so a structurally valid ClientHello produces a
  fingerprint whatever its body holds. This change records the behaviour and changes
  none of it, so no file under `ja4plus/` moves. A fingerprint is evidence of the bytes
  the packet carried, and it is no evidence of a real client. `README.md` and
  `docs/output-schema.md` now
  state the property where a user reads it, and the `Divergence register` of
  `docs/specs/spec.md` holds the measurement.
- **The register records the kind of every decline** (#341). Round 116.
  `tests/foxio_deviations.json` carries a `capability` field on all 135 entries, and
  `CAPABILITY_DECLINES` is gone from `tests/test_precedence_exception.py`. #334 shipped
  bar 1 of the precedence exception as a constant set of issue numbers, so a new
  capability decline would have reached the exception unless somebody edited a test that
  named it nowhere near the decline. **`true` records a capability this project chose not
  to build, and `false` records a disagreement about the value.** `tests/foxio_deviations.py`
  reads the field beside `decided` and states the default in the schema, and
  `unrecorded_kinds` requires the field on every decided entry. **43 entries record a
  capability decline, and all 43 name #129**, which the recorded cause of each of the 135
  entries decides. No entry was undeterminable. **The reach of the exception is 6 rows
  before and after**, and the six rows are unchanged. No fingerprint moves, no file under
  `ja4plus/` changes, and no vector is adopted.

- **The precedence exception is source-neutral** (#334). Round 115.
  `.claude/rules/external-apis.md` wrote the exception of #332 for the Zeek baseline
  alone, because that was the case #327 raised. Where `tests/foxio_deviations.json`
  declines the FoxIO Python value under a decided entry, **any other FoxIO implementation
  may hold the reference value** for that method on that connection. **Two bars stand
  above the rule.** A decline that records a capability this project chose not to build
  reaches no row, and #129 is that case: `ja4plus` reads no encrypted request by
  decision. Where the remaining FoxIO sources hold different values, no source holds the
  reference and the row stays declined. **The exception reaches 6 rows of the 135 the
  register holds**, where the widened rule before the bars reaches 58.
  `tests/test_zeek_precedence_exception.py` becomes `tests/test_precedence_exception.py`
  and measures the reach against every source. **Three findings came out of the search.**
  The register records no field that separates a value decline from a capability decline,
  and the rule states a proposal for one. `gre-erspan-vxlan.pcap/0:65174/JA4T.1` carries
  the value form and declines no Python value, so the rule now reads that fact from the
  vectors. The Wireshark dissector appends the third part that bars a Zeek JA4L value,
  which the bar does not name; #225 records that this project adopted the `quic` marker
  from the dissector on purpose, so nothing there changed. **No vector is adopted, no
  register entry changes, no file under `ja4plus/` changes, and no fingerprint moves.**

- **A declined FoxIO Python value forfeits its precedence** (#332). Round 114.
  `.claude/rules/external-apis.md` states that `python/test/testdata/` decides where it
  and a Zeek baseline both hold a value for one method on one connection, and it named no
  exception for a value this project already ruled wrong. The rule now carries one
  exception: where `tests/foxio_deviations.json` declines the Python value under a decided
  entry, a Zeek baseline may hold the reference value for that method on that connection.
  **Python keeps its precedence everywhere else.** **The condition is one recorded decline
  that names an issue, and no reading of which value looks right reaches it.** An
  undecided entry is an open question, and the exception passes over it.
  `docs/specs/foxio/zeek.md` now rates `Scripts.ja4-ssh2/ja4ssh.log` Medium and states the
  reason, where #327 left it `Undecided`. `tests/test_zeek_precedence_exception.py`
  measures the reach: the exception reaches 1 row of the 135 the register holds, and that
  row is `ssh2.pcapng/14:57377/JA4SSH.2` under #97. **No baseline is adopted as a vector**,
  no file under `ja4plus/` changes, and no fingerprint moves.

- **The vocabulary settles one word for the serialized output line** (#306). Round 111.
  The `## Terms` table of `docs/specs/spec.md` listed `record` in the `Do not use`
  column of `result`, and `ja4plus/output.py` used it as a noun in five places. #50
  found that and reworded its own page rather than the shared table. The table now holds
  the term `output line`, whose `Do not use` column names `record`, `result` and
  `entry`. **A result and an output line are two things.** A result is one fingerprint
  one method produced. An output line carries every field of the result, plus
  `schema_version` and `identified_as`, which the command-line program owns. The word
  now reads the same way in `ja4plus/output.py`, `ja4plus/cli.py`, `README.md`,
  `tests/test_output_schema.py`, `tests/test_cli.py`, `tests/test_parity.py`,
  `tests/compare_zeek_baselines.py` and `examples/monitoring_daemon.py`.
  `docs/output-schema.md` already used it and needs no change. The `json` format writes
  one output line as one JSON object, and the `csv` format writes it as one row, so the
  identifier for a parsed line is now `json_object`. **The word `record` keeps two other
  meanings that this term does not touch**: the verb, as in `#215 records the reading`,
  and the TLS record of RFC 8446. **No field name and no column name moved.**
  `schema_version` stays 1, `CSV_COLUMNS` holds the same eleven names in the same order,
  and `ja4plus.__all__` names the same 25 entries. A replay of the 38 committed captures
  in all three formats produces 114 runs, 2466 output lines and 0 differing bytes
  against the base. Both suites report the counts of the base: 1839 passed and 8
  xfailed in the unit suite, and 1531 passed, 143 skipped and 135 xfailed in the
  conformance suite, against 135 keys in `tests/foxio_deviations.json`.

### Added

- **The site carries a page per method, the output schema and the migration page**
  (#65). Round 139. `docs/methods/` holds eleven method pages and an index. **FoxIO
  publishes twelve methods, this project implements eleven, and ten fingerprinter classes
  carry the eleven**, because `JA4LFingerprinter` writes `JA4L-S=` at
  `ja4plus/fingerprinters/ja4l.py:446` and `JA4L-C=` at `:482`. The set was measured
  against `__all__`, against `VALID_TYPES` of `ja4plus/cli.py:51` and against the README
  table of #62, and the three agree. **JA4TScan reaches no method page**, because this
  project declines it, and `docs/methods/index.md` holds the twelve-row table and states
  the decline. **Every value on a method page is a claim, and
  `tests/test_method_pages.py` holds 144 cases against the code.** Each page carries a
  `## The facts` table that a parser reads: the `--types` token against `VALID_TYPES`,
  the class and the one-shot function against `__all__`, the hash rule against the
  `hexdigest()[:12]` its own module holds, and the FoxIO file against the inventory of
  `docs/specs/foxio/README.md`. **The example table of each page names a committed
  capture and a value, and the case runs the capture and compares.** 142 of the 144 cases
  failed on the unchanged base, and five mutations prove they discriminate.
  **`docs/output-schema.md` already existed, so this round extended it rather than adding
  a second schema page.** Its `## The raw forms` table was prose that no case read, and a
  case now runs the capture of each method page and compares the two raw fields. A
  `## The method of each output line` section links the ten `type` values to the eleven
  pages. `docs/concurrency.md` restates the contract of `README.md`, and two cases read
  the two default bounds out of `ja4plus/utils/state_table.py`.

- **The site carries a migration page for the move from version 0.6.0 to version 1.0.0**
  (#65). Round 139. `docs/migration-0.6-to-1.0.md` lists eleven breaking changes with the
  old form, the new form, the reason and the round, plus the seven fingerprints that
  move. **The issue body listed five breaking changes and the record holds eleven.**
  **Two gaps in the record are findings and this round repairs neither.** `CHANGELOG.md`
  holds no mention of `ja4plus.collector`, which round 71 of `docs/specs/spec.md` records
  alone. **The Python floor moved from 3.8 to 3.9 and no Changelog round records it in
  either file**; it shipped in commit `02ee772` under #76, and round 4 names #27 alone.
  The migration page states that gap in its row rather than hide it. FR-documentation-13
  belongs to #66, so this round writes no release notes.

- **The documentation site builds from the Markdown files that already exist** (#64).
  Round 137. `mkdocs.yml` at the repository root configures MkDocs 1.6.1 with the
  Material theme 9.7.7. `docs_dir` is `docs/`, so no page moves. Build the site with
  `pip install -e ".[docs]"` and `mkdocs build --strict`. `docs/specs/` stays out of the
  site, because the specification package is design material. The new `docs` extra holds
  every generator, and no entry of it reaches the runtime dependencies, so a user who
  installs `ja4plus` installs no site generator. Every version in the extra is exact.

- **The site carries an API reference the docstrings generate** (#64). Round 137. The
  five pages under `docs/reference/` name objects rather than describe them, and
  `mkdocstrings-python` 1.15.0 reads the docstrings of the source, so the reference
  cannot fall behind the code. The reference covers `Processor`, `ProcessorStats`,
  `FingerprintResult`, the ten fingerprinter modules and the lookup.

- **A broken internal link fails the documentation build** (#64). Round 137.
  `strict: true` fails the build on a warning, and `validation.links.anchors: warn`
  raises a broken anchor from information to a warning. Without the second setting the
  site builds while an anchor is dead. A link changed to a page that does not exist and
  a link changed to an anchor that does not exist each abort the build with exit code 1.
  `tests/test_documentation_site.py` carries the same check inside the unit suite, which
  installs no site generator. One of its cases is stricter than the build: a link into
  the excluded `docs/specs/` returns a 404 on the published site, and
  `mkdocs build --strict` reports it at the information level and still succeeds.

- **A `LookupResult` supports item access by field name** (#364). Round 123. Version
  0.6.0 returned a dict with the keys `application`, `type` and `notes`, and #59 replaced
  it with a frozen `LookupResult`. A caller that reads `result["application"]` keeps
  working for one major version, and that read emits a `DeprecationWarning` that names
  the attribute to read instead. Every key version 0.6.0 published names a field of
  `LookupResult`, so no key returns the value of another field. A key that names no field
  raises `KeyError` and emits no warning. Item access reads a field and writes none, so
  a `LookupResult` stays frozen. `FingerprintResult` holds the same behaviour from #44,
  under `FR-typed-api-5` and `FR-typed-api-6`.

- **`JA4DBClient.lookup_many` identifies many fingerprints in one call** (#59). Round
  122. It accepts a sequence of fingerprints and returns one entry per fingerprint. A
  miss holds `None`, so a caller reads one entry for every fingerprint it passed. The
  returned mapping keys the fingerprint, so a sequence that repeats a fingerprint holds
  one entry for it. The call reaches the lookup service under the rule that `lookup`
  holds, and under no other rule. A client built with `allow_remote=False` sends nothing,
  whatever count of fingerprints the call carries. A client built with
  `allow_remote=True` sends one request for each fingerprint the mapping file holds no
  entry for. The lookup cache holds a miss as well as a hit, so a repeated fingerprint
  costs one request and no more.

- **`--lookup-remote` and `JA4PLUS_DB_LOOKUP` ask for the remote lookup** (#58). Round
  118. `--lookup` reads the bundled mapping file and makes no network request.
  `--lookup-remote` identifies each fingerprint, and it sends every fingerprint the
  mapping file holds no entry for to `https://ja4db.com`. It asks for the lookup as well
  as for the disclosure, so an operator who passes it needs no `--lookup`.
  `JA4PLUS_DB_LOOKUP=1` permits the same request, for an operator who runs a command line
  another program builds. The variable permits the request on the value `1` and on no
  other value, and it asks for no lookup. The option and the variable each permit the
  request, and neither one refuses it, so `JA4PLUS_DB_LOOKUP=0` cancels no option. The
  command writes one notice to standard error for each run that permits the remote
  lookup. The notice names the lookup service and the two ways to stop the request, and
  it appears once whatever count of fingerprints the run looks up. Where the operator
  asks for the remote lookup and the `requests` package is absent, the command names the
  `lookup` extra and ends the run with the status 1.

### Changed

- **A lookup result is a frozen `LookupResult` and it records its source** (#59). Round
  122. Through version 0.6.0 `JA4DBClient.lookup` returned a dict with the keys
  `application`, `type` and `notes`. It now returns a frozen `LookupResult` that carries
  the same three fields plus `source`, so a caller reads `result.application` where it
  read `result["application"]` before. `LookupResult` of `lookup.go:23` carries the three
  fields, and `CLAUDE.md` parity rule 2 adopts them. The `source` field holds `embedded`
  for the mapping file that ships inside the package, `cache` for the file that
  `ja4plus db update` wrote to the cache directory, and `remote` for the lookup service.
  An analyst needs to know where a name came from to judge how much to trust it. The
  command-line output schema is unchanged, because the command writes the application
  name alone.

- **`ja4plus db update` writes to the cache directory, and the client prefers that file**
  (#61). Round 121. Through version 0.6.0 `db update` wrote the download over
  `ja4plus/data/ja4plus-mapping.csv` inside the installed package. That directory may be
  read-only, several users may share it, and the next `pip install` discards the file.
  `db update` now writes `ja4plus-mapping.csv` to the platform cache directory:
  `$XDG_CACHE_HOME/ja4plus` or `~/.cache/ja4plus` on Linux, and
  `~/Library/Caches/ja4plus` on macOS. It writes a temporary file and renames it, so a
  reader sees the whole new file or the file the last run wrote. It leaves the installed
  package byte for byte as it was. `JA4DBClient` and `ja4plus db info` now read the
  cached mapping file when one exists, and the bundled mapping file otherwise. A cache
  file that is empty, corrupt or unreadable falls back to the bundled file, and the
  client reports the problem at `WARNING`. `db info` reports the source on its first
  line, as `embedded` or `cache`, and it names the mapping file path on the second. The Go
  port publishes the value `embedded` for the file that ships inside the package, at
  `lookup.go:31`, and `CLAUDE.md` parity rule 2 adopts it. The prose of this project still
  calls that file the bundled mapping file. `db info` wrote the FoxIO address on a line
  named `Source` through version 0.6.0, and that line is now named `Mapping`. Where the
  source is `embedded`, `db info` names the cache file as well. It reports that the cache
  file holds no entry, or that no cache file exists.

- **The remote lookup is opt-in at the client** (#57). Round 117. Through version 0.6.0
  `JA4DBClient.lookup` sent every fingerprint the bundled mapping file held no entry for
  to `https://ja4db.com`, and no caller asked for that. A fingerprint describes traffic
  the operator observed, so each request told a third party what the operator watched.
  `JA4DBClient()` now performs no network request. `JA4DBClient(allow_remote=True)`
  permits one request per miss, and it is the only way to reach the service.
  `ja4plus --lookup analyze` and `ja4plus.ja4db.lookup` both hold the new default, so
  the command-line program makes no network request. #58 adds the command-line option
  that permits the remote lookup. The remote lookup waits 5 seconds at most, and
  version 1.0.0 is the first release that may make the interval configurable. A request
  that fails returns None and raises nothing. The lookup service publishes no versioned
  API document, so the client accepts one shape: an object that carries a non-empty
  `application` string. Version 0.6.0 read an object without that field as the
  application `Unknown`, and the client now reads it as a miss. `allow_remote` is the
  first parameter of the constructor, where `cache_size` was, so `JA4DBClient(100)` now
  raises `TypeError`. Write `JA4DBClient(cache_size=100)` instead. The client also
  escapes the fingerprint it puts in the request path, so a string that carries `/` or
  `?` names no other path on the lookup service.

- **The command-line program separates results from diagnostics and gains `--output`**
  (#52). Round 95. The program writes results to standard output and every diagnostic
  to standard error, so a pipe that reads standard output reads results alone. The
  progress line of `db update` moves to standard error. `--output FILE` writes the
  results to a file and leaves standard output empty. The program refuses to overwrite a
  file that exists and exits with the status 1, and `--force` overwrites it. Without
  `--force` the program creates the file, so it writes through no symbolic link and it
  loses no file to a second writer. A reader
  that closes the pipe early, such as `head -1`, ends the run with no traceback and no
  shutdown message. Every option now runs before the subcommand name and after it, so
  `ja4plus analyze capture.pcap --format csv` does what
  `ja4plus --format csv analyze capture.pcap` does. A capture that produces no
  fingerprint writes one line to standard error in the `table` format, and the `json`
  and `csv` formats keep the output the schema promises.

- **The command-line program runs on `Processor` and reports a fingerprinter error**
  (#51). Round 94. The program built its own dictionary of fingerprinters and ran its
  own per-packet loop in `analyze` and in `live`. Both loops caught every error with
  `except Exception` and continued without a word. The program now builds one
  `Processor`, so it gets the connection eviction of Epic 3 and the errors of Epic 4. A
  method that fails to read a packet writes one line to standard error that names the
  method, and the run continues. The program keeps no exception, because an exception it
  kept would hold the error chain of every packet it read. `--types` now selects which
  methods the program reports rather than which methods it builds, so the program evicts
  the connections of a method you filtered out and it reports that method's errors. The
  reported order is still the order you wrote in `--types`, and a name you write twice
  keeps its first position. No fingerprint value moved:
  the program writes the same 863 output lines over the 43 committed captures, byte for
  byte,
  and the conformance suite reports the same 1531 passed, 143 skipped and 135 xfailed.
  The unit suite rises from 1801 passed to 1814 passed, which is the 13 cases the change
  adds.

- **The command-line program writes the addresses and the ports as separate fields**
  (#49). Round 96. The `json` and the `csv` formats replace the composite `source`
  field of version 0.6.0 with `src_ip`, `src_port`, `dst_ip` and `dst_port`, so a
  downstream tool parses no composite string. The CSV header is now fixed at
  `schema_version,timestamp,type,fingerprint,raw,raw_original_order,src_ip,src_port,dst_ip,dst_port,identified_as`,
  and it no longer changes with `--lookup`. Every field is present in every output line:
  a field with no value is `null` in the `json` format and empty in the `csv` format.
  `identified_as` is therefore present without `--lookup`, where version 0.6.0 omitted
  it. Each output line also carries the packet `timestamp` in RFC 3339 form. New module
  `ja4plus/output.py` holds one writer per format. #50 documents the schema and its
  version.

- **`Processor.process_packet` returns a list of `FingerprintResult`** (#45). Round 90.
  The method returned a list of dictionaries through version 0.6.0. A caller who reads
  `result["fingerprint"]` keeps working for one major version, and item access emits a
  `DeprecationWarning` that names the attribute form. Read `result.fingerprint` instead.
  The results follow the fixed method order `ja4`, `ja4s`, `ja4h`, `ja4t`, `ja4ts`,
  `ja4l`, `ja4x`, `ja4ssh`, `ja4d`, `ja4d6`, and that order is part of the interface.
  `Processor.close_open_windows` still returns a list of dictionaries, because a window
  carries a connection key and no `FingerprintResult` field holds one. The processor
  reads no packet timestamp, so `timestamp` holds `None`. No fingerprint value moved:
  the conformance suite reports the same 1477 passed, 143 skipped and 137 xfailed.
  `docs/specs/features/04-typed-api.md` states FR-typed-api-3.

### Added

- **`ja4plus watch` stops on an interface that carries no traffic** (#320). Round 105.
  A monitor on a quiet interface exits within one second of `SIGINT` or of `SIGTERM`.
  `scapy` applies the `stop_filter` argument of `sniff` to a packet and to nothing else,
  and its capture loop waits in `select` without an end, so the monitor read the stop
  flag when the next packet arrived and not when the signal arrived. An operator who ran
  `systemctl stop` on such a monitor waited for the service timeout, and the host then
  sent `SIGKILL`, which skips the flush. The command now opens the capture socket itself
  and calls `sniff` with `opened_socket` and a timeout of 0.25 seconds, in a loop, and it
  reads the stop flag after each call. The socket stays open across the calls, so the
  monitor loses no packet that arrives between two of them. `--bpf` still applies, and
  `libpcap` now compiles the expression when the socket opens. The command still starts
  no thread other than the one `--stats-interval` starts.

- **`ja4plus watch` applies a capture filter and reads the capture failure** (#56). Round
  104. `--bpf FILTER` passes a Berkeley Packet Filter expression to the capture layer,
  which drops every packet the filter rejects. The command reads no user identity. It
  attempts the capture and reads the failure, so a Linux host that grants `CAP_NET_RAW`
  without granting the user identity zero runs the monitor. Version 0.6.0 read
  `os.geteuid() != 0`, which refused that operator and raised `AttributeError` on
  Windows, where `os.geteuid` is absent. The command now names `CAP_NET_RAW` and the
  `/dev/bpf*` devices for a refused privilege, lists every interface the host holds for
  an interface it does not hold, and repeats the filter error for an expression the
  capture layer refuses. Each of the three ends the run with the status 1. The command
  runs on Linux and on macOS, and it reports that Windows carries no monitor and ends
  the run with the status 1. `examples/monitoring_daemon.py` is removed, because
  `ja4plus watch` is the supported monitor and `docs/usage.md` documents it.

- **`ja4plus watch` reports statistics on exit and on a schedule** (#55). Round 103. The
  monitor writes one statistics line when it exits, and `--stats-interval SECONDS` adds
  a line for each interval that passes. Every line goes to standard error, so a pipe
  that reads standard output reads fingerprints alone. The line reports the packet
  count, the fingerprint count, the connection count, the eviction count, the
  dropped-packet count and the uptime. `MonitorStats` holds the four counts under one
  lock, and the capture thread publishes the two table counts, so the statistics thread
  reads no state table. The statistics thread is the only thread the command starts, and
  the command starts it only when the operator passes `--stats-interval`. The thread
  ends with the capture, so a termination signal stops the monitor and the thread
  together. The `dropped` field reads `null`, because `scapy` 2.7.0 reports no drop
  count to a caller of `sniff`; #326 records the measurement and the work that reports a
  count. The fingerprint count holds the trailing JA4SSH window that a capture leaves
  open, which the command writes and #214 decided.

- **`ja4plus watch` stops on a termination signal and flushes its output** (#54). Round
  102. `SIGINT` and `SIGTERM` both stop the monitor, and both end the run with the
  status zero. The handler sets a flag and returns. It calls `sys.exit` never, because a
  signal arrives at any point, including the point where the output holds half a line.
  `scapy` reads the flag through the `stop_filter` argument of `sniff`, and it applies
  that filter after it reports a packet, so the monitor finishes the line it writes. The
  command then flushes the output and exits, so the output file holds every fingerprint
  the monitor reported. The command flushed the output only when it wrote a result, so a
  monitor that produced no fingerprint left its header in the buffer. `scapy` applies the
  filter on packet arrival alone, so an interface that carries no traffic reached that
  filter never; the entry for #320 records the loop that repairs it.

- **`ja4plus watch <interface>` reads an interface and bounds its connection table**
  (#53). Round 101. `ja4plus live` stays as an alias of it, so a version 0.6.0 script
  keeps working. The command owns the connection table, and that table holds a maximum
  entry count and a maximum age. `--max-connections COUNT` sets the entry count, and it
  defaults to 10000. `--connection-timeout SECONDS` sets the age, and it defaults to
  300. When the table is full, the monitor evicts the least recently used connection.
  When a connection sends no packet for the stated age of capture time, the monitor
  evicts it too. Each eviction calls `Processor.cleanup_connection`, so it drops the
  entry of the connection table and the per-connection state of all ten methods
  together. Version 0.6.0 called `cleanup_connection` never, so its live capture held
  the state of every connection it ever read and a monitor on a busy interface grew
  until the host stopped it. Eviction runs on packet arrival, and the command starts no
  thread for it. One million packets across 50000 connections leave the monitor holding
  10000 connections and 7.20 MiB.

- **`Processor.process_packet_with_method_errors` names the method that raised** (#51).
  Round 94. It returns the same results as `process_packet_with_errors`, and one pair
  of the method name and the exception for each method that raised. An exception names
  no method, so `process_packet_with_errors` alone cannot tell a caller which method
  failed. Every returned exception still carries no traceback, for the reason #45
  records. `process_packet_with_errors` keeps its signature and drops the name.

- **The output schema carries a version, and `docs/output-schema.md` records it** (#50).
  Round 96. The new page states the schema version, the eleven fields, the raw form
  each of the ten methods writes, and the rule that raises the version. **The rule is a
  check and not prose alone.** `SCHEMA_HISTORY` in `tests/test_output_schema.py` freezes
  the column list of each released version, and `TheSchemaVersionRule` fails when a
  released column moves, changes name or goes away while `SCHEMA_VERSION` stays the
  same. A new column appends to the end of the row and raises no version.
  `TheSchemaDocument` parses the page and compares its field table against the written
  CSV header and the written JSON object, so the page and the code cannot drift apart.
  Two further cases read the value of each field, because a swap of two values changes
  the meaning of both fields and moves no name. **Ten mutations each make the file
  fail**, measured on 2026-08-08 against a baseline of 41 passed: a swap of two CSV
  columns fails 7 cases, an appended column fails 4, a dropped JSON field fails 5, a
  raise of `SCHEMA_VERSION` with no history entry fails 6, a renamed column in the page
  alone fails 3, a changed stability promise fails 1, a deleted rule sentence fails 1, a
  swap of two JSON values fails 1, a swap of two CSV values fails 2, and a write of
  `src_port` into `dst_port` fails 2. The appended column is the case that proves the
  rule: it fails the page checks, because a new field must be documented, and it leaves
  the version checks green, because a new field raises no version.
  **The `json` and `csv` formats carry the stability promise, and the `table` format
  carries none**, which the page states and a check reads back. The page records that
  `ja4`, `ja4s`, `ja4h` and `ja4x` write a raw form and the other six methods write
  `null`; `ja4x` now writes `JA4X_r`, which #267 added.

- **The package ships the `py.typed` marker and declares `__all__`** (#47). Round 90.
  The new file `ja4plus/py.typed` follows PEP 561, and `pyproject.toml` ships it as
  package data. A caller who runs `mypy --strict` against their own code now resolves
  the annotations of `ja4plus`: `unzip -l dist/*.whl` lists `ja4plus/py.typed`, and a
  consumer installed from that wheel reads `result.fingerprint` as `str`.
  **`ja4plus.__all__` names the 25 promised names**, and version 1.0.0 keeps each one
  until version 2.0.0. A name absent from `__all__` is not promised. The list holds the
  typed result, the processor, the ten fingerprinter classes, the ten one-shot
  functions, the two certificate helpers and `__version__`. `bind_loopback_ipv6`,
  `register_tunnel_dissectors`, `__author__` and `__license__` stay out: the package
  calls the first two at import time, and the last two describe the project and not the
  interface.
  **`ProcessorStats` is public at `ja4plus.processor.ProcessorStats`**, because
  `Processor.stats` returns `dict[str, ProcessorStats]`; the class moves nowhere.
  `docs/specs/features/04-typed-api.md` states FR-typed-api-9, FR-typed-api-10,
  FR-typed-api-12 and FR-typed-api-13.

- **`Processor.process_packet_with_errors` returns the results and the errors** (#45).
  Round 90. `process_packet` logs a fingerprinter error at DEBUG and returns the
  results alone, so a caller could not tell a packet that produces no fingerprint from a
  packet that failed a parse. The new method returns both lists, and one method that
  raises poisons no other method. The Go port returns the pair from one call, and parity
  rule 2 keeps it. **Every returned exception carries no traceback.** A traceback holds
  the frame of every call it passed. Those frames hold the packet. A monitor that keeps
  the errors of every packet would therefore hold every packet it read. The type, the
  message and the error chain stay. `docs/specs/features/04-typed-api.md` states
  FR-typed-api-4. `CLAUDE.md` states the packet rule.

- **`FingerprintResult` is the typed result of the public interface** (#44). The new
  module `ja4plus/types.py` holds a frozen dataclass with nine fields, and `ja4plus`
  exports the name. The field names are the snake-case form of the `FingerprintResult`
  struct of the Go port, under parity rule 2, so the field that names the method is
  `type` and not `method`. A result reads by field name as well as by attribute, so
  code written against the dictionary of version 0.6.0 keeps working for one major
  version. **Item access emits a `DeprecationWarning` that names the attribute form.**
  The item access covers reading only, and a result supports no item assignment.
  #45 makes `Processor.process_packet` return these results. No fingerprint value moved. `docs/specs/features/04-typed-api.md` states
  FR-typed-api-1, FR-typed-api-2, FR-typed-api-5 and FR-typed-api-6.

- **JA4SSH emits the window a connection holds open when the capture ends**
  (#214). Every fingerprinter and the processor now carry `close_open_windows()`.
  Call it when the packet source ends. `ja4plus analyze` calls it after the file
  reader, and `ja4plus live` calls it after the capture stops. JA4SSH is the only
  method that holds a window, so every other method returns an empty list. A
  connection that sends no FIN+ACK packet held its last window open, and no rule
  emitted it. `ssh2.pcapng` carries 452 TCP packets on port 22 and no FIN+ACK
  packet, so it now produces a second value, `c36s52_c42s76_c51s2`, which the
  FoxIO Rust snapshot and the FoxIO Zeek baseline both hold. Five other captures
  gain one trailing value each: `ssh.pcapng`, `ssh-scp-1050.pcap`,
  `ssh2-malformed.pcap`, `ssh2-moloch-crash.pcap` and `tcpdump-geneve.pcap`. No
  value of another method moved. **This is a behaviour change for a caller that
  reads JA4SSH.** A window that holds no SSH packet still emits nothing, so the
  value `c0s0` that #97 declines does not return. `docs/specs/foxio/JA4SSH.md`
  R11 records that the specification states no rule here, and the user decided it
  on 2026-08-08.

- **JA4H computes its raw form** (#131). FoxIO publishes one raw key for JA4H,
  `JA4H_ro`, and `ja4plus` computed none, so 89 reference values reached no
  comparison. Every JA4H result now carries `raw_original_order`, and the
  fingerprinter carries `last_raw_original_order`, so the processor and the
  command-line program report the value the way they report `JA4_ro`. The form is
  `<part a>_<header names>_<cookie names>_<cookie pairs>`, and every list holds the
  wire order. A request that carries no cookie ends after the header names and one
  underscore. 79 of the 89 values now match. The other ten sit on a stream whose
  hashed JA4H value fails too, and #129 and #35 own them. No hashed fingerprint
  changed.

### Fixed

- **The two handlers of the X.509 byte reader name the errors they expect** (#316).
  Round 100. `extract_certificate_from_bytes` wrote `except Exception` twice, once
  around the ASN.1 parse and once around the whole function body. #294 narrowed
  neither, because it targeted the `(ValueError, TypeError, Exception)` form. The inner
  list now names `ValueError` and `InvalidVersion`. The `cryptography` documentation
  states `ValueError` alone, and a measurement of malformed candidates raised
  `InvalidVersion` as well, which inherits `Exception` and not `ValueError`. The outer
  list names `TypeError`, which `len()` raises for input that is no sequence. **The
  reader still returns nothing and raises nothing for hostile input**: 13680 calls over
  empty, truncated, textual, damaged and random data raised no error. **A defect of
  this project now reaches a reader**, where the wide catch returned nothing. **No
  fingerprint moves**: the conformance suite reports 1531 passed, 143 skipped and 135
  xfailed before the change and after it. `tests/test_x509_certificate_reader.py` holds
  16 cases, and one of the 12 new cases failed against the base.

- **`extract_certificate_info` reads the module `x509`** (#309). Round 98.
  `x509_utils.py:262` and `x509_utils.py:263` imported `x509` and `default_backend`
  inside one branch, which made both names locals of the whole function. The parse at
  `x509_utils.py:285` therefore raised `UnboundLocalError` for every packet whose
  payload carried a certificate the reader found, and the wide handler below it returned
  nothing. The module imports both names already, so the branch-local import bought
  nothing, and this release removes it. **No caller inside `ja4plus/` calls the
  function**, so no fingerprint moves: the conformance suite reports 1531 passed, 143
  skipped and 135 xfailed before the change and after it.
  `tests/test_x509_certificate_info.py` holds three cases, and one of them failed
  against the base.

- **The three X.509 handlers name the errors they expect** (#294). Round 97.
  `ja4x.py:460`, `ja4x.py:490` and `x509_utils.py:267` each wrote
  `except (ValueError, TypeError, Exception) as e:`. `Exception` is a superclass of the
  other two names, so each handler caught every error while it read as a narrow catch.
  `CLAUDE.md` states that a fingerprinter catches the parse errors it expects and catches
  no bare `Exception`. The three lists now name the errors the `cryptography`
  documentation states for the calls inside them: `ValueError` for
  `load_der_x509_certificate`, `DuplicateExtension` and `UnsupportedGeneralNameType` for
  `Certificate.extensions`, and `InvalidVersion` for `Certificate.version`.
  `read_certificate` keeps `TypeError`, because `bytes()` raises it for input that is no
  byte string. **A defect of this project now reaches a reader**, where the wide catch
  logged it and returned nothing. **No fingerprint moves**: the conformance suite reports
  1531 passed, 143 skipped and 135 xfailed before the change and after it.
  `tests/test_ja4x_named_exceptions.py` holds 18 cases, and three of them failed against
  the base.

- **JA4 and JA4S write `s2` for the SSL 2.0 version value `0x0002`** (#227).
  `ja4.py:127`, `ja4.py:250` and `ja4s.py:393` wrote `s2` for `0x0200`, which is the
  value FoxIO retracted. `technical_details/JA4.md:65` at the pinned commit states
  `0x0002 = SSL 2.0 = “s2”`, and FoxIO commit `3e02a27`, dated 2024-08-23, is titled
  `Fix SSL version fields: SSL 2.0 is 0x0002, SSL 1.0 never existed`. The three sites
  now hold `0x0002`, and `0x0200` reaches the `00` fallback that the same specification
  line states. The dissector table `ssl_versions[]` and the `TLS_MAPPER` of the FoxIO
  Python reference both hold `0x0002` and neither holds `0x0200`, so the repair adds no
  alias. `ja4plus` held no `0x0100` row, so the SSL 1.0 half of the correction needed
  nothing. **No fingerprint of the vector set moves**: no capture under
  `tests/foxio_vectors/` carries an SSL 2.0 hello, the 38 captures produce 1494 values
  before and 1494 after, and zero values differ. Two parser paths present the value —
  the legacy version field and the `supported_versions` extension — and the SSL 2.0
  record format reaches none, because `parse_tls_handshake` reads a TLS record header.
  `tests/test_ja4_ssl2_version.py` holds the measurements, and #221 found the defect.

- **The QUIC CRYPTO fragment buffer of JA4 holds a limit** (#122).
  `reassemble_crypto_fragments` allocated a buffer that reached the highest fragment
  offset, and RFC 9000 Section 16 lets a CRYPTO frame offset reach
  4611686018427387903. A client Initial packet derives its keys from the connection
  ID the same packet carries in cleartext, so one UDP datagram from a sender who
  holds no connection reached the allocation. One fragment of one byte at offset
  `2**28` allocated 256 MiB, and offset `2**40` names 1024 GiB. The reader now drops
  a fragment that ends past `MAXIMUM_CRYPTO_BUFFER_BYTES`, which is 16384 and comes
  from the RFC 8446 Section 5.1 cap on a TLS record plaintext. The JA4 client path
  collects through `collect_crypto_fragments`, which #102 already shipped, so the
  per-connection list is bounded too. The fragment table of `JA4Fingerprinter` gains
  a maximum entry count of 1000 connections and a maximum age of 30 seconds, which
  the packet clock measures. No fingerprint changed.

- **JA4S tells a QUIC server Initial packet from a client one** (#118). `ja4plus`
  read every QUIC Initial packet as a client Initial packet, because the two carry
  the same long-header packet type. It stored the connection ID of the server packet
  under the reverse connection key and returned, so it never read the ServerHello.
  A server Initial packet names the client with the connection ID the client chose
  as its source, so the stored value was empty. JA4S now reads the port to tell the
  two apart, as JA4L does, and a server Initial packet replaces no stored client
  connection ID. `chrome-cloudflare-quic-with-secrets.pcapng` stream 50280 now
  reports `q130200_1301_234ea6891581`, and `ssh2.pcapng` and `tls3.pcapng` report a
  JA4S value on eight more QUIC streams. No JA4S value on any other stream changed.
  The FoxIO reference reads no QUIC handshake in the committed vectors, so it holds
  no value for those nine streams. It holds no JA4 value for the same nine streams,
  and #13 already owns that divergence for JA4. The register rises from 67 entries
  to 70.

- **BREAKING — the JA4S raw form holds the extensions in wire order** (#108). The
  `raw` key of a JA4S result sorted the extensions into numeric order. The FoxIO
  `JA4S_r` value holds them in the order the ServerHello carries them. A
  caller who stored the `raw` value of a JA4S result before this release gets a
  different string now. The old value matched 49 of the 84 `JA4S_r` values the
  committed vectors hold. FoxIO publishes `JA4S_r` and no `JA4S_ro`, because JA4S
  sorts no list. Both `raw` and `raw_original_order` now hold one value.
  `badcurveball.pcap` reports `t1205h1_c02b_0000,ff01,000b,0023,0010` where it
  reported `t1205h1_c02b_0000,000b,0010,0023,ff01`. The JA4S fingerprint is
  unchanged, because it already hashed the extensions in wire order. JA4 is
  unchanged: `JA4_r` sorts the ciphers and the extensions, and `JA4_ro` holds
  the wire order. `docs/implementation_notes.md` records the sort rule of each
  method and the evidence for it.

- **BREAKING — the JA4L QUIC server point reads the Initial packet that completes
  the ServerHello** (#102). `ja4plus` read the first server Initial packet, and the
  reference reads the Initial packet whose TLS handshake type is `2`. A server sends
  an Initial packet that holds an ACK frame first, so the two points differ. The
  cause was one line: `decrypt_initial_payload` read the ciphertext to the end of the
  UDP datagram, and the AEAD tag of an Initial packet covers only the bytes the
  Length field names. Every server Initial packet therefore failed the tag.
  `ja4plus/utils/quic_utils.py` gains four functions:

  - `_initial_packet_end` bounds the ciphertext by the Length field.
  - `decrypt_quic_server_initial_crypto` returns the CRYPTO fragments of one server
    Initial packet.
  - `server_hello_is_complete` reports whether the collected fragments hold a whole
    ServerHello.
  - `collect_crypto_fragments` stops a buffer at 16384 bytes. RFC 9000 Section 16
    lets a CRYPTO frame offset reach 4611686018427387903, and a reassembly allocates
    a buffer that reaches the highest offset.

  A QUIC connection whose server Initial packets do not decrypt now emits no
  `JA4L-S` value, as the reference does.
  `chrome-cloudflare-quic-with-secrets.pcapng` stream
  50280 now reports `10990_56` where it reported `9285_56`, and `tls3.pcapng` stream
  61884 reports `3583_57` where it reported `3051_57`. The register falls from 73
  entries to 71. No other vector changed.

- **BREAKING — JA4SSH counts an SSH message, not a TCP segment** (#98). `ja4plus`
  counted one SSH packet for every TCP segment that carried a payload. The FoxIO
  reference counts the packets `tshark` labels `ssh`, and `tshark` labels only the
  segment that completes an SSH message. The two counts therefore differed by one
  packet for each SSH message that spans two segments, and every window boundary
  after such a message moved. `ja4plus/utils/ssh_utils.py` gains
  `SSHMessageTracker`, which follows the message boundary of one direction while
  the direction sends plaintext. `ssh-r.pcap` stream 1 now reports `c6s5` where it
  reported `c7s5`, and all five windows of `ssh-r.pcap` stream 2 now hold the
  reference packet counts. `ssh.pcapng`, `ssh-scp-1050.pcap` and `ssh2.pcapng` are
  unchanged.

- **BREAKING — JA4L reports the one-way latency and the measurement point the
  FoxIO vectors hold** (#88). The fingerprinter reported the whole round-trip
  time, and it measured the client value to the bare ACK of the handshake. The
  FoxIO material states `One-way TCP latency in us`, and the vectors hold half of
  the measured time. The client value now measures to the last packet that
  carries the relative sequence number 1 and the relative acknowledgement number
  1. One connection now carries one `JA4L-C` value. The QUIC form now reads the
  Initial packets and the Handshake packets on port 443. A UDP flow that carries
  no QUIC long header gives no value. `ja4plus` also imports the scapy
  Geneve, VXLAN and ERSPAN dissectors, so a mirrored capture reads its inner TCP
  layer. Every JA4L value a caller stored before this release differs from the
  value this release emits. 108 of the 114 registered JA4L value deviations
  now conform, and #101 and #102 own the six that remain.

- **BREAKING — JA4SSH counts a bare ACK the way FoxIO counts one** (#92). A bare
  ACK carries the ACK flag alone and no payload. `ja4plus` read the ACK flag
  alone, so it counted a SYN+ACK, a FIN+ACK and a RST+ACK as bare ACKs. It also
  created its state table entry on the first SSH packet, so it dropped the ACK
  that completes the TCP handshake. The two ACK counts of a JA4SSH fingerprint
  therefore change on any connection that carries a bare ACK. `ssh-r.pcap`,
  `ssh-scp-1050.pcap` and `ssh2.pcapng` now equal the reference on their first
  window. `ssh.pcapng` holds no bare ACK, and it stays at `c36s36_c76s124_c0s0`.

- **JA4SSH emits the window a connection holds open when it closes** (#92). A
  connection that carries fewer than 200 SSH packets produced no fingerprint at
  all, and a connection that closed part way through a window lost those packets.
  `ja4plus` now emits that window on a packet that carries the FIN flag and the ACK
  flag, which is the rule `python/ja4.py` states above `finalize_ja4ssh`. An empty
  window emits nothing. `ssh-r.pcap` now produces the occurrence keys the reference
  holds on all three of its streams.

### Divergence from the FoxIO reference

- **JA4SSH declines three results of the reference** (#96, #97, #105). Each one
  describes the capture and not the connection, so it cannot be compared against
  the output of another tool. The reference reads its mode field from the packet
  lengths of every connection in the capture, because `dict(ja4sh_stats)` shares
  one payload list (#96). It writes an extra occurrence from a window of zero SSH
  packets whenever a bare ACK follows a window boundary (#97). It emits no trailing
  window for the connection it holds at stream index 0, because `finalize_ja4ssh`
  guards with `if stream:` (#105). `ja4plus` reads the window alone, emits a value
  only for a window that holds SSH packets, and emits the trailing window for every
  connection that closes. `docs/implementation_notes.md` holds the measurement.

- **A loopback capture that carries IPv6 now reads the same way on every host**
  (#94). A capture whose link type is `DLT_NULL` starts each frame with the
  address family value of the host that captured it. That value is 24 on NetBSD
  and OpenBSD, 28 on FreeBSD, and 30 on Darwin. scapy binds one value,
  `socket.AF_INET6`, which is 10 on Linux, and no capture holds 10. `ipv6.pcapng`,
  `tls-alpn-h2.pcap` and `http-empty-useragent.pcap` therefore produced
  fingerprints on macOS and none on Linux. `ja4plus` binds all three BSD values
  when a caller imports it, and the conformance suite now reports the same counts
  on both hosts.

### Changed

- **BREAKING — JA4SSH emits one fingerprint for every 200 SSH packets** (#28).
  The window triggered at `min(packet_count, 10)`, and a complete key exchange
  also triggered it. A caller who relies on a fingerprint at 10 packets gets no
  fingerprint now. FoxIO states the interval verbatim in
  `technical_details/JA4SSH.png`: `(runs every 200 SSH packets by default)`. The
  constructor argument `packet_count` sets the window, and it defaults to 200. A
  bare ACK is not an SSH packet, and it does not advance the window. `ssh.pcapng`
  now produces exactly one JA4SSH fingerprint, `c36s36_c76s124_c0s0`, which
  equals the reference.

### Removed

- **BREAKING — the `ja4plus.collector` module leaves the package** (#191). Round 71.
  **This entry is the record that was missing.** #191 removed `ja4plus/collector.py` on
  2026-08-08, and round 71 of `docs/specs/spec.md` recorded it. This file named the module
  nowhere, so a reader who works from the Changelog alone met no removal. #65 found the
  gap while it wrote `docs/migration-0.6-to-1.0.md`, and #395 records it here. **No new
  round records the removal**, because round 71 already records it, and a second round
  would give one change two citation targets. `import ja4plus.collector` raises
  `ModuleNotFoundError`. The module held module-level state that grew without a bound, and
  it carried its own removal notice for version 0.4.0. Use `Processor` instead.
  `tests/test_breaking_change_record.py` reads the 25 modules of version 0.6.0 against the
  package, so a later removal that no round records fails a case.

- **Four X.509 helpers leave `ja4plus/utils/x509_utils.py`** (#314). Round 99. The
  user decided on 2026-08-08 that `extract_certificate_info` leaves the package before
  version 1.0.0, together with the sibling helpers no caller uses. The four are
  `extract_certificate_info`, `get_certificate_issuer`, `get_certificate_subject` and
  `get_name_attribute`. `__all__` named none of the four, and a grep of `ja4plus/`,
  `tests/`, `examples/` and `docs/` found no caller for any of them. `__all__` still
  names 25 entries. `docs/api_reference.md` documented `extract_certificate_info` alone
  of the four, and that row is gone. **Two plain `except Exception` handlers leave with
  the function**, which #294 narrowed neither, because each wrote the plain form rather
  than the deceptive form. **No fingerprint moves**: the conformance suite reports 1531
  passed, 143 skipped and 135 xfailed before the change and after it.
  `tests/test_x509_certificate_info.py` is now
  `tests/test_x509_certificate_reader.py`, because it measures
  `extract_certificate_from_bytes`, the reader that stays.

- **The private helper `_src_is_client` leaves `ja4plus/fingerprinters/ja4l.py`**
  (#119). The helper read the outer address of a packet with `get_ip_layer`, and
  it compared that address against the address the connection key holds. #101
  made the JA4L connection key hold the inner address pair, so the two addresses
  are never equal for a tunnelled packet. No caller reads the helper, so no
  fingerprint changes. `FR-correctness-audit-11` asks for the removal.

## [0.6.0] - 2026-05

Major spec-compliance update against the May 2026 FoxIO JA4+ spec
(PRs #267, #270, #277, #281, #288), and a parity pass against the Go
reference implementation.

### Added

- **JA4D6** (`ja4plus.JA4D6Fingerprinter` / `generate_ja4d6`): DHCPv6
  fingerprinting (10th JA4+ method). Format mirrors JA4D with DHCPv6
  semantics — DUID size from option 1, IATA presence flag, Client FQDN
  flag, all option types in presence order including nested options
  inside IA_NA / IA_TA / IA_PD / IA Address / IA Prefix.
- **JA4D** is now a public package export
  (`from ja4plus import JA4DFingerprinter, generate_ja4d`).
- **`Processor`** aggregator class (`ja4plus.Processor`) — runs every
  JA4+ fingerprinter on each packet and returns a list of result dicts.
  Provides `process_packet`, `reset`, `cleanup_connection`,
  `get_shard_key` (sorted 5-tuple, direction-independent).
- **JA4 / JA4S raw exposure**: every result entry on these fingerprinters
  now includes `raw` and `raw_original_order` keys, plus
  `last_raw` / `last_raw_original_order` instance attributes for the most
  recent successful parse. JSON CLI output emits these fields.
- **Multi-packet QUIC CRYPTO reassembly**: large ClientHellos that span
  multiple Initial datagrams (sharing a DCID) are now reassembled. New
  helpers `decrypt_quic_initial_crypto`, `parse_crypto_frames`,
  `reassemble_crypto_fragments`, `client_hello_from_crypto_fragments` in
  `ja4plus.utils.quic_utils`. The CRYPTO frame parser now skips ACK
  frames (0x02/0x03) instead of bailing on them.
- **X.509 module helpers**: `compute_ja4x_from_pem(bytes)` and
  `compute_ja4x_from_der(bytes)` mirroring Go's
  `ComputeJA4XFromPEM` / `ComputeJA4XFromDER`.
- CLI `--types` accepts `ja4d` and `ja4d6`.

### Fixed

- **JA4 ALPN non-alphanumeric** (PR #277): when the first or last byte
  of the first ALPN value is not ASCII alphanumeric, the JA4 ALPN
  component is now the first/last character of the lowercase HEX of the
  full first ALPN value. Previously ja4plus dropped non-ASCII bytes via
  `decode('ascii', errors='ignore')` and emitted `"99"` on the first
  byte being non-ASCII. Raw ALPN bytes are now preserved on
  `tls_info["alpn_raw"]`.
- **JA4H HTTP/2 + HTTP/3 version codes** (PR #288): `HTTP/2` now maps to
  `"20"` and `HTTP/3` to `"30"` in the JA4H part-A version code (not
  `"2"` / `"3"`). HTTP/1.0 / HTTP/1.1 unchanged.
- **JA4H cookie-VALUES sort by NAME only** (PR #288): the cookie-values
  hash component now sorts pairs explicitly by cookie name; previously
  relied on tuple-sort tie-breaking.
- **JA4SSH deterministic mode tiebreak** (PR #281): when multiple packet
  sizes tie for the highest frequency, the LOWEST value wins. Previously
  used `Counter.most_common(1)[0][0]`, whose result could vary based on
  insertion order.
- **JA4L UDP/QUIC server-first orderings**: the QUIC timing path no
  longer requires the connection's lexicographic direction to be
  `forward`. The first packet on the flow defines the client; subsequent
  packets are routed by comparing endpoints to that anchor.
- **JA4D skip set** matches the spec exactly: `{0, 53, 50, 81}`. The
  End marker (255) is handled by the parse loop and never recorded.

### Changed

- Bumped version to **0.6.0**.
- README updated to reflect 10 JA4+ methods and new APIs.

### Internal

- Per-DCID QUIC fragment buffer + reverse map for cleanup.
- New `ja4plus.utils.quic_utils._parse_alpn_with_bytes` returns both
  decoded strings and raw bytes for ALPN.
