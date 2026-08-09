---
id: pre-release-validation
feature: Pre-release validation
epic: "Epic 11: Pre-release validation"
status: issued
issues: [406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 419]
mockups: []
number_gap: "The file number equals the epic number. Epic 10 (#194) holds no feature
  document, so `features/10-*.md` does not exist. The directory sequence carries a gap,
  and it loses no file."
---

## Purpose

Version 1.0.0 promises conformance, safety and stability. Epic 9 publishes it, and Epic
9 depends on this feature set.

Four statements a user relies on hold no measurement today. This feature set takes each
measurement before the publish.

1. **Nothing runs the shipped package.** #68 and #69 read the contents of the wheel. No
   case installs the wheel and then produces a fingerprint. No case installs the source
   distribution at all.
2. **Every Linux result comes from a continuous-integration runner.** The development
   host is macOS. The user granted one Linux host on 2026-08-09, and no run has used it.
3. **The mutation sweep names 976 candidates, and #172 settled two of them.** #206
   records the count, and the report of 2026-08-07 states it in the `Candidates` row.
   **That count is stale, and no later count replaces it here.** It comes from one sweep
   of the whole package, against a commit that `dev` no longer holds. #412, #413 and #414
   each run one sweep and write one report under `docs/mutation_reports/`, and the union
   of those reports carries the count this epic settles.
4. **The package states no throughput.** `Non-goals` of `docs/specs/spec.md` states that
   this project measures throughput and reports it.
   `docs/specs/features/03-concurrency-safety.md` states the memory ceiling, and that
   ceiling is the only performance number this project holds.

**This feature set produces evidence. It publishes nothing, and it moves no
fingerprint.**

## User stories

- As a maintainer, I want a case that installs the built package and produces a
  fingerprint, so that I publish no package that only imports.
- As a maintainer, I want the gates measured on a Linux host, so that a Linux defect
  reaches me before the batch gate.
- As a maintainer, I want every candidate settled, so that I know which cases measure the
  code and which cases measure nothing.
- As a user, I want the package to state its throughput, so that I decide whether it
  suits my packet run.

## Functional requirements

FR-pre-release-validation-1 — One case installs the built wheel into a clean
environment.

FR-pre-release-validation-2 — That case produces a fingerprint through the public
interface of the clean environment.

FR-pre-release-validation-3 — That case produces a fingerprint through `ja4plus analyze`
in the clean environment.

FR-pre-release-validation-4 — That case fails when `ja4plus.__file__` of the clean
environment names a path below the repository root.

FR-pre-release-validation-5 — That case compares the output of the clean environment
against the output of the source tree, byte for byte.

FR-pre-release-validation-6 — One control case removes `ja4plus/data/ja4plus-mapping.csv`
from the clean environment, and the lookup then reports an empty database.

FR-pre-release-validation-7 — `.github/workflows/test.yml` holds one job that runs the
`installed_wheel` marker.

FR-pre-release-validation-8 — One case installs the built source distribution into a
clean environment, and it passes `--no-binary ja4plus` to `pip install`.

FR-pre-release-validation-9 — That case reads the recorded `pip` output, and it confirms
that `pip` built the package from the source distribution.

FR-pre-release-validation-10 — That case compares the byte count of
`ja4plus/data/ja4plus-mapping.csv` in the clean environment against the byte count of the
file in the repository.

FR-pre-release-validation-11 — One lookup through the clean environment returns a record
for one named fingerprint.

FR-pre-release-validation-12 — The five gates run on the granted Linux host.

FR-pre-release-validation-13 — #410 records the verbatim output of each gate the Linux
host ran.

FR-pre-release-validation-14 — Every record of a Linux gate states that the host predicts
no `ubuntu-latest` result.

FR-pre-release-validation-15 — Every record of a Linux gate states that the host measures
`python3.12` alone.

FR-pre-release-validation-16 — The sweeps together apply every mutation of every module
that `git ls-files 'ja4plus/*.py' 'ja4plus/*/*.py'` lists. One sweep for each module group
satisfies this, and one sweep of the whole package satisfies it too.

FR-pre-release-validation-16a — A case fails when the module list one sweep reads differs
from the tracked Python files of `ja4plus/`. **Never write `git ls-files
'ja4plus/**/*.py'`.** Git reads `**` in a pathspec as one or more directories. That
pattern therefore lists 24 files where the package holds 31. It drops every module of the
top directory of the package.

FR-pre-release-validation-17 — The report of each sweep states the commit the sweep read.

FR-pre-release-validation-18 — That commit is an ancestor of the head of the branch under
test.

FR-pre-release-validation-19 — `tests/mutation_census.py` reads the JSON report of each
sweep, and it opens no Markdown file.

FR-pre-release-validation-20 — `tests/test_mutation_census.py` fails when the candidate
count of one test file changes by one. **A candidate is keyed by the sweep that named it
and by the case**, because two sweeps may name the same case and that is one candidate for
each sweep.

FR-pre-release-validation-21 — `docs/mutation_settlements/` holds one settlement record
for each module group.

FR-pre-release-validation-22 — A settlement record states one verdict for each candidate:
`repaired` with the case name, or `correct` with the reason the mutation cannot reach the
case.

FR-pre-release-validation-23 — A `repaired` verdict of a settlement record names a case
that `tests/test_settlement_procedure.py` collects from the suite.

FR-pre-release-validation-23a — A worker proves each mutation live in both directions with
`inspect.getsource` before it settles the candidate. **No check tests this statement**, and
the list below names it.

FR-pre-release-validation-24 — A repaired guard case feeds input that produces a
fingerprint when the guard alone is removed.

FR-pre-release-validation-25 — A repaired output case reads one parsed output line or one
result, and it asserts on one named field.

FR-pre-release-validation-26 — A case of `tests/test_db_offline.py` that asserts that
`ja4plus/ja4db.py` sends no request reads the recorded transport `RecordingRequests`.

FR-pre-release-validation-26a — That case reaches no address of the lookup service at
`https://ja4db.com`.

FR-pre-release-validation-26b — The install cases of `tests/test_installed_wheel.py`
reach a package index.

FR-pre-release-validation-26c — `pip` resolves `scapy` and `cryptography` from that index
for each clean environment those cases build.

FR-pre-release-validation-27 — `tests/throughput_run.py` writes one JSON object that
holds `packets`, `connections`, `elapsed_seconds`, `packets_per_second`,
`python_version`, `platform` and `commit`.

FR-pre-release-validation-28 — `tests/test_throughput.py` asserts that the run fed the
packet count the case states.

FR-pre-release-validation-29 — `tests/test_throughput.py` asserts that a run of twice the
packets reports a longer elapsed time.

FR-pre-release-validation-30 — `tests/test_throughput.py` asserts that the run produced
more than zero fingerprints.

FR-pre-release-validation-31 — `docs/performance.md` states the host, the Python version
and the commit of each throughput measurement.

FR-pre-release-validation-32 — No continuous-integration job gates on a throughput value.

FR-pre-release-validation-33 — Every issue of this feature set holds the conformance
suite at 1532 passed, 143 skipped and 134 xfailed, against 134 keys of
`tests/foxio_deviations.json`.

## User flows

**A maintainer proves the shipped package runs.**

1. The maintainer runs `python -m build`, which writes the source distribution and the
   wheel.
2. The case creates a clean environment and installs the wheel into it.
3. The case runs `ja4plus analyze` on one vector in the clean environment.
4. The case compares that output against the output of the source tree.
5. The case repeats steps 2 to 4 for the source distribution.

**A maintainer takes a Linux measurement.**

1. The maintainer reads `uptime` on the granted Linux host.
2. The maintainer creates a clean environment on that host and installs the development
   extra.
3. The maintainer runs the five gates and the memory ceiling case.
4. The maintainer writes the verbatim output of each command into #410, with the caveat.
5. The maintainer reads `uptime` again and records it.

**A maintainer settles a candidate.**

1. The maintainer sweeps one module whole, and names every test file that reads it.
2. The maintainer reads the case before the mutation.
3. The maintainer applies the mutation by hand and confirms it with `inspect.getsource`.
4. The maintainer runs the case and records the failure.
5. The maintainer reverts the mutation, confirms the revert, and records the pass.
6. The maintainer repairs the case, or records it as correct with the reason.

## Screens & states

| Screen | Purpose | States |
|---|---|---|
| Gate summary line | Report the result of one gate run. | Passed; failed at a named case. |
| `docs/mutation_reports/` | Report every mutation and every candidate of one sweep. | One report for each module group; each one applied whole. |
| `docs/mutation_settlements/` | Report the verdict of each candidate. | `repaired` with the case name; `correct` with the reason. |
| `docs/performance.md` | Report the throughput of each named packet run. | One row for each host, each Python version and each commit. |
| #410 | Hold the verbatim transcript of the Linux gates. | Run on 2026-08-09 at commit `3991712`; recorded with the caveat. |

## Behaviour rules

- This feature set changes no file under `tests/foxio_vectors/`, and it moves no
  fingerprint.
- A change to a file under `ja4plus/fingerprinters/` needs a vector, or a test derived
  from the FoxIO material, that proves the change. `CLAUDE.md` rule 1 binds it.
- Where a candidate shows that a fingerprinter produces a wrong value, the worker opens a
  decision issue and changes no fingerprinter.
- A candidate belongs to one sweep. The sweep names a case a candidate when both
  statements below hold.
  1. No mutation of that sweep makes the case fail.
  2. The sweep does not count the case as a failure before it applies a mutation.
- **A candidate of the whole-package sweep names no module.** `tests/mutation_sweep.py`
  writes the `candidates` key as one list of case identifiers, and it groups that list by
  test file at `tests/mutation_sweep.py:396`. A candidate survives every mutation of
  every swept module, so no module owns it. A count for one module comes from a sweep
  that names that module alone.
- **The union of the per-module sweeps is larger than the candidate set of one
  whole-package sweep, and the union is the correct input for settlement.** A
  whole-package sweep names the cases that no mutation of any module kills. A sweep of
  module X names the cases that no mutation of X kills, and a case that module Y kills
  still reaches that list. So a case can be a candidate of the sweep of X and reach no
  list of the whole-package sweep. **A reader who compares the two counts reads a
  regression that did not happen.** #411 measured the whole-package run at 71.6 hours and
  the project manager partitioned it on 2026-08-09, so the union is the set this project
  settles.
- **The partitioned sweep is the method this project already documents.**
  `tests/mutation_sweep.py:340` directs a reader to settle a case with
  `--max-per-module 0 --tests tests/<file>.py`, and `tests/mutation_sweep.py:482` runs the
  whole suite for each mutation when `--tests` names nothing. A sweep scoped to the test
  files that read one module therefore runs a small suite for each mutation.
- A checkpoint belongs to one commit, because it keys each result on the position of the
  expression in the file. A worker deletes the checkpoint file before the first sweep of
  a new commit.
- Before every sweep, and before every mutation a worker applies by hand, the worker sets
  `PYTHONDONTWRITEBYTECODE=1` and removes every `__pycache__` directory. Stale bytecode
  makes a candidate indistinguishable from a case the mutation reached.
- A case that the sweep counts as skipped or as xfailed before it applies a mutation
  cannot fail. #206 records 248 such cases of the 976, and a settlement states that
  reason rather than a repair.
- The Linux host is shared. It carries an Elasticsearch node and continuous-integration
  runners, so no run on it starts a load generator.
- The Linux host verifies a Linux code path. It predicts no `ubuntu-latest` result,
  because the runner holds another kernel, another processor count, another memory size
  and another Python version.
- The Linux host measures `python3.12` alone. It holds no other interpreter, so the 3.9,
  the 3.10, the 3.11 and the 3.13 rows of the matrix get no measurement on that host.
- Every measurement this host produces carries the two rules above beside it. A record
  that omits them states more than the host measured.
- The clean environment installs no development extra, so the run reads the shipped
  dependency list.
- **The install cases reach a package index, and that index is part of the interface
  under test.** An install that resolves no dependency measures no shipped dependency
  list, and that list is what `FR-pre-release-validation-1` exists to check.
- **A rule of this feature set that binds the cases names the case file.** The set holds
  install cases and lookup cases. The two carry opposite network rules. A rule over every
  case of the set therefore binds cases it was not written for.
  `tests/test_requirement_scope.py` reads the requirement text of every feature document.
  It fails a rule that names no case file. #419 records the repair.
- A case that installs the shipped package builds and installs before it measures, so its
  cost follows the host rather than the case count. #410 measured 71.56 s on the granted
  Linux host against the 23 s #408 measured on macOS.
- **This feature set sets no throughput target, and it adds no gate on a throughput
  value.** `Non-goals` of `docs/specs/spec.md` states the reason.
- A throughput measurement of this feature set becomes no floor. A floor derived from one
  measurement cannot detect a fault in that measurement.

## Data touched

- New file `tests/test_installed_wheel.py`.
- New file `tests/test_installed_sdist.py`, or the source-distribution path inside
  `tests/test_installed_wheel.py`.
- New file `tests/mutation_census.py`.
- New file `tests/test_mutation_census.py`.
- New file `tests/throughput_run.py`.
- New file `tests/test_throughput.py`.
- New file `tests/test_specification_terms.py`.
- New file `tests/test_requirement_scope.py`.
- New directory `docs/mutation_settlements/`, with one record for each module group.
- New directory `docs/mutation_reports/`, with one JSON report for each sweep.
- New file `docs/performance.md`.
- Changed file `.claude/rules/conformance.md`, which carries the measured cost of one
  sweep and the census schema.
- Changed file `pyproject.toml`, which gains the `installed_wheel` marker.
- Changed file `.github/workflows/test.yml`, which gains the `installed-wheel` job.
- Changed file `docs/specs/spec.md`.
- Changed file `CHANGELOG.md`.

## Interfaces

| Service | What it does | Documentation |
|---|---|---|
| `build` | Writes the source distribution and the wheel. | https://build.pypa.io/en/stable/reference/cli.html |
| `pip install` | Installs one artefact into the clean environment. | https://pip.pypa.io/en/stable/cli/pip_install/ |
| `venv` | Creates the clean environment. | https://docs.python.org/3/library/venv.html |
| `bigboy` | The granted Linux host. `.issue-flow.json` records it. | — |

Verified against the pages above, retrieved 2026-08-09.

`python -m build` writes both artefacts into `{srcdir}/dist` by default. It builds the
source distribution from the source tree, and it builds the wheel from that source
distribution. A wheel run therefore reads the source distribution already. #409 still
installs the source distribution, because `pip` runs the build backend on the user's
host.

`pip install --no-binary` accepts `:all:`, `:none:`, or one or more package names
separated by commas. `--no-binary ja4plus` is the package-name form, so `pip` builds
`ja4plus` from the source distribution and resolves no wheel for it.

`.issue-flow.json` records the Linux host as Ubuntu 24.10, kernel 6.11, 56 cores, 137 GiB
and `python3.12`. It records no checkout path, so the first run on that host states where
the checkout is.

## Edge cases & failures

| Case | What happens |
|---|---|
| The clean environment resolves the source tree. | The case fails, because `ja4plus.__file__` names a path below the repository root. |
| The wheel omits the mapping file. | The lookup reports an empty database, and the control case proves the comparison can fail. |
| The source distribution omits the mapping file. | The byte-count case fails, and the package imports. |
| `pip` resolves a wheel where the case asks for the source distribution. | The case reads the recorded `pip` output and fails. |
| A killed sweep leaves a change in `ja4plus/`. | The next sweep refuses to start. The worker runs `git checkout -- ja4plus/`. |
| A checkpoint from an older commit reaches a new sweep. | The keys name other expressions, and the result is unreadable. The worker deletes the checkpoint first. |
| Stale bytecode survives a mutation. | The suite reads the old module, and a reached case reports as a candidate. |
| A guard case feeds input the parser rejects for a second reason. | The case passes with the guard removed, so it measures nothing. |
| The Linux host is busy. | The throughput measurement reads the load of the host and not the package. The worker reads `uptime` before the run and after it. |
| The Linux gates pass and `ubuntu-latest` fails. | The caveat holds. The host predicts no runner result. |
| A settlement repairs a case and the fingerprint moves. | The conformance suite fails, and the change needs a vector that proves it. |

## Acceptance criteria

- [ ] `pytest tests/test_installed_wheel.py -m installed_wheel` passes on macOS and on
      Linux.
- [ ] The wheel case and the source-distribution case each assert that
      `ja4plus.__file__` starts with the `site-packages` path of the clean environment.
- [ ] The wheel case asserts that the output of `ja4plus analyze` from the clean
      environment equals the output of the source tree, byte for byte.
- [ ] One control case removes the mapping file from the clean environment, and the
      lookup then returns nothing.
- [ ] #410 holds the verbatim output of each of the five gates, and the summary line of
      `pytest tests/ -m "not spec_validation"` reports 0 failed.
- [ ] #410 holds the caveat, and it states that `python3.12` is the only version the host
      measured.
- [ ] The reports of `docs/mutation_reports/` together hold one `modules` entry for every
      file that `git ls-files 'ja4plus/*.py' 'ja4plus/*/*.py'` lists.
- [ ] One case fails when the module list one sweep reads differs from the tracked Python
      files of `ja4plus/`, so no writer reintroduces the `**` pathspec in silence.
- [ ] `tests/test_mutation_census.py` reports 0 unsettled candidates for every module of
      `ja4plus/utils/`, `ja4plus/fingerprinters/` and the interface modules.
- [ ] Each settlement record holds one row for each candidate, and the row count equals
      the count `tests/mutation_census.py` reports for that module group.
- [ ] `python tests/throughput_run.py` writes one JSON object holding the seven fields
      `FR-pre-release-validation-27` names.
- [ ] `grep -rn "packets_per_second" .github/workflows/` finds nothing.
- [ ] `docs/performance.md` states one row for each capture the run timed, and each row
      names its host, its Python version and its commit.
- [ ] `pytest tests/ -m spec_validation` reports 1532 passed, 143 skipped and 134 xfailed
      against 134 keys of `tests/foxio_deviations.json`.
- [ ] `git diff --name-only` lists no file under `tests/foxio_vectors/`.
- [ ] `pytest tests/test_requirement_scope.py` passes, so every requirement that binds a
      feature set names one path under `tests/`.
- [ ] `pytest tests/test_settlement_procedure.py` passes, so every `repaired` verdict names
      a case the suite collects.

**Three statements here are not checkable, and each names its reason.**

1. **No check confirms that a recorded transcript came from the granted Linux host.** The
   output is evidence under `.claude/rules/ste.md`, so a worker pastes it verbatim and
   rewrites none of it. A reader trusts the transcript or repeats the run.
2. **No check states whether a measured throughput is adequate.** Adequacy is a decision
   the user makes against a use, and `Non-goals` states no target.
3. **No check confirms that a worker proved a mutation live in both directions with
   `inspect.getsource`.** `FR-pre-release-validation-23a` states that procedure, and a
   case observes no worker. #419 found the statement among rules a check tests, and #414
   split it. **The artefact keeps a check where the procedure keeps none**: a worker who
   followed the procedure leaves a `repaired` verdict that names a case the suite
   collects, and `FR-pre-release-validation-23` states that condition.
   `tests/test_settlement_procedure.py` reads it. **That condition is necessary and it is
   not sufficient**, because a record that names a collected case still proves no run of
   the mutation. A reader trusts the transcript in the pull request or repeats the run.

## Out of scope

- The publish itself. Epic 9 owns it.
- A throughput target, and a continuous-integration gate on a throughput value.
- A reading of the FoxIO material. This feature set settles no register entry.
- A change to a fingerprinter. A candidate that exposes a wrong value opens a decision
  issue.
- The 3.9, 3.10, 3.11 and 3.13 rows of the matrix on the granted Linux host. That host
  holds `python3.12` alone.
- The one-million-packet run on the granted Linux host. That host is shared, and #410
  already runs the memory ceiling case there.

## Open questions

- ~~Whether `tests/mutation_sweep.py` writes a commit field.~~ **Settled by #411 on
  2026-08-09.** The sweep writes a `commit` key and a `Commit` row, read from
  `git rev-parse HEAD` before the first mutation lands.
- ~~Whether the acceptance criteria of #411 can group the `candidates` key by module.~~
  **Settled by #411 on 2026-08-09.** The census groups by test file, and the sweep is
  partitioned into one sweep for each module group.
- ~~Which checkout path the granted Linux host holds.~~ **Settled by #410 on 2026-08-09.**
  The host holds a checkout at `/home/e/ja4plus-verify`, and its environment is
  `/home/e/ja4plus-verify/.venv` on `python3.12`.
