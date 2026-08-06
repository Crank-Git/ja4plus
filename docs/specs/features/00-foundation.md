---
id: foundation
feature: Foundation
epic: "Epic 0: Foundation"
status: built
issues: [11, 21, 22, 23, 24, 25, 26]
mockups: []
---

## Purpose

The repository already has a test suite and a continuous-integration workflow. It
does not have the gates that make a later change provable. This feature set adds
the gates first, so that every later epic can fail loudly.

The existing codebase covers most of what a greenfield foundation epic would
build. Three items are missing. The conformance suite does not run in continuous
integration. No lint, format, or type check runs at all. Coverage is not measured.
Two tests fail on any machine where the command `python` is absent.

## User stories

- As a maintainer, I want a pull request to fail when a fingerprint changes, so
  that I do not publish a regression.
- As a maintainer, I want the conformance suite to run without network access, so
  that a pull request does not fail for a reason unrelated to the change.
- As a library integrator, I want to know which Python versions the project
  supports, so that I can pin a dependency.

## Functional requirements

FR-foundation-1 — The repository holds the FoxIO vectors under
`tests/foxio_vectors/`.

FR-foundation-2 — The vector directory holds a `NOTICE` file. The file records the
upstream repository URL, the upstream commit identifier, and the FoxIO License 1.1
attribution.

FR-foundation-3 — The `.gitignore` file no longer excludes `tests/foxio_vectors/`.

FR-foundation-3a — The `.gitignore` file permits a capture file under
`tests/foxio_vectors/`.

> **Warning.** `.gitignore` excludes `*.pcap` and `*.pcapng` for the whole
> repository. Removing the `tests/foxio_vectors/` line is not enough: 34 of the 37
> vectors carry one of those two extensions and stay excluded. The fix is a
> negation rule, and the issue must verify it with `git check-ignore`.
>
> ```gitignore
> *.pcap
> *.pcapng
> !tests/foxio_vectors/**
> ```
>
> The existing captures under `tests/data/` are tracked only because they use the
> `.cap` and `.dmp` extensions, which no rule matches.

FR-foundation-4 — The conformance suite runs on every pull request.

FR-foundation-5 — The conformance suite fails when a vector produces an unexpected
fingerprint.

FR-foundation-6 — The conformance suite fails when it collects zero vectors.

FR-foundation-7 — `ruff check ja4plus/ tests/` runs on every pull request.

FR-foundation-8 — `ruff format --check ja4plus/ tests/` runs on every pull request.

FR-foundation-8a — One commit applies `ruff format` across `ja4plus/` and `tests/`,
and that commit changes no behaviour.

> **Warning.** Land FR-foundation-8a before any other issue in this epic. The
> repository has never been formatted, so `ruff format` rewrites 26 lines in
> `ja4plus/processor.py` alone. The project also configures a format-on-edit hook in
> `.claude/settings.json`. Without the one-time commit first, the first edit to any
> file produces a large diff that hides the real change. Record the commit
> identifier in `.git-blame-ignore-revs`.

FR-foundation-9 — `mypy ja4plus/` runs on every pull request.

FR-foundation-10 — The test job measures line coverage and writes the number to the
job summary.

FR-foundation-11 — The test job fails when line coverage is below the configured
floor.

FR-foundation-12 — `pyproject.toml` declares `requires-python = ">=3.9"`.

FR-foundation-13 — The test matrix runs Python 3.9 through 3.13.

FR-foundation-14 — Every test that starts a Python subprocess uses
`sys.executable`.

FR-foundation-15 — The repository has a `dev` branch. The planner created it
locally. This requirement is met once the branch exists on the remote.

FR-foundation-15a — The `dev` branch is the default branch on GitHub.

FR-foundation-15b — The `master` branch is protected and accepts a merge only from
`dev`.

FR-foundation-16 — Every GitHub Actions step pins its action to a commit
identifier.

FR-foundation-17 — The repository has a Dependabot configuration for `pip` and for
`github-actions`.

## User flows

**A maintainer opens a pull request.**

1. The maintainer pushes a branch and opens a pull request into `dev`.
2. Continuous integration runs `ruff check`, `ruff format --check`, and `mypy`.
3. Continuous integration runs the unit suite on each Python version.
4. Continuous integration runs the conformance suite once.
5. Continuous integration reports line coverage.
6. The maintainer merges when every check passes.

**A maintainer refreshes the vectors.**

1. The maintainer runs `python tests/download_test_vectors.py --refresh`.
2. The script downloads every vector from the pinned upstream commit.
3. The script rewrites the `NOTICE` file with the new commit identifier.
4. The maintainer commits the change and opens a pull request.

## Screens & states

This feature set has no screen. Its output is the continuous-integration job
summary.

| State | What the maintainer sees |
|---|---|
| Pass | Every check is green. The summary shows the coverage number. |
| Lint failure | `ruff` names the file and the rule. |
| Type failure | `mypy` names the file, the line, and the error. |
| Conformance failure | The suite names the vector, the method, the expected value, and the produced value. |
| Empty suite | The suite fails with the message that it collected zero vectors. |

## Behaviour rules

- The coverage floor starts at the measured baseline, rounded down to a whole
  percent. It rises with each epic. It never falls.
- `mypy` runs without `--strict` in this epic. Epic 4 turns `--strict` on.
- The lint configuration lives in `pyproject.toml`, not in a separate file.
- `ruff` runs with the default rule set plus `I` for import order. A rule that
  produces more than 50 findings on the existing code is disabled with a comment
  that names the epic that will enable it.
- The vector download script never runs during a test. A test reads a committed
  file or it skips with a message that names the missing file.

## Data touched

- New directory `tests/foxio_vectors/`, holding 37 packet captures and 37
  expected-output files.
- New file `tests/foxio_vectors/NOTICE`.
- New file `.github/dependabot.yml`.
- Changed file `.gitignore`.
- Changed file `pyproject.toml`.
- Changed file `.github/workflows/test.yml`.
- Changed file `tests/download_test_vectors.py`.
- Changed file `tests/test_ja4db.py`.

## Interfaces

The vectors come from the FoxIO repository. Two paths matter.

| What | Path | Note |
|---|---|---|
| Packet captures | `pcap/<name>` | 38 files. One, `dtls-udp.notest.cap`, carries a `notest` marker and has no expected-output file. |
| Expected output | `python/test/testdata/<name>.json` | 37 files. This is the authority. |

The expected-output file is a JSON array. Each element describes one stream.

```json
[
  {
    "stream": 0,
    "src": "192.168.133.129",
    "dst": "34.117.237.239",
    "srcport": "36372",
    "dstport": "443",
    "domain": "contile.services.mozilla.com",
    "JA4.1": "t13d1715h2_5b57614c22b0_3d5424432f57",
    "JA4_r.1": "t13d1715h2_002f,0035,...",
    "JA4_o.1": "t13d1715h2_5b234860e130_014157ec0da2",
    "JA4_ro.1": "t13d1715h2_1301,1303,..."
  }
]
```

The suffix after the method name is an occurrence counter. `JA4SSH.1` is the
first JA4SSH fingerprint on that stream, `JA4SSH.2` the second.

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/python/test/testdata
(retrieved 2026-08-06).

The matching files under `wireshark/test/testdata/` are not the authority.
`wireshark/test/testdata/tls12.pcap.json` is an empty array, while the file under
`python/test/testdata/` holds four fingerprints for the same capture.

## Edge cases & failures

| Case | What happens |
|---|---|
| A vector file is missing from the working tree. | The suite fails and names the file. It does not download it. |
| A vector exercises a method this project does not implement. | The suite ignores that key and records it in the coverage report for the epic. |
| A vector exercises no method this project implements. | The suite reports the vector as not applicable. It does not count as a pass. |
| Every vector is not applicable. | The suite fails, because a silent skip looks like a pass. |
| `ruff` is not installed. | The workflow step fails. A local run is the developer's responsibility. |
| Python 3.9 rejects a type annotation. | The test job for 3.9 fails. This is the gate working. |

## Acceptance criteria

- [ ] `git ls-files tests/foxio_vectors | wc -l` reports 75 files.
- [ ] `git check-ignore -v tests/foxio_vectors/tls12.pcap` reports no match.
- [ ] `git check-ignore -v capture.pcap` at the repository root still reports a
      match, so an accidental capture stays excluded.
- [ ] `tests/foxio_vectors/NOTICE` names the upstream commit identifier.
- [ ] `pytest tests/ -m spec_validation` passes with no network access.
- [ ] `pytest tests/ -m spec_validation` fails when a vector file is deleted.
- [ ] The conformance suite fails when it collects zero vectors.
- [ ] `ruff check ja4plus/ tests/` reports no finding.
- [ ] `ruff format --check ja4plus/ tests/` reports no finding.
- [ ] `.git-blame-ignore-revs` names the formatting commit.
- [ ] The formatting commit changes no test result.
- [ ] `mypy ja4plus/` reports no error.
- [ ] The test job summary shows a line-coverage percentage.
- [ ] The test job fails when coverage falls below the floor.
- [ ] `pyproject.toml` declares `requires-python = ">=3.9"`.
- [ ] The full suite passes in a virtual environment that has no `python` on the
      path.
- [ ] `git branch -r` lists `origin/dev`.
- [ ] `gh repo view --json defaultBranchRef` reports `dev`.
- [ ] A push directly to `master` is rejected.
- [ ] Every `uses:` line in every workflow names a commit identifier.

## Out of scope

- Any change to a fingerprint. Epic 1 makes the vectors pass.
- `mypy --strict`. Epic 4 turns it on.
- The malformed-input suite. Epic 2 adds it.
- A benchmark job.

## Open questions

- The exact coverage floor. It is the measured baseline, and the baseline is not
  measured yet. The first issue in this epic measures it.
