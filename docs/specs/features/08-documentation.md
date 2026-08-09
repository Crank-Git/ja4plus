---
id: documentation
feature: Documentation
epic: "Epic 8: Documentation"
status: issued
issues: [19, 62, 63, 64, 65, 66]
mockups: []
---

## Purpose

The user asked for the documentation to be correct. Two statements in it are not.

The README said the project implements "all ten JA4+ methods". FoxIO documents
twelve, and counts JA4LS and JA4TScan separately. The project implements eleven of
the twelve, and it declines JA4TScan.

`JA4LFingerprinter` writes both JA4L and JA4LS, so ten fingerprinter classes carry
eleven methods. **Read the ten as a count of fingerprinter classes, and never as a
count of methods.** This paragraph stated ten of the twelve, and #387 corrected it.
`tests/test_documented_method_count.py` reads the count out of `ja4plus`, so a
document that states another number fails a case.

The README says nothing about thread safety, and nothing about memory growth. An
integrator who shares a processor between threads today gets no warning.

Nothing tests any code sample in the README, in `docs/`, or in `examples/`. A
sample that stops working stops working silently.

## User stories

- As a library integrator, I want a code sample that runs, so that I do not debug
  the documentation.
- As a library integrator, I want to read the concurrency contract before I write
  threaded code, so that I do not discover it from a corrupted state table.
- As an analyst, I want a searchable reference for every method, so that I do not
  read the source.

## Functional requirements

FR-documentation-1 — The README states which FoxIO methods the project implements
and which it does not.

FR-documentation-2 — The README states the concurrency contract.

FR-documentation-3 — The README states the memory bounds and their defaults.

FR-documentation-4 — Every code sample in the README runs in continuous
integration.

FR-documentation-5 — Every code sample in `docs/` runs in continuous integration.

FR-documentation-6 — Every script in `examples/` runs in continuous integration.

FR-documentation-7 — The documentation site builds from the Markdown files that
already exist.

FR-documentation-8 — The documentation site publishes to GitHub Pages on a push to
the live branch.

FR-documentation-9 — The documentation site carries an API reference generated from
the docstrings.

FR-documentation-10 — The documentation site carries a page per method.

FR-documentation-11 — The documentation site carries the output schema.

FR-documentation-12 — The documentation site carries a migration page for the move
from version 0.6.0 to version 1.0.0.

FR-documentation-13 — The `CHANGELOG.md` file records every breaking change in this
release.

FR-documentation-14 — The documentation states that FoxIO owns the JA4+ standard
and that this project is an independent implementation.

FR-documentation-15 — A broken internal link fails the documentation build.

## User flows

**An integrator learns the library.**

1. The integrator opens the documentation site.
2. The integrator reads the quick-start page and copies a sample.
3. The sample runs without a change.
4. The integrator reads the concurrency page before writing threaded code.

**A user upgrades from version 0.6.0.**

1. The user reads the migration page.
2. The page lists each breaking change and the replacement for it.
3. The user changes their code.

**A maintainer changes a docstring.**

1. The maintainer edits a docstring and opens a pull request.
2. Continuous integration builds the documentation site.
3. The build fails if a link broke.
4. The site publishes on merge to the live branch.

## Screens & states

| Screen | Purpose | States |
|---|---|---|
| Documentation home | Say what the project is and link the quick start. | Published. |
| Method page | Describe one method, its output, and its FoxIO source. | One page per implemented method. |
| API reference | List every public name with its signature and docstring. | Generated. |
| Migration page | List the breaking changes from version 0.6.0. | Published. |
| Output schema page | Define the JSON and CSV contract. | Published. |

The documentation site uses the `mkdocs-material` theme without modification. This
project writes no theme, so this feature set has no mockup.

## Behaviour rules

- The README stays the front door. It is short, and it links the site for detail.
- The README states method coverage as a table with an implemented column, so that
  the reader can see the two gaps rather than infer them.
- A code sample is tested by `pytest --doctest-glob`. A sample that cannot run in
  continuous integration, because it needs a capture interface, is marked and
  excluded, and the marker names the reason.
- An example script runs against a committed capture, not against a live
  interface.
- The migration page lists a breaking change with the old form, the new form, and
  the reason.
- Documentation prose follows the writing standard in `.claude/rules/ste.md` and
  uses the `## Terms` vocabulary from `docs/specs/spec.md`.
- The documentation build runs `mkdocs build --strict`, so a broken link fails it.

## Data touched

- Changed files: `README.md`, `CHANGELOG.md`, `docs/README.md`, `docs/usage.md`,
  `docs/api_reference.md`, `docs/implementation_notes.md`.
- New file `mkdocs.yml`.
- New files under `docs/methods/`, one per method.
- New file `docs/migration-0.6-to-1.0.md`.
- New file `docs/concurrency.md`.
- New file `.github/workflows/docs.yml`.
- Changed files under `examples/`.
- New file `tests/test_examples.py`.

## Interfaces

| Tool | Version | Documentation |
|---|---|---|
| `mkdocs-material` | 9.x | https://squidfunk.github.io/mkdocs-material/ |
| `mkdocstrings-python` | 1.x | https://mkdocstrings.github.io/python/ |
| GitHub Pages deployment | `actions/deploy-pages` v4 | https://github.com/actions/deploy-pages |

Verified against the pages above, retrieved 2026-08-06.

The documentation workflow needs `pages: write` and `id-token: write` permissions,
and the repository must have GitHub Pages set to build from GitHub Actions.

## Edge cases & failures

| Case | What happens |
|---|---|
| A code sample raises. | The doctest run fails and names the file and the line. |
| A sample needs a capture interface. | It is marked as not runnable, and the marker names the reason. |
| An internal link points at a page that does not exist. | `mkdocs build --strict` fails. |
| An example script needs a capture that is not committed. | The example test skips and names the missing capture. |
| GitHub Pages is not enabled on the repository. | The workflow fails with a message that names the setting. |
| A docstring is absent from a public function. | The API reference shows the signature with no description, and the lint rule for missing docstrings reports it. |

## Acceptance criteria

- [ ] The README method table lists twelve FoxIO methods and marks JA4TScan as not
      implemented.
- [ ] The README no longer claims that the project implements all JA4+ methods.
- [ ] The README states, in one paragraph, whether a processor may be shared
      between threads.
- [ ] The README states the default maximum connection count and the default
      maximum connection age.
- [ ] `pytest --doctest-glob="*.md" README.md docs/` passes.
- [ ] `pytest tests/test_examples.py` runs every script in `examples/` and passes.
- [ ] `mkdocs build --strict` succeeds.
- [ ] The documentation workflow publishes the site on a push to the live branch.
- [ ] The published site serves an API reference page for `Processor`.
- [ ] The published site serves one page per implemented method.
- [ ] The migration page lists every breaking change this release makes.
- [ ] `CHANGELOG.md` holds a `1.0.0` section that names each breaking change.
- [ ] Every method page cites its FoxIO source.

## Out of scope

- A translated documentation site.
- A custom theme.
- Versioned documentation for releases before 1.0.0.
- A tutorial series.

## Open questions

None.
