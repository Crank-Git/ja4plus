# ja4plus

`ja4plus` is a Python library and command-line program. It reads network packets and
produces JA4+ fingerprints. FoxIO publishes the JA4+ standard. This project is an
independent implementation of it.

This repository declares version 1.1.1, and `ja4plus/__init__.py:101` holds that one
declaration. A publish to PyPI is a separate step, and the maintainer runs it.

Design lives in `docs/specs/`. Read `docs/specs/spec.md` and the relevant
`docs/specs/features/*.md` before you build a feature.

## The two rules that matter most

1. **The specification decides intent and schema. The vectors decide the exact bytes
   where intent runs out. A provable reference defect is declined and recorded.** A
   fingerprint exists so that one tool's output can be compared against another tool's
   output. Never change a fingerprinter without a vector, or a test derived from the
   FoxIO material, that proves the change is correct.
   `docs/specs/foxio/README.md` holds the inventory of the FoxIO specification material
   and the transcription procedure. `.claude/rules/conformance.md` states the two shapes
   that decline a defect.
2. **Every packet is hostile input.** No parser trusts a length field it read from the
   packet. A parser that cannot read a packet returns nothing. It does not raise.

## Layout

| Path | What it holds |
|---|---|
| `ja4plus/fingerprinters/` | One module per method. `base.py` holds the shared class. |
| `ja4plus/utils/` | Protocol parsing: TLS, HTTP, SSH, X.509, QUIC, TCP reassembly. |
| `ja4plus/processor.py` | The `Processor` class that runs every fingerprinter. |
| `ja4plus/cli.py` | The command-line program. |
| `ja4plus/ja4db.py` | Fingerprint lookup against the FoxIO mapping file. |
| `ja4plus/data/` | The bundled `ja4plus-mapping.csv`. |
| `tests/` | The test suite. |
| `tests/foxio_vectors/` | The FoxIO packet captures and expected output. |
| `docs/specs/` | The spec package. |

## Commands

```bash
pip install -e ".[dev]"                       # install
pytest tests/ -m "not spec_validation"        # unit suite
pytest tests/ -m spec_validation              # FoxIO conformance suite
ruff check ja4plus/ tests/                    # lint
ruff format ja4plus/ tests/                   # format
mypy --strict ja4plus/                        # type check
python -m build                               # build the package
```

Run the conformance suite before you open a pull request that touches any file under
`ja4plus/fingerprinters/` or `ja4plus/utils/`.

## Branch model

The model is dev-and-live. `dev` is the default branch and the integration branch.
`master` is the release branch. Work merges into `dev`. A promotion from `dev` to
`master` is a separate approved step.

**Read `.claude/rules/batch-gate.md` before you merge a batch pull request.** An absent
run is not a passed run, and `gh pr checks` reports an absence as "no checks reported".
`python -m tests.batch_gate --pr <number>` exits non-zero on every state that is not a
terminal successful run of the head commit. #459 records the cause: a skip keyword
anywhere in a head commit message creates no run for that commit.

## Parity with ja4plus-go

A Go port exists at `Crank-Git/ja4plus-go`. The two must not drift apart. Three rules:

1. **FoxIO decides behaviour.** Where FoxIO specifies the output, the vectors decide.
   This outranks the port.
2. **The port decides interface.** Where FoxIO specifies nothing — a field name, a
   subcommand, a default — the port has already shipped a choice. Adopt it.
3. **The gate is the shared vector set.** No test here builds, runs, or imports the port.

**Rule 2 carries the shape of a pattern and no statement of its cost.**
`.claude/rules/conformance.md` requires a measurement against hostile input before a
regular expression from the port lands. #612 measured 3017.9 milliseconds on the ported
form of one pattern.

Do not edit the port from this repository. `docs/specs/spec.md` holds the divergence
register.

## Conventions

- Every module gets its logger with `logging.getLogger(__name__)`. The library adds no
  handler and sets no level.
- A fingerprinter catches the parse errors it expects. It does not catch bare
  `Exception`.
- A state table has a maximum entry count and a maximum age. A state table survives
  across packets, and nothing that survives across packets grows without a limit.
- A structure that one packet or one request builds and releases is not a state table,
  and it holds neither bound. The cookie list of one HTTP request is such a structure.
  #175 records the ruling. The boundary removes no bound from a state table. The six
  unbounded state tables that #179 records keep their bound.
- No code holds a reference to a packet object after `process_packet` returns.
- Prose and code comments follow `.claude/rules/ste.md`. The controlled vocabulary is
  the `## Terms` table in `docs/specs/spec.md`.
- Commit messages use the form `type(scope): summary`, matching the existing history.

## How to file an issue

**Warning: the rule below is a verbatim copy from `Crank-Git/ja4plus-go/CLAUDE.md`, and
every issue number it names is an issue of the port.** No issue of this repository carries
those numbers under this rule. #727 adopted the rule under parity rule 2, because FoxIO
specifies no filing policy.

- **A finding earns a tracker issue in five cases, and never otherwise.** The maintainer
  adopted this policy on 2026-08-13. A finding earns an issue when it touches one of these.
  - Behavior.
  - A fingerprint value.
  - A guard that guards nothing.
  - A blocked epic.
  - A question the maintainer must rule.

  **The batch documentation round repairs every other finding, in the batch that found it,
  and it files no issue.** A falsified sentence, a moved citation, a missing term and a
  stale count each reach the round. **The round reports a finding that turns out to touch
  behavior**, and that finding then becomes an issue under the five cases above.

  The measurement that earned the policy: of 42 loose open issues, about twenty repaired a
  sentence, a citation, a term or a stale count. **Each repair produced more issues.** #410
  exists because #398 edited a file. #419 exists because #355 edited a file. #436 exists
  because #70 measured something. **The backlog regenerated at about the rate it closed.**

**The maintainer set one valve on 2026-08-15, and `.issue-flow.json` records it under
`filingRule`.** No issue is filed whose only symptom is a stale citation, or a record that
describes a past state. Three rules follow.

1. A worker repairs what its own change falsifies, in the same pull request, even where
   another live batch owns the file. The project manager resolves the conflict once, at
   the sub-merge.
2. A finding that does not fit the change becomes a comment on an issue that exists, and
   never a new issue.
3. A finding that is a defect of the library, or that moves a fingerprint, is still filed.
   This valve reaches a record, and it reaches no measurement of the product.

**#708, #709 and #719 are the three issues the maintainer declined under this valve.** A
read of 2026-08-15 measured the last 300 commits of `master`: 56 touch a file under
`ja4plus/`, 192 touch `docs/specs/spec.md` and 186 touch `CHANGELOG.md`, against 333 closed
issues.
