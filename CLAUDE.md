# ja4plus

`ja4plus` is a Python library and command-line program. It reads network packets and
produces JA4+ fingerprints. FoxIO publishes the JA4+ standard. This project is an
independent implementation of it.

Version 0.6.0 is on PyPI. The project is working toward version 1.0.0.

Design lives in `docs/specs/`. Read `docs/specs/spec.md` and the relevant
`docs/specs/features/*.md` before you build a feature.

## The two rules that matter most

1. **The specification decides intent and schema. The vectors decide the exact bytes
   where intent runs out. A provable reference defect is declined and recorded.** A
   fingerprint exists so that one tool's output can be compared against another tool's
   output. Never change a fingerprinter without a vector, or a test derived from the
   FoxIO material, that proves the change is correct.
   `docs/specs/foxio/README.md` holds the FoxIO specification material and the method for
   a reading. `.claude/rules/conformance.md` states the two shapes that decline a defect.
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
mypy ja4plus/                                 # type check
python -m build                               # build the package
```

Run the conformance suite before you open a pull request that touches any file under
`ja4plus/fingerprinters/` or `ja4plus/utils/`.

## Branch model

The model is dev-and-live. `dev` is the default branch and the integration branch.
`master` is the release branch. Work merges into `dev`. A promotion from `dev` to
`master` is a separate approved step.

## Parity with ja4plus-go

A Go port exists at `Crank-Git/ja4plus-go`. The two must not drift apart. Three rules:

1. **FoxIO decides behaviour.** Where FoxIO specifies the output, the vectors decide.
   This outranks the port.
2. **The port decides interface.** Where FoxIO specifies nothing — a field name, a
   subcommand, a default — the port has already shipped a choice. Adopt it.
3. **The gate is the shared vector set.** No test here builds, runs, or imports the port.

Do not edit the port from this repository. `docs/specs/spec.md` holds the divergence
register.

## Conventions

- Every module gets its logger with `logging.getLogger(__name__)`. The library adds no
  handler and sets no level.
- A fingerprinter catches the parse errors it expects. It does not catch bare
  `Exception`.
- A state table has a maximum entry count and a maximum age. Nothing grows without a
  limit.
- No code holds a reference to a packet object after `process_packet` returns.
- Prose and code comments follow `.claude/rules/ste.md`. The controlled vocabulary is
  the `## Terms` table in `docs/specs/spec.md`.
- Commit messages use the form `type(scope): summary`, matching the existing history.
