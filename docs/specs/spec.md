---
name: ja4plus 1.0
slug: ja4plus
repo: Crank-Git/ja4plus
status: approved
spec_version: 2
created: 2026-08-06
approved: 2026-08-06
html_generated: 2026-08-06
branch_model: dev-and-live
features:
  - id: foundation
    file: features/00-foundation.md
  - id: spec-conformance
    file: features/01-spec-conformance.md
  - id: correctness-audit
    file: features/02-correctness-audit.md
  - id: concurrency-safety
    file: features/03-concurrency-safety.md
  - id: typed-api
    file: features/04-typed-api.md
  - id: structured-output
    file: features/05-structured-output.md
  - id: live-capture
    file: features/06-live-capture.md
  - id: db-enrichment
    file: features/07-db-enrichment.md
  - id: documentation
    file: features/08-documentation.md
  - id: release
    file: features/09-release.md
---

# ja4plus 1.0

## Overview

`ja4plus` is a Python library and command-line program. It reads network packets
and produces JA4+ fingerprints. FoxIO publishes the JA4+ standard. `ja4plus` is an
independent implementation of that standard. Version 0.6.0 is on PyPI now.

This spec defines version 1.0.0. Version 1.0.0 makes three promises that version
0.6.0 does not make. The first promise is conformance: every fingerprinter matches
the FoxIO reference output on every FoxIO test vector. The second promise is
safety: the library states a thread-safety contract, holds bounded memory, and
survives malformed packets. The third promise is stability: the public interface is
typed, documented, and does not change again before version 2.0.0.

The reader of this spec is an engineer who works on `ja4plus`. The user of
`ja4plus` is a security engineer. That user reads packet captures, or watches live
traffic, and needs a fingerprint they can compare against a fingerprint another
tool produced. A fingerprint that does not match the reference is worthless to
that user, because comparison is the only thing a fingerprint is for.

## Terms

| Term | Part of speech | Meaning in this project | Do not use |
|---|---|---|---|
| method | noun | One named JA4+ algorithm, for example JA4 or JA4SSH. | type, algorithm, mode |
| fingerprint | noun | The output string of one method for one connection. | hash, signature, ID |
| fingerprinter | noun | The class that implements one method. | analyzer, parser, engine |
| processor | noun | The `Processor` class that runs every fingerprinter on each packet. | aggregator, pipeline, collector |
| connection | noun | One network flow, identified by protocol and two endpoints. | session, stream, flow |
| endpoint | noun | One address and one port. | host, peer, side |
| state table | noun | The dictionary a fingerprinter uses to hold per-connection data. | cache, store, map |
| eviction | noun | The removal of one entry from a state table. | cleanup, expiry, purge |
| vector | noun | One FoxIO packet capture plus its expected-output file. | fixture, sample, test case |
| conformance suite | noun | The test suite that compares `ja4plus` output against every vector. | validation tests, spec tests |
| window | noun | The count of packets JA4SSH reads before it emits a fingerprint. | interval, batch, sample |
| raw form | noun | The unhashed form of a fingerprint, for example `JA4_r`. | expanded form, debug form |
| result | noun | One typed object that carries a fingerprint and its connection. | record, row, output |
| emit | verb | To return a fingerprint from a fingerprinter. | output, produce, yield |
| evict | verb | To remove one entry from a state table. | clean up, expire, purge |
| conform | verb | To produce the same output as the FoxIO reference. | comply, match spec |
| port | noun | The Go implementation at `Crank-Git/ja4plus-go`. | Go version, sibling, twin |
| parity | noun | The state where this project and the port expose the same interface and emit the same fingerprint. | alignment, sync, consistency |
| hop count | noun | The count of routers a packet crossed, read as the initial TTL minus the observed TTL. | hop distance, TTL delta |
| propagation factor | noun | The JA4L divisor that the FoxIO hop-count table gives for one hop count. | propagation delay, terrain factor |

## Goals

1. Every method matches the FoxIO reference output on all 37 FoxIO vectors, except
   where the reference holds a proven defect this project declines to reproduce.
   `.claude/rules/conformance.md` states the two shapes that decide it, and every
   exception carries a closed issue and a register entry. #96, #97 and #105 are the
   first three.
2. The conformance suite runs on every pull request and blocks a merge on failure.
3. The library holds bounded memory under a continuous packet stream.
4. The library states one thread-safety contract, and tests prove that contract.
5. No packet input crashes the library, including truncated and corrupt packets.
6. Test coverage is 90 percent or higher, measured by line.
7. The public interface carries type annotations, and `mypy --strict` passes on it.
8. Version 1.0.0 is on PyPI, with documentation published on GitHub Pages.
9. This project and the port emit the same fingerprint for every vector, and the
   typed result carries the same field names.

## Non-goals

- JA4TScan is out of scope. It is an active scanner, and `ja4plus` reads traffic
  only. The README must stop implying full method coverage while this is true.
- Live packet capture on Windows is out of scope. The daemon mode targets Linux
  and macOS.
- A fingerprint database service is out of scope. `ja4plus` reads FoxIO's
  published mapping file and, when the user opts in, the public `ja4db.com` API.
- Wire-speed performance is out of scope. The project measures throughput and
  reports it, but sets no throughput target for version 1.0.0.
- An asynchronous interface is out of scope. The library stays synchronous.

## Users & personas

| Persona | What they need | What they are allowed to do |
|---|---|---|
| Capture analyst | Fingerprints from a saved packet capture, in a format another tool can read. | Read a capture file. Write output to a file or to standard output. |
| Monitor operator | A long-running process that reads a live interface and never exhausts memory. | Open a capture interface. This needs elevated privileges on the host. |
| Library integrator | A typed, documented Python interface with a stated concurrency contract. | Import `ja4plus` inside their own program. |
| Maintainer | Evidence that a change did not break conformance. | Merge a pull request when every gate passes. |

## Feature map

| Feature set | Spec file | Epic | Mockups |
|---|---|---|---|
| Foundation | `features/00-foundation.md` | Epic 0: Foundation | — |
| Spec conformance | `features/01-spec-conformance.md` | Epic 1: Spec conformance | — |
| Correctness audit | `features/02-correctness-audit.md` | Epic 2: Correctness audit | — |
| Concurrency and resource safety | `features/03-concurrency-safety.md` | Epic 3: Concurrency and resource safety | — |
| Typed public interface | `features/04-typed-api.md` | Epic 4: Typed public interface | — |
| Structured output | `features/05-structured-output.md` | Epic 5: Structured output | `mockups/01-cli-output.html` |
| Live capture | `features/06-live-capture.md` | Epic 6: Live capture | — |
| Database enrichment | `features/07-db-enrichment.md` | Epic 7: Database enrichment | — |
| Documentation | `features/08-documentation.md` | Epic 8: Documentation | — |
| Release | `features/09-release.md` | Epic 9: Release | — |

## Architecture & stack

`ja4plus` is a pure Python package. It has two runtime dependencies.

| Component | Choice | Why this choice beat the alternative |
|---|---|---|
| Language | Python 3.9 or later | Python 3.8 reached end of life in October 2024. Python 3.9 is the oldest line that still receives security fixes. |
| Packet parsing | `scapy>=2.4.0` | `scapy` reads every capture format the project needs and needs no C toolchain. `dpkt` is faster but parses fewer link types. |
| Certificate parsing | `cryptography>=42.0.0` | JA4X reads X.509 structure. `cryptography` is maintained and already a dependency. |
| Build backend | `setuptools` | Already in use. A move to `hatchling` changes nothing a user sees. |
| Test runner | `pytest` | Already in use, and the conformance suite needs its parameterization. |
| Lint and format | `ruff` | One tool replaces `flake8`, `isort` and `black`. It runs in under one second on this codebase. |
| Type check | `mypy --strict` on `ja4plus/` | `mypy` supports the `py.typed` marker that the typed interface needs. `pyright` needs Node.js in CI. |
| Documentation site | `mkdocs-material` with `mkdocstrings` | The existing documentation is Markdown. Sphinx would need a rewrite into reStructuredText. |
| Documentation host | GitHub Pages | The repository is already on GitHub. Read the Docs adds an account and a webhook. |
| Package host | PyPI, through trusted publishing | Already configured in `.github/workflows/publish.yml`. No token is stored. |

Data flow: a packet enters `Processor.process_packet`. The processor calls each of
the ten fingerprinters in a fixed order. A fingerprinter reads the packet, updates
its state table, and emits a fingerprint or returns nothing. The processor collects
every fingerprint into a list of results and returns it.

Verified against: https://github.com/FoxIO-LLC/ja4 (retrieved 2026-08-06, upstream
default branch at commit dated 2026-07-21).

## Parity with ja4plus-go

A Go port of this project exists at `Crank-Git/ja4plus-go`. `ja4plus/processor.py`
already states that it mirrors that port. The two must not drift apart, because a
user who runs both must get one answer.

Three rules govern parity.

1. **FoxIO decides behaviour.** Where FoxIO specifies the output, the vectors
   decide. This rule outranks the port. Where the port disagrees with a vector, the
   port is wrong.
2. **The port decides interface.** Where FoxIO specifies nothing — a field name, a
   subcommand name, a default — the port has already shipped a choice. This project
   adopts that choice rather than inventing a second one.
3. **The gate is the shared vector set.** Both repositories read the same 37 FoxIO
   vectors, pinned to the same upstream commit. No test in this repository builds,
   runs, or imports the port. A cross-language test rig couples two repositories
   that move at different speeds, and it fails for reasons that have nothing to do
   with the change under test.

This spec plans changes to this repository only. It records what the port should
change, and files nothing there.

### Divergence register

| Item | This project today | The port today | Rule | Action |
|---|---|---|---|---|
| Result type | `dict` with 8 keys. | `FingerprintResult` struct with 9 fields. | 2 | Adopt the port's field set, including `Timestamp`. Epic 4. |
| Results per packet | One fingerprint string. | A slice of results. | 2 | Return a list. Epic 4. |
| Parse failures | Swallowed, logged at `DEBUG`. | Returned as a second value. | 2 | Expose the errors the processor collected. Epic 4. |
| Remote lookup | The command-line flag `--lookup` is opt-in, but `JA4DBClient.lookup` then calls `ja4db.com` on every miss with no second opt-in. | The remote fallback is a separate opt-in. | 2 | Separate the local lookup from the remote lookup. Epic 7. |
| Mapping file refresh | `db update` and `db info` already exist. | The same two subcommands. | — | Already at parity. Keep a test that proves it. |
| Shard key format | `tcp:ip:port->ip:port`. | The same format. | — | Already at parity. Keep a test that proves it. |
| JA4SSH window | Emits at `packet_count`, which defaults to 200. | Emits at `min(packetCount, 10)`. | 1 | Fixed here by #28. The port carries the defect at `ja4ssh.go:176`. |
| JA4SSH results the reference produces and this project declines | Reads the mode field from the window alone, emits a value only for a window that holds SSH packets, and emits the trailing window for every connection that closes. | Not measured. | 1 | Three defects of the FoxIO reference produce output that describes the capture and not the connection, so rule 1 does not settle them and a person decided each one. #96, #97 and #105 hold the decision and the measurement. The port must adopt all three, or the two implementations disagree on JA4SSH. |
| Parity test | 6 tests that assert names exist. | Not applicable. | 3 | Replace with the shared vector suite. Epic 1. |

Verified against: https://github.com/Crank-Git/ja4plus-go (`types.go`,
`processor.go`, `lookup.go`, `ja4ssh.go`, retrieved 2026-08-06, default branch
`master` at 2026-05-09).

## Data model

The library holds no database. It holds three kinds of in-memory state.

### Result

The typed object each fingerprinter returns. Epic 4 defines it as a frozen
dataclass named `FingerprintResult`. The field names are the snake-case form of
the port's `FingerprintResult` struct, under parity rule 2. The field that names
the method is called `type`, because the port calls it `Type` and because the
current dictionary already uses that key.

| Field | Type | Constraint |
|---|---|---|
| `type` | `str` | One of the ten method names, lowercase. |
| `fingerprint` | `str` | The fingerprint string. Never empty. |
| `raw` | `str \| None` | The raw form, when the method defines one. |
| `raw_original_order` | `str \| None` | The original-order raw form, when the method defines one. |
| `src_ip` | `str` | Source address. Empty when the packet carries no address. |
| `src_port` | `int` | Source port. Zero when the packet carries no port. |
| `dst_ip` | `str` | Destination address. |
| `dst_port` | `int` | Destination port. |
| `timestamp` | `datetime \| None` | The packet timestamp. The port carries this field and this project does not. |

### Connection state

Each stateful fingerprinter holds one state table. The key is the connection. The
value holds the data the method needs across packets.

| Method | What the value holds | Lifecycle |
|---|---|---|
| JA4 | QUIC CRYPTO fragments, keyed by connection identifier. | Created on the first fragment. Evicted when the handshake message is complete, on eviction by age, or on eviction by count. |
| JA4H | Reassembled TCP segments. | Created on the first segment. Evicted when the request is complete, on eviction by age, or on eviction by count. |
| JA4X | Reassembled TCP segments. | Same as JA4H. |
| JA4L | Handshake timestamps and observed TTL values. | Created on the first packet. Evicted when the handshake is complete, on eviction by age, or on eviction by count. |
| JA4SSH | Packet lengths, bare-ACK counts, and banner strings. | Created on the first SSH packet. Counters reset at each window. Evicted on eviction by age or by count. |

### Vector

One entry in the conformance suite.

| Field | Type | Constraint |
|---|---|---|
| capture file | path | A file under `tests/foxio_vectors/`. |
| expected file | path | The matching `.json` file FoxIO publishes. |
| upstream commit | string | The FoxIO commit the snapshot came from. |

## Cross-cutting concerns

**Thread safety.** Every fingerprinter and the processor lock their state table by
default. A caller who shards traffic across processes, and needs the fastest path,
constructs the processor with `thread_safe=False`. Feature set
`concurrency-safety` defines the contract and the tests that prove it.

**Bounded memory.** Every state table has a maximum entry count and a maximum age.
The library never holds a reference to a packet object after
`process_packet` returns. Feature set `concurrency-safety` defines the limits.

**Error handling.** A fingerprinter that cannot parse a packet returns nothing. It
does not raise. The processor logs the failure at `DEBUG` and continues with the
next fingerprinter. A caller error, such as a bad argument, raises `ValueError`.
The library defines no exception type of its own before version 1.0.0.

**Validation.** The library treats every packet as hostile input. No parser trusts
a length field it reads from the packet. Feature set `correctness-audit` defines
the malformed-input suite.

**Logging.** Every module uses `logging.getLogger(__name__)`. The library adds no
handler and sets no level. The command-line program configures logging.

**Security posture.** The library performs no network request unless the caller
opts in. Feature set `db-enrichment` makes the `ja4db.com` lookup opt-in, because a
fingerprint sent to a third party discloses traffic the operator observed.

**Performance.** The project measures packets per second on a fixed capture and
records the number in the pull request. Version 1.0.0 sets no target. A change that
halves throughput needs a stated reason.

## Environments & config

The library reads no environment variable. The command-line program and the
continuous-integration workflow read the following.

| Name | Where it is read | What it does |
|---|---|---|
| `JA4PLUS_DB_LOOKUP` | Command-line program | When set to `1`, the program allows the remote lookup. The `--lookup-remote` flag does the same. |
| `GITHUB_TOKEN` | Workflows | Provided by GitHub Actions. The documentation workflow uses it to publish to GitHub Pages. |

No secret is stored in the repository. PyPI publishing uses trusted publishing, so
no PyPI token exists.

Seed data: the conformance suite needs the FoxIO vectors. Epic 0 commits them under
`tests/foxio_vectors/`, with a `NOTICE` file that records the upstream commit, the
source URL, and the FoxIO License 1.1 attribution.

Verified against: https://docs.pypi.org/trusted-publishers/ (retrieved 2026-08-06).

## Testing strategy

| Layer | What it covers | Command |
|---|---|---|
| Unit | One function or one class, with synthetic packets. | `pytest tests/ -m "not spec_validation"` |
| Conformance | Every FoxIO vector against the FoxIO expected output. | `pytest tests/ -m spec_validation` |
| Malformed input | Truncated, corrupt and adversarial packets against every parser. | `pytest tests/fuzz/` |
| Concurrency | Many threads against one processor, checked for state corruption. | `pytest tests/test_thread_safety.py` |
| Documentation | Every code sample in the README and in `docs/`. | `pytest --doctest-glob="*.md" README.md docs/` |
| Packaging | The built wheel installs into a clean environment and runs. | `pytest tests/test_packaging.py` |

A change is done when every layer above passes, `ruff check` reports nothing,
`mypy --strict ja4plus/` reports nothing, and line coverage is 90 percent or
higher.

## Epics

### Epic 0: Foundation

Goal: make the gates exist before any behaviour changes, so every later epic has
something that can fail.

Covers `features/00-foundation.md`. Depends on nothing.

Exit criteria: the `dev` branch exists. Continuous integration runs `ruff`, `mypy`,
the unit suite and the conformance suite on every pull request. The FoxIO vectors
are committed. Coverage is measured and reported. The two failing tests in
`tests/test_ja4db.py` pass.

### Epic 1: Spec conformance

Goal: every method matches the FoxIO reference on every vector.

Covers `features/01-spec-conformance.md`. Depends on Epic 0.

Exit criteria: all 37 vectors pass. The JA4SSH window is 200 packets. `JA4_o` is
exposed. The JA4L propagation factor follows the FoxIO table. The six surface-area
tests in `tests/test_parity.py` are replaced by the vector suite.

### Epic 2: Correctness audit

Goal: remove the defects that produce a wrong fingerprint, or a crash, on input the
vectors do not cover.

Covers `features/02-correctness-audit.md`. Depends on Epic 1, because a conformance
gate must exist before a parser changes.

Exit criteria: the malformed-input suite passes. TCP sequence wraparound is
handled. JA4L emits one client fingerprint per connection. JA4H handles a repeated
cookie name.

### Epic 3: Concurrency and resource safety

Goal: state the concurrency contract, prove it, and bound every state table.

Covers `features/03-concurrency-safety.md`. Depends on Epic 2.

Exit criteria: the thread-safety suite passes. Every state table has a maximum
count and a maximum age. A one-hour packet stream holds flat memory.

### Epic 4: Typed public interface

Goal: give version 1.0.0 an interface that does not change again before 2.0.0.

Covers `features/04-typed-api.md`. Depends on Epic 3, because the constructor
signature carries the `thread_safe` argument.

Exit criteria: `mypy --strict ja4plus/` reports nothing. `py.typed` ships in the
wheel. `Processor.process_packet` returns typed results whose field names match the
port. The processor exposes the parse failures it collected.
`ja4plus/collector.py` is removed.

### Epic 5: Structured output

Goal: give the capture analyst an output format another tool can read.

Covers `features/05-structured-output.md`. Depends on Epic 4, because the output
schema is derived from the typed result.

Exit criteria: the command-line program writes JSON Lines, CSV and a table. The
schema is documented and versioned.

### Epic 6: Live capture

Goal: make a long-running monitor a supported mode rather than an example script.

Covers `features/06-live-capture.md`. Depends on Epic 3 and Epic 5.

Exit criteria: `ja4plus watch` reads an interface, evicts connections by age,
handles a termination signal, and reports its own statistics.

### Epic 7: Database enrichment

Goal: make fingerprint lookup useful offline and safe by default.

Covers `features/07-db-enrichment.md`. Depends on Epic 4.

Exit criteria: no network request happens unless the caller opts in. Bulk lookup
exists. The `db update` and `db info` subcommands exist and match the port. The
mapping file refresh is documented.

### Epic 8: Documentation

Goal: make every published statement about `ja4plus` true and testable.

Covers `features/08-documentation.md`. Depends on every epic above, because the
documentation describes the finished interface.

Exit criteria: the documentation site builds and publishes. Every code sample runs
in continuous integration. The README states the concurrency contract and the real
method coverage.

### Epic 9: Release

Goal: publish version 1.0.0.

Covers `features/09-release.md`. Depends on Epic 8.

Exit criteria: version 1.0.0 is on PyPI. The wheel installs into a clean
environment. The GitHub release carries the changelog entry.

## Milestones

| Milestone | Epics | What "shippable" means here |
|---|---|---|
| M1 — Gates | 0 | The repository can prove a regression. Nothing user-facing changed. |
| M2 — Correct | 1, 2 | Every fingerprint matches the reference. This alone justifies a 0.7.0 release if version 1.0.0 slips. |
| M3 — Safe | 3 | A monitor can run for a day without memory growth. |
| M4 — Stable | 4, 5, 6, 7 | The interface is typed and will not change again before 2.0.0. |
| M5 — Released | 8, 9 | Version 1.0.0 is on PyPI with published documentation. |

## Assumptions

1. The user accepts a break in the `Processor.process_packet` return type at
   version 1.0.0. A major version is the correct place for it.
2. FoxIO License 1.1 permits redistribution of the vectors with attribution. The
   project already declares `LicenseRef-FoxIO-1.1` in `pyproject.toml`.
3. The FoxIO expected-output files under `python/test/testdata/` are the reference
   the project measures against. The matching files under `wireshark/test/testdata/`
   are not, because `tls12.pcap.json` there is an empty list.
4. `Development Status` moves to `5 - Production/Stable` at version 1.0.0.
5. The default state-table limits are 10000 entries and 300 seconds. Epic 3 tunes
   them against a measurement.
6. The remote lookup becomes opt-in. This changes behaviour for a caller who relies
   on it today, which a major version permits.
7. The port stays at its 2026-05-09 state while this work proceeds. Another session
   works on the port. This spec reads the port and never writes to it.
8. The port adopts the same 200-packet JA4SSH window. Until it does, the two
   implementations disagree on JA4SSH. This spec follows FoxIO, per parity rule 1.

## Risks & open questions

| Item | Why it matters | Blocks approval |
|---|---|---|
| Some FoxIO methods are specified only in a PNG image, not in text. `technical_details/` holds `JA4.md` and `JA4H.md` as text and publishes JA4L, JA4S, JA4SSH, JA4T, JA4X, JA4D and JA4D6 as images. Where the image is ambiguous, the project treats the expected-output files as the authority and records the reading in `docs/implementation_notes.md`. | An ambiguous spec produces a defensible but non-conforming implementation. | No |
| Not every vector exercises a method `ja4plus` implements. The suite must skip a method a vector does not cover, and must never pass by skipping everything. | A silent skip looks identical to a pass. | No |
| The 90 percent coverage target may not be reachable on the `scapy` interface layer without brittle mocks. | An unreachable gate gets lowered under pressure, which defeats it. | No |
| Fixing the JA4SSH window changes the output for every existing user of that method. | It is a breaking behaviour change, correct but disruptive. Version 1.0.0 is the right place, and the changelog must state it plainly. | No |
| The README claims ten methods. FoxIO documents twelve, and counts JA4LS and JA4TScan separately. | A false coverage claim is the kind of documentation error the user asked to fix. | No |
| Fixing the JA4SSH window here, before the port fixes it, breaks parity on that one method until the port catches up. | A user who runs both gets two answers for JA4SSH during that period. | No |

Two items blocked approval. Both are now decided.

- **JA4TScan stays out of scope.** It sends crafted packets and this project reads
  traffic. Epic 8 corrects the coverage claim in the README instead. This is a
  permanent non-goal, not deferred work.
- **`dev` becomes the default branch on GitHub.** A pull request then opens against
  `dev` with no manual step. `master` stays the release branch and is protected.
  Epic 0 makes both changes.

## Changelog

| Round | Date | What changed |
|---|---|---|
| 1 | 2026-08-06 | First draft, written from the Phase 1 interview and a read of the codebase at commit `5ab0252`. |
| 2 | 2026-08-06 | Added the parity section and the divergence register after the user named the Go port. Corrected the register: `db update`, `db info`, and the three output formats already exist in `ja4plus/cli.py`. |
| 3 | 2026-08-06 | Approved. JA4TScan confirmed out of scope. `dev` confirmed as the GitHub default branch. |
| 4 | 2026-08-06 | Epic 0 built. #27 was moved into the Epic 0 batch, and stays a child of Epic 1, because #23 cannot gate the conformance suite against a harness that compares one expected value against every fingerprint in a capture. |
| 5 | 2026-08-06 | The `xfail` decision on #23 was revised from five hand-written markers to a deviation register keyed by case, applied as `xfail(strict=True)`, after the measured baseline came to 263 known deviations rather than 5. |
| 6 | 2026-08-06 | The conformance baseline was measured for the first time. It is recorded on #12. The figure of 69 of 74 vectors passing is withdrawn: it came from a harness that matched a value against every fingerprint in a capture and skipped four whole methods. |
| 7 | 2026-08-06 | #78 opened. JA4X fails 35 cases and no issue owned the method. |
| 8 | 2026-08-06 | #80 opened. The conformance harness never runs the JA4L fingerprinter, so 162 of the 263 registered deviations state a harness defect, not non-conformance. JA4L conformance is unmeasured until #80 lands. |
| 9 | 2026-08-06 | Epic 1 batch 1 shipped: #29 `JA4_o`, #80 the JA4L harness, #28 the JA4SSH window. Two are breaking behaviour changes. |
| 10 | 2026-08-06 | #88, #92 and #78 opened for the conformance gaps the honest harness exposed. #34 widened to both directions of the connection and its acceptance criterion withdrawn; #89 carries that correction into the feature file. |
| 11 | 2026-08-06 | `JA4S_o` is published with no FoxIO material to validate it. Recorded for the ambiguity register #31 builds. |
| 12 | 2026-08-07 | Epic 1 batch 1 merged into `dev` as `e911d99`, after #94. The conformance suite gave different results on Linux and on macOS: a capture whose link type is `DLT_NULL` starts each frame with the capturing host's address family value, and scapy binds only the reading host's value. `ja4plus` binds 24, 28 and 30 to the IPv6 layer. The suite now reports the same counts on both hosts, and the register count of 240 is host-independent. The rounds below hold two entries numbered 9. |
| 9 | 2026-08-06 | #80 landed and JA4L conformance is measured for the first time. The harness runs the JA4L fingerprinter, reads the JA4L connection key form, and strips the method prefix from the produced value. The register holds 252 entries, and it held 263. JA4L passes 16 of its 167 cases. #88 opened to own the 114 value cases, and #34 widened to own the 37 occurrence-key cases on both sides of the connection. #89 opened, because the vectors contradict the JA4L requirement in `features/02-correctness-audit.md`. |
| 13 | 2026-08-07 | #78 landed and JA4X passes 26 of its 35 failing cases. Two defects caused them. The scan read only the first handshake message of a TLS record. The processed certificate table named the certificate alone, so it dropped the value of every stream after the first that carried the same chain. The JA4X register entries fall from 35 to 9, and the register holds 214 entries where it held 240. Seven of the nine state that the reference decrypts the handshake with the secrets the capture carries. Two state that the reference reads no TLS on the proxy port. `socks4-https.pcap/JA4X` is one of the two, and it is a new entry: the scan now reads three certificates that the reference never sees. The project withdraws the claim that JA4X "depends on full TLS dissection which is not always available from pcapng captures". `b9a19a3` removed that claim with `KNOWN_DEVIATIONS`, and the measurement now names a cause for each case. |

| 14 | 2026-08-07 | Goal 1 gains an exception. The FoxIO reference holds three proven defects, and the user decided `ja4plus` reproduces none of them. #96: `dict(ja4sh_stats)` shares one payload list across every window on every connection, so the reference mode field reads the whole capture. #97: a bare ACK after a window boundary writes an occurrence key from a window of zero SSH packets. #105: `finalize_ja4ssh` guards with `if stream:`, and the index 0 is false, so no trailing window reaches the connection at index 0. Each is proven by a measurement of the reference at the pinned commit, not by a reading of its source. `.claude/rules/conformance.md` now states when this project declines a reference defect, and it names the two shapes: a fingerprint that depends on the capture rather than the connection, and a fingerprint that describes no traffic. A defect outside those two shapes stays a question for the user. |
| 15 | 2026-08-07 | #92 landed. `tshark` settled the condition FoxIO applies to the window a connection holds open at close, and the answer was #105. `ssh-r.pcap` now produces the reference occurrence keys on all three streams, and `ssh-scp-1050.pcap` matches with no register entry. Eleven JA4SSH entries remain: #96 owns 4, #97 owns 3, #105 owns 3, #98 owns 1. #105 costs three cases that matched before. `gre-sample.pcap`, `sshv1.pcap` and `v6.pcap` now hold a trailing JA4SSH fingerprint the reference output does not hold, and it is the first divergence where this project emits more than the reference. #98 opened: `ja4plus` counts a TCP segment where the reference counts an SSH message, so the two disagree by one packet for each SSH message that spans two segments. |
| 16 | 2026-08-07 | #88 landed and the JA4L values conform. FoxIO reports one-way latency, so it halves every measured round-trip time, and `JA4L-C` measures to the client's first data packet after the SYN-ACK. The comment at `ja4l.py:218` stated the opposite and is deleted. The register falls from 213 entries to 74, and JA4L conformance failures fall from 151 to 12. #34 shrank as a side effect, from 37 occurrence-key entries to 6, and it is re-scoped before it is scheduled. #101 opened: `gre-erspan-vxlan.pcap` mirrors both directions of the inner connection from one outer address pair, so the SYN and the SYN-ACK reach two different connection keys. #102 opened: `ja4plus` reads the first server Initial packet of a QUIC connection, and the reference reads the Initial packet that completes the ServerHello. |
| 17 | 2026-08-07 | Epic 1 batch 2 ships #78, #92 and #88. #30 was a member and never started; it moves to batch 3, because no fingerprint value reads `calculate_distance` and holding the batch for it delays a register that falls from 240 entries to 74. |

## Issue map

Created by `spec-to-issues` on 2026-08-06 against `Crank-Git/ja4plus`.

### Epics

| Epic | Feature file | Epic issue | Sub-issues |
|---|---|---|---|
| Epic 0: Foundation | `features/00-foundation.md` | #11 | #21, #22, #23, #24, #25, #26 |
| Epic 1: Spec conformance | `features/01-spec-conformance.md` | #12 | #27, #28, #29, #30, #31, #78, #80 |
| Epic 2: Correctness audit | `features/02-correctness-audit.md` | #13 | #32, #33, #34, #35, #36, #37 |
| Epic 3: Concurrency and resource safety | `features/03-concurrency-safety.md` | #14 | #38, #39, #40, #41, #42, #43 |
| Epic 4: Typed public interface | `features/04-typed-api.md` | #15 | #44, #45, #46, #47, #48 |
| Epic 5: Structured output | `features/05-structured-output.md` | #16 | #49, #50, #51, #52 |
| Epic 6: Live capture | `features/06-live-capture.md` | #17 | #53, #54, #55, #56 |
| Epic 7: Database enrichment | `features/07-db-enrichment.md` | #18 | #57, #58, #59, #60, #61 |
| Epic 8: Documentation | `features/08-documentation.md` | #19 | #62, #63, #64, #65, #66 |
| Epic 9: Release | `features/09-release.md` | #20 | #67, #68, #69, #70 |

### Requirements

| Requirement | Issues |
|---|---|
| `FR-concurrency-safety-1` | #40 |
| `FR-concurrency-safety-2` | #40 |
| `FR-concurrency-safety-3` | #40 |
| `FR-concurrency-safety-4` | #40 |
| `FR-concurrency-safety-5` | #40 |
| `FR-concurrency-safety-6` | #40 |
| `FR-concurrency-safety-7` | #38, #39 |
| `FR-concurrency-safety-8` | #38, #39 |
| `FR-concurrency-safety-9` | #38 |
| `FR-concurrency-safety-10` | #38 |
| `FR-concurrency-safety-11` | #41 |
| `FR-concurrency-safety-12` | #41 |
| `FR-concurrency-safety-13` | #42 |
| `FR-concurrency-safety-14` | #42 |
| `FR-concurrency-safety-15` | #43 |
| `FR-correctness-audit-1` | #32 |
| `FR-correctness-audit-2` | #33 |
| `FR-correctness-audit-3` | #32 |
| `FR-correctness-audit-4` | #34 |
| `FR-correctness-audit-5` | #34 |
| `FR-correctness-audit-6` | #35 |
| `FR-correctness-audit-7` | #35 |
| `FR-correctness-audit-8` | #37 |
| `FR-correctness-audit-9` | #37 |
| `FR-correctness-audit-10` | #37 |
| `FR-correctness-audit-11` | #34 |
| `FR-correctness-audit-12` | #36 |
| `FR-correctness-audit-13` | #37 |
| `FR-db-enrichment-1` | #57 |
| `FR-db-enrichment-2` | #57 |
| `FR-db-enrichment-3` | #58 |
| `FR-db-enrichment-4` | #58 |
| `FR-db-enrichment-5` | #58 |
| `FR-db-enrichment-6` | #58 |
| `FR-db-enrichment-7` | #59 |
| `FR-db-enrichment-8` | #59 |
| `FR-db-enrichment-9` | #60 |
| `FR-db-enrichment-10` | #60 |
| `FR-db-enrichment-11` | #61 |
| `FR-db-enrichment-12` | #61 |
| `FR-db-enrichment-13` | #61 |
| `FR-db-enrichment-14` | #57 |
| `FR-db-enrichment-15` | #57 |
| `FR-documentation-1` | #62 |
| `FR-documentation-2` | #62 |
| `FR-documentation-3` | #62 |
| `FR-documentation-4` | #63 |
| `FR-documentation-5` | #63 |
| `FR-documentation-6` | #63 |
| `FR-documentation-7` | #64 |
| `FR-documentation-8` | #66 |
| `FR-documentation-9` | #64 |
| `FR-documentation-10` | #65 |
| `FR-documentation-11` | #65 |
| `FR-documentation-12` | #65 |
| `FR-documentation-13` | #66 |
| `FR-documentation-14` | #62 |
| `FR-documentation-15` | #64 |
| `FR-foundation-1` | #22 |
| `FR-foundation-2` | #22 |
| `FR-foundation-3` | #22 |
| `FR-foundation-3a` | #22 |
| `FR-foundation-4` | #23 |
| `FR-foundation-5` | #23 |
| `FR-foundation-6` | #23 |
| `FR-foundation-7` | #24 |
| `FR-foundation-8` | #24 |
| `FR-foundation-8a` | #21 |
| `FR-foundation-9` | #24 |
| `FR-foundation-10` | #24 |
| `FR-foundation-11` | #24 |
| `FR-foundation-12` | #24 |
| `FR-foundation-13` | #24 |
| `FR-foundation-14` | #25 |
| `FR-foundation-15` | #26 |
| `FR-foundation-15a` | #26 |
| `FR-foundation-15b` | #26 |
| `FR-foundation-16` | #26 |
| `FR-foundation-17` | #26 |
| `FR-live-capture-1` | #53 |
| `FR-live-capture-2` | #53 |
| `FR-live-capture-3` | #53 |
| `FR-live-capture-4` | #53 |
| `FR-live-capture-5` | #54 |
| `FR-live-capture-6` | #54 |
| `FR-live-capture-7` | #54 |
| `FR-live-capture-8` | #55 |
| `FR-live-capture-9` | #55 |
| `FR-live-capture-10` | #55 |
| `FR-live-capture-11` | #56 |
| `FR-live-capture-12` | #56 |
| `FR-live-capture-13` | #56 |
| `FR-live-capture-14` | #53 |
| `FR-release-1` | #67 |
| `FR-release-2` | #67 |
| `FR-release-3` | #67 |
| `FR-release-4` | #68 |
| `FR-release-5` | #68 |
| `FR-release-6` | #68 |
| `FR-release-7` | #68 |
| `FR-release-8` | #68 |
| `FR-release-9` | #68 |
| `FR-release-10` | #69 |
| `FR-release-11` | #69 |
| `FR-release-12` | #69 |
| `FR-release-13` | #70 |
| `FR-release-14` | #70 |
| `FR-spec-conformance-1` | #27 |
| `FR-spec-conformance-2` | #27 |
| `FR-spec-conformance-3` | #27 |
| `FR-spec-conformance-4` | #28 |
| `FR-spec-conformance-5` | #28 |
| `FR-spec-conformance-6` | #28 |
| `FR-spec-conformance-7` | #29 |
| `FR-spec-conformance-8` | #29 |
| `FR-spec-conformance-9` | #30 |
| `FR-spec-conformance-10` | #30 |
| `FR-spec-conformance-11` | #31 |
| `FR-spec-conformance-12` | #31 |
| `FR-structured-output-1` | #49 |
| `FR-structured-output-2` | #49 |
| `FR-structured-output-3` | #50 |
| `FR-structured-output-4` | #49 |
| `FR-structured-output-5` | #49 |
| `FR-structured-output-6` | #52 |
| `FR-structured-output-7` | #50 |
| `FR-structured-output-8` | #50 |
| `FR-structured-output-9` | #52 |
| `FR-structured-output-10` | #52 |
| `FR-structured-output-11` | #51 |
| `FR-structured-output-12` | #51 |
| `FR-structured-output-13` | #50 |
| `FR-typed-api-1` | #44 |
| `FR-typed-api-2` | #44 |
| `FR-typed-api-3` | #45 |
| `FR-typed-api-4` | #45 |
| `FR-typed-api-5` | #44 |
| `FR-typed-api-6` | #44 |
| `FR-typed-api-7` | #46 |
| `FR-typed-api-8` | #46 |
| `FR-typed-api-9` | #47 |
| `FR-typed-api-10` | #47 |
| `FR-typed-api-11` | #48 |
| `FR-typed-api-12` | #47 |
| `FR-typed-api-13` | #47 |
