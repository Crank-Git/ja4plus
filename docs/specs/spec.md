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
| zero sentinel | noun | The literal value `000000000000` that a hash field carries when its list holds no value. | zero marker, zero hash, twelve zeros |
| result | noun | One typed object that carries a fingerprint and its connection. | record, row, output |
| emit | verb | To return a fingerprint from a fingerprinter. | output, produce, yield |
| evict | verb | To remove one entry from a state table. | clean up, expire, purge |
| conform | verb | To produce the same output as the FoxIO reference. | comply, match spec |
| port | noun | The Go implementation at `Crank-Git/ja4plus-go`. | Go version, sibling, twin |
| parity | noun | The state where this project and the port expose the same interface and emit the same fingerprint. | alignment, sync, consistency |
| hop count | noun | The count of routers a packet crossed, read as the initial TTL minus the observed TTL. | hop distance, TTL delta |
| propagation factor | noun | The JA4L divisor that the FoxIO hop-count table gives for one hop count. | propagation delay, terrain factor |
| measurement point | noun | One packet timestamp that a JA4L value measures from or to. | anchor, marker, reference point |
| Initial packet | noun | One QUIC packet whose long-header type is Initial. RFC 9000 Section 17.2 gives the layout. | first packet, opening packet |
| connection ID | noun | The QUIC identifier that names one endpoint of a connection. The Initial keys derive from the one the client chooses. | CID, connection identifier, DCID |
| Retry packet | noun | One QUIC packet that asks the client to send its Initial packet again with another connection ID. RFC 9000 Section 17.2.5 gives the layout. | retry, redirect |
| Handshake packet | noun | One QUIC packet whose long-header type is Handshake. RFC 9000 Section 17.2.4 gives the layout. | handshake, HS packet |
| key material | noun | One secret that decrypts recorded traffic, such as a TLS session key. | secret, key log, session keys |
| Decryption Secrets Block | noun | The pcapng block that carries key material inside a capture file. | DSB, secrets block, key log block |

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
- Decryption is out of scope. `ja4plus` reads no key material and reads no Decryption
  Secrets Block. It decrypts no TLS record and no QUIC 1-RTT packet. Traffic that a
  capture carries only in encrypted form therefore produces no fingerprint, even when
  the same capture file carries the key material that decrypts it. #129 holds the
  decision, and the decision is reversible.

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
| JA4 ALPN value for a byte that is not alphanumeric | Writes `99`. | Not measured. | 1 | The FoxIO prose and the FoxIO implementations disagree, so rule 1 settles the value on the vector. #127 holds the decision and the measurement. The port must adopt `99`, or the two implementations disagree on JA4 and on JA4S. #141 owns the condition that triggers the value, which no vector separates. |
| JA4 ALPN value for a byte outside `0x20-0x7E` in a position other than the first | Writes `99`. | Not measured. | 1 | The two FoxIO implementations disagree with each other, so this is a reference split and rule 1 does not settle it. The user decided on 2026-08-07 that `99` stays. Two reasons support the reading. The FoxIO Rust result is an artifact. `rust/ja4/src/tls.rs` reads the tshark escape text, so it reads `h\x1f` as the five characters `h`, `\`, `x`, `1` and `f`. The FoxIO Python result puts `U+FFFD` into a fingerprint, which is a character no byte of the packet holds. #141 holds the measurement, #162 holds the decision, and the decision is reversible. `tests/foxio_vectors/alpn-condition.pcap` streams 2, 4 and 5 carry `h\xab`, `h\x1f` and `h\x0a`, and the register holds twelve entries that state the measured value of both implementations. The port must write `99`, or the two implementations disagree on JA4 and on JA4S. |
| JA4 ALPN value for a first ALPN value of one byte | Repeats the byte and writes `hh`. | Not measured. | 1 | All three sources differ on the input `h`: FoxIO Python writes `h`, FoxIO Rust writes `h0`, and no vector separates them. The FoxIO Python value holds one character, which cannot fill a two-character field. `ja4plus` writes a value that is well formed and stable, and the user decided on 2026-08-07 that it stays. #141 holds the measurement, #162 holds the decision, and the decision is reversible. `tests/foxio_vectors/alpn-condition.pcap` stream 6 carries the input, and the register holds four entries that state the measured value of both implementations. The port must repeat the byte, or the two implementations disagree on JA4 and on JA4S. |
| JA4L client value on the return path of `process_packet` | Returns a client value for every packet that moves the client measurement point. Across the committed vectors the return path reports 105 client values, and the stored list holds 60. | Not measured. | 1 | The reference reports one client value for one connection, and the stored list of `ja4plus` holds one. `tests/conformance_index.py` reads the stored list, so every conformance case measures the correct value and no fingerprint moves. The return path repeats the value, because the reference measures to the last packet that carries both relative numbers. A reader knows which packet is last only when the connection ends. #156 measured three candidate end-of-connection points against the 60 client values. A FIN or a RST reports 26 and loses 34, because 34 connections never close inside their capture. `macos_tcp_flags.pcap` holds no FIN packet and no RST packet at all. Every measurement point read reports 105, which is the behaviour today. A read of the stored list at the end of a capture reports all 60, and that is not a `process_packet` return. That candidate needs a new flush call, and a live capture never ends, so `ja4plus --live` would then report no client value. The user decided on 2026-08-07 to record the divergence and to leave the return path as it is. #156 holds the decision and the measurement, and the decision is reversible. The register holds no entry for this divergence, because the conformance harness reads the stored list and a strict entry would report `XPASS`. `tests/test_ja4l_return_path.py` holds both counts instead, so the divergence is a comparison that runs. The port must report one client value for one connection, or the two implementations disagree on JA4L. |
| JA4X on a stream that a proxy tunnel carries | Reads the record layer without regard to the tunnel protocol that carries it. Produces three JA4X values on the SOCKS4 tunnel of `socks4-https.pcap` on port 9901, and no FoxIO implementation holds one. | Not measured. | 1 | No FoxIO implementation holds a value, so this is unanimity and not a reference split, and rule 1 does not settle it. The user decided on 2026-08-07 that the three values stay. The same behaviour produces the `https-connect.pcap` values that the FoxIO Rust snapshot and the Wireshark dissector both hold. A gate on the record-layer scan would risk that case. #138 holds the decision and the measurement, the register records the divergence, and the decision is reversible. The port must read the record layer the same way, or the two implementations disagree on JA4X. |

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
fingerprint sent to a third party discloses traffic the operator observed. The library
also reads no key material, because a program that reads a key log file reads the plain
text of the traffic the operator captured. That capability is larger than fingerprint
production, and this project does not take it. The `Non-goals` section states what the
limitation removes.

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
| 18 | 2026-08-07 | #98 landed and JA4SSH counts an SSH message, not a TCP segment. `tshark` proved the boundary: `frame.protocols` of `ssh-r.pcap` frame 399 is `eth:ethertype:ip:tcp`, and frame 400 carries `eth:ethertype:ip:tcp:ssh` with `tcp.segment` `399,400`. `ja4plus/utils/ssh_utils.py` gains `SSHMessageTracker`, which follows the four-byte length field of each plaintext message and turns opaque after `SSH_MSG_NEWKEYS`. Two vectors hold such a message: `ssh-r.pcap` stream 1 holds one, and `ssh-r.pcap` stream 2 holds one. All five windows of stream 2 now hold the reference packet counts, and the register falls from 74 entries to 73. The remaining JA4SSH entries are #96 with 4, #97 with 3 and #105 with 3. No vector that conformed before changed: `ssh.pcapng`, `ssh-scp-1050.pcap`, `ssh2.pcapng` and `ssh-r.pcap` stream 0 hold their values. |
| 19 | 2026-08-07 | #89 landed and the JA4L measurement points move to `features/01-spec-conformance.md`. `FR-correctness-audit-5` claimed that JA4L emits the client fingerprint from the ACK that completes the handshake. Stream 0 of `browsers-x509.pcapng` contradicts it. The SYN-ACK is at `+0.003815s`, the bare ACK at `+0.003927s`, and the Client Hello at `+0.004371s`. The reference `JA4L-C` is `278_128`, and `(4371 - 3815) / 2 = 278`. The project withdraws `FR-correctness-audit-5` and keeps its number, because #34, #35, #36 and #37 quote the numbers below it. `FR-spec-conformance-17` to `FR-spec-conformance-21` replace it, and #88 built them. `FR-spec-conformance-18` to `FR-spec-conformance-21` describe the TCP form of JA4L, because the QUIC form reads no SYN and no relative sequence number. Row 5 of the audit register drops the measurement point and keeps the multiplicity defect. #34 now owns multiplicity alone, and its acceptance criterion that quoted the old requirement is withdrawn. #34 also shrank from 37 register entries to 6 after #88. |

| 20 | 2026-08-07 | Epic 1 batch 3 ships #30, #31, #98 and #89. The register falls from 74 entries to 73. #30 reads the FoxIO hop-count propagation factor and moved no conformance value, which confirms that no fingerprint reads `calculate_distance`. #31 records a reading for every image-published method and replaces the six parity tests that asserted a name exists; each replacement was run against a mutated expected-output file and failed, which proves it compares a value. #98 counts an SSH message rather than a TCP segment, and every vector that conformed before is byte-identical after. Three issues opened from work this batch exposed. #108: the JA4S `raw` value sorts the extensions and the FoxIO `JA4S_r` holds them in wire order; the fingerprint itself conforms. #109: `tests/test_ja4d_foxio.py` and `tests/test_ja4d6_foxio.py` name paths this repository does not hold, so both skip on every run and nothing tests JA4D or JA4D6. #113: `SSHMessageTracker` reads segments in capture order, so a retransmitted segment desyncs the message boundary on live traffic. |

| 21 | 2026-08-07 | #102 landed and the JA4L QUIC server point reads the Initial packet that completes the ServerHello. The cause was one line of `decrypt_initial_payload`. It read the ciphertext to the end of the datagram. The AEAD tag of an Initial packet covers only the bytes the Length field names, so every server Initial packet of the vector set failed the tag. The fingerprinter then fell back to the first one. `_initial_packet_end` now bounds the ciphertext. Both server Initial packets of `chrome-cloudflare-quic-with-secrets.pcapng` stream 50280 decrypt. The packet at `+18569 us` holds an ACK frame, and the packet at `+21981 us` holds the whole 90-byte ServerHello. The register falls from 73 entries to 71. Neither vector splits a ServerHello across two Initial packets. The accumulation across packets therefore rests on RFC 9001 and on synthetic packets, not on a vector. No JA4S value changed, because `ja4s.py` reads a server Initial packet as a client Initial packet. It records the empty connection ID of that packet, and it never reaches the server path. That defect is #118. The self-review found a second one. A CRYPTO frame offset is a 62-bit number, and `reassemble_crypto_fragments` allocates a buffer that reaches the highest offset. `collect_crypto_fragments` now stops every buffer at 16384 bytes, on the JA4L path and on the JA4S path. The JA4 client path holds the same defect and is #122. |

| 22 | 2026-08-07 | Epic 1 batch 4 ships #109, #101, #102 and #108. The register falls from 73 entries to 67, and no entry that remains is an Epic 1 conformance defect: 48 belong to the correctness audit on #13, #35 and #34, 9 state a genuine limitation of a capture on #78, and 10 record a declined FoxIO defect on #96, #97 and #105. #109 found that FoxIO does publish JA4D and JA4D6 reference values, in `wireshark/test/testdata/`, where the Python implementation emits neither method; ten values now run where zero ran, and `.claude/rules/external-apis.md` records the exception to the Wireshark precedence rule plus the fact that nothing corroborates the six JA4D6 values. #101 groups a mirrored capture by its inner connection and reports the outer one. #102 found one line: `decrypt_initial_payload` read the ciphertext to the end of the UDP datagram, and the AEAD tag of a QUIC Initial packet covers only the bytes the Length field names, so every server Initial packet failed the tag. #108 makes the JA4S `raw` key hold the FoxIO wire order, and all 84 `JA4S_r` values now match where 49 did. #121 opened: `tests/conformance_index.py:29` drops every raw key before the comparison, so no raw form of any method has ever been compared against the reference. #115, #118 and #119 opened. |

| 23 | 2026-08-07 | #118 landed and JA4S tells a QUIC server Initial packet from a client one. `_is_quic_client_initial` tested the long-header packet type alone, and a server Initial packet carries the same type. The fingerprinter stored the connection ID of the server packet under the reverse connection key and returned, so it never read the ServerHello. That connection ID was empty, because a server Initial packet names the client with the connection ID the client chose as its source. `ja4s.py` now reads the port that names the server, as `ja4l.py` does, and a server Initial packet replaces no stored value. `chrome-cloudflare-quic-with-secrets.pcapng` stream 50280 produces `q130200_1301_234ea6891581`, which holds the cipher and the extension hash of the `t130200_1301_234ea6891581` value the reference holds for the TCP stream of the same capture. No JA4S value on any other stream changed, and no vector reports a missing occurrence key. The reference reads no QUIC handshake in the committed vectors, so it holds no JA4S value for the nine QUIC streams of `chrome-cloudflare-quic-with-secrets.pcapng`, `ssh2.pcapng` and `tls3.pcapng`. It holds no JA4 value for the same nine streams, and #13 already owned that divergence for JA4. Three register entries record the JA4S form of it, and the register rises from 67 entries to 70. #130 opened: `ja4s.py` reads one server Initial packet at a time, so a ServerHello that spans two Initial packets produces no JA4S value. |
| 24 | 2026-08-07 | #121 landed and the conformance suite compares a raw form for the first time. `tests/conformance_index.py` dropped every key that ends with `_r`, `_ro`, `_o` or `_raw`, so 653 reference values reached no test. The register rises from 67 entries to 220, measured against `epic/12-spec-conformance` at `03c7c02`, and no hashed-form case changed state. `JA4S_r` matches all 84 values, which confirms the #108 measurement. `JA4_r` and `JA4_ro` each match 149 of 160, and every failure sits on a stream whose `JA4` value fails too, so #13 owns all 22. `JA4_o` matches 145 of 160. `JA4H_ro` matches 0 of 89, because `ja4plus` computes no JA4H raw form. Two issues opened. #131 owns the 89 `JA4H_ro` values and the 11 occurrence-key cases with them. #132 owns four `JA4_o` values whose client hello carries SNI as its only extension: the reference gives `000000000000` as the extension hash, and `ja4plus` hashes the original-order extension list, which is the rule that matches the other 156 values. `tests/generate_foxio_baseline.py` now keeps the entry the committed register holds for a key that still fails, because a cause read from a failure message states the symptom and #78, #96, #97 and #105 hold mechanisms a person wrote. |

| 25 | 2026-08-07 | Epic 1 batch 5 ships #119, #118, #115 and #121. **The register rises from 67 entries to 226, and the rise is the point.** 153 entries record a raw form that no test had ever compared, and 3 record the JA4S occurrence keys that #118 exposed. #115 removed the last skip from the unit suite: three tests named a fixture path this repository does not hold, one now compares a committed FoxIO Rust snapshot and passes, and two carry a strict `xfail` naming #127 and #129. #121 found that `tests/generate_foxio_baseline.py` overwrote every cause on each run, so running it would have destroyed 19 hand-written causes, including the ten that record the declined FoxIO defects. Four issues opened from the measurement: #131, `ja4plus` computes no JA4H raw form, so all 89 `JA4H_ro` values fail; #128, 18 register entries state a cause the evidence does not support; #132, four `JA4_o` values whose client hello carries SNI as its only extension; #127, the FoxIO prose and two FoxIO implementations disagree on the JA4 ALPN value for a non-ASCII first byte. #13 grew from 21 entries to 73 and now owns one question: does `ja4plus` emit a fingerprint on a QUIC stream the reference ignores, or does the reference miss it. |

| 26 | 2026-08-07 | #129 settled decryption. `ja4plus` reads no key material, it reads no Decryption Secrets Block, it decrypts no TLS record, and it decrypts no QUIC 1-RTT packet. The reason is a security boundary: a program that reads a key log file reads the plain text of the traffic the operator captured, and that capability is larger than fingerprint production. The decision is reversible. `Non-goals` states the limitation and `Cross-cutting concerns` states the reason. 17 JA4H register entries move from #35 to #129, and they hold the cause the JA4X entries of the same two captures already state. The 17 are `http2-with-cookies.pcapng/JA4H`, the 15 value cases of `http2-with-cookies.pcapng` stream 58847, and `chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4H.1`. `http1-with-cookies.pcapng` carries no secrets block and holds two cleartext HTTP messages, so #35 keeps it. No fingerprinter changed and no vector changed state. |
| 27 | 2026-08-07 | #127 landed and the JA4 ALPN value follows the FoxIO implementations, not the FoxIO prose. The prose of `technical_details/JA4.md` states that a first ALPN value whose first byte or last byte is not an ASCII alphanumeric prints the first and the last character of the hex form. The FoxIO Python implementation writes `99` instead, and the FoxIO Rust snapshot holds the same `99`. `tests/foxio_vectors/tls-non-ascii-alpn.pcapng` measures the difference: its first ALPN value is the two bytes `0xba 0xad`, the prose gives `t13d1516bd_8daaf6152771_e5627efa2ab1`, and both FoxIO implementations give `t13d151699_8daaf6152771_e5627efa2ab1`. Only the two ALPN characters differ. The user decided on 2026-08-07 that this project follows the vector, because `CLAUDE.md` rule 1 states that a fingerprint changes only when a FoxIO vector requires it, and because a fingerprint exists so that one tool output can be compared against another tool output. `compute_alpn_value` now returns `99` whenever the first byte or the last byte of the first ALPN value falls outside `0x30-0x39`, `0x41-0x5A` and `0x61-0x7A`. `ja4s.py` reads the same function, so JA4 and JA4S carry one rule. #127 settled the value alone, and #141 owns the condition, because `python/ja4.py`, `rust/ja4/src/tls.rs`, the FoxIO prose and this project apply four different conditions that every vector fires. Four register entries go away, `JA4.1`, `JA4_o.1`, `JA4_r.1` and `JA4_ro.1` on `tls-non-ascii-alpn.pcapng/0:50112`. Measured alone the register falls from 226 entries to 222. Measured on the integration branch, after #129 and #131 landed, it falls from 147 entries to 143. No vector that passed before fails now: the conformance suite reports 1205 passed where it reported 1201. The Go port at `Crank-Git/ja4plus-go` reads the same specification and must adopt `99`. |
| 28 | 2026-08-07 | #113 landed and JA4SSH reads the payload of an SSH direction in sequence order. `SSHMessageTracker` read the segments in capture order and held no sequence number, so a retransmitted segment reached it twice and an out-of-order segment reached it early. Either one moved the tracker off the message boundary for the rest of the direction. The measurement on a synthetic connection: a clean direction gives the packet lengths `[21, 48, 36, 36, 36]`, one retransmission gives `[21, 1448, 48, 36, 36, 36]`, and one reorder gives `[21, 48, 1448, 36, 36, 36]`. `SSHMessageTracker.add_segment` now takes the TCP sequence number, drops a segment the direction already sent, trims a segment that repeats part of the stream, and holds a segment that arrives before its predecessor. The held segments stop at 32 segments or 65536 bytes, and a gap that never fills turns the tracker opaque. The self-review found a second defect in the same code. A sequence number wraps at 2**32, and a plain comparison reads a wrapped number as a number far behind the base. A retransmission that precedes the wrap point would then be held until the buffer reached its bound, and an out-of-order segment that follows the wrap point would be dropped. `_offset` now measures the distance in the shorter direction around the sequence space. Both cases are measured against the plain comparison and both fail it. `ja4plus/utils/tcp_stream.py` compares raw sequence numbers and holds the same defect; JA4H and JA4X read it. `ja4ssh.py` calls `add_segment` and extends the window with the lengths it returns, because the counted segment is the one that completes the message in sequence order, not the one that arrives last. `tests/build_ssh_retransmission.py` builds a capture that holds one retransmitted SSH segment; `tshark -Y "ssh"` labels five client frames and four server frames, and it labels the retransmitted frame 7 `tcp`. The capture produces `c36s36_c5s4_c1s0`. This is a resource bound and not a conformance defect: no FoxIO vector holds a retransmitted or out-of-order SSH segment. The register holds 143 entries before and after, and the conformance suite reports 1284 passed, 141 skipped and 143 xfailed on both. `tests/test_ja4ssh.py` and `tests/test_ja4ssh_message_count.py` gain sequence numbers, because a synthetic segment that repeats sequence number 0 models traffic no direction sends. |
| 29 | 2026-08-07 | #130 landed and JA4S reads a ServerHello that two QUIC Initial packets split. `ja4s.py` read one Initial packet at a time, so neither packet held the whole message, and the connection carried no JA4S value. The fingerprinter now collects the CRYPTO fragments of the server Initial packets of one connection, and it reads the message when `server_hello_is_complete` reports a whole one. The fragment table holds `MAX_QUIC_FRAGMENT_CONNECTIONS` connections for `MAX_QUIC_FRAGMENT_AGE_SECONDS`, which are the two limits `ja4.py` already names, and `cleanup_connection` drops the entry of the connection it names. No vector splits a ServerHello across two Initial packets, so `tests/test_ja4s_quic_split_server_hello.py` carries its own capture. The conformance suite still reports 103 xfailed, and no fingerprint value moved. |
| 30 | 2026-08-07 | #138 landed and the FoxIO Rust snapshot settles the streams the FoxIO Python file omits. The FoxIO Python implementation reads no QUIC handshake, and it reads no TLS on a port it does not know. The FoxIO Rust implementation reads both. Where the two disagree on whether a stream carries a value, the Rust snapshot decides. A value that one implementation holds and another omits is a gap in the implementation that omits it. No fingerprinter changed. `CLAUDE.md` rule 1 holds, because `ja4plus` is right on every stream #138 names. The FoxIO Python file omits 85 streams that the Rust snapshot holds. `ja4plus` produces the exact Rust value on 82 of the 85. It contradicts the Rust snapshot on 0. The user decided the `socks4-https.pcap/JA4X` case on 2026-08-07, and the three values stay. `ja4plus` produces three JA4X values on the SOCKS4 tunnel on port 9901, and no FoxIO implementation holds one. That is unanimity, not a reference split, so the rule above does not reach it. `ja4plus` reads the record layer without regard to the tunnel protocol that carries it. The same behaviour produces the `https-connect.pcap` values that the FoxIO Rust snapshot and the Wireshark dissector both hold. A gate on the record-layer scan would risk the case `ja4plus` provably wins. The decision is reversible, and the `Divergence register` states it. The register ownership figures were stale in two places. The #138 body said 21 entries and the session-4 status digest said 34. The measured count of entries that name the epic #13 is 0. Commit `31b8539` from #128 had already repointed them. 34 entries name #138, and all 34 are now `decided`. The register holds 103 keys before and after, and the key set is unchanged. #138 also found the Rust snapshot rule under-scoped, and it corrects `.claude/rules/external-apis.md`. The rule read at file granularity, so the snapshot decided only where the FoxIO Python file holds an empty array. The unit is the stream. `python/test/testdata/tls3.pcapng.json` is not empty, yet it omits 6 of its 13 streams, and the Rust snapshot holds all 13. The old form covered one capture of the eight. #151 opened from the measurement, and it names three streams where `ja4plus` produces nothing and the FoxIO Rust implementation holds a JA4S value. That is the opposite reading from #138. |
| 31 | 2026-08-07 | #132 landed and the `JA4_o` extension hash reads the sorted extension list for the zero sentinel. FoxIO tests one string, and it sets both extension hashes from that one test. A client hello whose only extensions are SNI and ALPN therefore gives `JA4_o` the zero sentinel. `JA4_ro` still shows the extension in wire order. `technical_details/JA4.md` states the rule and names one field, `JA4_c`, and it describes `JA4_o` by example alone. A probe on `python/ja4.py` at the pinned commit reads `sorted_extensions=''`, `original_extensions='0000'` and `sha_encode(original_extensions)=9af15b336e6a`, which is the value `ja4plus` emitted before this change. The reading is a published rule, not a defect, so `.claude/rules/conformance.md` does not apply and no entry joins the declined set. `JA4_o` now matches all 160 reference values, and the count was 156. The four register entries disappear, so the register falls from 103 keys to 99 and the conformance suite reports 99 xfailed. `docs/implementation_notes.md` holds the reading. |
| 32 | 2026-08-07 | #151 landed and a hello is bounded on its own length field, not on the length of the record that carries it. A TLS handshake record carries one or more handshake messages, so `record_length` bounds the group and not the hello. `parse_tls_handshake` rejected every hello whose enclosing record spans several TCP segments, and a TLS 1.2 server that coalesces the ServerHello, the Certificate and the ServerHelloDone into one record produces exactly that shape. The reader now takes the three-byte handshake length at `offset + 6`, and it stops the slice at the end of the hello. The old form passed `raw_data[offset:]`, so a reader could walk into the Certificate message that follows and report an extension the peer never sent. The three streams #151 names now produce the FoxIO Rust value: `ssh2.pcapng` ports 57374 and 57375, and `tls-handshake.pcapng` port 50167. One bound explains all three, so the fix settles every coalesced-record stream, and four more became readable. The FoxIO Rust snapshots for `browsers-x509.pcapng` and `latest.pcapng` were fetched at the pinned commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`, `ja4plus` reproduces each value exactly, and both snapshots join `tests/foxio_vectors/rust_expected/`. The register rises from 99 keys to 104, and the conformance suite reports 104 xfailed. Four of the five new entries are corroborated by the Rust snapshot. The fifth is `socks4-https.pcap/JA4S`, which no FoxIO implementation holds, and it follows the `socks4-https.pcap/JA4X` decision the user made on 2026-08-07: `ja4plus` reads the record layer without regard to the tunnel protocol that carries it. #151 also found a **third** gap in the FoxIO Python implementation, so `.claude/rules/external-apis.md` is corrected. The rule stated that two gaps produce every case. The implementation also reads no ServerHello whose handshake record spans several TCP segments. `tls-handshake.pcapng` stream 50167 is the proof: the port is 443, so neither known gap explains the omission, and the Rust snapshot holds a value. |
| 33 | 2026-08-07 | #141 landed and the JA4 ALPN condition passes a printable ASCII byte through. The FoxIO prose tests for an alphanumeric byte, and the measurement contradicts it. Both FoxIO implementations read a first ALPN value of `h` and a space as `h `, and not as `99`. The range stops at `0x7E`, because the two implementations agree only inside it. `tests/foxio_vectors/alpn-condition.pcap` holds the separating case, and it is the first capture in the set that reaches the branch with a value the three rules do not agree on. Before it, `tls-non-ascii-alpn.pcapng` held `0xba 0xad`, and all three rules fire on it, so the comparison was never made. The user settled the disputed region on 2026-08-07, and both readings hold the value `ja4plus` wrote before. A byte outside `0x20-0x7E` in a position other than the first keeps `99`, because the two implementations disagree with each other and `CLAUDE.md` rule 1 forbids a move that no vector requires. The FoxIO Rust results on a control byte are an artifact, because `rust/ja4/src/tls.rs` reads the tshark escape text and reads `h\x1f` as five characters. The FoxIO Python result puts `U+FFFD` into a fingerprint, which is a character no byte of the packet holds. A one-byte first ALPN value keeps `hh`. All three sources differ, and the FoxIO Python value holds one character, which cannot fill a two-character field. Both readings are reversible, and #162 records them in the `Divergence register` and adds the disputed inputs to the vector set. The register holds 104 keys before and after, and #141 added none. |
| 34 | 2026-08-07 | #161 landed and the baseline generator keeps the register it rewrites. `tests/generate_foxio_baseline.py` rebuilt every entry from `issue` and `cause`, so a run deleted the `decided` field of 49 entries and reordered the fields of every entry. `decided` records that a person settled a deviation, and the generator measures no such field. `tests/foxio_manifest.py` documents the generator as the way to add a vector, so the next person to add a vector deleted 49 decisions and saw no count change. The entry count held at 104 either way, so the invariant this project checks first did not reach the loss. #141 met the defect, noticed it, and restored the file with `git checkout`. The register run now merges. A key the register already holds keeps its stored entry, byte for byte. The generator writes a new entry only for a deviation the register does not hold, and a key that stops failing still leaves. A run that measures the deviations the register already holds now changes no byte of `tests/foxio_deviations.json`, and the project manager measured that: the file holds md5 `93c8cd5d6800c994c2b5421ac5aa2a91` before the run and after it. The tests fail against the generator as it stood, 6 of 22, so the comparison runs. No fingerprinter changed, and the register holds 104 keys before and after. |
| 35 | 2026-08-07 | #162 landed and the settled JA4 ALPN readings are a comparison the suite runs. #141 measured the disputed region and the user settled it on 2026-08-07, but the readings sat in two issue comments and in `docs/implementation_notes.md`. No capture held a disputed input, so the suite was green because the comparison was never made. This is the seventh instance of that shape in this project. `tests/build_alpn_condition_capture.py` now writes seven streams instead of two. Streams 2, 4, 5 and 6 carry `h\xab`, `h\x1f`, `h\x0a` and `h`, where `ja4plus` matches neither FoxIO implementation. Stream 3 carries `\xabh`, where FoxIO Python writes `99` and `ja4plus` writes `99`, so it conforms and it holds no register entry. The expected-output file holds the FoxIO Python characters #141 measured. The hash halves are invariant across the streams, because the seven client hellos carry the same ciphers and the same extensions. `test_every_stream_differs_from_the_others_in_the_alpn_characters_alone` proves that invariance. The register rises from 104 keys to 120, and the conformance suite reports 120 xfailed. The sixteen new entries are four methods on each of four streams. They all name #162 and they are all `decided`. Each cause states the measured output of both FoxIO implementations. The decided count rises from 49 to 65. A mutation proves the entries bite. Move the stream 6 expected value to `hh`, and four cases report `XPASS(strict)` and the suite fails. `Divergence register` gains two rows, one for the disputed-byte reading and one for the one-byte reading, and both state that the decision is reversible. `compute_alpn_value` is unchanged, and no fingerprint value moved. |
| 36 | 2026-08-07 | #32 landed and the TCP reassembler orders segments across the 32-bit sequence wrap. `get_stream` sorted raw sequence numbers, so a connection that crossed the boundary reassembled in the wrong order. The order now reads from the widest sequence step, which depends only on the sequence numbers. A first implementation compared each segment against a running earliest value, and that comparison is not transitive once segments span more than half the sequence space: three segments at `0x00000000`, `0x60000000` and `0xC0000000` gave three results across the six arrival orders, so a fingerprint would have depended on capture read order. `.claude/rules/conformance.md` forbids that, and the self-review of the issue caught it before the gate. `add_segment` detects a duplicate through a set of `(seq, length)` pairs instead of a scan, so the cost of one segment no longer grows with the segment count, and 10000 segments fell from 0.4511 s to 0.0018 s. The dead `base_seq` dictionary value is removed, and the `base_seq` method stays because `ja4plus/fingerprinters/ja4x.py:166` reads it. **The second acceptance criterion of the issue was itself a comparison that is never made.** "Adding 10000 segments completes in under one second" already passed against the unfixed code at 0.4511 s, so the gate would have reported it met with no change made. A growth-rate assertion replaces it, and that one fails against the unfixed code. No fingerprint moved, and the register holds 120 keys before and after. |
| 37 | 2026-08-07 | #33 landed and one TCP stream is bounded in stored bytes and in segments. It closes #103, which named the same defect. `max_stream_bytes` limited the reassembled output and `max_streams` limited the count of streams, so nothing bounded the list of `(seq, data)` tuples one stream holds, and a sender emitting many distinct small segments grew one stream without limit. `trim_stream` also compared raw sequence numbers, so it held the wrap defect #32 removed from `get_stream`, and it is repaired rather than left. The call shape #78 removed is not restored, because that call passed a byte offset where the method expects an absolute sequence number. A buffer that cannot become an HTTP request now leaves the reassembler, and the removal happens on the second packet that leaves the base sequence number unmoved: removing on the first packet drops a segment an out-of-order request needs, measured on a request whose tail arrives at sequence number 126 and whose head arrives at 100. **The byte cap truncates a real vector stream and the vectors say that is safe.** The largest stream in `tests/foxio_vectors/` holds 1853328 bytes and 1336 segments, on `http2-with-cookies.pcapng`, and the 1048576-byte cap cuts it to 1048554. No reference value stopped matching, because JA4H and JA4X read the head of a stream. A later issue that reads further into a stream must re-measure this cap. **Three tests that were already committed and green asserted nothing.** `test_max_stream_size` read `assertLessEqual(len(result), 20)` against a cap of 10, so it passed whatever the reassembler did. #172 opens to sweep the suite for the shape. |
| 38 | 2026-08-07 | #34 landed and it closes on the stored-list reading. The user decided that on 2026-08-07. Two of the three things the issue asked for were already built, and the issue body did not know it: #126 removed `_src_is_client` in `03c7c02`, and #104 already made the stored list hold one `JA4L-C` per connection through the `client_entry` overwrite. **The defect that survives is on the return value of `process_packet`**, which fires once per matching packet and is what `ja4plus/cli.py`, `ja4plus/collector.py` and `ja4plus/processor.py` read. Every rule a streaming return can compute was measured over the 60 connections in `tests/foxio_vectors/` that produce a client value: the first matching packet is wrong on 44 of 60, the first packet carrying a payload is wrong on 1 and drops 13 connections for which the reference holds a value, and only the last matching packet reproduces all 60. The last rule needs an end-of-connection point that `process_packet` does not have, so the return-path work moved to #156. The worker returned `needs-feedback` rather than choose, which `CLAUDE.md` rule 1 requires: every other candidate moves a fingerprint that no vector requires. A regression test landed, and it fails when the `client_entry` overwrite is removed. The second acceptance criterion stays withdrawn by #89. |
| 39 | 2026-08-07 | #156 landed and the JA4L return-path divergence is a comparison that runs. **The rule the issue stated is wrong, and the vectors settled it.** The reference gates `JA4L-S` and `JA4L-C` independently, and not on all four measurement points: implementing the literal rule breaks 80 conformance cases and deletes `ssh2.pcapng` stream 33 at `16192_57` and `tls3.pcapng` stream 25 at `3583_57`, which are reference values that match today and sit on connections with no client value. `docs/implementation_notes.md` states the measured rule and quotes the failure output. **The return path stays as it is, and the user decided that on 2026-08-07.** A flush interface was measured and rejected: against the 60 client values the vectors hold, a FIN or RST end point reports 26 and loses 34, because 34 connections never close inside their capture and `macos_tcp_flags.pcap` holds no FIN and no RST. Only a read at the end of a capture reports all 60, and a live capture never ends, so the watch command would report no client value until a reader flushed. **The divergence was invisible before this issue**, because `tests/conformance_index.py` reads the stored list, the stored list is correct at 60, and nothing measured the return path. `tests/test_ja4l_return_path.py` now measures it, and the `Divergence register` records the reading as reversible. No entry joined `tests/foxio_deviations.json`, and the worker proved that rather than assumed it: a probe entry for `latest.pcapng/JA4L-C` reported `XPASS(strict)` and failed the suite, which is the reasoning #162 used. One measured fix landed: a QUIC client value now requires the server Initial point, so `quic_mirrored.pcap` moves from `JA4L-C=500_64` to no value, which is what the reference reports. The register holds 120 keys before and after. |

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
| `FR-correctness-audit-5` | #89 withdrew it |
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
| `FR-spec-conformance-17` | #88 |
| `FR-spec-conformance-18` | #88 |
| `FR-spec-conformance-19` | #88 |
| `FR-spec-conformance-20` | #88 |
| `FR-spec-conformance-21` | #88 |
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
