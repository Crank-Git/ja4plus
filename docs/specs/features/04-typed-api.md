---
id: typed-api
feature: Typed public interface
epic: "Epic 4: Typed public interface"
status: issued
issues: [15, 44, 45, 46, 47, 48]
mockups: []
---

## Purpose

Version 1.0.0 promises that the interface does not change again before version
2.0.0. That promise is only worth making once the interface is written down in a
form a type checker can read.

Today `Processor.process_packet` returns a list of untyped dictionaries. The port
returns a slice of `FingerprintResult`. This feature set closes that gap, adds the
`py.typed` marker, and removes the deprecated module that has outlived its stated
removal version by two minor releases.

## User stories

- As a library integrator, I want my editor to complete the fields of a result, so
  that I do not read the source to learn them.
- As a library integrator, I want the same field names as the Go port, so that I
  can port code between them.
- As a library integrator, I want to see the errors a packet caused, so that I can
  tell an unfingerprinted packet from a failed parse.

## Functional requirements

FR-typed-api-1 — The package exports a frozen dataclass named `FingerprintResult`.

FR-typed-api-2 — `FingerprintResult` carries the fields the spec's data model
lists.

FR-typed-api-3 — `Processor.process_packet` returns a list of `FingerprintResult`.

FR-typed-api-4 — `Processor.process_packet` exposes the parse failures it collected.

FR-typed-api-5 — A `FingerprintResult` supports item access by field name, so that
code written against the dictionary keeps working for one major version.

FR-typed-api-6 — Item access on a `FingerprintResult` emits a `DeprecationWarning`.

FR-typed-api-7 — Every public function and method in `ja4plus/` carries type
annotations.

FR-typed-api-8 — `mypy --strict ja4plus/` reports no error.

FR-typed-api-9 — The package ships a `py.typed` marker file.

FR-typed-api-10 — The wheel contains the `py.typed` marker.

FR-typed-api-11 — The project removes `ja4plus/collector.py`.

FR-typed-api-12 — `ja4plus/__init__.py` lists every public name in `__all__`.

FR-typed-api-13 — A name absent from `__all__` is not part of the interface the
project promises.

## User flows

**An integrator reads a fingerprint.**

1. The integrator builds a `Processor`.
2. The integrator calls `process_packet` with a packet.
3. The call returns a list of `FingerprintResult`.
4. The integrator reads `result.fingerprint` and `result.type`.
5. The editor completes both field names.

**An integrator upgrades from version 0.6.0.**

1. The integrator's code reads `result["fingerprint"]`.
2. The code keeps working.
3. Python emits a `DeprecationWarning` that names the replacement.
4. The integrator changes the code to `result.fingerprint`.

## Screens & states

This feature set has no screen.

## Behaviour rules

- `FingerprintResult` is frozen. A result describes something that already
  happened, and nothing should change it.
- The field that names the method is `type`, not `method`. The port calls it
  `Type`, and the current dictionary key is `"type"`. Parity rule 2 decides this.
- `timestamp` is `None` when the packet carries no timestamp.
- The deprecated item access covers reading only. A result does not support item
  assignment.
- `process_packet` returns results in the fixed method order the processor already
  uses. The order is part of the interface.
- Removing `ja4plus/collector.py` is a breaking change. The module has warned since
  version 0.3.0 and stated removal at version 0.4.0.
- `mypy --strict` applies to `ja4plus/` only. The test suite is not type checked.

## Data touched

- New file `ja4plus/types.py`, holding `FingerprintResult` and `ProcessorStats`.
- New file `ja4plus/py.typed`.
- Removed file `ja4plus/collector.py`.
- Changed files: `ja4plus/processor.py`, `ja4plus/__init__.py`,
  `ja4plus/cli.py`, every file under `ja4plus/fingerprinters/`, every file under
  `ja4plus/utils/`.
- Changed file `pyproject.toml`, to ship the marker as package data.

## Interfaces

```python
@dataclass(frozen=True)
class FingerprintResult:
    type: str
    fingerprint: str
    raw: str | None = None
    raw_original_order: str | None = None
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    timestamp: datetime | None = None

class Processor:
    def process_packet(self, packet: Packet) -> list[FingerprintResult]: ...
    def process_packet_with_errors(
        self, packet: Packet
    ) -> tuple[list[FingerprintResult], list[Exception]]: ...
```

The field names are the snake-case form of the port's `FingerprintResult` struct.

Verified against:
https://github.com/Crank-Git/ja4plus-go/blob/master/types.go (retrieved
2026-08-06).

The port's `ProcessPacket` returns results and errors together. Python has no
multiple-return form that reads well as a default, so this project keeps
`process_packet` returning results and adds `process_packet_with_errors` for a
caller who needs both.

The `py.typed` marker follows PEP 561.

Verified against: https://peps.python.org/pep-0561/ (retrieved 2026-08-06).

## Edge cases & failures

| Case | What happens |
|---|---|
| A caller reads `result["fingerprint"]`. | The value is returned and a `DeprecationWarning` is emitted. |
| A caller reads `result["method"]`. | `KeyError` is raised. The field is `type`. |
| A caller assigns `result.fingerprint = "x"`. | `FrozenInstanceError` is raised. |
| A caller imports `ja4plus.collector`. | `ModuleNotFoundError` is raised. The changelog names the replacement. |
| A packet produces no fingerprint but raises inside one fingerprinter. | `process_packet` returns an empty list. `process_packet_with_errors` returns the exception. |
| A packet carries no address layer. | `src_ip` and `dst_ip` are the empty string, and the ports are zero. |
| A caller runs `mypy --strict` against their own code that uses `ja4plus`. | The annotations resolve, because the wheel ships `py.typed`. |

## Acceptance criteria

- [ ] `mypy --strict ja4plus/` reports no error.
- [ ] `Processor().process_packet(pkt)` returns a list whose elements are
      `FingerprintResult`.
- [ ] `result.type` and `result["type"]` return the same value.
- [ ] `result["type"]` emits a `DeprecationWarning`.
- [ ] `result.fingerprint = "x"` raises.
- [ ] `python -c "import ja4plus.collector"` fails.
- [ ] `unzip -l dist/*.whl` lists `ja4plus/py.typed`.
- [ ] Every name in `ja4plus.__all__` is importable from `ja4plus`.
- [ ] A test asserts that `FingerprintResult` field names match the list in
      `docs/specs/spec.md`.
- [ ] `process_packet_with_errors` returns the exception raised by a fingerprinter
      given a packet crafted to raise.

## Out of scope

- An asynchronous interface.
- A protocol or abstract base class for third-party fingerprinters.
- Type checking the test suite.
- Renaming any method.

## Open questions

None.
