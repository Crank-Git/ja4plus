# How to move from version 0.6.0 to version 1.0.0

Where `ja4plus --version` reports 0.6.0, read this page before you install version 1.0.0.
That command names the version of the package your environment holds.

This repository declares version 1.2.1, which is a patch release of version 1.2.0.
**Python 3.9 leaves the supported set at version 1.1.0**, and version 1.0.1 is the release
that still installs on it. Version 1.1.0 moves no other interface and no fingerprint, and
version 1.1.1 repairs one crash of the ServerHello reader and moves neither.

**Version 1.2.0 moves several fingerprint values, and it breaks no row of this page.** The
rows below state what version 1.0.0 changed against version 0.6.0, and version 1.2.0
changes none of them, so every row reads the same here. **Version 1.2.1 moves no
fingerprint value at all**, so it breaks no row either. It repairs the address pair the
command prints for a value that no packet released, and it moves the frame that carries
the QUIC `JA4L-S` value without moving the text of that value. **A reader who moves from version
1.1.1 rather than from version 0.6.0 reads the `## [1.2.0]` section of `CHANGELOG.md`
instead**, which names each value that moves and the issue that carries it. Those values
are JA4X and JA4H on an empty list, JA4TS on a reset of a one-SYN-ACK connection, JA4T on
the header an ICMP error message quotes, and JA4, JA4S, JA4D and JA4D6 on a tunneled
packet.

This page states what a reader must change. It lists each breaking change with the old
form, the new form and the reason. `CHANGELOG.md` and the `## Changelog` table of
`docs/specs/spec.md` hold the whole record, and each row below names the issue that
carries it.

**Warning: a fingerprint of version 0.6.0 and a fingerprint of version 1.0.0 are not
always comparable.** Seven of the changes below move a value that a tool may have stored.
Read [The fingerprints that move](#the-fingerprints-that-move) before you compare two
sets of results.

## The breaking changes

| Change | The version 0.6.0 form | The version 1.0.0 form | Why | Record |
|---|---|---|---|---|
| The result of a fingerprinter | `Processor.process_packet` returns a list of dictionaries. | It returns a list of `FingerprintResult` objects. Item access still works and it raises a `DeprecationWarning`. | A typed result states the field set, and a static checker reads it. | Round 90, #45 |
| The result of a lookup | `JA4DBClient.lookup` returns a dictionary with the keys `application`, `type` and `notes`. | It returns a frozen `LookupResult`, which adds the `source` field. | The typed result matches `lookup.go:23` of the port, under parity rule 2. | Round 122, #59 |
| Item access on a lookup result | `result["application"]` reads a key of the dictionary. | `result.application` reads the field. Item access still works and it raises a `DeprecationWarning`. | Epic 4 gives `FingerprintResult` the same access, and one rule serves both results. | Round 123, #364 |
| The remote lookup | `JA4DBClient()` sends every fingerprint the mapping file misses to `https://ja4db.com`. | `JA4DBClient()` reaches no network. `JA4DBClient(allow_remote=True)` opts in, and the command writes a disclosure notice. | A fingerprint describes traffic the operator observed, and a default that discloses it is a defect. | Round 117, #57 |
| The first argument of the lookup client | `JA4DBClient(100)` sets the cache size. | `allow_remote` is the first argument, so `JA4DBClient(100)` raises a `TypeError`. Pass `JA4DBClient(cache_size=100)`. | The opt-in belongs first, so a caller reads it. | Round 117, #57 |
| The mapping file that `db update` writes | `ja4plus db update` overwrites `ja4plus/data/ja4plus-mapping.csv` inside the installed package. | It writes the cache directory of the platform, and `db info` renames its `Source` line to `Mapping`. | An installed package directory is read-only on many hosts, and a reinstall drops the update. | Round 121, #61 |
| The monitor subcommand | `ja4plus live <interface>` reads an interface. | `ja4plus watch <interface>` reads an interface, and `live` stays as an alias. | The monitor gained a bounded connection table, and the new name states what it does. | Round 101, #53 |
| The `ja4plus.collector` module | `import ja4plus.collector` works, and the module carries a removal notice from version 0.4.0. | The module is gone, and the import raises a `ModuleNotFoundError`. Use `Processor` instead. | The module held module-level state that grew without a bound. | Round 71, #191 |
| The fields of an output line | The `json` format and the `csv` format write one composite `source` field. | They write `src_ip`, `src_port`, `dst_ip` and `dst_port`, plus `schema_version` and `identified_as`. The CSV column order is fixed. | A composite string forced every downstream tool to parse it again. | Round 96, #49 |
| The place a diagnostic goes | The command mixes results and progress messages on standard output. | Results go to standard output, and every diagnostic goes to standard error. `--output FILE` writes the results to a file. | A pipe that reads standard output reads results alone. | Round 95, #52 |
| The privilege check of the monitor | The monitor reads `os.geteuid()`, which raises an `AttributeError` on Windows. | The monitor opens the capture socket and reports the failure it meets, naming `CAP_NET_RAW` or `/dev/bpf*`. | The root check answered the wrong question, and it broke the import on Windows. | Round 104, #56 |
| The certificate readers | `compute_ja4x_from_pem` and `compute_ja4x_from_der` catch `Exception`, so they return `None` for every input they cannot read. | Each one names the errors it expects. An input that returned `None` in version 0.6.0 can now raise. | A bare `Exception` handler hides a defect of the caller, and `CLAUDE.md` binds a reader to the errors it expects. | Round 133, #319 |
| The Python floor | `requires-python` is `>=3.8`. | `requires-python` is `>=3.9`, and continuous integration runs Python 3.9 through Python 3.13. | Python 3.8 reached its end of life in October 2024. | Round 135, #76 |

**The Python floor moved again after version 1.0.0.** `requires-python` reads `>=3.10`,
and continuous integration runs Python 3.10 through Python 3.13. Python 3.9 reached its
end of life in October 2025, and #575 records the ruling. **Version 1.1.0 publishes that
move**, so an environment that runs Python 3.9 installs version 1.0.1 and no later
release.

## The fingerprints that move

Seven changes move a fingerprint value, and the table below holds one row for each. A
stored value of version 0.6.0 therefore does not always match the value that version
1.0.0 produces for the same traffic.

| Method | The version 0.6.0 value | The version 1.0.0 value | Record |
|---|---|---|---|
| JA4SSH | The fingerprinter emits one fingerprint for every 10 SSH packets. | It emits one fingerprint for every 200 SSH packets, which is the FoxIO window. | Round 9, #28 |
| JA4SSH | The fingerprinter counts every TCP segment that carries a payload. | It counts SSH messages, and it tracks the message boundary. | #98 |
| JA4SSH | The bare ACK counts include a SYN-ACK packet, a FIN-ACK packet and an RST-ACK packet. | They count a true bare ACK alone. | #92 |
| JA4L and JA4LS | The value reports a round-trip time, and the client point reads a bare ACK. | The value reports a one-way latency, and the client point reads the packet with `seq=1` and `ack=1`. | #88 |
| JA4L and JA4LS | The QUIC server point reads the first server Initial packet. | It reads the Initial packet whose TLS handshake type is `2`. | #102 |
| JA4S | The `raw` field sorts the extension list. | Both raw fields hold the extension list in wire order, which is the `JA4S_r` value. | #108 |
| JA4 and JA4S | A version of `0x0200` writes `s2`. | A version of `0x0002` writes `s2`, and FoxIO retracted the earlier reading. | #227 |

**JA4SSH also gained a trailing fingerprint.** `Processor.close_open_windows` emits every
window a connection left open, so a capture produces one more JA4SSH value than version
0.6.0 produced. #214 records the change. **That change adds a value and it moves none.**
The count above excludes it, and the table above holds no row for it.

## What stays the same

- Every fingerprinter class keeps its name, and `ja4plus.__all__` names the 25 entries the
  version 1.0.0 interface promises.
- Every `generate_*` function keeps its name and its signature.
- `ja4plus live` keeps working as an alias of `ja4plus watch`.
- Item access keeps working on a result and on a lookup result, for one major version.

## How to read a deprecation warning

Item access on `FingerprintResult` and on `LookupResult` raises a `DeprecationWarning`.
Python hides that warning by default, so run the interpreter with `-W default` to see it.

Replace `result["fingerprint"]` with `result.fingerprint`. **The key `"method"` raises a
`KeyError`, because the field is `type`.**

## Where to read more

- [The output schema](output-schema.md) states the shape of every output line, and its
  version rule.
- [The method index](methods/index.md) names every method and links its page.
- [The concurrency contract](concurrency.md) states whether threads may share one
  processor.
- `CHANGELOG.md` holds every change of this release, and not the breaking ones alone.
