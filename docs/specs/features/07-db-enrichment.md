---
id: db-enrichment
feature: Database enrichment
epic: "Epic 7: Database enrichment"
status: issued
issues: [18, 57, 58, 59, 60, 61]
mockups: []
---

## Purpose

A fingerprint on its own is an identifier. An analyst wants a name. `ja4plus`
ships FoxIO's mapping file and looks a fingerprint up in it.

One behaviour needs to change before version 1.0.0. `JA4DBClient.lookup` calls
`https://ja4db.com/api/read/<fingerprint>` on every miss, with no opt-in at that
layer. A fingerprint describes traffic the operator observed. Sending it to a
third party discloses that traffic. The command-line flag `--lookup` reads as a
request for a local lookup, and the operator is not told that a network request
follows.

The port already separates the two. Parity rule 2 says this project adopts that.

## User stories

- As a monitor operator, I want the library to make no network request unless I
  ask for one, so that my monitor discloses nothing about the traffic I watch.
- As an analyst, I want to identify many fingerprints in one call, so that I do not
  pay the lookup cost once per result.
- As an analyst, I want to know where a name came from, so that I can judge how
  much to trust it.

## Functional requirements

FR-db-enrichment-1 — `JA4DBClient` performs no network request by default.

FR-db-enrichment-2 — `JA4DBClient(allow_remote=True)` permits the remote lookup.

FR-db-enrichment-3 — The command-line option `--lookup` performs a local lookup
only.

FR-db-enrichment-4 — The command-line option `--lookup-remote` permits the remote
lookup.

FR-db-enrichment-5 — The environment variable `JA4PLUS_DB_LOOKUP` set to `1`
permits the remote lookup.

FR-db-enrichment-6 — The command reports on standard error, once, that a remote
lookup is enabled.

FR-db-enrichment-7 — `JA4DBClient.lookup_many` accepts a sequence of fingerprints
and returns a result per fingerprint.

FR-db-enrichment-8 — A lookup result records its source.

FR-db-enrichment-9 — The lookup cache holds no more than a maximum entry count.

FR-db-enrichment-10 — The lookup cache evicts the least recently used entry when it
reaches its maximum.

FR-db-enrichment-11 — `db info` reports the mapping file path, its entry count and
its source.

FR-db-enrichment-12 — `db update` downloads the mapping file to a cache directory
and leaves the bundled file unchanged.

FR-db-enrichment-13 — The client prefers a cached mapping file over the bundled
one.

FR-db-enrichment-14 — The remote lookup has a timeout.

FR-db-enrichment-15 — A remote lookup failure returns nothing and does not raise.

## User flows

**An analyst identifies fingerprints from a capture.**

1. The analyst runs `ja4plus analyze capture.pcap --lookup`.
2. The program loads the mapping file.
3. The program identifies each fingerprint from that file only.
4. The program makes no network request.

**An analyst opts into the remote lookup.**

1. The analyst runs `ja4plus analyze capture.pcap --lookup-remote`.
2. The program writes one line to standard error that names the service it will
   contact.
3. The program looks a miss up at `ja4db.com`.
4. Each result records whether it came from the local file or the service.

**An operator refreshes the mapping file.**

1. The operator runs `ja4plus db update`.
2. The program downloads the current mapping file from FoxIO.
3. The program writes it to the cache directory.
4. `ja4plus db info` reports the new entry count and names the cache as the source.

## Screens & states

| Screen | Purpose | States |
|---|---|---|
| `db info` output | Show which mapping file is in use. | Bundled file; cached file; cached file unreadable. |
| `db update` output | Show the refresh result. | Downloaded; already current; download failed. |
| Remote-lookup notice | Tell the operator that traffic data leaves the host. | Shown once, on standard error, when remote lookup is on. |

## Behaviour rules

- The default is local. An operator who wants the network asks for it.
- The notice appears once per run, not once per lookup.
- The lookup cache stores a miss as well as a hit, so that a repeated miss costs
  nothing.
- The cache maximum is 100000 entries.
- The remote timeout is 5 seconds, and is not configurable before version 1.0.0.
- `db update` never writes inside the installed package. A package directory may be
  read-only, and a wheel reinstall would discard the file.
- The cache directory follows the platform convention: `$XDG_CACHE_HOME/ja4plus`
  or `~/.cache/ja4plus` on Linux, `~/Library/Caches/ja4plus` on macOS.
- A source value is one of `embedded`, `cache` or `remote`.

**The published source value is `embedded`, and the prose of this project still calls the
file bundled.** The two are not a contradiction. `lookup.go:31` of `Crank-Git/ja4plus-go`
sets `dbSource = "embedded"`, and `runDBInfo` of `cmd/ja4plus/main.go:378` prints it.
`CLAUDE.md` parity rule 2 gives the port the interface where FoxIO specifies nothing, and
a source label is that kind of choice. An earlier form of this file published `bundled`,
and #61 found the disagreement. The user decided on 2026-08-08 that the port wins, because
the port already corroborates every other interface choice of this feature: the cache
directory and the file name at `CachedDatabasePath` of `lookup.go:210`, the temporary-file
rename at `runDBUpdate` of `cmd/ja4plus/main.go:352`, the cache preference at `loadDB` of
`lookup.go:41`, and the `Source`, `Path` and `Entries` lines of `runDBInfo`. One
disagreement against five agreements is a specification that drifted. Read `embedded` as
the value alone. The word `bundled` describes the file that ships inside the package, and
`_BUNDLED_CSV` and `_load_bundled_db` keep their names.

Verified against: https://github.com/Crank-Git/ja4plus-go/blob/master/lookup.go (retrieved
2026-08-08).

## Data touched

- Changed file `ja4plus/ja4db.py`.
- Changed file `ja4plus/cli.py`.
- New file `tests/test_db_offline.py`.
- The cache file at the platform cache directory. It is not in the repository.

## Interfaces

```python
class JA4DBClient:
    def __init__(
        self,
        allow_remote: bool = False,
        cache_size: int = 100_000,
    ) -> None: ...

    def lookup(self, fingerprint: str) -> LookupResult | None: ...
    def lookup_many(
        self, fingerprints: Sequence[str]
    ) -> dict[str, LookupResult | None]: ...

@dataclass(frozen=True)
class LookupResult:
    application: str
    type: str
    notes: str
    source: str          # "bundled" | "cache" | "remote"
```

`LookupResult` carries the port's three fields plus `source`.

The constructor publishes no `timeout` parameter. The behaviour rule above refuses one
before version 1.0.0, and the Go port publishes none either. `RemoteLookupConfig` of
`lookup.go` holds two fields, `Endpoint` and `HTTPClient`, and it holds no field for the
remote timeout. `tests/test_db_offline.py` pins the parameter list, so a parameter that
this file does not publish fails the unit suite. #354 records the reading.

Verified against:
https://github.com/Crank-Git/ja4plus-go/blob/master/lookup.go (retrieved
2026-08-06).

Two external resources:

| Resource | URL | Note |
|---|---|---|
| Mapping file | `https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv` | Read by `db update`. |
| Lookup service | `https://ja4db.com/api/read/<fingerprint>` | Read only when the operator opts in. |

The lookup service publishes no versioned API document that this project could
find. Its response shape is therefore recorded as an assumption, and the client
treats any unexpected shape as a miss. This is listed in the spec's
`Risks & open questions`.

## Edge cases & failures

| Case | What happens |
|---|---|
| The mapping file is absent from the package. | The client loads no entry and reports a count of zero. It does not raise. |
| The cache file exists and is empty. | The client uses the bundled file. |
| The cache file exists and is corrupt. | The client uses the bundled file and reports the problem at `WARNING`. |
| The remote lookup times out. | `lookup` returns `None`. |
| The remote lookup returns a shape the client does not expect. | `lookup` returns `None`. |
| `requests` is not installed and remote lookup is requested. | The command exits with status 1 and names the extra to install. |
| `db update` runs with no network. | The command exits with status 1 and leaves the cache unchanged. |
| `db update` runs where the cache directory cannot be created. | The command exits with status 1 and names the directory. |
| `lookup_many` is given 100000 fingerprints with remote lookup off. | The call performs no network request and returns 100000 entries. |

## Acceptance criteria

- [ ] A test that fails on any outbound socket passes while `JA4DBClient()` looks
      up 1000 fingerprints.
- [ ] `JA4DBClient(allow_remote=True)` performs the remote lookup on a miss.
- [ ] `ja4plus analyze <capture> --lookup` performs no network request.
- [ ] `ja4plus analyze <capture> --lookup-remote` writes the notice once to
      standard error.
- [ ] `JA4PLUS_DB_LOOKUP=1 ja4plus analyze <capture> --lookup` permits the remote
      lookup.
- [ ] `lookup_many` returns one entry per input fingerprint, including misses.
- [ ] Every `LookupResult` carries a `source` value of `bundled`, `cache` or
      `remote`.
- [ ] The cache holds no more than `cache_size` entries after 200000 distinct
      lookups.
- [ ] `ja4plus db info` reports the path, the entry count and the source.
- [ ] `ja4plus db update` writes to the platform cache directory and leaves the
      installed package unchanged.
- [ ] After `db update`, `db info` reports `cache` as the source.
- [ ] A corrupt cache file makes `db info` report `embedded` as the source.

## Out of scope

- Writing to the lookup service.
- A local database format other than the FoxIO mapping file.
- Automatic refresh on a schedule. The operator runs `db update`.
- Enrichment fields beyond the ones the mapping file carries.

## Open questions

None.
