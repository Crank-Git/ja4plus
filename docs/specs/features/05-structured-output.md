---
id: structured-output
feature: Structured output
epic: "Epic 5: Structured output"
status: issued
issues: [16, 49, 50, 51, 52]
mockups: [mockups/01-cli-output.html]
---

## Purpose

The command-line program already writes three formats. None of them is a contract.
The JSON object carries a `source` string that packs the addresses and ports
together, so a downstream tool must parse it apart again. The CSV header changes
depending on whether the `--lookup` flag was passed. Nothing records which version
of the schema produced a line.

A capture analyst pipes this output into another tool. That tool breaks when a
column moves. This feature set makes the output a stable, documented, versioned
contract.

## User stories

- As a capture analyst, I want each output line to carry the addresses and ports as
  separate fields, so that I do not parse a composite string.
- As a capture analyst, I want the CSV columns to be the same whatever flags I
  passed, so that my parser does not need to know the command line.
- As a capture analyst, I want to know which schema version produced a file, so
  that my parser can reject a file it does not understand.

## Functional requirements

FR-structured-output-1 — Every output format carries the source address, source
port, destination address and destination port as separate fields.

FR-structured-output-2 — The JSON format writes one object per line.

FR-structured-output-3 — Every JSON object carries a `schema_version` field.

FR-structured-output-4 — The CSV format writes the same columns whatever flags the
user passed.

FR-structured-output-5 — A column with no value is empty rather than absent.

FR-structured-output-6 — The `--format` option accepts `table`, `json` and `csv`.

FR-structured-output-7 — The table format is for a person reading a terminal, and
carries no stability promise.

FR-structured-output-8 — The JSON and CSV formats carry a stability promise, stated
in the documentation.

FR-structured-output-9 — The program writes results to standard output and
diagnostics to standard error.

FR-structured-output-10 — The `--output` option writes results to a file.

FR-structured-output-11 — The program builds one `Processor` rather than a
dictionary of fingerprinters.

FR-structured-output-12 — The program does not swallow a fingerprinter error
silently.

FR-structured-output-13 — The documentation records the schema and its version.

## User flows

**An analyst reads a capture into another tool.**

1. The analyst runs `ja4plus analyze capture.pcap --format json`.
2. The program writes one JSON object per line to standard output.
3. The analyst pipes the output into `jq` or into a log shipper.
4. Each line carries every field the downstream tool needs.

**An analyst reads a capture at a terminal.**

1. The analyst runs `ja4plus analyze capture.pcap`.
2. The program writes an aligned table with a header.
3. The analyst reads the fingerprints.

## Screens & states

The mockup at `mockups/01-cli-output.html` shows the three formats.

| Screen | Purpose | States |
|---|---|---|
| Table output | A person reads fingerprints at a terminal. | Header and rows; no results; error on standard error. |
| JSON Lines output | A tool reads fingerprints. | One object per line; no output when there are no results. |
| CSV output | A spreadsheet or a database reads fingerprints. | Header row and data rows; header only when there are no results. |

## Behaviour rules

- The schema version starts at 1. It rises when a field is removed or its meaning
  changes. Adding a field does not raise it.
- A JSON object omits no field. A field with no value is `null`.
- The CSV column order is fixed and documented. A new column is appended, never
  inserted.
- The table format aligns columns to the terminal width when the output is a
  terminal, and uses fixed widths otherwise.
- The program writes nothing to standard output except results. A progress message
  goes to standard error.
- When `--output` names an existing file, the program refuses to overwrite unless
  `--force` is passed.
- The identification field is present in every format, and is `null` or empty when
  the user did not pass `--lookup`.

## Data touched

- Changed file `ja4plus/cli.py`.
- New file `ja4plus/output.py`, holding one writer per format.
- New file `docs/output-schema.md`.
- New file `tests/test_output_schema.py`.

## Interfaces

The JSON Lines object:

```json
{
  "schema_version": 1,
  "timestamp": "2026-08-06T12:34:56.789012Z",
  "type": "ja4",
  "fingerprint": "t13d1516h2_8daaf6152771_02713d6af862",
  "raw": null,
  "raw_original_order": null,
  "src_ip": "192.168.1.10",
  "src_port": 54321,
  "dst_ip": "93.184.216.34",
  "dst_port": 443,
  "identified_as": null
}
```

The CSV columns, in order:

```
schema_version,timestamp,type,fingerprint,raw,raw_original_order,src_ip,src_port,dst_ip,dst_port,identified_as
```

The field names match `FingerprintResult`, which matches the port's struct under
parity rule 2. `schema_version` and `identified_as` are additions of the
command-line program, not of the library.

## Edge cases & failures

| Case | What happens |
|---|---|
| The capture holds no fingerprintable packet. | The JSON format writes nothing. The CSV format writes the header only. The table format writes the header and a message on standard error. |
| A fingerprint contains a comma. | The CSV writer quotes the field. |
| The output file already exists. | The program exits with an error unless `--force` is passed. |
| Standard output is a pipe that closes early. | The program exits quietly, without a traceback. |
| A packet carries no timestamp. | The `timestamp` field is `null`. |
| A fingerprinter raises. | The program writes one line to standard error that names the method, and continues. |
| The user passes `--format json --output out.json`. | The file holds one JSON object per line. It is not a single JSON array. |

## Acceptance criteria

- [ ] `ja4plus analyze <capture> --format json` writes one JSON object per line.
- [ ] Every JSON object holds all 11 fields listed above.
- [ ] Every JSON object holds `"schema_version": 1`.
- [ ] The CSV header is identical with and without `--lookup`.
- [ ] The CSV header matches the documented column order exactly.
- [ ] `ja4plus analyze <capture> --format json | jq -e '.src_port' ` succeeds.
- [ ] `ja4plus analyze <empty capture> --format csv` writes the header and no data
      row.
- [ ] `ja4plus analyze <capture> --output existing.json` exits non-zero.
- [ ] `ja4plus analyze <capture> --output existing.json --force` overwrites.
- [ ] Piping the output into `head -1` produces no traceback.
- [ ] `docs/output-schema.md` documents every field.
- [ ] A test compares the CSV header against the documented column list.

## Out of scope

- An output format other than table, JSON Lines and CSV.
- Direct delivery to a message queue or a log service.
- Compression of the output file.
- A schema version above 1.

## Open questions

None.
