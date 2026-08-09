# The output schema

The command-line program writes one output line for each fingerprint it produces. This
page records the schema of that line and the version of that schema. A downstream tool
reads this page to learn what it may rely on.

`docs/specs/features/05-structured-output.md` defines the feature.
`ja4plus/output.py` writes the output lines, and `tests/test_output_schema.py` reads
this page back and compares it against the written output line.

**The current schema version is 1.**

## The version rule

The rule holds three parts:

- The schema version rises when a field goes away or its meaning changes.
- A new field raises no version.
- A new CSV column appends to the end of the row.

A JSON object omits no field, and a field with no value is `null`. A CSV row holds one
value for each column, and a column with no value is empty. The output line therefore
holds the same field set whatever options the user passed. `--lookup` changes the value
of `identified_as` and no other part of the line.

`tests/test_output_schema.py` holds the rule as a check. `SCHEMA_HISTORY` in that file
records the column list of each released version. The check fails when a released
column moves, changes name or goes away while `SCHEMA_VERSION` stays the same.

## How a parser reads the version

A parser reads `schema_version` first. A parser that understands version 1 accepts an
output line whose `schema_version` is 1, and rejects a line whose `schema_version` is
above 1. A parser reads a field by name in the JSON format, and by the position of the
header name in the CSV format. When this project appends a field, a parser that ignores
an unknown field keeps working.

## Stability

| Format | Stability promise | Who reads it |
|---|---|---|
| `json` | Yes | A tool. The format writes one JSON object on each line. |
| `csv` | Yes | A spreadsheet or a database. The column order is fixed. |
| `table` | No | A person at a terminal. The layout may change in any release. |

The `table` format carries no stability promise, and it writes no `schema_version`. It
packs the four endpoint values into one `Source` column for a person to read. A tool
reads the `json` format or the `csv` format instead.

## What a fingerprint is evidence of

**A fingerprint is evidence of the bytes the packet carried. It is no evidence of a real
client.**

`ja4plus` adds no plausibility guard. A structurally valid ClientHello produces a
fingerprint, whatever its body holds. The headers and the length fields decide the
outcome, and the content of the body decides nothing.

Read the consequence before you trust an output line that untrusted traffic produced. Any
sender can build bytes that produce a well formed fingerprint. That fingerprint names no
application on its own. `identified_as` reports what the mapping file holds for the
value, and a sender who chooses the bytes chooses that value too.

The behaviour follows the FoxIO reference. No FoxIO material rejects such a packet, so a
guard here would make `ja4plus` answer differently from every FoxIO implementation on the
same bytes. #343 holds the decision, the `Divergence register` of `docs/specs/spec.md`
holds the measurement, and `tests/fuzz/test_structural_validity.py` holds the cases.

## Where the output goes

The command writes results to standard output and every diagnostic to standard error, so
a pipe that reads standard output reads results alone. A progress message, a warning and
an error each go to standard error.

`--output FILE` writes the results to a file instead, and standard output stays empty.
The diagnostics still go to standard error. When the file exists, the command writes one
line to standard error and exits with the status 1:

```
Error: the output file exists: results.json. Pass --force to overwrite it.
```

`--force` overwrites the file. The command reads the file never. Without `--force` the
command creates the file and fails when the path already holds one, so it writes through
no symbolic link and it loses no file to a second writer.

A capture that the command cannot read leaves a partial file. The command writes the
header first and the results as it reads them, which is what a shell redirection of
standard output also produces. Read the exit status before you read the file.

A reader that closes the pipe early ends the run. `ja4plus analyze capture.pcap | head -1`
writes no traceback and no shutdown message. The command exits with the status 1.

The header of each format belongs to the results, so it goes to standard output or to
the file that `--output` names. The `csv` header is a row a parser reads. The `table`
header is the first line a person reads.

A capture that produces no fingerprint therefore writes nothing in the `json` format. It
writes the header alone in the `csv` format. It writes the header in the `table` format,
plus one line on standard error:

```
No fingerprint was produced.
```

Every option runs before the subcommand name and after it. `ja4plus --format json analyze
capture.pcap` and `ja4plus analyze capture.pcap --format json` do the same thing.

## Fields

The output line holds eleven fields. The CSV format writes them as eleven columns in
this order, and the JSON format writes them as eleven keys.

| Position | Field | JSON type | Empty value | Meaning |
|---|---|---|---|---|
| 1 | `schema_version` | number | Never empty | The version of this schema. It is `1`. |
| 2 | `timestamp` | string or null | `null` | The time of the packet that produced the fingerprint, in RFC 3339 form with the suffix `Z`. |
| 3 | `type` | string | Never empty | The method name in lowercase, for example `ja4` or `ja4ssh`. |
| 4 | `fingerprint` | string | Never empty | The fingerprint string of that method. |
| 5 | `raw` | string or null | `null` | The raw form, when the method writes one. |
| 6 | `raw_original_order` | string or null | `null` | The original-order raw form, when the method writes one. |
| 7 | `src_ip` | string | `""` | The source address of the packet or the connection. |
| 8 | `src_port` | number | `0` | The source port. It is `0` when the packet carries no port. |
| 9 | `dst_ip` | string | `""` | The destination address. |
| 10 | `dst_port` | number | `0` | The destination port. It is `0` when the packet carries no port. |
| 11 | `identified_as` | string or null | `null` | The application name the lookup returned. It is `null` without `--lookup`, and `null` when the lookup finds no match. |

The CSV format writes an empty column where the JSON format writes `null`. The CSV
format writes `0` where the JSON format writes the number `0`.

Fields 2 through 10 carry the names of `FingerprintResult`, which carries the names of
the `ja4plus-go` struct under parity rule 2. `schema_version` and `identified_as`
belong to the command-line program, and the library result carries neither.

## The raw forms

Four of the ten methods write a value into a raw field. The other six write `null` into
both raw fields. JA4H writes a value into one raw field and `null` into the other, so
read the table for the exact behaviour of each method.

| Method | `raw` | `raw_original_order` |
|---|---|---|
| `ja4` | The `JA4_r` value. | The `JA4_ro` value. |
| `ja4s` | The `JA4S_r` value. | The `JA4S_r` value. |
| `ja4h` | `null` | The `JA4H_ro` value. |
| `ja4x` | The `JA4X_r` value. | The `JA4X_r` value. |
| `ja4t`, `ja4ts`, `ja4l`, `ja4ssh`, `ja4d`, `ja4d6` | `null` | `null` |

JA4S and JA4X sort no list, so one value serves both raw fields. JA4H writes no `JA4H_r`
value, so its `raw` field is always `null`.

## An example JSON object

```json
{"schema_version": 1, "timestamp": "2004-05-13T10:17:08.222534Z", "type": "ja4h", "fingerprint": "ge11nr08enus_dacf082e1695_000000000000_000000000000", "raw": null, "raw_original_order": "ge11nr08enus_Host,User-Agent,Accept,Accept-Language,Accept-Encoding,Accept-Charset,Keep-Alive,Connection_", "src_ip": "145.254.160.237", "src_port": 3372, "dst_ip": "65.208.228.223", "dst_port": 80, "identified_as": null}
```

The `json` format writes one object on each line. The output is no JSON array, so a
reader parses each line on its own.

## An example CSV file

```
schema_version,timestamp,type,fingerprint,raw,raw_original_order,src_ip,src_port,dst_ip,dst_port,identified_as
1,2004-05-13T10:17:07.311224Z,ja4t,8760_2-1-1-4_1460_00,,,145.254.160.237,3372,65.208.228.223,80,
```

The writer quotes a value that holds a comma. The `raw_original_order` value of JA4H
holds commas, so the writer quotes it.

## The history of the schema

| Version | Release | What changed |
|---|---|---|
| 1 | Unreleased | The first published schema. It holds the eleven fields above. |
