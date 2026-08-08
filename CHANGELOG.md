# Changelog

All notable changes to ja4plus are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The Zeek reference page reads the current comparison** (#327). Round TBD.
  `docs/specs/foxio/zeek.md` read as though #214 were open, in three places. #214 made
  JA4SSH emit the window a connection holds open when the capture ends, so `ssh2.pcapng`
  now produces `c36s52_c42s76_c51s2` as its second value, which the Zeek baseline holds.
  The re-run against the pinned FoxIO checkout prints 98 rows, of which 63 match and 35
  differ, where round 52 read 98 rows, 62 match and 36 differ. **The page now names the
  Changelog round of every run it cites**, so a reader can tell a stale count from a
  current one. **One value rating no longer follows from its evidence, and #327 leaves it
  `Undecided`**: the JA4SSH baseline was `Blocked` on #214, and the replacement rating is
  a precedence question the user decides. **#332 answers that question.** No file under
  `ja4plus/` changes, no fingerprint moves, and the register holds 135 keys against 135
  xfailed.

- **The Zeek baseline comparison script runs again, and a case now runs it** (#324).
  Round TBD. `tests/compare_zeek_baselines.py` read the composite `source` field that
  #49 removed, so the script raised `KeyError` on the first output line it parsed. The
  reader now reads `src_ip`, `src_port`, `dst_ip` and `dst_port`, which
  `docs/output-schema.md` states, and `split_source` goes away because nothing needs it.
  The reader also reads `schema_version` first and stops on a version above 1, which the
  same page states. **The script is evidence-producing tooling, not dead code**:
  `docs/specs/foxio/zeek.md` rests on it, and #198, #226 and #276 reason from its
  readings. `tests/test_compare_zeek_baselines.py` runs the script end to end over
  `dhcp.pcapng`, so a later schema change fails a case instead of breaking the script in
  silence. No fingerprint moves, no output field changes, and the schema version stays 1.

### Changed

- **The register records the kind of every decline** (#341). Round TBD.
  `tests/foxio_deviations.json` carries a `capability` field on all 135 entries, and
  `CAPABILITY_DECLINES` is gone from `tests/test_precedence_exception.py`. #334 shipped
  bar 1 of the precedence exception as a constant set of issue numbers, so a new
  capability decline would have reached the exception unless somebody edited a test that
  named it nowhere near the decline. **`true` records a capability this project chose not
  to build, and `false` records a disagreement about the value.** `tests/foxio_deviations.py`
  reads the field beside `decided` and states the default in the schema, and
  `unkinded_declines` requires the field on every decided entry. **43 entries record a
  capability decline, and all 43 name #129**, which the recorded cause of each of the 135
  entries decides. No entry was undeterminable. **The reach of the exception is 6 rows
  before and after**, and the six rows are unchanged. No fingerprint moves, no file under
  `ja4plus/` changes, and no vector is adopted.

- **The precedence exception is source-neutral** (#334). Round TBD.
  `.claude/rules/external-apis.md` wrote the exception of #332 for the Zeek baseline
  alone, because that was the case #327 raised. Where `tests/foxio_deviations.json`
  declines the FoxIO Python value under a decided entry, **any other FoxIO implementation
  may hold the reference value** for that method on that connection. **Two bars stand
  above the rule.** A decline that records a capability this project chose not to build
  reaches no row, and #129 is that case: `ja4plus` reads no encrypted request by
  decision. Where the remaining FoxIO sources hold different values, no source holds the
  reference and the row stays declined. **The exception reaches 6 rows of the 135 the
  register holds**, where the widened rule before the bars reaches 58.
  `tests/test_zeek_precedence_exception.py` becomes `tests/test_precedence_exception.py`
  and measures the reach against every source. **Three findings came out of the search.**
  The register records no field that separates a value decline from a capability decline,
  and the rule states a proposal for one. `gre-erspan-vxlan.pcap/0:65174/JA4T.1` carries
  the value form and declines no Python value, so the rule now reads that fact from the
  vectors. The Wireshark dissector appends the third part that bars a Zeek JA4L value,
  which the bar does not name; #225 records that this project adopted the `quic` marker
  from the dissector on purpose, so nothing there changed. **No vector is adopted, no
  register entry changes, no file under `ja4plus/` changes, and no fingerprint moves.**

- **A declined FoxIO Python value forfeits its precedence** (#332). Round TBD.
  `.claude/rules/external-apis.md` states that `python/test/testdata/` decides where it
  and a Zeek baseline both hold a value for one method on one connection, and it named no
  exception for a value this project already ruled wrong. The rule now carries one
  exception: where `tests/foxio_deviations.json` declines the Python value under a decided
  entry, a Zeek baseline may hold the reference value for that method on that connection.
  **Python keeps its precedence everywhere else.** **The condition is one recorded decline
  that names an issue, and no reading of which value looks right reaches it.** An
  undecided entry is an open question, and the exception passes over it.
  `docs/specs/foxio/zeek.md` now rates `Scripts.ja4-ssh2/ja4ssh.log` Medium and states the
  reason, where #327 left it `Undecided`. `tests/test_zeek_precedence_exception.py`
  measures the reach: the exception reaches 1 row of the 135 the register holds, and that
  row is `ssh2.pcapng/14:57377/JA4SSH.2` under #97. **No baseline is adopted as a vector**,
  no file under `ja4plus/` changes, and no fingerprint moves.

- **The vocabulary settles one word for the serialized output line** (#306). Round TBD.
  The `## Terms` table of `docs/specs/spec.md` listed `record` in the `Do not use`
  column of `result`, and `ja4plus/output.py` used it as a noun in five places. #50
  found that and reworded its own page rather than the shared table. The table now holds
  the term `output line`, whose `Do not use` column names `record`, `result` and
  `entry`. **A result and an output line are two things.** A result is one fingerprint
  one method produced. An output line carries every field of the result, plus
  `schema_version` and `identified_as`, which the command-line program owns. The word
  now reads the same way in `ja4plus/output.py`, `ja4plus/cli.py`, `README.md`,
  `tests/test_output_schema.py`, `tests/test_cli.py`, `tests/test_parity.py`,
  `tests/compare_zeek_baselines.py` and `examples/monitoring_daemon.py`.
  `docs/output-schema.md` already used it and needs no change. The `json` format writes
  one output line as one JSON object, and the `csv` format writes it as one row, so the
  identifier for a parsed line is now `json_object`. **The word `record` keeps two other
  meanings that this term does not touch**: the verb, as in `#215 records the reading`,
  and the TLS record of RFC 8446. **No field name and no column name moved.**
  `schema_version` stays 1, `CSV_COLUMNS` holds the same eleven names in the same order,
  and `ja4plus.__all__` names the same 25 entries. A replay of the 38 committed captures
  in all three formats produces 114 runs, 2466 output lines and 0 differing bytes
  against the base. Both suites report the counts of the base: 1839 passed and 8
  xfailed in the unit suite, and 1531 passed, 143 skipped and 135 xfailed in the
  conformance suite, against 135 keys in `tests/foxio_deviations.json`.

- **The command-line program separates results from diagnostics and gains `--output`**
  (#52). Round 95. The program writes results to standard output and every diagnostic
  to standard error, so a pipe that reads standard output reads results alone. The
  progress line of `db update` moves to standard error. `--output FILE` writes the
  results to a file and leaves standard output empty. The program refuses to overwrite a
  file that exists and exits with the status 1, and `--force` overwrites it. Without
  `--force` the program creates the file, so it writes through no symbolic link and it
  loses no file to a second writer. A reader
  that closes the pipe early, such as `head -1`, ends the run with no traceback and no
  shutdown message. Every option now runs before the subcommand name and after it, so
  `ja4plus analyze capture.pcap --format csv` does what
  `ja4plus --format csv analyze capture.pcap` does. A capture that produces no
  fingerprint writes one line to standard error in the `table` format, and the `json`
  and `csv` formats keep the output the schema promises.

- **The command-line program runs on `Processor` and reports a fingerprinter error**
  (#51). Round 94. The program built its own dictionary of fingerprinters and ran its
  own per-packet loop in `analyze` and in `live`. Both loops caught every error with
  `except Exception` and continued without a word. The program now builds one
  `Processor`, so it gets the connection eviction of Epic 3 and the errors of Epic 4. A
  method that fails to read a packet writes one line to standard error that names the
  method, and the run continues. The program keeps no exception, because an exception it
  kept would hold the error chain of every packet it read. `--types` now selects which
  methods the program reports rather than which methods it builds, so the program evicts
  the connections of a method you filtered out and it reports that method's errors. The
  reported order is still the order you wrote in `--types`, and a name you write twice
  keeps its first position. No fingerprint value moved:
  the program writes the same 863 output lines over the 43 committed captures, byte for
  byte,
  and the conformance suite reports the same 1531 passed, 143 skipped and 135 xfailed.
  The unit suite rises from 1801 passed to 1814 passed, which is the 13 cases the change
  adds.

- **The command-line program writes the addresses and the ports as separate fields**
  (#49). Round 96. The `json` and the `csv` formats replace the composite `source`
  field of version 0.6.0 with `src_ip`, `src_port`, `dst_ip` and `dst_port`, so a
  downstream tool parses no composite string. The CSV header is now fixed at
  `schema_version,timestamp,type,fingerprint,raw,raw_original_order,src_ip,src_port,dst_ip,dst_port,identified_as`,
  and it no longer changes with `--lookup`. Every field is present in every output line:
  a field with no value is `null` in the `json` format and empty in the `csv` format.
  `identified_as` is therefore present without `--lookup`, where version 0.6.0 omitted
  it. Each output line also carries the packet `timestamp` in RFC 3339 form. New module
  `ja4plus/output.py` holds one writer per format. #50 documents the schema and its
  version.

- **`Processor.process_packet` returns a list of `FingerprintResult`** (#45). Round TBD.
  The method returned a list of dictionaries through version 0.6.0. A caller who reads
  `result["fingerprint"]` keeps working for one major version, and item access emits a
  `DeprecationWarning` that names the attribute form. Read `result.fingerprint` instead.
  The results follow the fixed method order `ja4`, `ja4s`, `ja4h`, `ja4t`, `ja4ts`,
  `ja4l`, `ja4x`, `ja4ssh`, `ja4d`, `ja4d6`, and that order is part of the interface.
  `Processor.close_open_windows` still returns a list of dictionaries, because a window
  carries a connection key and no `FingerprintResult` field holds one. The processor
  reads no packet timestamp, so `timestamp` holds `None`. No fingerprint value moved:
  the conformance suite reports the same 1477 passed, 143 skipped and 137 xfailed.
  `docs/specs/features/04-typed-api.md` states FR-typed-api-3.

### Added

- **`Processor.process_packet_with_method_errors` names the method that raised** (#51).
  Round 94. It returns the same results as `process_packet_with_errors`, and one pair
  of the method name and the exception for each method that raised. An exception names
  no method, so `process_packet_with_errors` alone cannot tell a caller which method
  failed. Every returned exception still carries no traceback, for the reason #45
  records. `process_packet_with_errors` keeps its signature and drops the name.

- **The output schema carries a version, and `docs/output-schema.md` records it** (#50).
  Round 96. The new page states the schema version, the eleven fields, the raw form
  each of the ten methods writes, and the rule that raises the version. **The rule is a
  check and not prose alone.** `SCHEMA_HISTORY` in `tests/test_output_schema.py` freezes
  the column list of each released version, and `TheSchemaVersionRule` fails when a
  released column moves, changes name or goes away while `SCHEMA_VERSION` stays the
  same. A new column appends to the end of the row and raises no version.
  `TheSchemaDocument` parses the page and compares its field table against the written
  CSV header and the written JSON object, so the page and the code cannot drift apart.
  Two further cases read the value of each field, because a swap of two values changes
  the meaning of both fields and moves no name. **Ten mutations each make the file
  fail**, measured on 2026-08-08 against a baseline of 41 passed: a swap of two CSV
  columns fails 7 cases, an appended column fails 4, a dropped JSON field fails 5, a
  raise of `SCHEMA_VERSION` with no history entry fails 6, a renamed column in the page
  alone fails 3, a changed stability promise fails 1, a deleted rule sentence fails 1, a
  swap of two JSON values fails 1, a swap of two CSV values fails 2, and a write of
  `src_port` into `dst_port` fails 2. The appended column is the case that proves the
  rule: it fails the page checks, because a new field must be documented, and it leaves
  the version checks green, because a new field raises no version.
  **The `json` and `csv` formats carry the stability promise, and the `table` format
  carries none**, which the page states and a check reads back. The page records that
  `ja4`, `ja4s`, `ja4h` and `ja4x` write a raw form and the other six methods write
  `null`; `ja4x` now writes `JA4X_r`, which #267 added.

- **The package ships the `py.typed` marker and declares `__all__`** (#47). Round TBD.
  The new file `ja4plus/py.typed` follows PEP 561, and `pyproject.toml` ships it as
  package data. A caller who runs `mypy --strict` against their own code now resolves
  the annotations of `ja4plus`: `unzip -l dist/*.whl` lists `ja4plus/py.typed`, and a
  consumer installed from that wheel reads `result.fingerprint` as `str`.
  **`ja4plus.__all__` names the 25 promised names**, and version 1.0.0 keeps each one
  until version 2.0.0. A name absent from `__all__` is not promised. The list holds the
  typed result, the processor, the ten fingerprinter classes, the ten one-shot
  functions, the two certificate helpers and `__version__`. `bind_loopback_ipv6`,
  `register_tunnel_dissectors`, `__author__` and `__license__` stay out: the package
  calls the first two at import time, and the last two describe the project and not the
  interface.
  **`ProcessorStats` is public at `ja4plus.processor.ProcessorStats`**, because
  `Processor.stats` returns `dict[str, ProcessorStats]`; the class moves nowhere.
  `docs/specs/features/04-typed-api.md` states FR-typed-api-9, FR-typed-api-10,
  FR-typed-api-12 and FR-typed-api-13.

- **`Processor.process_packet_with_errors` returns the results and the errors** (#45).
  Round TBD. `process_packet` logs a fingerprinter error at DEBUG and returns the
  results alone, so a caller could not tell a packet that produces no fingerprint from a
  packet that failed a parse. The new method returns both lists, and one method that
  raises poisons no other method. The Go port returns the pair from one call, and parity
  rule 2 keeps it. **Every returned exception carries no traceback.** A traceback holds
  the frame of every call it passed. Those frames hold the packet. A monitor that keeps
  the errors of every packet would therefore hold every packet it read. The type, the
  message and the error chain stay. `docs/specs/features/04-typed-api.md` states
  FR-typed-api-4. `CLAUDE.md` states the packet rule.

- **`FingerprintResult` is the typed result of the public interface** (#44). The new
  module `ja4plus/types.py` holds a frozen dataclass with nine fields, and `ja4plus`
  exports the name. The field names are the snake-case form of the `FingerprintResult`
  struct of the Go port, under parity rule 2, so the field that names the method is
  `type` and not `method`. A result reads by field name as well as by attribute, so
  code written against the dictionary of version 0.6.0 keeps working for one major
  version. **Item access emits a `DeprecationWarning` that names the attribute form.**
  The item access covers reading only, and a result supports no item assignment.
  #45 makes `Processor.process_packet` return these results. No fingerprint value moved. `docs/specs/features/04-typed-api.md` states
  FR-typed-api-1, FR-typed-api-2, FR-typed-api-5 and FR-typed-api-6.

- **JA4SSH emits the window a connection holds open when the capture ends**
  (#214). Every fingerprinter and the processor now carry `close_open_windows()`.
  Call it when the packet source ends. `ja4plus analyze` calls it after the file
  reader, and `ja4plus live` calls it after the capture stops. JA4SSH is the only
  method that holds a window, so every other method returns an empty list. A
  connection that sends no FIN+ACK packet held its last window open, and no rule
  emitted it. `ssh2.pcapng` carries 452 TCP packets on port 22 and no FIN+ACK
  packet, so it now produces a second value, `c36s52_c42s76_c51s2`, which the
  FoxIO Rust snapshot and the FoxIO Zeek baseline both hold. Five other captures
  gain one trailing value each: `ssh.pcapng`, `ssh-scp-1050.pcap`,
  `ssh2-malformed.pcap`, `ssh2-moloch-crash.pcap` and `tcpdump-geneve.pcap`. No
  value of another method moved. **This is a behaviour change for a caller that
  reads JA4SSH.** A window that holds no SSH packet still emits nothing, so the
  value `c0s0` that #97 declines does not return. `docs/specs/foxio/JA4SSH.md`
  R11 records that the specification states no rule here, and the user decided it
  on 2026-08-08.

- **JA4H computes its raw form** (#131). FoxIO publishes one raw key for JA4H,
  `JA4H_ro`, and `ja4plus` computed none, so 89 reference values reached no
  comparison. Every JA4H result now carries `raw_original_order`, and the
  fingerprinter carries `last_raw_original_order`, so the processor and the
  command-line program report the value the way they report `JA4_ro`. The form is
  `<part a>_<header names>_<cookie names>_<cookie pairs>`, and every list holds the
  wire order. A request that carries no cookie ends after the header names and one
  underscore. 79 of the 89 values now match. The other ten sit on a stream whose
  hashed JA4H value fails too, and #129 and #35 own them. No hashed fingerprint
  changed.

### Fixed

- **JA4 and JA4S write `s2` for the SSL 2.0 version value `0x0002`** (#227).
  `ja4.py:127`, `ja4.py:250` and `ja4s.py:393` wrote `s2` for `0x0200`, which is the
  value FoxIO retracted. `technical_details/JA4.md:65` at the pinned commit states
  `0x0002 = SSL 2.0 = “s2”`, and FoxIO commit `3e02a27`, dated 2024-08-23, is titled
  `Fix SSL version fields: SSL 2.0 is 0x0002, SSL 1.0 never existed`. The three sites
  now hold `0x0002`, and `0x0200` reaches the `00` fallback that the same specification
  line states. The dissector table `ssl_versions[]` and the `TLS_MAPPER` of the FoxIO
  Python reference both hold `0x0002` and neither holds `0x0200`, so the repair adds no
  alias. `ja4plus` held no `0x0100` row, so the SSL 1.0 half of the correction needed
  nothing. **No fingerprint of the vector set moves**: no capture under
  `tests/foxio_vectors/` carries an SSL 2.0 hello, the 38 captures produce 1494 values
  before and 1494 after, and zero values differ. Two parser paths present the value —
  the legacy version field and the `supported_versions` extension — and the SSL 2.0
  record format reaches none, because `parse_tls_handshake` reads a TLS record header.
  `tests/test_ja4_ssl2_version.py` holds the measurements, and #221 found the defect.

- **The QUIC CRYPTO fragment buffer of JA4 holds a limit** (#122).
  `reassemble_crypto_fragments` allocated a buffer that reached the highest fragment
  offset, and RFC 9000 Section 16 lets a CRYPTO frame offset reach
  4611686018427387903. A client Initial packet derives its keys from the connection
  ID the same packet carries in cleartext, so one UDP datagram from a sender who
  holds no connection reached the allocation. One fragment of one byte at offset
  `2**28` allocated 256 MiB, and offset `2**40` names 1024 GiB. The reader now drops
  a fragment that ends past `MAXIMUM_CRYPTO_BUFFER_BYTES`, which is 16384 and comes
  from the RFC 8446 Section 5.1 cap on a TLS record plaintext. The JA4 client path
  collects through `collect_crypto_fragments`, which #102 already shipped, so the
  per-connection list is bounded too. The fragment table of `JA4Fingerprinter` gains
  a maximum entry count of 1000 connections and a maximum age of 30 seconds, which
  the packet clock measures. No fingerprint changed.

- **JA4S tells a QUIC server Initial packet from a client one** (#118). `ja4plus`
  read every QUIC Initial packet as a client Initial packet, because the two carry
  the same long-header packet type. It stored the connection ID of the server packet
  under the reverse connection key and returned, so it never read the ServerHello.
  A server Initial packet names the client with the connection ID the client chose
  as its source, so the stored value was empty. JA4S now reads the port to tell the
  two apart, as JA4L does, and a server Initial packet replaces no stored client
  connection ID. `chrome-cloudflare-quic-with-secrets.pcapng` stream 50280 now
  reports `q130200_1301_234ea6891581`, and `ssh2.pcapng` and `tls3.pcapng` report a
  JA4S value on eight more QUIC streams. No JA4S value on any other stream changed.
  The FoxIO reference reads no QUIC handshake in the committed vectors, so it holds
  no value for those nine streams. It holds no JA4 value for the same nine streams,
  and #13 already owns that divergence for JA4. The register rises from 67 entries
  to 70.

- **BREAKING — the JA4S raw form holds the extensions in wire order** (#108). The
  `raw` key of a JA4S result sorted the extensions into numeric order. The FoxIO
  `JA4S_r` value holds them in the order the ServerHello carries them. A
  caller who stored the `raw` value of a JA4S result before this release gets a
  different string now. The old value matched 49 of the 84 `JA4S_r` values the
  committed vectors hold. FoxIO publishes `JA4S_r` and no `JA4S_ro`, because JA4S
  sorts no list. Both `raw` and `raw_original_order` now hold one value.
  `badcurveball.pcap` reports `t1205h1_c02b_0000,ff01,000b,0023,0010` where it
  reported `t1205h1_c02b_0000,000b,0010,0023,ff01`. The JA4S fingerprint is
  unchanged, because it already hashed the extensions in wire order. JA4 is
  unchanged: `JA4_r` sorts the ciphers and the extensions, and `JA4_ro` holds
  the wire order. `docs/implementation_notes.md` records the sort rule of each
  method and the evidence for it.

- **BREAKING — the JA4L QUIC server point reads the Initial packet that completes
  the ServerHello** (#102). `ja4plus` read the first server Initial packet, and the
  reference reads the Initial packet whose TLS handshake type is `2`. A server sends
  an Initial packet that holds an ACK frame first, so the two points differ. The
  cause was one line: `decrypt_initial_payload` read the ciphertext to the end of the
  UDP datagram, and the AEAD tag of an Initial packet covers only the bytes the
  Length field names. Every server Initial packet therefore failed the tag.
  `ja4plus/utils/quic_utils.py` gains four functions:

  - `_initial_packet_end` bounds the ciphertext by the Length field.
  - `decrypt_quic_server_initial_crypto` returns the CRYPTO fragments of one server
    Initial packet.
  - `server_hello_is_complete` reports whether the collected fragments hold a whole
    ServerHello.
  - `collect_crypto_fragments` stops a buffer at 16384 bytes. RFC 9000 Section 16
    lets a CRYPTO frame offset reach 4611686018427387903, and a reassembly allocates
    a buffer that reaches the highest offset.

  A QUIC connection whose server Initial packets do not decrypt now emits no
  `JA4L-S` value, as the reference does.
  `chrome-cloudflare-quic-with-secrets.pcapng` stream
  50280 now reports `10990_56` where it reported `9285_56`, and `tls3.pcapng` stream
  61884 reports `3583_57` where it reported `3051_57`. The register falls from 73
  entries to 71. No other vector changed.

- **BREAKING — JA4SSH counts an SSH message, not a TCP segment** (#98). `ja4plus`
  counted one SSH packet for every TCP segment that carried a payload. The FoxIO
  reference counts the packets `tshark` labels `ssh`, and `tshark` labels only the
  segment that completes an SSH message. The two counts therefore differed by one
  packet for each SSH message that spans two segments, and every window boundary
  after such a message moved. `ja4plus/utils/ssh_utils.py` gains
  `SSHMessageTracker`, which follows the message boundary of one direction while
  the direction sends plaintext. `ssh-r.pcap` stream 1 now reports `c6s5` where it
  reported `c7s5`, and all five windows of `ssh-r.pcap` stream 2 now hold the
  reference packet counts. `ssh.pcapng`, `ssh-scp-1050.pcap` and `ssh2.pcapng` are
  unchanged.

- **BREAKING — JA4L reports the one-way latency and the measurement point the
  FoxIO vectors hold** (#88). The fingerprinter reported the whole round-trip
  time, and it measured the client value to the bare ACK of the handshake. The
  FoxIO material states `One-way TCP latency in us`, and the vectors hold half of
  the measured time. The client value now measures to the last packet that
  carries the relative sequence number 1 and the relative acknowledgement number
  1. One connection now carries one `JA4L-C` value. The QUIC form now reads the
  Initial packets and the Handshake packets on port 443. A UDP flow that carries
  no QUIC long header gives no value. `ja4plus` also imports the scapy
  Geneve, VXLAN and ERSPAN dissectors, so a mirrored capture reads its inner TCP
  layer. Every JA4L value a caller stored before this release differs from the
  value this release emits. 108 of the 114 registered JA4L value deviations
  now conform, and #101 and #102 own the six that remain.

- **BREAKING — JA4SSH counts a bare ACK the way FoxIO counts one** (#92). A bare
  ACK carries the ACK flag alone and no payload. `ja4plus` read the ACK flag
  alone, so it counted a SYN+ACK, a FIN+ACK and a RST+ACK as bare ACKs. It also
  created its state table entry on the first SSH packet, so it dropped the ACK
  that completes the TCP handshake. The two ACK counts of a JA4SSH fingerprint
  therefore change on any connection that carries a bare ACK. `ssh-r.pcap`,
  `ssh-scp-1050.pcap` and `ssh2.pcapng` now equal the reference on their first
  window. `ssh.pcapng` holds no bare ACK, and it stays at `c36s36_c76s124_c0s0`.

- **JA4SSH emits the window a connection holds open when it closes** (#92). A
  connection that carries fewer than 200 SSH packets produced no fingerprint at
  all, and a connection that closed part way through a window lost those packets.
  `ja4plus` now emits that window on a packet that carries the FIN flag and the ACK
  flag, which is the rule `python/ja4.py` states above `finalize_ja4ssh`. An empty
  window emits nothing. `ssh-r.pcap` now produces the occurrence keys the reference
  holds on all three of its streams.

### Divergence from the FoxIO reference

- **JA4SSH declines three results of the reference** (#96, #97, #105). Each one
  describes the capture and not the connection, so it cannot be compared against
  the output of another tool. The reference reads its mode field from the packet
  lengths of every connection in the capture, because `dict(ja4sh_stats)` shares
  one payload list (#96). It writes an extra occurrence from a window of zero SSH
  packets whenever a bare ACK follows a window boundary (#97). It emits no trailing
  window for the connection it holds at stream index 0, because `finalize_ja4ssh`
  guards with `if stream:` (#105). `ja4plus` reads the window alone, emits a value
  only for a window that holds SSH packets, and emits the trailing window for every
  connection that closes. `docs/implementation_notes.md` holds the measurement.

- **A loopback capture that carries IPv6 now reads the same way on every host**
  (#94). A capture whose link type is `DLT_NULL` starts each frame with the
  address family value of the host that captured it. That value is 24 on NetBSD
  and OpenBSD, 28 on FreeBSD, and 30 on Darwin. scapy binds one value,
  `socket.AF_INET6`, which is 10 on Linux, and no capture holds 10. `ipv6.pcapng`,
  `tls-alpn-h2.pcap` and `http-empty-useragent.pcap` therefore produced
  fingerprints on macOS and none on Linux. `ja4plus` binds all three BSD values
  when a caller imports it, and the conformance suite now reports the same counts
  on both hosts.

### Changed

- **BREAKING — JA4SSH emits one fingerprint for every 200 SSH packets** (#28).
  The window triggered at `min(packet_count, 10)`, and a complete key exchange
  also triggered it. A caller who relies on a fingerprint at 10 packets gets no
  fingerprint now. FoxIO states the interval verbatim in
  `technical_details/JA4SSH.png`: `(runs every 200 SSH packets by default)`. The
  constructor argument `packet_count` sets the window, and it defaults to 200. A
  bare ACK is not an SSH packet, and it does not advance the window. `ssh.pcapng`
  now produces exactly one JA4SSH fingerprint, `c36s36_c76s124_c0s0`, which
  equals the reference.

### Removed

- **The private helper `_src_is_client` leaves `ja4plus/fingerprinters/ja4l.py`**
  (#119). The helper read the outer address of a packet with `get_ip_layer`, and
  it compared that address against the address the connection key holds. #101
  made the JA4L connection key hold the inner address pair, so the two addresses
  are never equal for a tunnelled packet. No caller reads the helper, so no
  fingerprint changes. `FR-correctness-audit-11` asks for the removal.

## [0.6.0] - 2026-05

Major spec-compliance update against the May 2026 FoxIO JA4+ spec
(PRs #267, #270, #277, #281, #288), and a parity pass against the Go
reference implementation.

### Added

- **JA4D6** (`ja4plus.JA4D6Fingerprinter` / `generate_ja4d6`): DHCPv6
  fingerprinting (10th JA4+ method). Format mirrors JA4D with DHCPv6
  semantics — DUID size from option 1, IATA presence flag, Client FQDN
  flag, all option types in presence order including nested options
  inside IA_NA / IA_TA / IA_PD / IA Address / IA Prefix.
- **JA4D** is now a public package export
  (`from ja4plus import JA4DFingerprinter, generate_ja4d`).
- **`Processor`** aggregator class (`ja4plus.Processor`) — runs every
  JA4+ fingerprinter on each packet and returns a list of result dicts.
  Provides `process_packet`, `reset`, `cleanup_connection`,
  `get_shard_key` (sorted 5-tuple, direction-independent).
- **JA4 / JA4S raw exposure**: every result entry on these fingerprinters
  now includes `raw` and `raw_original_order` keys, plus
  `last_raw` / `last_raw_original_order` instance attributes for the most
  recent successful parse. JSON CLI output emits these fields.
- **Multi-packet QUIC CRYPTO reassembly**: large ClientHellos that span
  multiple Initial datagrams (sharing a DCID) are now reassembled. New
  helpers `decrypt_quic_initial_crypto`, `parse_crypto_frames`,
  `reassemble_crypto_fragments`, `client_hello_from_crypto_fragments` in
  `ja4plus.utils.quic_utils`. The CRYPTO frame parser now skips ACK
  frames (0x02/0x03) instead of bailing on them.
- **X.509 module helpers**: `compute_ja4x_from_pem(bytes)` and
  `compute_ja4x_from_der(bytes)` mirroring Go's
  `ComputeJA4XFromPEM` / `ComputeJA4XFromDER`.
- CLI `--types` accepts `ja4d` and `ja4d6`.

### Fixed

- **JA4 ALPN non-alphanumeric** (PR #277): when the first or last byte
  of the first ALPN value is not ASCII alphanumeric, the JA4 ALPN
  component is now the first/last character of the lowercase HEX of the
  full first ALPN value. Previously ja4plus dropped non-ASCII bytes via
  `decode('ascii', errors='ignore')` and emitted `"99"` on the first
  byte being non-ASCII. Raw ALPN bytes are now preserved on
  `tls_info["alpn_raw"]`.
- **JA4H HTTP/2 + HTTP/3 version codes** (PR #288): `HTTP/2` now maps to
  `"20"` and `HTTP/3` to `"30"` in the JA4H part-A version code (not
  `"2"` / `"3"`). HTTP/1.0 / HTTP/1.1 unchanged.
- **JA4H cookie-VALUES sort by NAME only** (PR #288): the cookie-values
  hash component now sorts pairs explicitly by cookie name; previously
  relied on tuple-sort tie-breaking.
- **JA4SSH deterministic mode tiebreak** (PR #281): when multiple packet
  sizes tie for the highest frequency, the LOWEST value wins. Previously
  used `Counter.most_common(1)[0][0]`, whose result could vary based on
  insertion order.
- **JA4L UDP/QUIC server-first orderings**: the QUIC timing path no
  longer requires the connection's lexicographic direction to be
  `forward`. The first packet on the flow defines the client; subsequent
  packets are routed by comparing endpoints to that anchor.
- **JA4D skip set** matches the spec exactly: `{0, 53, 50, 81}`. The
  End marker (255) is handled by the parse loop and never recorded.

### Changed

- Bumped version to **0.6.0**.
- README updated to reflect 10 JA4+ methods and new APIs.

### Internal

- Per-DCID QUIC fragment buffer + reverse map for cleanup.
- New `ja4plus.utils.quic_utils._parse_alpn_with_bytes` returns both
  decoded strings and raw bytes for ALPN.
