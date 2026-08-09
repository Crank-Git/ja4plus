# Changelog

All notable changes to ja4plus are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **The README states eleven of the twelve FoxIO methods, the two contracts and the four
  default bounds** (#62). Round TBD. The README claimed "all ten JA4+ methods". FoxIO
  publishes twelve, and `technical_details/README.md:5-16` at the pinned commit lists
  JA4LS and JA4TScan as rows of their own. **The claim was false in two directions**: the
  project builds no JA4TScan, and it builds JA4LS, which the table never named. **The
  issue body and `docs/specs/features/08-documentation.md` each say ten of the twelve,
  and eleven is the number.** `JA4LFingerprinter` writes both `JA4L-C=` and `JA4L-S=`, so
  ten classes carry eleven methods, and the count of ten counts classes.
  `docs/specs/spec.md:42` already read eleven. The method table now holds twelve rows and
  an `Implemented` column, and JA4TScan alone reads `No`. **The README states the four
  default bounds in one table**: 10000 entries and 600 seconds for a state table, 10000
  connections and 300 seconds for the monitor. **The concurrency contract and the
  independent-implementation sentence were already present**, so two new cases record
  that rather than change prose. `tests/test_readme_contracts.py` holds fifteen case
  functions, and each reads its number out of `ja4plus/` instead of restating it. Four
  mutations prove them, and the mutation of `DEFAULT_MAX_CONNECTION_AGE` to 900 in the
  code is the one that proves the bound cases read the code. No file under `ja4plus/`
  changes and no fingerprint moves.

- **Four QUIC and certificate readers name the errors they expect, and ten wide catches
  state why they stay wide** (#319). Round 133. `grep -rn "except Exception" ja4plus/`
  reads 14 sites across five files. **#319 is a reading of all fourteen, and it narrows
  the four that `CLAUDE.md` binds.** A parser that cannot read a packet returns nothing,
  and it does not raise. `decrypt_quic_initial_crypto`, `decrypt_quic_server_initial_crypto`
  and `parse_quic_initial` of `ja4plus/utils/quic_utils.py` now name `IndexError`,
  `ValueError` and `InvalidTag`. `compute_ja4x_from_pem` of `ja4plus/__init__.py` now
  names `ValueError` and `x509.InvalidVersion`. **`InvalidTag` and `InvalidVersion` each
  inherit `Exception` and not `ValueError`**, so a list of `ValueError` alone drops a real
  packet and a real certificate. A fuzz of 90000 datagrams and a second fuzz of 40005
  decrypted payloads measured the set. A bound of 16384 bytes on the reassembled
  ClientHello proves that `struct.error` reaches no site. **The three sites of
  `ja4plus/processor.py` hand each failure to the caller, and #45 decided that.** The five
  sites of `ja4plus/cli.py` and the two of `ja4plus/ja4db.py` report a failure and return.
  Each of those ten now carries a comment that states the reason.

- **The QUIC frame reader returns the frames it read when a CRYPTO frame is truncated**
  (#382, absorbed by #319). Round 133. The CRYPTO branch of `parse_crypto_frames` read a
  varint behind the frame type byte and guarded no index. A plaintext that ends on that
  byte made `_decode_varint` raise `IndexError`. **Two of the three callers call that
  reader outside their handler**, so the error reached the caller of a parser, which
  `CLAUDE.md` rule 2 forbids. **The defect is remotely triggerable by construction**,
  because the Initial keys derive from the destination connection ID that the packet
  carries in the clear. The branch now holds the guard its own ACK branch already used.
  The defect predates #319, and the same datagram raises the same error against the base
  commit. **No fingerprint moves, and the conformance suite reports 134 xfailed against
  134 register keys.**

- **JA4L emits one server value for one connection, and the six open JA4L register
  entries now hold a live owner** (#272). Round 130. `ja4plus/fingerprinters/ja4l.py`
  returned the server value on every SYN-ACK, so a retransmitted SYN-ACK repeated the
  value the first SYN-ACK gave. A retransmitted SYN-ACK moves neither the server
  measurement point nor the server TTL, so the repeat described no second measurement.
  **`ssh2.pcapng` stream 15 is the one vector that reaches the rule**: the FoxIO Python
  file holds `JA4L-S=6252_58` once, and `ja4plus` produced it twice. A replay of the 38
  committed captures moved exactly one value, and it is that duplicate. No JA4L value
  moved on any other capture. **#272 declines five of the six entries instead of
  repairing them, because the comparison is unreachable and not satisfied.**
  `CVE-2018-6794.pcap`, `https-connect.pcap` and `tls-handshake.pcapng` publish no JA4L
  key at all, because `python/ja4.py:339` runs
  `delete_keys(['JA4L-S','JA4L-C'], final)` when the generating run names another
  method. This project was never emitting more than the reference. The reference
  published nothing to compare. `tests/foxio_deviations.json` falls from 135 keys to
  134, and the conformance suite falls from 135 `xfailed` to 134.
- **`ruff` enforces the F401 rule, and 54 unused imports are gone** (#297). Round 131.
  `pyproject.toml` no longer holds `F401` in the `ignore` list of `[tool.ruff.lint]`.
  **Every count the issue recorded is stale.** The issue read 58 findings across 28
  files on `issue/47-py-typed` at `ruff 0.14.5`, and this round reads **54 findings
  across 27 files** on `batch/362-hygiene-three` at `ruff 0.16.2`. The `ignore` comment
  recorded 82 I001 findings, the rule reports 76, and the comment now states 76.
  **`ruff --fix` decides no removal here, because an unused import is not always
  unused.** This round classified all 54 first, against five shapes: a side-effect
  import, a re-export, a `TYPE_CHECKING` import, a test helper, and a genuinely unused
  name. All 54 are genuinely unused. No consumer imports a flagged name from a flagged
  module, and no file that holds a finding declares `__all__` or a `TYPE_CHECKING`
  block. **No import statement under `ja4plus/` loses every name**, so every
  `scapy.all` line keeps `Packet` and no module-level side effect disappears. 15
  findings sit under `ja4plus/fingerprinters/` and `ja4plus/utils/`, and the
  conformance suite proves each removal inert: 1531 passed, 143 skipped and 135 xfailed
  before the change and after it, against 135 register keys. The unit suite reports
  2212 passed, 2 skipped, 8 xfailed and 96 subtests before and after. Coverage holds at
  93, and the missed line count stays at 287. **No fingerprint moves.**

- **The lookup cache remembers no key it evicts, and it saves 16.06 MiB** (#359).
  Round 129. `StateTable` remembers the key of every entry it evicts, and that memory
  buys `returned_connections`. `Processor.stats` collects the state tables of the
  fingerprinters, and `JA4DBClient` is no fingerprinter, so nothing under `ja4plus/`
  reads the count for the lookup cache. `BoundedStateTable` now takes
  `track_evictions`, it defaults to True, and every existing caller keeps the statistic
  it had. The lookup cache is the one caller that states False. **A full lookup cache of
  100000 entries falls from 47.06 MiB to 31.00 MiB under `tracemalloc`.** It falls
  from 44.66 MiB to 28.60 MiB under `sys.getsizeof`. The two methods agree on the saving to
  0.00 MiB. The eviction count stands, so FR-concurrency-safety-12 holds for this table,
  and the invariant `inserts == entries + evictions + removals` holds. **#279 measured
  the 512 MiB ceiling case without a lookup cache**, so this saving moves none of its
  four runs. No file under `ja4plus/fingerprinters/` changes, no fingerprint moves, and
  the register holds 135 keys against 135 xfailed. **A first form of the new cases
  turned the resident-memory control of #279 red**, because each one loaded the whole
  mapping file into the session. The cases now patch `load_mapping_file` to an empty
  mapping. A deselect run proves that the production change causes none of it.

### Fixed

- **Every entry of this file states the round its specification row states** (#302).
  Round 134. Eight entries read `Round TBD` while `docs/specs/spec.md` had already
  assigned their round. A reader who follows such an entry reaches nothing, and version
  1.0.0 is close. **Each entry names the round its row records, and this repair invents
  no number, adds no row and moves no number.** Three entries of Epic 4 name round 90,
  which is the Epic 4 shipment row and already records all three pieces of work in the
  words the entries use. #258 settled that shape, because a repair folds a detail into
  the shipment row and renumbers no row. The other five name rounds 122, 118, 122, 104
  and 102. **Each match reads what the two records state and not the issue number**,
  because #59 carries two entries against one round, and rounds 123 and 124 are the rival
  candidates and each is already taken, 123 by #364 and 124 by #368. **No prose of the
  eight entries changes**, and the eight lines differ by the round word alone.
  `tests/test_changelog_round_agreement.py` holds the invariant. **It bars no `TBD`.** A
  guard that barred the literal word would fail on every integration branch, because the
  batch model requires a member to write it and the project manager to assign the number
  at the batch gate. The guard instead compares the two files against each other, so the
  ten unassigned entries of this branch stay untouched. **Five of the eight orphans hid
  behind a defect in the guard itself.** The round pattern read a literal space, the file
  wraps at 90 columns, and `Round` therefore ends one line and `  TBD.` opens the next on
  five entries. The parser read 36 entries where 41 exist and skipped all five, so the
  guard reported green over the defect it exists to report. **A comparison that never
  runs reads as a comparison that passes**, and this project records that fault sixteen
  times. **The floor recorded the fault rather than the fault reporting the floor**: it
  read 36, which is the count the broken parser produced, so it could never fire. It now
  reads 41 from the corrected parser. Seven mutations prove the guard, and the two that
  wrap a round sentence are the pair the first five could not reach. No file under
  `ja4plus/` changes and no fingerprint moves.

- **The marker rule states the decided-entry count the register holds, and a case
  holds it there** (#345). Round 132. The `## The marker rule` section of
  `tests/foxio_deviations.py` read `38 of the 128 decided entries`. The register holds
  134 decided entries of 134 keys, measured on the base commit `f238c15`. **The
  denominator went stale twice**, because nothing measured it. #341 found the first
  drift at 129. #272 then removed one entry and decided five inside this batch. **The
  numerator of 38 was correct**, and the 38 are still the 34 entries of #138 and 4 of
  the 5 entries of #151. `TestTheMarkerRuleCounts` in `tests/test_foxio_deviations.py`
  now reads the two counts out of the prose and measures them against the register. The
  next move of the register therefore fails a case, where the count sat unmeasured in a
  docstring before. The case failed on the unchanged prose with `assert 128 == 134`.
  Three mutations prove that it fails when the register moves and the prose does not,
  and each run restored the file it moved. No register entry changed, no file under
  `ja4plus/` changed, and no fingerprint moved.
- **The `capability` field alone bars the rows of #129** (#347). Round 127.
  #341 shipped the field on all 135 register entries and reported that it could not
  prove the one thing it exists for. **The bar stood twice**: once in the field, and once
  in an absent measurement. #334 measured the 35 source values of #129 and left them out
  of `SOURCE_VALUES`, and `test_no_measured_row_records_a_capability_decline` asserted
  the exclusion. Flipping the field on a #129 entry therefore moved nothing, and no case
  failed. **This round measured the 35 rows against the pinned FoxIO checkout**
  `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` and put them in the table. It resolved every
  Wireshark frame number against its capture with `scapy` and read the 5-tuple, which is
  the method #334 recorded. **The reading corroborates itself**: all 16 Wireshark JA4H
  values and all 3 Wireshark JA4X values equal the FoxIO Python values at the same
  occurrence. Two of the 37 rows carry no source value, and they are
  `chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4X.1` and `JA4X.2`. Neither the
  Rust snapshot nor the Wireshark file holds a JA4X value for that capture.
  **The reach holds at 6 rows, and the measurement the field now permits reads 25.**
  With `capability` false on all 43 #129 entries, live on disk, the reach rises from 6 to
  25 and returns to 6 after the restore. On the base file the same flip reads 6 and 6.
  The 19 rows that enter are the 16 JA4H_ro rows and the 3 JA4X rows; the 16 JA4H rows
  stay out because the Rust value and the Wireshark value differ.
  `test_no_measured_row_records_a_capability_decline` is renamed to
  `test_every_measured_capability_row_names_the_issue_the_bar_exists_for`. The new name
  holds the one meaning the exclusion did not carry: a measured capability row names
  #129, and a row under another issue reaches a bar no measurement has read. No file
  under `ja4plus/` changes, no register entry changes, no fingerprint moves, and the
  register holds 135 keys against 135 xfailed.

- **Every Changelog round number of the specification names one row** (#258). Round 128.
  `docs/specs/spec.md` carried the number 9 on two rows, and a round number is a citation
  target. **The two rows are not two rounds.** One row records the shipment of Epic 1
  batch 1, and it names #80 as a member. The other row details #80 on the same date.
  **The repair folds the detail row into the shipment row, and it renumbers no row.** The
  fold preserves every sentence of the folded row. **A round number is an identifier, and
  it states no order.** The date column carries the order. Rounds 10 through 124 are all
  taken, so no free number sits beside the number 9. A renumber of the rows above it
  would break every citation of a round number. Those citations carry weight: round 67
  holds the #226 part e decision, and #215 and #226 cite it. **Three premises of the issue
  were stale, and this round measured all three again.** The ruling named `spec.md:542`
  and `:546`, and the rows were at 569 and 573. The ruling named 88 as the highest round,
  and the highest was 124. The ruling searched `[Rr]ound 9\b` and found no citation. That
  pattern misses the one citation that exists. Round 12 closed with "The rounds below hold
  two entries numbered 9". The fold makes that sentence false, so round 12 now records the
  repair. `tests/test_specification_changelog.py` holds the invariant. Both of its cases
  fail when the duplicate returns. No file under `ja4plus/` changes, no fingerprint moves,
  and the register holds 135 keys against 135 xfailed.

- **The example that a merge restored is absent again** (#368). Round 124.
  #56 removed `examples/monitoring_daemon.py` and added
  `tests/test_watch_capture.py::TheExampleDaemonIsAbsent`, which asserts that the file
  stays absent. `batch/322-hygiene-two` forked from `dev` before that case landed, so
  its own run never collected the case, and its merge `8b87c20` restored the file. **Both
  parents of the merge were green and the merged tree was not**, because the file and the
  case live in different directories. `dev` then ran red across `35bdfab` and `8ef8acc`.
  The case
  fails on the base commit `8ef8acc` and passes after the removal. `ja4plus watch` is
  the supported monitor, and `docs/usage.md` documents it. No file under `ja4plus/`
  changes, no fingerprint moves, and the register holds 135 keys against 135 xfailed.
- **The statistics interval cases state the schedule rather than sample it** (#369).
  Round 125. `TheReporterWritesOneLinePerInterval` started the reporter at a 0.05 second
  interval, slept a fraction of a second, and counted the lines that arrived. That count
  measures how promptly the host schedules a thread. The `macos-latest, 3.12` job of the
  run for `8ef8acc` read 2 lines where the case asked for 3, and `dev` went red on a
  package that holds no defect. `StatisticsReporter` gains a `wait` parameter, which
  receives the interval and returns True when the stop arrives. The default waits on the
  stop event, and `ja4plus watch` passes no other call, so the shipped behaviour is
  unchanged. Each case now drives the reporter from a scripted wait and reads an exact
  line count. The class asserts the interval the reporter passed to the wait, which is
  what FR-live-capture-9 states, and it sleeps not at all.

- **The Zeek reference page reads the current comparison** (#327). Round 113.
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
  Round 112. `tests/compare_zeek_baselines.py` read the composite `source` field that
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

- **The package states a memory ceiling of 512 MiB** (#279). Round 126. One
  `Processor()` at the shipped defaults reads 1000000 packets across 100000 distinct
  connections and holds resident memory below 512 MiB. Four runs measured 383.47 MiB,
  388.25 MiB, 392.05 MiB and 394.94 MiB, and the highest is 77 percent of the ceiling.
  `README.md` and `docs/api_reference.md` each carried the sentence "This package states
  no memory ceiling", and each now states the number, the defaults the ceiling holds at,
  and the boundary of the claim.
  `docs/specs/features/03-concurrency-safety.md` states the whole measurement. **The
  ceiling covers that packet run and no longer run.** Each fingerprinter keeps every
  fingerprint it produces and that list holds no bound, so resident memory keeps rising
  after every state table settles, at about 23 MiB for each 100000 packets. The same
  traffic passes 512 MiB at 1500000 packets, where it reads 513.06 MiB. New file
  `tests/memory_ceiling_run.py` measures one packet run in an interpreter of its own,
  because `resource.getrusage(RUSAGE_SELF).ru_maxrss` reports the high-water mark of the
  whole process. No file under `ja4plus/` changes and no fingerprint moves.
  **The two controls beside the ceiling now read the current resident set, because two
  high-water marks subtract to no growth.** A mark rises and never falls, so the
  difference between two of them states `max(0, later mark - earlier mark)`. The import
  of scapy reaches a mark on Ubuntu that the traffic run then stays below, and the four
  Ubuntu jobs of pull request #384 read `idle_mib 154.7` and `peak_mib 154.7` for a run
  that allocated tens of MiB. The ceiling itself is a claim about the mark and it stands
  unchanged, and the run now also reports `idle_resident_mib` and `final_resident_mib`
  from `/proc/self/statm`, or from `ps` on Darwin. `traffic_growth_mib` refuses a
  high-water pair as a void measurement, and `TestTheGrowthReading` measures that refusal
  against the Ubuntu numbers on every platform.

- **The documentation states what a fingerprint is evidence of** (#343). Round 110.
  ja4plus adds no plausibility guard, so a structurally valid ClientHello produces a
  fingerprint whatever its body holds. This change records the behaviour and changes
  none of it, so no file under `ja4plus/` moves. A fingerprint is evidence of the bytes
  the packet carried, and it is no evidence of a real client. `README.md` and
  `docs/output-schema.md` now
  state the property where a user reads it, and the `Divergence register` of
  `docs/specs/spec.md` holds the measurement.
- **The register records the kind of every decline** (#341). Round 116.
  `tests/foxio_deviations.json` carries a `capability` field on all 135 entries, and
  `CAPABILITY_DECLINES` is gone from `tests/test_precedence_exception.py`. #334 shipped
  bar 1 of the precedence exception as a constant set of issue numbers, so a new
  capability decline would have reached the exception unless somebody edited a test that
  named it nowhere near the decline. **`true` records a capability this project chose not
  to build, and `false` records a disagreement about the value.** `tests/foxio_deviations.py`
  reads the field beside `decided` and states the default in the schema, and
  `unrecorded_kinds` requires the field on every decided entry. **43 entries record a
  capability decline, and all 43 name #129**, which the recorded cause of each of the 135
  entries decides. No entry was undeterminable. **The reach of the exception is 6 rows
  before and after**, and the six rows are unchanged. No fingerprint moves, no file under
  `ja4plus/` changes, and no vector is adopted.

- **The precedence exception is source-neutral** (#334). Round 115.
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

- **A declined FoxIO Python value forfeits its precedence** (#332). Round 114.
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

- **The vocabulary settles one word for the serialized output line** (#306). Round 111.
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
### Added

- **A `LookupResult` supports item access by field name** (#364). Round 123. Version
  0.6.0 returned a dict with the keys `application`, `type` and `notes`, and #59 replaced
  it with a frozen `LookupResult`. A caller that reads `result["application"]` keeps
  working for one major version, and that read emits a `DeprecationWarning` that names
  the attribute to read instead. Every key version 0.6.0 published names a field of
  `LookupResult`, so no key returns the value of another field. A key that names no field
  raises `KeyError` and emits no warning. Item access reads a field and writes none, so
  a `LookupResult` stays frozen. `FingerprintResult` holds the same behaviour from #44,
  under `FR-typed-api-5` and `FR-typed-api-6`.

- **`JA4DBClient.lookup_many` identifies many fingerprints in one call** (#59). Round
  122. It accepts a sequence of fingerprints and returns one entry per fingerprint. A
  miss holds `None`, so a caller reads one entry for every fingerprint it passed. The
  returned mapping keys the fingerprint, so a sequence that repeats a fingerprint holds
  one entry for it. The call reaches the lookup service under the rule that `lookup`
  holds, and under no other rule. A client built with `allow_remote=False` sends nothing,
  whatever count of fingerprints the call carries. A client built with
  `allow_remote=True` sends one request for each fingerprint the mapping file holds no
  entry for. The lookup cache holds a miss as well as a hit, so a repeated fingerprint
  costs one request and no more.

- **`--lookup-remote` and `JA4PLUS_DB_LOOKUP` ask for the remote lookup** (#58). Round
  118. `--lookup` reads the bundled mapping file and makes no network request.
  `--lookup-remote` identifies each fingerprint, and it sends every fingerprint the
  mapping file holds no entry for to `https://ja4db.com`. It asks for the lookup as well
  as for the disclosure, so an operator who passes it needs no `--lookup`.
  `JA4PLUS_DB_LOOKUP=1` permits the same request, for an operator who runs a command line
  another program builds. The variable permits the request on the value `1` and on no
  other value, and it asks for no lookup. The option and the variable each permit the
  request, and neither one refuses it, so `JA4PLUS_DB_LOOKUP=0` cancels no option. The
  command writes one notice to standard error for each run that permits the remote
  lookup. The notice names the lookup service and the two ways to stop the request, and
  it appears once whatever count of fingerprints the run looks up. Where the operator
  asks for the remote lookup and the `requests` package is absent, the command names the
  `lookup` extra and ends the run with the status 1.

### Changed

- **A lookup result is a frozen `LookupResult` and it records its source** (#59). Round
  122. Through version 0.6.0 `JA4DBClient.lookup` returned a dict with the keys
  `application`, `type` and `notes`. It now returns a frozen `LookupResult` that carries
  the same three fields plus `source`, so a caller reads `result.application` where it
  read `result["application"]` before. `LookupResult` of `lookup.go:23` carries the three
  fields, and `CLAUDE.md` parity rule 2 adopts them. The `source` field holds `embedded`
  for the mapping file that ships inside the package, `cache` for the file that
  `ja4plus db update` wrote to the cache directory, and `remote` for the lookup service.
  An analyst needs to know where a name came from to judge how much to trust it. The
  command-line output schema is unchanged, because the command writes the application
  name alone.

- **`ja4plus db update` writes to the cache directory, and the client prefers that file**
  (#61). Round 121. Through version 0.6.0 `db update` wrote the download over
  `ja4plus/data/ja4plus-mapping.csv` inside the installed package. That directory may be
  read-only, several users may share it, and the next `pip install` discards the file.
  `db update` now writes `ja4plus-mapping.csv` to the platform cache directory:
  `$XDG_CACHE_HOME/ja4plus` or `~/.cache/ja4plus` on Linux, and
  `~/Library/Caches/ja4plus` on macOS. It writes a temporary file and renames it, so a
  reader sees the whole new file or the file the last run wrote. It leaves the installed
  package byte for byte as it was. `JA4DBClient` and `ja4plus db info` now read the
  cached mapping file when one exists, and the bundled mapping file otherwise. A cache
  file that is empty, corrupt or unreadable falls back to the bundled file, and the
  client reports the problem at `WARNING`. `db info` reports the source on its first
  line, as `embedded` or `cache`, and it names the mapping file path on the second. The Go
  port publishes the value `embedded` for the file that ships inside the package, at
  `lookup.go:31`, and `CLAUDE.md` parity rule 2 adopts it. The prose of this project still
  calls that file the bundled mapping file. `db info` wrote the FoxIO address on a line
  named `Source` through version 0.6.0, and that line is now named `Mapping`. Where the
  source is `embedded`, `db info` names the cache file as well. It reports that the cache
  file holds no entry, or that no cache file exists.

- **The remote lookup is opt-in at the client** (#57). Round 117. Through version 0.6.0
  `JA4DBClient.lookup` sent every fingerprint the bundled mapping file held no entry for
  to `https://ja4db.com`, and no caller asked for that. A fingerprint describes traffic
  the operator observed, so each request told a third party what the operator watched.
  `JA4DBClient()` now performs no network request. `JA4DBClient(allow_remote=True)`
  permits one request per miss, and it is the only way to reach the service.
  `ja4plus --lookup analyze` and `ja4plus.ja4db.lookup` both hold the new default, so
  the command-line program makes no network request. #58 adds the command-line option
  that permits the remote lookup. The remote lookup waits 5 seconds at most, and
  version 1.0.0 is the first release that may make the interval configurable. A request
  that fails returns None and raises nothing. The lookup service publishes no versioned
  API document, so the client accepts one shape: an object that carries a non-empty
  `application` string. Version 0.6.0 read an object without that field as the
  application `Unknown`, and the client now reads it as a miss. `allow_remote` is the
  first parameter of the constructor, where `cache_size` was, so `JA4DBClient(100)` now
  raises `TypeError`. Write `JA4DBClient(cache_size=100)` instead. The client also
  escapes the fingerprint it puts in the request path, so a string that carries `/` or
  `?` names no other path on the lookup service.

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

- **`Processor.process_packet` returns a list of `FingerprintResult`** (#45). Round 90.
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

- **`ja4plus watch` stops on an interface that carries no traffic** (#320). Round 105.
  A monitor on a quiet interface exits within one second of `SIGINT` or of `SIGTERM`.
  `scapy` applies the `stop_filter` argument of `sniff` to a packet and to nothing else,
  and its capture loop waits in `select` without an end, so the monitor read the stop
  flag when the next packet arrived and not when the signal arrived. An operator who ran
  `systemctl stop` on such a monitor waited for the service timeout, and the host then
  sent `SIGKILL`, which skips the flush. The command now opens the capture socket itself
  and calls `sniff` with `opened_socket` and a timeout of 0.25 seconds, in a loop, and it
  reads the stop flag after each call. The socket stays open across the calls, so the
  monitor loses no packet that arrives between two of them. `--bpf` still applies, and
  `libpcap` now compiles the expression when the socket opens. The command still starts
  no thread other than the one `--stats-interval` starts.

- **`ja4plus watch` applies a capture filter and reads the capture failure** (#56). Round
  104. `--bpf FILTER` passes a Berkeley Packet Filter expression to the capture layer,
  which drops every packet the filter rejects. The command reads no user identity. It
  attempts the capture and reads the failure, so a Linux host that grants `CAP_NET_RAW`
  without granting the user identity zero runs the monitor. Version 0.6.0 read
  `os.geteuid() != 0`, which refused that operator and raised `AttributeError` on
  Windows, where `os.geteuid` is absent. The command now names `CAP_NET_RAW` and the
  `/dev/bpf*` devices for a refused privilege, lists every interface the host holds for
  an interface it does not hold, and repeats the filter error for an expression the
  capture layer refuses. Each of the three ends the run with the status 1. The command
  runs on Linux and on macOS, and it reports that Windows carries no monitor and ends
  the run with the status 1. `examples/monitoring_daemon.py` is removed, because
  `ja4plus watch` is the supported monitor and `docs/usage.md` documents it.

- **`ja4plus watch` reports statistics on exit and on a schedule** (#55). Round 103. The
  monitor writes one statistics line when it exits, and `--stats-interval SECONDS` adds
  a line for each interval that passes. Every line goes to standard error, so a pipe
  that reads standard output reads fingerprints alone. The line reports the packet
  count, the fingerprint count, the connection count, the eviction count, the
  dropped-packet count and the uptime. `MonitorStats` holds the four counts under one
  lock, and the capture thread publishes the two table counts, so the statistics thread
  reads no state table. The statistics thread is the only thread the command starts, and
  the command starts it only when the operator passes `--stats-interval`. The thread
  ends with the capture, so a termination signal stops the monitor and the thread
  together. The `dropped` field reads `null`, because `scapy` 2.7.0 reports no drop
  count to a caller of `sniff`; #326 records the measurement and the work that reports a
  count. The fingerprint count holds the trailing JA4SSH window that a capture leaves
  open, which the command writes and #214 decided.

- **`ja4plus watch` stops on a termination signal and flushes its output** (#54). Round
  102. `SIGINT` and `SIGTERM` both stop the monitor, and both end the run with the
  status zero. The handler sets a flag and returns. It calls `sys.exit` never, because a
  signal arrives at any point, including the point where the output holds half a line.
  `scapy` reads the flag through the `stop_filter` argument of `sniff`, and it applies
  that filter after it reports a packet, so the monitor finishes the line it writes. The
  command then flushes the output and exits, so the output file holds every fingerprint
  the monitor reported. The command flushed the output only when it wrote a result, so a
  monitor that produced no fingerprint left its header in the buffer. `scapy` applies the
  filter on packet arrival alone, so an interface that carries no traffic reached that
  filter never; the entry for #320 records the loop that repairs it.

- **`ja4plus watch <interface>` reads an interface and bounds its connection table**
  (#53). Round 101. `ja4plus live` stays as an alias of it, so a version 0.6.0 script
  keeps working. The command owns the connection table, and that table holds a maximum
  entry count and a maximum age. `--max-connections COUNT` sets the entry count, and it
  defaults to 10000. `--connection-timeout SECONDS` sets the age, and it defaults to
  300. When the table is full, the monitor evicts the least recently used connection.
  When a connection sends no packet for the stated age of capture time, the monitor
  evicts it too. Each eviction calls `Processor.cleanup_connection`, so it drops the
  entry of the connection table and the per-connection state of all ten methods
  together. Version 0.6.0 called `cleanup_connection` never, so its live capture held
  the state of every connection it ever read and a monitor on a busy interface grew
  until the host stopped it. Eviction runs on packet arrival, and the command starts no
  thread for it. One million packets across 50000 connections leave the monitor holding
  10000 connections and 7.20 MiB.

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

- **The package ships the `py.typed` marker and declares `__all__`** (#47). Round 90.
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
  Round 90. `process_packet` logs a fingerprinter error at DEBUG and returns the
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

- **The two handlers of the X.509 byte reader name the errors they expect** (#316).
  Round 100. `extract_certificate_from_bytes` wrote `except Exception` twice, once
  around the ASN.1 parse and once around the whole function body. #294 narrowed
  neither, because it targeted the `(ValueError, TypeError, Exception)` form. The inner
  list now names `ValueError` and `InvalidVersion`. The `cryptography` documentation
  states `ValueError` alone, and a measurement of malformed candidates raised
  `InvalidVersion` as well, which inherits `Exception` and not `ValueError`. The outer
  list names `TypeError`, which `len()` raises for input that is no sequence. **The
  reader still returns nothing and raises nothing for hostile input**: 13680 calls over
  empty, truncated, textual, damaged and random data raised no error. **A defect of
  this project now reaches a reader**, where the wide catch returned nothing. **No
  fingerprint moves**: the conformance suite reports 1531 passed, 143 skipped and 135
  xfailed before the change and after it. `tests/test_x509_certificate_reader.py` holds
  16 cases, and one of the 12 new cases failed against the base.

- **`extract_certificate_info` reads the module `x509`** (#309). Round 98.
  `x509_utils.py:262` and `x509_utils.py:263` imported `x509` and `default_backend`
  inside one branch, which made both names locals of the whole function. The parse at
  `x509_utils.py:285` therefore raised `UnboundLocalError` for every packet whose
  payload carried a certificate the reader found, and the wide handler below it returned
  nothing. The module imports both names already, so the branch-local import bought
  nothing, and this release removes it. **No caller inside `ja4plus/` calls the
  function**, so no fingerprint moves: the conformance suite reports 1531 passed, 143
  skipped and 135 xfailed before the change and after it.
  `tests/test_x509_certificate_info.py` holds three cases, and one of them failed
  against the base.

- **The three X.509 handlers name the errors they expect** (#294). Round 97.
  `ja4x.py:460`, `ja4x.py:490` and `x509_utils.py:267` each wrote
  `except (ValueError, TypeError, Exception) as e:`. `Exception` is a superclass of the
  other two names, so each handler caught every error while it read as a narrow catch.
  `CLAUDE.md` states that a fingerprinter catches the parse errors it expects and catches
  no bare `Exception`. The three lists now name the errors the `cryptography`
  documentation states for the calls inside them: `ValueError` for
  `load_der_x509_certificate`, `DuplicateExtension` and `UnsupportedGeneralNameType` for
  `Certificate.extensions`, and `InvalidVersion` for `Certificate.version`.
  `read_certificate` keeps `TypeError`, because `bytes()` raises it for input that is no
  byte string. **A defect of this project now reaches a reader**, where the wide catch
  logged it and returned nothing. **No fingerprint moves**: the conformance suite reports
  1531 passed, 143 skipped and 135 xfailed before the change and after it.
  `tests/test_ja4x_named_exceptions.py` holds 18 cases, and three of them failed against
  the base.

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

- **Four X.509 helpers leave `ja4plus/utils/x509_utils.py`** (#314). Round 99. The
  user decided on 2026-08-08 that `extract_certificate_info` leaves the package before
  version 1.0.0, together with the sibling helpers no caller uses. The four are
  `extract_certificate_info`, `get_certificate_issuer`, `get_certificate_subject` and
  `get_name_attribute`. `__all__` named none of the four, and a grep of `ja4plus/`,
  `tests/`, `examples/` and `docs/` found no caller for any of them. `__all__` still
  names 25 entries. `docs/api_reference.md` documented `extract_certificate_info` alone
  of the four, and that row is gone. **Two plain `except Exception` handlers leave with
  the function**, which #294 narrowed neither, because each wrote the plain form rather
  than the deceptive form. **No fingerprint moves**: the conformance suite reports 1531
  passed, 143 skipped and 135 xfailed before the change and after it.
  `tests/test_x509_certificate_info.py` is now
  `tests/test_x509_certificate_reader.py`, because it measures
  `extract_certificate_from_bytes`, the reader that stays.

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
