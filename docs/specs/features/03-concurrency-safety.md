---
id: concurrency-safety
feature: Concurrency and resource safety
epic: "Epic 3: Concurrency and resource safety"
status: issued
issues: [14, 38, 39, 40, 41, 42, 43]
mockups: []
---

## Purpose

The library held no lock anywhere. Every stateful fingerprinter holds a mutable
state table, and the processor drives ten of them. `Processor.get_shard_key` exists
so that a caller can spread traffic across workers, which tells the reader that
concurrency is expected. Nothing stated what is safe. #42 guarded the lookup client and
#40 gave every fingerprinter one lock, so the section below states what the code holds.

Every state table also grew without limit. `cleanup_connection` exists, but the
caller must call it, and a caller who does not know it exists runs out of memory. #38
built `BoundedStateTable` and #39 moved every fingerprinter table onto it, so the
section below states what each table holds today.

This feature set states the contract, proves it with tests, and bounds every table.

## User stories

- As a library integrator, I want to read one sentence that tells me whether I can
  share a processor between threads, so that I do not have to read the source.
- As a monitor operator, I want memory to stay flat over a day, so that my monitor
  does not need a restart.
- As a library integrator running one processor per shard, I want a way to switch
  the locking off, so that I do not pay for a lock I do not need.

## Functional requirements

FR-concurrency-safety-1 — `Processor.__init__` accepts a `thread_safe` argument.

FR-concurrency-safety-2 — The `thread_safe` argument defaults to `True`.

FR-concurrency-safety-3 — When `thread_safe` is `True`, two threads may call
`process_packet` on one processor at the same time.

FR-concurrency-safety-4 — When `thread_safe` is `True`, a call to `reset` does not
corrupt a state table that another thread is reading.

FR-concurrency-safety-5 — When `thread_safe` is `False`, the processor acquires no
lock.

FR-concurrency-safety-6 — The processor passes its `thread_safe` value to every
fingerprinter it builds.

FR-concurrency-safety-7 — Every state table holds no more than a maximum entry
count.

FR-concurrency-safety-8 — Every state table evicts an entry that has not been read
for longer than a maximum age.

FR-concurrency-safety-9 — The maximum entry count and the maximum age are
constructor arguments.

FR-concurrency-safety-10 — A state table evicts the least recently used entry when
it reaches its maximum entry count.

FR-concurrency-safety-11 — The processor reports how many entries each state table
holds.

FR-concurrency-safety-12 — The processor reports how many entries it evicted.

FR-concurrency-safety-13 — The module-level `lookup` function builds its client
once, and two threads that call it at the same time receive one client.

FR-concurrency-safety-14 — The lookup cache holds no more than a maximum entry
count.

FR-concurrency-safety-15 — The documentation states the concurrency contract.

## User flows

**An integrator shares one processor between threads.**

1. The integrator builds `Processor()`.
2. Four threads call `process_packet` on that processor.
3. Each call acquires the lock, updates state, and releases the lock.
4. Every fingerprint is correct, and no state table is corrupt.

**An integrator shards traffic across processes.**

1. The integrator builds `Processor(thread_safe=False)` in each worker process.
2. The integrator calls `get_shard_key` on each packet.
3. The integrator routes the packet to the worker that owns that key.
4. No worker acquires a lock.

**A monitor runs for a day.**

1. The monitor feeds packets continuously.
2. A connection stops sending.
3. After the maximum age passes, the next eviction pass removes its entry.
4. Memory stays flat.

## Screens & states

This feature set has no screen. The processor reports its own statistics.

| State | What the operator sees |
|---|---|
| Normal | Each state table reports an entry count below its maximum. |
| At capacity | A state table reports an entry count equal to its maximum, and a rising eviction count. |
| Idle | Entry counts fall to zero after the maximum age passes. |

## Behaviour rules

- The lock is one lock per fingerprinter, not one global lock. Ten fingerprinters
  that hold ten locks let ten threads work at once on different methods.
- The lock is a `threading.RLock`, because a fingerprinter may call its own method
  that also locks.
- Eviction runs on packet arrival, not on a timer. The library starts no thread.
- Eviction by age uses the packet timestamp when the packet carries one, and the
  wall clock otherwise. A capture file replays faster than real time, and a wall
  clock would evict entries that the capture still needs.
- The default maximum age is 600 seconds. A measurement sets it. The longest gap
  between two segments of one connection across `tests/foxio_vectors/` is
  320.714503 seconds. It sits in `ssh-r.pcap`, on the connection between
  `192.168.1.169:64980` and `192.168.1.197:22`. A second reading over every packet
  of that connection, rather than the segments that carry payload, is 320.336760
  seconds. Both readings are above 300.
- `TCPStreamReassembler` keys a stream by direction, and `add_segment` refuses a
  segment that carries no payload. The 320.714503 reading uses both conditions, so it
  is the reading that governs the default.
- The value 300 stood in this file until #170 measured the vectors. Nothing breaks at
  300 either, because the one connection above 300 seconds carries SSH traffic, and
  JA4H and JA4X read nothing from it. No comparison ever read the number, so the wrong
  value survived. #179 corrects it.
- The default maximum entry count is 10000 per state table. #39 holds every table that
  needs no smaller count at that number.
- An age pass runs at most once per 1000 packets, so that the eviction cost stays
  proportional to the traffic. A table whose maximum age sits below the default runs one
  pass on each packet, because a pass that waits longer than the age evicts nothing.
- `thread_safe=False` is a promise the caller makes, not a mode the library checks.
  The documentation states that a caller who breaks the promise gets undefined
  results.
- `cleanup_connection` stays. It is the caller's way to evict early, and the port
  has the same method.

## State bounds the code holds today

The table below records what the code holds, so that a reader does not read a target as
a description. #179 measured the first form against the code. #39 re-measured it, moved
every fingerprinter table onto `BoundedStateTable`, and wrote this form.

| State table | Maximum entry count | Maximum age | Packets between two age passes |
|---|---|---|---|
| `TCPStreamReassembler.streams`, built by JA4H | 100 | 600 seconds | 1 |
| `TCPStreamReassembler.streams`, built by JA4X | 50 | 600 seconds | 1 |
| `JA4Fingerprinter._quic_fragments` | 1000 | 30 seconds | 1 |
| `JA4Fingerprinter._quic_dcid_to_tuple` | 1000 | 30 seconds | 1 |
| `JA4SFingerprinter._quic_server_crypto` | 1000 | 30 seconds | 1 |
| `JA4SFingerprinter._quic_dcids` | 10000 | 600 seconds | 1000 |
| `JA4HFingerprinter.consumed_seq` | 100 | 600 seconds | 1 |
| `JA4HFingerprinter.unusable_base` | 100 | 600 seconds | 1000 |
| `JA4LFingerprinter.connections` | 10000 | 600 seconds | 1000 |
| `JA4LFingerprinter.grouping_keys` | 10000 | 600 seconds | 1000 |
| `JA4XFingerprinter.processed_certs` | 1000 | 600 seconds | 1000 |
| `JA4XFingerprinter.scan_offsets` | 50 | 600 seconds | 1000 |
| `JA4SSHFingerprinter.connections` | 10000 | 600 seconds | 1000 |
| `JA4SSHFingerprinter._handshake_clients` | 1000 | 600 seconds | 1000 |
| `SynAckTracker.times`, held by JA4TS | 1000 | 120 seconds | 1 |
| `SynAckTracker.prefixes`, held by JA4TS | 1000 | 120 seconds | none |
| `JA4DBClient._cache`, held by the lookup client | 100000 | 600 seconds | 100000 reads |
| `BaseFingerprinter.fingerprints` | none | none | none |

`TCPStreamReassembler` carries two more per-stream bounds: `max_stream_bytes` is
1048576, and `max_stream_segments` is 4096.

Every row other than the first two and `BaseFingerprinter.fingerprints` is a
`BoundedStateTable`. #39 moved thirteen tables, and it removed two companion tables,
`_quic_fragment_seen` and `_quic_server_crypto_seen`, because the state table holds the
age of each entry. #42 moved `JA4DBClient._cache`, which reads no packet, so its age
pass counts reads rather than packets. #285 moved `SynAckTracker.prefixes`, the
fourteenth, which #246 added while Epic 3 was live.

`SynAckTracker.prefixes` runs no age pass of its own, and the table above states no
eviction interval for it. `SynAckTracker.times` holds the eviction hook that
`BoundedStateTable` publishes, and that hook removes from `prefixes` the key `times`
evicted. The two tables therefore hold the same keys, and the RST value of #246 reads a
prefix for every connection `times` holds. Both bounds of `prefixes` are a second limit
that the hook keeps the table away from.

`TCPStreamReassembler.streams` stays an `OrderedDict`. It holds both bounds already, and
`add_segment` applies two more per-stream caps that no mapping models. #39 records the
decision and changes no behaviour of that class.

The `JA4HFingerprinter` tables and `JA4XFingerprinter.scan_offsets` read
`TCPStreamReassembler.max_streams` and `max_stream_age` of the reassembler that
fingerprinter holds, so one number bounds the stream and the state that describes it.

A table whose age is below the default runs one age pass on each packet. A pass that
waits for 1000 packets is longer than a 30-second age on a connection that sends few
packets, so that pass evicts nothing. `JA4HFingerprinter.consumed_seq` runs one pass on
each packet too, because the base code ran that pass on each packet. Each of the five
holds 1000 entries at most, so the cost of the pass stays flat.

`BaseFingerprinter.fingerprints` holds one result per fingerprint, not per-connection
data, so the `## Terms` table does not name it a state table. It appears above because
it grows without a limit, and Goal 3 covers it.

#41 landed the statistics, and this section records what the code holds now.

- `Processor.stats` returns a dict that maps each of the ten fingerprinter names to one
  `ProcessorStats`. `ProcessorStats` is a plain object; Epic 4 makes it a typed
  dataclass.
- `ProcessorStats` states the packet count of the method and one `TableStats` for each
  state table the method holds. It also states the sum of the entry counts, the sum of
  the eviction counts and the sum of the returned connections.
- `TableStats` states six counts: `entries`, `max_entries`, `inserts`, `evictions`,
  `removals` and `returned_connections`. The six hold the invariant
  `inserts == entries + evictions + removals`.
- **The report covers sixteen state tables, and not thirteen.** Round 82 counted the
  thirteen `BoundedStateTable` instances. `JA4HFingerprinter.reassembler` and
  `JA4XFingerprinter.reassembler` each hold per-connection data across packets, so the
  `## Terms` table names each one a state table too. `TCPStreamReassembler` therefore
  inherits `StateTable` and counts the same six things. Round 87 adds the sixteenth,
  `SynAckTracker.prefixes`.
- `StateTable` is the base class both hold. `BaseFingerprinter.state_tables` finds a
  state table by that type, so a new table reaches the report with no further change.
  The search descends one level, which reaches `SynAckTracker.times` and
  `SynAckTracker.prefixes`.
- A returned connection is a connection the table evicted and then saw again. The table
  remembers the keys it evicted, and it bounds that memory at its own entry count. A
  key the caller removed leaves no memory, so a connection that returns after
  `cleanup_connection` counts as a first sighting. The sixteen tables hold 47400
  remembered keys between them, at 187 bytes for one key, so the memory costs 8.5 MiB
  at its worst.
- `Processor.stats` holds the lock of one fingerprinter across the read of that
  fingerprinter, because the counts of one method describe one instant. It acquires one
  lock at a time and holds two never.
- The report describes ten instants and not one. A caller that needs one instant across
  the ten fingerprinters stops the packet source first.
- `Processor.reset` returns every packet count to zero, because a reset drops the state
  tables that the counts describe.
- `max_connections` and `max_connection_age` stay targets on `Processor.__init__`.

#40 landed the lock, and this section records what the code holds now.

- `Processor.__init__` accepts `thread_safe`, and it defaults to True. The
  `max_connections` and `max_connection_age` arguments stay targets.
- Every fingerprinter holds one lock. `BaseFingerprinter.__init__` builds a
  `threading.RLock` when `thread_safe` is True, and it holds the shared `NULL_LOCK`
  when `thread_safe` is False. Ten fingerprinters hold ten locks.
- The lock is reentrant, because `Processor.process_packet` holds the lock of one
  fingerprinter and then calls `process_packet` on that fingerprinter, which holds it
  again. A `threading.Lock` deadlocks on the first packet.
- The processor holds the lock of one fingerprinter across the call and across the read
  of `last_raw` that follows it. The raw form describes the value the call produced, so
  a second thread that runs between the two pairs one fingerprint with the raw form of
  another packet.
- `BaseFingerprinter.add_fingerprint`, `get_fingerprints` and `reset` hold no lock.
  `list.append` and the rebind each run as one operation, and every composite operation
  over that list sits in a subclass method or in `Processor.process_packet`. A lock on
  the three failed no run of `tests/test_thread_safety.py` out of 20 with it removed.
- `SynAckTracker` holds no lock. Every caller of it runs inside a method of
  `JA4TSFingerprinter`, and that method holds the lock of that fingerprinter.
- The lock of a fingerprinter and the module lock of `ja4plus/ja4db.py` never meet. No
  fingerprinter calls `ja4plus.ja4db.lookup`, so no thread holds one while it waits for
  the other, and the two cannot deadlock.

#42 built the lookup client, and this paragraph records what the code holds now.
`ja4plus.ja4db.lookup` builds one client, and every thread that calls it receives
that client. The lookup cache holds 100000 entries at most, and
`features/07-db-enrichment.md` states that entry count. The `## Terms` table names
the lookup cache no state table, so the 10000 above describes a different object. The
lookup cache is a `BoundedStateTable`, and one lookup drives its age pass.

**The lookup cache remembers no evicted key, and #359 decided it.** `StateTable`
remembers the key of every entry it evicts, and that memory buys `returned_connections`.
`Processor.stats` collects the state tables of the fingerprinters, and `JA4DBClient` is
no fingerprinter, so no reader reads the count for this table. `BoundedStateTable` now
takes `track_evictions`, it defaults to True, and the lookup cache is the one caller that
states False. **The saving is 16.06 MiB, and two methods agree on it to 0.00 MiB.** A
full lookup cache of 100000 entries falls from 47.06 MiB to 31.00 MiB under
`tracemalloc`, and from 44.66 MiB to 28.60 MiB under `sys.getsizeof`. The eviction count
stands, so FR-concurrency-safety-12 holds for this table. **#279 measured the ceiling
case without a lookup cache**, so this saving moves no number of the four runs below. It
moves the worst case of a program that runs a monitor and a full lookup cache
together. That worst case falls from 442.00 MiB to 425.94 MiB, against the 512 MiB
ceiling.

## The concurrency contract, as #43 measured it

#43 states the contract and it re-measured every premise it rests on.
`tests/test_thread_safety.py` and `tests/test_memory_bounds.py` hold the cases, and
`README.md` and `docs/api_reference.md` hold the prose. This section records the
measurement, because the prose states the result and not the reading.

**The contract has three clauses.**

1. A caller that gives each thread whole connections reads the value set one thread
   reads. `Processor.get_shard_key` returns the key that arrangement routes on.
2. A caller that splits the packets of one connection across threads gets undefined
   results.
3. A caller feeds one processor the packets of one timeline.

**Clause 1 holds on every capture measured.** Eight threads that route on
`get_shard_key` match one thread on 3 of 3 runs for each of `latest.pcapng`,
`ssh2.pcapng`, `browsers-x509.pcapng`, `http1.pcapng` and `tls-sni.pcapng`. #40 read the
same result, and this reading reproduces it.

**#40 read the fourth premise wrongly, and #43 disproves it.** Round 84 records that
eight threads over five concatenated captures differ from one thread on 4 of 5 runs, and
it names the entry count bound as the cause. A re-measurement reads 5 of 5, and it names
a different cause. Four readings separate the two bounds over the same 2047 packets.

| Reading | Runs that differ |
|---|---|
| Both bounds as shipped | 5 of 5 |
| The entry count bound raised, the age bound as shipped | 4 of 5 |
| The age bound raised, the entry count bound as shipped | 0 of 5 |
| Both bounds raised | 0 of 5 |

**The age bound alone causes it, and the entry count bound causes none of it.** The third
reading raises the age bound alone, and `JA4XFingerprinter.scan_offsets` still evicts 168
entries on its entry count while the two lists stay equal.

**The mechanism is the clock of the concatenation, and it is no race.** The five captures
were recorded across 183 days, so the concatenation jumps the packet timestamp by months.
`BoundedStateTable.evict_aged` measures an age against the timestamp of the most recent
packet, so a packet of one capture ages out the entries of another. A concatenation that
moves each capture onto one timeline reads **0 of 5**, and it produces 310 values where
the jumping concatenation produces 309. One thread loses that value too, which is the
reading that proves the cause is no race: `test_one_processor_that_reads_two_clocks_produces_a_shorter_value_set`
runs on one thread.

So clause 3 replaces the reading of round 84. A workload that passes an entry count bound
produces the same values under eight sharded threads as under one. A workload that carries
two clocks does not, and it does not under one thread either.

**Clause 1 needs no lock, and the measurement says so.** #43 removed every fingerprinter
lock and ran `TestTheConcurrencyContract` 20 times, and 0 of 20 runs failed. It removed
the lock of `Processor.process_packet` and read 0 of 20 as well. A thread that owns whole
connections touches keys no other thread touches, so the lock guards nothing that
arrangement reads. This is the reason `thread_safe=False` is safe for a caller who shards,
and it is why the argument exists. The locks guard the caller who shares one processor
without that arrangement, and they guard a `reset` that runs beside a packet. Round 84
records 20 of 20 for each of those cases.

**Every case #43 adds is proven by its removal.** `tests/test_memory_bounds.py` holds 20
cases and `TestTheConcurrencyContract` holds 7.

| Removal | Runs that fail | Cases that fail |
|---|---|---|
| The entry count eviction of `BoundedStateTable.__setitem__` | 3 of 3 | 8 of 20 memory cases |
| The age pass of `BoundedStateTable.evict_aged` | 3 of 3 | 1 of 20 memory cases |
| The `max_streams` eviction of `TCPStreamReassembler.add_segment` | 3 of 3 | 4 of 20 memory cases |
| The returned connection count of `StateTable.count_insert` | 3 of 3 | 1 of 20 memory cases |
| The nested descent of `BaseFingerprinter.state_tables` | 3 of 3 | 1 of 20 memory cases |
| The direction sort of `Processor.get_shard_key` | 20 of 20 | 4 of 7 contract cases |
| The age pass of `BoundedStateTable.evict_aged` | 20 of 20 | 1 of 7 contract cases |

**The first sweep found one case shape that could not fail.** The memory file held no
case that measured the age bound, so removing the age pass failed 0 of 3 runs. The file
now holds `TestTheAgeBoundFreesAnIdleConnection`, which replays 100 connections, waits
5000 seconds of capture time, and feeds 1200 more packets so that the age pass runs. Its
control replays one connection in steps below the age, and that connection holds its
entry.

**A walk replaces a hardcoded table list.** `tests/test_bounded_state_table_adoption.py`
names each table in `TABLES`, and a list cannot report a table that a later change adds.
`test_the_processor_holds_no_mapping_without_a_bound` walks a live `Processor()` and fails
on any mapping that is neither a `BoundedStateTable` nor one of the two stream tables.
The walk reads 14 bounded tables and 2 stream tables, which matches the table above.

**#285 proves the eviction hook by its removal.** With the `self.on_eviction(key)` call
of `BoundedStateTable.evict_key` removed, five cases fail: two in
`tests/test_state_table.py::TestTheEvictionHook` and three in
`tests/test_ja4ts_prefix_bound.py`. The third of those three reads
`KeyError: ('10.0.0.2', 443, '10.0.0.1', 50000)`, because `SynAckTracker.reset_value`
then reads a prefix that the prefix table already lost.

**#43 stated no memory ceiling, and #279 states one.** The section below holds it. #43
proves the bound through entry counts and eviction counts as well: a second flood of 400
connections raises the entry count by zero while the eviction count rises.

**#41 landed before #43, so the contract states the statistics it built.**
`docs/api_reference.md` holds a `stats()` row, the six fields of `ProcessorStats`, and
the definition of a returned connection. **#285 re-measured the table count and reads
sixteen**: `Processor.stats()` reports 16 tables across 10 methods, and the walk of
`tests/test_memory_bounds.py` reads 16 by an independent route.
`test_the_walk_of_this_file_agrees_with_the_report_of_the_processor` compares the two, so
a change that hides a table from one of them fails. The count moved four times, from six
in #179 to thirteen in #39 to fifteen in #41 to sixteen in #285. Three of the four moves
followed a better walk rather than new code, and #285 is the one that followed new code:
#246 added `SynAckTracker.prefixes` while Epic 3 was live.

## The memory ceiling this package states

**This package holds resident memory below 512 MiB for the one-million-packet case at the
shipped defaults.** The user decided the number on 2026-08-08. #38 proposed it and #279
confirmed it, and #279 re-measured the package rather than quoting the projection of #38.

**A ceiling with no stated configuration is no claim a reader can check, so this table
states the defaults the ceiling holds at.**

| Default | Value |
|---|---|
| The maximum entry count of a state table | 10000 entries |
| The maximum age of a state table | 600 seconds |
| `thread_safe` | `True` |
| The lookup cache | 100000 entries, and the case runs no lookup |

The `State bounds the code holds today` table above states each table that holds a
smaller bound. A caller that raises a bound raises the memory, and this ceiling then
states nothing about that caller.

**The case the ceiling covers.** One `Processor()` reads 1000000 packets across 100000
distinct connections, which is ten packets for each connection. The traffic reaches every
stateful method. Each connection carries a SYN, a SYN-ACK, two SSH records, two HTTP
requests, two TLS records, one QUIC Initial packet and one bare ACK.

**The reading.** #279 measured the case four times on macOS 26.6.1 with Python 3.14.3, on
a ten-core Apple silicon laptop. **The table states every run and not the best one**,
because a resident memory reading moves with the platform and with the machine.

| Run | Peak resident memory |
|---|---|
| 1 | 383.47 MiB |
| 2 | 388.25 MiB |
| 3 | 392.05 MiB |
| 4 | 394.94 MiB |

**The highest of the four is 394.94 MiB, which is 77 percent of the ceiling.** The four
sit 11.47 MiB apart, and the ceiling holds 117.06 MiB above the highest.

An idle `Processor` with scapy imported reads about 100 MiB of each total, and a bare
interpreter reads 16.14 MiB of that. The run ends with 40200 entries across the seventeen
state tables and 400000 values across the ten value lists.

**The age bound holds most of the large tables, and the entry count bound holds two.**
This is the entry count of each table at the one-million-packet mark.

| State table | Entries | Maximum | What holds it |
|---|---|---|---|
| `ja4l.connections` | 10000 | 10000 | The entry count |
| `ja4l.grouping_keys` | 10000 | 10000 | The entry count |
| `ja4s._quic_dcids` | 6000 | 10000 | The age |
| `ja4ssh.connections` | 6000 | 10000 | The age |
| `ja4t.connections` | 6000 | 10000 | The age |
| `ja4ts.syn_ack_times.times` | 1000 | 1000 | The entry count |
| `ja4ts.syn_ack_times.prefixes` | 1000 | 1000 | The eviction hook of `times` |
| `ja4h.consumed_seq` | 100 | 100 | The entry count |
| `ja4x.scan_offsets` | 50 | 50 | The entry count |
| `ja4x.reassembler` | 50 streams | 50 | The stream count |
| The six remaining tables | 0 | | The traffic reaches none of them |

**The case advances the capture timestamp 0.1 seconds for each connection**, so 100000
connections span 10000 seconds of capture time. A 600-second age therefore holds a table
at about 6000 entries, which is why three tables sit below their maximum. A reader who
changes the traffic changes which bound binds.

**#279 read a larger idle figure than #38 and a smaller total than round 82.** #38 read
91.03 MiB for an idle `Processor` and projected 238.96 MiB, and round 82 read 419.27 MiB
for the whole run. Neither number describes this branch: #214 added emission to
`JA4SSHFingerprinter.connections`, #215 added a connection table to `ja4t.py`, #53 added
the table of the monitor, and #60 measured the lookup cache at 47.06 MiB. The projection
of #38 counted ten full tables, and the case saturates fewer than ten.

**The ceiling covers the stated case and no longer run.**
`BaseFingerprinter.fingerprints` grows without a limit, so resident memory keeps rising
after every state table settles. #279 read about 23 MiB for each 100000 packets past the
200000th, and **it measured the crossing at 1500000 packets and 513.06 MiB.** Goal 3 owns
the value list, and `TestTheStructuresThatHoldNoBound` records it. A reader must not read
this ceiling as a bound that holds for a monitor that runs without an end.

**How the case measures it.** `tests/memory_ceiling_run.py` feeds the packets in an
interpreter of its own and reports `resource.getrusage(RUSAGE_SELF).ru_maxrss` as
`peak_mib`. The separate interpreter is part of the measurement: `ru_maxrss` reports the
high-water mark of the whole process, so a reading taken inside the pytest session
measures every case that ran before it. `TestTheStatedMemoryCeiling` of
`tests/test_memory_bounds.py` reads the number and compares it against 512.0.

**The run reports two kinds of reading, and the two answer different questions.** The
ceiling is a claim about the high-water mark, so the ceiling case reads `peak_mib`. The
memory one run adds is no claim about a mark, so the run also reports the current
resident set before the traffic and after it, as `idle_resident_mib` and
`final_resident_mib`. Linux publishes the current reading in `/proc/self/statm` and
Darwin reports it through `ps`.

**Warning: two high-water marks subtract to no growth.** A mark rises and never falls, so
the difference between two of them states `max(0, later mark - earlier mark)`. The import
of scapy reaches a mark on Ubuntu that the traffic run then stays below, and the
difference is exactly zero for a run that allocated tens of MiB. **The four Ubuntu jobs of
pull request #384 read `idle_mib 154.7` and `peak_mib 154.7`, and the same run on macOS
read a difference because the import costs less there.** `traffic_growth_mib` of
`tests/test_memory_bounds.py` holds the rule, and it refuses a high-water pair as a void
measurement rather than reporting zero. `TestTheGrowthReading` measures that refusal
against the Ubuntu numbers, and it starts no interpreter.

**The case feeds 30000 packets by default, and `JA4PLUS_MEMORY_CEILING_PACKETS` sets the
count.** The full run costs 481 seconds, and a case of that length costs every later run
of the unit suite. `tests/test_thread_safety.py` holds the same arrangement for the
60-second soak of #40, and the pull request of #279 records one run at 1000000.

**The ceiling case goes red, and #279 measured the point.** At the shipped defaults the
run passes 512 MiB at **1500000 packets across 150000 connections, where it reads 513.06
MiB**. That reading is what makes the ceiling comparison falsifiable, and it replaces the
projection above with a measurement. The packet count is the mechanism that falsifies the
ceiling, and the entry count bound is not.

**#279 raised a table limit three ways, and the case stayed green each time.** The brief
of #279 expected a raised bound to turn the case red. It does not, and the three readings
below say why.

| Reversal | Reading at 1000000 packets | Result |
|---|---|---|
| `ja4ssh.connections` raised from 10000 to 100000 | 383.00 MiB | Green |
| `ja4l.connections` and `ja4l.grouping_keys` raised from 10000 to 100000 | 412.06 MiB | Green |
| Every one of the fifteen entry counts raised to 100000 | No reading | The run never finished |

**The third reversal produced no reading, and #279 ran it three times.** The operating
system killed two runs before either wrote a number, and the third reached 2500
connections in ten minutes. A table of 100000 entries makes each age pass cost more than
the packet does, so the run stops being the case the ceiling describes.

Three readings explain the two green results, and each one matters to a reader.

1. **The age bound holds the table that the reversal raises.** With both JA4L bounds at
   100000 the two tables settle at 24000 entries rather than 100000, because the capture
   timeline passes 600 seconds. The reversal therefore buys 14000 entries and 17.12 MiB.
2. **`ja4ssh.connections` never reaches its shipped maximum on this traffic.** It holds
   6000 entries against a maximum of 10000, so raising that maximum changes nothing.
3. **The 5423 bytes for each JA4SSH entry that #38 measured describe a full 200-packet
   window.** The case gives each connection two SSH packets, so each entry holds two
   packet lengths. **A ceiling describes a traffic mix and not a packet count alone.**

**The committed control proves the entry count bound is measured.** With the control
bound raised from 100 to the shipped 10000,
`test_a_smaller_entry_count_holds_fewer_memory_blocks` fails.

**Three controls sit beside the ceiling case.** The default size holds 3000 connections,
which no shipped bound reaches, so the ceiling comparison alone cannot fail at that size.

- `test_the_run_feeds_every_packet_the_case_states` reads the packet count and the
  connection count back from the run.
- `test_the_reading_measures_the_traffic_and_not_the_interpreter` reads the memory the
  traffic added, and it reads the mark against the resident set the run held.
- `test_a_smaller_entry_count_holds_fewer_memory_blocks` lowers every entry count to 100
  and reads a smaller number.

**The second control reads the current resident set and it subtracts no mark.** A run
that reports a flat pair fails it, and the message reads `the run added 0.00 MiB, so the
reading measures no traffic`.

**The third control reads a block count, and #389 moved it there.** A resident reading
states what the host left in memory, and a block count states what the program holds. A
host under memory pressure reclaims the pages of a running process, and it reaches the
run that holds the most memory first. The reclaim therefore moves the two runs by
different amounts, and it moves the ratio toward one. **Five workers saw the case fail
and then pass on an unchanged tree**, and every failure sat on a loaded host.

**#389 measured both readings across four memory limits**, on one Ubuntu 24.10 host with
`python3.12`, 30000 packets, and each run under `systemd-run --user --scope -p
MemoryMax=<limit>`.

| Memory limit | Resident growth, shipped and control | Resident ratio | Block ratio |
|---|---|---|---|
| none | 29.34 MiB, 12.72 MiB | 0.434 | 0.392 |
| 80 MiB | 10.98 MiB, 10.56 MiB | 0.962 | 0.392 |
| 75 MiB | 6.13 MiB, 4.82 MiB | 0.786 | 0.392 |
| 70 MiB | 0.00 MiB, 0.00 MiB | no reading | 0.392 |

The block growth of the shipped run held between 376952 and 376965 across all four, so
the four readings differ by 13 blocks. **The repaired case passes at every one of the
four**, and
the case that reads the resident growth fails at 80 MiB on the ratio, at 75 MiB on the
floor, and at 70 MiB on the floor.

**A rule that repeats the pair and takes the median repairs nothing.** Memory pressure
lasts as long as the host holds it, so every round reads the same clipped pair. Three
rounds of the resident reading at the 80 MiB limit read 1.047, 0.885 and 1.045, and the
median of the three fails. The rule also costs three times the wall clock, and one round
costs 57 seconds on that host.

**A deliberate load of the processor moves neither reading, and that reading is what
names the mechanism.** 56 spinners on the 56-core host held the load average at 58 for
three rounds, which matches the ratio of load to cores that every reported failure sat
at. The runs took 59 to 67 seconds against 27 quiet, and the resident ratio read 0.361,
0.445 and 0.407. **Memory pressure moves this reading and processor contention does
not.**

**The third control compares a ratio and not an absolute figure**, because the absolute
reading moves with the platform and with the interpreter while the ratio measures the
bound itself. **With the control bound raised to the shipped 10000 the case fails**: the
block ratio reads 1.367 on macOS with Python 3.14 and 1.361 on Linux with `python3.12`.
The true reading is 0.392 on Linux and 0.398 on macOS, so the threshold of 0.85 sits
between the two. The failure message is `a bound of 10000 added 506935 blocks and the
shipped bounds added 370945 blocks, a ratio of 1.367, so the entry count changed nothing`.

**The run collects the cyclic garbage before it counts the blocks.** A count taken
between two collections holds the garbage the collector has not reached, and the point it
reaches moves with the allocation history. Without the collection two macOS readings gave
a control growth of 230616 and 247991, at a ratio of 0.612 and 0.664. With the collection
three rounds read 147562, 147566 and 147569, and the ratio reads 0.398 at each. The
collection runs after the resident reading at both points, so it moves no part of the
ceiling reading.

**The floor reads a rate of four blocks for each packet, and it read 10.0 MiB until
#389.** A MiB floor is the reading a host moves: under the 70 MiB limit the shipped run
added 0.00 MiB and 376954 blocks. The measured rate is 12.37 blocks for each packet at
30000 packets, 13.99 at 5000 and 15.08 at 1000, so the reading sits 3.1 times above the
floor at the default size. The retired MiB floor sat 2.9 times below its reading, so the
rate holds the strength the MiB floor held.

## Data touched

- Changed files: every file under `ja4plus/fingerprinters/`,
  `ja4plus/utils/tcp_stream.py`, `ja4plus/processor.py`, `ja4plus/ja4db.py`.
- New file `ja4plus/utils/state_table.py`, holding the bounded table that every
  fingerprinter uses.
- New file `tests/test_thread_safety.py`.
- New file `tests/test_memory_bounds.py`.
- New file `tests/memory_ceiling_run.py`, which #279 added. It measures the resident
  memory of one packet run in an interpreter of its own.

## Interfaces

Epic 3 builds this interface. `Processor.__init__` accepts no argument today.

```python
class Processor:
    def __init__(
        self,
        thread_safe: bool = True,
        max_connections: int = 10_000,
        max_connection_age: float = 600.0,
    ) -> None: ...

    def stats(self) -> dict[str, ProcessorStats]: ...
```

`max_connection_age` defaults to 600.0, which matches `DEFAULT_MAX_STREAM_AGE` in
`ja4plus/utils/tcp_stream.py`. One project holds one maximum age.

`ProcessorStats` reports the entry count, the eviction count, and the packet count
for one method.

The port has no equivalent, because Go's `sync` types and its garbage collector
make different choices reasonable. This is an addition, not a divergence: parity
rule 2 applies only where the port has already shipped a choice.

## Edge cases & failures

| Case | What happens |
|---|---|
| Two threads process packets for one connection at the same time. | Both calls succeed. The resulting state is one of the two valid orderings. |
| A thread calls `reset` while another processes a packet. | `reset` waits for the lock. No state table is left half-cleared. |
| A state table reaches its maximum entry count. | The least recently used entry is evicted, and the eviction count rises. |
| A connection is evicted and then sends another packet. | A new entry is created. The fingerprint for that connection may be incomplete, and this is recorded in the statistics. |
| A capture file replays one hour of traffic in ten seconds. | Eviction uses the packet timestamp, so entries expire at the right point in the capture. |
| A packet carries no timestamp. | Eviction uses the wall clock for that packet. |
| `max_connections` is zero or negative. | The constructor raises `ValueError`. |
| A caller sets `thread_safe=False` and uses threads anyway. | The results are undefined. The documentation says so. |

## Acceptance criteria

- [x] Eight threads feeding one `Processor()` for 60 seconds produce the same
      fingerprint set as one thread feeding the same packets. #40 holds it. The
      committed case reads `JA4PLUS_THREAD_SOAK_SECONDS` and defaults to 2.0 seconds.
- [x] Eight threads feeding one `Processor()` raise no exception. #40 holds it.
- [x] A test that calls `reset` from one thread while eight threads process packets
      raises no exception. #40 holds it.
- [x] `Processor(thread_safe=False)` acquires no lock, proven by a test that
      replaces the lock with an object that fails when acquired. #40 holds it.
- [x] Feeding 1000000 packets across 100000 distinct connections holds resident
      memory below a stated ceiling. **The ceiling is 512 MiB, and #279 states it.**
      #279 measured 394.94 MiB at the highest of four runs, and
      `TestTheStatedMemoryCeiling::test_the_packet_run_holds_resident_memory_below_the_stated_ceiling`
      reads it. The same traffic passes the ceiling at 1500000 packets, which is the
      reading that makes the comparison falsifiable.
- [x] Every state table reports an entry count no greater than `max_connections`.
      `test_no_state_table_passes_its_entry_count_after_two_floods` reads every table.
- [x] An entry that receives no packet for longer than `max_connection_age` is
      absent from the state table afterwards.
      `test_a_connection_that_stops_sending_leaves_the_state_table` reads it.
- [x] `Processor().stats()` returns one entry per method. #41 holds it, and
      `test_the_processor_reports_one_entry_for_each_method` reads it.
- [x] Two threads that call `ja4plus.ja4db.lookup` at the same time receive results
      from one client instance. #42 holds it.
- [ ] `Processor(max_connections=0)` raises `ValueError`. **The constructor accepts no
      such argument today.** `BoundedStateTable` raises it, and
      `tests/test_state_table.py` reads that.
- [x] The README states the concurrency contract in one paragraph. #43 holds it.

## Out of scope

- An asynchronous interface.
- A process pool. The library gives the caller `get_shard_key` and the caller
  builds the pool.
- Lock-free data structures.
- A background eviction thread.

## Open questions

**#279 closed the one open question of this feature on 2026-08-08.** The user decided the
memory ceiling, and `The memory ceiling this package states` above holds it and the
measurement behind it. No constant in `ja4plus/` names the ceiling, because the ceiling
is a claim this package publishes and no code reads it.

The measurement #38 produced stays on record, because it is the reading the decision
started from. An idle `Processor()` with scapy imported held 91.03 MiB resident. One full
table of 10000 entries shaped like `JA4LFingerprinter.connections` held 10.69 MiB, at
1121 bytes for each entry. One full table of 10000 entries shaped like
`JA4SSHFingerprinter.connections` held 51.72 MiB at a 200 packet window, at 5423 bytes
for each entry. Ten tables at the default entry count therefore projected
91.03 + 51.72 + 96.21 = **238.96 MiB**. #279 re-measured the whole case and reads
394.94 MiB at the highest of four runs, because the projection counts a saturated table
where the case saturates fewer, and because the value lists hold 400000 values the
projection omits.
