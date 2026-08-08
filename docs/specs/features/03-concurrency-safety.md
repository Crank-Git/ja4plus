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
| `JA4DBClient._cache`, held by the lookup client | 100000 | 600 seconds | 100000 reads |
| `BaseFingerprinter.fingerprints` | none | none | none |

`TCPStreamReassembler` carries two more per-stream bounds: `max_stream_bytes` is
1048576, and `max_stream_segments` is 4096.

Every row other than the first two and `BaseFingerprinter.fingerprints` is a
`BoundedStateTable`. #39 moved thirteen tables, and it removed two companion tables,
`_quic_fragment_seen` and `_quic_server_crypto_seen`, because the state table holds the
age of each entry. #42 moved `JA4DBClient._cache`, which reads no packet, so its age
pass counts reads rather than packets.

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

- `Processor.stats` returns a dict that maps each of the ten method names to one
  `ProcessorStats`. `ProcessorStats` is a plain object; Epic 4 makes it a typed
  dataclass.
- `ProcessorStats` states the packet count of the method and one `TableStats` for each
  state table the method holds. It also states the sum of the entry counts, the sum of
  the eviction counts and the sum of the returned connections.
- `TableStats` states six counts: `entries`, `max_entries`, `inserts`, `evictions`,
  `removals` and `returned_connections`. The six hold the invariant
  `inserts == entries + evictions + removals`.
- **The report covers fifteen state tables, and not thirteen.** Round 82 counted the
  thirteen `BoundedStateTable` instances. `JA4HFingerprinter.reassembler` and
  `JA4XFingerprinter.reassembler` each hold per-connection data across packets, so the
  `## Terms` table names each one a state table too. `TCPStreamReassembler` therefore
  inherits `StateTable` and counts the same six things.
- `StateTable` is the base class both hold. `BaseFingerprinter.state_tables` finds a
  state table by that type, so a new table reaches the report with no further change.
  The search descends one level, which reaches `SynAckTracker.times`.
- A returned connection is a connection the table evicted and then saw again. The table
  remembers the keys it evicted, and it bounds that memory at its own entry count. A
  key the caller removed leaves no memory, so a connection that returns after
  `cleanup_connection` counts as a first sighting. The fifteen tables hold 46400
  remembered keys between them, at 187 bytes for one key, so the memory costs 8.3 MiB
  at its worst.
- `Processor.stats` holds the lock of one fingerprinter across the read of that
  fingerprinter, because the counts of one method describe one instant. It acquires one
  lock at a time and holds two never.
- The report describes ten instants and not one. A caller that needs one instant across
  the ten methods stops the packet source first.
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
The walk reads 13 bounded tables and 2 stream tables, which matches the table above.

**This feature states no memory ceiling, and #43 states none.** #279 owns the number, and
round 81 records that the measurement forces a floor and forces no ceiling. The memory
file proves the bound through entry counts and eviction counts instead: a second flood of
400 connections raises the entry count by zero while the eviction count rises.

**#41 landed before #43, so the contract states the statistics it built.**
`docs/api_reference.md` holds a `stats()` row, the six fields of `ProcessorStats`, and
the definition of a returned connection. **#43 re-measured the table count and reads
fifteen**, which matches round 85: `Processor.stats()` reports 15 tables across 10
methods, and the walk of `tests/test_memory_bounds.py` reads 15 by an independent route.
`test_the_walk_of_this_file_agrees_with_the_report_of_the_processor` compares the two, so
a change that hides a table from one of them fails. The count moved three times, from six
in #179 to thirteen in #39 to fifteen in #41, and each move followed a better walk rather
than new code.

## Data touched

- Changed files: every file under `ja4plus/fingerprinters/`,
  `ja4plus/utils/tcp_stream.py`, `ja4plus/processor.py`, `ja4plus/ja4db.py`.
- New file `ja4plus/utils/state_table.py`, holding the bounded table that every
  fingerprinter uses.
- New file `tests/test_thread_safety.py`.
- New file `tests/test_memory_bounds.py`.

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
- [ ] Feeding 1000000 packets across 100000 distinct connections holds resident
      memory below a stated ceiling. **#279 owns the ceiling, and this feature states
      none.** Round 82 measured 419.27 MiB for that run and zero tables above a bound.
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

- The stated memory ceiling for the one-million-packet test. **#38 measured the
  baseline and #279 decides the number.** The measurement forces a floor and it
  forces no ceiling, so the distance above that floor is a product judgement. A
  ceiling is a number this package states to its users.

  An idle `Processor()` with scapy imported holds 91.03 MiB resident. One full table
  of 10000 entries shaped like `JA4LFingerprinter.connections` holds 10.69 MiB, at
  1121 bytes for each entry. One full table of 10000 entries shaped like
  `JA4SSHFingerprinter.connections` holds 51.72 MiB at a 200 packet window, at 5423
  bytes for each entry. That table is the largest of the twelve. Ten tables at the
  default entry count therefore project 91.03 + 51.72 + 96.21 = **238.96 MiB**.

  The projection holds whatever the connection count is. `BoundedStateTable` never
  passes 10000 entries, so 100000 distinct connections reach no more than 10000
  entries in one table. No constant in `ja4plus/` names a ceiling, and no case
  asserts one.
