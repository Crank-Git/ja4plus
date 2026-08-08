---
id: concurrency-safety
feature: Concurrency and resource safety
epic: "Epic 3: Concurrency and resource safety"
status: issued
issues: [14, 38, 39, 40, 41, 42, 43]
mockups: []
---

## Purpose

The library holds no lock anywhere. Every stateful fingerprinter holds a mutable
state table, and the processor drives ten of them. `Processor.get_shard_key` exists
so that a caller can spread traffic across workers, which tells the reader that
concurrency is expected. Nothing states what is safe.

Every state table also grows without limit. `cleanup_connection` exists, but the
caller must call it, and a caller who does not know it exists runs out of memory.

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
- Epic 3 target: the default maximum entry count is 10000 per state table. No state
  table holds that count today.
- Epic 3 target: an eviction pass runs at most once per 1000 packets, so that the
  eviction cost stays proportional to the traffic. Every eviction pass runs on each
  packet today.
- `thread_safe=False` is a promise the caller makes, not a mode the library checks.
  The documentation states that a caller who breaks the promise gets undefined
  results.
- `cleanup_connection` stays. It is the caller's way to evict early, and the port
  has the same method.

## State bounds the code holds today

This feature set is unbuilt. The table below records what the code holds, so that a
reader does not read a target as a description. #179 measured it against the code.

| State table | Maximum entry count | Maximum age |
|---|---|---|
| `TCPStreamReassembler.streams`, built by JA4H | 100 | 600 seconds |
| `TCPStreamReassembler.streams`, built by JA4X | 50 | 600 seconds |
| `JA4HFingerprinter.consumed_seq` | 100 | 600 seconds |
| `JA4HFingerprinter.unusable_base` | 100 | none |
| `JA4Fingerprinter._quic_fragments` | 1000 | 30 seconds |
| `JA4SFingerprinter._quic_server_crypto` | 1000 | 30 seconds |
| `JA4XFingerprinter.processed_certs` | 1000 | none |
| `JA4SFingerprinter._quic_dcids` | none | none |
| `JA4LFingerprinter.connections` | none | none |
| `JA4SSHFingerprinter.connections` | none | none |
| `JA4DBClient._cache` | none | none |
| `BaseFingerprinter.fingerprints` | none | none |

`TCPStreamReassembler` carries two more per-stream bounds: `max_stream_bytes` is
1048576, and `max_stream_segments` is 4096.

The two `JA4HFingerprinter` tables read `TCPStreamReassembler.max_streams` and
`max_stream_age` of the reassembler that fingerprinter holds, so one number bounds the
stream and the state that describes it. #179 measured this table before #193 added
`consumed_seq`, and it omitted `unusable_base`, which #33 built.

A row that reads `none` relies on the caller to call `cleanup_connection`.
FR-concurrency-safety-7 and FR-concurrency-safety-8 own that gap, and Epic 3 closes it.

`BaseFingerprinter.fingerprints` holds one result per fingerprint, not per-connection
data, so the `## Terms` table does not name it a state table. It appears above because
it grows without a limit, and Goal 3 covers it.

This file states four more targets that the code does not hold today:

- `Processor.__init__` accepts no argument. The `thread_safe`, `max_connections` and
  `max_connection_age` arguments are targets.
- The library holds no lock. `threading` reaches no module under `ja4plus/`.
- No class reports a state table entry count, and no class counts an eviction.
  `Processor.stats` is a target.
- `JA4DBClient` builds no client once for every thread, and its lookup cache holds no
  maximum entry count.

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

- [ ] Eight threads feeding one `Processor()` for 60 seconds produce the same
      fingerprint set as one thread feeding the same packets.
- [ ] Eight threads feeding one `Processor()` raise no exception.
- [ ] A test that calls `reset` from one thread while eight threads process packets
      raises no exception.
- [ ] `Processor(thread_safe=False)` acquires no lock, proven by a test that
      replaces the lock with an object that fails when acquired.
- [ ] Feeding 1000000 packets across 100000 distinct connections holds resident
      memory below a stated ceiling.
- [ ] Every state table reports an entry count no greater than `max_connections`.
- [ ] An entry that receives no packet for longer than `max_connection_age` is
      absent from the state table afterwards.
- [ ] `Processor().stats()` returns one entry per method.
- [ ] Two threads that call `ja4plus.ja4db.lookup` at the same time receive results
      from one client instance.
- [ ] `Processor(max_connections=0)` raises `ValueError`.
- [ ] The README states the concurrency contract in one paragraph.

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
