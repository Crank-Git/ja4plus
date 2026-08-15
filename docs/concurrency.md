# The concurrency contract and the memory bounds

Read this page before you write threaded code against `ja4plus`, and before you run a
monitor for a long time.

`README.md` states the same contract for a reader of the front door, and
`tests/test_readme_contracts.py` reads each number out of the code. `docs/specs/features/03-concurrency-safety.md`
holds the design.

## The concurrency contract

Several threads may share one `Processor()`, and each fingerprinter guards its own state
with a reentrant lock.

**Warning: a caller that splits the packets of one connection across threads gets
undefined results.** The state of that connection then advances out of capture order.

Give each thread whole connections, which is what `get_shard_key` returns. Eight threads
then read the value set one thread reads.

**Warning: `thread_safe=False` is a promise the caller makes, and not a mode the library
checks.** A caller that runs one processor for each shard constructs
`Processor(thread_safe=False)` to acquire no lock.

## Why one processor reads one timeline

Feed one processor the packets of one timeline. Every state table evicts an entry that
receives no packet for its maximum age, and eviction reads the packet timestamp.

Two packet sources whose clocks sit far apart therefore age out state that the later
source still needs. A capture file and a live interface are two such sources.

## The memory bound

Every state table holds a maximum entry count and a maximum age. A monitor that runs for
a day therefore stops growing, and it does not run out of memory.

A table that reaches its maximum entry count evicts the least recently used entry. A
connection can therefore leave a long capture and return, and the fingerprint of a
returned connection may be incomplete. `Processor.stats()` reports the count of returned
connections for each method.

**Eviction runs on packet arrival, and the library starts no thread.**

## One packet dated in the future evicts every entry

The age pass reads the timestamp of the packet that arrives, and it compares that one
timestamp against the last-seen time of every entry. A packet dated far in the future
therefore ages every entry at once, and the pass evicts all of them.
`ja4plus/utils/state_table.py:414` holds the comparison, inside the loop at line 411.

**Warning: a packet carries its own timestamp, so a sender influences this input.** A
capture file that the operator did not produce is the reachable case. One packet of such
a file removes every entry of the state table. A bounded table otherwise lets a sender
remove one entry with one connection.

**A live capture reaches this property much less often.** It takes the timestamp of each
packet from the host clock rather than from the sender.

**This project accepts the property, and it changes no line of the age pass.** The
maintainer ruled it on 2026-08-14, on `Crank-Git/ja4plus-go#577` and on #618. Each
declined answer invents a rule that no FoxIO source states. A monotonic clock diverges
from the packet clock on a replayed capture. An offline run of an old capture then evicts
nothing or everything. A bound on the jump needs a number that no source justifies.

**An age against the highest timestamp seen bounds the forward jump alone.** It does
nothing about a timestamp that moves backwards.

**A repair in one implementation alone gives the two implementations two age clocks.**
The Go port holds the same comparison, so a repair changes both repositories.

**The eviction removes fingerprinting state, so a run answers with fewer fingerprints
rather than with wrong ones.** A connection that sends a packet after the eviction is a
returned connection, and the section above states that its fingerprint may be incomplete.

**The entry count bound holds the memory, whatever timestamp a packet carries.** That
bound reads the recency order of the entries, and it reads no timestamp. This property
therefore grants a sender no memory growth.

## The default bounds

| Bound | Default |
|---|---|
| The maximum entry count of one state table | 10000 entries |
| The maximum age of one entry of a state table | 600 seconds |
| The maximum count of connections the monitor holds | 10000 connections |
| The maximum age of one connection of the monitor | 300 seconds |

`ja4plus/utils/state_table.py` sets the first two, and a table that needs a smaller bound
states its own. `ja4plus/watch.py` sets the last two, and `--max-connections` and
`--connection-timeout` change them for one run.

**The monitor holds an idle connection for a shorter time than a state table does**, so
the monitor evicts a connection first.

## The memory ceiling

This package states a memory ceiling of **512 MiB**. One `Processor()` at the shipped
defaults reads 1000000 packets across 100000 distinct connections, and it holds resident
memory below that number.

**The ceiling covers that packet run and no longer run.** Each fingerprinter keeps every
fingerprint it produces, and that list holds no bound, so a longer run reads more memory.
The same traffic passes 512 MiB at 1500000 packets.

**Warning: a caller that runs `reset()` in the middle of a capture loses the connection
state the next packet needs.** `Processor.reset()` drops every fingerprint the run
produced, and it drops every state table with them.

## Where to read more

- [The usage guide](usage.md) holds the code samples.
- [The method index](methods/index.md) names every method.
- [The output schema](output-schema.md) states the shape of each output line.
