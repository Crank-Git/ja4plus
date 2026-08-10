"""A state table that holds a maximum entry count and a maximum age.

Every stateful fingerprinter holds per-connection data across packets, and
`CLAUDE.md` states the rule: nothing that survives across packets grows without a
limit. #179 records six tables that hold no bound today. #39 moves them, and this
class is the shape four of them take.

The table evicts on two conditions.

- The count bound removes the least recently used entry as soon as the table reaches
  `max_connections`. A count bound that waits overshoots the count it states.
- The age bound removes every entry of the calling thread that receives no read for
  `max_connection_age` seconds. `on_packet` runs that pass, and it runs it once for
  every `eviction_interval` packets, so the eviction cost stays proportional to the
  traffic. The clock belongs to the thread as well, because eight sharded threads stand
  at eight points of one timeline. #461 measured what one shared clock costs: the thread
  that stood 132 seconds ahead evicted a connection that a slower thread still read, and
  the fingerprint of that connection lost its last field. A table that reads the wall
  clock holds one clock for every thread, so every age pass evicts every entry of it.

The library starts no thread. Eviction runs on packet arrival.

Two of the six tables that #179 records need something else, and #39 owns the answer
for each.

- `BaseFingerprinter.fingerprints` is a list. It holds one result for each fingerprint
  and no per-connection data, so the `## Terms` table names it no state table.
  `ja4l.py` overwrites an entry at a stored index, and `ja4ssh.py` reads the entry at
  index -1. A mapping keyed by connection serves neither call site.
- `JA4DBClient._cache` reads no packet. #42 built the answer: `JA4DBClient.lookup`
  calls `on_packet` on every lookup, so one lookup counts as one arrival and the age
  pass runs on the lookup schedule. Its count bound holds whatever the caller does,
  because `__setitem__` applies that bound at once. A caller that drives neither a
  packet nor a lookup calls `evict_aged` to age an entry out.
"""

# Python 3.9 is the floor, and it evaluates no annotation written as `str | None`
# without this import.
from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterator, MutableMapping
from typing import Any

logger = logging.getLogger(__name__)

# The maximum entry count of one state table. `features/03-concurrency-safety.md` sets
# it as the Epic 3 target. No state table of the committed captures reaches it.
DEFAULT_MAX_CONNECTIONS = 10000

# The maximum age of one entry, in seconds. `ssh-r.pcap` holds the longest gap between
# two segments of one connection across `tests/foxio_vectors/`, at 320.714503 seconds.
# This age sits above that gap. The value 300 sits below it, and #179 records why that
# number survived: no comparison ever read it.
DEFAULT_MAX_CONNECTION_AGE = 600

# The count of packets between two eviction passes. A pass reads every entry, so a pass
# on each packet costs the entry count on each packet.
DEFAULT_EVICTION_INTERVAL = 1000

# The positions inside one stored entry. The entry is a list rather than a tuple,
# because a read rewrites the timestamp and a tuple allocates a new object each time.
# `_SHARD` holds the identifier of the thread that touched the entry last, and
# `evict_aged` reads it. It holds None where that thread read the wall clock, because one
# wall clock serves every thread and no thread owns such an entry.
_VALUE = 0
_LAST_SEEN = 1
_SHARD = 2


class TableStats:
    """The counts one state table reports.

    `Processor.stats` collects one of these for every state table of every method.
    FR-concurrency-safety-11 asks for the entry count, and FR-concurrency-safety-12
    asks for the eviction count. The other four counts make the report readable: a
    reader who sees 10000 entries cannot tell a table that filled once from a table
    that evicted a million connections.

    The six counts hold one invariant, `inserts == entries + evictions + removals`. A
    reader who sees it broken read the table while another thread wrote it.

    Args:
        entries: The count of entries the table holds now.
        max_entries: The maximum entry count of the table.
        inserts: The count of keys the table ever added.
        evictions: The count of entries the table itself removed, on either bound.
        removals: The count of entries the caller removed, through `del`, `pop`,
            `clear` or `cleanup_connection`.
        returned_connections: The count of connections the table evicted and then saw
            again. The fingerprint of such a connection may be incomplete, because the
            new entry holds none of the packets that came before the eviction.
    """

    __slots__ = (
        "entries",
        "max_entries",
        "inserts",
        "evictions",
        "removals",
        "returned_connections",
    )

    def __init__(
        self,
        entries: int,
        max_entries: int,
        inserts: int,
        evictions: int,
        removals: int,
        returned_connections: int,
    ) -> None:
        self.entries = entries
        self.max_entries = max_entries
        self.inserts = inserts
        self.evictions = evictions
        self.removals = removals
        self.returned_connections = returned_connections

    def __repr__(self) -> str:
        return (
            f"TableStats(entries={self.entries}, max_entries={self.max_entries}, "
            f"inserts={self.inserts}, evictions={self.evictions}, "
            f"removals={self.removals}, "
            f"returned_connections={self.returned_connections})"
        )


class StateTable:
    """The counters every state table keeps, and the keys the table evicted.

    Two classes hold per-connection data across packets: `BoundedStateTable` and
    `TCPStreamReassembler`. Both count the same six things, so both inherit this class.
    `BaseFingerprinter.state_tables` finds a state table by this type, so a new state
    table reaches `Processor.stats` as soon as it inherits this class.

    A subclass raises `inserts`, `evictions` and `removals` itself, through
    `count_insert`, `count_eviction` and `count_removals`. It builds its report with
    `build_stats`.

    A subclass that adds a key calls `take_evicted_key` first, then evicts, then stores
    the entry, then calls `count_insert`. The order matters: an insert can evict, and
    an eviction can drop the memory of the key that arrives.

    Args:
        max_evicted_keys: The count of evicted keys the table remembers. The memory of
            an evicted key costs one key, so this bound matches the entry bound of the
            table.
        track_evictions: True remembers the key of every entry the table evicts, and it
            reports `returned_connections`. False remembers no key, and it reports 0
            returned connections. #359 measured the cost of the memory, and only a
            reader of the count needs it.
    """

    def __init__(self, max_evicted_keys: int, track_evictions: bool = True) -> None:
        self.inserts = 0
        self.evictions = 0
        self.removals = 0
        self.returned_connections = 0
        self.max_evicted_keys = max_evicted_keys
        self.track_evictions = track_evictions

        # The keys the table evicted and has not seen again, least recent first. A set
        # answers the membership question, and it gives no order to drop the oldest
        # key by. Nothing that survives across packets grows without a limit, so this
        # memory holds the same bound the table holds.
        self._evicted_keys: OrderedDict[Any, None] = OrderedDict()

    def take_evicted_key(self, key: Any) -> bool:
        """Report whether this table evicted the key, and drop the memory of it.

        A first sighting and a return look the same at the call site: both add a key
        the table does not hold. The two differ in the memory of the evicted keys. A
        key this table evicted returns; a key it never evicted arrives for the first
        time. A key the caller removed returns nothing, because the caller asked for
        that removal and no eviction lost its packets.

        Call this method before the eviction that the arrival of the key drives. That
        eviction adds a key to the memory, and it drops the oldest key of the memory,
        which can be the key that arrives.

        Args:
            key: The key that arrives.

        Returns:
            True when this table evicted the key and has not seen it since. A table that
            tracks no eviction returns False for every key.
        """
        if key not in self._evicted_keys:
            return False
        del self._evicted_keys[key]
        return True

    def count_insert(self, returned: bool = False) -> None:
        """Count one new key, and count a connection that returned after an eviction.

        Args:
            returned: The value `take_evicted_key` returned for this key.
        """
        self.inserts += 1
        if returned:
            self.returned_connections += 1

    def count_eviction(self, key: Any) -> None:
        """Count one entry the table itself removed, and remember its key.

        Args:
            key: The key the table removed.
        """
        self.evictions += 1
        # A table that tracks no eviction reports no returned connection, so the key of
        # this entry buys nothing. The eviction count stands, because
        # FR-concurrency-safety-12 asks for it and it costs one integer.
        if not self.track_evictions:
            return
        self._evicted_keys[key] = None
        # A fresh key lands at the end already. This call covers a key the memory still
        # holds, which happens when a subclass evicts a key that no `take_evicted_key`
        # call removed. Without it the memory would drop the newest key first.
        self._evicted_keys.move_to_end(key)
        while len(self._evicted_keys) > self.max_evicted_keys:
            self._evicted_keys.popitem(last=False)

    def count_removals(self, count: int = 1) -> None:
        """Count the entries the caller removed.

        Args:
            count: The count of entries the caller removed.
        """
        self.removals += count

    def forget_evicted_keys(self) -> None:
        """Drop the memory of every evicted key.

        The caller runs this method when it empties the table. A key that arrives after
        the table is emptied describes a new run, so it counts as a first sighting.
        """
        self._evicted_keys.clear()

    def build_stats(self, entries: int, max_entries: int) -> TableStats:
        """Return the counts this table reports.

        Args:
            entries: The count of entries the table holds now.
            max_entries: The maximum entry count of the table.

        Returns:
            A `TableStats`.
        """
        return TableStats(
            entries=entries,
            max_entries=max_entries,
            inserts=self.inserts,
            evictions=self.evictions,
            removals=self.removals,
            returned_connections=self.returned_connections,
        )

    def stats(self) -> TableStats:
        """Return the counts this table reports.

        Raises:
            NotImplementedError: The subclass states no count. Every subclass overrides
                this method.
        """
        raise NotImplementedError("A state table reports its counts.")


class BoundedStateTable(StateTable, MutableMapping[Any, Any]):
    """A mapping that evicts an entry on the entry count and on the entry age.

    The table answers the operations a fingerprinter performs on a dictionary. #39
    therefore replaces a dictionary with it and changes nothing else at the call site.

    A read of one key counts as a read of that entry: `__getitem__`, `get` and the `in`
    operator each hold the entry against both bounds. A pass over the whole table holds
    no entry, because `keys`, `values`, `items` and iteration describe the table rather
    than one connection.

    Two operations of a dictionary read differently here, and neither reaches a call
    site today.

    - `dict(table)` reads each key through `__getitem__`, so it holds every entry
      against both bounds. Call `items` for a pass that holds none.
    - `popitem` removes the least recently used entry. A dictionary removes the entry
      it received last.

    Args:
        max_connections: The maximum entry count. The name matches the `Processor`
            argument that `features/03-concurrency-safety.md` publishes.
        max_connection_age: The maximum age of one entry, in seconds.
        eviction_interval: The count of packets between two age eviction passes.
        track_evictions: True remembers the key of every entry the table evicts, and it
            reports `returned_connections`. False remembers no key, and it reports 0
            returned connections. A full table of 100000 entries pays 16.06 MiB for that
            memory, and #359 measured it. Only a caller that reads the count needs it.
        on_eviction: A callable the table calls with the key of every entry it evicts,
            on either bound. The table calls it after it removes the entry. A caller
            that removes an entry itself receives no call, because that caller already
            knows. The hook exists for a second table that holds the same keys, and
            #285 is the first: `SynAckTracker` keeps its prefix table in lockstep with
            its time table through it. A hook that writes to this table produces
            undefined results, because the table calls it inside an eviction.

    Raises:
        ValueError: `max_connections` is below one, or `eviction_interval` is below one.
    """

    def __init__(
        self,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        max_connection_age: float = DEFAULT_MAX_CONNECTION_AGE,
        eviction_interval: int = DEFAULT_EVICTION_INTERVAL,
        track_evictions: bool = True,
        on_eviction: Callable[[Any], None] | None = None,
    ) -> None:
        if max_connections < 1:
            raise ValueError(f"max_connections must be 1 or more, and it is {max_connections}")
        if eviction_interval < 1:
            raise ValueError(f"eviction_interval must be 1 or more, and it is {eviction_interval}")

        # `evictions` counts the entries the table itself removed. `pop` and `del`
        # belong to the caller, so neither raises that count. #41 reports it.
        StateTable.__init__(self, max_evicted_keys=max_connections, track_evictions=track_evictions)

        self.max_connections = max_connections
        self.max_connection_age = max_connection_age
        self.eviction_interval = eviction_interval
        self.on_eviction = on_eviction

        # Each entry is a three-item list: the stored value, the time of the last read,
        # then the thread that read it. `_VALUE`, `_LAST_SEEN` and `_SHARD` name the
        # three positions.
        self._entries: OrderedDict[Any, list[Any]] = OrderedDict()
        self._packets = 0
        self._now: float | None = None

        # The clock of each thread that announces a packet to this table. A caller that
        # gives each thread whole connections puts each thread at its own point of the
        # one timeline, and #461 measured what one shared clock costs there: the thread
        # that stood furthest ahead evicted a connection that a slower thread still
        # read, and the fingerprint of that connection lost a field. The store is a
        # `threading.local`, so a thread that ends takes its reading with it and nothing
        # here grows without a limit.
        self._clock = threading.local()

    def on_packet(self, timestamp: float | None = None) -> None:
        """Announce one packet to the table, and run the age eviction pass on schedule.

        A stated timestamp holds until the next packet of the calling thread arrives,
        and every operation of that thread between the two reads it. A capture file
        replays faster than real time, so a wall clock evicts state the capture still
        needs.

        The reading belongs to the calling thread. A thread that announces no packet
        reads the timestamp of the most recent packet of any thread.

        Warning: one call that states no timestamp moves the table to the wall clock
        for that packet. A replay of a capture recorded in the past then ages out
        whole. A caller states the timestamp on every packet of one capture, or on
        none of them.

        Args:
            timestamp: The packet timestamp, in seconds since the epoch. A caller that
                states None makes the table read the wall clock for each operation,
                until a later packet states a timestamp.
        """
        self._clock.now = timestamp
        self._now = timestamp
        self._packets += 1
        if self._packets % self.eviction_interval == 0:
            self.evict_aged()

    def evict_aged(self, now: float | None = None) -> int:
        """Remove the entries of the calling thread that receive no read for the maximum age.

        The pass holds the entry of every other thread that a packet timestamp dated. A
        caller who gives each thread whole connections gives each thread whole entries.
        Those threads stand at different points of one timeline. A pass that read every
        such entry would let the thread that stands furthest ahead evict a live
        connection of a slower thread. #461 measured the fingerprint that loses. One
        thread owns every entry it stores, so a caller that runs one thread reads the
        pass this class always ran.

        The pass evicts an entry that the wall clock dated, whichever thread stored it.
        One wall clock serves every thread, so those readings compare and no thread owns
        such an entry. `JA4DBClient` builds the one table that reads the wall clock.

        Warning: the entry of a thread that ends stays until the entry count bound
        removes it. The entry count bound is the bound that holds the memory, and the
        age bound holds the memory of a thread that keeps running.

        Args:
            now: The current time, in seconds. A caller that states None makes the
                table read the timestamp of the most recent packet of the calling
                thread, or the wall clock when no packet carried one.

        Returns:
            The count of entries this pass removed.
        """
        if now is None:
            now = self._read_clock()
        shard = threading.get_ident()

        # A packet timestamp and the wall clock can disagree, so the entry order does
        # not follow the entry age. The pass therefore reads every entry.
        removed = 0
        for key, entry in list(self._entries.items()):
            if entry[_SHARD] is not None and entry[_SHARD] != shard:
                continue
            if now - entry[_LAST_SEEN] > self.max_connection_age:
                self.evict_key(key)
                removed += 1

        return removed

    def evict_key(self, key: Any) -> bool:
        """Remove one entry, count it as an eviction, and call the eviction hook.

        The eviction count and the removal count answer two different questions, and
        FR-concurrency-safety-12 asks for the first. This method raises the eviction
        count, so a table that another table drives reports the entries it lost. `pop`
        and `del` raise the removal count instead, because the caller asked for those.

        Args:
            key: The key to remove.

        Returns:
            True when the table held the key, and False when it held no such key.
        """
        if key not in self._entries:
            return False
        del self._entries[key]
        self.count_eviction(key)
        if self.on_eviction is not None:
            self.on_eviction(key)
        return True

    def _stated_clock(self) -> float | None:
        """Return the packet timestamp this operation reads, or None for the wall clock.

        Returns:
            The timestamp of the most recent packet of the calling thread. A thread that
            announced no packet reads the timestamp of the most recent packet of any
            thread. None reports that the operation reads the wall clock.
        """
        # `on_packet(None)` states a reading, so the absence of the attribute is the only
        # way to tell a thread that announced no packet from one that announced a packet
        # with no timestamp.
        if hasattr(self._clock, "now"):
            reading: float | None = self._clock.now
        else:
            reading = self._now
        return reading

    def _read_clock(self) -> float:
        """Return the time the table measures an age against, in seconds.

        Returns:
            The packet timestamp this operation reads, or the wall clock reading when it
            reads no packet timestamp. Both count seconds since the epoch, so the two
            compare.
        """
        reading = self._stated_clock()
        if reading is None:
            return time.time()
        return reading

    def _read_shard(self) -> int | None:
        """Return the thread that owns an entry this operation touches, or None.

        Returns:
            The identifier of the calling thread, when that thread reads a packet
            timestamp. Such a thread stands at its own point of one timeline, so the age
            pass of another thread reads no comparable clock. None reports that the
            operation reads the wall clock, which every thread reads alike, so the entry
            belongs to no thread and every age pass may evict it.
        """
        if self._stated_clock() is None:
            return None
        return threading.get_ident()

    def __getitem__(self, key: Any) -> Any:
        entry = self._entries[key]
        entry[_LAST_SEEN] = self._read_clock()
        entry[_SHARD] = self._read_shard()
        self._entries.move_to_end(key)
        return entry[_VALUE]

    def __setitem__(self, key: Any, value: Any) -> None:
        now = self._read_clock()
        shard = self._read_shard()

        entry = self._entries.get(key)
        if entry is not None:
            entry[_VALUE] = value
            entry[_LAST_SEEN] = now
            entry[_SHARD] = shard
            self._entries.move_to_end(key)
            return

        # The loop rather than one removal covers a caller that lowered the bound after
        # the table filled.
        returned = self.take_evicted_key(key)

        while len(self._entries) >= self.max_connections:
            evicted_key = next(iter(self._entries))
            self.evict_key(evicted_key)
            logger.debug("state table evicts %r on its entry count", evicted_key)

        self._entries[key] = [value, now, shard]
        self.count_insert(returned)

    def __delitem__(self, key: Any) -> None:
        del self._entries[key]
        self.count_removals()

    def __iter__(self) -> Iterator[Any]:
        # A caller that reads a value inside this loop moves that entry to the end, and
        # an OrderedDict refuses that move during its own iteration.
        return iter(list(self._entries))

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, key: object) -> bool:
        entry = self._entries.get(key)
        if entry is None:
            return False
        entry[_LAST_SEEN] = self._read_clock()
        entry[_SHARD] = self._read_shard()
        self._entries.move_to_end(key)
        return True

    def keys(self) -> list[Any]:  # type: ignore[override]  # A list, not a live view.
        """Return the keys, least recently read first. The pass holds no entry.

        The result is a list and not a view. A caller that reads a value inside a loop
        over a live view moves that entry. An OrderedDict refuses that move during its
        own iteration.
        """
        return list(self._entries.keys())

    def values(self) -> list[Any]:  # type: ignore[override]  # A list, not a live view.
        """Return the values, least recently read first. The pass holds no entry."""
        return [entry[_VALUE] for entry in self._entries.values()]

    def items(  # type: ignore[override]  # A list of pairs, not a live view.
        self,
    ) -> list[tuple[Any, Any]]:
        """Return the pairs, least recently read first. The pass holds no entry."""
        return [(key, entry[_VALUE]) for key, entry in self._entries.items()]

    def clear(self) -> None:
        """Remove every entry. The removal belongs to the caller, so it evicts none."""
        self.count_removals(len(self._entries))
        self._entries.clear()
        # A key that arrives after this call describes a new run of the table, so it
        # counts as a first sighting and not as a connection that returned.
        self.forget_evicted_keys()

    def stats(self) -> TableStats:
        """Return the counts this table reports.

        Returns:
            A `TableStats`. The caller holds the lock of the fingerprinter across this
            call, because the six counts describe one instant.
        """
        return self.build_stats(len(self._entries), self.max_connections)

    def __repr__(self) -> str:
        return (
            f"BoundedStateTable(entries={len(self._entries)}, "
            f"max_connections={self.max_connections}, "
            f"max_connection_age={self.max_connection_age})"
        )
