"""A state table that holds a maximum entry count and a maximum age.

Every stateful fingerprinter holds per-connection data across packets, and
`CLAUDE.md` states the rule: nothing that survives across packets grows without a
limit. #179 records six tables that hold no bound today. This class is the one shape
they all move onto, and #39 performs that move.

The table evicts on two conditions.

- The count bound removes the least recently used entry as soon as the table reaches
  `max_connections`. A count bound that waits overshoots the count it states.
- The age bound removes every entry that receives no read for `max_connection_age`
  seconds. `on_packet` runs that pass, and it runs it once for every
  `eviction_interval` packets, so the eviction cost stays proportional to the traffic.

The library starts no thread. Eviction runs on packet arrival.
"""

import logging
import time
from collections import OrderedDict
from collections.abc import MutableMapping

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
_VALUE = 0
_LAST_SEEN = 1


class BoundedStateTable(MutableMapping):
    """A mapping that evicts an entry on the entry count and on the entry age.

    The table answers the operations a fingerprinter performs on a dictionary. #39
    therefore replaces a dictionary with it and changes nothing else at the call site.

    A read of one key counts as a read of that entry: `__getitem__`, `get` and the `in`
    operator each hold the entry against both bounds. A pass over the whole table holds
    no entry, because `keys`, `values`, `items` and iteration describe the table rather
    than one connection.

    Args:
        max_connections: The maximum entry count. The name matches the `Processor`
            argument that `features/03-concurrency-safety.md` publishes.
        max_connection_age: The maximum age of one entry, in seconds.
        eviction_interval: The count of packets between two age eviction passes.

    Raises:
        ValueError: `max_connections` is below one, or `eviction_interval` is below one.
    """

    def __init__(
        self,
        max_connections=DEFAULT_MAX_CONNECTIONS,
        max_connection_age=DEFAULT_MAX_CONNECTION_AGE,
        eviction_interval=DEFAULT_EVICTION_INTERVAL,
    ):
        if max_connections < 1:
            raise ValueError(f"max_connections must be 1 or more, and it is {max_connections}")
        if eviction_interval < 1:
            raise ValueError(f"eviction_interval must be 1 or more, and it is {eviction_interval}")

        self.max_connections = max_connections
        self.max_connection_age = max_connection_age
        self.eviction_interval = eviction_interval

        # The count of entries the table itself removed. `pop` and `del` belong to the
        # caller, so neither raises this count. #41 reports it.
        self.evictions = 0

        self._entries = OrderedDict()
        self._packets = 0
        self._now = None

    def on_packet(self, timestamp=None):
        """Announce one packet to the table, and run the age eviction pass on schedule.

        The table reads this timestamp for every later operation, until the next packet
        arrives. A capture file replays faster than real time, so a wall clock evicts
        state the capture still needs.

        Args:
            timestamp: The packet timestamp, in seconds since the epoch. A caller that
                states None makes the table read the wall clock instead.
        """
        self._now = timestamp
        self._packets += 1
        if self._packets % self.eviction_interval == 0:
            self.evict_aged()

    def evict_aged(self, now=None):
        """Remove every entry that receives no read for `max_connection_age` seconds.

        Args:
            now: The current time, in seconds. A caller that states None makes the
                table read the timestamp of the most recent packet, or the wall clock
                when no packet carried one.

        Returns:
            The count of entries this pass removed.
        """
        if now is None:
            now = self._read_clock()

        # A packet timestamp and the wall clock can disagree, so the entry order does
        # not follow the entry age. The pass therefore reads every entry.
        removed = 0
        for key, entry in list(self._entries.items()):
            if now - entry[_LAST_SEEN] > self.max_connection_age:
                del self._entries[key]
                removed += 1

        self.evictions += removed
        return removed

    def _read_clock(self):
        """Return the time the table measures an age against, in seconds.

        Returns:
            The timestamp of the most recent packet, or the wall clock reading when no
            packet carried one. Both read seconds since the epoch, so the two compare.
        """
        if self._now is None:
            return time.time()
        return self._now

    def __getitem__(self, key):
        entry = self._entries[key]
        entry[_LAST_SEEN] = self._read_clock()
        self._entries.move_to_end(key)
        return entry[_VALUE]

    def __setitem__(self, key, value):
        now = self._read_clock()

        entry = self._entries.get(key)
        if entry is not None:
            entry[_VALUE] = value
            entry[_LAST_SEEN] = now
            self._entries.move_to_end(key)
            return

        # The loop rather than one removal covers a caller that lowered the bound after
        # the table filled.
        while len(self._entries) >= self.max_connections:
            evicted_key, _ = self._entries.popitem(last=False)
            self.evictions += 1
            logger.debug("state table evicts %r on its entry count", evicted_key)

        self._entries[key] = [value, now]

    def __delitem__(self, key):
        del self._entries[key]

    def __iter__(self):
        # A caller that reads a value inside this loop moves that entry to the end, and
        # an OrderedDict refuses that move during its own iteration.
        return iter(list(self._entries))

    def __len__(self):
        return len(self._entries)

    def __contains__(self, key):
        entry = self._entries.get(key)
        if entry is None:
            return False
        entry[_LAST_SEEN] = self._read_clock()
        self._entries.move_to_end(key)
        return True

    def keys(self):
        """Return the keys, least recently read first. The pass holds no entry."""
        return self._entries.keys()

    def values(self):
        """Return the values, least recently read first. The pass holds no entry."""
        return [entry[_VALUE] for entry in self._entries.values()]

    def items(self):
        """Return the pairs, least recently read first. The pass holds no entry."""
        return [(key, entry[_VALUE]) for key, entry in self._entries.items()]

    def clear(self):
        """Remove every entry. The removal belongs to the caller, so it counts none."""
        self._entries.clear()

    def __repr__(self):
        return (
            f"BoundedStateTable(entries={len(self._entries)}, "
            f"max_connections={self.max_connections}, "
            f"max_connection_age={self.max_connection_age})"
        )
