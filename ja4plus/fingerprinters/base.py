"""
Base fingerprinter class for JA4+ fingerprinters.
"""

import logging
import threading

from ja4plus.utils.packet_utils import packet_endpoints
from ja4plus.utils.state_table import StateTable

logger = logging.getLogger(__name__)


class NullLock:
    """A lock placeholder that acquires nothing.

    `Processor(thread_safe=False)` is a promise the caller makes, and
    FR-concurrency-safety-5 states that the processor then acquires no lock. This
    placeholder gives every guarded method one code path, and it holds no lock.

    Its `__enter__` runs no atomic operation, so a second thread never waits on it.
    """

    __slots__ = ()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def __repr__(self):
        return "NullLock()"


# Every fingerprinter that locks none shares this instance. The placeholder holds no
# state, so one instance serves every caller.
NULL_LOCK = NullLock()


class BaseFingerprinter:
    """Base class for all JA4+ fingerprinters.

    Args:
        thread_safe: True makes the fingerprinter guard its own state with a lock.
            False makes it acquire no lock, and the caller then promises that one
            thread at a time calls it.
    """

    def __init__(self, thread_safe=True):
        """Initialize the fingerprinter and its lock."""
        self.fingerprints = []
        self.thread_safe = bool(thread_safe)
        # The lock is a reentrant lock, because `Processor.process_packet` holds it and
        # then calls `process_packet` on this fingerprinter, which holds it again. A
        # `threading.Lock` deadlocks on that second acquisition, and it deadlocks on the
        # first packet. One fingerprinter holds one lock, so ten threads work at once on
        # ten methods.
        self._lock = threading.RLock() if thread_safe else NULL_LOCK

    @property
    def lock(self):
        """Return the lock that guards the state of this fingerprinter.

        `Processor.process_packet` reads `last_raw` after the call that writes it, so
        the processor holds this lock across both operations.

        Returns:
            A `threading.RLock` when the caller asked for a thread-safe fingerprinter,
            and a `NullLock` otherwise.
        """
        return self._lock

    def state_tables(self):
        """Return every state table this fingerprinter holds, keyed by its name.

        The method reads the attributes of the fingerprinter rather than a list each
        subclass writes. A list in ten files goes stale, and #39 found that a list
        written in an issue named six tables where the code held thirteen. A table that
        inherits `StateTable` reaches `Processor.stats` with no further change.

        The search descends one level. `JA4TSFingerprinter` holds a `SynAckTracker`,
        and that tracker holds the table, so the name of that table reads
        `syn_ack_times.times`. No fingerprinter nests a table deeper.

        Returns:
            A dict that maps the attribute name to the state table.
        """
        tables = {}
        for name, value in vars(self).items():
            if isinstance(value, StateTable):
                tables[name] = value
                continue
            inner = getattr(value, "__dict__", None)
            if not inner:
                continue
            for inner_name, inner_value in inner.items():
                if isinstance(inner_value, StateTable):
                    tables[f"{name}.{inner_name}"] = inner_value
        return tables

    def process_packet(self, packet):
        """
        Process a packet and extract fingerprint if applicable.
        This method should be overridden by subclasses.

        Args:
            packet: A network packet to analyze

        Returns:
            The extracted fingerprint if successful, None otherwise
        """
        raise NotImplementedError("Subclasses must implement this method.")

    def add_fingerprint(self, fingerprint, packet):
        """Add a fingerprint to the collection.

        The entry holds the address pair and the port pair of the packet, and it never
        holds the packet. A monitor runs for weeks, and a stored packet holds every
        packet the monitor ever fingerprinted.

        Args:
            fingerprint: The extracted fingerprint.
            packet: The packet that produced this fingerprint. The method reads the
                endpoints of the packet and drops the reference when it returns.
        """
        # This method holds no lock. `list.append` runs as one operation, so a second
        # thread reads the list at no halfway point. Every composite operation over this
        # list sits in a subclass method or in `Processor.process_packet`, and each of
        # those holds the lock. `ja4l.py` holds the one composite: it reads the length
        # and appends after it.
        entry = {"fingerprint": fingerprint}
        entry.update(packet_endpoints(packet))
        self.fingerprints.append(entry)

    def get_fingerprints(self):
        """Return all collected fingerprints."""
        return self.fingerprints

    def reset(self):
        """Reset the fingerprinter state."""
        self.fingerprints = []

    def close_open_windows(self):
        """Emit every window this fingerprinter holds open, and return the new entries.

        The caller runs this method when the packet source ends. JA4SSH is the only
        method that holds a window, so every other fingerprinter uses this no-op.

        Returns:
            A list of the fingerprint entries the call appended. The list is empty when
            the fingerprinter holds no open window.
        """
        return []

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        """
        Remove internal state for the given completed or evicted connection.

        Stateless fingerprinters (JA4, JA4T, JA4D) use this no-op. JA4TS is stateful,
        because part e reads the delay between two SYN-ACK packets.
        Stateful subclasses override to evict per-connection data and prevent
        memory leaks in long-running monitors.

        Args:
            src_ip:   Source IP address string
            src_port: Source port (int)
            dst_ip:   Destination IP address string
            dst_port: Destination port (int)
            proto:    Protocol string, e.g. 'tcp' or 'udp'
        """
