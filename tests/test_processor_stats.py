"""The statistics `Processor.stats` reports, FR-concurrency-safety-11 and -12.

`docs/specs/features/03-concurrency-safety.md` states the requirements. #41 owns them.

Two cases at the end measure the guard. `Processor.stats` reads the counts of one
method under the lock of that method, and the pair proves what the lock buys: the
guarded case reports a consistent snapshot, and the unguarded case reports a broken
one. Each forces the race with a `threading.Event` rather than sampling it, the way
`tests/test_thread_safety.py` does. A case that starts threads and hopes for an
interleaving measures nothing.
"""

import threading
from pathlib import Path

import pytest
from scapy.all import rdpcap

from ja4plus.processor import Processor, ProcessorStats
from ja4plus.utils.state_table import BoundedStateTable, StateTable, TableStats
from ja4plus.utils.tcp_stream import TCPStreamReassembler

VECTORS = Path(__file__).parent / "foxio_vectors"

# The capture the cases replay. It holds 209 packets over several connections, and one
# pass costs well under a second.
CAPTURE = "latest.pcapng"

# The count of state tables the ten methods hold. #39 moved thirteen tables to
# `BoundedStateTable`, and the two reassemblers of JA4H and JA4X carry their own bounds,
# so the report covers fifteen. The case below re-measures the count rather than trusting
# this number.
STATE_TABLE_COUNT = 15

# The seconds a case waits for a thread. A case that hangs reports nothing, so every
# wait states a limit.
JOIN_TIMEOUT = 60

# The seconds the reader thread gets before the case releases the writer. The guarded
# reader waits for the writer, so it returns nothing inside this time. The unguarded
# reader returns at once.
READER_GRACE = 0.5


@pytest.fixture(scope="module")
def packets():
    """Return the packets of the replay capture."""
    return list(rdpcap(str(VECTORS / CAPTURE)))


def walk_state_tables(fingerprinter):
    """Return every state table of one fingerprinter, found without `state_tables`.

    The case that counts the tables must not read the same code it measures, so this
    function walks the attributes itself.

    Args:
        fingerprinter: One fingerprinter.

    Returns:
        A list of the state tables.
    """
    found = []
    for value in vars(fingerprinter).values():
        if isinstance(value, StateTable):
            found.append(value)
            continue
        for inner in getattr(value, "__dict__", {}).values():
            if isinstance(inner, StateTable):
                found.append(inner)
    return found


def snapshot_holds(table_stats):
    """Report whether one `TableStats` holds the count invariant.

    Every key the table ever added is either an entry it holds now, an entry the table
    evicted, or an entry the caller removed.

    Args:
        table_stats: One `TableStats`.

    Returns:
        True when the counts agree.
    """
    return table_stats.inserts == (
        table_stats.entries + table_stats.evictions + table_stats.removals
    )


class TestTheReport:
    """`Processor.stats` returns one entry per method."""

    def test_the_report_holds_one_entry_for_each_method(self):
        processor = Processor()
        report = processor.stats()
        assert sorted(report) == sorted(processor.fingerprinters)
        assert len(report) == 10

    def test_each_entry_reports_the_entry_count_the_evictions_and_the_packets(self):
        report = Processor().stats()
        for method, stats in report.items():
            assert isinstance(stats, ProcessorStats), method
            assert stats.method == method
            assert stats.entries == 0
            assert stats.evictions == 0
            assert stats.packets == 0

    def test_the_report_names_every_state_table_of_every_method(self):
        processor = Processor()
        report = processor.stats()

        reported = 0
        for method, fingerprinter in processor.fingerprinters.items():
            walked = walk_state_tables(fingerprinter)
            assert len(report[method].tables) == len(walked), method
            reported += len(walked)
        assert reported == STATE_TABLE_COUNT

    def test_each_state_table_reports_a_table_stats(self):
        report = Processor().stats()
        for method, stats in report.items():
            for name, table_stats in stats.tables.items():
                assert isinstance(table_stats, TableStats), f"{method}.{name}"
                assert table_stats.max_entries >= 1
                assert snapshot_holds(table_stats)

    def test_the_ja4ts_table_reports_under_its_nested_name(self):
        report = Processor().stats()
        assert sorted(report["ja4ts"].tables) == ["syn_ack_times.times"]

    def test_a_method_that_holds_no_state_table_reports_no_table(self):
        report = Processor().stats()
        assert report["ja4t"].tables == {}
        assert report["ja4t"].entries == 0

    def test_the_method_totals_add_the_counts_of_its_tables(self):
        processor = Processor()
        processor.ja4l.connections["a"] = 1
        processor.ja4l.grouping_keys["b"] = 2
        stats = processor.stats()["ja4l"]
        assert stats.tables["connections"].entries == 1
        assert stats.tables["grouping_keys"].entries == 1
        assert stats.entries == 2

    def test_the_report_reads_a_repr_that_names_the_method(self):
        stats = Processor().stats()["ja4h"]
        assert "ja4h" in repr(stats)
        assert "TableStats(entries=" in repr(stats.tables["consumed_seq"])


class TestThePacketCount:
    """The processor counts the packets it gives to each method."""

    def test_the_packet_count_rises_by_one_for_each_packet(self, packets):
        processor = Processor()
        for packet in packets[:20]:
            processor.process_packet(packet)
        report = processor.stats()
        for method, stats in report.items():
            assert stats.packets == 20, method

    def test_the_packet_count_counts_a_packet_that_produces_no_fingerprint(self):
        from scapy.all import IP, UDP, Ether

        processor = Processor()
        processor.process_packet(Ether() / IP() / UDP(sport=1, dport=2) / b"\x00")
        assert processor.stats()["ja4"].packets == 1

    def test_reset_returns_every_packet_count_to_zero(self, packets):
        processor = Processor()
        for packet in packets[:20]:
            processor.process_packet(packet)
        processor.reset()
        report = processor.stats()
        for method, stats in report.items():
            assert stats.packets == 0, method
            assert stats.entries == 0, method


class TestTheEvictionCount:
    """The processor reports how many entries it evicted."""

    def test_the_entry_count_bound_raises_the_eviction_count(self):
        processor = Processor()
        processor.ja4l.connections.max_connections = 2
        for index in range(5):
            processor.ja4l.connections[("connection", index)] = index
        stats = processor.stats()["ja4l"].tables["connections"]
        assert stats.entries == 2
        assert stats.evictions == 3
        assert stats.inserts == 5
        assert snapshot_holds(stats)

    def test_the_age_bound_raises_the_eviction_count(self):
        processor = Processor()
        table = processor.ja4l.connections
        table.on_packet(1000.0)
        table[("connection", 0)] = 0
        table.on_packet(1000.0 + table.max_connection_age + 1)
        table.evict_aged()
        stats = processor.stats()["ja4l"].tables["connections"]
        assert stats.entries == 0
        assert stats.evictions == 1

    def test_a_removal_the_caller_asks_for_evicts_nothing(self):
        processor = Processor()
        table = processor.ja4l.connections
        table[("connection", 0)] = 0
        del table[("connection", 0)]
        stats = processor.stats()["ja4l"].tables["connections"]
        assert stats.evictions == 0
        assert stats.removals == 1
        assert snapshot_holds(stats)

    def test_the_dictionary_operations_the_table_inherits_count_their_removals(self):
        # `BoundedStateTable` inherits `pop`, `popitem`, `setdefault` and `update` from
        # `MutableMapping`, and each reaches `__setitem__` or `__delitem__`. A count
        # that sits in one of those four instead would miss these call sites.
        # `SynAckTracker.drop` calls `pop`, at `ja4plus/fingerprinters/ja4ts.py:74`.
        table = BoundedStateTable(max_connections=4)
        table.update({"a": 1, "b": 2})
        table.setdefault("c", 3)
        table.setdefault("c", 4)
        table.pop("a")
        table.pop("absent", None)
        table.popitem()
        stats = table.stats()
        assert stats.inserts == 3
        assert stats.removals == 2
        assert stats.evictions == 0
        assert snapshot_holds(stats)

    def test_clear_removes_every_entry_and_evicts_none(self):
        table = BoundedStateTable()
        table["a"] = 1
        table["b"] = 2
        table.clear()
        stats = table.stats()
        assert stats.evictions == 0
        assert stats.removals == 2
        assert snapshot_holds(stats)


class TestTheReturnedConnections:
    """A connection that returns after an eviction reaches the statistics."""

    def test_a_connection_that_returns_after_an_eviction_counts_one(self):
        table = BoundedStateTable(max_connections=2)
        table["a"] = 1
        table["b"] = 2
        table["c"] = 3
        assert "a" not in table
        table["a"] = 4
        assert table.stats().returned_connections == 1

    def test_a_first_sighting_counts_no_returned_connection(self):
        table = BoundedStateTable(max_connections=2)
        table["a"] = 1
        table["b"] = 2
        table["c"] = 3
        assert table.stats().evictions == 1
        assert table.stats().returned_connections == 0

    def test_a_connection_the_caller_removed_counts_no_returned_connection(self):
        table = BoundedStateTable()
        table["a"] = 1
        del table["a"]
        table["a"] = 2
        assert table.stats().returned_connections == 0

    def test_the_count_rises_once_for_each_return(self):
        # The table holds one entry, so each write evicts the other key. Key `a`
        # arrives three times and returns twice. Key `b` arrives twice and returns
        # once. The count reports every return, not the count of distinct connections.
        table = BoundedStateTable(max_connections=1)
        for key in ["a", "b", "a", "b", "a"]:
            table[key] = key
        assert table.stats().returned_connections == 3

    def test_an_entry_the_table_holds_counts_no_returned_connection(self):
        table = BoundedStateTable()
        table["a"] = 1
        table["a"] = 2
        assert table.stats().inserts == 1
        assert table.stats().returned_connections == 0

    def test_the_age_bound_marks_the_connection_that_returns(self):
        table = BoundedStateTable(max_connection_age=10)
        table.on_packet(1000.0)
        table["a"] = 1
        table.on_packet(1100.0)
        table.evict_aged()
        table["a"] = 2
        assert table.stats().returned_connections == 1

    def test_clear_makes_the_next_arrival_a_first_sighting(self):
        table = BoundedStateTable(max_connections=1)
        table["a"] = 1
        table["b"] = 2
        table.clear()
        table["a"] = 3
        assert table.stats().returned_connections == 0

    def test_the_memory_of_the_evicted_keys_holds_the_entry_bound(self):
        table = BoundedStateTable(max_connections=4)
        for index in range(100):
            table[index] = index
        assert len(table._evicted_keys) == 4

    def test_the_processor_reports_a_returned_connection_for_a_method(self):
        processor = Processor()
        processor.ja4l.connections.max_connections = 1
        processor.ja4l.connections["a"] = 1
        processor.ja4l.connections["b"] = 2
        processor.ja4l.connections["a"] = 3
        stats = processor.stats()["ja4l"]
        assert stats.returned_connections == 1
        assert stats.tables["connections"].returned_connections == 1


class TestTheReassembler:
    """The two TCP reassemblers report the counts every state table reports."""

    def test_the_reassembler_is_a_state_table(self):
        assert isinstance(TCPStreamReassembler(), StateTable)

    def test_the_reassembler_reports_its_stream_count(self):
        reassembler = TCPStreamReassembler(max_streams=3)
        reassembler.add_segment("a", 1, b"one")
        reassembler.add_segment("b", 1, b"two")
        stats = reassembler.stats()
        assert stats.entries == 2
        assert stats.max_entries == 3
        assert stats.inserts == 2
        assert snapshot_holds(stats)

    def test_the_stream_count_bound_raises_the_eviction_count(self):
        reassembler = TCPStreamReassembler(max_streams=2)
        for index in range(5):
            reassembler.add_segment(index, 1, b"payload")
        stats = reassembler.stats()
        assert stats.entries == 2
        assert stats.evictions == 3
        assert snapshot_holds(stats)

    def test_the_stream_age_bound_raises_the_eviction_count(self):
        reassembler = TCPStreamReassembler(max_stream_age=10)
        reassembler.add_segment("a", 1, b"one", timestamp=1000.0)
        reassembler.add_segment("b", 1, b"two", timestamp=1100.0)
        stats = reassembler.stats()
        assert stats.evictions == 1
        assert snapshot_holds(stats)

    def test_a_stream_the_caller_removes_evicts_nothing(self):
        reassembler = TCPStreamReassembler()
        reassembler.add_segment("a", 1, b"one")
        reassembler.remove_stream("a")
        stats = reassembler.stats()
        assert stats.removals == 1
        assert stats.evictions == 0
        assert snapshot_holds(stats)

    def test_a_stream_key_the_reassembler_never_held_removes_nothing(self):
        reassembler = TCPStreamReassembler()
        reassembler.remove_stream("a")
        assert reassembler.stats().removals == 0

    def test_a_stream_that_returns_after_an_eviction_counts_one(self):
        reassembler = TCPStreamReassembler(max_streams=1)
        reassembler.add_segment("a", 1, b"one")
        reassembler.add_segment("b", 1, b"two")
        reassembler.add_segment("a", 1, b"three")
        assert reassembler.stats().returned_connections == 1

    def test_the_processor_reports_the_reassembler_of_ja4h_and_ja4x(self):
        report = Processor().stats()
        assert "reassembler" in report["ja4h"].tables
        assert "reassembler" in report["ja4x"].tables


class TestAReplay:
    """The report describes a capture the processor read."""

    def test_a_replay_reports_a_packet_count_and_an_entry_count(self, packets):
        processor = Processor()
        for packet in packets:
            processor.process_packet(packet)
        report = processor.stats()
        assert report["ja4l"].packets == len(packets)
        assert report["ja4l"].entries > 0

    def test_a_replay_holds_the_count_invariant_of_every_table(self, packets):
        processor = Processor()
        for packet in packets:
            processor.process_packet(packet)
        for method, stats in processor.stats().items():
            for name, table_stats in stats.tables.items():
                assert snapshot_holds(table_stats), f"{method}.{name} {table_stats}"

    def test_a_replay_evicts_nothing_from_a_committed_capture(self, packets):
        processor = Processor()
        for packet in packets:
            processor.process_packet(packet)
        for method, stats in processor.stats().items():
            assert stats.evictions == 0, method
            assert stats.returned_connections == 0, method


class PausingTable(BoundedStateTable):
    """A table that holds the writer inside the window `__setitem__` holds open.

    `BoundedStateTable.__setitem__` stores the new entry, and it calls `count_insert`
    after that store. Between the two steps the table holds one entry that `inserts`
    does not count, so a reader that reads the counts there reports
    `inserts == entries + evictions + removals - 1`.

    The window is one statement wide in the production code. This subclass holds the
    writer inside it, so a case forces the race rather than sampling it. The subclass
    changes no other behaviour.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.entered = threading.Event()
        self.release = threading.Event()

    def count_insert(self, returned=False):
        self.entered.set()
        self.release.wait(timeout=JOIN_TIMEOUT)
        super().count_insert(returned)


def run_the_snapshot_race(thread_safe):
    """Read the statistics while one thread sits inside the window of `__setitem__`.

    Args:
        thread_safe: The value the case gives `Processor`.

    Returns:
        A tuple of two booleans. The first states that the reader returned before the
        case released the writer. The second states that the snapshot holds the count
        invariant.
    """
    processor = Processor(thread_safe=thread_safe)
    fingerprinter = processor.ja4l
    table = PausingTable()
    fingerprinter.connections = table

    # The fill runs through the same code, so it pauses too unless the case releases it.
    table.release.set()
    for index in range(3):
        table[("filled", index)] = index
    table.release.clear()
    table.entered.clear()

    def write():
        # `Processor.process_packet` writes a state table under the lock of that
        # fingerprinter, and this thread does the same.
        with fingerprinter.lock:
            table[("writer", 0)] = 0

    result = {}

    def read():
        result["report"] = processor.stats()

    writer = threading.Thread(target=write)
    writer.start()
    assert table.entered.wait(timeout=JOIN_TIMEOUT), "the writer never reached the window"

    reader = threading.Thread(target=read)
    reader.start()
    reader.join(timeout=READER_GRACE)
    read_before_release = "report" in result

    table.release.set()
    writer.join(timeout=JOIN_TIMEOUT)
    reader.join(timeout=JOIN_TIMEOUT)
    assert "report" in result, "the reader never returned"

    return read_before_release, snapshot_holds(result["report"]["ja4l"].tables["connections"])


class TestTheGuard:
    """The lock of one method holds the snapshot of that method consistent."""

    def test_the_reader_waits_for_the_writer_and_reports_a_consistent_snapshot(self):
        read_before_release, holds = run_the_snapshot_race(thread_safe=True)
        assert not read_before_release
        assert holds

    def test_a_reader_that_acquires_nothing_reports_a_broken_snapshot(self):
        # `Processor(thread_safe=False)` states that the caller runs one thread, and
        # this case breaks that promise on purpose. It measures what the guard buys:
        # the same experiment against the same code, with the lock removed.
        read_before_release, holds = run_the_snapshot_race(thread_safe=False)
        assert read_before_release
        assert not holds
