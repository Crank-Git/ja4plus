"""The memory bound of a `Processor`, FR-concurrency-safety-7 and -8.

`tests/test_state_table.py` measures `BoundedStateTable` on its own, and
`tests/test_bounded_state_table_adoption.py` measures each table against the two bounds
it states. Neither answers the question an operator asks: does one processor stop
growing when the traffic never stops? This file answers it, and it answers it in three
shapes.

1. A walk of a live `Processor()` finds every mapping that survives across packets. A
   hardcoded list cannot report a table that a later change adds, and the walk can.
2. A flood of distinct connections runs twice. The entry count after the second flood
   equals the entry count after the first, and the eviction count rises between the two.
   A flat entry count alone proves nothing, because a flood that reaches no table is
   also flat.
3. One case records the structure that holds no bound, so a reader does not read
   "every table is bounded" as "the processor is bounded".
4. One case reads the memory ceiling this package states. #279 added it.

`TestTheStatedMemoryCeiling` holds the fourth shape. The user decided 512 MiB on
2026-08-08, and `features/03-concurrency-safety.md` states the number, the defaults it
holds at, and the case it covers. The ceiling covers the one-million-packet case and no
longer run, because `BaseFingerprinter.fingerprints` grows without a limit.

Every case here is proven by its removal, and #43 ran each removal three times against
the base commit `0e377b0`.

- The entry count eviction of `BoundedStateTable.__setitem__` removed: 3 of 3 runs fail,
  and 8 cases fail on each run.
- The age eviction pass of `BoundedStateTable.evict_aged` removed: 3 of 3 runs fail, and
  1 case fails on each run.
- The `max_streams` eviction of `TCPStreamReassembler.add_segment` removed: 3 of 3 runs
  fail, and 4 cases fail on each run.
- The returned connection count of `StateTable.count_insert` removed: 3 of 3 runs fail.
- The nested descent of `BaseFingerprinter.state_tables` removed: 3 of 3 runs fail. That
  descent is what reaches `SynAckTracker.times`, and a walk without it reads 14.

Every fingerprinter lock removed fails 0 of 3 runs here, which is the correct reading:
every case in this file runs on one thread. `tests/test_thread_safety.py` measures the
locks.
"""

import importlib.util
import json
import os
import subprocess
import sys
from collections import OrderedDict
from pathlib import Path

import pytest
from scapy.all import IP, TCP, UDP, Raw

from ja4plus.processor import Processor
from ja4plus.utils.state_table import BoundedStateTable, StateTable
from ja4plus.utils.tcp_stream import TCPStreamReassembler

# The count of state tables one processor holds. The count moved four times, and each
# move improved the way the project counts rather than the code: #179 read six, #39 read
# thirteen, #41 read fifteen, and #43 re-measured fifteen. #285 re-measured it after the
# merge of #246 and reads sixteen, because `SynAckTracker.prefixes` is now a
# `BoundedStateTable`. #215 reads seventeen, because JA4T holds a connection table of
# its own. The number is a literal, so a table that a later change adds fails this file
# rather than passing it unread.
STATE_TABLE_COUNT = 17

# The count of those seventeen that are a `BoundedStateTable`. The other two are the
# `TCPStreamReassembler` of JA4H and of JA4X. #41 made `TCPStreamReassembler` inherit
# `StateTable`, and each one keeps the two bounds it already held.
BOUNDED_TABLE_COUNT = 15
STREAM_TABLE_COUNT = 2

# The entry count each table holds while a case floods the processor. A small bound
# saturates every table inside a few hundred connections, so the case stays cheap.
SMALL_BOUND = 25

# The connections one flood builds. The value saturates a bound of 25 many times over.
FLOOD_CONNECTIONS = 400

# The memory ceiling this package states, in MiB. The user decided the number on
# 2026-08-08, and `features/03-concurrency-safety.md` states it beside the defaults it
# holds at. A measurement forces the floor and forces no ceiling, so the distance above
# the floor is a product judgement and no case here may derive the number.
MEMORY_CEILING_MIB = 512.0

# The packets the ceiling case feeds. The acceptance criterion states 1000000 packets
# across 100000 connections, and #279 measured that run at 481 seconds. A case of that
# length costs every later run of the unit suite, so the default holds the case cheap and
# the pull request records one run at 1000000. `tests/test_thread_safety.py` holds the
# same arrangement for the 60-second soak of #40.
CEILING_PACKETS = int(os.environ.get("JA4PLUS_MEMORY_CEILING_PACKETS", "30000"))

# The packets one connection carries. `ceiling_traffic` returns ten, so the case spreads
# its packets across one tenth as many connections.
PACKETS_PER_CONNECTION = 10

# The connections the case builds, and the packets it feeds across them. The run stops on
# a whole connection, so a count that is no multiple of ten rounds down here rather than
# failing a case that reads the count back.
CEILING_CONNECTIONS = max(CEILING_PACKETS // PACKETS_PER_CONNECTION, 1)
CEILING_RUN_PACKETS = CEILING_CONNECTIONS * PACKETS_PER_CONNECTION

# The entry count the control run gives every state table. A run whose tables hold 100
# entries reads less resident memory than a run whose tables hold every connection.
CONTROL_BOUND = 100

# The share of the shipped run's memory that the control run may reach. The reading is a
# ratio and not a MiB figure, because the absolute numbers move with the platform and the
# interpreter while the ratio measures the bound itself. #279 read five runs at the
# default size: the ratio held between 0.746 and 0.769, and a control bound raised to the
# shipped 10000 read 0.955. The threshold sits between the two.
CONTROL_GROWTH_RATIO = 0.85

# The MiB the shipped run must add before the ratio above means anything. A run that added
# nothing would divide one small number by another.
CONTROL_FLOOR_MIB = 10.0

# The seconds one measurement may take. #279 read 481 seconds for 1000000 packets on a
# ten-core laptop, so the limit holds about four times that rate.
CEILING_TIMEOUT = 120 + CEILING_PACKETS // 500

CEILING_RUNNER = Path(__file__).resolve().with_name("memory_ceiling_run.py")


def walk_tables(processor):
    """Return every bounded state table of a processor, keyed by its path.

    Args:
        processor: A live `Processor`.

    Returns:
        A dict that maps a dotted path to the `BoundedStateTable` at that path.
    """
    found = {}
    for name, fingerprinter in processor.fingerprinters.items():
        for holder_name, holder in _holders(name, fingerprinter):
            for attribute, value in vars(holder).items():
                if isinstance(value, BoundedStateTable):
                    found[f"{holder_name}.{attribute}"] = value
    return found


def walk_reassemblers(processor):
    """Return every `TCPStreamReassembler` of a processor, keyed by its path."""
    found = {}
    for name, fingerprinter in processor.fingerprinters.items():
        reassembler = getattr(fingerprinter, "reassembler", None)
        if isinstance(reassembler, TCPStreamReassembler):
            found[f"{name}.reassembler"] = reassembler
    return found


def _holders(name, fingerprinter):
    """Return each object of one fingerprinter that can hold a state table.

    `JA4TSFingerprinter` keeps its table on `syn_ack_times`, and JA4H and JA4X each keep
    one on `reassembler`. A walk that reads the fingerprinter alone misses all three.
    """
    holders = [(name, fingerprinter)]
    for attribute in ("syn_ack_times", "reassembler"):
        nested = getattr(fingerprinter, attribute, None)
        if nested is not None:
            holders.append((f"{name}.{attribute}", nested))
    return holders


def lower_every_bound(processor, count=SMALL_BOUND):
    """Lower the entry count of every table of a processor, and return the table count.

    A shipped bound of 10000 needs 10000 connections to saturate, and the flood then
    costs minutes. A lowered bound measures the same mechanism in a few hundred.

    Args:
        processor: A live `Processor`.
        count: The maximum entry count every table reads after the call.

    Returns:
        The count of tables the call changed.
    """
    tables = walk_tables(processor)
    for table in tables.values():
        table.max_connections = count
    for reassembler in walk_reassemblers(processor).values():
        reassembler.max_streams = count
    return len(tables)


def _tcp(src, sport, dst, dport, flags, seconds, payload=None):
    """Return one TCP packet that carries the stated capture timestamp."""
    packet = IP(src=src, dst=dst, ttl=64) / TCP(sport=sport, dport=dport, flags=flags)
    if payload is not None:
        packet = packet / Raw(load=payload)
    packet.time = seconds
    return packet


def connection_traffic(index, second):
    """Return the packets of one connection, each with its own capture timestamp.

    The traffic reaches every stateful method, so one connection builds an entry in
    every table the processor holds.

    Args:
        index: The connection number. It decides the client address and the client port.
        second: The capture timestamp of every packet, in seconds since the epoch.

    Returns:
        A list of six packets: a SYN, a SYN-ACK, one SSH record, one HTTP request, one
        TLS record and one QUIC Initial packet. The list carries no final ACK, because
        the case seeds a state table rather than completing a handshake. Call
        `handshake` for the three packets JA4L reads as one connection.
    """
    client = f"10.{(index >> 16) & 0xFF}.{(index >> 8) & 0xFF}.{index & 0xFF}"
    port = 20000 + (index % 40000)
    http = b"GET /a HTTP/1.1\r\nHost: e.com\r\nUser-Agent: t\r\n\r\n"
    ssh = b"\x00\x00\x00\x20\x0a" + b"z" * 27
    tls = b"\x16\x03\x03\x00\x20" + b"\x00" * 32
    quic = b"\xc0\x00\x00\x00\x01\x04\xaa\xbb\xcc\xdd\x00" + b"\x00" * 40
    packets = [
        _tcp(client, port, "10.9.9.9", 22, "S", second),
        _tcp("10.9.9.9", 22, client, port, "SA", second),
        _tcp(client, port, "10.9.9.9", 22, "PA", second, payload=ssh),
        _tcp(client, port, "10.9.9.9", 80, "PA", second, payload=http),
        _tcp(client, port, "10.9.9.9", 443, "PA", second, payload=tls),
        IP(src=client, dst="10.9.9.9") / UDP(sport=port, dport=443) / Raw(load=quic),
    ]
    packets[-1].time = second
    return packets


def ceiling_traffic(index, second):
    """Return the ten packets of one connection, each with its own capture timestamp.

    The acceptance criterion of #279 states 1000000 packets across 100000 distinct
    connections, which is ten packets for each connection. `connection_traffic` returns
    six, so this function repeats the three payload packets and closes with a bare ACK.

    Args:
        index: The connection number. It decides the client address and the client port.
        second: The capture timestamp of the first packet, in seconds since the epoch.

    Returns:
        A list of ten packets on one connection.
    """
    client = f"10.{(index >> 16) & 0xFF}.{(index >> 8) & 0xFF}.{index & 0xFF}"
    port = 20000 + (index % 40000)
    ssh = b"\x00\x00\x00\x20\x0a" + b"y" * 27
    http = b"GET /b HTTP/1.1\r\nHost: e.com\r\nUser-Agent: t\r\n\r\n"
    tls = b"\x16\x03\x03\x00\x20" + b"\x11" * 32
    return connection_traffic(index, second) + [
        _tcp(client, port, "10.9.9.9", 22, "PA", second + 0.01, payload=ssh),
        _tcp(client, port, "10.9.9.9", 80, "PA", second + 0.02, payload=http),
        _tcp(client, port, "10.9.9.9", 443, "PA", second + 0.03, payload=tls),
        _tcp(client, port, "10.9.9.9", 443, "A", second + 0.04),
    ]


def handshake(index, second):
    """Return the three packets of one TCP handshake, each with a capture timestamp.

    One handshake builds exactly one entry of `JA4LFingerprinter.connections`, so a case
    that counts entries reads the count it states. `connection_traffic` reaches four
    ports, and JA4L then reads four connections rather than one.

    Args:
        index: The connection number. It decides the client address and the client port.
        second: The capture timestamp of the SYN packet, in seconds since the epoch.

    Returns:
        A list of the SYN, the SYN-ACK and the ACK packet, in that order.
    """
    client = f"10.{(index >> 16) & 0xFF}.{(index >> 8) & 0xFF}.{index & 0xFF}"
    port = 20000 + (index % 40000)
    return [
        _tcp(client, port, "10.9.9.9", 443, "S", second),
        _tcp("10.9.9.9", 443, client, port, "SA", second + 0.010),
        _tcp(client, port, "10.9.9.9", 443, "A", second + 0.020),
    ]


def flood(processor, first_index, connections=FLOOD_CONNECTIONS, start=1000.0):
    """Feed one processor the traffic of many distinct connections.

    Each connection carries a capture timestamp 0.1 seconds after the one before it, so
    no entry ages out inside one flood. The count bound is therefore the only bound the
    flood measures.

    Args:
        processor: A live `Processor`.
        first_index: The connection number the flood starts at. A second flood states a
            later number, so it builds connections the first flood never built.
        connections: The count of connections to build.
        start: The capture timestamp of the first connection, in seconds.

    Returns:
        The count of packets the flood fed.
    """
    fed = 0
    for offset in range(connections):
        index = first_index + offset
        for packet in connection_traffic(index, start + index * 0.1):
            processor.process_packet(packet)
            fed += 1
    return fed


def total_entries(processor):
    """Return the count of entries every state table of a processor holds."""
    counted = sum(len(table) for table in walk_tables(processor).values())
    return counted + sum(len(r.streams) for r in walk_reassemblers(processor).values())


def total_evictions(processor):
    """Return the count of entries every state table of a processor evicted."""
    return sum(table.evictions for table in walk_tables(processor).values())


def traffic_growth_mib(reading):
    """Return the resident memory the traffic of one run added, in MiB.

    A high-water mark rises and never falls, so the difference between two of them is
    `max(0, later mark - earlier mark)` and not the growth between the two readings. The
    import of scapy reaches a mark that the traffic then stays below, and the difference
    is then exactly zero on a run that allocated tens of MiB. The Ubuntu jobs of pull
    request #384 read `idle_mib 154.7` and `peak_mib 154.7` for that reason, and the same
    run on macOS read a difference because the import cost less there. This function
    therefore reads the two current resident readings and subtracts no high-water mark.

    Args:
        reading: One JSON object of `tests/memory_ceiling_run.py`.

    Returns:
        The MiB the traffic added to the resident set. The number may be negative, and a
        caller that needs a positive reading states that comparison itself.

    Raises:
        ValueError: The reading carries no current resident pair. Such a reading states
            nothing about the traffic, and it is void rather than zero.
    """
    pair = ("idle_resident_mib", "final_resident_mib")
    if any(key not in reading for key in pair):
        raise ValueError(
            "the reading holds no current resident pair, so the measurement is void: "
            f"{sorted(reading)}"
        )
    return reading["final_resident_mib"] - reading["idle_resident_mib"]


def measure_resident_memory(packets, bound=0):
    """Return the memory reading of one packet run, taken in a clean interpreter.

    `resource.getrusage` reports the high-water mark of the whole process, so a reading
    taken inside this pytest session would measure every case that ran before it. A
    separate interpreter is therefore part of the measurement and not a convenience.

    Args:
        packets: The count of packets to feed.
        bound: The entry count every state table reads. Zero keeps the shipped bounds.

    Returns:
        A dict with the keys `idle_resident_mib`, `final_resident_mib`, `peak_mib`,
        `packets`, `connections` and `bound`.

    Raises:
        subprocess.CalledProcessError: The run failed.
        subprocess.TimeoutExpired: The run passed `CEILING_TIMEOUT` seconds.
    """
    completed = subprocess.run(
        [
            sys.executable,
            str(CEILING_RUNNER),
            "--packets",
            str(packets),
            "--connections",
            str(max(packets // PACKETS_PER_CONNECTION, 1)),
            "--bound",
            str(bound),
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=CEILING_TIMEOUT,
    )
    # scapy writes a deprecation warning to standard error, and a future release may
    # write to standard output. The reading is the last line, so a banner costs nothing.
    return json.loads(completed.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def shipped_reading():
    """Return the memory reading of one packet run at every bound the library ships."""
    return measure_resident_memory(CEILING_PACKETS)


@pytest.fixture(scope="module")
def control_reading():
    """Return the memory reading of the same run with every entry count lowered."""
    return measure_resident_memory(CEILING_PACKETS, bound=CONTROL_BOUND)


@pytest.fixture(scope="module")
def flooded():
    """Return one processor, its two entry counts and its two eviction counts.

    The flood costs about one second, so the fixture runs once for the whole file.
    """
    processor = Processor()
    changed = lower_every_bound(processor)
    assert changed == BOUNDED_TABLE_COUNT, f"the walk changed {changed} tables"

    flood(processor, first_index=0)
    first = (total_entries(processor), total_evictions(processor))
    flood(processor, first_index=FLOOD_CONNECTIONS)
    second = (total_entries(processor), total_evictions(processor))
    return processor, first, second


@pytest.fixture(scope="module")
def shipped_flood():
    """Return one processor that a flood passed, with every bound the library ships."""
    processor = Processor()
    flood(processor, first_index=0, connections=300)
    return processor


class TestTheProcessorHoldsNoUnboundedStateTable:
    """Every mapping that survives across packets states both bounds."""

    def test_a_walk_of_the_processor_finds_fifteen_bounded_state_tables(self):
        tables = walk_tables(Processor())
        assert len(tables) == BOUNDED_TABLE_COUNT, sorted(tables)

    def test_every_state_table_states_a_maximum_entry_count(self):
        """FR-concurrency-safety-7. No table reads `None` or a count below one."""
        for path, table in walk_tables(Processor()).items():
            assert isinstance(table.max_connections, int), path
            assert table.max_connections >= 1, path

    def test_every_state_table_states_a_maximum_age(self):
        """FR-concurrency-safety-8. No table reads `None` for its age."""
        for path, table in walk_tables(Processor()).items():
            assert table.max_connection_age is not None, path
            assert table.max_connection_age > 0, path

    def test_the_two_stream_tables_state_both_bounds(self):
        """`TCPStreamReassembler` holds an `OrderedDict` and both bounds of its own."""
        reassemblers = walk_reassemblers(Processor())
        assert len(reassemblers) == STREAM_TABLE_COUNT, sorted(reassemblers)
        for path, reassembler in reassemblers.items():
            assert isinstance(reassembler.streams, OrderedDict), path
            assert reassembler.max_streams >= 1, path
            assert reassembler.max_stream_age > 0, path

    def test_the_processor_holds_no_mapping_without_a_bound(self):
        """A mapping that no bound covers fails here rather than reaching an operator.

        The rule is the type and not a list of names. A mapping a fingerprinter holds
        must be a `StateTable`, because that class carries both bounds. A mapping that a
        `StateTable` holds inside itself needs no separate reading, because the table
        bounds its own storage: `_entries` and `_evicted_keys` are two of those.

        An earlier form of this case named `streams` in an allowlist, and #41 then added
        `_evicted_keys` to every `StateTable`. The case failed on a mapping that is in
        fact bounded, which is why the rule now reads the holder rather than the name.
        """
        processor = Processor()
        unbounded = []
        for name, fingerprinter in processor.fingerprinters.items():
            for holder_name, holder in _holders(name, fingerprinter):
                if isinstance(holder, StateTable):
                    continue
                for attribute, value in vars(holder).items():
                    if isinstance(value, StateTable):
                        continue
                    if isinstance(value, dict):
                        unbounded.append(f"{holder_name}.{attribute}")
        assert unbounded == [], f"these mappings hold no bound: {unbounded}"

    def test_the_walk_of_this_file_agrees_with_the_report_of_the_processor(self):
        """Two counting methods read one number, FR-concurrency-safety-11.

        `Processor.stats()` finds a table through `BaseFingerprinter.state_tables`, and
        this file finds one through its own walk. The two are independent, so a change
        that hides a table from one of them fails this case. The count moved three times
        for exactly that reason, and each move followed a better walk rather than new
        code.
        """
        processor = Processor()
        reported = sum(len(entry.tables) for entry in processor.stats().values())
        walked = len(walk_tables(processor)) + len(walk_reassemblers(processor))

        assert reported == STATE_TABLE_COUNT, f"the processor reports {reported} tables"
        assert walked == STATE_TABLE_COUNT, f"the walk of this file reads {walked} tables"

    def test_the_processor_reports_one_entry_for_each_method(self):
        """`stats()` returns one `ProcessorStats` for each of the ten methods."""
        processor = Processor()
        stats = processor.stats()
        assert sorted(stats) == sorted(processor.fingerprinters)
        assert len(stats) == 10


class TestTheEntryCountStopsRising:
    """A processor that never stops receiving traffic stops growing.

    The pair of cases below runs one flood twice. The first flood saturates every table,
    and the second builds connections the first never built. A flat entry count across
    the two is the reading that makes memory flat over a day.
    """

    def test_a_second_flood_of_connections_raises_no_entry_count(self, flooded):
        """The entry count after the second flood equals the count after the first."""
        processor, first, second = flooded
        assert first[0] == second[0], (
            f"the entry count rose from {first[0]} to {second[0]} on the second flood"
        )

    def test_the_second_flood_evicts_entries(self, flooded):
        """The control. It proves the flat count above measures a saturated table.

        A flood that reached no table would report a flat entry count too, and the case
        above would then pass against a processor that holds no bound at all.
        """
        _, first, second = flooded
        assert second[1] > first[1], (
            f"the eviction count held at {first[1]}, so the second flood reached no table"
        )

    def test_no_state_table_passes_its_entry_count_after_two_floods(self, flooded):
        processor, _, _ = flooded
        for path, table in walk_tables(processor).items():
            assert len(table) <= table.max_connections, path
        for path, reassembler in walk_reassemblers(processor).items():
            assert len(reassembler.streams) <= reassembler.max_streams, path


class TestTheShippedBoundsHoldUnderAFlood:
    """The tables whose shipped bound is small saturate at that bound.

    `TestTheEntryCountStopsRising` lowers every bound so that the flood stays cheap.
    This case changes no bound, so it reads the numbers the library ships.
    """

    # The table and the entry count each one holds after a flood that passes it.
    # `features/03-concurrency-safety.md` states every number, and each is a literal
    # here. #175 derived a boundary case from the constant it asserted, and raising the
    # constant then left that case green.
    SMALL_TABLES = [("ja4h.unusable_base", 100), ("ja4x.scan_offsets", 50)]
    SMALL_STREAM_TABLES = [("ja4h.reassembler", 100), ("ja4x.reassembler", 50)]

    @pytest.mark.parametrize(("path", "bound"), SMALL_TABLES)
    def test_a_small_state_table_saturates_at_its_shipped_entry_count(
        self, shipped_flood, path, bound
    ):
        table = walk_tables(shipped_flood)[path]
        assert table.max_connections == bound
        assert len(table) == bound

    @pytest.mark.parametrize(("path", "bound"), SMALL_STREAM_TABLES)
    def test_a_stream_table_saturates_at_its_shipped_stream_count(self, shipped_flood, path, bound):
        reassembler = walk_reassemblers(shipped_flood)[path]
        assert reassembler.max_streams == bound
        assert len(reassembler.streams) == bound

    def test_the_flood_evicts_from_every_small_table(self, shipped_flood):
        """The control. A table that evicts nothing saturates by accident."""
        for path, _ in self.SMALL_TABLES:
            assert walk_tables(shipped_flood)[path].evictions > 0, path


class TestTheAgeBoundFreesAnIdleConnection:
    """A connection that stops sending leaves the state table, FR-concurrency-safety-8.

    This case is the third user story of `features/03-concurrency-safety.md`: a monitor
    runs for a day and memory stays flat. The entry count bound alone cannot hold memory
    flat for that monitor, because a monitor below the entry count never reaches it. The
    age bound is what frees the connection that stops.

    `JA4LFingerprinter.connections` runs one age pass for every 1000 packets, so the
    case feeds more than 1000 packets after the gap. A case that fed fewer would report
    a full table and read it as a defect.
    """

    # The connections the first phase builds, and the gap in seconds before the second.
    # The maximum age of the table is 600 seconds, so 5000 passes it many times over.
    IDLE_CONNECTIONS = 100
    GAP_SECONDS = 5000

    # The connections the second phase builds. Each one carries three packets, so 400
    # connections feed 1200 packets and the age pass runs.
    LATER_CONNECTIONS = 400

    def test_a_connection_that_stops_sending_leaves_the_state_table(self):
        processor = Processor()
        table = processor.fingerprinters["ja4l"].connections

        for index in range(self.IDLE_CONNECTIONS):
            for packet in handshake(index, 1000.0 + index):
                processor.process_packet(packet)
        idle_keys = set(table.keys())
        assert len(idle_keys) == self.IDLE_CONNECTIONS, "the first phase built no table"

        later = 1000.0 + self.GAP_SECONDS
        for offset in range(self.LATER_CONNECTIONS):
            index = self.IDLE_CONNECTIONS + offset
            for packet in handshake(index, later + offset):
                processor.process_packet(packet)

        survivors = idle_keys & set(table.keys())
        assert survivors == set(), (
            f"{len(survivors)} connections that stopped sending still hold an entry"
        )
        assert len(table) < self.IDLE_CONNECTIONS + self.LATER_CONNECTIONS

    def test_a_connection_that_keeps_sending_holds_its_entry(self):
        """The control. It proves the case above measures the age and not the traffic.

        A table that dropped every entry on every pass would pass the case above. This
        case replays one connection across the same gap in steps below the maximum age,
        and that connection holds its entry.
        """
        processor = Processor()
        table = processor.fingerprinters["ja4l"].connections

        for packet in handshake(0, 1000.0):
            processor.process_packet(packet)
        key = table.keys()[0]

        # Each step sits below the 600-second age, so the pass evicts this entry never.
        for step in range(1, 11):
            for packet in handshake(0, 1000.0 + step * 500.0):
                processor.process_packet(packet)
            for offset in range(200):
                for packet in handshake(1000 + step * 200 + offset, 1000.0 + step * 500.0):
                    processor.process_packet(packet)

        assert key in table.keys(), "the connection that kept sending lost its entry"


class TestAConnectionThatReturns:
    """A returned connection builds a new entry, and the processor counts it.

    The `## Terms` table of `docs/specs/spec.md` names a returned connection: one
    connection that a state table evicted and then saw again. Its new entry holds none of
    the packets that came before the eviction, so its fingerprint may be incomplete.
    #41 built the count and #43 states the consequence for a reader of a fingerprint.
    """

    def test_a_connection_that_returns_after_its_eviction_builds_a_new_entry(self):
        processor = Processor()
        table = processor.fingerprinters["ja4l"].connections
        table.max_connections = 4

        for packet in handshake(0, 1000.0):
            processor.process_packet(packet)
        assert len(table) == 1, "the first connection built no entry, so nothing evicts"
        first_key = table.keys()[0]

        # Four later connections pass the entry count, so the table evicts the first.
        for index in range(1, 5):
            for packet in handshake(index, 1000.0 + index):
                processor.process_packet(packet)
        assert len(table) == 4
        assert first_key not in table.keys(), "the table evicted no entry"
        evicted = table.evictions

        # The first connection returns. The processor raises nothing and builds an entry
        # again, and the entry it builds holds none of the state the eviction removed.
        for packet in handshake(0, 1010.0):
            processor.process_packet(packet)
        assert len(table) == 4
        assert first_key in table.keys(), "the connection that returned built no entry"
        assert table.evictions > evicted

    def test_the_processor_counts_the_connection_that_returned(self):
        """`stats()` separates a returned connection from a first sighting.

        An operator who reads an incomplete fingerprint needs to know the eviction lost
        packets of that connection. The count is the reading that tells them.
        """
        processor = Processor()
        table = processor.fingerprinters["ja4l"].connections
        table.max_connections = 4

        for index in range(5):
            for packet in handshake(index, 1000.0 + index):
                processor.process_packet(packet)
        assert processor.stats()["ja4l"].returned_connections == 0, (
            "no connection returned yet, so the count measures nothing"
        )

        for packet in handshake(0, 1010.0):
            processor.process_packet(packet)

        assert processor.stats()["ja4l"].returned_connections >= 1


@pytest.mark.skipif(
    importlib.util.find_spec("resource") is None,
    reason="the reading needs `resource.getrusage`, and Windows ships no `resource`",
)
class TestTheStatedMemoryCeiling:
    """One packet run holds resident memory below the ceiling this package states.

    `features/03-concurrency-safety.md` states 512 MiB for the one-million-packet case at
    the shipped defaults, and the user decided that number on 2026-08-08. This class is
    what makes the number a claim a reader can check rather than prose.

    **The ceiling covers the stated case and no longer run.**
    `BaseFingerprinter.fingerprints` grows without a limit, so resident memory rises with
    the packet count after every state table settles. #279 read 23 MiB for each 100000
    packets past 200000, and it measured the crossing at 1500000 packets and 513.06 MiB.
    `TestTheStructuresThatHoldNoBound` records the structure that causes it, and Goal 3
    owns the list.

    **The packet count falsifies this ceiling, and a raised entry count does not.** #279
    raised a table limit three ways and the case stayed green each time, because the age
    bound holds the tables the reversal raises.
    `features/03-concurrency-safety.md` records all three readings.

    Three controls sit beside the ceiling case, because a comparison that cannot fail
    measures nothing. The default size holds 3000 connections, which no shipped bound
    reaches, so the ceiling comparison alone cannot fail at that size. The first control
    reads the packet count back. The second reads the memory the traffic added. The third
    lowers every entry count and reads a smaller number, which is the reading that proves
    the entry count bound is measured here at all.

    The third control compares a ratio and not a MiB figure. A resident memory reading
    moves with the platform and with the interpreter, and an absolute margin that suits
    one platform can sit above the whole signal on another.

    **The ceiling reads a high-water mark, and the second and third controls read the
    current resident set.** The two kinds answer different questions, and the split is
    what repairs the controls. A high-water mark never falls, so the difference between
    two of them states `max(0, later mark - earlier mark)`. The import of scapy reaches a
    mark on Ubuntu that the traffic then stays below, and both controls therefore read a
    difference of exactly zero on a run that allocated tens of MiB. `traffic_growth_mib`
    holds the rule, and `TestTheGrowthReading` measures it against the Ubuntu numbers.
    """

    def test_the_packet_run_holds_resident_memory_below_the_stated_ceiling(self, shipped_reading):
        """The claim itself.

        #279 read 383.47 MiB, 388.25 MiB, 392.05 MiB and 394.94 MiB across four runs of
        the full 1000000-packet case. The highest is 77 percent of the ceiling, and the
        same traffic passes the ceiling at 1500000 packets.
        """
        assert shipped_reading["peak_mib"] < MEMORY_CEILING_MIB, (
            f"{shipped_reading['packets']} packets across "
            f"{shipped_reading['connections']} connections held "
            f"{shipped_reading['peak_mib']} MiB, above the stated {MEMORY_CEILING_MIB} MiB"
        )

    def test_the_run_feeds_every_packet_the_case_states(self, shipped_reading):
        """The first control. A run that fed fewer packets measures a smaller number."""
        assert shipped_reading["packets"] == CEILING_RUN_PACKETS
        assert shipped_reading["connections"] == CEILING_CONNECTIONS

    def test_the_reading_measures_the_traffic_and_not_the_interpreter(self, shipped_reading):
        """The second control. A constant reading would pass the case above unread.

        The growth comes from the two current resident readings, because the difference
        between two high-water marks is no growth. The second assertion ties the ceiling
        number to the run: the mark covers the resident set the traffic left behind.
        """
        growth = traffic_growth_mib(shipped_reading)
        assert growth > 0.0, f"the run added {growth:.2f} MiB, so the reading measures no traffic"
        assert shipped_reading["peak_mib"] >= shipped_reading["final_resident_mib"], (
            f"the mark reads {shipped_reading['peak_mib']} MiB and the run held "
            f"{shipped_reading['final_resident_mib']} MiB, so the mark covers no run"
        )

    def test_a_smaller_entry_count_holds_less_resident_memory(
        self, shipped_reading, control_reading
    ):
        """The third control. It proves the entry count bound holds the ceiling.

        A package that ignored its entry count bound would read one number for both runs.
        The comparison is a ratio, because the absolute readings move with the platform.
        """
        shipped_growth = traffic_growth_mib(shipped_reading)
        control_growth = traffic_growth_mib(control_reading)
        assert shipped_growth > CONTROL_FLOOR_MIB, (
            f"the shipped run added {shipped_growth:.2f} MiB, which is too little to read"
        )
        assert control_growth < shipped_growth * CONTROL_GROWTH_RATIO, (
            f"a bound of {CONTROL_BOUND} added {control_growth:.2f} MiB and the shipped "
            f"bounds added {shipped_growth:.2f} MiB, a ratio of "
            f"{control_growth / shipped_growth:.3f}, so the entry count changed nothing"
        )


class TestTheGrowthReading:
    """`traffic_growth_mib` reads a growth, and it subtracts no high-water mark.

    These cases run on every platform, because they read numbers and start no
    interpreter. They are the part of the memory measurement a reader can check in a
    millisecond, and they hold the rule that pull request #384 found broken.
    """

    # The reading the four Ubuntu jobs of pull request #384 wrote. The two numbers are
    # equal because the import of scapy reached a mark the traffic stayed below, and the
    # run allocated tens of MiB all the same.
    UBUNTU_HIGH_WATER_READING = {
        "idle_mib": 154.7,
        "peak_mib": 154.7,
        "packets": 30000,
        "connections": 3000,
        "bound": 0,
    }

    def test_a_pair_of_high_water_marks_reads_as_a_void_measurement(self):
        """A reader must read `idle 154.7, peak 154.7` as void, and not as no memory.

        An earlier form of the two controls subtracted the pair below and read 0.00 MiB
        as the memory the package used. The reading states nothing about the traffic, so
        the helper refuses it rather than returning a number.
        """
        with pytest.raises(ValueError, match="void"):
            traffic_growth_mib(self.UBUNTU_HIGH_WATER_READING)

    def test_the_growth_is_the_difference_of_the_two_current_readings(self):
        """The control. It proves the case above refuses the pair and not every reading.

        The two numbers are one macOS run of 30000 packets at the shipped bounds, taken
        under an artificial 80 MiB import transient that reproduces the Ubuntu shape.
        """
        reading = {"idle_resident_mib": 111.86, "final_resident_mib": 147.44}
        assert traffic_growth_mib(reading) == pytest.approx(35.58)

    def test_a_run_that_frees_its_memory_reads_a_negative_growth(self):
        """The current reading falls, where a high-water mark cannot.

        The helper returns the signed difference, so a caller reads a shrinking process
        as a fall. A high-water mark reports zero for the same run and hides it.
        """
        reading = {"idle_resident_mib": 140.0, "final_resident_mib": 120.0}
        assert traffic_growth_mib(reading) == pytest.approx(-20.0)


class TestTheStructuresThatHoldNoBound:
    """The value list of a fingerprinter grows without a limit, and the contract says so.

    `BaseFingerprinter.fingerprints` holds one result for each fingerprint rather than
    per-connection data, so the `## Terms` table names it no state table. A reader who
    reads "every state table holds a bound" must not read it as "one processor holds a
    bound". Goal 3 owns the list, and this case records the reading until then.
    """

    def test_the_value_list_of_a_fingerprinter_grows_without_a_limit(self):
        processor = Processor()
        flood(processor, first_index=0, connections=60)
        short = len(processor.fingerprinters["ja4l"].fingerprints)

        processor = Processor()
        flood(processor, first_index=0, connections=120)
        long = len(processor.fingerprinters["ja4l"].fingerprints)

        assert short > 0, "the flood produced no value, so the case measures nothing"
        assert long > short, (
            "the value list stopped growing, so it now holds a bound the contract omits"
        )
