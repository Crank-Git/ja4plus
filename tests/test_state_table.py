"""The bounded state table holds a maximum entry count and a maximum age.

#38 builds `ja4plus/utils/state_table.py`. Every case below states its bounds as
literal numbers, never as the constant the case asserts. #175 recorded the reason: a
case that reads its input from the constant passes at any value of that constant.
`test_the_defaults_hold_the_values_the_project_decided` pins the defaults on its own.

`ssh-r.pcap` sets the maximum age. It holds the longest gap between two segments of one
connection across `tests/foxio_vectors/`, at 320.714503 seconds. Two cases replay that
capture. The case at 600 seconds loses no entry. The case at 300 seconds loses the
connection that holds the gap.
"""

import types
from pathlib import Path

import pytest
from scapy.all import IP, TCP, PcapReader

from ja4plus.utils import state_table
from ja4plus.utils.state_table import BoundedStateTable

VECTOR_DIR = Path(__file__).parent / "foxio_vectors"

# The connection of `ssh-r.pcap` that holds the 320.714503 second gap. #170 measured it
# and #179 records it.
SSH_R_LONG_GAP_KEY = ("192.168.1.169", 64980, "192.168.1.197", 22)


def _ssh_r_payload_packets():
    """Return the directional key and the timestamp of each `ssh-r.pcap` payload packet.

    The reading matches `TCPStreamReassembler`. That class keys a stream by direction,
    and `add_segment` refuses a segment that carries no payload.

    Returns:
        A list of (key, timestamp) pairs, in capture order.
    """
    packets = []
    with PcapReader(str(VECTOR_DIR / "ssh-r.pcap")) as reader:
        for packet in reader:
            if IP not in packet or TCP not in packet:
                continue
            payload = bytes(packet[TCP].payload)
            if not payload:
                continue
            key = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
            packets.append((key, float(packet.time)))
    return packets


def _replay_ssh_r(max_connection_age):
    """Return the table that a replay of `ssh-r.pcap` fills at one maximum age.

    Args:
        max_connection_age: The maximum age of one entry, in seconds.

    Returns:
        The filled table. Its `evictions` attribute counts what the replay lost.
    """
    table = BoundedStateTable(
        max_connections=64,
        max_connection_age=max_connection_age,
        eviction_interval=1,
    )
    for key, timestamp in _ssh_r_payload_packets():
        table.on_packet(timestamp)
        table[key] = timestamp
    return table


class TestTheCountBound:
    """FR-concurrency-safety-7 and FR-concurrency-safety-10."""

    def test_the_table_holds_no_more_than_its_maximum_entry_count(self):
        table = BoundedStateTable(max_connections=8, max_connection_age=600.0)
        for index in range(50):
            table[f"connection-{index}"] = index
        assert len(table) == 8

    def test_the_table_evicts_the_least_recently_used_entry_at_its_maximum_count(self):
        table = BoundedStateTable(max_connections=3, max_connection_age=600.0)
        table["a"] = 1
        table["b"] = 2
        table["c"] = 3
        # The read makes "b" the least recently used entry, so the fourth insert drops it.
        assert table["a"] == 1
        table["d"] = 4
        assert "b" not in table
        assert sorted(table.keys()) == ["a", "c", "d"]

    def test_the_table_keeps_the_newest_entries_when_it_overflows(self):
        table = BoundedStateTable(max_connections=4, max_connection_age=600.0)
        for index in range(10):
            table[index] = index
        assert sorted(table.keys()) == [6, 7, 8, 9]

    def test_a_second_write_to_one_key_evicts_no_entry(self):
        table = BoundedStateTable(max_connections=2, max_connection_age=600.0)
        table["a"] = 1
        table["a"] = 2
        table["b"] = 3
        assert table["a"] == 2
        assert table.evictions == 0

    def test_a_second_write_to_one_key_holds_that_entry_against_the_count_bound(self):
        # A fingerprinter rewrites the entry of a connection on each packet, so the
        # rewrite is what holds a busy connection in a full table.
        table = BoundedStateTable(max_connections=3, max_connection_age=600.0)
        table["a"] = 1
        table["b"] = 2
        table["c"] = 3
        table["a"] = 99
        table["d"] = 4
        assert sorted(table.keys()) == ["a", "c", "d"]
        assert table["a"] == 99
        assert table.evictions == 1

    def test_the_table_counts_every_entry_it_evicts(self):
        table = BoundedStateTable(max_connections=5, max_connection_age=600.0)
        for index in range(12):
            table[index] = index
        assert table.evictions == 7


class TestTheAgeBound:
    """FR-concurrency-safety-8."""

    def test_the_table_drops_an_entry_that_receives_no_packet_for_the_maximum_age(self):
        table = BoundedStateTable(max_connections=100, max_connection_age=10.0, eviction_interval=1)
        table.on_packet(1000.0)
        table["idle"] = "state"
        table.on_packet(1011.0)
        assert "idle" not in table
        assert table.evictions == 1

    def test_the_table_keeps_an_entry_inside_the_maximum_age(self):
        table = BoundedStateTable(max_connections=100, max_connection_age=10.0, eviction_interval=1)
        table.on_packet(1000.0)
        table["idle"] = "state"
        table.on_packet(1009.0)
        assert table["idle"] == "state"
        assert table.evictions == 0

    def test_the_contains_operator_holds_an_entry_past_the_maximum_age(self):
        # A fingerprinter asks `if key in self.connections` before it reads the entry,
        # so that question is a read of the entry.
        table = BoundedStateTable(max_connections=100, max_connection_age=10.0, eviction_interval=1)
        table.on_packet(1000.0)
        table["busy"] = "state"
        for timestamp in (1005.0, 1012.0, 1019.0):
            table.on_packet(timestamp)
            assert "busy" in table
        assert table.evictions == 0

    def test_the_contains_operator_holds_an_entry_against_the_count_bound(self):
        table = BoundedStateTable(max_connections=3, max_connection_age=600.0)
        table["a"] = 1
        table["b"] = 2
        table["c"] = 3
        # The question makes "b" the least recently used entry, so the insert drops it.
        assert "a" in table
        table["d"] = 4
        assert sorted(table.keys()) == ["a", "c", "d"]

    def test_a_read_holds_an_entry_past_the_maximum_age(self):
        table = BoundedStateTable(max_connections=100, max_connection_age=10.0, eviction_interval=1)
        table.on_packet(1000.0)
        table["busy"] = "state"
        for timestamp in (1005.0, 1012.0, 1019.0):
            table.on_packet(timestamp)
            assert table["busy"] == "state"
        assert table.evictions == 0

    def test_the_eviction_reads_the_packet_timestamp_and_never_the_wall_clock(self, monkeypatch):
        # The capture replays faster than real time, so a wall clock reads no gap at all.
        monkeypatch.setattr(state_table, "time", types.SimpleNamespace(time=lambda: 0.0))
        table = BoundedStateTable(max_connections=100, max_connection_age=10.0, eviction_interval=1)
        table.on_packet(1000.0)
        table["idle"] = "state"
        table.on_packet(1100.0)
        assert "idle" not in table

    def test_the_eviction_reads_the_wall_clock_when_the_packet_carries_no_timestamp(
        self, monkeypatch
    ):
        clock = types.SimpleNamespace(time=lambda: 5000.0)
        monkeypatch.setattr(state_table, "time", clock)
        table = BoundedStateTable(max_connections=100, max_connection_age=10.0, eviction_interval=1)
        table.on_packet()
        table["idle"] = "state"
        clock.time = lambda: 5100.0
        table.on_packet()
        assert "idle" not in table

    def test_one_packet_without_a_timestamp_moves_the_table_to_the_wall_clock(self, monkeypatch):
        # The class docstring warns about this. A capture recorded in the past ages out
        # whole when one packet of the replay states no timestamp.
        monkeypatch.setattr(state_table, "time", types.SimpleNamespace(time=lambda: 5000.0))
        table = BoundedStateTable(max_connections=100, max_connection_age=10.0, eviction_interval=1)
        table.on_packet(1000.0)
        table["conn"] = "state"
        table.on_packet(1002.0)
        assert "conn" in table
        table.on_packet()
        assert "conn" not in table
        assert table.evictions == 1


class TestTheEvictionInterval:
    """An eviction pass runs at most once per 1000 packets."""

    def test_the_table_runs_no_eviction_pass_before_the_thousandth_packet(self):
        table = BoundedStateTable(max_connections=100, max_connection_age=10.0)
        table.on_packet(1000.0)
        table["idle"] = "state"
        for _ in range(998):
            table.on_packet(2000.0)
        assert table.evictions == 0

    def test_the_table_runs_one_eviction_pass_on_the_thousandth_packet(self):
        table = BoundedStateTable(max_connections=100, max_connection_age=10.0)
        table.on_packet(1000.0)
        table["idle"] = "state"
        for _ in range(999):
            table.on_packet(2000.0)
        assert table.evictions == 1

    def test_the_count_bound_holds_between_two_eviction_passes(self):
        # A table that waits 1000 packets to bound its count overshoots that count.
        table = BoundedStateTable(max_connections=4, max_connection_age=600.0)
        table.on_packet(1000.0)
        for index in range(20):
            table[index] = index
        assert len(table) == 4


class TestTheConstructor:
    """FR-concurrency-safety-9."""

    def test_the_constructor_refuses_a_maximum_entry_count_of_zero(self):
        with pytest.raises(ValueError):
            BoundedStateTable(max_connections=0)

    def test_the_constructor_refuses_a_negative_maximum_entry_count(self):
        with pytest.raises(ValueError):
            BoundedStateTable(max_connections=-1)

    def test_the_constructor_refuses_an_eviction_interval_below_one(self):
        with pytest.raises(ValueError):
            BoundedStateTable(eviction_interval=0)

    def test_the_constructor_accepts_a_maximum_entry_count_of_one(self):
        table = BoundedStateTable(max_connections=1, max_connection_age=600.0)
        table["a"] = 1
        table["b"] = 2
        assert list(table.keys()) == ["b"]

    def test_the_defaults_hold_the_values_the_project_decided(self):
        table = BoundedStateTable()
        assert table.max_connections == 10000
        assert table.max_connection_age == 600.0
        assert table.eviction_interval == 1000

    def test_the_maximum_age_default_matches_the_reassembler(self):
        # One project holds one maximum age. `features/03-concurrency-safety.md` says so.
        from ja4plus.utils.tcp_stream import DEFAULT_MAX_STREAM_AGE

        assert state_table.DEFAULT_MAX_CONNECTION_AGE == DEFAULT_MAX_STREAM_AGE


class TestTheEvictionHook:
    """#285 added `on_eviction` and `evict_key`, and this class measures both.

    A second table that holds the same keys needs to hear about an eviction.
    `SynAckTracker` is the first caller: `times` evicts, and `prefixes` loses the same
    key. Every case here is proven by its removal. With the `self.on_eviction(key)` call
    of `evict_key` removed, the first three cases fail.
    """

    def test_the_table_calls_the_hook_on_the_entry_count_bound(self):
        """The count bound reports the key it removes."""
        seen = []
        table = BoundedStateTable(
            max_connections=2, max_connection_age=600.0, on_eviction=seen.append
        )

        table["a"] = 1
        table["b"] = 2
        table["c"] = 3

        assert seen == ["a"]

    def test_the_table_calls_the_hook_on_the_age_pass(self):
        """The age pass reports every key it removes."""
        seen = []
        table = BoundedStateTable(
            max_connections=10,
            max_connection_age=60.0,
            eviction_interval=1,
            on_eviction=seen.append,
        )

        table.on_packet(1000.0)
        table["a"] = 1
        table.on_packet(1100.0)
        table["b"] = 2

        assert seen == ["a"]

    def test_the_table_calls_no_hook_for_a_removal_the_caller_asked_for(self):
        """`pop`, `del` and `clear` belong to the caller, so none of them reports."""
        seen = []
        table = BoundedStateTable(max_connection_age=600.0, on_eviction=seen.append)

        table["a"] = 1
        table["b"] = 2
        table["c"] = 3
        table.pop("a", None)
        del table["b"]
        table.clear()

        assert seen == []

    def test_evict_key_raises_the_eviction_count_and_not_the_removal_count(self):
        """FR-concurrency-safety-12 counts what the table lost without a caller ask."""
        table = BoundedStateTable(max_connection_age=600.0)
        table["a"] = 1

        assert table.evict_key("a") is True
        assert table.evictions == 1
        assert table.removals == 0
        assert len(table) == 0

    def test_evict_key_reports_false_for_a_key_the_table_does_not_hold(self):
        """A hook that arrives twice for one key evicts once."""
        table = BoundedStateTable(max_connection_age=600.0)

        assert table.evict_key("a") is False
        assert table.evictions == 0

    def test_the_table_holds_its_count_invariant_after_a_hook_eviction(self):
        """`inserts == entries + evictions + removals` survives `evict_key`."""
        table = BoundedStateTable(max_connection_age=600.0)
        for index in range(5):
            table[index] = index
        table.evict_key(0)
        table.pop(1, None)

        stats = table.stats()
        assert stats.inserts == stats.entries + stats.evictions + stats.removals


class TestTheDictionaryInterface:
    """#39 replaces a plain dictionary with this table, so the operations must match."""

    def test_the_table_answers_the_operations_a_fingerprinter_uses(self):
        table = BoundedStateTable(max_connections=10, max_connection_age=600.0)
        table["a"] = 1
        assert "a" in table
        assert "z" not in table
        assert table.get("a") == 1
        assert table.get("z") is None
        assert table.get("z", 9) == 9
        assert table.pop("a") == 1
        assert len(table) == 0
        assert table.pop("a", None) is None

    def test_the_table_reports_its_items_in_the_order_it_last_read_them(self):
        table = BoundedStateTable(max_connections=10, max_connection_age=600.0)
        table["a"] = 1
        table["b"] = 2
        table["c"] = 3
        assert table["a"] == 1
        assert list(table.items()) == [("b", 2), ("c", 3), ("a", 1)]
        assert list(table.values()) == [2, 3, 1]

    def test_a_read_of_an_absent_key_raises_key_error(self):
        table = BoundedStateTable(max_connections=10, max_connection_age=600.0)
        with pytest.raises(KeyError):
            table["absent"]

    def test_a_read_inside_a_loop_over_the_keys_raises_no_error(self):
        # A read moves the entry to the end, and an OrderedDict refuses that move during
        # its own iteration.
        table = BoundedStateTable(max_connections=10, max_connection_age=600.0)
        for index in range(5):
            table[index] = index
        assert [table[key] for key in table] == [0, 1, 2, 3, 4]

    def test_the_table_reports_its_entry_count_and_its_bounds(self):
        # A reader of a log line needs the bounds beside the count.
        table = BoundedStateTable(max_connections=10, max_connection_age=600.0)
        table["a"] = 1
        assert repr(table) == (
            "BoundedStateTable(entries=1, max_connections=10, max_connection_age=600.0)"
        )

    def test_a_read_inside_a_loop_over_the_keys_method_raises_no_error(self):
        # `keys` returns a list and not a view, for the reason the case above states.
        table = BoundedStateTable(max_connections=10, max_connection_age=600.0)
        for index in range(5):
            table[index] = index
        assert [table[key] for key in table.keys()] == [0, 1, 2, 3, 4]

    def test_a_pass_over_the_items_holds_no_entry_against_the_age_bound(self):
        table = BoundedStateTable(max_connections=10, max_connection_age=10.0, eviction_interval=1)
        table.on_packet(1000.0)
        table["idle"] = "state"
        table.on_packet(1005.0)
        assert list(table.items()) == [("idle", "state")]
        assert list(table.values()) == ["state"]
        assert list(table.keys()) == ["idle"]
        table.on_packet(1011.0)
        assert "idle" not in table

    def test_the_dict_constructor_holds_every_entry_against_the_age_bound(self):
        # `dict(table)` reads each key through `__getitem__`, so it is a read of each
        # entry. The class docstring states it, because a dictionary reads otherwise.
        table = BoundedStateTable(max_connections=10, max_connection_age=10.0, eviction_interval=1)
        table.on_packet(1000.0)
        table["idle"] = "state"
        table.on_packet(1005.0)
        assert dict(table) == {"idle": "state"}
        table.on_packet(1011.0)
        assert "idle" in table

    def test_popitem_removes_the_least_recently_used_entry(self):
        # A dictionary removes the entry it received last. The class docstring states
        # the difference, and no call site reaches this operation today.
        table = BoundedStateTable(max_connections=10, max_connection_age=600.0)
        table["a"] = 1
        table["b"] = 2
        table["c"] = 3
        assert table.popitem() == ("a", 1)

    def test_clear_removes_every_entry_and_counts_no_eviction(self):
        table = BoundedStateTable(max_connections=10, max_connection_age=600.0)
        table["a"] = 1
        table["b"] = 2
        table.clear()
        assert len(table) == 0
        assert table.evictions == 0

    def test_a_delete_counts_no_eviction(self):
        # `cleanup_connection` is the caller's removal, not a removal the table decided.
        table = BoundedStateTable(max_connections=10, max_connection_age=600.0)
        table["a"] = 1
        del table["a"]
        assert table.evictions == 0


class TestTheCaptureReplay:
    """The measurement that sets the maximum age, replayed against the table."""

    def test_a_replay_of_ssh_r_pcap_loses_no_entry_at_600_seconds(self):
        table = _replay_ssh_r(600.0)
        assert table.evictions == 0

    def test_a_replay_of_ssh_r_pcap_loses_a_connection_at_300_seconds(self):
        # #179 records the defect this case pins. The longest gap of the committed
        # captures is 320.714503 seconds, and a 300 second age evicts across it.
        table = _replay_ssh_r(300.0)
        assert table.evictions > 0

    def test_the_replay_reaches_the_connection_that_holds_the_longest_gap(self):
        # A replay that never reads this connection proves nothing about the gap.
        keys = {key for key, _ in _ssh_r_payload_packets()}
        assert SSH_R_LONG_GAP_KEY in keys
