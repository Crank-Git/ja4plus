"""The JA4TS prefix table holds the two bounds, and it stays in lockstep with `times`.

#246 added `SynAckTracker.prefixes`, which holds part a through part d of the first
SYN-ACK of one connection. The RST value reads it. #39 replaced `SynAckTracker.times`
with a `BoundedStateTable`, and that table evicts inside itself. The two changes were
live on two branches at the same time, so neither could see the other. The merge of the
two leaves `prefixes` with nothing that removes a key `times` evicted, and #285 records
the defect.

Every case here is proven by its removal. Run each one against the merge resolution that
holds `self.prefixes = {}` and the `BoundedStateTable` of #39:

- `test_the_prefix_table_stays_inside_the_entry_count_bound` fails with 60 entries
  against a bound of 25.
- `test_the_age_pass_removes_the_prefix_of_an_aged_connection` fails with 2 entries
  against 1.
- `test_the_two_tables_hold_the_same_keys` fails with 35 keys that `times` does not
  hold.
"""

import pytest
from scapy.all import IP, TCP

from ja4plus.fingerprinters.ja4ts import (
    MAX_TRACKED_CONNECTIONS,
    SYN_ACK_TIMEOUT_SECONDS,
    JA4TSFingerprinter,
    SynAckTracker,
)
from ja4plus.processor import Processor
from ja4plus.utils.state_table import BoundedStateTable

# The entry count each table holds while a case floods the fingerprinter. The shipped
# bound of 1000 needs 1000 connections, and a lowered bound measures the same mechanism
# in a few dozen.
SMALL_BOUND = 25

# The connections one flood builds. The value passes the lowered bound twice over.
FLOOD_CONNECTIONS = 60


def _syn_ack(port, when):
    """Return one SYN-ACK packet of the connection that the port names.

    Args:
        port: The client port, which names the connection.
        when: The capture timestamp, in seconds.

    Returns:
        A scapy packet.
    """
    packet = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(
        sport=443, dport=port, flags="SA", window=64240, options=[("MSS", 1460)]
    )
    packet.time = when
    return packet


def _lower_both_bounds(fingerprinter, count=SMALL_BOUND):
    """Lower the entry count of every table of one JA4TS fingerprinter.

    Args:
        fingerprinter: A `JA4TSFingerprinter`.
        count: The maximum entry count every table reads after the call.
    """
    for table in fingerprinter.state_tables().values():
        table.max_connections = count
        table.max_evicted_keys = count


def test_the_prefix_table_stays_inside_the_entry_count_bound():
    """The prefix table holds no more entries than its maximum entry count."""
    fingerprinter = JA4TSFingerprinter()
    _lower_both_bounds(fingerprinter)

    for index in range(FLOOD_CONNECTIONS):
        fingerprinter.process_packet(_syn_ack(50000 + index, 1000.0 + index * 0.001))

    assert len(fingerprinter.syn_ack_times.times) <= SMALL_BOUND
    assert len(fingerprinter.syn_ack_times.prefixes) <= SMALL_BOUND


def test_the_age_pass_removes_the_prefix_of_an_aged_connection():
    """The prefix of a connection goes when the connection passes the maximum age."""
    fingerprinter = JA4TSFingerprinter()

    fingerprinter.process_packet(_syn_ack(50000, 1000.0))
    assert len(fingerprinter.syn_ack_times.prefixes) == 1

    later = 1000.0 + SYN_ACK_TIMEOUT_SECONDS + 1
    fingerprinter.process_packet(_syn_ack(50001, later))

    assert len(fingerprinter.syn_ack_times.times) == 1
    assert len(fingerprinter.syn_ack_times.prefixes) == 1


def test_the_two_tables_hold_the_same_keys():
    """The prefix table holds the keys the time table holds, and no other key."""
    fingerprinter = JA4TSFingerprinter()
    _lower_both_bounds(fingerprinter)

    for index in range(FLOOD_CONNECTIONS):
        fingerprinter.process_packet(_syn_ack(50000 + index, 1000.0 + index * 0.001))

    times = set(fingerprinter.syn_ack_times.times.keys())
    prefixes = set(fingerprinter.syn_ack_times.prefixes.keys())
    assert prefixes == times


def _fill_three_and_refresh_the_first(fingerprinter):
    """Feed three connections, retransmit on the first, then add a fourth.

    The retransmission reads `times` and reads `prefixes` not at all, so the two tables
    hold a different least recently used order. The fourth connection then passes the
    entry count, and `times` evicts the second connection while `prefixes` on its own
    order would evict the first. Two tables that each hold their own bound are therefore
    not in lockstep, and the eviction hook is what makes them so.

    Args:
        fingerprinter: A `JA4TSFingerprinter` whose tables hold three entries at most.

    Returns:
        The connection key of the first connection.
    """
    for index in range(3):
        fingerprinter.process_packet(_syn_ack(50000 + index, 1000.0 + index * 0.1))
    fingerprinter.process_packet(_syn_ack(50000, 1000.3))
    fingerprinter.process_packet(_syn_ack(50003, 1000.4))
    return ("10.0.0.2", 443, "10.0.0.1", 50000)


def test_a_read_of_one_table_moves_no_key_out_of_step_with_the_other():
    """The two tables hold the same keys after a read reorders one of them."""
    fingerprinter = JA4TSFingerprinter()
    _lower_both_bounds(fingerprinter, 3)

    _fill_three_and_refresh_the_first(fingerprinter)

    times = set(fingerprinter.syn_ack_times.times.keys())
    prefixes = set(fingerprinter.syn_ack_times.prefixes.keys())
    assert prefixes == times


def test_the_rst_value_survives_an_eviction_that_the_entry_count_drives():
    """A RST on a connection that both tables still hold produces its value."""
    fingerprinter = JA4TSFingerprinter()
    _lower_both_bounds(fingerprinter, 3)

    key = _fill_three_and_refresh_the_first(fingerprinter)
    assert key in fingerprinter.syn_ack_times.times

    value = fingerprinter.syn_ack_times.reset_value(key, 1000.5)

    assert value == "64240_2_1460_00_0-R0"


def test_the_prefix_table_is_a_bounded_state_table():
    """The prefix table reads the class of #38 and the two bounds JA4TS states."""
    table = SynAckTracker().prefixes
    assert isinstance(table, BoundedStateTable)
    assert table.max_connections == MAX_TRACKED_CONNECTIONS
    assert table.max_connection_age == SYN_ACK_TIMEOUT_SECONDS


def test_the_processor_reports_the_prefix_table():
    """`Processor.stats()` names the prefix table under its nested name."""
    report = Processor().stats()
    assert sorted(report["ja4ts"].tables) == ["syn_ack_times.prefixes", "syn_ack_times.times"]


def test_the_reset_of_the_fingerprinter_empties_both_tables():
    """`reset` drops every entry of the time table and of the prefix table."""
    fingerprinter = JA4TSFingerprinter()
    fingerprinter.process_packet(_syn_ack(50000, 1000.0))

    fingerprinter.reset()

    assert len(fingerprinter.syn_ack_times.times) == 0
    assert len(fingerprinter.syn_ack_times.prefixes) == 0


@pytest.mark.parametrize("order", [("src", "dst"), ("dst", "src")])
def test_cleanup_connection_removes_the_prefix_in_either_direction(order):
    """`cleanup_connection` drops the prefix whichever endpoint the caller names first."""
    fingerprinter = JA4TSFingerprinter()
    fingerprinter.process_packet(_syn_ack(50000, 1000.0))
    assert len(fingerprinter.syn_ack_times.prefixes) == 1

    if order == ("src", "dst"):
        fingerprinter.cleanup_connection("10.0.0.2", 443, "10.0.0.1", 50000, "tcp")
    else:
        fingerprinter.cleanup_connection("10.0.0.1", 50000, "10.0.0.2", 443, "tcp")

    assert len(fingerprinter.syn_ack_times.prefixes) == 0
