"""One packet dated far in the future evicts every entry of a bounded state table.

The maintainer ruled the property on 2026-08-14, on `Crank-Git/ja4plus-go#577` and on
#618. Both projects accept it and document it, and no line of the age pass changes.
`ja4plus/utils/state_table.py:414` holds the comparison that produces it.

These cases hold the behavior, so a later change to the age pass fails a run rather
than removes a documented behavior without a report. `docs/concurrency.md` states the
property, and the last case reads that page.
"""

from pathlib import Path

from ja4plus.utils.state_table import BoundedStateTable

DOCS_DIR = Path(__file__).parent.parent / "docs"


class TestOnePacketDatedInTheFuture:
    """#618."""

    def test_one_packet_dated_far_in_the_future_evicts_every_entry(self):
        table = BoundedStateTable(
            max_connections=100, max_connection_age=600.0, eviction_interval=1
        )
        table.on_packet(1000.0)
        for index in range(8):
            table[f"connection-{index}"] = "state"
        # The age pass compares one packet timestamp against every entry, so a jump of
        # 1e9 seconds ages all eight entries at once.
        table.on_packet(1000.0 + 1e9)
        assert table.keys() == []
        assert len(table) == 0
        assert table.evictions == 8

    def test_a_packet_inside_the_maximum_age_evicts_no_entry(self):
        # The control proves the case above reads the timestamp and not the eviction
        # pass alone.
        table = BoundedStateTable(
            max_connections=100, max_connection_age=600.0, eviction_interval=1
        )
        table.on_packet(1000.0)
        for index in range(8):
            table[f"connection-{index}"] = "state"
        table.on_packet(1500.0)
        assert len(table) == 8
        assert table.evictions == 0

    def test_one_packet_dated_in_the_future_evicts_an_entry_the_next_packet_needs(self):
        # The cost is the fingerprinting state of a live connection, so the run answers
        # with fewer fingerprints. #618 records the reading.
        table = BoundedStateTable(
            max_connections=100, max_connection_age=600.0, eviction_interval=1
        )
        table.on_packet(1000.0)
        table["live"] = "state"
        table.on_packet(1000.0 + 1e9)
        table.on_packet(1001.0)
        assert "live" not in table

    def test_the_concurrency_page_states_that_one_future_packet_evicts_every_entry(self):
        text = (DOCS_DIR / "concurrency.md").read_text(encoding="utf-8")
        for stated in (
            "## One packet dated in the future evicts every entry",
            # Each phrase below sits on one line of the page, because a phrase that
            # spans a line break fails this case on a reflow of the paragraph.
            "therefore ages every entry at once, and the pass evicts all of them.",
            "a sender influences this input",
            "This project accepts the property, and it changes no line of the age pass.",
        ):
            assert stated in text, f"the concurrency page states no {stated!r}"
