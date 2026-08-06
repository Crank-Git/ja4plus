"""Check how the baseline generator reads a failure and assigns an owning issue.

The generator writes the deviation register from a measurement. It reads the cause and
the owning issue from the failure message, so a defect in that reading puts a false
cause and a false owner on hundreds of entries. These tests check the reading.
"""

from tests.generate_foxio_baseline import (
    JA4L_MULTIPLICITY_ISSUE,
    JA4L_VALUE_ISSUE,
    _entry,
    _failure_line,
)

# pytest prints the source of the test above the failure line. The source holds the
# format string of the failure message, so a search of the whole report matches text the
# case never produced.
REPORT_WITH_SOURCE = """
        if len(produced) < occurrence:
            pytest.fail(
                "{} {} {}.{}: expected={!r} produced=<none>, {} produced {} value(s) "
E           Failed: badcurveball.pcap stream=0 a:1 -> b:2 JA4L-S.1: expected='781_238' produced='1562_238'
"""


class TestTheFailureLineReader:
    """Check that the reader separates the failure from the source pytest prints."""

    def test_the_reader_returns_the_failure_line(self):
        assert _failure_line(REPORT_WITH_SOURCE).startswith("E           Failed: badcurveball")

    def test_the_reader_drops_the_source_that_holds_the_format_string(self):
        assert "produced=<none>" not in _failure_line(REPORT_WITH_SOURCE)

    def test_the_reader_returns_the_report_when_it_holds_no_failure_line(self):
        assert _failure_line("internal error") == "internal error"


class TestTheJA4LOwner:
    """Check that each JA4L defect shape names the issue that fixes it."""

    def test_a_latency_of_twice_the_reference_names_the_value_issue(self):
        entry = _entry(
            "JA4L-S",
            "Failed: v.pcap s JA4L-S.1: expected='781_238' produced='1562_238'",
            occurrence_form=False,
        )
        assert entry["issue"] == JA4L_VALUE_ISSUE
        assert entry["cause"] == (
            "ja4plus reports the round-trip time, and the reference holds half of it."
        )

    def test_a_truncated_latency_of_twice_the_reference_names_the_value_issue(self):
        entry = _entry(
            "JA4L-S",
            "Failed: v.pcap s JA4L-S.1: expected='210_64' produced='421_64'",
            occurrence_form=False,
        )
        assert entry["issue"] == JA4L_VALUE_ISSUE
        assert "half of it" in entry["cause"]

    def test_a_client_latency_of_another_amount_names_the_measurement_point(self):
        entry = _entry(
            "JA4L-C",
            "Failed: v.pcap s JA4L-C.1: expected='278_128' produced='111_128'",
            occurrence_form=False,
        )
        assert entry["issue"] == JA4L_VALUE_ISSUE
        assert entry["cause"] == (
            "ja4plus measures JA4L-C to the bare ACK, and it does not halve the round-trip time."
        )

    def test_an_extra_client_occurrence_key_names_the_multiplicity_issue(self):
        entry = _entry(
            "JA4L-C",
            "Failed: v.pcap JA4L-C: 169 extra occurrence key(s) []; 0 missing occurrence key(s) []",
            occurrence_form=True,
        )
        assert entry["issue"] == JA4L_MULTIPLICITY_ISSUE
        assert entry["cause"] == "ja4plus emits one JA4L-C value for every ACK on the connection."

    def test_an_extra_server_occurrence_key_names_the_multiplicity_issue(self):
        entry = _entry(
            "JA4L-S",
            "Failed: v.pcap JA4L-S: 27 extra occurrence key(s) []; 0 missing occurrence key(s) []",
            occurrence_form=True,
        )
        assert entry["issue"] == JA4L_MULTIPLICITY_ISSUE
        assert entry["cause"] == "ja4plus emits more JA4L-S values than the reference holds."

    def test_a_missing_occurrence_key_names_the_multiplicity_issue(self):
        entry = _entry(
            "JA4L-S",
            "Failed: v.pcap JA4L-S: 0 extra occurrence key(s) []; 1 missing occurrence key(s) []",
            occurrence_form=True,
        )
        assert entry["issue"] == JA4L_MULTIPLICITY_ISSUE
        assert "tunnel payload" in entry["cause"]

    def test_a_produced_none_names_the_tunnel_capture(self):
        entry = _entry(
            "JA4L-C",
            "Failed: v.pcap s JA4L-C.1: expected='953_64' produced=<none>, JA4L-C "
            "produced 0 value(s) on this stream",
            occurrence_form=False,
        )
        assert entry["issue"] == JA4L_VALUE_ISSUE
        assert "tunnel payload" in entry["cause"]


class TestTheOwnerOfAnotherMethod:
    """Check that a method the generator already knew keeps its owner and its cause."""

    def test_a_JA4X_value_mismatch_names_its_issue_and_the_mismatch(self):
        entry = _entry(
            "JA4X",
            "Failed: v.pcap s JA4X.1: expected='a_b_c' produced='d_e_f'",
            occurrence_form=False,
        )
        assert entry["issue"] == 78
        assert entry["cause"] == "The produced JA4X value differs from the reference."
