"""Check how the baseline generator reads a failure and assigns an owning issue.

The generator writes the deviation register from a measurement. It reads the cause and
the owning issue from the failure message, so a defect in that reading puts a false
cause and a false owner on hundreds of entries. These tests check the reading.
"""

from types import SimpleNamespace

from tests.foxio_deviations import Deviation
from tests.generate_foxio_baseline import (
    JA4_O_EMPTY_EXTENSION_ISSUE,
    JA4H_RAW_ISSUE,
    JA4L_MIRRORED_CAPTURE_ISSUE,
    JA4L_MULTIPLICITY_ISSUE,
    JA4L_QUIC_SERVER_POINT_ISSUE,
    _entry,
    _failure_line,
    _register,
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

    def test_a_server_latency_of_another_amount_names_the_quic_server_point(self):
        entry = _entry(
            "JA4L-S",
            "Failed: v.pcapng s JA4L-S.1: expected='10990_56' produced='9285_56'",
            occurrence_form=False,
        )
        assert entry["issue"] == JA4L_QUIC_SERVER_POINT_ISSUE
        assert entry["cause"] == (
            "ja4plus reads the first server Initial packet, and the reference reads the "
            "Initial packet that completes the ServerHello."
        )

    def test_an_extra_client_occurrence_key_names_the_multiplicity_issue(self):
        entry = _entry(
            "JA4L-C",
            "Failed: v.pcap JA4L-C: 169 extra occurrence key(s) []; 0 missing occurrence key(s) []",
            occurrence_form=True,
        )
        assert entry["issue"] == JA4L_MULTIPLICITY_ISSUE
        assert entry["cause"] == "ja4plus emits more JA4L-C values than the reference holds."

    def test_an_extra_server_occurrence_key_names_the_multiplicity_issue(self):
        entry = _entry(
            "JA4L-S",
            "Failed: v.pcap JA4L-S: 27 extra occurrence key(s) []; 0 missing occurrence key(s) []",
            occurrence_form=True,
        )
        assert entry["issue"] == JA4L_MULTIPLICITY_ISSUE
        assert entry["cause"] == "ja4plus emits more JA4L-S values than the reference holds."

    def test_a_missing_occurrence_key_names_the_mirrored_capture(self):
        entry = _entry(
            "JA4L-S",
            "Failed: v.pcap JA4L-S: 0 extra occurrence key(s) []; 1 missing occurrence key(s) []",
            occurrence_form=True,
        )
        assert entry["issue"] == JA4L_MIRRORED_CAPTURE_ISSUE
        assert "mirrored capture" in entry["cause"]

    def test_a_produced_none_names_the_mirrored_capture(self):
        entry = _entry(
            "JA4L-C",
            "Failed: v.pcap s JA4L-C.1: expected='953_64' produced=<none>, JA4L-C "
            "produced 0 value(s) on this stream",
            occurrence_form=False,
        )
        assert entry["issue"] == JA4L_MIRRORED_CAPTURE_ISSUE
        assert "mirrored capture" in entry["cause"]


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


class TestTheOwnerOfARawForm:
    """Check that each raw form names the issue that owns it."""

    def test_a_JA4_r_mismatch_names_the_issue_of_the_hashed_form(self):
        entry = _entry(
            "JA4_r",
            "Failed: v.pcap s JA4_r.1: expected='t13d_0001_0002' produced='t13d_0001_0003'",
            occurrence_form=False,
        )
        assert entry["issue"] == 13
        assert entry["cause"] == "The produced JA4_r value differs from the reference."

    def test_a_JA4S_r_mismatch_names_the_issue_of_the_hashed_form(self):
        entry = _entry(
            "JA4S_r",
            "Failed: v.pcap s JA4S_r.1: expected='t1204h2_cca9_0000' produced='t1204h2_cca9_ff01'",
            occurrence_form=False,
        )
        assert entry["issue"] == 13

    def test_a_JA4H_ro_failure_names_the_absent_raw_form(self):
        entry = _entry(
            "JA4H_ro",
            "Failed: v.pcap s JA4H_ro.1: expected='ge11nn' produced=<none>, JA4H_ro "
            "produced 0 value(s) on this stream",
            occurrence_form=False,
        )
        assert entry["issue"] == JA4H_RAW_ISSUE
        assert entry["cause"] == "ja4plus computes no JA4H raw form."

    def test_a_JA4H_ro_occurrence_failure_names_the_absent_raw_form(self):
        entry = _entry(
            "JA4H_ro",
            "Failed: v.pcap JA4H_ro: 0 extra occurrence key(s) []; 1 missing occurrence key(s) []",
            occurrence_form=True,
        )
        assert entry["issue"] == JA4H_RAW_ISSUE

    def test_a_zero_extension_hash_names_the_JA4_o_reading(self):
        entry = _entry(
            "JA4_o",
            "Failed: v.pcap s JA4_o.1: expected='t10d230100_ce175d585f73_000000000000' "
            "produced='t10d230100_ce175d585f73_9af15b336e6a'",
            occurrence_form=False,
        )
        assert entry["issue"] == JA4_O_EMPTY_EXTENSION_ISSUE
        assert "only extension" in entry["cause"]

    def test_another_JA4_o_mismatch_names_the_issue_of_the_hashed_form(self):
        entry = _entry(
            "JA4_o",
            "Failed: v.pcap s JA4_o.1: expected='t13d151699_acb_8fc' produced='t13d1516bd_acb_8fc'",
            occurrence_form=False,
        )
        assert entry["issue"] == 13


class TestTheCommittedEntry:
    """Check that a regeneration keeps the mechanism a person wrote."""

    def _collector(self):
        """Return a collector that reports one failed JA4X value case."""
        nodeid = "tests/test_spec_validation.py::test_x[v.pcap-JA4X.1]"
        callspec = SimpleNamespace(
            params={
                "method": "JA4X",
                "pcap_path": SimpleNamespace(name="v.pcap"),
                "stream": SimpleNamespace(index=0, src_port="443"),
                "occurrence": 1,
            }
        )
        return SimpleNamespace(
            failures=[(nodeid, "E           Failed: v.pcap s JA4X.1: expected='a' produced='b'")],
            params={nodeid: callspec},
        )

    def test_a_committed_entry_survives_the_regeneration(self):
        committed = {"v.pcap/0:443/JA4X.1": Deviation(issue=78, cause="The reference decrypts.")}
        register, _ = _register(self._collector(), committed)
        assert register["v.pcap/0:443/JA4X.1"] == {
            "issue": 78,
            "cause": "The reference decrypts.",
        }

    def test_a_new_key_gets_the_cause_the_failure_message_states(self):
        register, _ = _register(self._collector(), {})
        assert register["v.pcap/0:443/JA4X.1"] == {
            "issue": 78,
            "cause": "The produced JA4X value differs from the reference.",
        }
