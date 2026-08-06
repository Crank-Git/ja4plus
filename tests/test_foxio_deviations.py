"""Check the deviation register and its reader.

The register records a conformance case that this project fails today. The suite reads
it and marks the matching case `xfail(strict=True)`. These tests check the reader, the
key forms and the shape of the committed register.
"""

import json

import pytest

from tests.foxio_deviations import (
    REGISTER_PATH,
    Deviation,
    load_register,
    occurrence_key,
    value_key,
)


class TestTheKeyForms:
    """Check the two key forms the register holds."""

    def test_the_value_key_names_the_vector_the_stream_and_the_occurrence(self):
        assert value_key("tls-sni.pcapng", 38, "57377", "JA4", 1) == (
            "tls-sni.pcapng/38:57377/JA4.1"
        )

    def test_the_value_key_separates_two_streams_that_share_one_index(self):
        first = value_key("quic.pcapng", 0, "57098", "JA4L-C", 1)
        second = value_key("quic.pcapng", 0, "50280", "JA4L-C", 1)
        assert first != second

    def test_the_value_key_accepts_an_unknown_stream_index(self):
        assert value_key("tls-sni.pcapng", "?", "443", "JA4", 2) == "tls-sni.pcapng/?:443/JA4.2"

    def test_the_occurrence_key_names_the_vector_and_the_method(self):
        assert occurrence_key("ssh2.pcapng", "JA4") == "ssh2.pcapng/JA4"

    def test_the_two_key_forms_never_collide(self):
        assert value_key("a.pcap", 0, "443", "JA4", 1) != occurrence_key("a.pcap", "JA4")


class TestTheRegisterReader:
    """Check the reader that turns the register file into Deviation entries."""

    def _write(self, tmp_path, content):
        path = tmp_path / "deviations.json"
        path.write_text(json.dumps(content))
        return path

    def test_the_reader_returns_one_entry_for_one_key(self, tmp_path):
        path = self._write(
            tmp_path,
            {"a.pcap/0/JA4.1": {"issue": 13, "cause": "The extension count differs."}},
        )
        register = load_register(path)
        assert register["a.pcap/0/JA4.1"] == Deviation(
            issue=13, cause="The extension count differs."
        )

    def test_the_reader_returns_an_empty_register_for_an_empty_file(self, tmp_path):
        assert load_register(self._write(tmp_path, {})) == {}

    def test_the_reader_rejects_an_entry_that_names_no_issue(self, tmp_path):
        path = self._write(tmp_path, {"a.pcap/0/JA4.1": {"cause": "The count differs."}})
        with pytest.raises(ValueError, match="a.pcap/0/JA4.1"):
            load_register(path)

    def test_the_reader_rejects_an_issue_number_that_is_not_a_number(self, tmp_path):
        path = self._write(tmp_path, {"a.pcap/0/JA4.1": {"issue": "13", "cause": "x"}})
        with pytest.raises(ValueError, match="a.pcap/0/JA4.1"):
            load_register(path)

    def test_the_reader_rejects_an_entry_that_states_no_cause(self, tmp_path):
        path = self._write(tmp_path, {"a.pcap/0/JA4.1": {"issue": 13}})
        with pytest.raises(ValueError, match="a.pcap/0/JA4.1"):
            load_register(path)

    def test_the_reader_rejects_an_entry_that_is_not_a_table(self, tmp_path):
        path = self._write(tmp_path, {"a.pcap/0/JA4.1": "The count differs."})
        with pytest.raises(ValueError, match="a.pcap/0/JA4.1"):
            load_register(path)

    def test_the_reader_returns_an_empty_register_for_a_missing_file(self, tmp_path):
        assert load_register(tmp_path / "absent.json") == {}

    def test_the_reason_names_the_issue_and_the_cause(self):
        deviation = Deviation(issue=30, cause="JA4L needs the hop count.")
        assert deviation.reason() == "issue #30: JA4L needs the hop count."


class TestTheCommittedRegister:
    """Check the register this repository ships."""

    def test_the_register_reads(self):
        assert isinstance(load_register(), dict)

    def test_every_entry_names_an_issue(self):
        for key, deviation in load_register().items():
            assert deviation.issue > 0, "{} names no issue".format(key)

    def test_every_entry_states_a_cause(self):
        for key, deviation in load_register().items():
            assert deviation.cause.strip(), "{} states no cause".format(key)

    def test_the_register_holds_no_duplicate_key(self):
        with open(REGISTER_PATH) as handle:
            text = handle.read()
        pairs = json.loads(text, object_pairs_hook=lambda items: items)
        keys = [key for key, _ in pairs]
        assert len(keys) == len(set(keys))
