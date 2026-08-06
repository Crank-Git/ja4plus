"""Check the vector manifest and its reader.

The manifest names every vector the conformance suite expects. These tests check the
reader, the comparison it feeds, and the shape of the committed manifest.
"""

import json

import pytest

from tests.foxio_manifest import compare, load_manifest


class TestTheManifestReader:
    """Check the reader that turns the manifest file into a map of counts."""

    def _write(self, tmp_path, content):
        path = tmp_path / "manifest.json"
        path.write_text(json.dumps(content))
        return path

    def test_the_reader_returns_the_case_count_of_each_vector(self, tmp_path):
        path = self._write(tmp_path, {"tls12.pcap": 9, "ssh2.pcapng": 40})
        assert load_manifest(path) == {"tls12.pcap": 9, "ssh2.pcapng": 40}

    def test_the_reader_accepts_a_vector_that_carries_no_case(self, tmp_path):
        assert load_manifest(self._write(tmp_path, {"dhcp.pcapng": 0})) == {"dhcp.pcapng": 0}

    def test_the_reader_rejects_a_count_that_is_not_a_number(self, tmp_path):
        path = self._write(tmp_path, {"tls12.pcap": "9"})
        with pytest.raises(ValueError, match="tls12.pcap"):
            load_manifest(path)

    def test_the_reader_rejects_a_negative_count(self, tmp_path):
        path = self._write(tmp_path, {"tls12.pcap": -1})
        with pytest.raises(ValueError, match="tls12.pcap"):
            load_manifest(path)

    def test_the_reader_rejects_an_absent_manifest(self, tmp_path):
        with pytest.raises(ValueError, match="absent"):
            load_manifest(tmp_path / "absent.json")


class TestTheComparison:
    """Check the comparison that the suite reports on."""

    def test_the_comparison_reports_nothing_when_the_two_agree(self):
        assert compare({"tls12.pcap": 9}, {"tls12.pcap": 9}) == []

    def test_the_comparison_names_a_vector_the_suite_did_not_collect(self):
        differences = compare({"tls12.pcap": 9}, {})
        assert len(differences) == 1
        assert "tls12.pcap" in differences[0]
        assert "absent" in differences[0]

    def test_the_comparison_names_a_vector_the_manifest_does_not_hold(self):
        differences = compare({}, {"new.pcap": 3})
        assert differences == ["new.pcap is not in the manifest"]

    def test_the_comparison_names_a_vector_whose_case_count_changed(self):
        differences = compare({"tls12.pcap": 9}, {"tls12.pcap": 5})
        assert len(differences) == 1
        assert "tls12.pcap" in differences[0]
        assert "5" in differences[0] and "9" in differences[0]

    def test_the_comparison_reports_every_difference(self):
        differences = compare({"a.pcap": 1, "b.pcap": 2}, {"b.pcap": 3, "c.pcap": 4})
        assert len(differences) == 3


class TestTheCommittedManifest:
    """Check the manifest this repository ships."""

    def test_the_manifest_reads(self):
        assert load_manifest()

    def test_every_entry_names_a_capture_file(self):
        for vector in load_manifest():
            assert ".pcap" in vector, "{} is not a capture file name".format(vector)
