"""Bulk lookup and the source of every result, issue #59.

`JA4DBClient.lookup_many` accepts a sequence of fingerprints and returns a result per
fingerprint, FR-db-enrichment-7. A lookup result records its source, FR-db-enrichment-8.
An analyst needs to know where a name came from to judge how much to trust it.

A case that only reads `embedded` cannot separate a client that reads the source from a
client that writes one value. The cases below read all three: a hit from the bundled
mapping file, a hit from a cached mapping file, and a hit from the lookup service.

Every case reaches no network. The `no_network` fixture of `tests/test_db_offline.py`
blocks every outbound socket, and the `RecordingRequests` stand-in of the same module
records a request rather than sends one.
"""

import dataclasses
import inspect
import os
import sys

import pytest

import ja4plus.ja4db as ja4db
import tests.test_db_offline as db_offline
from ja4plus.ja4db import JA4DBClient, LookupResult

# The `no_network` fixture of #57 blocks every outbound socket. The assignment registers
# it in this module, and an import of the name would shadow every case that requests it.
no_network = db_offline.no_network

# A fingerprint the bundled mapping file holds.
BUNDLED_FINGERPRINT = "t13d1516h2_8daaf6152771_02713d6af862"

# A fingerprint that no bundled mapping file holds. Only a cached mapping file names it,
# so a lookup that answers it proves which file the client read.
CACHE_ONLY_FINGERPRINT = "t13d000000_000000000000_000000000059"

# A fingerprint that no mapping file holds. Only the lookup service answers it.
MISSING_FINGERPRINT = "t99z9999h0_000000000000_000000000000"

# One mapping file that names the cache-only fingerprint. The header carries the column
# names that the client reads.
CACHE_CSV = (
    "Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes\r\n"
    f"Issue 59 Client,,,,{CACHE_ONLY_FINGERPRINT},,,,,,a cached entry\r\n"
)


@pytest.fixture
def cache_home(tmp_path, monkeypatch):
    """Point the cache directory at a temporary directory.

    The convention reads `$XDG_CACHE_HOME` on Linux and the home directory on macOS, so
    the fixture sets both names. No case writes outside the directory it returns.

    Args:
        tmp_path: The pytest fixture that holds one directory for one case.
        monkeypatch: The pytest fixture that restores each name after the case.

    Returns:
        The cache directory of the program, which no case creates in advance.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    # `expanduser` reads a cached home directory on some platforms, and it reads `HOME`
    # again once the case clears that cache.
    monkeypatch.delenv("USERPROFILE", raising=False)
    return os.path.dirname(ja4db.cache_file_path())


def write_cache_file(cache_home, text=CACHE_CSV):
    """Write one mapping file to the cache directory.

    Args:
        cache_home: The cache directory the `cache_home` fixture returns.
        text: The text of the mapping file.

    Returns:
        The path of the file written.
    """
    os.makedirs(cache_home, exist_ok=True)
    path = ja4db.cache_file_path()
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


class TestTheShapeOfALookupResult:
    """`LookupResult` carries the port's three fields plus `source`."""

    def test_a_lookup_result_holds_the_four_published_fields(self):
        """The `Interfaces` block of `docs/specs/features/07-db-enrichment.md` publishes
        `application`, `type`, `notes` and `source`, in that order."""
        fields = [field.name for field in dataclasses.fields(LookupResult)]
        assert fields == ["application", "type", "notes", "source"]

    def test_a_lookup_result_refuses_a_write(self):
        """The published type is frozen, so no caller edits a result the cache holds."""
        result = LookupResult(application="a", type="ja4", notes="", source="embedded")
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.source = "remote"


class TestTheSourceOfEveryResult:
    """A lookup result records its source, FR-db-enrichment-8.

    A source value is `embedded`, `cache` or `remote`. The port publishes the first two
    at `lookup.go:31`, and `CLAUDE.md` parity rule 2 adopts them.
    """

    def test_a_hit_from_the_bundled_mapping_file_records_embedded(self, cache_home, no_network):
        result = JA4DBClient().lookup(BUNDLED_FINGERPRINT)
        assert result is not None
        assert result.source == "embedded"
        assert "Chromium" in result.application

    def test_a_hit_from_the_cached_mapping_file_records_cache(self, cache_home, no_network):
        """The client prefers the cached mapping file, FR-db-enrichment-13, so a result it
        answers records the cache and not the package."""
        write_cache_file(cache_home)
        result = JA4DBClient().lookup(CACHE_ONLY_FINGERPRINT)
        assert result is not None
        assert result.source == "cache"
        assert result.application == "Issue 59 Client"

    def test_a_hit_from_the_lookup_service_records_remote(self, cache_home, monkeypatch):
        """A client that reads the source cannot report `embedded` for a name the service
        gave it."""
        payload = {"application": "Test Client", "type": "ja4", "notes": "a note"}
        recorder = db_offline.RecordingRequests(response=db_offline.StubResponse(payload=payload))
        client = JA4DBClient(allow_remote=True)
        monkeypatch.setitem(sys.modules, "requests", recorder)
        result = client.lookup(MISSING_FINGERPRINT)
        assert result is not None
        assert result.source == "remote"
        assert result.application == "Test Client"

    def test_every_entry_of_the_mapping_file_records_the_file_it_came_from(
        self, cache_home, no_network
    ):
        """The client reads one mapping file, so every entry it holds names one source."""
        db, source, _path = ja4db.load_mapping_file()
        assert source == "embedded"
        assert {entry.source for entry in db.values()} == {"embedded"}


class TestBulkLookup:
    """`lookup_many` accepts a sequence of fingerprints and returns a result per
    fingerprint, FR-db-enrichment-7."""

    def test_the_client_publishes_the_signature_the_specification_states(self):
        parameters = list(inspect.signature(JA4DBClient.lookup_many).parameters)
        assert parameters == ["self", "fingerprints"]

    def test_a_miss_holds_none_in_its_own_entry(self, cache_home, no_network):
        """A miss holds None rather than no entry, so a caller reads one entry for every
        fingerprint it passed."""
        results = JA4DBClient().lookup_many([BUNDLED_FINGERPRINT, MISSING_FINGERPRINT])
        assert list(results) == [BUNDLED_FINGERPRINT, MISSING_FINGERPRINT]
        assert results[MISSING_FINGERPRINT] is None
        assert results[BUNDLED_FINGERPRINT] is not None

    def test_an_empty_sequence_returns_an_empty_mapping(self, cache_home, no_network):
        assert JA4DBClient().lookup_many([]) == {}

    def test_a_repeated_fingerprint_holds_one_entry(self, cache_home, no_network):
        """The published return type is a mapping the fingerprint keys, so a sequence that
        repeats a fingerprint holds one entry for it."""
        results = JA4DBClient().lookup_many([BUNDLED_FINGERPRINT] * 3)
        assert len(results) == 1

    def test_the_entry_count_matches_the_count_of_distinct_fingerprints(
        self, cache_home, no_network
    ):
        fingerprints = [f"t13d1516h2_000000000000_{index:012d}" for index in range(50)]
        results = JA4DBClient().lookup_many(fingerprints + fingerprints)
        assert len(results) == len(fingerprints)
        assert all(results[fingerprint] is None for fingerprint in fingerprints)

    def test_the_source_of_every_result_reaches_the_caller(self, cache_home, no_network):
        write_cache_file(cache_home)
        results = JA4DBClient().lookup_many([CACHE_ONLY_FINGERPRINT, MISSING_FINGERPRINT])
        assert results[CACHE_ONLY_FINGERPRINT] is not None
        assert results[CACHE_ONLY_FINGERPRINT].source == "cache"


class TestBulkLookupDoesNotMultiplyTheNetwork:
    """One consent covers one request per fingerprint the mapping file holds no entry
    for. A bulk call that repeats a fingerprint discloses it once."""

    def test_100000_fingerprints_with_the_remote_lookup_off_perform_no_request(
        self, cache_home, no_network, monkeypatch
    ):
        """`features/07-db-enrichment.md` states this case. The `lookup` extra is absent
        from this environment, so the case installs a stand-in that opens a socket."""
        recorder = db_offline.RecordingRequests(
            error=db_offline.SocketAttempted("the stand-in opens no port")
        )
        fingerprints = [f"t13d1516h2_000000000000_{index:012d}" for index in range(100000)]
        client = JA4DBClient()
        monkeypatch.setitem(sys.modules, "requests", recorder)
        results = client.lookup_many(fingerprints)
        assert len(results) == 100000
        assert recorder.calls == []

    def test_a_repeated_miss_reaches_the_service_once(self, cache_home, monkeypatch):
        """The lookup cache holds a miss as well as a hit, so a repeated fingerprint costs
        one request. A call that sent one request per occurrence would turn one consent
        into a thousand disclosures."""
        recorder = db_offline.RecordingRequests(
            response=db_offline.StubResponse(status_code=404, payload={})
        )
        client = JA4DBClient(allow_remote=True)
        monkeypatch.setitem(sys.modules, "requests", recorder)
        client.lookup_many([MISSING_FINGERPRINT] * 1000)
        assert len(recorder.calls) == 1

    def test_the_service_reads_one_request_for_each_distinct_miss(self, cache_home, monkeypatch):
        """The lookup service publishes no bulk interface, so one miss costs one request.
        A hit from the mapping file costs none."""
        payload = {"application": "Test Client", "type": "ja4", "notes": ""}
        recorder = db_offline.RecordingRequests(response=db_offline.StubResponse(payload=payload))
        misses = [f"t99z9999h0_000000000000_{index:012d}" for index in range(5)]
        client = JA4DBClient(allow_remote=True)
        monkeypatch.setitem(sys.modules, "requests", recorder)
        results = client.lookup_many(misses + [BUNDLED_FINGERPRINT] * 5)
        assert len(recorder.calls) == 5
        assert results[BUNDLED_FINGERPRINT] is not None
        assert results[BUNDLED_FINGERPRINT].source == "embedded"
        assert results[misses[0]] is not None
        assert results[misses[0]].source == "remote"
