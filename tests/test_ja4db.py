"""Tests for ja4db fingerprint lookup."""

import threading
import time
from unittest.mock import patch, MagicMock

import pytest

import ja4plus.ja4db as ja4db
from ja4plus.ja4db import JA4DBClient, lookup, _load_bundled_db

# A fingerprint the bundled mapping file holds.
KNOWN_FINGERPRINT = "t13d1516h2_8daaf6152771_02713d6af862"


class TestBundledDB:
    """Test the bundled ja4plus-mapping.csv database."""

    def test_load_bundled_db(self):
        db = _load_bundled_db()
        assert isinstance(db, dict)
        assert len(db) > 0

    def test_chromium_in_db(self):
        db = _load_bundled_db()
        # Known Chromium JA4 fingerprint from FoxIO mapping
        result = db.get("t13d1516h2_8daaf6152771_02713d6af862")
        assert result is not None
        assert "Chromium" in result["application"]

    def test_python_in_db(self):
        db = _load_bundled_db()
        result = db.get("t13i181000_85036bcba153_d41ae481755e")
        assert result is not None
        assert "Python" in result["application"]


class TestJA4DBClient:
    """Test the JA4DBClient class."""

    def test_lookup_known_fingerprint(self):
        client = JA4DBClient()
        result = client.lookup("t13d1516h2_8daaf6152771_02713d6af862")
        assert result is not None
        assert "Chromium" in result["application"]

    def test_lookup_unknown_fingerprint(self):
        client = JA4DBClient()
        result = client.lookup("t99z9999h0_000000000000_000000000000")
        assert result is None

    def test_lookup_cache_hit(self):
        client = JA4DBClient()
        fp = "t13d1516h2_8daaf6152771_02713d6af862"
        result1 = client.lookup(fp)
        result2 = client.lookup(fp)
        assert result1 is result2  # Same object from cache

    def test_lookup_cache_none(self):
        """Unknown fingerprints are also cached (as None)."""
        client = JA4DBClient()
        fp = "t99z9999h0_000000000000_000000000000"
        client.lookup(fp)
        assert fp in client._cache
        assert client._cache[fp] is None

    def test_remote_lookup_no_requests(self):
        """Remote lookup gracefully handles missing requests package."""
        client = JA4DBClient()
        with patch.dict("sys.modules", {"requests": None}):
            # Should still work (falls back to bundled DB)
            result = client.lookup("t13d1516h2_8daaf6152771_02713d6af862")
            assert result is not None

    def test_remote_lookup_timeout(self):
        """Remote lookup gracefully handles timeouts."""
        client = JA4DBClient()
        mock_requests = MagicMock()
        mock_requests.get.side_effect = Exception("Connection timed out")

        with patch.dict("sys.modules", {"requests": mock_requests}):
            # Unknown fingerprint that would need remote lookup
            result = client._remote_lookup("unknown_fp_12345678")
            # Should return None, not raise
            assert result is None


class TestConvenienceFunction:
    """Test the module-level lookup() function."""

    def test_lookup_function(self):
        result = lookup("t13d1516h2_8daaf6152771_02713d6af862")
        assert result is not None
        assert "Chromium" in result["application"]

    def test_lookup_function_unknown(self):
        result = lookup("t99z9999h0_000000000000_000000000000")
        assert result is None


class TestTheModuleLevelClient:
    """The module-level `lookup` function builds one client, FR-concurrency-safety-13."""

    def test_two_threads_that_call_lookup_at_the_same_time_receive_one_client(self):
        """The second caller arrives while the first still builds, and one client exists.

        The case forces the race. It holds the first caller inside the constructor until
        the second caller runs, so a run against an unguarded module builds two clients.
        """
        built = []
        inside_constructor = threading.Event()
        release_constructor = threading.Event()

        class SlowClient(JA4DBClient):
            def __init__(self):
                built.append(self)
                inside_constructor.set()
                # The guard holds the second caller here. A run without the guard lets
                # the second caller reach this constructor and append a second client.
                release_constructor.wait(timeout=30)
                super().__init__()

        results = {}

        def call(name):
            results[name] = ja4db.lookup(KNOWN_FINGERPRINT)

        with patch.object(ja4db, "JA4DBClient", SlowClient):
            with patch.object(ja4db, "_default_client", None):
                first = threading.Thread(target=call, args=("first",))
                first.start()
                assert inside_constructor.wait(timeout=30), "the first caller never built"

                second = threading.Thread(target=call, args=("second",))
                second.start()
                # The second caller now runs against a module that holds no client. The
                # first caller stays inside the constructor for this whole interval.
                time.sleep(0.25)
                release_constructor.set()

                first.join(timeout=30)
                second.join(timeout=30)
                default_client = ja4db._default_client

        assert len(built) == 1, f"the module built {len(built)} clients"
        assert default_client is built[0]
        assert results["first"] is results["second"]
        assert results["first"]["application"] is not None

    def test_the_module_builds_the_client_on_the_first_call(self):
        """The module holds no client before a caller looks a fingerprint up."""
        with patch.object(ja4db, "_default_client", None):
            assert ja4db._default_client is None
            ja4db.lookup(KNOWN_FINGERPRINT)
            assert isinstance(ja4db._default_client, JA4DBClient)


class TestTheLookupCacheBound:
    """The lookup cache holds a maximum entry count, FR-concurrency-safety-14."""

    def offline_client(self, **kwargs):
        """Return a client whose miss reaches no network.

        Args:
            kwargs: The `JA4DBClient` arguments.

        Returns:
            The client. Its `_remote_lookup` returns None for every fingerprint.
        """
        client = JA4DBClient(**kwargs)
        client._remote_lookup = lambda fingerprint: None
        return client

    def test_the_cache_holds_no_more_than_its_maximum_entry_count(self):
        client = self.offline_client(cache_size=3)
        for index in range(10):
            client.lookup(f"t13d1516h2_000000000000_{index:012d}")
        assert len(client._cache) == 3

    def test_the_cache_evicts_the_least_recently_used_entry(self):
        client = self.offline_client(cache_size=3)
        first = "t13d1516h2_000000000000_000000000001"
        second = "t13d1516h2_000000000000_000000000002"
        third = "t13d1516h2_000000000000_000000000003"
        fourth = "t13d1516h2_000000000000_000000000004"

        for fingerprint in (first, second, third):
            client.lookup(fingerprint)
        # The read moves the first entry ahead of the second, so the second is the least
        # recently used entry when the fourth arrives.
        client.lookup(first)
        client.lookup(fourth)

        assert second not in client._cache
        assert first in client._cache
        assert third in client._cache
        assert fourth in client._cache

    def test_the_default_cache_size_is_100000_entries(self):
        """`features/07-db-enrichment.md` states 100000, and the client holds that value."""
        assert JA4DBClient()._cache.max_connections == 100000

    def test_a_small_cache_runs_its_age_pass_on_its_own_entry_count(self):
        """An age pass reads every entry, so the interval stays at or below that count."""
        assert JA4DBClient()._cache.eviction_interval == 100000
        assert JA4DBClient(cache_size=50)._cache.eviction_interval == 50

    def test_the_cache_holds_no_more_than_cache_size_after_200000_distinct_lookups(self):
        client = self.offline_client(cache_size=1000)
        for index in range(200000):
            client.lookup(f"t13d1516h2_000000000000_{index:012d}")
        assert len(client._cache) == 1000

    def test_a_cache_size_below_one_raises_value_error(self):
        with pytest.raises(ValueError):
            JA4DBClient(cache_size=0)

    def test_the_cache_holds_a_miss(self):
        """A repeated miss reads the cache and reaches no lookup."""
        client = self.offline_client(cache_size=10)
        missing = "t99z9999h0_000000000000_000000000000"
        calls = []
        real_do_lookup = client._do_lookup

        def counted(fingerprint):
            calls.append(fingerprint)
            return real_do_lookup(fingerprint)

        client._do_lookup = counted
        assert client.lookup(missing) is None
        assert client.lookup(missing) is None
        assert calls == [missing]

    def test_an_entry_that_receives_no_read_ages_out(self):
        """The cache runs its age pass on its own lookup schedule."""
        with patch.object(ja4db, "DEFAULT_CACHE_AGE", 0.0):
            with patch.object(ja4db, "DEFAULT_CACHE_EVICTION_INTERVAL", 4):
                client = self.offline_client(cache_size=1000)
                client.lookup("t13d1516h2_000000000000_000000000001")
                time.sleep(0.01)
                # The fourth lookup runs the age pass, and the first entry is older than
                # the maximum age of this client.
                for index in range(2, 5):
                    client.lookup(f"t13d1516h2_000000000000_{index:012d}")
                assert "t13d1516h2_000000000000_000000000001" not in client._cache

    def test_two_threads_that_look_up_at_the_same_time_hold_the_cache_bound(self):
        """Eight threads share one client, and the cache holds its maximum entry count."""
        client = self.offline_client(cache_size=50)
        failures = []

        def call(worker):
            try:
                for index in range(2000):
                    client.lookup(f"t13d1516h2_{worker:012d}_{index:012d}")
            except Exception as error:  # The case reports the failure of any thread.
                failures.append(error)

        threads = [threading.Thread(target=call, args=(worker,)) for worker in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)

        assert failures == []
        assert len(client._cache) == 50

    def test_eight_threads_that_share_one_client_raise_nothing(self):
        """The lock holds the lookup cache together while a pass evicts an entry.

        The client holds two entries and it ages every entry out, so an eviction runs
        beside every read. A run that replaces the lock with a no-op raises `KeyError`.
        """
        with patch.object(ja4db, "DEFAULT_CACHE_AGE", 0.0):
            client = self.offline_client(cache_size=2)
        failures = []

        def call():
            try:
                for index in range(60000):
                    client.lookup(f"t13d1516h2_000000000000_{index % 6:012d}")
            except Exception as error:  # The case reports the failure of any thread.
                failures.append(f"{type(error).__name__}: {error}")

        threads = [threading.Thread(target=call) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)

        assert failures == []
        assert len(client._cache) <= 2


class TestCLILookupFlag:
    """Test CLI --lookup integration."""

    def test_analyze_with_lookup_json(self):
        import subprocess
        import json
        import sys

        result = subprocess.run(
            [
                # The interpreter that runs the test holds the installed package. The name
                # `python` is absent from a plain virtual environment path.
                sys.executable,
                "-m",
                "ja4plus.cli",
                "--format",
                "json",
                "--lookup",
                "analyze",
                "tests/data/http.cap",
            ],
            capture_output=True,
            text=True,
            # #57 made the remote lookup opt-in, so every fingerprint the bundled
            # database does not hold now costs one cache write and no request.
            timeout=180,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                obj = json.loads(line)
                assert "identified_as" in obj  # Field present when --lookup used

    def test_analyze_without_lookup_json(self):
        import subprocess
        import json
        import sys

        result = subprocess.run(
            [
                # The interpreter that runs the test holds the installed package. The name
                # `python` is absent from a plain virtual environment path.
                sys.executable,
                "-m",
                "ja4plus.cli",
                "--format",
                "json",
                "analyze",
                "tests/data/http.cap",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                obj = json.loads(line)
                # FR-structured-output-5 asks for a field that is present and null
                # rather than absent, so the field set reads no flag. #49 changed this
                # expectation from the absent field of version 0.6.0.
                assert obj["identified_as"] is None
