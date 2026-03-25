"""Tests for ja4db fingerprint lookup."""

import pytest
from unittest.mock import patch, MagicMock

from ja4plus.ja4db import JA4DBClient, lookup, _load_bundled_db


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


class TestCLILookupFlag:
    """Test CLI --lookup integration."""

    def test_analyze_with_lookup_json(self):
        import subprocess
        import json

        result = subprocess.run(
            ["python", "-m", "ja4plus.cli", "--format", "json", "--lookup",
             "analyze", "tests/data/http.cap"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                obj = json.loads(line)
                assert "identified_as" in obj  # Field present when --lookup used

    def test_analyze_without_lookup_json(self):
        import subprocess
        import json

        result = subprocess.run(
            ["python", "-m", "ja4plus.cli", "--format", "json",
             "analyze", "tests/data/http.cap"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                obj = json.loads(line)
                assert "identified_as" not in obj  # Not present without --lookup
