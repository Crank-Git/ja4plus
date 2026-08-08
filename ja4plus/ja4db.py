"""
JA4+ fingerprint lookup client.

Identifies known applications, libraries, and operating systems from JA4+
fingerprints using FoxIO's ja4plus-mapping.csv as a local database.

Usage:
    from ja4plus.ja4db import JA4DBClient
    client = JA4DBClient()
    result = client.lookup("t13d1516h2_8daaf6152771_02713d6af862")
    # {"application": "Chromium Browser", "type": "ja4"}
"""

# Python 3.9 is the floor, and it evaluates no annotation written as `str | None`
# without this import.
from __future__ import annotations

import csv
import logging
import os
import threading

from ja4plus.utils.state_table import DEFAULT_MAX_CONNECTION_AGE, BoundedStateTable

logger = logging.getLogger(__name__)

# One match the mapping file or the remote interface holds. The three keys are
# `application`, `type` and `notes`.
LookupResult = dict[str, str]

# Bundled mapping from FoxIO's ja4plus-mapping.csv
_MAPPING_URL = "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv"
_BUNDLED_CSV = os.path.join(os.path.dirname(__file__), "data", "ja4plus-mapping.csv")

# The maximum entry count of the lookup cache. `features/07-db-enrichment.md` line 112
# states 100000, and line 134 publishes the same number as the `cache_size` default.
# The `## Terms` table names the lookup cache no state table, so the 10000 of
# `features/03-concurrency-safety.md` describes a different object.
DEFAULT_CACHE_SIZE = 100000

# The maximum age of one lookup cache entry, in seconds. One project holds one maximum
# age.
DEFAULT_CACHE_AGE = DEFAULT_MAX_CONNECTION_AGE

# The maximum count of lookups between two age eviction passes. A pass reads every
# entry, so an interval below the entry count costs more than one entry read for each
# lookup. A client that holds a smaller lookup cache reads its own entry count instead,
# and its age pass therefore runs.
DEFAULT_CACHE_EVICTION_INTERVAL = DEFAULT_CACHE_SIZE

# The value the lookup cache holds for no fingerprint. A cached miss holds None, so a
# read needs a value that no lookup produces.
_UNCACHED = object()


def _load_bundled_db() -> dict[str, LookupResult]:
    """Load the bundled ja4plus-mapping.csv into a lookup dict."""
    db: dict[str, LookupResult] = {}
    csv_path = _BUNDLED_CSV
    if not os.path.exists(csv_path):
        logger.debug("No bundled mapping CSV found at %s", csv_path)
        return db

    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Build identification string from available fields
                ident_parts: list[str] = []
                for field in ("Application", "Library", "Device", "OS"):
                    val = row.get(field, "").strip()
                    if val:
                        ident_parts.append(val)
                if not ident_parts:
                    continue

                ident = " / ".join(ident_parts)
                notes = row.get("Notes", "").strip()

                # Index by each fingerprint type present
                for fp_type in ("ja4", "ja4s", "ja4h", "ja4x", "ja4t", "ja4tscan"):
                    fp_val = row.get(fp_type, "").strip()
                    if fp_val:
                        db[fp_val] = {
                            "application": ident,
                            "type": fp_type,
                            "notes": notes,
                        }
    except (OSError, csv.Error) as e:
        logger.warning("Failed to load bundled mapping CSV: %s", e)

    return db


class JA4DBClient:
    """Client for looking up JA4+ fingerprints against known databases.

    Several threads may share one client. The client holds a lock over the lookup cache
    read and over the lookup cache write.

    Args:
        cache_size: The maximum entry count of the lookup cache.

    Raises:
        ValueError: `cache_size` is below one.
    """

    def __init__(self, cache_size: int = DEFAULT_CACHE_SIZE) -> None:
        # A monitor looks every fingerprint it reads up, so a plain dictionary here holds
        # one entry for every fingerprint the traffic carries.
        self._cache = BoundedStateTable(
            max_connections=cache_size,
            max_connection_age=DEFAULT_CACHE_AGE,
            # An age pass reads every entry, so a lookup cache below the default entry
            # count runs its pass on its own entry count.
            eviction_interval=min(DEFAULT_CACHE_EVICTION_INTERVAL, cache_size),
        )
        self._cache_lock = threading.Lock()
        self._db = _load_bundled_db()
        logger.debug("JA4DB client initialized with %d bundled entries", len(self._db))

    def lookup(self, fingerprint: str) -> LookupResult | None:
        """
        Look up a fingerprint.

        Args:
            fingerprint: JA4+ fingerprint string

        Returns:
            dict with 'application', 'type', 'notes' keys, or None if unknown.
        """
        with self._cache_lock:
            # The lookup cache reads no packet, so one lookup announces itself as one
            # arrival, and the lookup cache runs its age pass on that schedule.
            self._cache.on_packet()
            # A read of one key holds that entry against both bounds, so one read costs
            # less than the `in` operator plus the read that follows it.
            # The lookup cache holds a result or None, and it returns `_UNCACHED` for a
            # fingerprint it holds no entry for. The identity test below separates the
            # two, so the annotation states the type of a value the cache holds.
            cached: LookupResult | None = self._cache.get(fingerprint, _UNCACHED)
            if cached is not _UNCACHED:
                return cached

        # A remote lookup takes up to 5 seconds, so no thread holds the lock across it.
        # Two threads that miss on one fingerprint each read the result, and the second
        # write replaces an equal value.
        result = self._do_lookup(fingerprint)
        with self._cache_lock:
            self._cache[fingerprint] = result
        return result

    def _do_lookup(self, fingerprint: str) -> LookupResult | None:
        """Perform the actual lookup."""
        # Check bundled database first
        if fingerprint in self._db:
            return self._db[fingerprint]

        # Try remote API if requests is available
        try:
            return self._remote_lookup(fingerprint)
        except Exception as e:
            logger.debug("Remote lookup failed for %s: %s", fingerprint, e)
            return None

    def _remote_lookup(self, fingerprint: str) -> LookupResult | None:
        """Try to look up via ja4db.com (requires requests)."""
        try:
            import requests
        except ImportError:
            return None

        try:
            resp = requests.get(
                f"https://ja4db.com/api/read/{fingerprint}",
                timeout=5,
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data and isinstance(data, dict):
                    return {
                        "application": data.get("application", "Unknown"),
                        "type": data.get("type", ""),
                        "notes": data.get("notes", ""),
                    }
        except (ValueError, KeyError, AttributeError):
            pass
        except Exception as e:
            logger.debug("ja4db.com API error: %s", e)

        return None


# Module-level convenience
_default_client: JA4DBClient | None = None

# Two threads that both read no client build two clients, and each one reads the mapping
# file again. The port guards the same construction with `sync.Once`, at `lookup.go:31`.
_client_lock = threading.Lock()


def lookup(fingerprint: str) -> LookupResult | None:
    """Return the match for the fingerprint from the module-level client.

    The first caller builds the client. Several threads that call this function at the
    same time receive results from one client.

    Args:
        fingerprint: A JA4+ fingerprint string.

    Returns:
        The match, or None when the mapping file holds no entry.
    """
    global _default_client
    client = _default_client
    if client is None:
        with _client_lock:
            if _default_client is None:
                _default_client = JA4DBClient()
            client = _default_client
    return client.lookup(fingerprint)
