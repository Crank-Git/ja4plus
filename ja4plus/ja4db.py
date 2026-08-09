"""
JA4+ fingerprint lookup client.

Identifies known applications, libraries, and operating systems from JA4+
fingerprints using FoxIO's ja4plus-mapping.csv as a local database.

Usage:
    from ja4plus.ja4db import JA4DBClient
    client = JA4DBClient()
    result = client.lookup("t13d1516h2_8daaf6152771_02713d6af862")
    # LookupResult(application="Chromium Browser", type="ja4", notes="", source="embedded")
"""

# Python 3.9 is the floor, and it evaluates no annotation written as `str | None`
# without this import.
from __future__ import annotations

import csv
import logging
import os
import sys
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import quote

from ja4plus.utils.state_table import DEFAULT_MAX_CONNECTION_AGE, BoundedStateTable

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LookupResult:
    """One match, with the place the match came from.

    `LookupResult` of `lookup.go:23` holds `Application`, `Type` and `Notes`, and
    `CLAUDE.md` parity rule 2 adopts the three. FR-db-enrichment-8 adds `source`, because
    an analyst judges a name by the place it came from.

    The type is frozen, because the lookup cache hands one result to every caller that
    asks for one fingerprint.

    Attributes:
        application: The name the mapping file or the lookup service gives.
        type: The fingerprint method the entry names, such as `ja4`.
        notes: The note the entry carries, or an empty string.
        source: The place the match came from: `embedded`, `cache` or `remote`.
    """

    application: str
    type: str
    notes: str
    source: str


# Bundled mapping from FoxIO's ja4plus-mapping.csv
_MAPPING_URL = "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv"
_BUNDLED_CSV = os.path.join(os.path.dirname(__file__), "data", "ja4plus-mapping.csv")

# The directory name and the file name that `db update` writes under the platform cache
# directory. `CachedDatabasePath` of `lookup.go:210` writes the same two names, so one
# `db update` serves both implementations.
_CACHE_DIR_NAME = "ja4plus"
_CACHE_FILE_NAME = "ja4plus-mapping.csv"

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

# The maximum interval of one remote lookup, in seconds.
# `features/07-db-enrichment.md` line 113 states 5 seconds, and it states that no
# operator configures the interval before version 1.0.0.
_REMOTE_TIMEOUT = 5.0

# The value the lookup cache holds for no fingerprint. A cached miss holds None, so a
# read needs a value that no lookup produces.
_UNCACHED = object()


def cache_dir_path() -> str:
    """Return the cache directory of the program.

    The path follows the platform convention that
    `features/07-db-enrichment.md` states: `$XDG_CACHE_HOME/ja4plus` or `~/.cache/ja4plus`
    on Linux, and `~/Library/Caches/ja4plus` on macOS. `os.UserCacheDir` of the port reads
    the same two names.

    Returns:
        The directory path. The caller creates the directory.
    """
    if sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Caches")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, _CACHE_DIR_NAME)


def cache_file_path() -> str:
    """Return the path of the cached mapping file.

    Returns:
        The path. The file exists only after one `db update` run.
    """
    return os.path.join(cache_dir_path(), _CACHE_FILE_NAME)


def load_mapping_file() -> tuple[dict[str, LookupResult], str, str]:
    """Return the mapping the client reads, with the source and the path it came from.

    The client prefers the cached mapping file over the bundled one,
    FR-db-enrichment-13. This program did not write the cached file, so a cached file that
    holds no entry falls back to the bundled file. An empty file, a corrupt file and a
    file the user cannot read all reach that fallback.

    Returns:
        The mapping, the source as `embedded` or `cache`, and the path of the file read.
    """
    path = cache_file_path()
    if os.path.exists(path):
        cached = _read_mapping_file(path, "cache")
        if cached:
            return cached, "cache", path
        logger.warning(
            "The cached mapping file at %s holds no entry. The bundled file answers "
            "instead. Run `ja4plus db update` to write it again.",
            path,
        )
    # The prose of this project calls the file bundled, and the published value is
    # `embedded`. `lookup.go:31` of the port sets `dbSource = "embedded"`, and `CLAUDE.md`
    # parity rule 2 gives the port the interface. The user decided this on 2026-08-08, and
    # `features/07-db-enrichment.md` records it.
    return _load_bundled_db(), "embedded", _BUNDLED_CSV


def _load_bundled_db() -> dict[str, LookupResult]:
    """Load the bundled ja4plus-mapping.csv into a lookup dict."""
    return _read_mapping_file(_BUNDLED_CSV, "embedded")


def _read_mapping_file(csv_path: str, source: str) -> dict[str, LookupResult]:
    """Return the mapping that one ja4plus-mapping.csv file holds.

    Args:
        csv_path: The path of the file to read.
        source: The source every entry of this file records: `embedded` or `cache`.

    Returns:
        The mapping, or an empty mapping when the file is absent, unreadable or corrupt.
    """
    db: dict[str, LookupResult] = {}
    if not os.path.exists(csv_path):
        logger.debug("No mapping file found at %s", csv_path)
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
                        db[fp_val] = LookupResult(
                            application=ident,
                            type=fp_type,
                            notes=notes,
                            source=source,
                        )
    # A cached mapping file is input that this program did not write. A file of arbitrary
    # bytes raises `UnicodeDecodeError`, which is no `OSError`, so the handler names it.
    except (OSError, csv.Error, UnicodeDecodeError) as e:
        logger.warning("Failed to load the mapping file at %s: %s", csv_path, e)

    return db


def _read_remote_body(data: object) -> LookupResult | None:
    """Return the match that the response body of the lookup service holds.

    The service publishes no versioned API document. The client therefore reads every
    shape it does not know as a miss, and it lets no unchecked field reach a caller.

    Args:
        data: The value the response body decoded to.

    Returns:
        The match, or None when the body carries no application name.
    """
    if not isinstance(data, dict):
        return None
    application: object = data.get("application")
    if not isinstance(application, str) or not application:
        return None
    fields: dict[str, str] = {}
    for name in ("type", "notes"):
        value: object = data.get(name)
        fields[name] = value if isinstance(value, str) else ""
    return LookupResult(
        application=application,
        type=fields["type"],
        notes=fields["notes"],
        # The service answered, so the caller reads the name of the service and not the
        # name of a file.
        source="remote",
    )


class JA4DBClient:
    """Client for looking up JA4+ fingerprints against known databases.

    Several threads may share one client. The client holds a lock over the lookup cache
    read and over the lookup cache write.

    The client reads the cached mapping file when one exists, and the bundled mapping
    file otherwise. The client reaches no network of its own. A fingerprint
    describes traffic the operator observed, so a request to `ja4db.com` discloses that
    traffic to a third party. The operator asks for that disclosure with
    `allow_remote=True`.

    Args:
        allow_remote: True permits a request to `ja4db.com` for a fingerprint the
            mapping file holds no entry for.
        cache_size: The maximum entry count of the lookup cache.

    Raises:
        TypeError: `allow_remote` is no bool.
        ValueError: `cache_size` is below one.
    """

    def __init__(self, allow_remote: bool = False, cache_size: int = DEFAULT_CACHE_SIZE) -> None:
        # `cache_size` was the first parameter before #57. A caller that wrote
        # `JA4DBClient(100)` for a lookup cache of 100 entries would now permit the
        # disclosure that #57 repairs, and would keep the default entry count. The
        # client refuses that call rather than reach the lookup service for it.
        if not isinstance(allow_remote, bool):
            raise TypeError("allow_remote takes True or False")
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
        self._allow_remote = allow_remote
        # The client prefers the cached mapping file over the bundled one,
        # FR-db-enrichment-13. An operator who ran `db update` reads the newer file.
        self._db, source, path = load_mapping_file()
        logger.debug(
            "JA4DB client initialized with %d entries from the %s mapping file at %s",
            len(self._db),
            source,
            path,
        )

    def lookup(self, fingerprint: str) -> LookupResult | None:
        """Return the match for one fingerprint.

        Args:
            fingerprint: A JA4+ fingerprint string.

        Returns:
            The match, with the source it came from, or None when no source holds an
            entry.
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

    def lookup_many(self, fingerprints: Sequence[str]) -> dict[str, LookupResult | None]:
        """Return one entry for every fingerprint of the sequence.

        A miss holds None, so the caller reads one entry for every fingerprint it passed.
        The returned mapping keys the fingerprint, so a sequence that repeats a
        fingerprint holds one entry for it.

        This method reaches the lookup service under the rule that `lookup` holds, and
        under no other rule. A client that the operator built with `allow_remote=False`
        therefore sends nothing, whatever count of fingerprints the call carries. A client
        that the operator built with `allow_remote=True` sends one request for each
        fingerprint the mapping file holds no entry for. The lookup cache holds a miss as
        well as a hit, so a repeated fingerprint costs one request and no more.

        Args:
            fingerprints: The fingerprints to look up, in any order.

        Returns:
            The mapping from each fingerprint to its match, or to None for a miss.
        """
        return {fingerprint: self.lookup(fingerprint) for fingerprint in fingerprints}

    def _do_lookup(self, fingerprint: str) -> LookupResult | None:
        """Return the match for the fingerprint from the mapping file or the service.

        Args:
            fingerprint: A JA4+ fingerprint string.

        Returns:
            The match, or None when no source holds an entry.
        """
        # The mapping file answers first, so a hit costs no request.
        if fingerprint in self._db:
            return self._db[fingerprint]

        # A client that reaches the service tells it which fingerprint the operator
        # observed. A miss stays a miss until the operator asks for that disclosure.
        if not self._allow_remote:
            return None

        # #319 owns this wide handler. The handlers that name their errors are inside
        # `_remote_lookup`.
        try:
            return self._remote_lookup(fingerprint)
        except Exception as e:
            logger.debug("Remote lookup failed for %s: %s", fingerprint, e)
            return None

    def _remote_lookup(self, fingerprint: str) -> LookupResult | None:
        """Return the match the lookup service holds for the fingerprint.

        The caller decides whether the request happens. `_do_lookup` calls this method
        only for a client that the operator built with `allow_remote=True`. The `lookup`
        extra installs the `requests` package that the request needs.

        Args:
            fingerprint: A JA4+ fingerprint string.

        Returns:
            The match, or None when the request fails, the package is absent, or the
            response holds a shape the client does not know.
        """
        try:
            import requests
        except ImportError:
            return None

        # `lookup` accepts any string, and a string that carries `/` or `?` would name
        # another path on the service. A JA4+ fingerprint holds no character that the
        # escape changes, so the escape moves no request the project makes.
        path = quote(fingerprint, safe="")

        try:
            resp = requests.get(
                f"https://ja4db.com/api/read/{path}",
                timeout=_REMOTE_TIMEOUT,
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 200:
                return _read_remote_body(resp.json())
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
