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

import csv
import logging
import os

logger = logging.getLogger(__name__)

# Bundled mapping from FoxIO's ja4plus-mapping.csv
_MAPPING_URL = "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv"
_BUNDLED_CSV = os.path.join(os.path.dirname(__file__), "data", "ja4plus-mapping.csv")


def _load_bundled_db():
    """Load the bundled ja4plus-mapping.csv into a lookup dict."""
    db = {}
    csv_path = _BUNDLED_CSV
    if not os.path.exists(csv_path):
        logger.debug("No bundled mapping CSV found at %s", csv_path)
        return db

    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Build identification string from available fields
                ident_parts = []
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
    """Client for looking up JA4+ fingerprints against known databases."""

    def __init__(self):
        self._cache = {}
        self._db = _load_bundled_db()
        logger.debug("JA4DB client initialized with %d bundled entries", len(self._db))

    def lookup(self, fingerprint):
        """
        Look up a fingerprint.

        Args:
            fingerprint: JA4+ fingerprint string

        Returns:
            dict with 'application', 'type', 'notes' keys, or None if unknown.
        """
        if fingerprint in self._cache:
            return self._cache[fingerprint]

        result = self._do_lookup(fingerprint)
        self._cache[fingerprint] = result
        return result

    def _do_lookup(self, fingerprint):
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

    def _remote_lookup(self, fingerprint):
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
_default_client = None


def lookup(fingerprint):
    """Convenience function using a module-level client."""
    global _default_client
    if _default_client is None:
        _default_client = JA4DBClient()
    return _default_client.lookup(fingerprint)
