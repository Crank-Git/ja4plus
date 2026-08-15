"""The lookup reads both forms of an empty-list value, on the parts the ruling names.

#639 holds the ruling of 2026-08-15. FoxIO builds `ja4plus-mapping.csv` from an
implementation that writes `000000000000` for an empty list, and this project writes the
hash of the empty input instead. The lookup therefore reads the two forms as one value,
and it reads them on the parts the ruling of 2026-08-14 moved and on no other part.
"""

import csv

import pytest

import ja4plus.ja4db as ja4db
from ja4plus.ja4db import (
    _EMPTY_LIST_HASH,
    _EMPTY_LIST_PARTS,
    _EMPTY_LIST_SENTINEL,
    JA4DBClient,
    LookupResult,
    _empty_list_aliases,
    _load_bundled_db,
)

# The three JA4X rows of the bundled mapping file that carry the zero sentinel. #639
# names each one by line, and `test_the_bundled_mapping_file_holds_the_three_rows`
# reads the file rather than trust this list.
SLIVER_ISSUER_ROW = "000000000000_4f24da86fad6_bf0f0589fc03"
SLIVER_SECOND_ROW = "000000000000_7c32fa18c13e_bf0f0589fc03"
QAKBOT_EXTENSION_ROW = "2bab15409345_af684594efb4_000000000000"

# A JA4H row of the bundled mapping file. Part c and part d each hold the sentinel,
# which R17 and R27 of `docs/specs/foxio/JA4H.md` read as `no cookie`.
CHROMIUM_JA4H_ROW = "ge11nn08enus_050dd5cfb971_000000000000_000000000000"

# The header of `ja4plus-mapping.csv`, which a synthetic mapping file repeats.
MAPPING_FIELDS = [
    "Application",
    "Library",
    "Device",
    "OS",
    "ja4",
    "ja4s",
    "ja4h",
    "ja4x",
    "ja4t",
    "ja4tscan",
    "Notes",
]


def write_mapping_file(path, rows):
    """Write one mapping file that holds the rows, and return the path.

    Args:
        path: The file to write.
        rows: One dictionary for each row, keyed by a field of `MAPPING_FIELDS`.

    Returns:
        The path the caller passed.
    """
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MAPPING_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in MAPPING_FIELDS})
    return path


@pytest.fixture
def bundled_client(monkeypatch, tmp_path):
    """Return a client that reads the bundled mapping file.

    The client prefers a cached mapping file, and the host of this run may hold one. The
    fixture names a cache path that no file occupies, so the client reads the file this
    repository ships.
    """
    monkeypatch.setattr(ja4db, "cache_file_path", lambda: str(tmp_path / "absent.csv"))
    return JA4DBClient()


@pytest.fixture
def client_of(monkeypatch, tmp_path):
    """Return a factory that builds a client over one synthetic mapping file."""

    def build(rows):
        path = write_mapping_file(tmp_path / "mapping.csv", rows)
        monkeypatch.setattr(ja4db, "cache_file_path", lambda: str(path))
        return JA4DBClient()

    return build


class TestTheBundledRowsTheRulingCloses:
    """The three JA4X rows #639 names become matchable again."""

    def test_the_bundled_mapping_file_holds_the_three_rows(self):
        db = _load_bundled_db()
        for fingerprint in (SLIVER_ISSUER_ROW, SLIVER_SECOND_ROW, QAKBOT_EXTENSION_ROW):
            assert db[fingerprint].type == "ja4x"

    def test_an_empty_issuer_list_matches_the_first_sliver_row(self, bundled_client):
        hashed = f"{_EMPTY_LIST_HASH}_4f24da86fad6_bf0f0589fc03"
        result = bundled_client.lookup(hashed)
        assert result is not None
        assert result.application == "Sliver/Havoc C2 Server"
        assert result.type == "ja4x"

    def test_an_empty_issuer_list_matches_the_second_sliver_row(self, bundled_client):
        hashed = f"{_EMPTY_LIST_HASH}_7c32fa18c13e_bf0f0589fc03"
        result = bundled_client.lookup(hashed)
        assert result is not None
        assert result.application == "Sliver/Havoc C2 Server"

    def test_an_empty_extension_list_matches_the_qakbot_row(self, bundled_client):
        hashed = f"2bab15409345_af684594efb4_{_EMPTY_LIST_HASH}"
        result = bundled_client.lookup(hashed)
        assert result is not None
        assert result.application == "Qakbot C2"

    def test_a_value_that_holds_the_sentinel_keeps_its_match(self, bundled_client):
        for fingerprint in (SLIVER_ISSUER_ROW, SLIVER_SECOND_ROW, QAKBOT_EXTENSION_ROW):
            result = bundled_client.lookup(fingerprint)
            assert result is not None
            assert result.type == "ja4x"

    def test_the_bundled_mapping_file_gains_three_alias_values(self):
        aliases = _empty_list_aliases(_load_bundled_db())
        assert set(aliases) == {
            f"{_EMPTY_LIST_HASH}_4f24da86fad6_bf0f0589fc03",
            f"{_EMPTY_LIST_HASH}_7c32fa18c13e_bf0f0589fc03",
            f"2bab15409345_af684594efb4_{_EMPTY_LIST_HASH}",
        }

    def test_no_alias_shadows_a_row_of_the_bundled_mapping_file(self):
        db = _load_bundled_db()
        assert set(_empty_list_aliases(db)) & set(db) == set()


class TestTheCookiePartsRefuseTheFallback:
    """Part c and part d of JA4H hold `no cookie`, so the two forms name two values."""

    def test_the_ruling_names_part_b_of_ja4h_and_no_other_part(self):
        assert _EMPTY_LIST_PARTS["ja4h"] == (4, (1,))

    def test_a_sentinel_in_part_c_of_ja4h_gains_no_match(self, bundled_client):
        # `no cookie` in part c is a value of its own, so the hashed form names a request
        # that carries one cookie field and it names no row.
        assert (
            bundled_client.lookup(f"ge11nn08enus_050dd5cfb971_{_EMPTY_LIST_HASH}_000000000000")
            is None
        )

    def test_a_sentinel_in_part_d_of_ja4h_gains_no_match(self, bundled_client):
        assert (
            bundled_client.lookup(f"ge11nn08enus_050dd5cfb971_000000000000_{_EMPTY_LIST_HASH}")
            is None
        )

    def test_a_sentinel_in_both_cookie_parts_of_ja4h_gains_no_match(self, bundled_client):
        hashed = f"ge11nn08enus_050dd5cfb971_{_EMPTY_LIST_HASH}_{_EMPTY_LIST_HASH}"
        assert bundled_client.lookup(hashed) is None

    def test_the_chromium_ja4h_row_keeps_its_own_match(self, bundled_client):
        result = bundled_client.lookup(CHROMIUM_JA4H_ROW)
        assert result is not None
        assert result.type == "ja4h"

    def test_no_ja4h_row_of_the_bundled_mapping_file_gains_an_alias(self):
        db = _load_bundled_db()
        aliases = _empty_list_aliases(db)
        assert [key for key, value in aliases.items() if value.type == "ja4h"] == []


class TestPartBOfJA4HReadsBothForms:
    """The ruling of 2026-08-14 moved part b, so the two forms name one value there."""

    def test_a_row_whose_part_b_holds_the_sentinel_matches_the_hashed_form(self, client_of):
        row = {
            "Application": "Header Free Client",
            "ja4h": f"ge11nn00enus_{_EMPTY_LIST_SENTINEL}_000000000000_000000000000",
        }
        client = client_of([row])
        hashed = f"ge11nn00enus_{_EMPTY_LIST_HASH}_000000000000_000000000000"
        result = client.lookup(hashed)
        assert result is not None
        assert result.application == "Header Free Client"

    def test_a_row_whose_part_b_holds_the_hash_matches_the_sentinel_form(self, client_of):
        row = {
            "Application": "Header Free Client",
            "ja4h": f"ge11nn00enus_{_EMPTY_LIST_HASH}_000000000000_000000000000",
        }
        client = client_of([row])
        sentinel = f"ge11nn00enus_{_EMPTY_LIST_SENTINEL}_000000000000_000000000000"
        result = client.lookup(sentinel)
        assert result is not None
        assert result.application == "Header Free Client"

    def test_a_row_that_holds_the_sentinel_in_every_part_aliases_part_b_alone(self, client_of):
        fingerprint = "_".join(["ge11nn00enus"] + [_EMPTY_LIST_SENTINEL] * 3)
        client = client_of([{"Application": "Header Free Client", "ja4h": fingerprint}])
        assert set(client._empty_list_aliases) == {
            f"ge11nn00enus_{_EMPTY_LIST_HASH}_{_EMPTY_LIST_SENTINEL}_{_EMPTY_LIST_SENTINEL}"
        }


class TestTheMethodsTheRulingLeaves:
    """The fallback reaches the parts the ruling of 2026-08-14 moved and no other part."""

    def test_the_ruling_names_ja4x_and_ja4h_and_no_other_method(self):
        assert set(_EMPTY_LIST_PARTS) == {"ja4x", "ja4h"}

    def test_a_ja4_row_that_holds_the_sentinel_gains_no_alias(self, client_of):
        # `ja4plus/fingerprinters/ja4.py:202` still writes the sentinel for an empty
        # cipher list, so the two forms name two values in a JA4 value.
        fingerprint = f"t13d1516h2_{_EMPTY_LIST_SENTINEL}_02713d6af862"
        client = client_of([{"Application": "Cipherless Client", "ja4": fingerprint}])
        assert client._empty_list_aliases == {}
        assert client.lookup(f"t13d1516h2_{_EMPTY_LIST_HASH}_02713d6af862") is None

    def test_a_ja4s_row_that_holds_the_sentinel_gains_no_alias(self, client_of):
        fingerprint = f"t130200_1301_{_EMPTY_LIST_SENTINEL}"
        client = client_of([{"Application": "Bare Server", "ja4s": fingerprint}])
        assert client._empty_list_aliases == {}

    def test_a_ja4x_value_that_holds_no_empty_list_gains_no_alias(self, client_of):
        client = client_of(
            [{"Application": "Plain", "ja4x": "aaaaaaaaaaaa_bbbbbbbbbbbb_cccccccccccc"}]
        )
        assert client._empty_list_aliases == {}


class TestEveryPartOfAJA4XValue:
    """JA4X hashes all three of its parts, so an empty list reaches every one."""

    @pytest.mark.parametrize("index", [0, 1, 2])
    def test_the_sentinel_in_one_part_reads_the_hashed_form(self, client_of, index):
        parts = ["aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"]
        parts[index] = _EMPTY_LIST_SENTINEL
        client = client_of([{"Application": "One Empty List", "ja4x": "_".join(parts)}])
        parts[index] = _EMPTY_LIST_HASH
        result = client.lookup("_".join(parts))
        assert result is not None
        assert result.application == "One Empty List"

    def test_a_value_that_holds_two_empty_lists_reads_both_of_them(self, client_of):
        fingerprint = f"{_EMPTY_LIST_SENTINEL}_bbbbbbbbbbbb_{_EMPTY_LIST_SENTINEL}"
        client = client_of([{"Application": "Two Empty Lists", "ja4x": fingerprint}])
        both = f"{_EMPTY_LIST_HASH}_bbbbbbbbbbbb_{_EMPTY_LIST_HASH}"
        result = client.lookup(both)
        assert result is not None
        assert result.application == "Two Empty Lists"

    def test_a_value_that_holds_two_empty_lists_reads_each_one_alone(self, client_of):
        fingerprint = f"{_EMPTY_LIST_SENTINEL}_bbbbbbbbbbbb_{_EMPTY_LIST_SENTINEL}"
        client = client_of([{"Application": "Two Empty Lists", "ja4x": fingerprint}])
        first = f"{_EMPTY_LIST_HASH}_bbbbbbbbbbbb_{_EMPTY_LIST_SENTINEL}"
        second = f"{_EMPTY_LIST_SENTINEL}_bbbbbbbbbbbb_{_EMPTY_LIST_HASH}"
        assert client.lookup(first) is not None
        assert client.lookup(second) is not None


class TestEveryLookupPathReadsTheAlias:
    """A fallback that reaches one path and not another tells a caller nothing."""

    def test_lookup_many_reads_the_alias(self, bundled_client):
        hashed = f"{_EMPTY_LIST_HASH}_4f24da86fad6_bf0f0589fc03"
        results = bundled_client.lookup_many([hashed, CHROMIUM_JA4H_ROW])
        assert results[hashed] is not None
        assert results[CHROMIUM_JA4H_ROW] is not None

    def test_the_module_level_lookup_reads_the_alias(self, monkeypatch, tmp_path):
        monkeypatch.setattr(ja4db, "cache_file_path", lambda: str(tmp_path / "absent.csv"))
        monkeypatch.setattr(ja4db, "_default_client", None)
        hashed = f"{_EMPTY_LIST_HASH}_4f24da86fad6_bf0f0589fc03"
        result = ja4db.lookup(hashed)
        assert result is not None
        assert result.application == "Sliver/Havoc C2 Server"

    def test_the_lookup_cache_holds_the_alias_match(self, bundled_client):
        hashed = f"{_EMPTY_LIST_HASH}_4f24da86fad6_bf0f0589fc03"
        first = bundled_client.lookup(hashed)
        # The second read answers from the lookup cache, so it returns the same object.
        assert bundled_client.lookup(hashed) is first

    def test_the_alias_carries_the_source_of_the_row_it_came_from(self, bundled_client):
        hashed = f"{_EMPTY_LIST_HASH}_4f24da86fad6_bf0f0589fc03"
        result = bundled_client.lookup(hashed)
        assert result is not None
        assert result.source == "embedded"


class TestTheAliasTableStandsBesideTheMappingFile:
    """`db info` reports the entry count of the file, so the alias table stays apart."""

    def test_the_alias_table_moves_no_entry_count_of_the_mapping_file(self, monkeypatch, tmp_path):
        monkeypatch.setattr(ja4db, "cache_file_path", lambda: str(tmp_path / "absent.csv"))
        db, source, path = ja4db.load_mapping_file()
        assert db == _load_bundled_db()
        assert source == "embedded"

    def test_the_alias_of_a_row_is_the_result_that_row_holds(self):
        db = _load_bundled_db()
        aliases = _empty_list_aliases(db)
        hashed = f"{_EMPTY_LIST_HASH}_4f24da86fad6_bf0f0589fc03"
        assert aliases[hashed] is db[SLIVER_ISSUER_ROW]

    def test_an_empty_mapping_file_produces_an_empty_alias_table(self):
        assert _empty_list_aliases({}) == {}

    def test_a_row_whose_part_count_misses_the_form_gains_no_alias(self):
        # A malformed row names no part index, so the ruling reaches none of its parts.
        db = {
            f"{_EMPTY_LIST_SENTINEL}_aaaaaaaaaaaa": LookupResult(
                application="Short", type="ja4x", notes="", source="embedded"
            )
        }
        assert _empty_list_aliases(db) == {}
