"""Tests that `LookupResult` deprecates item access the way `FingerprintResult` does.

`docs/specs/features/07-db-enrichment.md` states FR-db-enrichment-16 and
FR-db-enrichment-17. `tests/test_types.py` holds the same cases for
`FingerprintResult`, because this project holds one spelling of the behavior.

Version 0.6.0 published the three keys `application`, `type` and `notes`, and
`LookupResult` names a field for each one. No key of version 0.6.0 changed its name.

These cases reach no network and they produce no fingerprint.
"""

import dataclasses
import warnings

import pytest

from ja4plus.ja4db import LookupResult

# One filled result. Every field holds a value a reader can tell from every other
# field, so a method that returns the wrong field fails a case here.
SAMPLE = LookupResult(
    application="Chromium Browser",
    type="ja4",
    notes="A bundled entry.",
    source="embedded",
)

# The three keys the dictionary of version 0.6.0 published. `ja4db.py` of tag `v0.6.0`
# builds them at `_load_bundled_db` and at `_remote_lookup`.
KEYS_OF_VERSION_0_6_0 = ("application", "type", "notes")


def test_every_key_of_version_0_6_0_names_a_field():
    """No field renames a key that version 0.6.0 published."""
    names = {field.name for field in dataclasses.fields(LookupResult)}
    assert set(KEYS_OF_VERSION_0_6_0) <= names


def test_item_access_returns_the_value_the_attribute_holds():
    """Every field reads the same through both forms."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        for field in dataclasses.fields(LookupResult):
            assert SAMPLE[field.name] == getattr(SAMPLE, field.name)


def test_the_application_key_returns_the_application_name():
    """`result["application"]` returns the value `result.application` holds."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        value = SAMPLE["application"]
    assert value == "Chromium Browser"
    assert value == SAMPLE.application


def test_item_access_emits_a_deprecation_warning():
    """FR-db-enrichment-17 states that item access emits a `DeprecationWarning`."""
    with pytest.warns(DeprecationWarning) as record:
        SAMPLE["application"]
    assert len(record) == 1
    message = str(record[0].message)
    assert "LookupResult" in message
    assert "result.application" in message


def test_the_warning_reports_the_line_of_the_caller():
    """`stacklevel=2` reports the caller's line, so the reader finds the call."""
    with pytest.warns(DeprecationWarning) as record:
        SAMPLE["notes"]
    assert record[0].filename == __file__


def test_attribute_access_emits_no_warning():
    """A reader of the new form sees no warning."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        assert SAMPLE.application == "Chromium Browser"


def test_an_unknown_key_raises_a_key_error_and_emits_no_warning_first():
    """The membership test runs before the warning, so an unknown key warns nothing."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        with pytest.raises(KeyError):
            SAMPLE["method"]


def test_a_private_attribute_name_raises_a_key_error():
    """Item access reads a field, so it reaches no other attribute."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        with pytest.raises(KeyError):
            SAMPLE["__class__"]


def test_an_integer_key_raises_a_key_error():
    """A `__getitem__` makes the old iteration protocol reach the result.

    `list(result)` therefore calls `result[0]`, and the membership test refuses it.
    Version 0.6.0 returned a dictionary, which iterates its keys, so this case records
    that a `LookupResult` iterates nothing. `FingerprintResult` behaves the same way.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        with pytest.raises(KeyError):
            SAMPLE[0]


def test_attribute_assignment_raises_a_frozen_instance_error():
    """The result is frozen, so a caller changes no field."""
    with pytest.raises(dataclasses.FrozenInstanceError):
        SAMPLE.application = "x"


def test_item_assignment_raises_a_type_error():
    """The deprecated item access covers reading only."""
    with pytest.raises(TypeError):
        SAMPLE["application"] = "x"
