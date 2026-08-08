"""Tests that `FingerprintResult` matches the data model and deprecates item access.

`docs/specs/features/04-typed-api.md` states FR-typed-api-1, FR-typed-api-2,
FR-typed-api-5 and FR-typed-api-6. The `### Result` table of `docs/specs/spec.md`
holds the field list, and one case here reads that table, so a field the spec adds
fails this suite until the dataclass carries it.

These cases import no fingerprinter and they produce no fingerprint.
"""

import dataclasses
import re
import warnings
from datetime import datetime, timezone
from pathlib import Path

import pytest

import ja4plus
from ja4plus.types import FingerprintResult

REPO_ROOT = Path(__file__).resolve().parent.parent

SPEC = REPO_ROOT / "docs" / "specs" / "spec.md"

# One filled result. Every field holds a value a reader can tell from every other
# value, so a case that reads the wrong field fails.
SAMPLE = FingerprintResult(
    type="ja4",
    fingerprint="t13d1516h2_8daaf6152771_b0da82dd1658",
    raw="t13d1516h2_002f,0035_0005,000a",
    raw_original_order="t13d1516h2_0035,002f_000a,0005",
    src_ip="10.0.0.1",
    src_port=44100,
    dst_ip="10.0.0.2",
    dst_port=443,
    timestamp=datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc),
)


def _spec_field_names() -> list[str]:
    """Return the field names the `### Result` table of the spec lists.

    Returns:
        The first cell of each table row, in the order the table holds.

    Raises:
        AssertionError: The spec holds no `### Result` table.
    """
    text = SPEC.read_text(encoding="utf-8")
    start = text.index("\n### Result\n")
    end = text.index("\n### ", start + 1)
    section = text[start:end]
    names = re.findall(r"^\| `([a-z_]+)` \|", section, flags=re.MULTILINE)
    assert names, "`docs/specs/spec.md` holds no `### Result` field table"
    return names


def test_the_field_names_match_the_spec_data_model():
    """The dataclass carries the fields the spec lists, in the spec's order."""
    declared = [field.name for field in dataclasses.fields(FingerprintResult)]
    assert declared == _spec_field_names()


def test_the_package_exports_the_result_type():
    """`ja4plus.FingerprintResult` is the dataclass `ja4plus.types` defines."""
    assert ja4plus.FingerprintResult is FingerprintResult


def test_the_result_is_a_frozen_dataclass():
    """FR-typed-api-1 states the result is a frozen dataclass."""
    assert dataclasses.is_dataclass(FingerprintResult)
    assert FingerprintResult.__dataclass_params__.frozen is True


def test_item_access_returns_the_value_the_attribute_holds():
    """Every field reads the same through both forms."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        for field in dataclasses.fields(FingerprintResult):
            assert SAMPLE[field.name] == getattr(SAMPLE, field.name)


def test_item_access_by_the_type_key_returns_the_method_name():
    """`result["type"]` returns the value `result.type` holds."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        value = SAMPLE["type"]
    assert value == "ja4"
    assert value == SAMPLE.type


def test_item_access_emits_a_deprecation_warning():
    """FR-typed-api-6 states that item access emits a `DeprecationWarning`."""
    with pytest.warns(DeprecationWarning) as record:
        SAMPLE["fingerprint"]
    assert len(record) == 1
    message = str(record[0].message)
    assert "FingerprintResult" in message
    assert "result.fingerprint" in message


def test_attribute_access_emits_no_warning():
    """A reader of the new form sees no warning."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        assert SAMPLE.fingerprint == "t13d1516h2_8daaf6152771_b0da82dd1658"


def test_the_method_key_raises_a_key_error():
    """The field is `type`, so `result["method"]` raises `KeyError`."""
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


def test_attribute_assignment_raises_a_frozen_instance_error():
    """The result is frozen, so a caller changes no field."""
    with pytest.raises(dataclasses.FrozenInstanceError):
        SAMPLE.fingerprint = "x"


def test_item_assignment_raises_a_type_error():
    """The deprecated item access covers reading only."""
    with pytest.raises(TypeError):
        SAMPLE["fingerprint"] = "x"


def test_item_deletion_raises_a_type_error():
    """A result supports no item deletion either."""
    with pytest.raises(TypeError):
        del SAMPLE["fingerprint"]


def test_the_optional_fields_hold_the_documented_defaults():
    """A result built from the two required fields holds the spec's defaults."""
    result = FingerprintResult(type="ja4t", fingerprint="64240_2-4-8-1-1-3-3_1460_8")
    assert result.raw is None
    assert result.raw_original_order is None
    assert result.src_ip == ""
    assert result.src_port == 0
    assert result.dst_ip == ""
    assert result.dst_port == 0
    assert result.timestamp is None


def test_two_results_that_hold_the_same_fields_are_equal():
    """The dataclass compares by value, so a test can assert on a whole result."""
    other = dataclasses.replace(SAMPLE)
    assert other == SAMPLE
    assert other != dataclasses.replace(SAMPLE, fingerprint="other")


def test_a_result_is_hashable():
    """The result is frozen, so a caller counts results with a set."""
    assert len({SAMPLE, dataclasses.replace(SAMPLE)}) == 1
