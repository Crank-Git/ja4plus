"""`interpret_fingerprint` catches the parse errors it expects and no other error.

`docs/specs/features/02-correctness-audit.md` row 14 records the defect. A handler that
catches every exception turns a defect in this project into an error dictionary that a
caller reads as a malformed fingerprint. The defect then reaches a user as a wrong
answer instead of a stack trace.
"""

import pytest

from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter


class RaisesOnSplit:
    """A stand-in for a fingerprint whose `split` raises an error the parser expects
    from no input."""

    def split(self, separator):
        """Raise the error a defect inside this project produces."""
        raise RuntimeError("a defect inside ja4plus, not a malformed fingerprint")


@pytest.fixture
def fingerprinter():
    """Return one JA4SSH fingerprinter."""
    return JA4SSHFingerprinter()


def test_an_error_the_parser_expects_from_no_input_reaches_the_caller(fingerprinter):
    """`interpret_fingerprint` lets an unexpected error propagate."""
    with pytest.raises(RuntimeError, match="a defect inside ja4plus"):
        fingerprinter.interpret_fingerprint(RaisesOnSplit())


@pytest.mark.parametrize(
    "value",
    [
        "invalid",
        "",
        "a_b_c",
        "c36s36_c50s50",
        "cXXsYY_c50s50_c70s30",
        "c36s36_c50s50_c70s30_c1s1",
        "c36_c50s50_c70s30",
    ],
    ids=[
        "one part",
        "an empty string",
        "three parts that hold no number",
        "two parts",
        "a size that holds no digit",
        "four parts",
        "a part that holds no server field",
    ],
)
def test_a_malformed_fingerprint_returns_an_error_dictionary(fingerprinter, value):
    """A malformed fingerprint returns an error dictionary and raises nothing."""
    result = fingerprinter.interpret_fingerprint(value)
    assert "error" in result, f"{value!r} returned no error: {result}"


def test_a_fingerprint_that_is_none_returns_an_error_dictionary(fingerprinter):
    """A fingerprint of None returns an error dictionary and raises nothing.

    `_close_window` returns None when a window holds no SSH packet, so a caller can
    reach this method with None.
    """
    result = fingerprinter.interpret_fingerprint(None)
    assert "error" in result, f"None returned no error: {result}"


def test_a_valid_fingerprint_still_reports_the_session_type(fingerprinter):
    """A valid fingerprint reports the session type it reported before the change."""
    result = fingerprinter.interpret_fingerprint("c36s36_c50s50_c70s30")
    assert result["session_type"] == "Interactive SSH Session"
    assert result["details"]["packet_sizes"] == {"client": 36, "server": 36}
