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


class SplitsIntoBytes:
    """A stand-in for a fingerprint whose `split` returns three parts of type bytes."""

    def split(self, separator):
        """Return three parts that the part guard cannot read."""
        return [b"c36s36", b"c50s50", b"c70s30"]


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


@pytest.mark.parametrize(
    "value",
    [
        b"c36s36_c50s50_c70s30",
        bytearray(b"c36s36_c50s50_c70s30"),
        b"",
    ],
    ids=[
        "a bytes fingerprint",
        "a bytearray fingerprint",
        "an empty bytes fingerprint",
    ],
)
def test_a_fingerprint_of_a_bytes_like_type_returns_an_error_dictionary(fingerprinter, value):
    """A fingerprint that holds bytes returns an error dictionary and raises nothing.

    Issue #262 records the defect. `bytes.split` denies the separator `"_"` and raises
    `TypeError`, so the error reached the caller as a stack trace. A value of the wrong
    type is a malformed fingerprint, and the method already answers None that way.
    """
    result = fingerprinter.interpret_fingerprint(value)
    assert "error" in result, f"{value!r} returned no error: {result}"


def test_a_fingerprint_whose_parts_hold_bytes_returns_an_error_dictionary(fingerprinter):
    """A fingerprint whose `split` returns parts of type bytes returns an error dictionary.

    The part guard holds a string pattern, so `fullmatch` raises `TypeError` on a part of
    type bytes. That is the second place issue #262 covers, and `fingerprint.split` is the
    first.
    """
    result = fingerprinter.interpret_fingerprint(SplitsIntoBytes())
    assert "error" in result, f"three parts of type bytes returned no error: {result}"


@pytest.mark.parametrize(
    "value",
    [
        "36s36_c50s50_c70s30",
        "c36s36_50s50_c70s30",
        "c36s36_c50s50_70s30",
        "x36s36_c50s50_c70s30",
        "c36s36_y50s50_c70s30",
    ],
    ids=[
        "a packet size part that carries no client prefix",
        "an SSH ratio part that carries no client prefix",
        "an ACK ratio part that carries no client prefix",
        "a packet size part that carries a wrong client prefix",
        "an SSH ratio part that carries a wrong client prefix",
    ],
)
def test_a_part_that_carries_no_client_prefix_returns_an_error_dictionary(fingerprinter, value):
    """A part that carries no `c` prefix returns an error dictionary."""
    result = fingerprinter.interpret_fingerprint(value)
    assert "error" in result, f"{value!r} returned no error: {result}"


def test_a_part_that_carries_no_client_prefix_reports_no_client_number(fingerprinter):
    """The method reports no client packet size for a part that carries no `c` prefix.

    Issue #182 records the defect. The part `36s36` reported a client packet size of 6,
    because the method removed the digit `3` as though it were the prefix `c`.
    """
    result = fingerprinter.interpret_fingerprint("36s36_c50s50_c70s30")
    assert result == {"error": "Invalid JA4SSH format"}


@pytest.mark.parametrize(
    "value",
    [
        "c36s36s99_c50s50_c70s30",
        "c36s36_c50s50s1_c70s30",
        "c36s36_c50s50_c70s30s7",
    ],
    ids=[
        "a packet size part that carries a second separator",
        "an SSH ratio part that carries a second separator",
        "an ACK ratio part that carries a second separator",
    ],
)
def test_a_part_that_carries_a_second_separator_returns_an_error_dictionary(fingerprinter, value):
    """A part that carries a second `s` separator returns an error dictionary.

    Issue #186 records the defect. The part `c36s36s99` reported a server packet size of
    36 and dropped `99`, because nothing checked that the split produced two elements.
    """
    result = fingerprinter.interpret_fingerprint(value)
    assert result == {"error": "Invalid JA4SSH format"}, f"{value!r} returned {result}"


@pytest.mark.parametrize(
    "value",
    [
        "c 36s36_c50s50_c70s30",
        "c36s 36_c50s50_c70s30",
        "c-5s36_c50s50_c70s30",
        "c36s-5_c50s50_c70s30",
        "c36s+36_c50s50_c70s30",
        "c٦s36_c50s50_c70s30",
        "c36s٦_c50s50_c70s30",
        "c36s36_c50s50_c70s30\n",
        "c36s36_c50s50_c70s30 ",
        "c36_c50s50_c70s30",
    ],
    ids=[
        "a client packet size that holds a space",
        "a server packet size that holds a space",
        "a client packet size that holds a sign",
        "a server packet size that holds a sign",
        "a server packet size that holds a plus sign",
        "a client packet size that holds an Arabic-Indic digit",
        "a server packet size that holds an Arabic-Indic digit",
        "an ACK ratio part that ends with a line feed",
        "an ACK ratio part that ends with a space",
        "a part that holds no server field",
    ],
)
def test_a_part_that_holds_a_character_the_form_denies_returns_an_error(fingerprinter, value):
    """A part that holds any character other than `c`, `s` and an ASCII digit fails.

    Issue #186 records the three readings a comment measured. `int()` accepts a space, a
    sign and a Unicode digit, so each of these parts reported a number the fingerprint
    does not hold.
    """
    result = fingerprinter.interpret_fingerprint(value)
    assert result == {"error": "Invalid JA4SSH format"}, f"{value!r} returned {result}"


def test_a_part_that_holds_more_digits_than_python_converts_returns_an_error(fingerprinter):
    """A part of 5000 digits returns an error dictionary and raises nothing.

    CPython converts 4300 digits at most. Such a part matches the JA4SSH form, so the
    part guard admits it and `int()` raises the `ValueError` the handler names.
    """
    result = fingerprinter.interpret_fingerprint(f"c{'9' * 5000}s36_c50s50_c70s30")
    assert "error" in result, f"a part of 5000 digits returned no error: {result}"


def test_a_valid_fingerprint_still_reports_the_session_type(fingerprinter):
    """A valid fingerprint reports the session type it reported before the change."""
    result = fingerprinter.interpret_fingerprint("c36s36_c50s50_c70s30")
    assert result["session_type"] == "Interactive SSH Session"
    assert result["details"]["packet_sizes"] == {"client": 36, "server": 36}
