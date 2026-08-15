"""The `ja4ls` token of `--types` selects the JA4LS values alone.

One fingerprinter writes JA4L and JA4LS, and `ja4plus/processor.py` sets the type from
`_SPEC`, so both methods report the type `ja4l`. The value prefix `JA4L-S=` is therefore
the one discriminator the command holds. #605 adds the token under parity rule 2, and
`cmd/ja4plus/types.go` of `Crank-Git/ja4plus-go` states the behaviour this file reads.
"""

from __future__ import annotations

import io
import json
import pathlib
from unittest.mock import patch

import pytest

from ja4plus.cli import VALID_TYPES, _parse_types, _reporting_order, _select, main
from ja4plus.types import FingerprintResult

# A committed capture that produces a JA4L value and a JA4LS value. `docs/methods/ja4ls.md`
# names the same capture in its example table.
LATENCY_CAPTURE = str(pathlib.Path(__file__).parent / "foxio_vectors" / "https-connect.pcap")

CLIENT_LATENCY = FingerprintResult(type="ja4l", fingerprint="JA4L-C=1234_64")
SERVER_LATENCY = FingerprintResult(type="ja4l", fingerprint="JA4L-S=5678_128")
TCP_FINGERPRINT = FingerprintResult(type="ja4t", fingerprint="8760_2-1-1-4_1460_00")

LATENCY_RESULTS = [CLIENT_LATENCY, SERVER_LATENCY, TCP_FINGERPRINT]


def _selected(argument: str) -> list[str]:
    """Return the fingerprint of each result the `--types` argument selects.

    Args:
        argument: The text the user writes after `--types`.

    Returns:
        The fingerprint strings, in the order the command writes them.
    """
    order = _reporting_order(_parse_types(argument))
    return [result.fingerprint for result in _select(LATENCY_RESULTS, order)]


def test_the_token_list_holds_ja4ls() -> None:
    """`VALID_TYPES` names `ja4ls`, so `_parse_types` accepts it."""
    assert "ja4ls" in VALID_TYPES


def test_the_ja4ls_token_selects_the_server_value_alone() -> None:
    """The token `ja4ls` selects the JA4LS value and it declines the JA4L value."""
    assert _selected("ja4ls") == ["JA4L-S=5678_128"]


def test_the_ja4l_token_selects_the_client_value_and_the_server_value() -> None:
    """The token `ja4l` keeps selecting both latency values, so no caller sees a change."""
    assert _selected("ja4l") == ["JA4L-C=1234_64", "JA4L-S=5678_128"]


def test_the_ja4ls_token_declines_the_result_of_another_method() -> None:
    """The token `ja4ls` names one method, so it selects no JA4T value."""
    assert "8760_2-1-1-4_1460_00" not in _selected("ja4ls")


def test_the_two_latency_tokens_together_select_both_values() -> None:
    """`--types ja4l,ja4ls` selects the same two values as `--types ja4l`."""
    assert _selected("ja4l,ja4ls") == ["JA4L-C=1234_64", "JA4L-S=5678_128"]


def test_the_default_token_list_selects_both_latency_values() -> None:
    """A run that names no `--types` option writes both latency values."""
    order = _reporting_order(list(VALID_TYPES))
    assert [result.fingerprint for result in _select(LATENCY_RESULTS, order)] == [
        "JA4L-C=1234_64",
        "JA4L-S=5678_128",
        "8760_2-1-1-4_1460_00",
    ]


def test_the_parser_reads_the_ja4ls_token_in_upper_case() -> None:
    """`_parse_types` lowercases each token, so `JA4LS` names the same method."""
    assert _parse_types("JA4LS") == ["ja4ls"]


def test_the_parser_declines_a_token_the_list_omits() -> None:
    """`_parse_types` ends the run with the status 1 on a token that names no method."""
    with pytest.raises(SystemExit) as raised:
        _parse_types("ja4lls")
    assert raised.value.code == 1


def _analyze(token: str) -> list[str]:
    """Return the fingerprint of every line the command writes for one `--types` token.

    Args:
        token: The text the run writes after `--types`.

    Returns:
        The `fingerprint` field of each JSON line, in the order the command wrote them.
    """
    argv = ["ja4plus", "--format", "json", "--types", token, "analyze", LATENCY_CAPTURE]
    stream = io.StringIO()
    with patch("sys.argv", argv), patch("sys.stdout", stream):
        main()
    return [json.loads(line)["fingerprint"] for line in stream.getvalue().splitlines() if line]


def test_a_run_that_names_ja4ls_writes_the_server_values_alone() -> None:
    """`--types ja4ls` writes every JA4LS value of a capture and no JA4L value."""
    written = _analyze("ja4ls")
    assert written, "the capture produced no fingerprint for the token ja4ls"
    assert all(value.startswith("JA4L-S=") for value in written), written


def test_a_run_that_names_ja4l_writes_the_client_values_and_the_server_values() -> None:
    """`--types ja4l` writes both latency methods, as version 1.1.1 does."""
    written = _analyze("ja4l")
    assert any(value.startswith("JA4L-C=") for value in written), written
    assert any(value.startswith("JA4L-S=") for value in written), written


def test_the_ja4ls_run_writes_the_server_values_the_ja4l_run_writes() -> None:
    """The two tokens agree on the JA4LS values, so `ja4ls` drops no server value."""
    from_both = [value for value in _analyze("ja4l") if value.startswith("JA4L-S=")]
    assert _analyze("ja4ls") == from_both
