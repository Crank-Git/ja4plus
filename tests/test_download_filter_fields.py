"""Read the snapshot field list of the vector download filter against the parity module.

`tests/download_test_vectors.py` keeps a FoxIO Rust snapshot only where one line of it
starts with an entry of `RUST_COMPARED_FIELDS`. `tests/test_foxio_rust_parity.py`
compares six methods against such a snapshot. A method the field list names nowhere
reaches the parity module only where the same snapshot carries a method the list does
name. #670 added the JA4H comparison and #671 added the JA4SSH comparison. Neither round
moved the field list, so this module holds the two files against each other.

Every snapshot line below carries the indentation the FoxIO Rust implementation writes,
because the filter strips each line before it matches.
"""

import pytest

from tests.download_test_vectors import RUST_COMPARED_FIELDS, RUST_DIR, keeps_rust_snapshot
from tests.test_foxio_rust_parity import (
    SNAPSHOT_CERT_METHOD,
    SNAPSHOT_HTTP_METHOD,
    SNAPSHOT_LATENCY_METHODS,
    SNAPSHOT_METHODS,
    SNAPSHOT_SSH_METHOD,
)

# The header every FoxIO Rust snapshot opens with, and the stream fields that carry no
# fingerprint value. A snapshot the cases below build holds this text and one value line,
# so the value line is the one line the filter can match.
SNAPSHOT_HEAD = b"""\
---
source: ja4/src/lib.rs
expression: output
---
- stream: 0
  transport: tcp
  src: 10.0.0.1
  dst: 10.0.0.2
  src_port: 49152
  dst_port: 443
"""

# One value line for each method the parity module compares against a Rust snapshot. Four
# of the six write the value beside the field name. JA4X and JA4H write theirs as a list
# item, so the stripped line opens with the list marker. JA4SSH names no field at all, so
# the block opener `ja4ssh:` is the one line that carries the method.
METHOD_VALUE_LINES = {
    "JA4": b"  ja4: t13d1516h2_8daaf6152771_b0da82dd1658\n",
    "JA4S": b"  ja4s: t130200_1301_234ea6891581\n",
    "JA4T": b"  ja4t: 64240_2-1-3-1-1-4_1460_8\n",
    "JA4X": b"  tls_certs:\n  - x509:\n    - ja4x: a373a9f83c6b_2bab15409345_0f2217ba412e\n",
    "JA4H": b"  http:\n  - ja4h: ge11nn07enus_3e3b55d61660_000000000000_000000000000\n",
    "JA4SSH": b"  ja4ssh:\n  - c36s36_c76s124_c74s5\n",
}

# The methods the field list names, against the methods the parity module compares. The
# two latency methods stand outside the six, because #684 read the field list as four
# entries of six and named neither one. A read of 2026-08-15 measured that all seven
# committed snapshots that hold a JA4L value hold a JA4T value as well. No committed
# snapshot therefore rests on a latency entry.
EXPECTED_METHODS = frozenset(METHOD_VALUE_LINES)

# The method the field list names with a form that matches no line the FoxIO Rust
# implementation writes. #719 records the measurement and owns the repair.
UNMATCHED_METHOD = "JA4X"


def _snapshot_holding(value_line: bytes) -> bytes:
    """Return a one-stream Rust snapshot that carries the value line and no other value.

    Args:
        value_line: The lines that carry one fingerprint value.

    Returns:
        The bytes of the snapshot.
    """
    return SNAPSHOT_HEAD + value_line


def test_the_field_list_holds_the_methods_the_parity_module_compares():
    """The two lists name the same methods, so a rename in either file fails a case."""
    compared = {method for method, _field in SNAPSHOT_METHODS}
    compared -= {method for method, _field in SNAPSHOT_LATENCY_METHODS}
    compared |= {SNAPSHOT_CERT_METHOD, SNAPSHOT_HTTP_METHOD, SNAPSHOT_SSH_METHOD}
    assert compared == EXPECTED_METHODS


@pytest.mark.parametrize(
    "method",
    [
        pytest.param(
            method,
            marks=(
                pytest.mark.xfail(
                    strict=True,
                    reason="#719: the field list writes `ja4x: ` and the snapshot writes `- ja4x: `",
                )
                if method == UNMATCHED_METHOD
                else ()
            ),
        )
        for method in sorted(METHOD_VALUE_LINES)
    ],
)
def test_the_filter_keeps_a_snapshot_that_holds_one_method_alone(method):
    """The filter keeps a snapshot whose one value belongs to the method."""
    assert keeps_rust_snapshot(_snapshot_holding(METHOD_VALUE_LINES[method]))


def test_the_filter_refuses_a_snapshot_that_holds_no_fingerprint_value():
    """The filter refuses a snapshot of stream fields alone, which is the defect #115 closes."""
    assert not keeps_rust_snapshot(SNAPSHOT_HEAD)


def test_the_filter_keeps_every_committed_rust_snapshot():
    """The field list keeps all eleven committed snapshots, so this change moves no vector."""
    snapshots = sorted(RUST_DIR.glob("*.snap"))
    assert len(snapshots) == 11
    kept = [path.name for path in snapshots if keeps_rust_snapshot(path.read_bytes())]
    assert len(kept) == 11


def test_the_field_list_holds_no_entry_twice():
    """A repeated entry reads as a second method, and the list holds one entry per form."""
    assert len(set(RUST_COMPARED_FIELDS)) == len(RUST_COMPARED_FIELDS)
