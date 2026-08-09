"""Deselect the `installed_wheel` marker from every run that does not ask for it.

The `installed-wheel` job of `.github/workflows/test.yml` is the only runner of that
marker. The `conformance` job holds the same relation to `spec_validation`.

**A `-m` expression on the command line replaces the one in `addopts`, so `addopts`
cannot hold this rule.** A measurement of 2026-08-09 proved it: with
`addopts = "-m 'not installed_wheel'"` and the gate command `-m "not spec_validation"`,
`pytest --collect-only` still collected all seven cases. `pytest` reads `-m` as one
value, and the later value wins. This hook therefore carries the rule.

The rule is one sentence. **Where the `-m` expression does not name `installed_wheel`,
the run deselects every case that carries the marker.** A deselected case appears in the
summary line as `deselected`, so the count stays visible.

Three commands follow from the rule.

- `pytest tests/ -m "not spec_validation"` reports the marker as deselected, and it runs
  no wheel build.
- `pytest tests/test_installed_wheel.py -m installed_wheel` runs the seven cases.
- `pytest tests/` reports the marker as deselected.

`tests/test_installed_wheel_selection.py` holds the rule against all three commands, so a
rename of the marker fails a case rather than removing the wheel cases from the gate in
silence.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    import pytest

# The marker this hook deselects. `tests/test_installed_wheel_selection.py` reads the
# same name, so the two files cannot disagree.
DESELECTED_MARKER = "installed_wheel"


def marker_is_requested(mark_expression: str, marker: str = DESELECTED_MARKER) -> bool:
    """Report whether one `-m` expression names the marker.

    An expression that excludes the marker, as `not installed_wheel`, names it too. That
    reading loses nothing, because `pytest` applies the expression itself and it removes
    the cases the expression excludes.

    Args:
        mark_expression: The value of the `-m` option, or an empty string.
        marker: The marker name to look for.

    Returns:
        True where the expression names the marker, False otherwise.
    """
    return re.search(rf"\b{re.escape(marker)}\b", mark_expression) is not None


def pytest_collection_modifyitems(config: pytest.Config, items: List[pytest.Item]) -> None:
    """Remove the marked cases from a run whose `-m` expression does not name the marker.

    Args:
        config: The configuration of the run, which holds the `-m` value.
        items: The collected cases. The hook edits this list in place.
    """
    if marker_is_requested(config.option.markexpr or ""):
        return
    kept: List[pytest.Item] = []
    deselected: List[pytest.Item] = []
    for item in items:
        if item.get_closest_marker(DESELECTED_MARKER) is None:
            kept.append(item)
        else:
            deselected.append(item)
    if not deselected:
        return
    config.hook.pytest_deselected(items=deselected)
    items[:] = kept
