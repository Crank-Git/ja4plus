"""Write the deviation register from a measurement of the conformance suite.

The register holds one entry for each conformance case that ja4plus fails today. There
are hundreds, so this program measures them instead of a person writing them by hand.

It runs the conformance suite with the deviation lookup disabled, reads the parameters
of each failed case, and writes one register entry for each. It reads the parameters
from the pytest item, not from the report text, so a vector name that holds a hyphen
never confuses it.

Run it from the repository root, after a change that fixes or breaks a method:

    python tests/generate_foxio_deviations.py

It overwrites `tests/foxio_deviations.json`. Read the difference before you commit it.
A method this program does not know an issue for stops the run, because an entry with
no issue number is not allowed.
"""

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.foxio_deviations import (  # noqa: E402 - the path insert must run first
    IGNORE_VARIABLE,
    REGISTER_PATH,
    occurrence_key,
    value_key,
)

# The issue that owns each method. #12 records the measurement that assigns them.
OWNING_ISSUES = {
    "JA4": 13,
    "JA4S": 13,
    "JA4H": 35,
    "JA4SSH": 28,
    "JA4X": 78,
    "JA4L-C": 30,
    "JA4L-S": 30,
}

SUITE = "tests/test_spec_validation.py"


class _FailureCollector:
    """Collect the parameters of every failed conformance case."""

    def __init__(self):
        self.failures = []

    def pytest_runtest_logreport(self, report):
        if report.when != "call" or report.outcome != "failed":
            return
        self.failures.append((report.nodeid, str(report.longrepr)))

    def pytest_collection_modifyitems(self, items):
        self.params = {item.nodeid: getattr(item, "callspec", None) for item in items}


def _cause(method, message, occurrence_form):
    """Return one line that states the cause, read from the failure message."""
    if occurrence_form:
        extra = "extra occurrence key" in message and "0 extra" not in message
        missing = "missing occurrence key" in message and "0 missing" not in message
        if extra and missing:
            return "ja4plus produces a different set of {} fingerprints.".format(method)
        if extra:
            return "ja4plus produces a {} fingerprint the reference does not hold.".format(method)
        return "ja4plus produces no {} fingerprint the reference holds.".format(method)
    if "produced=<none>" in message:
        return "ja4plus produces no {} value on this stream.".format(method)
    return "The produced {} value differs from the reference.".format(method)


def _entry(method, message, occurrence_form):
    """Return one register entry, or raise KeyError when no issue owns the method."""
    return {
        "issue": OWNING_ISSUES[method],
        "cause": _cause(method, message, occurrence_form),
    }


def main():
    os.environ[IGNORE_VARIABLE] = "1"
    collector = _FailureCollector()
    pytest.main([SUITE, "-m", "spec_validation", "-q", "-p", "no:randomly"], plugins=[collector])

    register = {}
    for nodeid, message in collector.failures:
        callspec = collector.params.get(nodeid)
        if callspec is None:
            raise SystemExit(
                "{} carries no parameters; it is not a registrable case".format(nodeid)
            )
        params = callspec.params
        method = params["method"]
        vector = params["pcap_path"].name
        if "occurrence" in params:
            stream = params["stream"]
            key = value_key(vector, stream.index, stream.src_port, method, params["occurrence"])
            register[key] = _entry(method, message, occurrence_form=False)
        else:
            key = occurrence_key(vector, method)
            register[key] = _entry(method, message, occurrence_form=True)

    ordered = {key: register[key] for key in sorted(register)}
    with open(REGISTER_PATH, "w") as handle:
        json.dump(ordered, handle, indent=2, sort_keys=False)
        handle.write("\n")
    print("wrote {} entries to {}".format(len(ordered), REGISTER_PATH))


if __name__ == "__main__":
    main()
