"""Write the conformance baseline from a measurement of the suite.

The baseline is two committed files:

- `tests/foxio_vector_manifest.json` names every vector and the number of cases it
  carries. It makes a vector that disappears fail the suite by name.
- `tests/foxio_deviations.json` holds one entry for each conformance case that ja4plus
  fails today. There are hundreds, so this program measures them instead of a person
  writing them by hand.

It runs the conformance suite with the deviation lookup disabled, reads the parameters
of each collected case and each failed case, and writes both files. It reads the
parameters from the pytest item, not from the report text, so a vector name that holds
a hyphen never confuses it.

Run it from the repository root, after a change that adds a vector, fixes a method, or
breaks one:

    python tests/generate_foxio_baseline.py

It overwrites both files. Read the difference before you commit it. A method this
program does not know an issue for stops the run, because an entry with no issue number
is not allowed.
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
from tests.foxio_manifest import MANIFEST_PATH  # noqa: E402 - the path insert must run first

# The issue that owns each method. #12 records the measurement that assigns them.
#
# JA4L names #80, not #30 and not #34. The conformance harness does not run the JA4L
# fingerprinter, so every JA4L case fails before any fingerprint value is compared. #30
# changes `calculate_distance`, which no JA4L fingerprint value reads, so #30 fixes none
# of these cases. #34 owns the client-fingerprint multiplicity defect, and #80 must land
# first for the suite to measure it.
OWNING_ISSUES = {
    "JA4": 13,
    "JA4S": 13,
    "JA4H": 35,
    "JA4SSH": 28,
    "JA4X": 78,
    "JA4L-C": 80,
    "JA4L-S": 80,
}

# The cause of every JA4L case, which the failure message alone does not state. The
# harness reports "produced=<none>" because it runs five fingerprinters and JA4L is not
# one of them, not because ja4plus produces no JA4L value.
HARNESS_CAUSES = {
    "JA4L-C": "The conformance harness does not run the JA4L fingerprinter.",
    "JA4L-S": "The conformance harness does not run the JA4L fingerprinter.",
}

SUITE = "tests/test_spec_validation.py"


class _CaseCollector:
    """Collect every conformance case and the message of every failed case."""

    def __init__(self):
        self.failures = []
        self.params = {}

    def pytest_collection_modifyitems(self, items):
        self.params = {item.nodeid: getattr(item, "callspec", None) for item in items}

    def pytest_runtest_logreport(self, report):
        if report.when != "call" or report.outcome != "failed":
            return
        self.failures.append((report.nodeid, str(report.longrepr)))


def _cause(method, message, occurrence_form):
    """Return one line that states the cause, read from the failure message."""
    if method in HARNESS_CAUSES:
        return HARNESS_CAUSES[method]
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


def _write(path, content):
    """Write one JSON file with a trailing newline."""
    with open(path, "w") as handle:
        json.dump(content, handle, indent=2)
        handle.write("\n")


def _manifest(collector):
    """Return the case count of each vector, read from the collected items."""
    counts = {}
    for callspec in collector.params.values():
        if callspec is None or "pcap_path" not in callspec.params:
            continue
        if "method" not in callspec.params:
            # `test_the_vector_is_readable` runs once for each vector, and it is not a
            # conformance case. The manifest counts comparisons only.
            continue
        vector = callspec.params["pcap_path"].name
        counts[vector] = counts.get(vector, 0) + 1
    return {vector: counts[vector] for vector in sorted(counts)}


def _register(collector):
    """Return the register entries and the failures that are not conformance cases.

    A structural test, such as the manifest check, carries no method parameter. It is
    not a registrable case, so this program reports it instead of recording it.
    """
    register = {}
    other = []
    for nodeid, message in collector.failures:
        callspec = collector.params.get(nodeid)
        params = callspec.params if callspec else {}
        if "method" not in params or "pcap_path" not in params:
            other.append(nodeid)
            continue
        method = params["method"]
        vector = params["pcap_path"].name
        if "occurrence" in params:
            stream = params["stream"]
            key = value_key(vector, stream.index, stream.src_port, method, params["occurrence"])
            register[key] = _entry(method, message, occurrence_form=False)
        else:
            key = occurrence_key(vector, method)
            register[key] = _entry(method, message, occurrence_form=True)
    return {key: register[key] for key in sorted(register)}, other


def main():
    os.environ[IGNORE_VARIABLE] = "1"
    collector = _CaseCollector()
    pytest.main([SUITE, "-m", "spec_validation", "-q", "-p", "no:randomly"], plugins=[collector])

    manifest = _manifest(collector)
    register, other = _register(collector)
    _write(MANIFEST_PATH, manifest)
    _write(REGISTER_PATH, register)
    print("wrote {} vectors to {}".format(len(manifest), MANIFEST_PATH))
    print("wrote {} entries to {}".format(len(register), REGISTER_PATH))
    for nodeid in other:
        print("failed, and it is not a conformance case: {}".format(nodeid))


if __name__ == "__main__":
    main()
