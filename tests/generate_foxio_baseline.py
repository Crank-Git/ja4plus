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
import re
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
# #28 fixed the JA4SSH window, and it owns no case now. Every JA4SSH case that
# remains sits on a capture that holds more than one window. A capture of one window
# conforms, and a capture of several does not. #92 owns them.
OWNING_ISSUES = {
    "JA4": 13,
    "JA4S": 13,
    "JA4H": 35,
    "JA4SSH": 92,
    "JA4X": 78,
}

# JA4L holds defects of two kinds, so one issue does not own every JA4L case. #80 landed
# the harness change that measures them, and #80 owns none of them. #30 changes
# `calculate_distance`, which no JA4L fingerprint value reads, so #30 owns none of them
# either.
#
# #34 owns the multiplicity defect on both sides: how many JA4L values one connection
# emits. On the client side JA4L emits one JA4L-C value for every ACK.
JA4L_MULTIPLICITY_ISSUE = 34

# #88 owns every JA4L value defect. `ja4l.py:218` claims FoxIO uses the raw time
# difference. The vectors contradict that claim. On `badcurveball.pcap` stream 0, the
# SYN to SYN-ACK time is 1563 us and the reference JA4L-S is `781_238`, which is half of
# it. The same stream gives a client data packet 4362 us after the SYN-ACK, and the
# reference JA4L-C is `2181_64`, which is half of that. ja4plus halves neither, and it
# measures JA4L-C to the bare ACK rather than to the first client data packet.
JA4L_VALUE_ISSUE = 88

SUITE = "tests/test_spec_validation.py"

# The counts the occurrence-key failure message reports.
EXTRA_KEYS = re.compile(r": (\d+) extra occurrence key")
MISSING_KEYS = re.compile(r"; (\d+) missing occurrence key")

# The value pair the fingerprint failure message reports.
VALUE_PAIR = re.compile(r"expected='([^']*)' produced='([^']*)'")

# A produced latency this many microseconds from twice the reference counts as twice it.
# Both values truncate to a whole microsecond, so an exact comparison misses a case that
# the halving explains.
HALVING_TOLERANCE = 2


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


def _failure_line(message):
    """Return the failure line of one case.

    pytest prints the source of the test above the failure, and that source holds the
    format string of the failure message. A search of the whole report therefore matches
    text the case never produced. Read the failure line alone.

    Args:
        message: The report text of one failed case.

    Returns:
        The line that states the failure, or the whole report when it holds no such
        line.
    """
    for line in message.splitlines():
        if "Failed: " in line:
            return line
    return message


def _count(pattern, message):
    """Return the count the pattern reports, or 0 when the message holds none."""
    match = pattern.search(message)
    return int(match.group(1)) if match else 0


def _is_twice_the_reference(message):
    """Return True when the produced latency is twice the latency of the reference."""
    match = VALUE_PAIR.search(message)
    if not match:
        return False
    expected, produced = match.group(1), match.group(2)
    try:
        expected_latency = int(expected.split("_")[0])
        produced_latency = int(produced.split("_")[0])
    except (ValueError, IndexError):
        return False
    return abs(produced_latency - expected_latency * 2) <= HALVING_TOLERANCE


def _ja4l_entry(method, message, occurrence_form):
    """Return the register entry of one JA4L case, read from the failure message.

    Args:
        method: The method name, `JA4L-C` or `JA4L-S`.
        message: The failure message of the case.
        occurrence_form: True for an occurrence-key case, False for a value case.

    Returns:
        The entry, as a map of `issue` to the issue number and `cause` to one line.
    """
    # #34 owns every occurrence-key case, on both sides of the connection. A count that
    # differs from the reference is one defect, and the direction does not split it.
    if occurrence_form:
        extra = _count(EXTRA_KEYS, message)
        missing = _count(MISSING_KEYS, message)
        if extra and method == "JA4L-C":
            return {
                "issue": JA4L_MULTIPLICITY_ISSUE,
                "cause": "ja4plus emits one JA4L-C value for every ACK on the connection.",
            }
        if extra and missing:
            return {
                "issue": JA4L_MULTIPLICITY_ISSUE,
                "cause": "ja4plus produces a different set of {} fingerprints.".format(method),
            }
        if extra:
            return {
                "issue": JA4L_MULTIPLICITY_ISSUE,
                "cause": "ja4plus emits more {} values than the reference holds.".format(method),
            }
        return {
            "issue": JA4L_MULTIPLICITY_ISSUE,
            "cause": "ja4plus does not decode the tunnel payload of this capture, so it "
            "reads no TCP layer and produces no {} value.".format(method),
        }
    if "produced=<none>" in message:
        return {
            "issue": JA4L_VALUE_ISSUE,
            "cause": "ja4plus does not decode the tunnel payload of this capture, so it "
            "reads no TCP layer and produces no {} value on this stream.".format(method),
        }
    if _is_twice_the_reference(message):
        return {
            "issue": JA4L_VALUE_ISSUE,
            "cause": "ja4plus reports the round-trip time, and the reference holds half of it.",
        }
    if method == "JA4L-C":
        return {
            "issue": JA4L_VALUE_ISSUE,
            "cause": "ja4plus measures JA4L-C to the bare ACK, and it does not halve the "
            "round-trip time.",
        }
    return {
        "issue": JA4L_VALUE_ISSUE,
        "cause": "The produced JA4L-S value differs from the reference by another amount.",
    }


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
    if method.startswith("JA4L"):
        return _ja4l_entry(method, message, occurrence_form)
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
        message = _failure_line(message)
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
