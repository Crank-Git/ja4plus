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
# emits. #88 halved every latency and moved the client measurement point, and that fix
# also removed the JA4L values ja4plus produced on a UDP flow that carries no QUIC. The
# cases that remain are streams the reference holds no JA4L value for, and one repeated
# SYN-ACK.
JA4L_MULTIPLICITY_ISSUE = 34

# #101 owns the mirrored capture. `gre-erspan-vxlan.pcap` carries both directions of one
# inner session between one outer address pair, so ja4plus groups the two directions as
# two connections and reports no value.
JA4L_MIRRORED_CAPTURE_ISSUE = 101

# #102 owns the QUIC server measurement point. The reference reads the Initial packet
# that completes the ServerHello. ja4plus cannot decrypt these server Initial packets,
# so it reads the first one.
JA4L_QUIC_SERVER_POINT_ISSUE = 102

SUITE = "tests/test_spec_validation.py"

# The counts the occurrence-key failure message reports.
EXTRA_KEYS = re.compile(r": (\d+) extra occurrence key")
MISSING_KEYS = re.compile(r"; (\d+) missing occurrence key")


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


def _ja4l_entry(method, message, occurrence_form):
    """Return the register entry of one JA4L case, read from the failure message.

    Args:
        method: The method name, `JA4L-C` or `JA4L-S`.
        message: The failure message of the case.
        occurrence_form: True for an occurrence-key case, False for a value case.

    Returns:
        The entry, as a map of `issue` to the issue number and `cause` to one line.
    """
    mirrored_capture = {
        "issue": JA4L_MIRRORED_CAPTURE_ISSUE,
        "cause": "ja4plus groups the two directions of this mirrored capture as two "
        "connections, so it produces no {} value.".format(method),
    }

    if occurrence_form:
        extra = _count(EXTRA_KEYS, message)
        missing = _count(MISSING_KEYS, message)
        # A capture whose keys are only missing holds no defect of count. The mirrored
        # capture is the one vector that reaches this branch.
        if missing and not extra:
            return mirrored_capture
        if extra and missing:
            return {
                "issue": JA4L_MULTIPLICITY_ISSUE,
                "cause": "ja4plus produces a different set of {} fingerprints.".format(method),
            }
        return {
            "issue": JA4L_MULTIPLICITY_ISSUE,
            "cause": "ja4plus emits more {} values than the reference holds.".format(method),
        }
    if "produced=<none>" in message:
        return mirrored_capture
    return {
        "issue": JA4L_QUIC_SERVER_POINT_ISSUE,
        "cause": "ja4plus reads the first server Initial packet, and the reference reads the "
        "Initial packet that completes the ServerHello.",
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
