"""Check the throughput measurement and the three controls that keep it honest.

`tests/throughput_run.py` measures the throughput of one `Processor`. This file reads the
measurement it writes and states the conditions the measurement must meet.

**A timing case that measures the wrong thing reads as a fast package.** Three controls
close the three ways this measurement fails while it still reports a number.

1. **The packet count control.** A run that feeds fewer packets than the case states
   reads a shorter elapsed time. The rate then describes a run nobody asked for.
2. **The work control.** Twice the packets must report a longer elapsed time. A
   measurement that reads the process start rather than the traffic does not rise.
3. **The result control.** A processor that produces no fingerprint reads the highest
   rate of all, because it does no work.

**This file states no throughput target.** `Non-goals` of `docs/specs/spec.md` states that
wire-speed performance is out of scope, and that this project measures throughput and
reports it. No case here fails on a rate.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

THROUGHPUT_RUNNER = Path(__file__).resolve().with_name("throughput_run.py")

VECTOR_DIRECTORY = Path(__file__).resolve().parent / "foxio_vectors"

PERFORMANCE_PAGE = ROOT / "docs" / "performance.md"

WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"

# The packets one connection carries. `ceiling_traffic` of `tests/test_memory_bounds.py`
# returns ten, so the run spreads its packets across one tenth as many connections.
PACKETS_PER_CONNECTION = 10

# The packets the synthetic case feeds. `docs/specs/features/11-pre-release-validation.md`
# states the published run at 1000000 packets, and a run of that length costs every later
# run of the unit suite. The default therefore holds the case cheap, and the pull request
# records one run at 1000000. `tests/test_memory_bounds.py` holds the same arrangement for
# the memory ceiling, and it reads the same traffic builder, so the two measurements
# describe the same packet run.
THROUGHPUT_PACKETS = int(os.environ.get("JA4PLUS_THROUGHPUT_PACKETS", "10000"))

# The connections the case builds, and the packets it feeds across them. The run stops on
# a whole connection. A count that is no multiple of ten reaches the next multiple, so the
# count rounds up here. A reader who overrides the packet count with an odd number then
# reads a control that measures the run. It reads no control that fails on the rounding.
THROUGHPUT_CONNECTIONS = max(THROUGHPUT_PACKETS // PACKETS_PER_CONNECTION, 1)


def run_packets(packets):
    """Return the packets one run feeds when the case asks for a stated count.

    Args:
        packets: The count of packets the case asks for.

    Returns:
        The count the run feeds, which is the next whole connection at or above the ask.
    """
    return -(-packets // PACKETS_PER_CONNECTION) * PACKETS_PER_CONNECTION


THROUGHPUT_RUN_PACKETS = run_packets(THROUGHPUT_PACKETS)

# The packets the work control feeds. The rounding above applies to this run too, so a
# doubled ask is not always a doubled run, and the case reads this count rather than
# twice the first one.
DOUBLE_RUN_PACKETS = run_packets(2 * THROUGHPUT_PACKETS)

# The seconds one measurement may take. #279 read 481 seconds for 1000000 packets on a
# ten-core laptop, so the limit holds about four times that rate. The work control feeds
# twice the packets, so its own run reads twice this allowance.
THROUGHPUT_TIMEOUT = 120 + THROUGHPUT_PACKETS // 500

# The share by which the reported rate may differ from the rate the caller computes.
# The caller computes it from the two fields beside it. The criterion of #415 states the
# figure as one part in a thousand.
RATE_TOLERANCE = 1.0 / 1000.0

# The capture the capture-mode case reads. The case proves the mode measures one real
# capture; the published run reads every capture, and `docs/performance.md` holds it.
SMALL_CAPTURE = "tls12.pcap"

# Every field the measurement states. The acceptance criteria of #415 name the first
# seven, and `fingerprints` carries the result control.
MEASUREMENT_FIELDS = (
    "packets",
    "connections",
    "elapsed_seconds",
    "packets_per_second",
    "fingerprints",
    "python_version",
    "platform",
    "commit",
)


def measure_throughput(packets, captures=None, timeout=None):
    """Return the throughput measurement of one run, taken in an interpreter of its own.

    The run needs an interpreter of its own for the same reason the memory ceiling does.
    A measurement taken inside this pytest session shares its processor with every case
    that runs beside it.

    Args:
        packets: The count of packets to feed in the synthetic run.
        captures: The capture file names to time instead of the synthetic run. `None`
            runs the synthetic case.
        timeout: The seconds the run may take. `None` reads `THROUGHPUT_TIMEOUT`.

    Returns:
        The measurement, as a dict.

    Raises:
        subprocess.CalledProcessError: The run failed.
        subprocess.TimeoutExpired: The run passed the timeout.
    """
    command = [sys.executable, str(THROUGHPUT_RUNNER)]
    if captures is None:
        command += [
            "--packets",
            str(packets),
            "--connections",
            str(max(packets // PACKETS_PER_CONNECTION, 1)),
        ]
    else:
        command += ["--captures", *captures]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
        timeout=timeout or THROUGHPUT_TIMEOUT,
    )
    # scapy writes a deprecation warning to standard error, and a future release may
    # write to standard output. The measurement is the last line, so a banner costs
    # nothing. `tests/test_memory_bounds.py` reads its own measurement the same way.
    return json.loads(completed.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def measurement():
    """Return the measurement of the synthetic run at the stated packet count."""
    return measure_throughput(THROUGHPUT_PACKETS)


@pytest.fixture(scope="module")
def double_measurement():
    """Return the measurement of the same run at twice the packets."""
    return measure_throughput(2 * THROUGHPUT_PACKETS, timeout=2 * THROUGHPUT_TIMEOUT)


@pytest.fixture(scope="module")
def capture_measurement():
    """Return the measurement of the capture mode over one small capture."""
    return measure_throughput(0, captures=[SMALL_CAPTURE])


@pytest.fixture(scope="module")
def page():
    """Return the text of `docs/performance.md`."""
    return PERFORMANCE_PAGE.read_text()


class TestTheMeasurementTheRunWrites:
    """The run writes one JSON object, and the object states every field."""

    def test_the_run_writes_one_json_object(self, measurement):
        assert isinstance(measurement, dict)

    @pytest.mark.parametrize("field", MEASUREMENT_FIELDS)
    def test_the_measurement_states_the_field(self, measurement, field):
        assert field in measurement, sorted(measurement)

    def test_the_measurement_names_the_interpreter_that_takes_it(self, measurement):
        assert measurement["python_version"] == sys.version.split()[0]

    def test_the_measurement_names_the_platform_that_takes_it(self, measurement):
        assert measurement["platform"]

    def test_the_measurement_names_the_commit_it_measures(self, measurement):
        assert re.fullmatch(r"[0-9a-f]{40}", measurement["commit"])


class TestThePacketCountControl:
    """A run that fed fewer packets reads a shorter elapsed time."""

    def test_the_run_feeds_the_packet_count_the_case_states(self, measurement):
        assert measurement["packets"] == THROUGHPUT_RUN_PACKETS

    def test_the_run_builds_the_connection_count_the_case_states(self, measurement):
        assert measurement["connections"] == THROUGHPUT_CONNECTIONS


class TestTheWorkControl:
    """Twice the packets reports a longer elapsed time."""

    def test_the_double_run_feeds_more_packets_than_the_first(
        self, measurement, double_measurement
    ):
        assert double_measurement["packets"] == DOUBLE_RUN_PACKETS
        assert DOUBLE_RUN_PACKETS > measurement["packets"]

    def test_the_double_run_reports_a_longer_elapsed_time(self, measurement, double_measurement):
        assert double_measurement["elapsed_seconds"] > measurement["elapsed_seconds"]


class TestTheResultControl:
    """A processor that produced nothing reads the highest rate of all."""

    def test_the_run_produces_more_than_zero_fingerprints(self, measurement):
        assert measurement["fingerprints"] > 0


class TestTheReportedRate:
    """The reported rate is the rate the run measured."""

    def test_the_rate_equals_the_packets_divided_by_the_elapsed_time(self, measurement):
        computed = measurement["packets"] / measurement["elapsed_seconds"]
        assert abs(measurement["packets_per_second"] - computed) <= RATE_TOLERANCE * computed

    def test_the_elapsed_time_is_above_zero(self, measurement):
        assert measurement["elapsed_seconds"] > 0


class TestTheCaptureMode:
    """The run times each capture it reads, and it states one row for each."""

    def test_the_capture_mode_states_one_row_for_each_capture_it_reads(self, capture_measurement):
        assert [row["capture"] for row in capture_measurement["captures"]] == [SMALL_CAPTURE]

    def test_each_row_states_the_packets_it_times(self, capture_measurement):
        assert capture_measurement["captures"][0]["packets"] > 0

    def test_the_total_packets_equal_the_sum_of_the_rows(self, capture_measurement):
        rows = capture_measurement["captures"]
        assert capture_measurement["packets"] == sum(row["packets"] for row in rows)


class TestThePerformancePage:
    """`docs/performance.md` publishes the measurements, and it names each host."""

    def test_the_page_states_one_row_for_each_capture_the_run_reads(self, page):
        captures = sorted(
            path.name for path in VECTOR_DIRECTORY.rglob("*") if path.suffix in {".pcap", ".pcapng"}
        )
        named = sorted(
            {name for name in captures if re.search(rf"\| `{re.escape(name)}` \|", page)}
        )
        assert named == captures

    def test_the_page_names_the_host_of_each_measurement(self, page):
        assert "bigboy" in page

    def test_the_page_states_that_the_synthetic_run_has_one_host_only(self, page):
        assert "one host" in page

    def test_the_page_states_that_the_measurement_becomes_no_floor(self, page):
        assert "no floor" in page


class TestNoJobGatesOnARate:
    """`Non-goals` states no throughput target, so no workflow fails on a rate."""

    def test_no_workflow_names_the_rate_field(self):
        named = [
            path.name
            for path in WORKFLOW_DIRECTORY.rglob("*")
            if path.is_file() and "packets_per_second" in path.read_text()
        ]
        assert named == []
