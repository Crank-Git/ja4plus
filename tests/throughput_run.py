"""Measure the packet throughput of one `Processor` and write it as JSON.

`tests/test_throughput.py` runs this file as a program, in an interpreter of its own. A
separate interpreter is part of the measurement and not a convenience. A run taken inside
a pytest session shares its processor with every case that runs beside it. The rate then
reads the load of the session rather than the speed of the package.

**The clock covers `process_packet` and nothing else.** The program builds the traffic,
or reads the capture, outside the clock. `throughput` of the `## Terms` table of
`docs/specs/spec.md` names the count of packets one processor reads for each second. The
seconds scapy spends to build a packet, or to parse a capture file, belong to scapy. A run
that timed the traffic builder as well would report the speed of scapy under the name of
this package.

**The program takes no target and states no verdict.** `Non-goals` of
`docs/specs/spec.md` states that wire-speed performance is out of scope, and that this
project measures throughput and reports it. The program writes a number, and a reader
decides what the number is worth against a use.

**The measurement carries the fingerprint count for a reason.** A processor that produces
nothing reads the highest rate of all, because it does no work. `TestTheResultControl`
reads that field.

The program has two modes.

1. **The synthetic run.** It feeds the traffic builder of `tests/test_memory_bounds.py`,
   so this measurement and the memory ceiling describe the same packet run.
2. **The capture run.** It reads each named capture under `tests/foxio_vectors/` once,
   and it states the packets and the elapsed time of each one. That run states the rate
   on recorded traffic rather than on generated traffic.

Run it by hand like this:

    python tests/throughput_run.py --packets 1000000 --connections 100000
    python tests/throughput_run.py --captures tls12.pcap ssh2.pcapng
"""

import argparse
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT = Path(__file__).resolve().parent.parent

VECTOR_DIRECTORY = Path(__file__).resolve().parent / "foxio_vectors"

# The packets one connection carries. `ceiling_traffic` returns ten, so the run spreads
# its packets across one tenth as many connections.
PACKETS_PER_CONNECTION = 10

# The packets a bare invocation feeds. A reader who runs the program with no argument
# gets a measurement rather than a usage error, and the published run states its own
# count on the command line.
DEFAULT_PACKETS = 10000


def head_commit(root=ROOT):
    """Return the commit the measurement describes.

    A rate belongs to one state of the source. The measurement names that commit, and a
    reader then proves it is an ancestor of the branch the measurement is published on.

    Args:
        root: The repository root.

    Returns:
        The 40-character commit, or the empty string where git reads none.
    """
    finished = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    return finished.stdout.strip()


def rate(packets, elapsed):
    """Return the packets one run read for each second.

    Args:
        packets: The count of packets the run fed.
        elapsed: The seconds the processor spent on them.

    Returns:
        The rate, or 0.0 where the clock read no time at all. A run that reads zero
        seconds states no rate, and a division would raise instead.
    """
    if elapsed <= 0.0:
        return 0.0
    return packets / elapsed


def measure_synthetic(packets, connections):
    """Return the throughput measurement of one generated packet run.

    The clock covers `process_packet` alone. `ceiling_traffic` builds ten packets for one
    connection with scapy, and that build costs more than the work it feeds. A clock that
    spanned both would report the speed of scapy.

    Args:
        packets: The count of packets to feed.
        connections: The count of distinct connections to spread them across.

    Returns:
        A dict with the keys `packets`, `connections`, `fingerprints`, `elapsed_seconds`
        and `packets_per_second`.
    """
    from ja4plus.processor import Processor

    from test_memory_bounds import ceiling_traffic

    processor = Processor()
    fed = 0
    fingerprints = 0
    elapsed = 0.0
    index = 0
    while fed < packets:
        built = ceiling_traffic(index % connections, 1000.0 + index * 0.1)
        started = time.perf_counter()
        for packet in built:
            fingerprints += len(processor.process_packet(packet))
        elapsed += time.perf_counter() - started
        fed += len(built)
        index += 1
    return {
        "packets": fed,
        "connections": min(index, connections),
        "fingerprints": fingerprints,
        "elapsed_seconds": elapsed,
        "packets_per_second": rate(fed, elapsed),
    }


def measure_capture(path):
    """Return the throughput measurement of one capture file.

    The read sits outside the clock. scapy parses the whole file into packet objects
    first, and that parse costs more than the work that follows it.

    Args:
        path: The path of the capture file.

    Returns:
        A dict with the keys `capture`, `packets`, `fingerprints`, `elapsed_seconds` and
        `packets_per_second`.

    Raises:
        FileNotFoundError: The capture is absent.
    """
    from scapy.all import rdpcap

    from ja4plus.processor import Processor

    if not Path(path).exists():
        raise FileNotFoundError("the capture is absent from {}".format(path))
    packets = rdpcap(str(path))
    processor = Processor()
    fingerprints = 0
    started = time.perf_counter()
    for packet in packets:
        fingerprints += len(processor.process_packet(packet))
    elapsed = time.perf_counter() - started
    return {
        "capture": Path(path).name,
        "packets": len(packets),
        "fingerprints": fingerprints,
        "elapsed_seconds": elapsed,
        "packets_per_second": rate(len(packets), elapsed),
    }


def measure_captures(names):
    """Return the throughput measurement of each named capture, and the total.

    One processor reads one capture. A processor shared across captures would carry the
    state of an earlier capture into a later one. The rate of the later capture would then
    read the eviction work of the earlier one.

    Args:
        names: The capture file names under `tests/foxio_vectors/`.

    Returns:
        A dict with the key `captures`, which holds one row for each capture, and the
        totals under `packets`, `fingerprints`, `elapsed_seconds` and
        `packets_per_second`.
    """
    rows = [measure_capture(VECTOR_DIRECTORY / name) for name in names]
    packets = sum(row["packets"] for row in rows)
    elapsed = sum(row["elapsed_seconds"] for row in rows)
    return {
        "captures": rows,
        "packets": packets,
        "fingerprints": sum(row["fingerprints"] for row in rows),
        "elapsed_seconds": elapsed,
        "packets_per_second": rate(packets, elapsed),
    }


def every_capture_name():
    """Return the name of every capture under `tests/foxio_vectors/`, sorted."""
    return sorted(
        path.name for path in VECTOR_DIRECTORY.rglob("*") if path.suffix in {".pcap", ".pcapng"}
    )


def main(argv=None):
    """Measure the throughput of one `Processor` and write the measurement as JSON.

    Args:
        argv: The command-line arguments. `None` reads `sys.argv`.

    Returns:
        Zero. The program reports through its JSON object and not through its status.
    """
    parser = argparse.ArgumentParser(description="Measure the packet throughput.")
    parser.add_argument("--packets", type=int, default=DEFAULT_PACKETS)
    # The default is `None` and not zero, so the program tells an absent option from an
    # explicit `--connections 0`. A zero the caller typed reaches `parser.error` below,
    # where a zero used as the default would silently read the computed count instead.
    parser.add_argument("--connections", type=int, default=None)
    parser.add_argument(
        "--captures",
        nargs="*",
        default=None,
        help="Time these captures instead of the synthetic run. No name reads every one.",
    )
    arguments = parser.parse_args(argv)

    if arguments.captures is None:
        if arguments.packets < 1:
            parser.error("--packets needs at least 1")
        connections = arguments.connections
        if connections is None:
            connections = max(arguments.packets // PACKETS_PER_CONNECTION, 1)
        if connections < 1:
            parser.error("--connections needs at least 1")
        measurement = measure_synthetic(arguments.packets, connections)
    else:
        measurement = measure_captures(arguments.captures or every_capture_name())

    measurement.update(
        {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "commit": head_commit(),
        }
    )
    json.dump(measurement, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
