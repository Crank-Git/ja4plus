"""Measure the resident memory one `Processor` holds after a stated packet run.

`tests/test_memory_bounds.py` runs this file as a program, in an interpreter of its own.
A separate interpreter is what makes the reading mean anything: `ru_maxrss` reports the
high-water mark of the whole process, so a reading taken inside a pytest session measures
every case that ran before it as well.

**The program takes two kinds of reading, and the two answer different questions.**
`peak_mib` is the high-water mark, and the memory ceiling is a claim about that mark.
`idle_resident_mib` and `final_resident_mib` are the current resident set before and
after the traffic, and the memory the traffic adds is the difference between those two.

**Never subtract two high-water marks.** A high-water mark rises and never falls, so the
difference between two of them is `max(0, later mark - earlier mark)` and not the growth
between the readings. The import of scapy reaches a mark that the traffic run then stays
below, and the difference is exactly zero on a run that allocated tens of MiB. The
Ubuntu jobs of pull request #384 read `154.7` for both marks for that reason. Round 126
of `docs/specs/spec.md` records the whole measurement.

The program writes one JSON object to standard output. `TestTheStatedMemoryCeiling`
reads it.

Run it by hand like this:

    python tests/memory_ceiling_run.py --packets 1000000 --connections 100000
"""

import argparse
import json
import os
import resource
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

MIB = 1024.0 * 1024.0

# The resident page count of `/proc/<pid>/statm`. `proc_pid_statm(5)` states the field
# order `size resident shared text lib data dt`, so the resident count sits at index 1.
STATM_RESIDENT_FIELD = 1

STATM = Path("/proc/self/statm")


def resident_mib():
    """Return the highest resident memory this process has held, in MiB.

    `ru_maxrss` counts bytes on Darwin and kilobytes on Linux. The two platforms carry no
    shared unit, so the caller must never compare a raw reading across them.

    Returns:
        The high-water mark of the resident set, in MiB.
    """
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return value / MIB
    return value * 1024.0 / MIB


def current_resident_mib():
    """Return the resident memory this process holds now, in MiB.

    The reading rises and falls with the memory the process holds, where the high-water
    mark of `resident_mib` only rises. A caller that wants the memory one run added must
    read this function before the run and after it.

    Linux publishes the count in `/proc/self/statm`, and Darwin ships no `/proc`. The
    `ps` program reports the same number on Darwin, in 1024-byte units.

    Returns:
        The resident set of this process, in MiB.

    Raises:
        subprocess.CalledProcessError: `ps` failed, and the host ships no `/proc`.
    """
    if STATM.exists():
        pages = int(STATM.read_text().split()[STATM_RESIDENT_FIELD])
        return pages * os.sysconf("SC_PAGE_SIZE") / MIB
    completed = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(os.getpid())],
        capture_output=True,
        text=True,
        check=True,
    )
    return int(completed.stdout.strip()) * 1024.0 / MIB


def main(argv=None):
    """Feed one `Processor` a packet run and write the memory reading as JSON.

    Args:
        argv: The command-line arguments. `None` reads `sys.argv`.

    Returns:
        Zero. The program reports through its JSON object and not through its status.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=int, required=True)
    parser.add_argument("--connections", type=int, required=True)
    parser.add_argument(
        "--bound",
        type=int,
        default=0,
        help="The entry count every state table reads. Zero keeps the shipped bounds.",
    )
    arguments = parser.parse_args(argv)
    if arguments.connections < 1:
        parser.error("--connections needs at least 1")

    # The import sits here so that the reading above it measures a bare interpreter.
    # scapy costs about 84 MiB, and a reader who sees one number cannot separate the two.
    from ja4plus.processor import Processor

    from test_memory_bounds import ceiling_traffic, lower_every_bound

    processor = Processor()
    if arguments.bound:
        lower_every_bound(processor, arguments.bound)
    idle_resident = current_resident_mib()

    fed = 0
    index = 0
    while fed < arguments.packets:
        for packet in ceiling_traffic(index % arguments.connections, 1000.0 + index * 0.1):
            processor.process_packet(packet)
            fed += 1
        index += 1

    # The current reading comes first, so the high-water mark below covers it. The mark
    # never falls, and `current_resident_mib` may start one `ps` process on Darwin.
    final_resident = current_resident_mib()

    json.dump(
        {
            "idle_resident_mib": round(idle_resident, 2),
            "final_resident_mib": round(final_resident, 2),
            "peak_mib": round(resident_mib(), 2),
            "packets": fed,
            "connections": min(index, arguments.connections),
            "bound": arguments.bound,
        },
        sys.stdout,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
