"""Measure the resident memory one `Processor` holds after a stated packet run.

`tests/test_memory_bounds.py` runs this file as a program, in an interpreter of its own.
A separate interpreter is what makes the reading mean anything: `ru_maxrss` reports the
high-water mark of the whole process, so a reading taken inside a pytest session measures
every case that ran before it as well.

The program writes one JSON object to standard output. `TestTheStatedMemoryCeiling`
reads it.

Run it by hand like this:

    python tests/memory_ceiling_run.py --packets 1000000 --connections 100000
"""

import argparse
import json
import resource
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

MIB = 1024.0 * 1024.0


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
    idle = resident_mib()

    fed = 0
    index = 0
    while fed < arguments.packets:
        for packet in ceiling_traffic(index % arguments.connections, 1000.0 + index * 0.1):
            processor.process_packet(packet)
            fed += 1
        index += 1

    json.dump(
        {
            "idle_mib": round(idle, 2),
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
