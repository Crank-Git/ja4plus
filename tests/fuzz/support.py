"""Helpers that drive every fingerprinter over hostile input.

The suite generates each malformed copy at test time. The repository commits no
generated capture.
"""

import sys
import types

from scapy.all import Raw, rdpcap

from ja4plus.processor import Processor

# The four FoxIO captures that exist to carry malformed input.
MALFORMED_CAPTURES = (
    "ssh2-malformed.pcap",
    "ssh2-moloch-crash.pcap",
    "badcurveball.pcap",
    "CVE-2018-6794.pcap",
)


class CallCounter:
    """Counts the calls of one parser."""

    def __init__(self, target):
        self.target = target
        self.calls = 0


def spy_on(monkeypatch, module, name):
    """Return a counter that records each call of the named parser.

    A test that asserts "no exception" passes when no parser runs. The counter proves
    that the parser reads the malformed bytes, so the assertion can fail.

    Args:
        monkeypatch: The pytest `monkeypatch` fixture.
        module: The module that defines the parser.
        name: The parser name.

    Returns:
        A `CallCounter` whose `calls` attribute holds the call count.
    """
    original = getattr(module, name)
    counter = CallCounter(f"{module.__name__}.{name}")

    def wrapper(*args, **kwargs):
        counter.calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(module, name, wrapper)

    # A consumer that imports the name binds its own reference, and a patch on the
    # defining module never reaches that reference.
    for other in list(sys.modules.values()):
        if not isinstance(other, types.ModuleType):
            continue
        if not getattr(other, "__name__", "").startswith("ja4plus"):
            continue
        if getattr(other, name, None) is original:
            monkeypatch.setattr(other, name, wrapper)

    return counter


def read_capture(vector_dir, name):
    """Return the packets of one committed capture.

    Args:
        vector_dir: The directory that holds the FoxIO captures.
        name: The capture file name.

    Returns:
        The packet list scapy read.
    """
    return rdpcap(str(vector_dir / name))


def run_fingerprinters(packets):
    """Return the fingerprints every method produced, and the calls that raised.

    Each fingerprinter reads each packet directly. `Processor.process_packet` catches
    every exception, so a suite that drives the processor cannot observe a parser that
    raises.

    Args:
        packets: The packets to read.

    Returns:
        A tuple of two items. The first maps a method name to the fingerprints it
        produced. The second lists one description for each call that raised.
    """
    processor = Processor()
    produced = {}
    failures = []

    for index, packet in enumerate(packets):
        for method, fingerprinter in processor.fingerprinters.items():
            try:
                fingerprint = fingerprinter.process_packet(packet)
            # The harness catches every exception, because it measures whether one
            # happened. A fingerprinter still catches only the errors it expects.
            except Exception as error:
                failures.append(f"{method} raised on packet {index}: {error!r}")
                continue
            if fingerprint:
                produced.setdefault(method, []).append(fingerprint)

    return produced, failures


def truncate_payloads(packets, fraction):
    """Return copies of the packets whose transport payload keeps a part of its bytes.

    The length fields inside the payload keep their values, so each declared length
    exceeds the bytes that follow it. `FR-correctness-audit-10` names this case.

    Args:
        packets: The packets to copy.
        fraction: The part of the payload to keep, from 0 to 1.

    Returns:
        A new packet list. The input packets stay unchanged.
    """
    truncated = []
    for packet in packets:
        copy = packet.copy()
        if Raw in copy:
            load = bytes(copy[Raw].load)
            copy[Raw].load = load[: max(1, int(len(load) * fraction))]
        truncated.append(copy)
    return truncated


def truncate_frames(packets, fraction):
    """Return copies of the packets that keep a part of the whole frame.

    A cut frame carries a partial header, so scapy reports a layer the packet does not
    hold. `FR-correctness-audit-9` names this case.

    Args:
        packets: The packets to copy.
        fraction: The part of the frame to keep, from 0 to 1.

    Returns:
        A new packet list. The input packets stay unchanged.
    """
    truncated = []
    for packet in packets:
        data = bytes(packet)
        # scapy raises `struct.error` when it dissects a frame shorter than the
        # link-layer header, so the cut keeps that header. A shorter frame builds no
        # packet object, and it therefore reaches no fingerprinter.
        floor = len(packet) - len(packet.payload)
        truncated.append(packet.__class__(data[: max(floor, int(len(data) * fraction))]))
    return truncated
