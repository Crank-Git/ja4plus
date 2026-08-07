"""No fingerprinter holds a packet object after `process_packet` returns.

A monitor runs for weeks. A fingerprinter that stores the packet it read holds every
packet it ever fingerprinted, and the process grows without a limit. `CLAUDE.md` states
the rule, and `docs/specs/features/02-correctness-audit.md` row 11 records the defect.

Every test here first asserts that the fingerprinter produced at least one value. A
test that asserts "no packet is retained" passes when nothing was stored at all, so the
count guards the assertion against a result that is true for the wrong reason.
"""

from pathlib import Path

import pytest

pytest.importorskip("scapy")

from scapy.all import rdpcap  # noqa: E402
from scapy.packet import Packet  # noqa: E402

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter  # noqa: E402
from ja4plus.fingerprinters.ja4d import JA4DFingerprinter  # noqa: E402
from ja4plus.fingerprinters.ja4d6 import JA4D6Fingerprinter  # noqa: E402
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter  # noqa: E402
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter  # noqa: E402
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter  # noqa: E402
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter  # noqa: E402
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter  # noqa: E402
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter  # noqa: E402
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter  # noqa: E402

VECTORS = Path(__file__).parent / "foxio_vectors"

# One capture for each method. Every capture produces at least one value, so no test
# reports success on an empty fingerprint list.
CAPTURE_OF_METHOD = [
    ("JA4", JA4Fingerprinter, "tls12.pcap"),
    ("JA4S", JA4SFingerprinter, "latest.pcapng"),
    ("JA4H", JA4HFingerprinter, "http1-with-cookies.pcapng"),
    ("JA4X", JA4XFingerprinter, "browsers-x509.pcapng"),
    ("JA4SSH", JA4SSHFingerprinter, "ssh.pcapng"),
    ("JA4L", JA4LFingerprinter, "latest.pcapng"),
    ("JA4T", JA4TFingerprinter, "macos_tcp_flags.pcap"),
    ("JA4TS", JA4TSFingerprinter, "macos_tcp_flags.pcap"),
    ("JA4D", JA4DFingerprinter, "dhcp.pcapng"),
    ("JA4D6", JA4D6Fingerprinter, "dhcpv6.pcap"),
]

# JA4SSH reports a window of many packets, so it stored no packet and it carries no
# endpoint field. Every other method stored one packet for one value.
ENDPOINT_METHODS = [row for row in CAPTURE_OF_METHOD if row[0] != "JA4SSH"]


def run_capture(fingerprinter_class, capture_name):
    """Return the fingerprinter after it reads one capture.

    Args:
        fingerprinter_class: The fingerprinter class to build.
        capture_name: The file name of a capture under `tests/foxio_vectors`.

    Returns:
        The fingerprinter, with every entry the capture produced.
    """
    fingerprinter = fingerprinter_class()
    for packet in rdpcap(str(VECTORS / capture_name)):
        fingerprinter.process_packet(packet)
    return fingerprinter


def packet_paths(root, limit=20):
    """Return the attribute path of every packet object the object reaches.

    The walk reads the attributes of an object, the values of a dictionary and the
    items of a list, so it finds a packet under any key name and at any depth.

    Args:
        root: The object to walk.
        limit: The largest number of paths to report.

    Returns:
        A list of path strings. An empty list means the object reaches no packet.
    """
    seen = set()
    found = []
    stack = [("<fingerprinter>", root)]
    while stack and len(found) < limit:
        path, value = stack.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, Packet):
            found.append(f"{path} holds {type(value).__name__}")
            continue
        if isinstance(value, dict):
            for key, item in value.items():
                stack.append((f"{path}[{key!r}]", item))
        elif isinstance(value, (list, tuple, set)):
            for index, item in enumerate(value):
                stack.append((f"{path}[{index}]", item))
        elif hasattr(value, "__dict__") and not isinstance(value, (str, bytes, int, float)):
            for key, item in vars(value).items():
                stack.append((f"{path}.{key}", item))
    return found


@pytest.mark.parametrize(
    ("method", "fingerprinter_class", "capture_name"),
    CAPTURE_OF_METHOD,
    ids=[row[0] for row in CAPTURE_OF_METHOD],
)
def test_a_fingerprinter_holds_no_packet_after_it_reads_a_capture(
    method, fingerprinter_class, capture_name
):
    """A fingerprinter reaches no packet object after it reads a capture."""
    fingerprinter = run_capture(fingerprinter_class, capture_name)
    entries = fingerprinter.get_fingerprints()
    assert entries, f"{method} produced no value for {capture_name}, so the sweep proves nothing"
    retained = packet_paths(fingerprinter)
    assert retained == [], f"{method} retains {len(retained)} packet objects: {retained}"


@pytest.mark.parametrize(
    ("method", "fingerprinter_class", "capture_name"),
    ENDPOINT_METHODS,
    ids=[row[0] for row in ENDPOINT_METHODS],
)
def test_an_entry_carries_the_endpoints_of_the_packet_that_produced_it(
    method, fingerprinter_class, capture_name
):
    """Every entry carries the address pair and the port pair of its own packet.

    The endpoint fields replace the packet object. A caller that grouped values by
    packet reads these four fields instead. The assertion holds for every method that
    stored a packet. JA4SSH stored none, because it reports a window rather than one
    packet, and it names the stream with its connection key.
    """
    fingerprinter = run_capture(fingerprinter_class, capture_name)
    entries = fingerprinter.get_fingerprints()
    assert entries, f"{method} produced no value for {capture_name}"
    for entry in entries:
        for field in ("src", "dst", "srcport", "dstport"):
            assert field in entry, f"{method} entry holds no {field}: {sorted(entry)}"
        assert entry["src"], f"{method} entry holds an empty src"
        assert entry["dst"], f"{method} entry holds an empty dst"


def test_the_endpoint_fields_report_the_innermost_layers_of_a_tunnelled_packet():
    """A tunnelled packet reports the innermost address pair and port pair.

    `tests/conformance_index.py` groups a value by the innermost layers of the packet
    it came from. The endpoint fields replace that packet, so they must name the same
    layers. An outer address would move a value to a stream the reference does not
    hold.
    """
    from scapy.layers.inet import IP, TCP

    from ja4plus.utils.packet_utils import packet_endpoints

    tunnelled = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / IP(src="192.0.2.1", dst="192.0.2.2")
        / TCP(sport=1234, dport=443)
    )
    assert packet_endpoints(tunnelled) == {
        "src": "192.0.2.1",
        "dst": "192.0.2.2",
        "srcport": 1234,
        "dstport": 443,
    }
