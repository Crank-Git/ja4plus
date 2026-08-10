"""Compare the JA4TS values of ja4plus against the FoxIO Wireshark dissector.

**`wireshark/test/testdata/` holds 58 JA4TS values in 24 files, and this project recorded
that it holds none.** The table `The search for a reference value` in
`docs/specs/foxio/JA4T.md` read `No ja4t value and no ja4ts value` for that directory
until #515. The measurement of 2026-08-10 contradicts it: the directory holds 118
`ja4.ja4t` values and 58 `ja4.ja4ts` values, at the pinned commit. The earlier reading
searched for the key `ja4t`, and the dissector writes the key `ja4.ja4t`.

The FoxIO Wireshark dissector is therefore the richest FoxIO source of JA4TS values, and
`tests/foxio_vectors/wireshark_expected/` now holds a copy of the 24 files. The Zeek
package publishes 10 more, which `tests/test_foxio_zeek_ja4ts.py` reads.

Reproduce the count from a checkout at the pinned commit.

```bash
grep -c '"ja4.ja4ts"' wireshark/test/testdata/*.json
```

## How one value reaches one connection

The dissector writes one record for each frame, and it names the frame number rather than
the stream. This module reads the frame out of the capture, takes the address pair and the
port pair of that packet, and counts the occurrence in frame order. A tunneled capture
carries several address layers, and `packet[IP]` returns the outer one, which is the pair
`ja4plus` reports and the pair `python/test/testdata/gre-erspan-vxlan.pcap.json` names.
#242 records that reading.
"""

import json
import logging
from pathlib import Path
from typing import NamedTuple

import pytest

from tests.conformance_index import index_expected, index_produced, stream_identity
from tests.foxio_deviations import load_register, lookup, value_key

logger = logging.getLogger(__name__)

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"
WIRESHARK_DIR = VECTORS_DIR / "wireshark_expected"

# The register of known deviations. The module reads it once, at collection.
DEVIATIONS = load_register()

METHOD = "JA4TS"

# The key the dissector writes for the method, and the key that names the frame.
DISSECTOR_KEY = "ja4.ja4ts"
FRAME_KEY = "frame.number"

# Every capture whose local Wireshark expected-output file holds a JA4TS value. The
# measurement of 2026-08-10 read all 37 files of the directory at the pinned commit and
# found the key in these 24.
JA4TS_CAPTURES = (
    "CVE-2018-6794.pcap",
    "badcurveball.pcap",
    "browsers-x509.pcapng",
    "chrome-cloudflare-quic-with-secrets.pcapng",
    "gre-erspan-vxlan.pcap",
    "http-empty-useragent.pcap",
    "http1-with-cookies.pcapng",
    "http2-with-cookies.pcapng",
    "https-connect.pcap",
    "https3-301-get.pcap",
    "ipv6.pcapng",
    "latest.pcapng",
    "socks-https-example.pcap",
    "socks4-https.pcap",
    "ssh-r.pcap",
    "ssh-scp-1050.pcap",
    "ssh2-malformed.pcap",
    "ssh2-moloch-crash.pcap",
    "ssh2.pcapng",
    "sshv1.pcap",
    "tcpdump-geneve.pcap",
    "tls-alpn-h2.pcap",
    "tls3.pcapng",
    "v6.pcap",
)

# The count of JA4TS values the 24 local files hold. A vector refresh that moves the count
# fails `test_the_local_files_hold_the_fifty_eight_values_the_reading_counts`.
JA4TS_VALUE_COUNT = 58

# The count of values ja4plus matches, and the count the register owns. #246 owns every
# difference, and `TestTheDifferencesAreTheRecordedResetDecline` measures the cause.
MATCHING_VALUE_COUNT = 52
RESET_VALUE_COUNT = 6


class WiresharkCase(NamedTuple):
    """One JA4TS value that a FoxIO Wireshark expected-output file holds.

    Attributes:
        capture: The capture file name.
        frame: The frame number the dissector names, counted from 1.
        identity: The direction-free stream identity of that frame.
        index: The stream index the FoxIO Python file gives, or `?`.
        src_port: The source port the FoxIO Python file gives, or the client port.
        occurrence: The position of the value on the stream, counted from 1.
        value: The value the dissector wrote.
    """

    capture: str
    frame: int
    identity: tuple
    index: object
    src_port: str
    occurrence: int
    value: str


def _dissector_records(capture):
    """Return one (frame, value) pair for every JA4TS value of one capture.

    Args:
        capture: The capture file name.

    Returns:
        A list of pairs, in the order the file holds them.
    """
    path = WIRESHARK_DIR / "{}.json".format(capture)
    if not path.is_file():
        return []
    records = []
    with open(path) as handle:
        document = json.load(handle)
    for record in document:
        layers = record["_source"]["layers"]
        if DISSECTOR_KEY not in layers:
            continue
        frame = int(layers[FRAME_KEY][0])
        for value in layers[DISSECTOR_KEY]:
            records.append((frame, value))
    return records


def _packet_endpoints(packet):
    """Return the address pair and the port pair of one packet, or None.

    A tunneled capture carries several address layers, and this reader takes the outer
    one, because that is the pair ja4plus reports.
    """
    from scapy.all import IP, IPv6, TCP

    if TCP not in packet:
        return None
    if IP in packet:
        layer = packet[IP]
    elif IPv6 in packet:
        layer = packet[IPv6]
    else:
        return None
    return layer.src, str(packet[TCP].sport), layer.dst, str(packet[TCP].dport)


def _cases(capture):
    """Return every JA4TS case the Wireshark file of one capture holds.

    Args:
        capture: The capture file name.

    Returns:
        A list of WiresharkCase entries, in frame order.
    """
    records = _dissector_records(capture)
    if not records:
        return []
    # `ja4plus` loads the scapy contrib layers that dissect ERSPAN, VXLAN and Geneve, and
    # a reader that skips this import finds no TCP layer inside a tunnel. A read of
    # 2026-08-10 reports `gre-erspan-vxlan.pcap` frame 2 as `Ether / IP / GRE / Raw`
    # before the import and as a chain that ends in `TCP` after it.
    import ja4plus  # noqa: F401
    from scapy.all import rdpcap

    packets = rdpcap(str(VECTORS_DIR / capture))
    expected_path = VECTORS_DIR / "{}.json".format(capture)
    streams = {}
    if expected_path.is_file():
        with open(expected_path) as handle:
            streams = index_expected(json.load(handle))
    cases = []
    seen = {}
    for frame, value in records:
        endpoints = _packet_endpoints(packets[frame - 1])
        if endpoints is None:
            continue
        source, source_port, destination, destination_port = endpoints
        identity = stream_identity(source, source_port, destination, destination_port)
        seen[identity] = seen.get(identity, 0) + 1
        stream = streams.get(identity)
        cases.append(
            WiresharkCase(
                capture=capture,
                frame=frame,
                identity=identity,
                index="?" if stream is None else stream.index,
                # A SYN-ACK travels from the server, so the destination port is the client
                # port. The FoxIO Python file names the same port on its first record.
                src_port=destination_port if stream is None else stream.src_port,
                occurrence=seen[identity],
                value=value,
            )
        )
    return cases


def all_cases():
    """Return every JA4TS case the 24 local Wireshark files hold."""
    cases = []
    for capture in JA4TS_CAPTURES:
        cases.extend(_cases(capture))
    return cases


def case_key(case):
    """Return the register key of one case."""
    return value_key(case.capture, case.index, case.src_port, METHOD, case.occurrence)


def register_keys():
    """Return every register key this module reads.

    `tests/test_spec_validation.py` reads this list, because it rejects a register entry
    that matches no collected case. An entry of this module matches no case of that
    module, so the check needs every list.

    Returns:
        A list of register keys.
    """
    return [case_key(case) for case in all_cases()]


def _deviation_marks(key):
    """Return the marks one case carries, given its register key.

    Args:
        key: A key that `value_key` builds.

    Returns:
        A tuple of pytest marks. The tuple is empty when the register holds no entry.
    """
    deviation = lookup(DEVIATIONS, key)
    if deviation is None:
        return ()
    return (pytest.mark.xfail(reason=deviation.reason(), strict=True),)


CASES = all_cases()


def _params():
    """Return one parameter set for every JA4TS value the local files hold."""
    return [
        pytest.param(
            case,
            id="{}-frame{}-{}:{}-{}.{}".format(
                case.capture, case.frame, case.index, case.src_port, METHOD, case.occurrence
            ),
            marks=_deviation_marks(case_key(case)),
        )
        for case in CASES
    ]


@pytest.mark.spec_validation
class TestTheWiresharkDissectorHoldsWhatJa4plusProduces:
    """Compare each JA4TS value of the FoxIO Wireshark dissector against ja4plus.

    Each case names one capture, one frame, one stream and one occurrence, so a JA4TS
    value that moves fails a case that names where it moved.
    """

    @pytest.mark.parametrize("case", _params())
    def test_ja4plus_produces_the_wireshark_ja4ts_value(self, case):
        """ja4plus produces the JA4TS value the FoxIO Wireshark dissector wrote."""
        produced = index_produced(VECTORS_DIR / case.capture).get(case.identity, {})
        values = produced.get(METHOD, ())
        ours = values[case.occurrence - 1] if len(values) >= case.occurrence else "<none>"
        assert ours == case.value, "{} frame {} {}.{}: wireshark={!r} ja4plus={!r}".format(
            case.capture, case.frame, METHOD, case.occurrence, case.value, ours
        )

    def test_the_local_files_hold_the_fifty_eight_values_the_reading_counts(self):
        """The 24 local Wireshark files hold 58 JA4TS values."""
        assert len(CASES) == JA4TS_VALUE_COUNT

    def test_the_register_owns_six_of_the_fifty_eight_values(self):
        """Six values reach the register and 52 compare as a pass."""
        registered = [case for case in CASES if lookup(DEVIATIONS, case_key(case))]
        assert len(registered) == RESET_VALUE_COUNT
        assert len(CASES) - len(registered) == MATCHING_VALUE_COUNT

    @pytest.mark.parametrize("capture", JA4TS_CAPTURES)
    def test_the_capture_holds_a_wireshark_file_that_names_a_ja4ts_value(self, capture):
        """A capture earns its place in this module only when its file holds a value."""
        assert _dissector_records(capture), "{} holds no JA4TS value".format(capture)


@pytest.mark.spec_validation
class TestTheDifferencesAreTheRecordedResetDecline:
    """Measure the cause of every JA4TS value that ja4plus does not produce.

    R13 of `docs/specs/foxio/JA4T.md` records the decline. The dissector writes a second
    JA4TS value on a RST packet of a connection with no delay, and that value repeats the
    value the SYN-ACK already produced. `.claude/rules/conformance.md` declines a value
    that describes no packet of its own, and `zeek/ja4t/main.zeek` writes one JA4TS value
    for one connection, so the Zeek package corroborates the decline. #246 owns it.
    """

    def _registered(self):
        return [case for case in CASES if lookup(DEVIATIONS, case_key(case))]

    def test_every_registered_frame_carries_the_reset_flag(self):
        """Each value the register owns comes from a RST packet."""
        from scapy.all import TCP, rdpcap

        readings = []
        for case in self._registered():
            packets = rdpcap(str(VECTORS_DIR / case.capture))
            flags = packets[case.frame - 1][TCP].flags
            readings.append((case.capture, case.frame, str(flags)))
        assert readings, "no case reaches the register"
        assert all(reading[2] == "R" for reading in readings), readings

    def test_every_registered_value_repeats_the_value_of_the_first_synack(self):
        """A declined value equals the value the SYN-ACK of the same stream produced."""
        first = {}
        for case in CASES:
            first.setdefault((case.capture, case.identity), case.value)
        repeats = [
            case.value == first[(case.capture, case.identity)] for case in self._registered()
        ]
        assert repeats and all(repeats)

    def test_ja4plus_produces_no_value_for_a_declined_frame(self):
        """ja4plus writes one JA4TS value for the stream, and the dissector writes more."""
        extra = []
        for case in self._registered():
            values = index_produced(VECTORS_DIR / case.capture).get(case.identity, {})
            if len(values.get(METHOD, ())) >= case.occurrence:
                extra.append((case.capture, case.frame, case.occurrence))
        assert not extra, extra
