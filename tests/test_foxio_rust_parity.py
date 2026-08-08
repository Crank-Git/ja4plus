"""Compare ja4plus against the FoxIO Rust implementation on the streams Python omits.

The FoxIO project ships three implementations. The Python one writes
`python/test/testdata/<capture>.json`, and the conformance suite compares against that
file. The Rust one writes `rust/ja4/src/snapshots/ja4__insta@<capture>.snap`.

The two disagree. The FoxIO Python implementation reads no QUIC handshake, and it reads
no TLS on a port it does not know. The FoxIO Rust implementation reads both. Issue #138
names the streams that difference produces, and this module holds the measurement that
settles it: on every such stream, ja4plus produces the value the Rust snapshot holds.

The measurement is the proof `.claude/rules/conformance.md` requires. A reading of the
FoxIO source is not proof, so the snapshots are committed and the suite compares them.
"""

import json
import logging
from pathlib import Path
from typing import NamedTuple

import pytest

from tests.conformance_index import index_produced, stream_identity
from tests.foxio_deviations import load_register, lookup, occurrence_key, value_key

logger = logging.getLogger(__name__)

# The register of known deviations. The module reads it once, at collection.
DEVIATIONS = load_register()


def _deviation_marks(key):
    """Return the marks one case carries, given its register key.

    A registered case carries `xfail(strict=True)`, so it reports as `xfailed` while it
    fails and fails the suite the moment it passes.

    Args:
        key: A key that `value_key` or `occurrence_key` builds.

    Returns:
        A tuple of pytest marks. The tuple is empty when the register holds no entry.
    """
    deviation = lookup(DEVIATIONS, key)
    if deviation is None:
        return ()
    return (pytest.mark.xfail(reason=deviation.reason(), strict=True),)


VECTORS_DIR = Path(__file__).parent / "foxio_vectors"
RUST_DIR = VECTORS_DIR / "rust_expected"
RUST_SNAPSHOT_NAME = "ja4__insta@{capture}.snap"

# The captures issue #138 names, plus the two the register names under the same cause.
# Each one holds at least one stream that the FoxIO Python file omits and the FoxIO Rust
# snapshot holds.
DIVERGENT_CAPTURES = (
    "browsers-x509.pcapng",
    "chrome-cloudflare-quic-with-secrets.pcapng",
    "https-connect.pcap",
    "latest.pcapng",
    "quic-tls-handshake.pcapng",
    "quic-with-several-tls-frames.pcapng",
    "ssh2.pcapng",
    "tls-handshake.pcapng",
    "tls-sni.pcapng",
    "tls3.pcapng",
)

# The streams on which the server coalesces the ServerHello, the Certificate and the
# ServerHelloDone into one handshake record that spans several TCP segments. The FoxIO
# Python file omits the JA4S value of every one, and the FoxIO Rust snapshot holds it.
# Issue #151 names the first three, and the one reader change settles all six.
COALESCED_RECORD_STREAMS = (
    ("ssh2.pcapng", "172.16.225.48", "57374", "52.178.17.3", "t120300_c030_09f674154ab3"),
    ("ssh2.pcapng", "172.16.225.48", "57375", "204.79.197.220", "t1205h2_c030_015e35fdd027"),
    (
        "tls-handshake.pcapng",
        "192.168.1.168",
        "50167",
        "40.126.24.84",
        "t120400_c030_4e8089b08790",
    ),
    (
        "browsers-x509.pcapng",
        "172.27.7.31",
        "54524",
        "13.107.21.239",
        "t1206h2_c030_044dc9b3196d",
    ),
    ("latest.pcapng", "172.16.225.48", "52940", "52.249.29.248", "t120300_c030_09f674154ab3"),
    ("latest.pcapng", "172.16.225.48", "52941", "52.249.29.248", "t120300_c030_09f674154ab3"),
)

# The method name the reference uses, beside the field name the Rust snapshot writes.
# The FoxIO Python expected-output file holds no JA4T value for any capture, so the Rust
# snapshot is the only FoxIO reference this repository holds for the method. #216 added
# `JA4T`, and the six local snapshots carry 38 values.
SNAPSHOT_METHODS = (("JA4", "ja4"), ("JA4S", "ja4s"), ("JA4T", "ja4t"))

# The method the register-keyed cases below compare, and the field name it reads. No
# local snapshot holds a `ja4ts` field, so JA4TS reaches no reference value here.
SNAPSHOT_TCP_METHOD = "JA4T"

# The address fields the Rust snapshot writes for each stream.
SNAPSHOT_ADDRESS_FIELDS = ("src", "dst", "src_port", "dst_port")


class RustStream(NamedTuple):
    """One stream of a FoxIO Rust snapshot.

    Attributes:
        identity: The direction-free stream identity.
        index: The stream index the snapshot gives, as a string.
        src_port: The source port the snapshot gives.
        values: A map of method name to value.
    """

    identity: tuple
    index: str
    src_port: str
    values: dict


def read_rust_snapshot(path):
    """Return the streams one FoxIO Rust snapshot holds, keyed by stream identity.

    The snapshot is a YAML list. Each stream opens with `- stream:` at column 0, and the
    fields of that stream follow at two spaces. A nested block indents further, so the
    reader takes the two-space level alone and ignores `tls_certs` and `http`.

    Args:
        path: The path of the snapshot file.

    Returns:
        A map of stream identity to a RustStream. The index and the source port of the
        first block win, because the register key names the stream a reader sees first.

    Raises:
        AssertionError: The snapshot holds no JA4 value. An empty result compares equal
            to an empty produced list, and the caller then reports a pass on nothing.
    """
    streams = {}
    block = None

    def close(block):
        if block is None:
            return
        if not all(block.get(field) for field in SNAPSHOT_ADDRESS_FIELDS):
            return
        identity = stream_identity(block["src"], block["src_port"], block["dst"], block["dst_port"])
        held = streams.get(identity)
        if held is None:
            streams[identity] = RustStream(
                identity=identity,
                index=block["index"],
                src_port=block["src_port"],
                values=dict(block["values"]),
            )
            return
        held.values.update(block["values"])

    for line in path.read_text().splitlines():
        if line.startswith("- stream:"):
            close(block)
            block = {"index": line.partition(": ")[2].strip(), "values": {}}
            continue
        if block is None:
            continue
        # A field of the stream itself sits at two spaces. A deeper indent belongs to a
        # nested block, which names no stream of its own.
        if not line.startswith("  ") or line.startswith("   "):
            continue
        name, separator, value = line.strip().partition(": ")
        if not separator:
            continue
        if name in SNAPSHOT_ADDRESS_FIELDS:
            block[name] = value.strip()
        for method, field in SNAPSHOT_METHODS:
            if name == field:
                block["values"][method] = value.strip()
    close(block)

    assert any("JA4" in stream.values for stream in streams.values()), (
        "{} holds no JA4 value".format(path)
    )
    return streams


def read_python_methods(path):
    """Return the set of method names the FoxIO Python file holds, keyed by stream.

    Args:
        path: The path of the expected-output file.

    Returns:
        A map of stream identity to a set of method names.
    """
    streams = {}
    for record in json.loads(path.read_text()):
        identity = stream_identity(
            record["src"], record["srcport"], record["dst"], record["dstport"]
        )
        names = streams.setdefault(identity, set())
        for key in record:
            if key.startswith("JA4"):
                names.add(key.partition(".")[0])
    return streams


class OmittedCase(NamedTuple):
    """One comparison the FoxIO Python file omits and the FoxIO Rust snapshot holds.

    Attributes:
        identity: The direction-free stream identity.
        index: The stream index the snapshot gives.
        src_port: The source port the snapshot gives.
        method: The method name, such as `JA4T`.
        value: The value the snapshot holds.
    """

    identity: tuple
    index: str
    src_port: str
    method: str
    value: str


def omitted_cases(capture):
    """Return every case the FoxIO Python file omits and the FoxIO Rust snapshot holds.

    Args:
        capture: The capture file name.

    Returns:
        A list of OmittedCase entries.
    """
    rust = read_rust_snapshot(RUST_DIR / RUST_SNAPSHOT_NAME.format(capture=capture))
    python = read_python_methods(VECTORS_DIR / "{}.json".format(capture))
    cases = []
    for identity, stream in rust.items():
        for method, value in stream.values.items():
            if method in python.get(identity, set()):
                continue
            cases.append(
                OmittedCase(
                    identity=identity,
                    index=stream.index,
                    src_port=stream.src_port,
                    method=method,
                    value=value,
                )
            )
    return cases


def handshake_cases(capture):
    """Return every omitted case of a handshake method, for one capture.

    Issue #138 owns the handshake methods, and its rule rests on the three gaps of the
    FoxIO Python implementation. JA4T is not such a gap: the FoxIO Python implementation
    holds no JA4T value for any capture, and the register-keyed cases below own it.

    Args:
        capture: The capture file name.

    Returns:
        A list of OmittedCase entries whose method is not JA4T.
    """
    return [case for case in omitted_cases(capture) if case.method != SNAPSHOT_TCP_METHOD]


def tcp_cases(capture):
    """Return every JA4T value the FoxIO Rust snapshot of one capture holds.

    Args:
        capture: The capture file name.

    Returns:
        A list of OmittedCase entries whose method is JA4T, sorted by source port.
    """
    cases = [case for case in omitted_cases(capture) if case.method == SNAPSHOT_TCP_METHOD]
    return sorted(cases, key=lambda case: (case.index, case.src_port))


def tcp_captures():
    """Return every capture whose local Rust snapshot holds a JA4T value."""
    return tuple(capture for capture in DIVERGENT_CAPTURES if tcp_cases(capture))


def _tcp_value_params():
    """Return one parameter set for every JA4T value a local Rust snapshot holds.

    Each parameter set carries the register key of the case, so a mismatch that another
    issue owns reports as `xfailed` rather than as a failure.
    """
    params = []
    for capture in tcp_captures():
        for case in tcp_cases(capture):
            key = value_key(capture, case.index, case.src_port, case.method, 1)
            params.append(
                pytest.param(
                    capture,
                    case,
                    id="{}-stream{}:{}-{}.1".format(
                        capture, case.index, case.src_port, case.method
                    ),
                    marks=_deviation_marks(key),
                )
            )
    return params


def _tcp_occurrence_params():
    """Return one parameter set for every capture whose Rust snapshot holds a JA4T value."""
    return [
        pytest.param(
            capture,
            id="{}-{}".format(capture, SNAPSHOT_TCP_METHOD),
            marks=_deviation_marks(occurrence_key(capture, SNAPSHOT_TCP_METHOD)),
        )
        for capture in tcp_captures()
    ]


def register_keys():
    """Return every register key this module reads.

    `tests/test_spec_validation.py` reads this list, because it rejects a register entry
    that matches no collected case. An entry of this module matches no case of that
    module, so the check needs both lists.

    Returns:
        A list of register keys.
    """
    keys = []
    for capture in tcp_captures():
        keys.append(occurrence_key(capture, SNAPSHOT_TCP_METHOD))
        for case in tcp_cases(capture):
            keys.append(value_key(capture, case.index, case.src_port, case.method, 1))
    return keys


def label(identity):
    """Return a one-line description of a stream identity."""
    (first, first_port), (second, second_port) = identity
    return "{}:{} <-> {}:{}".format(first, first_port, second, second_port)


@pytest.mark.spec_validation
class TestTheRustImplementationHoldsWhatJa4plusProduces:
    """Check ja4plus against the FoxIO Rust snapshot on the streams Python omits.

    The FoxIO Python expected-output file omits these streams, so the conformance suite
    registers them as deviations. Issue #138 settles them: the omission is a gap in the
    FoxIO Python implementation, and ja4plus matches the FoxIO Rust implementation.
    """

    @pytest.mark.parametrize("capture", DIVERGENT_CAPTURES)
    def test_the_capture_holds_a_stream_the_python_file_omits(self, capture):
        """The capture earns its place in this module only when the two references differ."""
        assert handshake_cases(capture), "{} holds no omitted stream".format(capture)

    @pytest.mark.parametrize("capture", DIVERGENT_CAPTURES)
    def test_ja4plus_produces_no_value_the_rust_snapshot_contradicts(self, capture):
        """ja4plus never emits a value on a stream that the Rust snapshot reads differently.

        A produced value that differs from the Rust value would mean ja4plus reads the
        stream wrongly. A stream ja4plus reads and the Rust snapshot holds nothing for
        would mean ja4plus invents a value. Neither happens.
        """
        produced = index_produced(VECTORS_DIR / capture)
        contradictions = []
        for case in handshake_cases(capture):
            ours = produced.get(case.identity, {}).get(case.method, ())
            if len(ours) == 1 and ours[0] == case.value:
                continue
            if not ours:
                # ja4plus emits nothing here. That is the opposite direction, and issue
                # #138 does not own it, so this check lets it pass.
                continue
            contradictions.append(
                "{} {}: rust={} ja4plus={}".format(
                    label(case.identity), case.method, case.value, list(ours)
                )
            )
        assert not contradictions, "\n".join(contradictions)

    def test_ja4plus_matches_the_rust_value_on_every_quic_stream(self):
        """Every QUIC stream the FoxIO Python file omits produces the Rust value.

        The FoxIO Python implementation reads no QUIC handshake at all, so every QUIC
        value in the register comes from this gap. A QUIC value is one whose first
        character is `q`.
        """
        mismatches = []
        matched = 0
        for capture in DIVERGENT_CAPTURES:
            produced = index_produced(VECTORS_DIR / capture)
            for case in handshake_cases(capture):
                if not case.value.startswith("q"):
                    continue
                ours = produced.get(case.identity, {}).get(case.method, ())
                if len(ours) == 1 and ours[0] == case.value:
                    matched += 1
                    continue
                mismatches.append(
                    "{} {} {}: rust={} ja4plus={}".format(
                        capture, label(case.identity), case.method, case.value, list(ours)
                    )
                )
        assert not mismatches, "\n".join(mismatches)
        assert matched, "the vectors hold no QUIC stream the FoxIO Python file omits"


@pytest.mark.spec_validation
class TestTheStreamsThatCoalesceTheServerHelloRecord:
    """Measure each JA4S stream whose ServerHello record spans several TCP segments.

    The class above lets a stream on which ja4plus emits nothing pass, so it reports a
    pass on a comparison it never makes. These streams were exactly that case. Each
    check here names one stream and one value, so a later regression names itself.
    """

    @pytest.mark.parametrize(
        "capture,client,client_port,server,rust_value",
        COALESCED_RECORD_STREAMS,
        ids=[
            "{}:{}".format(capture, client_port)
            for capture, _, client_port, _, _ in COALESCED_RECORD_STREAMS
        ],
    )
    def test_the_stream_produces_the_foxio_rust_ja4s_value(
        self, capture, client, client_port, server, rust_value
    ):
        """ja4plus produces the JA4S value the FoxIO Rust snapshot holds."""
        identity = stream_identity(client, client_port, server, "443")
        produced = index_produced(VECTORS_DIR / capture)
        assert produced.get(identity, {}).get("JA4S", ()) == (rust_value,)

    @pytest.mark.parametrize(
        "capture,client,client_port,server,rust_value",
        COALESCED_RECORD_STREAMS,
        ids=[
            "{}:{}".format(capture, client_port)
            for capture, _, client_port, _, _ in COALESCED_RECORD_STREAMS
        ],
    )
    def test_the_foxio_python_file_omits_the_stream(
        self, capture, client, client_port, server, rust_value
    ):
        """The stream earns its place here only while the FoxIO Python file omits it.

        A vector refresh that adds a JA4S value for the stream makes the Rust snapshot
        the second reference, not the first. This check fails then, and it names the
        stream that changed.
        """
        identity = stream_identity(client, client_port, server, "443")
        python = read_python_methods(VECTORS_DIR / "{}.json".format(capture))
        assert "JA4S" not in python.get(identity, set())


@pytest.mark.spec_validation
class TestTheFoxioPythonImplementationReadsNoQuic:
    """Record the gap that issue #138 settles.

    The FoxIO Python expected-output file holds no QUIC fingerprint for any capture. The
    check states the mechanism as a measurement, so a later vector refresh that changes
    it fails here and names itself.
    """

    def test_the_python_expected_output_holds_no_quic_value(self):
        quic = []
        tcp = 0
        for path in sorted(VECTORS_DIR.glob("*.json")):
            for record in json.loads(path.read_text()):
                for key, value in record.items():
                    if not key.startswith(("JA4.", "JA4S", "JA4_")) and key != "JA4":
                        continue
                    if not isinstance(value, str):
                        continue
                    if value.startswith("q"):
                        quic.append("{}: {} = {}".format(path.name, key, value))
                    elif value.startswith("t"):
                        tcp += 1
        assert not quic, "\n".join(quic)
        # Without this check, a vector set that lost every value would pass the check
        # above on nothing.
        assert tcp > 100, "the vectors hold too few TCP values to prove the gap"


@pytest.mark.spec_validation
class TestTheJa4tValuesTheRustSnapshotHolds:
    """Compare JA4T against every JA4T value the local Rust snapshots hold.

    The FoxIO Python expected-output file holds no JA4T value, so the Rust snapshot is
    the only FoxIO reference this repository holds for the method. Before #216 the
    harness read two fields of the snapshot and never read `ja4t`, so no case compared a
    JA4T value and the suite reported green on a comparison it never made.

    Each value carries the register key `<capture>/<stream>:<port>/JA4T.1`, and the
    occurrence keys of each capture carry `<capture>/JA4T`. A mismatch that #215 owns
    reports as `xfailed`, and a mismatch the register does not name fails the suite.
    """

    def test_the_local_snapshots_hold_the_thirty_eight_values_the_reading_counts(self):
        """`docs/specs/foxio/JA4T.md` counts 38 JA4T values in the six local snapshots.

        A snapshot that leaves the repository takes its cases away, and the suite still
        reports green. This check makes that loss as loud as a mismatch.
        """
        counts = {capture: len(tcp_cases(capture)) for capture in tcp_captures()}
        assert counts == {
            "browsers-x509.pcapng": 3,
            "chrome-cloudflare-quic-with-secrets.pcapng": 1,
            "https-connect.pcap": 1,
            "latest.pcapng": 6,
            "ssh2.pcapng": 19,
            "tls3.pcapng": 8,
        }
        assert sum(counts.values()) == 38

    def test_the_suite_collects_one_case_for_every_value_the_snapshots_hold(self):
        """Fail when a snapshot value carries no case.

        The parameter list is the comparison. A reader who removes `JA4T` from
        `SNAPSHOT_METHODS` empties the list, and this check names the loss.
        """
        assert len(_tcp_value_params()) == 38

    def test_no_two_cases_share_one_register_key(self):
        """One entry that matches two cases marks both, so neither fix reports itself."""
        keys = register_keys()
        duplicates = sorted({key for key in keys if keys.count(key) > 1})
        assert not duplicates, "two cases share one register key: {}".format(duplicates)

    @pytest.mark.parametrize("capture,case", _tcp_value_params())
    def test_the_produced_ja4t_equals_the_rust_snapshot_value(self, capture, case):
        """ja4plus produces the JA4T value the FoxIO Rust snapshot holds for the stream."""
        produced = index_produced(VECTORS_DIR / capture).get(case.identity, {}).get(case.method, ())
        if not produced:
            pytest.fail(
                "{} {} {}: rust={} ja4plus=<none>".format(
                    capture, label(case.identity), case.method, case.value
                )
            )
        if produced[0] != case.value:
            pytest.fail(
                "{} {} {}: rust={} ja4plus={}".format(
                    capture, label(case.identity), case.method, case.value, produced[0]
                )
            )

    @pytest.mark.parametrize("capture", _tcp_occurrence_params())
    def test_the_produced_ja4t_count_equals_the_rust_snapshot_count(self, capture):
        """ja4plus produces one JA4T value on every stream the Rust snapshot names.

        The Rust implementation reads the first SYN of a connection alone, so it holds
        one value for each stream. A stream that produces several values is the defect
        `.claude/rules/conformance.md` names, and the value comparison above cannot
        report it, because it reads the first value alone.
        """
        produced = index_produced(VECTORS_DIR / capture)
        differences = []
        for case in tcp_cases(capture):
            ours = produced.get(case.identity, {}).get(case.method, ())
            if len(ours) != 1:
                differences.append(
                    "{} {}: rust=1 value ja4plus={} value(s)".format(
                        label(case.identity), case.method, len(ours)
                    )
                )
        assert not differences, "{}: {} stream(s) differ\n{}".format(
            capture, len(differences), "\n".join(differences)
        )


@pytest.mark.spec_validation
class TestTheLocalSnapshotsHoldNoJa4tsValue:
    """Record that JA4TS reaches no FoxIO reference value in this repository.

    `docs/specs/foxio/JA4T.md` reports no `ja4ts` value in `rust/ja4/src/snapshots/`, in
    `wireshark/test/testdata/` or in `python/test/testdata/`. The Zeek baseline holds
    one, and #198 owns that reading. **JA4TS therefore stays uncovered here.** A snapshot
    refresh that adds a `ja4ts` field fails this check, and the check names the file.
    """

    def test_no_local_rust_snapshot_writes_a_ja4ts_field(self):
        holders = [
            path.name
            for path in sorted(RUST_DIR.glob("*.snap"))
            if any(line.strip().startswith("ja4ts:") for line in path.read_text().splitlines())
        ]
        assert not holders, "\n".join(holders)
        # Without this check, an empty snapshot directory would pass the check above.
        assert len(list(RUST_DIR.glob("*.snap"))) == 10

    def test_no_foxio_python_expected_output_holds_a_ja4t_or_a_ja4ts_key(self):
        """The FoxIO Python implementation writes neither method, so it decides neither."""
        keys = set()
        for path in sorted(VECTORS_DIR.glob("*.json")):
            for record in json.loads(path.read_text()):
                keys.update(record)
        assert not {key for key in keys if key.startswith(("JA4T", "JA4TS"))}
