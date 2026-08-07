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

import pytest

from tests.conformance_index import index_produced, stream_identity

logger = logging.getLogger(__name__)

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
SNAPSHOT_METHODS = (("JA4", "ja4"), ("JA4S", "ja4s"))

# The address fields the Rust snapshot writes for each stream.
SNAPSHOT_ADDRESS_FIELDS = ("src", "dst", "src_port", "dst_port")


def read_rust_snapshot(path):
    """Return the values one FoxIO Rust snapshot holds, keyed by stream identity.

    The snapshot is a YAML list. Each stream opens with `- stream:` at column 0, and the
    fields of that stream follow at two spaces. A nested block indents further, so the
    reader takes the two-space level alone and ignores `tls_certs` and `http`.

    Args:
        path: The path of the snapshot file.

    Returns:
        A map of stream identity to a map of method name to value.

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
        streams.setdefault(identity, {}).update(block["values"])

    for line in path.read_text().splitlines():
        if line.startswith("- stream:"):
            close(block)
            block = {"values": {}}
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

    assert any("JA4" in values for values in streams.values()), "{} holds no JA4 value".format(path)
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


def omitted_cases(capture):
    """Return every case the FoxIO Python file omits and the FoxIO Rust snapshot holds.

    Args:
        capture: The capture file name.

    Returns:
        A list of (identity, method, rust_value) triples.
    """
    rust = read_rust_snapshot(RUST_DIR / RUST_SNAPSHOT_NAME.format(capture=capture))
    python = read_python_methods(VECTORS_DIR / "{}.json".format(capture))
    cases = []
    for identity, values in rust.items():
        for method, value in values.items():
            if method in python.get(identity, set()):
                continue
            cases.append((identity, method, value))
    return cases


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
        assert omitted_cases(capture), "{} holds no omitted stream".format(capture)

    @pytest.mark.parametrize("capture", DIVERGENT_CAPTURES)
    def test_ja4plus_produces_no_value_the_rust_snapshot_contradicts(self, capture):
        """ja4plus never emits a value on a stream that the Rust snapshot reads differently.

        A produced value that differs from the Rust value would mean ja4plus reads the
        stream wrongly. A stream ja4plus reads and the Rust snapshot holds nothing for
        would mean ja4plus invents a value. Neither happens.
        """
        produced = index_produced(VECTORS_DIR / capture)
        contradictions = []
        for identity, method, rust_value in omitted_cases(capture):
            ours = produced.get(identity, {}).get(method, ())
            if len(ours) == 1 and ours[0] == rust_value:
                continue
            if not ours:
                # ja4plus emits nothing here. That is the opposite direction, and issue
                # #138 does not own it, so this check lets it pass.
                continue
            contradictions.append(
                "{} {}: rust={} ja4plus={}".format(label(identity), method, rust_value, list(ours))
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
            for identity, method, rust_value in omitted_cases(capture):
                if not rust_value.startswith("q"):
                    continue
                ours = produced.get(identity, {}).get(method, ())
                if len(ours) == 1 and ours[0] == rust_value:
                    matched += 1
                    continue
                mismatches.append(
                    "{} {} {}: rust={} ja4plus={}".format(
                        capture, label(identity), method, rust_value, list(ours)
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
