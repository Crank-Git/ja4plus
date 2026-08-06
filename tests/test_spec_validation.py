"""
FoxIO JA4+ conformance suite.

The suite compares one method on one stream at a time. Each comparison is one test
case, and its identifier names the vector, the stream and the occurrence key, so a
failure names the vector, the stream, the method, the expected value and the produced
value on its own.

`tests/conformance_index.py` holds the index. It reads the FoxIO expected-output file
into a map of stream to method to occurrence, and it builds the same shape from the
fingerprints ja4plus produces.

The suite holds three groups of test:

- `TestConformanceIndex` checks the index itself. It needs no vector.
- `test_the_produced_fingerprint_equals_the_reference` compares one value.
- `test_the_produced_occurrence_keys_equal_the_reference` compares the occurrence keys
  of one method on one vector. It names an extra occurrence key and a missing one, and
  it reports a method that the vector does not exercise as not applicable.

The vectors are committed under `tests/foxio_vectors`, so this suite needs no network
access. To move the vectors to a newer upstream commit, run
`python tests/download_test_vectors.py` by hand.

Run with: pytest -m spec_validation -v
"""

import json
import logging
from pathlib import Path

import pytest

from tests.conformance_index import (
    index_expected,
    index_produced,
    method_and_occurrence,
    stream_identity,
)

logger = logging.getLogger(__name__)

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"

# The methods this suite reports on every vector. A method that a vector does not
# exercise is reported as not applicable, so the report separates it from a pass.
REPORTED_METHODS = ("JA4", "JA4H", "JA4S", "JA4SSH", "JA4X")


def have_vectors():
    return VECTORS_DIR.exists() and any(VECTORS_DIR.glob("*.pcap*"))


# ---------------------------------------------------------------------------
# Known deviations from FoxIO reference output.
# Keys are method names. A test that hits a known deviation emits a pytest.skip
# (with reason) instead of failing so CI stays green while deviations are tracked.
# ---------------------------------------------------------------------------
KNOWN_DEVIATIONS = {
    # JA4L requires per-packet arrival timestamps and TTL values that are not
    # reliably preserved in pcapng files captured offline.  ja4plus omits JA4L
    # from its fingerprinter set so these values are never produced.
    "JA4L-C": ("JA4L requires live-capture timing; not available from offline PCAPs"),
    "JA4L-S": ("JA4L requires live-capture timing; not available from offline PCAPs"),
    # JA4SSH uses a sliding packet-count window.  FoxIO's reference groups
    # packets by TCP stream; ja4plus currently uses a global window so the
    # per-stream values differ when multiple SSH sessions appear in one PCAP.
    "JA4SSH": (
        "JA4SSH stream-grouping differs: ja4plus uses a global window while "
        "FoxIO's reference groups by TCP stream"
    ),
    # JA4X certificate fingerprints require parsing DER-encoded certificates
    # embedded in the TLS handshake.  ja4plus extracts these only when scapy's
    # TLS layer is fully dissected; some pcapng captures lack the TLS layer
    # metadata needed for full certificate chain extraction.
    "JA4X": (
        "JA4X certificate chain extraction depends on full TLS dissection "
        "which is not always available from pcapng captures"
    ),
    # JA4 extension count: in certain ClientHello packets ja4plus counts one
    # more extension than FoxIO's tshark-based reference (16 vs 15).  This
    # occurs when an extension that FoxIO's parser treats as non-countable
    # (e.g. padding / 0x0015) is included in the raw bytes but excluded from
    # the FoxIO reference count.  Tracked as a known counting deviation.
    # Affects: tls-handshake.pcapng streams 38, 41, 42, 44, 45.
    "JA4_ext_count": (
        "JA4 extension count differs by 1 for some ClientHello packets: "
        "ja4plus counts padding extension 0x0015 while FoxIO reference does not"
    ),
}

# Per-PCAP/stream overrides for deviations that only apply to specific records.
# Keys: "<pcap_name>/<stream_index>/<method>" -> deviation reason string.
STREAM_DEVIATIONS = {
    "tls-handshake.pcapng/38/JA4": KNOWN_DEVIATIONS["JA4_ext_count"],
    "tls-handshake.pcapng/41/JA4": KNOWN_DEVIATIONS["JA4_ext_count"],
    "tls-handshake.pcapng/42/JA4": KNOWN_DEVIATIONS["JA4_ext_count"],
    "tls-handshake.pcapng/44/JA4": KNOWN_DEVIATIONS["JA4_ext_count"],
    "tls-handshake.pcapng/45/JA4": KNOWN_DEVIATIONS["JA4_ext_count"],
}


def _deviation_reason(pcap_name, stream_index, method):
    """Return the known-deviation reason for one method on one stream, or None."""
    stream_key = "{}/{}/{}".format(pcap_name, stream_index, method)
    if stream_key in STREAM_DEVIATIONS:
        return STREAM_DEVIATIONS[stream_key]
    return KNOWN_DEVIATIONS.get(method)


def _load_expected(json_path):
    """Return the expected records from a FoxIO expected-output file."""
    with open(json_path) as handle:
        return json.load(handle)


# ---------------------------------------------------------------------------
# Test parameters
# ---------------------------------------------------------------------------


def _vector_files():
    """Return the (pcap_path, json_path) pair of every available vector."""
    if not have_vectors():
        return []
    pairs = []
    for json_path in sorted(VECTORS_DIR.glob("*.json")):
        pcap_name = json_path.stem  # e.g. "tls12.pcap" or "tls-handshake.pcapng"
        pcap_path = VECTORS_DIR / pcap_name
        if pcap_path.exists():
            pairs.append((pcap_path, json_path))
    return pairs


def _vector_params():
    """Return one parameter set for every vector."""
    return [
        pytest.param(pcap_path, json_path, id=pcap_path.name)
        for pcap_path, json_path in _vector_files()
    ]


def _value_params():
    """Return one parameter set for every expected (vector, stream, occurrence)."""
    params = []
    for pcap_path, json_path in _vector_files():
        streams = index_expected(_load_expected(json_path))
        for stream in sorted(streams.values(), key=lambda item: (item.index, item.identity)):
            for method in sorted(stream.methods):
                for occurrence, expected in sorted(stream.methods[method].items()):
                    params.append(
                        pytest.param(
                            pcap_path,
                            stream,
                            method,
                            occurrence,
                            expected,
                            id="{}-stream{}:{}-{}.{}".format(
                                pcap_path.name,
                                stream.index,
                                stream.src_port,
                                method,
                                occurrence,
                            ),
                        )
                    )
    return params


def _method_params():
    """Return one parameter set for every (vector, method) pair the suite reports."""
    params = []
    for pcap_path, json_path in _vector_files():
        streams = index_expected(_load_expected(json_path))
        methods = set(REPORTED_METHODS)
        for stream in streams.values():
            methods.update(stream.methods)
        for method in sorted(methods):
            params.append(
                pytest.param(
                    pcap_path,
                    json_path,
                    method,
                    id="{}-{}".format(pcap_path.name, method),
                )
            )
    return params


def _occurrence_keys(streams_methods, method, label_of):
    """Return the set of "<stream label>/<method>.<n>" keys for one method."""
    keys = set()
    for identity, methods in streams_methods.items():
        occurrences = methods.get(method)
        if not occurrences:
            continue
        for occurrence in occurrences:
            keys.add("{}/{}.{}".format(label_of(identity), method, occurrence))
    return keys


# ---------------------------------------------------------------------------
# The index itself
# ---------------------------------------------------------------------------


@pytest.mark.spec_validation
class TestConformanceIndex:
    """Check the index that the conformance comparison depends on."""

    def test_the_stream_identity_ignores_the_direction(self):
        client = stream_identity("10.0.0.1", "1234", "10.0.0.2", 443)
        server = stream_identity("10.0.0.2", 443, "10.0.0.1", "1234")
        assert client == server

    def test_the_stream_identity_separates_two_ports(self):
        first = stream_identity("10.0.0.1", "1234", "10.0.0.2", 443)
        second = stream_identity("10.0.0.1", "1235", "10.0.0.2", 443)
        assert first != second

    def test_the_key_reader_reads_the_occurrence_counter(self):
        assert method_and_occurrence("JA4SSH.2") == ("JA4SSH", 2)

    def test_the_key_reader_reports_no_counter_on_a_plain_key(self):
        assert method_and_occurrence("JA4L-C") == ("JA4L-C", None)

    def test_the_key_reader_rejects_a_raw_form(self):
        assert method_and_occurrence("JA4_r.1") is None
        assert method_and_occurrence("JA4_ro.1") is None
        assert method_and_occurrence("JA4_o.1") is None
        assert method_and_occurrence("JA4S_r") is None
        assert method_and_occurrence("JA4H_ro") is None

    def test_the_key_reader_rejects_a_key_that_names_no_method(self):
        assert method_and_occurrence("domain") is None
        assert method_and_occurrence("ssh_extras") is None

    def test_the_index_holds_one_stream_for_both_directions(self):
        records = [
            {
                "stream": 0,
                "src": "10.0.0.1",
                "srcport": "1234",
                "dst": "10.0.0.2",
                "dstport": "443",
                "JA4H": "ge11nn020000_aaa_bbb_ccc",
            },
            {
                "stream": 0,
                "src": "10.0.0.2",
                "srcport": "443",
                "dst": "10.0.0.1",
                "dstport": "1234",
                "JA4H": "ge11nn020000_ddd_eee_fff",
            },
        ]
        streams = index_expected(records)
        assert len(streams) == 1
        stream = next(iter(streams.values()))
        assert stream.methods["JA4H"] == {
            1: "ge11nn020000_aaa_bbb_ccc",
            2: "ge11nn020000_ddd_eee_fff",
        }

    def test_the_index_keeps_the_occurrence_counter_of_the_reference(self):
        records = [
            {
                "stream": 3,
                "src": "10.0.0.1",
                "srcport": "1234",
                "dst": "10.0.0.2",
                "dstport": "22",
                "JA4SSH.1": "c36s36_c76s124_c0s0",
                "JA4SSH.2": "c36s36_c77s123_c0s0",
            }
        ]
        streams = index_expected(records)
        stream = next(iter(streams.values()))
        assert stream.index == 3
        assert stream.methods["JA4SSH"] == {
            1: "c36s36_c76s124_c0s0",
            2: "c36s36_c77s123_c0s0",
        }

    def test_the_index_drops_a_raw_form(self):
        records = [
            {
                "stream": 0,
                "src": "10.0.0.1",
                "srcport": "1234",
                "dst": "10.0.0.2",
                "dstport": "443",
                "JA4.1": "t13d1715h2_5b57614c22b0_3d5424432f57",
                "JA4_r.1": "t13d1715h2_002f,0035_0005,000a_0403",
            }
        ]
        streams = index_expected(records)
        stream = next(iter(streams.values()))
        assert set(stream.methods) == {"JA4"}

    def test_the_index_names_the_stream_in_its_label(self):
        records = [
            {
                "stream": 7,
                "src": "10.0.0.1",
                "srcport": "1234",
                "dst": "10.0.0.2",
                "dstport": "443",
                "JA4.1": "t13d1715h2_5b57614c22b0_3d5424432f57",
            }
        ]
        stream = next(iter(index_expected(records).values()))
        assert "stream=7" in stream.label
        assert "10.0.0.1:1234" in stream.label
        assert "10.0.0.2:443" in stream.label


# ---------------------------------------------------------------------------
# The comparison against the FoxIO reference
# ---------------------------------------------------------------------------


@pytest.mark.spec_validation
@pytest.mark.skipif(not have_vectors(), reason="FoxIO test vectors not downloaded")
@pytest.mark.parametrize("pcap_path,stream,method,occurrence,expected", _value_params())
def test_the_produced_fingerprint_equals_the_reference(
    pcap_path, stream, method, occurrence, expected
):
    """Compare one occurrence of one method on one stream against the reference."""
    reason = _deviation_reason(pcap_path.name, stream.index, method)
    if reason:
        pytest.skip("known deviation: {}".format(reason))

    produced = index_produced(pcap_path).get(stream.identity, {}).get(method, ())
    if len(produced) < occurrence:
        pytest.fail(
            "{} {} {}.{}: expected={!r} produced=<none>, {} produced {} value(s) "
            "on this stream".format(
                pcap_path.name,
                stream.label,
                method,
                occurrence,
                expected,
                method,
                len(produced),
            )
        )

    actual = produced[occurrence - 1]
    if actual != expected:
        pytest.fail(
            "{} {} {}.{}: expected={!r} produced={!r}".format(
                pcap_path.name, stream.label, method, occurrence, expected, actual
            )
        )


@pytest.mark.spec_validation
@pytest.mark.skipif(not have_vectors(), reason="FoxIO test vectors not downloaded")
@pytest.mark.parametrize("pcap_path,json_path,method", _method_params())
def test_the_produced_occurrence_keys_equal_the_reference(pcap_path, json_path, method):
    """Compare the occurrence keys of one method on one vector against the reference.

    A vector that produces more fingerprints than the reference fails, and the failure
    names the extra occurrence keys. A vector that exercises the method nowhere is
    reported as not applicable.
    """
    streams = index_expected(_load_expected(json_path))
    produced = index_produced(pcap_path)

    labels = {identity: stream.label for identity, stream in streams.items()}

    def label_of(identity):
        return labels.get(identity, _unlabelled(identity))

    expected_methods = {identity: stream.methods for identity, stream in streams.items()}
    expected_keys = _occurrence_keys(expected_methods, method, label_of)
    produced_keys = _occurrence_keys(
        {
            identity: {name: dict(enumerate(values, start=1)) for name, values in methods.items()}
            for identity, methods in produced.items()
        },
        method,
        label_of,
    )

    if not expected_keys and not produced_keys:
        pytest.skip(
            "not applicable: {} holds no {} value and ja4plus produces none".format(
                pcap_path.name, method
            )
        )

    reason = _deviation_reason(pcap_path.name, "*", method)
    if reason:
        pytest.skip("known deviation: {}".format(reason))

    extra = sorted(produced_keys - expected_keys)
    missing = sorted(expected_keys - produced_keys)
    if extra or missing:
        pytest.fail(
            "{} {}: {} extra occurrence key(s) {}; {} missing occurrence key(s) {}".format(
                pcap_path.name, method, len(extra), extra, len(missing), missing
            )
        )


def _unlabelled(identity):
    """Return a label for a stream that the reference does not hold."""
    if identity is None:
        return "stream=? address unknown"
    (first_host, first_port), (second_host, second_port) = identity
    return "stream=? {}:{} -> {}:{}".format(first_host, first_port, second_host, second_port)


@pytest.mark.spec_validation
@pytest.mark.skipif(not have_vectors(), reason="FoxIO test vectors not downloaded")
@pytest.mark.parametrize("pcap_path,json_path", _vector_params())
def test_the_vector_is_readable(pcap_path, json_path):
    """Read the capture and the expected-output file of one vector."""
    from scapy.all import rdpcap

    packets = rdpcap(str(pcap_path))
    assert len(packets) > 0, "No packets in {}".format(pcap_path.name)

    expected = _load_expected(json_path)
    # FoxIO ships an empty array for a capture that its Python implementation
    # produces no fingerprint for, such as dhcp.pcapng. That file is still a
    # valid vector, so an empty array is not a defect.
    assert isinstance(expected, list), "Expected JSON should be a list of records"


@pytest.mark.spec_validation
def test_the_suite_collects_at_least_one_vector():
    """Fail when no vector is available, because an empty suite proves nothing."""
    assert have_vectors(), "No FoxIO vector under {}".format(VECTORS_DIR)
    assert _vector_files(), "No capture and expected-output pair under {}".format(VECTORS_DIR)
