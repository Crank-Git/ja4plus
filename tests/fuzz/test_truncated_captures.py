"""A truncated copy of every FoxIO capture produces no exception.

The suite cuts each capture at test time. The repository commits no generated capture.
`FR-correctness-audit-9` and `FR-correctness-audit-10` state the contract.
"""

import pytest

import ja4plus.utils.http_utils as http_utils
import ja4plus.utils.ssh_utils as ssh_utils
import ja4plus.utils.tls_utils as tls_utils
from tests.fuzz.support import (
    MALFORMED_CAPTURES,
    read_capture,
    run_fingerprinters,
    spy_on,
    truncate_frames,
    truncate_payloads,
)

# The part of the input each case keeps.
FRACTIONS = (0.9, 0.5, 0.1)

SSH_CAPTURES = ("ssh2-malformed.pcap", "ssh2-moloch-crash.pcap")

# The method each capture loses when the cut removes the bytes its parser needs. The
# method produces a fingerprint on the committed capture and none on the cut copy, so
# the pair proves that the parser reads the cut payload and returns nothing.
SILENCED_METHOD = {
    "badcurveball.pcap": "ja4",
    "CVE-2018-6794.pcap": "ja4h",
}


@pytest.mark.parametrize("capture", MALFORMED_CAPTURES)
@pytest.mark.parametrize("fraction", FRACTIONS)
def test_a_truncated_payload_produces_no_exception(vector_dir, capture, fraction):
    packets = truncate_payloads(read_capture(vector_dir, capture), fraction)

    _, failures = run_fingerprinters(packets)

    assert failures == []


@pytest.mark.parametrize("capture", MALFORMED_CAPTURES)
@pytest.mark.parametrize("fraction", FRACTIONS)
def test_a_truncated_payload_reaches_the_tls_parser(monkeypatch, vector_dir, capture, fraction):
    """The TLS parser reads every truncated payload, so the case above can fail."""
    packets = truncate_payloads(read_capture(vector_dir, capture), fraction)
    counter = spy_on(monkeypatch, tls_utils, "parse_tls_handshake")

    run_fingerprinters(packets)

    assert counter.calls > 0


@pytest.mark.parametrize("capture", SSH_CAPTURES)
@pytest.mark.parametrize("fraction", FRACTIONS)
def test_a_truncated_ssh_payload_reaches_the_ssh_parser(monkeypatch, vector_dir, capture, fraction):
    packets = truncate_payloads(read_capture(vector_dir, capture), fraction)
    counter = spy_on(monkeypatch, ssh_utils, "parse_ssh_packet")

    run_fingerprinters(packets)

    assert counter.calls > 0


@pytest.mark.parametrize("fraction", FRACTIONS)
def test_a_truncated_http_payload_reaches_the_http_parser(monkeypatch, vector_dir, fraction):
    packets = truncate_payloads(read_capture(vector_dir, "CVE-2018-6794.pcap"), fraction)
    counter = spy_on(monkeypatch, http_utils, "is_http_request")

    run_fingerprinters(packets)

    assert counter.calls > 0


@pytest.mark.parametrize("capture", sorted(SILENCED_METHOD))
@pytest.mark.parametrize("fraction", FRACTIONS)
def test_a_truncated_payload_silences_the_method_that_reads_it(vector_dir, capture, fraction):
    """The parser produces a value on the committed capture and none on the cut copy.

    The packet keeps every header, so each length field inside the payload declares
    more bytes than the payload carries. `FR-correctness-audit-10` names this case.
    """
    method = SILENCED_METHOD[capture]
    packets = read_capture(vector_dir, capture)

    recorded, _ = run_fingerprinters(packets)
    produced, _ = run_fingerprinters(truncate_payloads(packets, fraction))

    assert recorded.get(method), f"{capture} produces no {method} value to silence."
    assert produced.get(method) is None


@pytest.mark.parametrize("capture", MALFORMED_CAPTURES)
@pytest.mark.parametrize("fraction", FRACTIONS)
def test_a_truncated_payload_produces_no_fingerprint_the_capture_lacks(
    vector_dir, capture, fraction
):
    """A cut payload produces a smaller result, never a value the capture never held.

    A parser that trusts a declared length reads the bytes that follow it and reports
    a fingerprint that describes no traffic.
    """
    packets = read_capture(vector_dir, capture)
    recorded, _ = run_fingerprinters(packets)
    produced, _ = run_fingerprinters(truncate_payloads(packets, fraction))

    for method, fingerprints in produced.items():
        invented = set(fingerprints) - set(recorded.get(method, []))
        assert invented == set(), f"{method} invented {sorted(invented)}"


@pytest.mark.parametrize("capture", MALFORMED_CAPTURES)
@pytest.mark.parametrize("fraction", FRACTIONS)
def test_a_truncated_frame_produces_no_exception(vector_dir, capture, fraction):
    """A cut frame carries a partial header, so scapy reports a layer it does not hold."""
    packets = truncate_frames(read_capture(vector_dir, capture), fraction)

    _, failures = run_fingerprinters(packets)

    assert failures == []


@pytest.mark.parametrize("capture", MALFORMED_CAPTURES)
def test_a_truncated_frame_reaches_the_tls_parser(monkeypatch, vector_dir, capture):
    packets = truncate_frames(read_capture(vector_dir, capture), 0.9)
    counter = spy_on(monkeypatch, tls_utils, "parse_tls_handshake")

    run_fingerprinters(packets)

    assert counter.calls > 0


@pytest.mark.parametrize("capture", MALFORMED_CAPTURES)
@pytest.mark.parametrize("fraction", FRACTIONS)
def test_a_truncated_copy_differs_from_the_committed_capture(vector_dir, capture, fraction):
    """The cut changes the bytes, so no case above reads the committed capture."""
    packets = read_capture(vector_dir, capture)
    original = [bytes(packet) for packet in packets]

    payload_cut = [bytes(packet) for packet in truncate_payloads(packets, fraction)]
    frame_cut = [bytes(packet) for packet in truncate_frames(packets, fraction)]

    assert payload_cut != original
    assert frame_cut != original
    # The helper copies each packet, so the committed capture stays unchanged.
    assert [bytes(packet) for packet in packets] == original
