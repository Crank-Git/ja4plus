"""JA4H spec compliance tests for FoxIO PR #288.

- HTTP version: HTTP/1.0 -> '10', HTTP/1.1 -> '11', HTTP/2 -> '20', HTTP/3 -> '30'
- Cookie-VALUES hash component sorts by NAME only
"""

import hashlib
import json
from pathlib import Path

import pytest

from ja4plus.fingerprinters.ja4h import _generate_ja4h_from_info, _http_version_to_str

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"
CAPTURE_PATH = VECTORS_DIR / "http2-with-cookies.pcapng"
EXPECTED_PATH = VECTORS_DIR / "http2-with-cookies.pcapng.json"


@pytest.mark.parametrize(
    "version,expected",
    [
        ("HTTP/1.0", "10"),
        ("HTTP/1.1", "11"),
        ("HTTP/2", "20"),
        ("HTTP/2.0", "20"),
        ("HTTP/3", "30"),
        ("HTTP/3.0", "30"),
        # Defensive: empty falls back to '11' (most common)
        ("", "11"),
    ],
)
def test_http_version_mapping(version, expected):
    assert _http_version_to_str(version) == expected


def _info(method="GET", version="HTTP/1.1", headers=None, cookies=None, referer="", language=""):
    return {
        "method": method,
        "path": "/",
        "version": version,
        "headers": headers or [],
        "cookies": cookies or {},
        "cookie_fields": list((cookies or {}).keys()),
        "cookie_values": list((cookies or {}).values()),
        "language": language,
        "referer": referer,
    }


def test_http_version_in_part_a_for_http2():
    fp = _generate_ja4h_from_info(_info(version="HTTP/2", headers=["Host"]))
    assert fp is not None
    # Part A: ge20...  ('ge' = method[:2] of 'get', '20' = HTTP/2)
    assert fp.startswith("ge20"), f"got {fp!r}"


def test_http_version_in_part_a_for_http3():
    fp = _generate_ja4h_from_info(_info(version="HTTP/3", headers=["Host"]))
    assert fp is not None
    assert fp.startswith("ge30"), f"got {fp!r}"


def test_http_version_in_part_a_for_http11():
    fp = _generate_ja4h_from_info(_info(version="HTTP/1.1", headers=["Host"]))
    assert fp is not None
    assert fp.startswith("ge11"), f"got {fp!r}"


def test_cookie_values_hash_sorts_by_name_only():
    """Same cookie names + same values, different INPUT order -> same hash."""
    fp1 = _generate_ja4h_from_info(
        _info(
            cookies={"alpha": "1", "bravo": "2", "charlie": "3"},
        )
    )
    fp2 = _generate_ja4h_from_info(
        _info(
            cookies={"charlie": "3", "alpha": "1", "bravo": "2"},
        )
    )
    assert fp1 == fp2

    # The sorted-by-name string is "alpha=1,bravo=2,charlie=3"
    expected_hash = hashlib.sha256(b"alpha=1,bravo=2,charlie=3").hexdigest()[:12]
    assert fp1.split("_")[-1] == expected_hash


def test_cookie_values_hash_input_form_is_name_value_pairs_sorted_by_name():
    """Verify the exact hash input string structure."""
    fp = _generate_ja4h_from_info(
        _info(
            cookies={"zeta": "z", "alpha": "a"},
        )
    )
    expected = hashlib.sha256(b"alpha=a,zeta=z").hexdigest()[:12]
    assert fp.split("_")[-1] == expected


def _reference_ja4h():
    """Return every JA4H value the FoxIO expected-output file holds, in file order.

    Returns:
        The list of `JA4H` values.

    Raises:
        FileNotFoundError: The expected-output file is absent.
        AssertionError: The expected-output file holds no JA4H value.
    """
    with open(EXPECTED_PATH) as handle:
        entries = json.load(handle)
    values = [entry["JA4H"] for entry in entries if "JA4H" in entry]
    # Without this check, an empty list compares equal to an empty produced list, and the
    # caller reports a pass on nothing. #115 exists to remove that defect.
    assert values, "{} holds no JA4H value".format(EXPECTED_PATH)
    return values


def _produced_ja4h():
    """Return every JA4H value the fingerprinter produces from the FoxIO capture."""
    from scapy.all import rdpcap

    from ja4plus.fingerprinters.ja4h import JA4HFingerprinter

    fingerprinter = JA4HFingerprinter()
    produced = []
    for packet in rdpcap(str(CAPTURE_PATH)):
        fingerprint = fingerprinter.process_packet(packet)
        if fingerprint:
            produced.append(fingerprint)
    return produced


def test_every_reference_value_of_the_foxio_capture_carries_the_version_code_20():
    """The FoxIO reference reads `20` as the version code of every request in the capture."""
    assert [value[2:4] for value in _reference_ja4h()] == ["20"] * 15


def test_the_foxio_capture_carries_no_cleartext_http_request():
    """Every HTTP request of `http2-with-cookies.pcapng` is inside a TLS record.

    The capture carries a Decryption Secrets Block, and the FoxIO reference reads the 15
    requests because it decrypts them. This test names the reason the comparison below
    fails, so that a reader does not look for the cause in the JA4H parser.
    """
    from scapy.all import Raw, rdpcap

    request_lines = []
    for packet in rdpcap(str(CAPTURE_PATH)):
        if packet.haslayer(Raw) and bytes(packet[Raw].load)[:4] in (b"GET ", b"POST", b"HTTP"):
            request_lines.append(bytes(packet[Raw].load)[:16])

    assert request_lines == []


@pytest.mark.xfail(
    strict=True,
    reason=(
        "issue #129: the reference decrypts the capture with the secrets it carries, and "
        "ja4plus reads no encrypted request."
    ),
)
def test_the_foxio_capture_produces_the_reference_ja4h_values():
    """`http2-with-cookies.pcapng` produces the JA4H values the FoxIO reference holds."""
    assert _produced_ja4h() == _reference_ja4h()
