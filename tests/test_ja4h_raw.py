"""The JA4H raw form, measured against the FoxIO reference.

FoxIO publishes one raw key for JA4H, `JA4H_ro`. It holds the wire order of the header
names, of the cookie names, and of the cookie name-and-value pairs. FoxIO publishes no
`JA4H_r` key, so this project computes no sorted JA4H raw form.

The form is `<part a>_<header names>_<cookie names>_<cookie pairs>`. A request that
carries no cookie ends after the header names and one underscore.

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4h.py (retrieved
2026-08-07) and the expected-output files under `tests/foxio_vectors/`.
"""

import json
from pathlib import Path

import pytest

from ja4plus.fingerprinters.ja4h import (
    JA4HFingerprinter,
    _generate_ja4h_raw_from_info,
)

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"

# Two cleartext HTTP vectors. `http2-with-cookies.pcapng` and
# `chrome-cloudflare-quic-with-secrets.pcapng` carry a Decryption Secrets Block, and
# ja4plus decrypts nothing, so #129 owns them. `http-empty-useragent.pcap` produces no
# JA4H value at all, which #35 owns.
COOKIE_VECTOR = "http1-with-cookies.pcapng"
MANY_REQUEST_VECTOR = "http1.pcapng"


def _info(method="GET", version="HTTP/1.1", headers=None, cookie_pairs=None, language=""):
    """Return one http_info dict, with the cookies in the order given.

    A request that carries a cookie carries a Cookie header, so the header list holds
    that name. Field a3 reads the header list, and #219 records the reading.
    """
    cookie_pairs = cookie_pairs or []
    header_names = list(headers or [])
    if cookie_pairs:
        header_names.append("Cookie")
    return {
        "method": method,
        "path": "/",
        "version": version,
        "headers": header_names,
        "cookies": dict(cookie_pairs),
        "cookie_fields": [name for name, _ in cookie_pairs],
        "cookie_values": [value for _, value in cookie_pairs],
        "language": language,
        "referer": "",
    }


def _reference_values(vector, key):
    """Return every value the FoxIO expected-output file holds for one key, in order."""
    with open(VECTORS_DIR / "{}.json".format(vector)) as handle:
        entries = json.load(handle)
    values = [entry[key] for entry in entries if key in entry]
    # An empty list compares equal to an empty produced list, so the caller would report
    # a pass on nothing.
    assert values, "{}.json holds no {} value".format(vector, key)
    return values


def _produced_raw(vector):
    """Return every JA4H raw original-order value the fingerprinter reads from a capture."""
    from scapy.all import rdpcap

    fingerprinter = JA4HFingerprinter()
    for packet in rdpcap(str(VECTORS_DIR / vector)):
        fingerprinter.process_packet(packet)
    return [entry["raw_original_order"] for entry in fingerprinter.get_fingerprints()]


# ---------------------------------------------------------------------------
# The form
# ---------------------------------------------------------------------------


def test_the_raw_form_holds_the_header_names_in_wire_order():
    raw = _generate_ja4h_raw_from_info(_info(headers=["Host", "User-Agent", "Accept"]))
    assert raw == "ge11nn030000_Host,User-Agent,Accept_"


def test_the_raw_form_ends_after_the_header_names_when_no_cookie_is_present():
    """A request with no cookie carries no cookie section, and one trailing underscore.

    `http1.pcapng.json` gives
    `po11nn050000_Host,Accept,User-Agent,Content-Type,Content-Length_` for such a request.
    """
    raw = _generate_ja4h_raw_from_info(_info(headers=["Host"]))
    assert raw.endswith("_Host_")
    assert raw.count("_") == 2


def test_the_raw_form_drops_the_cookie_header_and_the_referer_header():
    raw = _generate_ja4h_raw_from_info(
        _info(headers=["Host", "Cookie", "Referer", "Accept"], cookie_pairs=[("a", "1")])
    )
    assert raw.split("_")[1] == "Host,Accept"


def test_the_raw_form_drops_an_http2_pseudo_header():
    """The reference lists no `:method` name.

    `latest.pcapng.json` gives `ge20cn13enus_upgrade-insecure-requests,user-agent,...`.
    """
    raw = _generate_ja4h_raw_from_info(
        _info(version="HTTP/2", headers=[":method", ":path", "user-agent"])
    )
    assert raw.split("_")[1] == "user-agent"


def test_the_raw_form_holds_the_cookie_names_in_wire_order():
    """The hashed form sorts the cookie names, and the raw original-order form does not.

    `http1-with-cookies.pcapng.json` gives `yummy_cookie,tasty_cookie`, which is not
    sorted order.
    """
    raw = _generate_ja4h_raw_from_info(
        _info(headers=["Host"], cookie_pairs=[("zeta", "z"), ("alpha", "a")])
    )
    assert raw.endswith("_zeta,alpha_zeta=z,alpha=a")


def test_the_raw_form_holds_one_name_and_value_pair_for_each_cookie():
    raw = _generate_ja4h_raw_from_info(
        _info(headers=["Host"], cookie_pairs=[("a", "1"), ("b", "2")])
    )
    assert raw == "ge11cn010000_Host_a,b_a=1,b=2"


def test_the_raw_form_keeps_a_repeated_cookie_name():
    """Two cookies of one name are two entries on the wire, and the raw form holds both."""
    raw = _generate_ja4h_raw_from_info(
        _info(headers=["Host"], cookie_pairs=[("a", "1"), ("a", "2")])
    )
    assert raw.endswith("_a,a_a=1,a=2")


def test_the_raw_form_reports_nothing_for_an_empty_info():
    assert _generate_ja4h_raw_from_info(None) is None


# ---------------------------------------------------------------------------
# The FoxIO vectors
# ---------------------------------------------------------------------------


def test_the_cookie_vector_produces_the_reference_raw_value():
    """`http1-with-cookies.pcapng` produces the `JA4H_ro` value the reference holds."""
    assert _produced_raw(COOKIE_VECTOR) == _reference_values(COOKIE_VECTOR, "JA4H_ro")


def test_the_many_request_vector_produces_every_reference_raw_value():
    """`http1.pcapng` produces the 56 `JA4H_ro` values the reference holds, in order."""
    assert _produced_raw(MANY_REQUEST_VECTOR) == _reference_values(MANY_REQUEST_VECTOR, "JA4H_ro")


def test_the_fingerprinter_reports_the_raw_value_of_the_last_request():
    """The processor and the command-line program read `last_raw_original_order`."""
    from scapy.all import rdpcap

    fingerprinter = JA4HFingerprinter()
    for packet in rdpcap(str(VECTORS_DIR / COOKIE_VECTOR)):
        fingerprinter.process_packet(packet)
    assert fingerprinter.last_raw_original_order == _reference_values(COOKIE_VECTOR, "JA4H_ro")[-1]


def test_the_fingerprinter_reports_no_raw_value_before_it_reads_a_request():
    assert JA4HFingerprinter().last_raw_original_order is None


@pytest.mark.parametrize("vector", [COOKIE_VECTOR, MANY_REQUEST_VECTOR])
def test_the_raw_value_and_the_hashed_value_share_one_part_a(vector):
    """The raw form explains the hash, so the two forms hold one first section."""
    from scapy.all import rdpcap

    fingerprinter = JA4HFingerprinter()
    for packet in rdpcap(str(VECTORS_DIR / vector)):
        fingerprinter.process_packet(packet)
    for entry in fingerprinter.get_fingerprints():
        assert entry["raw_original_order"].split("_")[0] == entry["fingerprint"].split("_")[0]
