"""The JA4H sorted raw form, measured against the FoxIO reference.

FoxIO publishes two raw keys for JA4H. `JA4H_ro` holds the wire order, and `JA4H_r` holds
the sorted order. The per-stream expected-output files under `tests/foxio_vectors/` hold
no `JA4H_r` value, and the per-packet files under `tests/foxio_vectors/wireshark_expected/`
hold 62 of them.

The form is `<part a>_<header names>_<sorted cookie names>_<sorted cookie pairs>`. The
header names hold the wire order in both raw forms, and the cookie order is the one thing
that separates the two. Both cookie lists sort by the cookie name.

The base value hashes the sorted cookie name string and the sorted cookie pair string. The
three fields of a `JA4H_r` value are therefore the pre-image of part b, part c and part d.

A request that carries no cookie ends after the header names and one underscore, which is
the shape `JA4H_ro` already carries. The Wireshark dissector writes two trailing
underscores for that request. #285 of `Crank-Git/ja4plus-go` holds that reference split,
and the maintainer rules it.

Verified against:
https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/test/testdata/http1-with-cookies.pcapng.json
(retrieved 2026-08-15) and the expected-output files under `tests/foxio_vectors/`.
"""

import hashlib
import json
from pathlib import Path

import pytest

from ja4plus.fingerprinters.ja4h import (
    JA4HFingerprinter,
    _generate_ja4h_from_info,
    _generate_ja4h_raw_from_info,
    _generate_ja4h_raw_sorted_from_info,
)

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"
WIRESHARK_DIR = VECTORS_DIR / "wireshark_expected"

# `http1-with-cookies.pcapng` is the one cleartext vector whose Wireshark records hold a
# `ja4.ja4h_r` value with a cookie. A record with no cookie carries the trailing underscore
# of #285, so it separates no sort order and this file reads none.
COOKIE_VECTOR = "http1-with-cookies.pcapng"
MANY_REQUEST_VECTOR = "http1.pcapng"


def _info(method="GET", version="HTTP/1.1", headers=None, cookie_pairs=None, language=""):
    """Return one http_info dict, with the cookies in the order given.

    A request that carries a cookie carries a Cookie header, so the header list holds that
    name. Field a3 reads the header list, and #219 records the reading.
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


def _wireshark_values(vector, key):
    """Return every value the FoxIO Wireshark expected-output file holds for one key.

    Args:
        vector: The file name of the capture.
        key: A field name of the dissector, such as `ja4.ja4h_r`.

    Returns:
        The values in frame order.
    """
    with open(WIRESHARK_DIR / "{}.json".format(vector)) as handle:
        records = json.load(handle)
    values = []
    for record in records:
        layers = record["_source"]["layers"]
        if key in layers:
            values.extend(layers[key])
    # An empty list compares equal to an empty produced list, so the caller would report a
    # pass on nothing.
    assert values, "{}.json holds no {} value".format(vector, key)
    return values


def _produced(vector):
    """Return every JA4H entry the fingerprinter reads from one capture, in order."""
    from scapy.all import rdpcap

    fingerprinter = JA4HFingerprinter()
    for packet in rdpcap(str(VECTORS_DIR / vector)):
        fingerprinter.process_packet(packet)
    return fingerprinter.get_fingerprints()


# ---------------------------------------------------------------------------
# The form
# ---------------------------------------------------------------------------


def test_the_sorted_raw_form_holds_the_header_names_in_wire_order():
    """The sort reaches the cookie lists, and it reaches no header name."""
    raw = _generate_ja4h_raw_sorted_from_info(_info(headers=["Host", "User-Agent", "Accept"]))
    assert raw == "ge11nn030000_Host,User-Agent,Accept_"


def test_the_sorted_raw_form_sorts_the_cookie_names():
    """The wire order is `zeta,alpha`, and the sorted order is `alpha,zeta`."""
    raw = _generate_ja4h_raw_sorted_from_info(
        _info(headers=["Host"], cookie_pairs=[("zeta", "z"), ("alpha", "a")])
    )
    assert raw == "ge11cn010000_Host_alpha,zeta_alpha=a,zeta=z"


def test_the_sorted_raw_form_sorts_the_cookie_pairs_by_the_cookie_name():
    """A sort of the whole pair string reads the value, and this sort reads the name alone.

    `b=1` sorts before `b1=0` on the pair string, because `=` is 0x3D and `1` is 0x31. It
    sorts after `b1=0` on the name, because `b` is a prefix of `b1`.
    """
    raw = _generate_ja4h_raw_sorted_from_info(
        _info(headers=["Host"], cookie_pairs=[("b1", "0"), ("b", "1")])
    )
    assert raw.endswith("_b,b1_b=1,b1=0")


def test_the_sorted_raw_form_keeps_the_wire_order_of_a_repeated_cookie_name():
    """The sort is stable, so two cookies of one name keep the order the request holds."""
    raw = _generate_ja4h_raw_sorted_from_info(
        _info(headers=["Host"], cookie_pairs=[("b", "2"), ("a", "1"), ("b", "0")])
    )
    assert raw.endswith("_a,b,b_a=1,b=2,b=0")


def test_the_sorted_raw_form_drops_the_cookie_header_and_the_referer_header():
    raw = _generate_ja4h_raw_sorted_from_info(
        _info(headers=["Host", "Cookie", "Referer", "Accept"], cookie_pairs=[("a", "1")])
    )
    assert raw.split("_")[1] == "Host,Accept"


def test_the_sorted_raw_form_drops_an_http2_pseudo_header():
    raw = _generate_ja4h_raw_sorted_from_info(
        _info(version="HTTP/2", headers=[":method", ":path", "user-agent"])
    )
    assert raw.split("_")[1] == "user-agent"


def test_the_sorted_raw_form_ends_after_the_header_names_when_no_cookie_is_present():
    """A request with no cookie carries no cookie section, and one trailing underscore.

    The FoxIO Python reference appends the two cookie fields only when the request holds a
    cookie. The Wireshark dissector writes two trailing underscores. #285 of
    `Crank-Git/ja4plus-go` holds that reference split, and the maintainer rules it.
    """
    raw = _generate_ja4h_raw_sorted_from_info(_info(headers=["Host"]))
    assert raw.endswith("_Host_")
    assert raw.count("_") == 2


def test_the_two_raw_forms_end_the_same_way_when_no_cookie_is_present():
    """One ruling on #285 moves both raw forms, so the two agree on the request with none."""
    info = _info(headers=["Host", "Accept"])
    assert _generate_ja4h_raw_sorted_from_info(info) == _generate_ja4h_raw_from_info(info)


def test_the_sorted_raw_form_reports_nothing_for_an_empty_info():
    assert _generate_ja4h_raw_sorted_from_info(None) is None


# ---------------------------------------------------------------------------
# The FoxIO vectors
# ---------------------------------------------------------------------------


def test_the_cookie_vector_produces_the_reference_sorted_raw_value():
    """`http1-with-cookies.pcapng` produces the `ja4.ja4h_r` value the dissector holds."""
    produced = [entry["raw"] for entry in _produced(COOKIE_VECTOR)]
    assert produced == _wireshark_values(COOKIE_VECTOR, "ja4.ja4h_r")


def test_the_reference_sorted_raw_value_holds_a_cookie_order_the_wire_order_does_not():
    """The comparison above separates two sort orders, so it is not a comparison of one.

    The dissector writes `tasty_cookie,yummy_cookie` for `ja4.ja4h_r` and
    `yummy_cookie,tasty_cookie` for `ja4.ja4h_ro` on this frame.
    """
    sorted_value = _wireshark_values(COOKIE_VECTOR, "ja4.ja4h_r")[0]
    wire_value = _wireshark_values(COOKIE_VECTOR, "ja4.ja4h_ro")[0]
    assert sorted_value != wire_value
    assert "_tasty_cookie,yummy_cookie_" in sorted_value
    assert "_yummy_cookie,tasty_cookie_" in wire_value


@pytest.mark.parametrize(
    "cookie_pairs",
    [
        [("zeta", "z"), ("alpha", "a")],
        [("tasty_cookie", "strawberry"), ("yummy_cookie", "choco")],
        [("b1", "0"), ("b", "1")],
        [("a", "1"), ("a", "2")],
    ],
)
def test_the_sorted_raw_form_is_the_pre_image_of_the_hashed_value(cookie_pairs):
    """The two cookie fields of the sorted raw form hash to part c and to part d.

    A raw form that hashes to another value explains no hash. The parameter set holds a
    cookie name that carries an underscore, because the separator of the form is an
    underscore too.
    """
    info = _info(headers=["Host", "User-Agent"], cookie_pairs=cookie_pairs)
    raw = _generate_ja4h_raw_sorted_from_info(info)
    hashed = _generate_ja4h_from_info(info).split("_")

    ordered = sorted(cookie_pairs, key=lambda pair: pair[0])
    names = ",".join(name for name, _ in ordered)
    pairs = ",".join("{}={}".format(name, value) for name, value in ordered)
    assert raw == "{}_Host,User-Agent_{}_{}".format(hashed[0], names, pairs)

    assert hashlib.sha256("Host,User-Agent".encode()).hexdigest()[:12] == hashed[1]
    assert hashlib.sha256(names.encode()).hexdigest()[:12] == hashed[2]
    assert hashlib.sha256(pairs.encode()).hexdigest()[:12] == hashed[3]


@pytest.mark.parametrize("vector", [COOKIE_VECTOR, MANY_REQUEST_VECTOR])
def test_the_two_raw_forms_hold_one_character_multiset(vector):
    """The cookie order is the one thing that separates the two forms.

    A sorted form that drops a field, moves a header name or rewrites a value holds
    characters the wire-order form does not. The comparison reads no field boundary, so no
    cookie name that carries an underscore reaches it.
    """
    entries = _produced(vector)
    assert entries, "{} produces no JA4H value".format(vector)
    for entry in entries:
        assert sorted(entry["raw"]) == sorted(entry["raw_original_order"])
        assert entry["raw"].split("_")[0] == entry["fingerprint"].split("_")[0]


@pytest.mark.parametrize("vector", [COOKIE_VECTOR, MANY_REQUEST_VECTOR])
def test_the_wire_order_raw_form_keeps_the_value_it_had(vector):
    """The sorted form adds a value, and it moves no `JA4H_ro` value."""
    with open(VECTORS_DIR / "{}.json".format(vector)) as handle:
        reference = [entry["JA4H_ro"] for entry in json.load(handle) if "JA4H_ro" in entry]
    assert [entry["raw_original_order"] for entry in _produced(vector)] == reference


# ---------------------------------------------------------------------------
# The published field
# ---------------------------------------------------------------------------


def test_the_fingerprinter_reports_the_sorted_raw_value_of_the_last_request():
    """The processor reads `last_raw`, and `ja4plus/processor.py` writes it into `raw`."""
    from scapy.all import rdpcap

    fingerprinter = JA4HFingerprinter()
    for packet in rdpcap(str(VECTORS_DIR / COOKIE_VECTOR)):
        fingerprinter.process_packet(packet)
    assert fingerprinter.last_raw == _wireshark_values(COOKIE_VECTOR, "ja4.ja4h_r")[-1]


def test_the_fingerprinter_reports_no_sorted_raw_value_before_it_reads_a_request():
    assert JA4HFingerprinter().last_raw is None


def test_a_reset_drops_the_sorted_raw_value():
    """A reset returns the fingerprinter to the state a new one holds."""
    from scapy.all import rdpcap

    fingerprinter = JA4HFingerprinter()
    for packet in rdpcap(str(VECTORS_DIR / COOKIE_VECTOR)):
        fingerprinter.process_packet(packet)
    assert fingerprinter.last_raw is not None
    fingerprinter.reset()
    assert fingerprinter.last_raw is None


def test_every_entry_carries_both_raw_forms():
    """A reader of one entry reads the sorted form and the wire-order form together."""
    entries = _produced(MANY_REQUEST_VECTOR)
    assert len(entries) == 56
    for entry in entries:
        assert entry["raw"]
        assert entry["raw_original_order"]
