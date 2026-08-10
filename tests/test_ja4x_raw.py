"""JA4X publishes a raw form, and that form is `JA4X_r`.

R11 of `docs/specs/foxio/JA4X.md` states the rule. `rust/ja4x/src/lib.rs` writes
`let ja4x_r = with_raw.then(|| parts.join("_"));`, and `wireshark/source/packet-ja4.c:1726`
registers the field `ja4.ja4x_r`. The user decided on 2026-08-08 that this project writes
the same value, and #267 holds the ruling.

No expected-output file under `tests/foxio_vectors/` holds a `JA4X_r` key, so the raw form
reaches its reference value through the hash. `hash12` of each part of the raw form is the
matching part of the JA4X value, and the FoxIO Rust snapshot holds that value.
`tests/test_foxio_rust_parity.py` runs the same comparison over 43 snapshot values.

Every expected value here comes from a file under `tests/foxio_vectors/`.
`tests/foxio_vectors/NOTICE` records the FoxIO commit each file came from.
"""

import hashlib
import os

from ja4plus.fingerprinters.ja4x import generate_ja4x, generate_ja4x_raw

VECTOR_DIR = os.path.join(os.path.dirname(__file__), "foxio_vectors")

# The capture holds two certificates on one stream, and
# `tests/foxio_vectors/rust_expected/ja4__insta@https-connect.pcap.snap` holds the JA4X
# value of each. A capture with one certificate proves no order.
CERTIFICATE_CAPTURE = os.path.join(VECTOR_DIR, "https-connect.pcap")

# The raw form of the first certificate of `https-connect.pcap`, measured on 2026-08-08.
# The FoxIO Rust snapshot holds `7d5dbb3783b4_2bab15409345_5e17a2514980` for it, and
# `test_each_part_of_the_raw_form_hashes_to_the_fingerprint_part` proves the two agree.
FIRST_RAW = (
    "550406,55040a,55040b,550403"
    "_550406,550408,550407,55040a,550403"
    "_551d23,551d0e,551d11,551d0f,551d25,551d1f,551d20,2b06010505070101,551d13"
)

# The zero sentinel of R8. The hashed form writes it for an empty list, and the raw form
# writes an empty part instead.
ZERO_SENTINEL = "000000000000"


def ja4x_results(capture_path):
    """Return the JA4X result entries of one capture.

    Args:
        capture_path: The path of a capture file.

    Returns:
        The list of entries the JA4X fingerprinter collected.
    """
    from scapy.all import rdpcap

    from ja4plus.fingerprinters.ja4x import JA4XFingerprinter

    fingerprinter = JA4XFingerprinter()
    for packet in rdpcap(capture_path):
        fingerprinter.process_packet(packet)
    return fingerprinter.get_fingerprints()


def hash12(part):
    """Return the JA4X hash of one unhashed list.

    Args:
        part: One comma-separated list of hex object identifiers.

    Returns:
        The first 12 characters of the SHA-256 of the list. R8 returns the zero sentinel
        for an empty list.
    """
    if not part:
        return ZERO_SENTINEL
    return hashlib.sha256(part.encode()).hexdigest()[:12]


def test_the_raw_form_joins_the_three_unhashed_lists_with_an_underscore():
    """`generate_ja4x_raw` returns the issuer list, the subject list and the extensions."""
    cert_info = {
        "issuer_rdns": ["550403", "550406"],
        "subject_rdns": ["55040a"],
        "extensions": ["551d0f", "551d25"],
    }
    assert generate_ja4x_raw(cert_info) == "550403,550406_55040a_551d0f,551d25"


def test_the_raw_form_writes_an_empty_part_for_an_empty_list():
    """R8 gives the zero sentinel to the hashed form alone.

    `rust/ja4x/src/lib.rs` builds the raw form with `parts.join("_")`, and `hash12` runs
    on the hashed form alone. An empty list therefore reaches the raw form as an empty
    part, and the zero sentinel reaches no raw form.
    """
    cert_info = {
        "issuer_rdns": [],
        "subject_rdns": ["55040a"],
        "extensions": [],
    }
    raw = generate_ja4x_raw(cert_info)
    assert raw == "_55040a_"
    assert ZERO_SENTINEL not in raw
    assert generate_ja4x(cert_info) == "{}_b757977db3a9_{}".format(ZERO_SENTINEL, ZERO_SENTINEL)


def test_the_raw_form_reports_nothing_for_a_certificate_it_cannot_read():
    """A reader that produces no certificate details produces no raw form."""
    assert generate_ja4x_raw(None) is None
    assert generate_ja4x_raw({}) is None


def test_the_raw_form_returns_nothing_for_a_list_that_holds_no_string():
    """A reader that cannot join a list returns nothing, and it raises nothing."""
    assert generate_ja4x_raw({"issuer_rdns": [1], "subject_rdns": [], "extensions": []}) is None


def test_the_raw_form_of_the_first_certificate_equals_the_measured_lists():
    """The first certificate of `https-connect.pcap` produces the measured raw form."""
    results = ja4x_results(CERTIFICATE_CAPTURE)
    assert len(results) == 2
    assert results[0]["raw"] == FIRST_RAW


def test_each_part_of_the_raw_form_hashes_to_the_fingerprint_part():
    """The raw form is the preimage of the JA4X value, part by part.

    `rust/ja4x/src/lib.rs` builds one list of three parts, hashes each part for `ja4x`
    and joins the same three parts for `ja4x_r`. A raw form that joins another character,
    or that holds another list order, hashes to another value and this check fails.
    """
    results = ja4x_results(CERTIFICATE_CAPTURE)
    assert len(results) == 2
    for result in results:
        parts = result["raw"].split("_")
        assert len(parts) == 3
        assert "_".join(hash12(part) for part in parts) == result["fingerprint"]


def test_the_first_certificate_reproduces_the_foxio_rust_snapshot_value():
    """The measured raw form hashes to the value the FoxIO Rust snapshot holds.

    `tests/foxio_vectors/rust_expected/ja4__insta@https-connect.pcap.snap` holds
    `ja4x: 7d5dbb3783b4_2bab15409345_5e17a2514980` for the first certificate.
    """
    hashed = "_".join(hash12(part) for part in FIRST_RAW.split("_"))
    assert hashed == "7d5dbb3783b4_2bab15409345_5e17a2514980"


def test_the_two_raw_keys_of_one_ja4x_result_hold_one_value():
    """R10 sorts no list, so the wire form and the original-order form are one value."""
    results = ja4x_results(CERTIFICATE_CAPTURE)
    for result in results:
        assert result["raw"]
        assert result["raw"] == result["raw_original_order"]


def test_the_last_raw_attribute_holds_the_raw_form_of_the_last_value():
    """`Processor.process_packet` reads `last_raw`, so the fingerprinter writes it."""
    from scapy.all import rdpcap

    from ja4plus.fingerprinters.ja4x import JA4XFingerprinter

    fingerprinter = JA4XFingerprinter()
    assert fingerprinter.last_raw is None
    assert fingerprinter.last_raw_original_order is None
    for packet in rdpcap(CERTIFICATE_CAPTURE):
        fingerprinter.process_packet(packet)
    results = fingerprinter.get_fingerprints()
    assert fingerprinter.last_raw == results[-1]["raw"]
    assert fingerprinter.last_raw == fingerprinter.last_raw_original_order


def test_reset_drops_the_raw_form_of_the_last_value():
    """A reader that resets the fingerprinter reads no raw form of the capture before."""
    from scapy.all import rdpcap

    from ja4plus.fingerprinters.ja4x import JA4XFingerprinter

    fingerprinter = JA4XFingerprinter()
    for packet in rdpcap(CERTIFICATE_CAPTURE):
        fingerprinter.process_packet(packet)
    assert fingerprinter.last_raw is not None
    fingerprinter.reset()
    assert fingerprinter.last_raw is None
    assert fingerprinter.last_raw_original_order is None


def test_the_processor_pairs_the_raw_form_with_the_fingerprint_it_reports():
    """The `raw` key of a processor result holds the raw form of the value beside it.

    One packet of `https-connect.pcap` carries both certificates, and `process_packet`
    reports the last value of the packet. The raw form of the same result therefore
    names the same certificate, and this check hashes it to prove that pairing.
    """
    from scapy.all import rdpcap

    from ja4plus.processor import Processor

    processor = Processor()
    results = []
    for packet in rdpcap(CERTIFICATE_CAPTURE):
        for result in processor.process_packet(packet):
            if result["type"] == "ja4x":
                results.append(result)
    assert len(results) == 1
    [result] = results
    assert result["raw"] == result["raw_original_order"]
    assert "_".join(hash12(part) for part in result["raw"].split("_")) == result["fingerprint"]
