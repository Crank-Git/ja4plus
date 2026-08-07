"""The JA4 and JA4S fingerprinters expose the original-order hashed value.

`JA4_o` is the hashed form of the original-order raw value. `JA4_ro` is that raw
value unhashed. The relationship matches the one between `JA4` and `JA4_r`.

The FoxIO expected-output file `tests/foxio_vectors/tls12.pcap.json` names the JA4
value. FoxIO publishes no `JA4S_o` key, so each JA4S test derives the value it
expects from the published `JA4S_r` value.
"""

import hashlib
import json
import os

import pytest

JA4_PCAP = "tests/foxio_vectors/tls12.pcap"
JA4_EXPECTED = "tests/foxio_vectors/tls12.pcap.json"
JA4S_PCAP = "tests/foxio_vectors/latest.pcapng"
JA4S_EXPECTED = "tests/foxio_vectors/latest.pcapng.json"
SNI_ONLY_PCAP = "tests/foxio_vectors/https3-301-get.pcap"
SNI_ONLY_EXPECTED = "tests/foxio_vectors/https3-301-get.pcap.json"


pytestmark = pytest.mark.skipif(
    not all(
        os.path.exists(path)
        for path in (
            JA4_PCAP,
            JA4_EXPECTED,
            JA4S_PCAP,
            JA4S_EXPECTED,
            SNI_ONLY_PCAP,
            SNI_ONLY_EXPECTED,
        )
    ),
    reason="FoxIO vectors not available (download to tests/foxio_vectors/)",
)


def _first_expected(path, key):
    """Return the value of one key, from the first record that holds the key."""
    with open(path) as handle:
        records = json.load(handle)
    for record in records:
        if key in record:
            return record[key]
    raise AssertionError(f"{path} holds no {key} key")


def _run(fingerprinter, pcap_path):
    """Run one fingerprinter over one capture and return its result entries."""
    from scapy.all import rdpcap

    for packet in rdpcap(pcap_path):
        fingerprinter.process_packet(packet)
    return fingerprinter.get_fingerprints()


def _hash12(value):
    """Return the first 12 characters of the SHA-256 hexadecimal digest."""
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def test_ja4_emits_the_original_order_value_of_the_foxio_vector():
    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    fingerprinter = JA4Fingerprinter()
    entries = _run(fingerprinter, JA4_PCAP)

    assert len(entries) == 1
    expected = _first_expected(JA4_EXPECTED, "JA4_o.1")
    assert expected == "t13d1715h2_5b234860e130_014157ec0da2"
    assert entries[0]["fingerprint_original_order"] == expected
    assert fingerprinter.last_fingerprint_original_order == expected


def test_ja4_original_order_value_hashes_the_original_order_raw_value():
    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    entries = _run(JA4Fingerprinter(), JA4_PCAP)
    raw_original_order = _first_expected(JA4_EXPECTED, "JA4_ro.1")

    part_a, ciphers, extensions, signature_algorithms = raw_original_order.split("_")
    expected = "{}_{}_{}".format(
        part_a,
        _hash12(ciphers),
        _hash12(f"{extensions}_{signature_algorithms}"),
    )
    assert entries[0]["fingerprint_original_order"] == expected


def test_ja4_gives_the_zero_marker_when_sni_is_the_only_extension():
    """The vector `https3-301-get.pcap` names the value the reference computes.

    The client hello carries SNI as its only extension. The sorted extension list is
    therefore empty, and FoxIO sets both extension hashes to the zero marker. #132
    holds the measurement.
    """
    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    entries = _run(JA4Fingerprinter(), SNI_ONLY_PCAP)

    assert len(entries) == 1
    expected = _first_expected(SNI_ONLY_EXPECTED, "JA4_o.1")
    assert expected == "t10d230100_ce175d585f73_000000000000"
    assert entries[0]["fingerprint_original_order"] == expected


def test_ja4_keeps_sni_in_the_raw_value_when_sni_is_the_only_extension():
    """FoxIO zeroes the `JA4_o` hash and still shows `0000` in `JA4_ro`."""
    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    entries = _run(JA4Fingerprinter(), SNI_ONLY_PCAP)

    expected = _first_expected(SNI_ONLY_EXPECTED, "JA4_ro.1")
    assert expected.endswith("_0000")
    assert entries[0]["raw_original_order"] == expected


def test_ja4_reset_clears_the_original_order_value():
    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    fingerprinter = JA4Fingerprinter()
    _run(fingerprinter, JA4_PCAP)
    assert fingerprinter.last_fingerprint_original_order is not None

    fingerprinter.reset()
    assert fingerprinter.last_fingerprint_original_order is None


def test_ja4s_emits_the_original_order_value_of_the_foxio_vector():
    from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

    fingerprinter = JA4SFingerprinter()
    entries = _run(fingerprinter, JA4S_PCAP)

    assert entries
    raw = _first_expected(JA4S_EXPECTED, "JA4S_r")
    part_a, cipher, extensions = raw.split("_")
    expected = f"{part_a}_{cipher}_{_hash12(extensions)}"

    produced = [entry["fingerprint_original_order"] for entry in entries]
    assert expected in produced
    assert fingerprinter.last_fingerprint_original_order is not None


def test_ja4s_reset_clears_the_original_order_value():
    from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

    fingerprinter = JA4SFingerprinter()
    _run(fingerprinter, JA4S_PCAP)
    assert fingerprinter.last_fingerprint_original_order is not None

    fingerprinter.reset()
    assert fingerprinter.last_fingerprint_original_order is None
