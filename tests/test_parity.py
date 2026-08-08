"""Parity tests for the interface `ja4plus-go` shares with `ja4plus`.

The port publishes `ComputeJA4XFromPEM`, `ComputeJA4XFromDER`, the `Raw` and
`RawOriginalOrder` result fields, the ten command-line type names, and one shard-key
format. A test here compares a value the shared FoxIO vector holds. A test that asserts
only that a name exists passes on two implementations that disagree on every byte, so no
test here does that.

No test builds, runs or imports the port. The gate is the shared vector set.

Every expected value comes from `tests/foxio_vectors/tls-alpn-h2.pcap.json`.
`tests/foxio_vectors/NOTICE` records that file as a copy of
`python/test/testdata/tls-alpn-h2.pcap.json` at FoxIO commit
27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8.
"""

import io
import json
import os
from unittest.mock import patch

VECTOR_DIR = os.path.join(os.path.dirname(__file__), "foxio_vectors")

# One vector carries every value these tests compare: JA4, both JA4 raw forms, the JA4
# original-order hash, JA4S, JA4S_r and two JA4X values.
VECTOR_CAPTURE = os.path.join(VECTOR_DIR, "tls-alpn-h2.pcap")
VECTOR_EXPECTED = os.path.join(VECTOR_DIR, "tls-alpn-h2.pcap.json")

# The ten type names the command-line program accepts. The port ships the same list.
TYPE_NAMES = "ja4,ja4s,ja4h,ja4l,ja4t,ja4ts,ja4x,ja4ssh,ja4d,ja4d6"


def reference_stream():
    """Return the first stream of the expected-output file of the vector.

    Returns:
        The record, as a dictionary of method key to expected value.
    """
    with open(VECTOR_EXPECTED) as handle:
        return json.load(handle)[0]


def run_cli(*argv):
    """Return the standard output, the standard error and the exit code of the program.

    Args:
        argv: The command-line arguments, without the program name.

    Returns:
        A (stdout, stderr, exit_code) triple. The exit code is 0 when `main` returns.
    """
    from ja4plus.cli import main

    captured_out = io.StringIO()
    captured_err = io.StringIO()
    exit_code = 0
    with (
        patch("sys.argv", ["ja4plus"] + list(argv)),
        patch("sys.stdout", captured_out),
        patch("sys.stderr", captured_err),
    ):
        try:
            main()
        except SystemExit as error:
            exit_code = error.code if error.code is not None else 0
    return captured_out.getvalue(), captured_err.getvalue(), exit_code


def fingerprints_of_capture(fingerprinter):
    """Return the fingerprint entries one fingerprinter produces for the vector.

    Args:
        fingerprinter: A fingerprinter instance.

    Returns:
        The list of entries the fingerprinter collected.
    """
    from scapy.all import rdpcap

    for packet in rdpcap(VECTOR_CAPTURE):
        fingerprinter.process_packet(packet)
    return fingerprinter.get_fingerprints()


def test_the_command_line_program_accepts_every_type_name_and_reports_two_reference_values():
    """The program accepts the ten type names, and JA4 and JA4S give the reference value.

    The vector carries TLS alone, so `ja4h`, `ja4ssh`, `ja4d` and `ja4d6` produce nothing
    on it. The program rejects an unknown type name with the exit code 1, so an exit code
    of 0 proves that it accepts all ten names.
    """
    expected = reference_stream()
    out, err, code = run_cli("--format", "json", "--types", TYPE_NAMES, "analyze", VECTOR_CAPTURE)
    assert code == 0, err

    produced = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        produced.setdefault(record["type"], []).append(record["fingerprint"])

    assert expected["JA4.1"] in produced["ja4"]
    assert expected["JA4S"] in produced["ja4s"]

    # The exit code above proves that the program accepts the ten names only while the
    # program still rejects a name outside the list.
    _, _, unknown_code = run_cli("--types", "ja4nope", "analyze", VECTOR_CAPTURE)
    assert unknown_code == 1


def test_the_ja4_raw_forms_match_the_reference():
    """The JA4 result carries the four values the reference publishes for the stream."""
    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

    expected = reference_stream()
    fingerprinter = JA4Fingerprinter()
    entries = fingerprints_of_capture(fingerprinter)
    assert len(entries) == 1

    entry = entries[0]
    assert entry["fingerprint"] == expected["JA4.1"]
    assert entry["raw"] == expected["JA4_r.1"]
    assert entry["raw_original_order"] == expected["JA4_ro.1"]
    assert entry["fingerprint_original_order"] == expected["JA4_o.1"]
    assert fingerprinter.last_raw == expected["JA4_r.1"]
    assert fingerprinter.last_raw_original_order == expected["JA4_ro.1"]


def test_the_ja4s_raw_forms_match_the_reference():
    """Both JA4S raw keys hold the extensions in the reference order."""
    from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

    expected = reference_stream()
    fingerprinter = JA4SFingerprinter()
    entries = fingerprints_of_capture(fingerprinter)
    assert len(entries) == 1

    entry = entries[0]
    assert entry["fingerprint"] == expected["JA4S"]
    # The reference `JA4S_r` holds the extensions in wire order. JA4S sorts no list, so
    # both raw keys hold that one value. #108 records the reading.
    assert entry["raw"] == expected["JA4S_r"]
    assert entry["raw_original_order"] == expected["JA4S_r"]
    assert fingerprinter.last_raw == expected["JA4S_r"]
    assert fingerprinter.last_raw_original_order == expected["JA4S_r"]
    # FoxIO publishes no `JA4S_o` key, so no vector validates this value. JA4S hashes the
    # extensions in wire order, so the original-order hash equals the fingerprint.
    # `docs/implementation_notes.md` records the reading.
    assert entry["fingerprint_original_order"] == entry["fingerprint"]


def test_the_ja4x_helpers_produce_the_reference_value():
    """`compute_ja4x_from_der` and `compute_ja4x_from_pem` give the reference JA4X value."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    from ja4plus import compute_ja4x_from_der, compute_ja4x_from_pem
    from ja4plus.fingerprinters.ja4x import JA4XFingerprinter

    expected = reference_stream()
    certificates = []

    class RecordingFingerprinter(JA4XFingerprinter):
        """Collect the certificate bytes the scan reads, then fingerprint them.

        The scan calls `read_certificate`, because #267 made that method the reader of
        one certificate. `fingerprint_certificate` calls it too and returns the value
        alone.
        """

        def read_certificate(self, cert_data):
            certificates.append(cert_data)
            return super().read_certificate(cert_data)

    fingerprints_of_capture(RecordingFingerprinter())
    assert certificates, "the vector holds a Certificate message"

    der = certificates[-1]
    pem = x509.load_der_x509_certificate(der).public_bytes(Encoding.PEM)
    assert compute_ja4x_from_der(der) == expected["JA4X.2"]
    assert compute_ja4x_from_pem(pem) == expected["JA4X.2"]


def test_compute_ja4x_from_pem_returns_none_for_text_that_is_not_a_certificate():
    """A caller that passes text which is not a certificate gets None, not an exception."""
    from ja4plus import compute_ja4x_from_pem

    assert compute_ja4x_from_pem("-----not a real PEM-----") is None


def test_the_shard_key_matches_the_port_format():
    """The shard key reads `<protocol>:<address>:<port>-><address>:<port>`."""
    from scapy.all import IP, TCP, UDP

    from ja4plus.processor import Processor

    processor = Processor()
    # The port formats the key with `"%s:%s:%d->%s:%d"`. A shard key that reads any
    # other way sends one connection to two shards when the two programs run together.
    forward = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=44100, dport=443)
    assert processor.get_shard_key(forward) == "tcp:10.0.0.1:44100->10.0.0.2:443"

    reverse = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=443, dport=44100)
    assert processor.get_shard_key(reverse) == "tcp:10.0.0.1:44100->10.0.0.2:443"

    datagram = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=51000, dport=443)
    assert processor.get_shard_key(datagram) == "udp:10.0.0.1:51000->10.0.0.2:443"
