"""Measure the three X.509 handlers that #294 narrows.

`CLAUDE.md` states the rule: a fingerprinter catches the parse errors it expects, and it
does not catch bare `Exception`. Three handlers wrote `except (ValueError, TypeError,
Exception)`, which catches every exception, and #294 names the errors instead.

Every test holds one of two shapes.

- A named error reaches the handler, and the reader returns nothing. `CLAUDE.md` rule 2
  states that a parser which cannot read a packet returns nothing and does not raise.
- An error the narrow list does not name reaches the handler, and the handler holds it no
  longer. That shape fails on the wide form, so it measures the repair.

The `cryptography` documentation names the errors. `load_der_x509_certificate` raises
`ValueError`. `Certificate.extensions` raises `DuplicateExtension` and
`UnsupportedGeneralNameType`. `Certificate.version` raises `InvalidVersion`.
Verified against: https://cryptography.io/en/latest/x509/reference/ (cryptography 50.0.0,
retrieved 2026-08-08).
"""

import datetime
import logging

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from scapy.all import Raw

from ja4plus.fingerprinters.ja4x import JA4XFingerprinter
from ja4plus.utils import x509_utils

# An arbitrary extension OID. The stub certificate names it to build one error.
KEY_USAGE_OID = x509.ObjectIdentifier("2.5.29.15")

# The errors that `cryptography` documents for the calls the three handlers make.
NAMED_ERRORS = [
    ValueError("error parsing asn1 value"),
    x509.DuplicateExtension("duplicate extension", KEY_USAGE_OID),
    x509.UnsupportedGeneralNameType("unsupported general name type"),
]

# An error that no documented call raises. It stands for a defect of this project, and
# the repair lets it reach a reader.
PROJECT_DEFECT = RuntimeError("a defect of this project")


class _RaisingCertificate:
    """A stub certificate whose extension list raises one error.

    The stub reads as a certificate for the two name lists, so the reader reaches the
    extension list and the error the test names.
    """

    def __init__(self, error: BaseException) -> None:
        self._error = error

    @property
    def issuer(self) -> x509.Name:
        return x509.Name([])

    @property
    def subject(self) -> x509.Name:
        return x509.Name([])

    @property
    def extensions(self) -> object:
        raise self._error


def _one_certificate() -> bytes:
    """Return one DER certificate that every reader parses."""
    key = rsa.generate_private_key(65537, 2048, default_backend())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(Encoding.DER)


# --- Site one: `JA4XFingerprinter.get_cert_details` ---------------------------------


@pytest.mark.parametrize("error", NAMED_ERRORS, ids=lambda e: type(e).__name__)
def test_the_certificate_reader_returns_nothing_for_an_error_it_names(error):
    """The reader holds every error the narrow list names."""
    assert JA4XFingerprinter().get_cert_details(_RaisingCertificate(error)) is None


def test_the_certificate_reader_reports_a_defect_of_this_project():
    """The reader holds no error the narrow list omits, so a defect reaches a reader."""
    with pytest.raises(RuntimeError):
        JA4XFingerprinter().get_cert_details(_RaisingCertificate(PROJECT_DEFECT))


# --- Site two: `JA4XFingerprinter.read_certificate` ----------------------------------


def test_the_certificate_parser_returns_nothing_for_bytes_it_cannot_parse():
    """`load_der_x509_certificate` raises `ValueError`, and the parser holds it."""
    assert JA4XFingerprinter().read_certificate(b"not a certificate") == (None, None)


def test_the_certificate_parser_returns_nothing_for_input_that_is_no_byte_string():
    """`bytes()` raises `TypeError`, and the parser holds it."""
    assert JA4XFingerprinter().read_certificate(object()) == (None, None)


def test_the_certificate_parser_reports_a_defect_of_this_project():
    """The parser holds no error the narrow list omits."""
    fingerprinter = JA4XFingerprinter()

    def raise_the_defect(cert):
        raise PROJECT_DEFECT

    fingerprinter.get_cert_details = raise_the_defect
    with pytest.raises(RuntimeError):
        fingerprinter.read_certificate(_one_certificate())


# --- Site three: the direct parse of `extract_certificate_info` ----------------------

# The inner handler is the one line of the function that writes this message, so the
# record proves which handler read the error. The outer handler writes no log record.
INNER_HANDLER_MESSAGE = "Direct certificate parsing failed"

# The packet needs more than 100 bytes of payload before the direct parse runs.
HOSTILE_PAYLOAD = b"\xff" * 200


def _read_a_hostile_packet(caplog):
    """Return the messages the direct parse writes for one hostile packet."""
    with caplog.at_level(logging.DEBUG, logger="ja4plus.utils.x509_utils"):
        result = x509_utils.extract_certificate_info(Raw(HOSTILE_PAYLOAD))
    return result, [record.getMessage() for record in caplog.records]


def test_the_packet_reader_returns_nothing_for_a_payload_that_holds_no_certificate(caplog):
    """The real loader raises `ValueError`, and the inner handler holds it."""
    result, messages = _read_a_hostile_packet(caplog)
    assert result is None
    assert any(message.startswith(INNER_HANDLER_MESSAGE) for message in messages)


@pytest.mark.parametrize("error", NAMED_ERRORS, ids=lambda e: type(e).__name__)
def test_the_packet_reader_holds_every_error_the_direct_parse_names(error, caplog, monkeypatch):
    """The inner handler names every error the loader and the detail reader raise."""

    def raise_the_error(data, backend=None):
        raise error

    monkeypatch.setattr(x509, "load_der_x509_certificate", raise_the_error)
    result, messages = _read_a_hostile_packet(caplog)
    assert result is None
    assert any(message.startswith(INNER_HANDLER_MESSAGE) for message in messages)


def test_the_packet_reader_holds_the_invalid_version_error(caplog, monkeypatch):
    """`Certificate.version` raises `InvalidVersion`, and the detail reader lets it pass."""

    def raise_the_error(data, backend=None):
        raise x509.InvalidVersion("unknown version", 7)

    monkeypatch.setattr(x509, "load_der_x509_certificate", raise_the_error)
    result, messages = _read_a_hostile_packet(caplog)
    assert result is None
    assert any(message.startswith(INNER_HANDLER_MESSAGE) for message in messages)


def test_the_packet_reader_reports_a_defect_of_this_project(caplog, monkeypatch):
    """The inner handler holds no error the narrow list omits.

    The outer handler of the function still returns nothing, and it writes no record, so
    the absent record proves the inner handler read no error.
    """

    def raise_the_defect(data, backend=None):
        raise PROJECT_DEFECT

    monkeypatch.setattr(x509, "load_der_x509_certificate", raise_the_defect)
    result, messages = _read_a_hostile_packet(caplog)
    assert result is None
    assert not any(message.startswith(INNER_HANDLER_MESSAGE) for message in messages)


# --- The rule the repair must not break ---------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [b"", b"not a certificate", b"\x30\x82\x00\x00", b"\x00" * 5000, b"\xff" * 200],
    ids=["empty", "text", "short-der", "zeros", "ones"],
)
def test_the_fingerprinter_raises_no_error_for_hostile_certificate_bytes(hostile):
    """Every packet is hostile input, so the reader returns nothing and does not raise."""
    assert JA4XFingerprinter().fingerprint_certificate(hostile) is None
