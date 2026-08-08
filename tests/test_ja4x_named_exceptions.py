"""Measure the two X.509 handlers of `JA4XFingerprinter` that #294 narrows.

`CLAUDE.md` states the rule: a fingerprinter catches the parse errors it expects, and it
does not catch bare `Exception`. Three handlers wrote `except (ValueError, TypeError,
Exception)`, which catches every exception, and #294 names the errors instead. #314
removed the third handler with `extract_certificate_info`, the function that held it.

Every test holds one of two shapes.

- A named error reaches the handler, and the reader returns nothing. `CLAUDE.md` rule 2
  states that a parser which cannot read a packet returns nothing and does not raise.
- An error the narrow list does not name reaches the handler, and the handler holds it no
  longer. That shape fails on the wide form, so it measures the repair.

The `cryptography` documentation names the errors. `load_der_x509_certificate` raises
`ValueError`. `Certificate.extensions` raises `DuplicateExtension` and
`UnsupportedGeneralNameType`.
Verified against: https://cryptography.io/en/latest/x509/reference/ (cryptography 50.0.0,
retrieved 2026-08-08).
"""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from ja4plus.fingerprinters.ja4x import JA4XFingerprinter

# An arbitrary extension OID. The stub certificate names it to build one error.
KEY_USAGE_OID = x509.ObjectIdentifier("2.5.29.15")

# The errors that `cryptography` documents for the calls the three handlers make. Each
# entry builds one error, because a raised instance holds the traceback of every frame
# it passed and a shared instance would keep those frames for the whole run.
NAMED_ERRORS = [
    lambda: ValueError("error parsing asn1 value"),
    lambda: x509.DuplicateExtension("duplicate extension", KEY_USAGE_OID),
    lambda: x509.UnsupportedGeneralNameType("unsupported general name type"),
]
NAMED_ERROR_IDS = ["ValueError", "DuplicateExtension", "UnsupportedGeneralNameType"]


def project_defect() -> RuntimeError:
    """Return an error that no documented call raises.

    The error stands for a defect of this project. The wide form held it, and the narrow
    form lets it reach a reader.
    """
    return RuntimeError("a defect of this project")


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


@pytest.mark.parametrize("build_error", NAMED_ERRORS, ids=NAMED_ERROR_IDS)
def test_the_certificate_reader_returns_nothing_for_an_error_it_names(build_error):
    """The reader holds every error the narrow list names."""
    assert JA4XFingerprinter().get_cert_details(_RaisingCertificate(build_error())) is None


def test_the_certificate_reader_reports_a_defect_of_this_project():
    """The reader holds no error the narrow list omits, so a defect reaches a reader."""
    with pytest.raises(RuntimeError):
        JA4XFingerprinter().get_cert_details(_RaisingCertificate(project_defect()))


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
        raise project_defect()

    fingerprinter.get_cert_details = raise_the_defect
    with pytest.raises(RuntimeError):
        fingerprinter.read_certificate(_one_certificate())


# --- The rule the repair must not break ---------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [b"", b"not a certificate", b"\x30\x82\x00\x00", b"\x00" * 5000, b"\xff" * 200],
    ids=["empty", "text", "short-der", "zeros", "ones"],
)
def test_the_fingerprinter_raises_no_error_for_hostile_certificate_bytes(hostile):
    """Every packet is hostile input, so the reader returns nothing and does not raise."""
    assert JA4XFingerprinter().fingerprint_certificate(hostile) is None
