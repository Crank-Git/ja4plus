"""Pin the JA4X empty-list form the user decided on 2026-08-08.

An empty list writes the zero sentinel `000000000000`. It never writes
`e3b0c44298fc`, which is the truncated SHA-256 of the empty string.

R8 of `docs/specs/foxio/JA4X.md` holds the reading and the contradiction the FoxIO
image carries. Changelog round 77 of `docs/specs/spec.md` records the decision. No
local vector reaches the case, so this file is the whole gate on the sentinel.
"""

import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from ja4plus.fingerprinters.ja4x import JA4XFingerprinter, generate_ja4x

# The zero sentinel the user decided. The FoxIO Rust implementation, the Wireshark
# dissector and `README.md` line 146 all write it.
ZERO_SENTINEL = "000000000000"
# The form the decision rejects. `python/ja4x.py` writes it, because it hashes the empty
# join with no guard, and the Qakbot row of `JA4X.png` records that output.
EMPTY_STRING_HASH = "e3b0c44298fc"


def _certificate_with_no_extension():
    """Return one DER certificate that carries no extension.

    The issuer and the subject each hold three attributes, so part a and part b hold a
    hash and part c is the one part the empty list reaches.
    """
    key = rsa.generate_private_key(65537, 2048, default_backend())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
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


def test_the_rejected_form_is_the_truncated_hash_of_the_empty_string():
    """Reproduce the arithmetic the decision rests on."""
    assert hashlib.sha256(b"").hexdigest()[:12] == EMPTY_STRING_HASH


def test_an_empty_extension_list_writes_the_zero_sentinel():
    """Part c holds the sentinel when the certificate carries no extension."""
    cert_info = {
        "issuer_rdns": ["550406", "55040a", "550403"],
        "subject_rdns": ["550406", "55040a", "550403"],
        "extensions": [],
    }
    parts = generate_ja4x(cert_info).split("_")
    assert parts[2] == ZERO_SENTINEL
    assert parts[2] != EMPTY_STRING_HASH


def test_an_empty_issuer_list_writes_the_zero_sentinel():
    """Part a holds the sentinel. The two `Sliver, Havoc C2` rows of the image show it."""
    cert_info = {"issuer_rdns": [], "subject_rdns": ["550403"], "extensions": ["551d0f"]}
    parts = generate_ja4x(cert_info).split("_")
    assert parts[0] == ZERO_SENTINEL
    assert parts[0] != EMPTY_STRING_HASH


def test_an_empty_subject_list_writes_the_zero_sentinel():
    """Part b holds the sentinel."""
    cert_info = {"issuer_rdns": ["550403"], "subject_rdns": [], "extensions": ["551d0f"]}
    parts = generate_ja4x(cert_info).split("_")
    assert parts[1] == ZERO_SENTINEL
    assert parts[1] != EMPTY_STRING_HASH


def test_a_certificate_with_no_extension_writes_the_zero_sentinel():
    """The DER reader reaches the same sentinel as the direct call."""
    parts = JA4XFingerprinter().fingerprint_certificate(_certificate_with_no_extension()).split("_")
    assert parts[2] == ZERO_SENTINEL
    assert parts[2] != EMPTY_STRING_HASH


def test_a_certificate_with_no_extension_writes_a_hash_in_part_a_and_part_b():
    """The sentinel reaches part c alone. A test that pins three sentinels measures
    nothing about the extension list."""
    parts = JA4XFingerprinter().fingerprint_certificate(_certificate_with_no_extension()).split("_")
    assert parts[0] != ZERO_SENTINEL
    assert parts[1] != ZERO_SENTINEL


def test_an_extension_list_that_holds_one_entry_writes_a_hash():
    """A non-empty list never writes the sentinel, so the guard reads the list."""
    cert_info = {"issuer_rdns": ["550403"], "subject_rdns": ["550403"], "extensions": ["551d0f"]}
    parts = generate_ja4x(cert_info).split("_")
    assert parts[2] == hashlib.sha256(b"551d0f").hexdigest()[:12]
