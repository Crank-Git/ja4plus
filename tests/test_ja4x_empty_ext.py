"""Pin the JA4X empty-list form the maintainer ruled on 2026-08-14.

An empty list hashes, and it writes `e3b0c44298fc`, which is the truncated SHA-256 of
the empty string. It never writes the zero sentinel `000000000000`.

R8 of `docs/specs/foxio/JA4X.md` holds the reading, the contradiction the FoxIO image
carries, and the ruling of 2026-08-14 that reverses the earlier one. #619 holds the
reversal path, and `Crank-Git/ja4plus-go#582` holds the Go half. No local vector reaches
the case, so this file is the whole gate on the empty list.
"""

import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from ja4plus.fingerprinters.ja4x import JA4XFingerprinter, generate_ja4x, generate_ja4x_raw

# The form the ruling of 2026-08-14 requires. `python/ja4x.py` writes it, because it
# hashes the empty join with no guard, and the Qakbot row of `JA4X.png` records that
# output.
EMPTY_STRING_HASH = "e3b0c44298fc"
# The form the ruling rejects. The FoxIO Rust implementation and the Wireshark dissector
# each write it, and the earlier ruling of 2026-08-08 adopted it.
ZERO_SENTINEL = "000000000000"


def _certificate_with_no_extension():
    """Return one DER certificate that carries no extension.

    The issuer and the subject each hold three attributes, so part a and part b hold a
    hash of a list that holds a value, and part c is the one part the empty list reaches.
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


def test_the_required_form_is_the_truncated_hash_of_the_empty_string():
    """Reproduce the arithmetic the ruling rests on."""
    assert hashlib.sha256(b"").hexdigest()[:12] == EMPTY_STRING_HASH


def test_an_empty_extension_list_hashes():
    """Part c holds the hash of the empty string when the certificate carries no
    extension."""
    cert_info = {
        "issuer_rdns": ["550406", "55040a", "550403"],
        "subject_rdns": ["550406", "55040a", "550403"],
        "extensions": [],
    }
    parts = generate_ja4x(cert_info).split("_")
    assert parts[2] == EMPTY_STRING_HASH
    assert parts[2] != ZERO_SENTINEL


def test_an_empty_issuer_list_hashes():
    """Part a holds the hash of the empty string. The two `Sliver, Havoc C2` rows of the
    image write the rejected form for this condition."""
    cert_info = {"issuer_rdns": [], "subject_rdns": ["550403"], "extensions": ["551d0f"]}
    parts = generate_ja4x(cert_info).split("_")
    assert parts[0] == EMPTY_STRING_HASH
    assert parts[0] != ZERO_SENTINEL


def test_an_empty_subject_list_hashes():
    """Part b holds the hash of the empty string."""
    cert_info = {"issuer_rdns": ["550403"], "subject_rdns": [], "extensions": ["551d0f"]}
    parts = generate_ja4x(cert_info).split("_")
    assert parts[1] == EMPTY_STRING_HASH
    assert parts[1] != ZERO_SENTINEL


def test_three_empty_lists_write_the_same_hash_into_every_part():
    """No part of JA4X writes the zero sentinel."""
    cert_info = {"issuer_rdns": [], "subject_rdns": [], "extensions": []}
    value = generate_ja4x(cert_info)
    assert value == f"{EMPTY_STRING_HASH}_{EMPTY_STRING_HASH}_{EMPTY_STRING_HASH}"


def test_a_certificate_with_no_extension_hashes_part_c():
    """The DER reader reaches the same hash as the direct call."""
    parts = JA4XFingerprinter().fingerprint_certificate(_certificate_with_no_extension()).split("_")
    assert parts[2] == EMPTY_STRING_HASH
    assert parts[2] != ZERO_SENTINEL


def test_a_certificate_with_no_extension_writes_another_hash_in_part_a_and_part_b():
    """The empty-string hash reaches part c alone. A file that pins three equal parts
    measures nothing about the extension list."""
    parts = JA4XFingerprinter().fingerprint_certificate(_certificate_with_no_extension()).split("_")
    assert parts[0] != EMPTY_STRING_HASH
    assert parts[1] != EMPTY_STRING_HASH


def test_an_extension_list_that_holds_one_entry_writes_the_hash_of_that_entry():
    """A list that holds a value hashes that value, so the change moves no such part."""
    cert_info = {"issuer_rdns": ["550403"], "subject_rdns": ["550403"], "extensions": ["551d0f"]}
    parts = generate_ja4x(cert_info).split("_")
    assert parts[2] == hashlib.sha256(b"551d0f").hexdigest()[:12]


def test_the_hashed_form_is_the_hash_of_each_part_of_the_raw_form():
    """The raw form stays the exact preimage of the fingerprint on an empty list.

    The earlier ruling broke that relation on an empty part, because the raw form held
    an empty part and the hashed form held a sentinel that hashes nothing.
    """
    cert_info = {"issuer_rdns": [], "subject_rdns": ["550403"], "extensions": []}
    raw_parts = generate_ja4x_raw(cert_info).split("_")
    hashed_parts = generate_ja4x(cert_info).split("_")
    assert [hashlib.sha256(part.encode()).hexdigest()[:12] for part in raw_parts] == hashed_parts
