"""Tests for the SSL 2.0 version value that FoxIO corrected.

`technical_details/JA4.md:65` at the pinned commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`
states `0x0002 = SSL 2.0 = "s2"`, and it states `Unknown = "00"` for every value the table
omits. FoxIO commit `3e02a27`, dated 2024-08-23, is titled
`Fix SSL version fields: SSL 2.0 is 0x0002, SSL 1.0 never existed`. The table therefore
states no meaning for `0x0200` and no meaning for `0x0100`. #227 owns the repair.
"""

from ja4plus.fingerprinters.ja4 import generate_ja4, get_raw_fingerprint
from ja4plus.fingerprinters.ja4s import _version_to_str
from ja4plus.utils.tls_utils import parse_tls_handshake

SSL_2_0 = 0x0002
RETRACTED_SSL_2_0 = 0x0200
RETRACTED_SSL_1_0 = 0x0100


def _tls_info(version, supported_versions=None):
    """Return one parsed ClientHello that names the given version."""
    return {
        "type": "client_hello",
        "handshake_type": "client_hello",
        "version": version,
        "supported_versions": supported_versions or [],
        "ciphers": [0x1301, 0x1302],
        "extensions": [0x000A, 0x000B],
        "alpn_protocols": [],
        "signature_algorithms": [],
    }


def _client_hello_record(legacy_version, ext_bytes=b""):
    """Return one TLS handshake record that carries a ClientHello.

    Args:
        legacy_version: The value of the two-byte legacy version field.
        ext_bytes: The extension block, or an empty block.

    Returns:
        The record bytes.
    """
    body = (
        legacy_version.to_bytes(2, "big")
        + b"\x00" * 32
        + b"\x00"
        + b"\x00\x02\xc0\x2f"
        + b"\x01\x00"
        + len(ext_bytes).to_bytes(2, "big")
        + ext_bytes
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _ja4_version(version):
    """Return the two version characters of the JA4 fingerprint."""
    return generate_ja4(_tls_info(version))[1:3]


def _ja4_raw_version(version):
    """Return the two version characters of the raw JA4 fingerprint."""
    return get_raw_fingerprint(_tls_info(version))[1:3]


# ---------------------------------------------------------------------------
# The value the pinned specification states
# ---------------------------------------------------------------------------


def test_ja4_writes_s2_for_the_ssl_2_0_version_value_0x0002():
    assert _ja4_version(SSL_2_0) == "s2"


def test_the_raw_form_writes_s2_for_the_ssl_2_0_version_value_0x0002():
    assert _ja4_raw_version(SSL_2_0) == "s2"


def test_ja4s_writes_s2_for_the_ssl_2_0_version_value_0x0002():
    assert _version_to_str(SSL_2_0) == "s2"


def test_the_supported_versions_extension_reaches_the_ssl_2_0_version_value():
    fingerprint = generate_ja4(_tls_info(0x0301, supported_versions=[SSL_2_0]))
    assert fingerprint[1:3] == "s2"


# ---------------------------------------------------------------------------
# The values the pinned specification omits
# ---------------------------------------------------------------------------


def test_ja4_writes_00_for_the_retracted_version_value_0x0200():
    assert _ja4_version(RETRACTED_SSL_2_0) == "00"


def test_the_raw_form_writes_00_for_the_retracted_version_value_0x0200():
    assert _ja4_raw_version(RETRACTED_SSL_2_0) == "00"


def test_ja4s_writes_00_for_the_retracted_version_value_0x0200():
    assert _version_to_str(RETRACTED_SSL_2_0) == "00"


def test_ja4_writes_00_for_the_ssl_1_0_version_value_0x0100():
    assert _ja4_version(RETRACTED_SSL_1_0) == "00"


def test_ja4s_writes_00_for_the_ssl_1_0_version_value_0x0100():
    assert _version_to_str(RETRACTED_SSL_1_0) == "00"


# ---------------------------------------------------------------------------
# Whether a parser path can present the value
# ---------------------------------------------------------------------------


def test_the_parser_presents_0x0002_from_the_legacy_version_field():
    parsed = parse_tls_handshake(_client_hello_record(SSL_2_0))
    assert parsed["version"] == SSL_2_0


def test_the_parser_presents_0x0002_from_the_supported_versions_extension():
    supported_versions = b"\x00\x2b\x00\x03\x02\x00\x02"
    parsed = parse_tls_handshake(_client_hello_record(0x0301, supported_versions))
    assert parsed["supported_versions"] == [SSL_2_0]


def test_the_parser_reads_no_ssl_2_0_record_format():
    # An SSL 2.0 ClientHello opens with a two-byte length whose high bit is set, and the
    # parser reads a TLS record header. The negative result belongs to #227.
    ssl_2_0_hello = (
        b"\x80\x2e\x01\x00\x02\x00\x15\x00\x00\x00\x10" + b"\x01\x00\x80" * 7 + b"\x00" * 16
    )
    assert parse_tls_handshake(ssl_2_0_hello) is None
