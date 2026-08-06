"""Verify JA4 emits the literal sentinel '000000000000' when, after GREASE
filtering, the extension list is empty.

Per FoxIO PR #288, the empty case must be the literal twelve zeros, NOT
sha256(b'')[:12].hexdigest() (which is 'e3b0c44298fc').
"""

from ja4plus.fingerprinters.ja4 import generate_ja4


def _client_hello_info(
    extensions=None, ciphers=None, alpn_protocols=None, version=0x0303, sni=None
):
    """Build a minimal tls_info dict that drives generate_ja4 directly."""
    return {
        "handshake_type": "client_hello",
        "type": "client_hello",
        "version": version,
        "is_quic": False,
        "is_dtls": False,
        "ciphers": ciphers or [],
        "extensions": extensions or [],
        "alpn_protocols": alpn_protocols or [],
        "signature_algorithms": [],
        "supported_versions": [],
        "sni": sni,
    }


def test_ja4_empty_extensions_yields_literal_zero_hash():
    """No extensions at all -> ext_hash must be '000000000000'."""
    info = _client_hello_info(extensions=[], ciphers=[0x1301])
    fp = generate_ja4(info)
    assert fp is not None
    parts = fp.split("_")
    assert len(parts) == 3
    # Last part is the extension hash
    assert parts[2] == "000000000000", f"got ext hash {parts[2]!r}"
    # Defensive: must NOT be the sha256(b'') value
    assert parts[2] != "e3b0c44298fc"


def test_ja4_only_grease_extensions_yields_literal_zero_hash():
    """When the only extensions are GREASE values, post-filter is empty."""
    # GREASE values follow pattern 0x[0-f]a[0-f]a — e.g. 0x0a0a, 0x1a1a
    info = _client_hello_info(extensions=[0x0A0A, 0x1A1A, 0x2A2A])
    fp = generate_ja4(info)
    assert fp is not None
    parts = fp.split("_")
    assert parts[2] == "000000000000"


def test_ja4_only_sni_and_alpn_extensions_yields_literal_zero_hash():
    """SNI (0x0000) and ALPN (0x0010) are excluded from the hash input."""
    # If the only extensions are SNI + ALPN, the filtered list is empty
    info = _client_hello_info(extensions=[0x0000, 0x0010], sni="example.com")
    fp = generate_ja4(info)
    assert fp is not None
    parts = fp.split("_")
    assert parts[2] == "000000000000"
