"""JA4 removes GREASE values from the signature algorithms before it hashes or prints them.

FoxIO fixed this defect in Rust in commit `d66336ef` ("fix(rust): ignore grease in
sigalgs"). The expected values come from `python/test/testdata/sigalg-grease.pcapng.json`
at FoxIO commit `16b96d95`. The `tls_info` below is the parse of the Client Hello in
`pcap/sigalg-grease.pcapng` of that commit, with frames 4 and 5 joined. The capture lists
`0x0a0a` first among its signature algorithms.

#773 records the defect. #772 adds the capture itself to the conformance suite.
"""

from ja4plus.fingerprinters.ja4 import generate_ja4, get_raw_fingerprint

SIGNATURE_ALGORITHMS_ON_THE_WIRE = [
    0x0A0A,
    0x0904,
    0x0905,
    0x0906,
    0x0403,
    0x0804,
    0x0401,
    0x0503,
    0x0805,
    0x0501,
    0x0806,
    0x0601,
]

SIGNATURE_ALGORITHMS_WITHOUT_GREASE = "0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"


def _sigalg_grease_client_hello(signature_algorithms):
    """Return the `tls_info` of the FoxIO sigalg-grease Client Hello."""
    return {
        "type": "client_hello",
        "version": 0x0303,
        "is_quic": False,
        "is_dtls": False,
        "ciphers": [
            0x4A4A,
            0x1301,
            0x1302,
            0x1303,
            0xC02B,
            0xC02F,
            0xC02C,
            0xC030,
            0xCCA9,
            0xCCA8,
            0xC013,
            0xC014,
            0x009C,
            0x009D,
            0x002F,
            0x0035,
        ],
        "extensions": [
            0x7A7A,
            0xFE0D,
            0x0010,
            0x0017,
            0x0033,
            0x44CD,
            0xFF01,
            0x000A,
            0x000D,
            0x0023,
            0x002B,
            0x000B,
            0xCA34,
            0x002D,
            0x0000,
            0x0005,
            0x001B,
            0x0012,
            0x6A6A,
        ],
        "supported_versions": [0xFAFA, 0x0304, 0x0303],
        "alpn_protocols": ["h2", "http/1.1"],
        "alpn_raw": [b"h2", b"http/1.1"],
        "signature_algorithms": signature_algorithms,
        "sni": "optimizationguide-pa.googleapis.com",
    }


def test_ja4_of_the_sigalg_grease_capture_equals_the_foxio_value():
    tls_info = _sigalg_grease_client_hello(SIGNATURE_ALGORITHMS_ON_THE_WIRE)

    assert generate_ja4(tls_info) == "t13d1517h2_8daaf6152771_cb7bf5808d99"


def test_ja4_o_of_the_sigalg_grease_capture_equals_the_foxio_value():
    tls_info = _sigalg_grease_client_hello(SIGNATURE_ALGORITHMS_ON_THE_WIRE)

    assert generate_ja4(tls_info, original_order=True) == "t13d1517h2_acb858a92679_88bf22a3e888"


def test_ja4_r_of_the_sigalg_grease_capture_equals_the_foxio_value():
    tls_info = _sigalg_grease_client_hello(SIGNATURE_ALGORITHMS_ON_THE_WIRE)

    assert get_raw_fingerprint(tls_info) == (
        "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,"
        "cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,"
        "fe0d,ff01_" + SIGNATURE_ALGORITHMS_WITHOUT_GREASE
    )


def test_ja4_ro_of_the_sigalg_grease_capture_equals_the_foxio_value():
    tls_info = _sigalg_grease_client_hello(SIGNATURE_ALGORITHMS_ON_THE_WIRE)

    assert get_raw_fingerprint(tls_info, original_order=True) == (
        "t13d1517h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,"
        "002f,0035_fe0d,0010,0017,0033,44cd,ff01,000a,000d,0023,002b,000b,ca34,002d,"
        "0000,0005,001b,0012_" + SIGNATURE_ALGORITHMS_WITHOUT_GREASE
    )


def test_a_grease_value_between_two_signature_algorithms_leaves_the_wire_order():
    with_grease = _sigalg_grease_client_hello([0x0403, 0x2A2A, 0x0804, 0xFAFA, 0x0401])
    without_grease = _sigalg_grease_client_hello([0x0403, 0x0804, 0x0401])

    assert get_raw_fingerprint(with_grease).endswith("_0403,0804,0401")
    assert get_raw_fingerprint(with_grease, original_order=True).endswith("_0403,0804,0401")
    assert generate_ja4(with_grease) == generate_ja4(without_grease)
    assert generate_ja4(with_grease, original_order=True) == generate_ja4(
        without_grease, original_order=True
    )
