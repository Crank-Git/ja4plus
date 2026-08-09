"""Measure the fourteen bare `Exception` handlers that #319 reads.

#319 reads every site and puts it in one of three groups. The group decides the change.

1. **A parser reading hostile input.** `CLAUDE.md` binds it: a parser that cannot read a
   packet returns nothing, and it does not raise. The group holds four sites, and #319
   narrows all four. The three QUIC readers of `ja4plus/utils/quic_utils.py` are three of
   them, and `compute_ja4x_from_pem` of `ja4plus/__init__.py` is the fourth.
2. **Deliberate collection of an error the caller receives.** The three sites of
   `ja4plus/processor.py` hold it. #45 made the processor hand each parse failure to its
   caller, so the wide catch is the design and #319 narrows none of them.
3. **Top-level reporting.** The five sites of `ja4plus/cli.py` and the two of
   `ja4plus/ja4db.py` hold it. Each one reports a failure and returns, and #319 narrows
   none of them.

The cases below measure four things.

- No group 1 handler names `Exception` any longer. `inspect.getsource` reads the loaded
  module, so the case fails on a stale `.pyc` that still holds the old handler.
- One case reaches each named error of each group 1 site. The case fails if the clause
  drops that name, because the error then leaves the reader.
- Every group 1 reader returns nothing and raises nothing for hostile input, over more
  than one input.
- A group 2 or group 3 caller returns rather than raises. #319 states the rule of each
  wide catch as a condition a case tests, because prose alone stated five earlier rules
  that no case measured.

The three QUIC payloads are short and constructive. `_find_pn_offset` reads offset 9 for
a header that names a zero-length connection ID, a zero-length source connection ID, a
zero-length token and a zero length, so the length of the datagram alone decides which
error the reader meets.

#294 and #316 hold the method. #316 found that `InvalidVersion` inherits `Exception` and
not `ValueError`, so a list of `ValueError` alone drops it. `InvalidTag` of the AEAD
decryption has the same shape, and the measurement of #319 records it.
"""

import base64
import datetime
import inspect
import random
import struct

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from scapy.all import IP, TCP

import ja4plus
from ja4plus import ja4db, processor
from ja4plus.utils import quic_utils

# A QUIC version 1 long header that names no connection ID, no source connection ID, no
# token and a zero length. `_find_pn_offset` reads offset 9 for it.
_EMPTY_HEADER = bytes([0xC0]) + struct.pack("!I", 1) + bytes([0x00, 0x00, 0x00, 0x00])

# The length byte names 255 connection-ID bytes that the 20-byte datagram does not hold,
# so `_find_pn_offset` reads past the end and raises `IndexError`.
INDEX_ERROR_PAYLOAD = bytes([0xC0]) + struct.pack("!I", 1) + bytes([0xFF]) + bytes(14)

# The header-protection sample is `payload[13:29]`. A 20-byte datagram leaves 7 bytes,
# and AES in ECB mode raises `ValueError` for a length that is no multiple of 16.
VALUE_ERROR_PAYLOAD = _EMPTY_HEADER + bytes(20 - len(_EMPTY_HEADER))

# A 40-byte datagram holds a full 16-byte sample, so the reader reaches the decryption.
# The zero length field leaves no ciphertext, and the AEAD raises `InvalidTag`.
INVALID_TAG_PAYLOAD = _EMPTY_HEADER + bytes(40 - len(_EMPTY_HEADER))

QUIC_ERROR_PAYLOADS = [
    (IndexError, INDEX_ERROR_PAYLOAD),
    (ValueError, VALUE_ERROR_PAYLOAD),
    (InvalidTag, INVALID_TAG_PAYLOAD),
]

# The server reader derives its keys from the connection ID the client chose, so it takes
# that value from the caller rather than from the datagram.
CLIENT_DCID = b"\x01\x02\x03\x04"

GROUP_ONE_READERS = [
    quic_utils.decrypt_quic_initial_crypto,
    quic_utils.decrypt_quic_server_initial_crypto,
    quic_utils.parse_quic_initial,
    ja4plus.compute_ja4x_from_pem,
]


def _reach_quic_handler(payload: bytes, server: bool) -> bytes:
    """Run the calls that the try-body of the three QUIC readers holds.

    The helper reaches the handler the same way the reader reaches it, so the error it
    raises is the error the clause of the reader must name.

    Args:
        payload: The bytes of the UDP payload.
        server: True runs the server key schedule, and False runs the client one.

    Returns:
        The decrypted payload.

    Raises:
        Exception: The error the reader meets for this payload.
    """
    dcid = CLIENT_DCID if server else payload[6 : 6 + payload[5]]
    client_secret, server_secret = quic_utils.derive_initial_secrets(dcid, 1)
    key, iv, hp_key = quic_utils.derive_key_iv_hp(server_secret if server else client_secret)
    unprotected, pn, pn_length = quic_utils.remove_header_protection(payload, hp_key)
    pn_offset = quic_utils._find_pn_offset(payload)
    return quic_utils.decrypt_initial_payload(unprotected, pn, pn_length, pn_offset, key, iv)


# ---------------------------------------------------------------------------
# Group 1 — the rule binds these four sites.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("reader", GROUP_ONE_READERS, ids=lambda f: f.__name__)
def test_a_group_one_reader_names_no_bare_exception(reader):
    """The handler of a parser names the errors it expects.

    `CLAUDE.md` states the rule. `inspect.getsource` reads the loaded module, so a stale
    `.pyc` that still holds the old handler turns this case red.
    """
    assert "except Exception" not in inspect.getsource(reader)


@pytest.mark.parametrize(
    "error,payload", QUIC_ERROR_PAYLOADS, ids=lambda v: getattr(v, "__name__", "")
)
def test_the_client_initial_reader_returns_nothing_for_each_error_it_names(error, payload):
    """The reader returns nothing for each error its clause names.

    The case fails if the clause drops the named error, because the error then leaves
    `decrypt_quic_initial_crypto` and `parse_quic_initial` rather than the reader.
    """
    with pytest.raises(error):
        _reach_quic_handler(payload, server=False)

    assert quic_utils.decrypt_quic_initial_crypto(payload) == (None, None)
    assert quic_utils.parse_quic_initial(payload) is None


@pytest.mark.parametrize(
    "error,payload", QUIC_ERROR_PAYLOADS, ids=lambda v: getattr(v, "__name__", "")
)
def test_the_server_initial_reader_returns_nothing_for_each_error_it_names(error, payload):
    """The server reader returns nothing for each error its clause names.

    The case fails if the clause drops the named error.
    """
    with pytest.raises(error):
        _reach_quic_handler(payload, server=True)

    assert quic_utils.decrypt_quic_server_initial_crypto(payload, CLIENT_DCID) is None


def test_the_quic_readers_return_nothing_and_raise_nothing_for_hostile_input():
    """Every packet is hostile input, so the three readers return nothing.

    The case runs 6000 datagrams through the three readers. A narrowing that misses an
    error the reader meets turns this case red.
    """
    generator = random.Random(319)
    for _ in range(2000):
        size = generator.choice([20, 21, 32, 64, 200, 1200])
        payload = bytearray(generator.getrandbits(8) for _ in range(size))
        payload[0] = 0xC0
        payload[1:5] = struct.pack("!I", generator.choice([1, 0x6B3343CF]))
        payload[5] = generator.choice([0, 4, 8, 20, 255])
        datagram = bytes(payload)

        assert quic_utils.decrypt_quic_initial_crypto(datagram) == (None, None)
        assert quic_utils.decrypt_quic_server_initial_crypto(datagram, CLIENT_DCID) is None
        assert quic_utils.parse_quic_initial(datagram) is None


def _self_signed_der() -> bytes:
    """Return the DER form of one self-signed certificate."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ja4plus.test")])
    start = datetime.datetime(2020, 1, 1)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def _pem(der: bytes) -> bytes:
    """Return the PEM form of one DER certificate."""
    return (
        b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der) + b"-----END CERTIFICATE-----\n"
    )


@pytest.fixture(scope="module")
def bad_version_pem() -> bytes:
    """Return the PEM form of one certificate whose version field names no version.

    The version field of a TBSCertificate holds the DER bytes `a0 03 02 01 02`. The
    fixture writes the value 18 in place of 2, and the loader then raises
    `InvalidVersion` rather than `ValueError`.

    Returns:
        The PEM form of one certificate.
    """
    der = _self_signed_der()
    assert der.count(b"\xa0\x03\x02\x01\x02") == 1
    return _pem(der.replace(b"\xa0\x03\x02\x01\x02", b"\xa0\x03\x02\x01\x12"))


def test_the_pem_reader_returns_nothing_for_a_certificate_that_holds_no_certificate():
    """The loader raises `ValueError`, and the reader returns nothing.

    The case fails if the clause drops `ValueError`.
    """
    text = _pem(b"\x30\x03\x02\x01\x00")
    with pytest.raises(ValueError):
        x509.load_pem_x509_certificate(text)

    assert ja4plus.compute_ja4x_from_pem(text) is None


def test_the_pem_reader_returns_nothing_for_a_certificate_of_an_unknown_version(bad_version_pem):
    """The loader raises `InvalidVersion`, which inherits `Exception` and not `ValueError`.

    The case fails if the clause drops `x509.InvalidVersion`, because a list of
    `ValueError` alone holds the error no longer. #316 found the same shape in the DER
    loader, and #319 measured it in the PEM loader.
    """
    with pytest.raises(x509.InvalidVersion):
        x509.load_pem_x509_certificate(bad_version_pem)

    assert ja4plus.compute_ja4x_from_pem(bad_version_pem) is None


def test_the_pem_reader_returns_nothing_and_raises_nothing_for_hostile_input():
    """Every certificate is hostile input, so the reader returns nothing.

    The case runs 200 inputs of four shapes.
    """
    generator = random.Random(319)
    for _ in range(50):
        body = bytes(generator.getrandbits(8) for _ in range(generator.choice([1, 64, 600])))
        assert ja4plus.compute_ja4x_from_pem(body) is None
        assert ja4plus.compute_ja4x_from_pem(_pem(body)) is None
        assert ja4plus.compute_ja4x_from_pem(b"-----BEGIN CERTIFICATE-----\n") is None
        assert ja4plus.compute_ja4x_from_pem(b"") is None


# ---------------------------------------------------------------------------
# Group 2 — the processor hands each error to its caller.
# ---------------------------------------------------------------------------


class _ForeignError(Exception):
    """An error that names no parse failure the fingerprinters raise."""


def test_the_processor_reports_the_error_of_a_method_rather_than_raising(monkeypatch):
    """`process_packet_with_method_errors` names the method behind each failure.

    #45 made the processor collect the failures it meets, so the wide catch of
    `ja4plus/processor.py` is the design. The case measures the rule the comment states.
    """
    driver = processor.Processor()
    monkeypatch.setattr(
        driver.fingerprinters["ja4"],
        "process_packet",
        lambda packet: (_ for _ in ()).throw(_ForeignError("read failed")),
    )

    results, errors = driver.process_packet_with_method_errors(IP() / TCP())

    assert [name for name, _ in errors] == ["ja4"]
    assert isinstance(errors[0][1], _ForeignError)
    assert isinstance(results, list)


def test_the_processor_loses_no_window_when_one_method_fails(monkeypatch):
    """One failing method costs the caller no window of the other nine.

    The case measures the rule the comment at `close_open_windows` states.
    """
    driver = processor.Processor()
    monkeypatch.setattr(
        driver.fingerprinters["ja4"],
        "close_open_windows",
        lambda: (_ for _ in ()).throw(_ForeignError("close failed")),
    )

    assert driver.close_open_windows() == []


def test_the_processor_returns_when_a_method_fails_to_drop_its_state(monkeypatch):
    """`cleanup_connection` returns rather than raises when one method fails.

    A long-running monitor drops a connection from every method or it leaks state, so
    the loop reaches all ten. The case measures the rule the comment states.
    """
    driver = processor.Processor()
    monkeypatch.setattr(
        driver.fingerprinters["ja4"],
        "cleanup_connection",
        lambda *args: (_ for _ in ()).throw(_ForeignError("cleanup failed")),
    )

    assert driver.cleanup_connection("1.1.1.1", 443, "2.2.2.2", 443, "tcp") is None


# ---------------------------------------------------------------------------
# Group 3 — the lookup reports a failure and returns.
# ---------------------------------------------------------------------------


def test_the_lookup_returns_no_match_when_the_service_fails(monkeypatch):
    """A failure of the lookup service is a miss, and the caller reads no error.

    `ja4db.com` publishes no versioned document, so the client treats every unexpected
    response as a miss. The case measures the rule the comment at `_do_lookup` states.
    """
    client = ja4db.JA4DBClient(allow_remote=True)
    monkeypatch.setattr(
        client,
        "_remote_lookup",
        lambda fingerprint: (_ for _ in ()).throw(_ForeignError("service failed")),
    )

    assert client._do_lookup("t13d1516h2_8daaf6152771_b0da82dd1658") is None
