"""The ServerHello reader bounds every extension read on the bytes the record holds.

`_parse_server_hello` clamps `ext_data_end` to the length of the record. #617 records
that the `supported_versions` branch tested the declared length and indexed the raw
buffer, so a record that declares two bytes and supplies none raised `IndexError`. The
Go library repaired the identical defect in `Crank-Git/ja4plus-go#556`.

Every packet is hostile input. A reader that cannot read a record returns a value or
nothing, and it raises no exception.
"""

from ja4plus.utils.tls_utils import _parse_server_hello, parse_tls_handshake

# The Go fuzzer wrote this 64-byte input, and #617 quotes it. The bytes `\x00+` are the
# `supported_versions` extension type, 0x002b.
FUZZER_INPUT = (
    b"\x1600\x009\x020000000000000000000000000000000000000\x000000000\x00\x0500000\x00+0000"
)


def _server_hello_record(extension_body: bytes, declared_extension_length: int) -> bytes:
    """Return one TLS handshake record that holds a ServerHello with one extension.

    Args:
        extension_body: The bytes of the `supported_versions` extension data.
        declared_extension_length: The length the extension header declares.

    Returns:
        The record, with every length field of the record and of the hello correct.
    """
    extension = b"\x00\x2b" + declared_extension_length.to_bytes(2, "big") + extension_body
    body = bytearray(b"\x03\x03")
    body += b"\x00" * 32  # Random
    body += b"\x00"  # Session identifier length
    body += b"\x13\x01"  # Cipher suite
    body += b"\x00"  # Compression method
    body += len(extension).to_bytes(2, "big")
    body += extension
    handshake = b"\x02" + len(body).to_bytes(3, "big") + bytes(body)
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def test_the_reader_returns_a_value_on_an_extension_that_declares_two_bytes_and_supplies_none() -> (
    None
):
    """The 53-byte record of #617 reaches the reader and raises no exception."""
    record = _server_hello_record(b"", 2)
    assert len(record) == 53

    tls_info = _parse_server_hello(record)

    assert tls_info is not None
    assert tls_info["extensions"] == [0x002B]
    assert tls_info["supported_versions"] == []


def test_the_reader_returns_a_value_on_an_extension_that_supplies_one_byte_of_two() -> None:
    """A declared length of two over one supplied byte reads no version."""
    record = _server_hello_record(b"\x03", 2)

    tls_info = _parse_server_hello(record)

    assert tls_info is not None
    assert tls_info["supported_versions"] == []


def test_the_reader_returns_a_value_on_the_input_the_go_fuzzer_wrote() -> None:
    """The 64-byte input of #617 reads two present bytes, and it raises no exception.

    This case passes against the committed reader too, and #617 predicted a failure. The
    last extension declares 12336 bytes and the record supplies two, so the clamp and the
    declared length both admit the read. The case therefore proves that the repair moves
    no value on this input, and it states the exact value the reader produces.
    """
    assert len(FUZZER_INPUT) == 64

    tls_info = _parse_server_hello(FUZZER_INPUT)

    assert tls_info is not None
    assert tls_info["handshake_type"] == "server_hello"
    assert tls_info["extensions"] == [12336, 0x002B]
    assert tls_info["supported_versions"] == [12336]


def test_the_record_walk_returns_nothing_on_the_input_the_go_fuzzer_wrote() -> None:
    """The library entry point reads the 64-byte input and raises no exception.

    `parse_tls_handshake` reads a handshake length of 0x303030, which passes the end of
    the record, so the walk returns nothing.
    """
    assert parse_tls_handshake(FUZZER_INPUT) is None


def test_the_reader_reads_the_version_of_a_well_formed_supported_versions_extension() -> None:
    """A record that supplies both bytes still produces the version the server selected."""
    record = _server_hello_record(b"\x03\x04", 2)

    tls_info = _parse_server_hello(record)

    assert tls_info is not None
    assert tls_info["supported_versions"] == [0x0304]
    assert tls_info["version"] == 0x0304
