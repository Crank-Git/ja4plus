"""The ServerHello reader raises no exception on a crafted extension block.

#617 records one crash of `_parse_server_hello`. The `supported_versions` branch tested
the length the packet declares, and it indexed the raw buffer. A record that declared two
bytes and supplied none therefore raised `IndexError`. `4497e9f` repaired that one branch,
and #629 audited every other extension branch and found no second one.

This file measures the class of defect and not the one instance. A crafted record
declares one length in an extension header and supplies another count of bytes. #628
records that a read is not a standing proof, so the corpus below stands in place of that
audit.

Every case reads what the reader produced, because a case that asserts "no exception"
alone passes where no parser runs. `tests/fuzz/README.md` states that rule.

Every packet is hostile input. A parser that cannot read a packet returns nothing, and it
does not raise.
"""

import random

import pytest

import ja4plus.utils.tls_utils as tls_utils
from ja4plus.utils.tls_utils import _parse_server_hello, parse_tls_handshake
from tests.fuzz.support import spy_on

# The Go fuzzer wrote this 64-byte input, and #617 quotes it. The bytes `\x00+` are the
# `supported_versions` extension type, 0x002b.
FUZZER_INPUT = (
    b"\x1600\x009\x020000000000000000000000000000000000000\x000000000\x00\x0500000\x00+0000"
)

# The `fuzz` job runs this file on every batch pull request, so the corpus holds a fixed
# count of records. A generator that runs for a time budget makes the job unpredictable.
DRAWS = 512

# The generator carries a fixed seed, so a failure repeats. `os.urandom` gives a suite
# that fails on one run in many and passes on the next, which reports a defect nobody can
# reproduce. `test_synthetic_hostile_input.py` states the same reason.
SEED = 628

# `_parse_server_hello` branches on two extension types, which are 0x0010 and 0x002b. The
# other four types reach the loop and no branch reads their data. A branch that reads its
# data and a branch that skips it each belong to the class this file measures, because the
# loop advances on the declared length in both cases. 0x0000 and 0x000d branch inside
# `_parse_client_hello` alone, and this list holds them so that a later branch of the
# ServerHello reader arrives with a case behind it.
EXTENSION_TYPES = (0x0000, 0x000D, 0x0010, 0x002B, 0x0A0A, 0xFFFF)

# Each declared length stands against each supplied count below, so the grid holds the
# case where the two agree and the cases where they disagree in both directions.
DECLARED_LENGTHS = (0, 1, 2, 3, 4, 255, 4096, 65535)
SUPPLIED_COUNTS = (0, 1, 2, 3, 8)


def extension(ext_type: int, declared_length: int, supplied: bytes) -> bytes:
    """Return one extension whose header declares a length the data need not hold.

    Args:
        ext_type: The extension type.
        declared_length: The length the extension header declares.
        supplied: The bytes that follow the header.

    Returns:
        The extension bytes.
    """
    return ext_type.to_bytes(2, "big") + declared_length.to_bytes(2, "big") + supplied


def server_hello_record(extension_block: bytes, declared_block_length: int | None = None) -> bytes:
    """Return one TLS handshake record that holds a ServerHello and the extension block.

    Every length field outside the extension block is correct, so the reader reaches the
    block. #617 holds the same builder for one extension.

    Args:
        extension_block: The bytes of the whole extension block.
        declared_block_length: The length the extension block header declares. The
            builder writes the true length where this is None.

    Returns:
        The record bytes.
    """
    if declared_block_length is None:
        declared_block_length = len(extension_block)
    body = bytearray(b"\x03\x03")
    body += b"\x00" * 32  # Random
    body += b"\x00"  # Session identifier length
    body += b"\x13\x01"  # Cipher suite
    body += b"\x00"  # Compression method
    body += declared_block_length.to_bytes(2, "big")
    body += extension_block
    handshake = b"\x02" + len(body).to_bytes(3, "big") + bytes(body)
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


# The 53-byte record of #617. The extension declares two bytes of `supported_versions`
# and it supplies none.
CRASHING_RECORD = server_hello_record(extension(0x002B, 2, b""))

# The same shape with both bytes present. The reader produces the version the server
# selected, so the corpus holds a record that the reader reads to the end.
WELL_FORMED_RECORD = server_hello_record(extension(0x002B, 2, b"\x03\x04"))


def read_hello(record: bytes) -> dict[str, object] | None:
    """Return what the ServerHello reader produced for the record.

    Args:
        record: The record bytes.

    Returns:
        The information the reader produced, or None.

    Raises:
        Exception: The reader raised. Every case treats a raise as a failure.
    """
    return _parse_server_hello(record)


def crafted_records() -> list[tuple[str, bytes]]:
    """Return one record for each cell of the extension grid.

    Returns:
        A list of pairs. Each pair holds a name and the record bytes.
    """
    records = []
    for ext_type in EXTENSION_TYPES:
        for declared in DECLARED_LENGTHS:
            for count in SUPPLIED_COUNTS:
                name = f"type {ext_type:#06x} declares {declared} and supplies {count}"
                block = extension(ext_type, declared, b"\x03" * count)
                records.append((name, server_hello_record(block)))
    return records


CRAFTED_RECORDS = dict(crafted_records())


@pytest.fixture
def reader_calls(monkeypatch):
    """Count the calls of `_parse_server_hello`.

    A case that reaches no reader proves nothing, so every case that drives the library
    entry point reads this counter.
    """
    return spy_on(monkeypatch, tls_utils, "_parse_server_hello")


def test_the_crashing_record_of_617_is_53_bytes_and_produces_no_version():
    """The seed record of #617 reaches the reader and it raises no exception.

    A reversal of the `4497e9f` guard makes this case raise `IndexError`, so the case
    discriminates a bounded read from an unbounded one.
    """
    assert len(CRASHING_RECORD) == 53

    tls_info = read_hello(CRASHING_RECORD)

    assert tls_info is not None
    assert tls_info["extensions"] == [0x002B]
    assert tls_info["supported_versions"] == []


def test_the_input_the_go_fuzzer_wrote_is_64_bytes_and_produces_a_value():
    """The second seed of #617 reads two present bytes, and it raises no exception."""
    assert len(FUZZER_INPUT) == 64

    tls_info = read_hello(FUZZER_INPUT)

    assert tls_info is not None
    assert tls_info["handshake_type"] == "server_hello"
    assert tls_info["extensions"] == [12336, 0x002B]
    assert tls_info["supported_versions"] == [12336]


def test_the_well_formed_record_produces_the_version_the_server_selected():
    """The reader reads the whole record, so every crafted case below can fail."""
    tls_info = read_hello(WELL_FORMED_RECORD)

    assert tls_info is not None
    assert tls_info["supported_versions"] == [0x0304]
    assert tls_info["version"] == 0x0304


@pytest.mark.parametrize("name", sorted(CRAFTED_RECORDS))
def test_a_crafted_extension_header_produces_a_server_hello_and_raises_nothing(name):
    """A declared length that disagrees with the bytes present produces a value.

    The reader reads the fields the record holds before the extension block, so it
    produces a value on every cell of the grid. A cell that produced nothing would mean
    the builder wrote a record the reader stops on before it reaches the block.
    """
    tls_info = read_hello(CRAFTED_RECORDS[name])

    assert tls_info is not None, name
    assert tls_info["handshake_type"] == "server_hello", name
    assert tls_info["cipher"] == 0x1301, name


def test_a_block_length_past_the_end_of_the_record_produces_a_server_hello():
    """The extension block header declares more bytes than the record holds.

    `extensions_end` clamps on the record length, so the reader stops at the last byte
    the record holds. #617 names the clamp that this case measures.
    """
    block = extension(0x002B, 2, b"")
    record = server_hello_record(block, declared_block_length=0xFFFF)

    tls_info = read_hello(record)

    assert tls_info is not None
    assert tls_info["extensions"] == [0x002B]
    assert tls_info["supported_versions"] == []


def test_a_random_extension_block_produces_a_server_hello_and_raises_nothing():
    """Random bytes in the extension block reach every branch the reader holds.

    The grid above names each extension type once. A random block names a type the grid
    omits, and it declares a length no cell of the grid holds.
    """
    source = random.Random(SEED)
    produced = 0

    for _ in range(DRAWS):
        size = source.randrange(0, 64)
        block = bytes(source.getrandbits(8) for _ in range(size))
        tls_info = read_hello(server_hello_record(block))
        if tls_info is not None:
            produced += 1
            assert tls_info["handshake_type"] == "server_hello", block.hex()

    # The reader reads every field before the extension block, so it produces a value on
    # every draw. A lower count would mean the corpus stops short of the block.
    assert produced == DRAWS


def test_random_bytes_produce_nothing_or_a_server_hello_and_raise_nothing():
    """The reader reads arbitrary bytes and it raises no exception.

    A record shape reaches the extension loop, and random bytes reach the length guards
    that stand before it. The case therefore measures the guards and not the loop.
    """
    source = random.Random(SEED)
    read = 0

    for _ in range(DRAWS):
        size = source.randrange(0, 128)
        raw = bytes(source.getrandbits(8) for _ in range(size))
        tls_info = read_hello(raw)
        if tls_info is not None:
            read += 1
            assert tls_info["handshake_type"] == "server_hello", raw.hex()

    # A record shorter than 11 bytes produces nothing, and the draw range holds both
    # outcomes. A count of zero would mean the case measures the short guard alone.
    assert read > 0


@pytest.mark.parametrize("mask", [0xFF, 0x01, 0x80])
def test_one_corrupted_byte_of_a_well_formed_record_raises_nothing(mask):
    """A corruption of any one byte produces nothing or a ServerHello.

    The case turns one bit group of each byte in turn. A corrupted length field is the
    shape #617 names, and this case reaches every length field of the record.
    """
    silenced = 0

    for index in range(len(WELL_FORMED_RECORD)):
        mutated = bytearray(WELL_FORMED_RECORD)
        mutated[index] ^= mask
        tls_info = read_hello(bytes(mutated))
        if tls_info is None:
            silenced += 1
            continue
        assert tls_info["handshake_type"] == "server_hello", f"byte {index}"

    # `_parse_server_hello` returns None on one condition, which is a record shorter than
    # 11 bytes. A flip of one bit moves no length of the record, so this count holds at
    # zero for the reader as it stands. The count therefore states the shape of the
    # reader, and the assertion above each iteration is what measures the corruption.
    assert silenced == 0


@pytest.mark.parametrize("name", sorted(CRAFTED_RECORDS))
def test_the_library_entry_point_reads_a_crafted_record_and_raises_nothing(name, reader_calls):
    """`parse_tls_handshake` reaches the ServerHello reader on every crafted record.

    #617 records that the exception reached the caller of the library, because neither
    the reader nor its one caller holds an `except`. This case drives the entry point a
    caller reads.
    """
    tls_info = parse_tls_handshake(CRAFTED_RECORDS[name])

    assert tls_info is not None, name
    assert tls_info["type"] == "server_hello", name
    assert reader_calls.calls > 0, "The case reached no reader, so it measures nothing."


def test_the_library_entry_point_reads_both_seed_records_and_raises_nothing(reader_calls):
    """The entry point reads the two seeds of #617.

    `parse_tls_handshake` returns nothing on the 64-byte input, because the handshake
    length that input declares is 0x303030 and it passes the end of the record. The
    reader therefore runs on one of the two seeds, and the counter states that.
    """
    assert parse_tls_handshake(FUZZER_INPUT) is None

    tls_info = parse_tls_handshake(CRASHING_RECORD)

    assert tls_info is not None
    assert tls_info["supported_versions"] == []
    assert reader_calls.calls > 0
