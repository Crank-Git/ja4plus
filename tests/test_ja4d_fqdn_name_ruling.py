"""The rule that reads the JA4D domain character from a name, which #615 records.

`ja4plus/fingerprinters/ja4d.py:165` gives `d` to an option 81 that carries a domain
name, and it gives `n` to an option 81 that carries none. Two FoxIO implementations split
on that reading. The Wireshark dissector tests the field `dhcp.fqdn.name`, and the Zeek
script tests the presence of the option.

**A ruling that lives only in a closed issue is a ruling the next reader reverses by
accident.** These cases hold the register row against the code it describes. A change of
line 165 to a presence test fails a case here, and so does a deletion of the row.

`Crank-Git/ja4plus-go#371` holds the ruling of 2026-08-14, and the port reads the name the
same way. A reversal therefore changes both repositories.

`tests/test_ja4d_decisions.py` holds D3 of #231, which is the reading this row records.
"""

from pathlib import Path
import re

from scapy.all import IP, UDP, Raw, rdpcap

from ja4plus.fingerprinters.ja4d import _DHCP_FQDN_NAME_OFFSET, generate_ja4d

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

# The one capture of the corpus that carries a DHCPv4 message.
DHCP_VECTOR = VECTORS / "dhcp.pcapng"

# The heading of the register, and the line that closes it.
# `tests/test_ja4ts_delay_rounding_ruling.py` reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The domain character of JA4D when option 81 carries no name"

DHCP_MAGIC = b"\x63\x82\x53\x63"

# The position of the domain character inside a JA4D value. Part a holds eleven
# characters, and the domain character is the last of them.
DOMAIN_POSITION = 10

# The three bytes RFC 4702 puts before the domain name of option 81.
FQDN_HEADER = b"\x00\x00\x00"

# The count of DHCPv4 messages of the corpus, and the count of option 81 occurrences.
CORPUS_MESSAGES = 4
CORPUS_OPTION_81_OCCURRENCES = 0


def _register_row() -> str:
    """Return the register row that records the rule.

    Returns:
        The whole text of the row.

    Raises:
        AssertionError: The page holds no register, or the register holds no such row.
    """
    page = SPECIFICATION.read_text(encoding="utf-8")
    assert REGISTER_HEADING in page, f"the specification holds no {REGISTER_HEADING!r}"
    section = page[page.index(REGISTER_HEADING) : page.index(REGISTER_END)]
    for line in section.splitlines():
        if not line.startswith("|") or REGISTER_SEPARATOR.match(line):
            continue
        if line.split("|")[1].strip() == RULING_ITEM:
            return line
    raise AssertionError(f"the divergence register holds no row named {RULING_ITEM!r}")


def _dhcp_option(code: int, data: bytes = b"") -> bytes:
    """Return one DHCPv4 option as bytes.

    Args:
        code: The option code.
        data: The option data.

    Returns:
        The code byte, the length byte and the data.
    """
    return bytes([code, len(data)]) + bytes(data)


def _dhcp_packet(options: bytes) -> object:
    """Return one Scapy packet that carries a DHCPv4 message.

    Args:
        options: The option bytes that follow the magic cookie, without the End option.

    Returns:
        The packet.
    """
    payload = bytes(236) + DHCP_MAGIC + bytes(options) + bytes([255])
    return IP() / UDP(sport=68, dport=67) / Raw(load=payload)


def _domain_character(option_81: bytes | None) -> str:
    """Return the domain character of a DHCPDISCOVER that carries the option.

    Args:
        option_81: The data of option 81, or None for a message that omits the option.

    Returns:
        The one character at position 10 of the JA4D value.
    """
    options = _dhcp_option(53, b"\x01")
    if option_81 is not None:
        options += _dhcp_option(81, option_81)
    value = generate_ja4d(_dhcp_packet(options))
    assert value is not None, "the message produced no JA4D value"
    return value[DOMAIN_POSITION]


def _corpus_option_81_occurrences() -> int:
    """Return the count of option 81 occurrences of the one DHCPv4 capture.

    Returns:
        The count over every DHCPv4 message of `tests/foxio_vectors/dhcp.pcapng`.
    """
    occurrences = 0
    for packet in rdpcap(str(DHCP_VECTOR)):
        if UDP not in packet:
            continue
        raw = bytes(packet[UDP].payload)
        if len(raw) < 240 or raw[236:240] != DHCP_MAGIC:
            continue
        position = 240
        while position < len(raw):
            code = raw[position]
            position += 1
            if code == 255:
                break
            if code == 0:
                continue
            if position >= len(raw):
                break
            length = raw[position]
            position += 1
            if position + length > len(raw):
                break
            position += length
            if code == 81:
                occurrences += 1
    return occurrences


def test_the_register_holds_a_row_for_the_rule() -> None:
    """The divergence register holds the row that records the rule."""
    assert RULING_ITEM in _register_row()


def test_the_register_states_the_line_that_reads_the_name() -> None:
    """The row names the line of `ja4plus` that reads the name, and the offset."""
    row = _register_row()
    assert "`ja4plus/fingerprinters/ja4d.py:165`" in row
    assert "`_DHCP_FQDN_NAME_OFFSET = 3`" in row


def test_the_register_cites_each_of_the_two_references() -> None:
    """The row cites the Wireshark dissector and the Zeek script, on each condition."""
    row = _register_row()
    absent = [
        citation
        for citation in (
            "`wireshark/source/packet-ja4.c:1521`",
            "`wireshark/source/packet-ja4.c:1522`",
            "`zeek/ja4d/main.zeek:73`",
            "`zeek/ja4d/main.zeek:74`",
        )
        if citation not in row
    ]
    assert absent == [], f"the row cites none of these references: {absent}"


def test_the_register_quotes_the_caption_of_the_image() -> None:
    """The row quotes the caption that decides the character, and it names R7."""
    row = _register_row()
    assert "`Has a Domain name (d) or No domain (n)`" in row
    assert "R7 of `docs/specs/foxio/JA4D.md`" in row


def test_the_register_names_the_issue_that_holds_the_ruling() -> None:
    """The row names the issue of the port that holds the ruling of 2026-08-14."""
    row = _register_row()
    assert "`Crank-Git/ja4plus-go#371`" in row
    assert "2026-08-14" in row


def test_the_register_states_the_count_the_corpus_holds() -> None:
    """The row states the DHCPv4 message count and the option 81 count of the corpus."""
    row = _register_row()
    assert f"{CORPUS_MESSAGES} DHCPv4 messages" in row
    assert f"{CORPUS_OPTION_81_OCCURRENCES} occurrences of option 81" in row


def test_the_offset_holds_the_three_bytes_that_precede_the_name() -> None:
    """RFC 4702 puts one flags byte and two rcode bytes before the domain name."""
    assert _DHCP_FQDN_NAME_OFFSET == len(FQDN_HEADER)


def test_an_absent_option_81_gives_no_domain() -> None:
    """A message that carries no option 81 gives `n`."""
    assert _domain_character(None) == "n"


def test_an_empty_option_81_gives_no_domain() -> None:
    """An option 81 of zero bytes gives `n`, and a presence test gives `d`."""
    assert _domain_character(b"") == "n"


def test_an_option_81_that_carries_the_header_alone_gives_no_domain() -> None:
    """An option 81 of three bytes gives `n`, and a presence test gives `d`."""
    assert _domain_character(FQDN_HEADER) == "n"


def test_an_option_81_that_carries_one_name_byte_gives_a_domain() -> None:
    """An option 81 of four bytes gives `d`, because the fourth byte is a name byte."""
    assert _domain_character(FQDN_HEADER + b"\x00") == "d"


def test_an_option_81_that_carries_a_name_gives_a_domain() -> None:
    """An option 81 of seven bytes gives `d`."""
    assert _domain_character(FQDN_HEADER + b"host") == "d"


def test_a_repeated_option_81_reads_the_occurrence_that_carries_the_name() -> None:
    """One occurrence that carries a name decides the character."""
    options = (
        _dhcp_option(53, b"\x01")
        + _dhcp_option(81, FQDN_HEADER)
        + _dhcp_option(81, FQDN_HEADER + b"host")
    )
    value = generate_ja4d(_dhcp_packet(options))
    assert value is not None
    assert value[DOMAIN_POSITION] == "d"


def test_the_corpus_separates_the_two_readings_on_no_message() -> None:
    """The one DHCPv4 capture of the corpus holds no option 81."""
    assert DHCP_VECTOR.exists()
    assert _corpus_option_81_occurrences() == CORPUS_OPTION_81_OCCURRENCES


def test_every_ja4d_value_of_the_corpus_gives_no_domain() -> None:
    """The four DHCPv4 messages of the corpus each give `n` under either reading."""
    values = [generate_ja4d(packet) for packet in rdpcap(str(DHCP_VECTOR))]
    values = [value for value in values if value is not None]
    assert len(values) == CORPUS_MESSAGES
    assert [value[DOMAIN_POSITION] for value in values] == ["n"] * CORPUS_MESSAGES
