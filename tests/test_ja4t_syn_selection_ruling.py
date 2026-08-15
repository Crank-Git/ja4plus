"""The JA4T SYN selection the divergence register records under #603.

`ja4plus/fingerprinters/ja4t.py:159` tests the SYN bit and the ACK bit, and it reads no
other flag. Three FoxIO references split on that selection. Rust tests the two bits, and
the Zeek script and the Wireshark dissector each test the whole flag byte against `0x02`.

**A ruling that lives only in a closed issue is a ruling the next reader reverses by
accident.** These cases hold the register row against the code it describes. A change of
line 159 to an equality test fails a case here, and so does a deletion of the row.

`Crank-Git/ja4plus-go#126` holds the ruling of 2026-08-13, and the port holds the same bit
test. A reversal therefore changes both repositories.
"""

from pathlib import Path
import re

from scapy.all import IP, TCP, rdpcap

from ja4plus.fingerprinters.ja4t import JA4TFingerprinter

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

# The heading of the register, and the line that closes it. `tests/test_alpn_ruling_register.py`
# reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The flag test that selects the SYN of a JA4T value"

# The flag byte of a SYN that also sets `CWR` and `ECE`. `rust/ja4/src/tcp.rs:154` asserts
# `is_initial_syn(0xC2)`, and the two references that test for equality decline it.
ECN_SYN = 0xC2

# Each capture of the corpus that carries such a SYN, and the JA4T value it gives. The row
# of the register states both values, so a reader compares the two records.
MEASURED = (
    ("gre-sample.pcap", "5744_2-4-8-1-3_1436_00"),
    ("macos_tcp_flags.pcap", "65535_2-1-3-1-1-8-4-0-0_1460_6"),
)


def _register_row() -> str:
    """Return the register row that records the SYN selection.

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


def _syn(flags: int, sport: int = 54321) -> object:
    """Return one TCP packet that carries the flag byte and one Window Scale option.

    Args:
        flags: The TCP flag byte.
        sport: The source port, which parts one connection from another.

    Returns:
        The packet.
    """
    return IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
        sport=sport, dport=443, flags=flags, window=65535, options=[("WScale", 7)]
    )


def test_the_register_holds_a_row_for_the_syn_selection() -> None:
    """The divergence register holds the row that records the flag test."""
    assert RULING_ITEM in _register_row()


def test_the_register_states_the_line_that_holds_the_flag_test() -> None:
    """The row names the line of `ja4plus` that tests the two bits."""
    assert "`ja4plus/fingerprinters/ja4t.py:159`" in _register_row()


def test_the_register_cites_each_of_the_three_references() -> None:
    """The row cites the Rust file, the Zeek script and the Wireshark dissector."""
    row = _register_row()
    absent = [
        citation
        for citation in (
            "`rust/ja4/src/tcp.rs:146`",
            "`rust/ja4/src/tcp.rs:154`",
            "`zeek/ja4t/main.zeek:126`",
            "`wireshark/source/packet-ja4.c:1266`",
        )
        if citation not in row
    ]
    assert absent == [], f"the row cites none of these references: {absent}"


def test_the_register_names_the_issue_that_holds_the_ruling() -> None:
    """The row names the issue of the port that holds the ruling of 2026-08-13."""
    row = _register_row()
    assert "`Crank-Git/ja4plus-go#126`" in row
    assert "2026-08-13" in row


def test_a_syn_that_sets_the_two_congestion_flags_produces_a_value() -> None:
    """A SYN whose flag byte is `0xC2` produces a JA4T value."""
    assert JA4TFingerprinter().process_packet(_syn(ECN_SYN)) is not None


def test_a_syn_that_sets_no_other_flag_produces_a_value() -> None:
    """A SYN whose flag byte is `0x02` produces a JA4T value."""
    assert JA4TFingerprinter().process_packet(_syn(0x02)) is not None


def test_a_syn_that_sets_the_two_congestion_flags_produces_the_value_of_a_plain_syn() -> None:
    """The two congestion flags change no part of the JA4T value."""
    plain = JA4TFingerprinter().process_packet(_syn(0x02))
    marked = JA4TFingerprinter().process_packet(_syn(ECN_SYN))
    assert plain == marked


def test_a_syn_ack_produces_no_value() -> None:
    """A packet that carries the ACK bit beside the SYN bit produces no JA4T value."""
    assert JA4TFingerprinter().process_packet(_syn(0x12)) is None


def test_the_corpus_holds_two_syn_packets_that_set_the_two_congestion_flags() -> None:
    """Two SYN packets of the vector corpus carry the flag byte `0xC2`."""
    captures = sorted(
        name.name
        for name in list(VECTORS.glob("*.pcap")) + list(VECTORS.glob("*.pcapng"))
        if any(
            packet.haslayer(TCP) and int(packet[TCP].flags) == ECN_SYN
            for packet in rdpcap(str(name))
        )
    )
    assert captures == sorted(name for name, _ in MEASURED)


def test_each_marked_syn_of_the_corpus_gives_the_value_the_register_states() -> None:
    """Each capture that holds such a SYN gives the JA4T value the register row states."""
    row = _register_row()
    for name, expected in MEASURED:
        fingerprinter = JA4TFingerprinter()
        values = [
            fingerprinter.process_packet(packet)
            for packet in rdpcap(str(VECTORS / name))
            if packet.haslayer(TCP) and int(packet[TCP].flags) == ECN_SYN
        ]
        assert values == [expected], f"{name} gives {values}"
        assert f"`{expected}`" in row, f"the row states no value for {name}"
