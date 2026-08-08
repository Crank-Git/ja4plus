"""Hold one separating packet for each of the eleven JA4D and JA4D6 readings of #231.

No capture under `tests/foxio_vectors/` separates the two readings of any item, so the
conformance suite stays green whether the rulings are right or wrong. Each case below
builds the packet the vector set lacks. `docs/specs/foxio/JA4D.md` holds the rulings and
names the FoxIO source of each.
"""

from pathlib import Path

from scapy.all import IP, IPv6, UDP, Raw

from ja4plus.fingerprinters.ja4d import generate_ja4d
from ja4plus.fingerprinters.ja4d6 import generate_ja4d6

SOURCE_DIR = Path(__file__).parent.parent / "ja4plus" / "fingerprinters"

DHCP_MAGIC = b"\x63\x82\x53\x63"


def _dhcp_packet(options, sport=68, dport=67):
    """Return a Scapy packet that carries one DHCPv4 message.

    Args:
        options: The option bytes that follow the magic cookie, without the End option.
        sport: The UDP source port.
        dport: The UDP destination port.

    Returns:
        A Scapy packet.
    """
    payload = bytes(236) + DHCP_MAGIC + bytes(options) + bytes([255])
    return IP() / UDP(sport=sport, dport=dport) / Raw(load=payload)


def _dhcp_option(code, data=b""):
    """Return one DHCPv4 option as bytes.

    Args:
        code: The option code.
        data: The option data.

    Returns:
        The code byte, the length byte and the data.
    """
    return bytes([code, len(data)]) + bytes(data)


def _dhcpv6_option(code, data=b""):
    """Return one DHCPv6 option as bytes.

    Args:
        code: The option code.
        data: The option data.

    Returns:
        Two code bytes, two length bytes and the data.
    """
    return code.to_bytes(2, "big") + len(data).to_bytes(2, "big") + bytes(data)


def _dhcpv6_packet(payload, sport=546, dport=547):
    """Return a Scapy packet that carries one DHCPv6 message.

    Args:
        payload: The whole UDP payload, message type first.
        sport: The UDP source port.
        dport: The UDP destination port.

    Returns:
        A Scapy packet.
    """
    return IPv6() / UDP(sport=sport, dport=dport) / Raw(load=bytes(payload))


def _dhcpv6_message(msg_type, options=b""):
    """Return one DHCPv6 client message or server message.

    Args:
        msg_type: The message type byte.
        options: The option bytes.

    Returns:
        The message type, a three-byte transaction identifier and the options.
    """
    return bytes([msg_type, 0, 0, 1]) + bytes(options)


# --- D1 — the JA4D port set -------------------------------------------------------


def test_ja4d_reads_a_dhcp_message_on_the_proxy_dhcp_port():
    """Port 4011 reaches the reference, so it reaches this project.

    `epan/dissectors/packet-dhcp.c` sets `DHCP_UDP_PORT_RANGE "67-68,4011"`.
    """
    packet = _dhcp_packet(_dhcp_option(53, b"\x01"), sport=1234, dport=4011)
    assert generate_ja4d(packet) == "disco0000nn_00_00"


def test_ja4d_reads_no_dhcp_message_on_a_port_the_reference_omits():
    """Wireshark claims no DHCP on port 9999, so this project emits nothing there."""
    packet = _dhcp_packet(_dhcp_option(53, b"\x01"), sport=1234, dport=9999)
    assert generate_ja4d(packet) is None


# --- D2 — a BOOTP message that carries no option 53 -------------------------------


def test_ja4d_emits_nothing_for_a_bootp_message_that_holds_no_message_type():
    """Two references against one keep the present reading.

    `wireshark/source/packet-ja4.c:1498` sets the emit flag inside the option 53 block
    alone, so the dissector emits nothing. `zeek/ja4d/main.zeek:43-45` emits `00000`.
    """
    packet = _dhcp_packet(_dhcp_option(61, b"\x01\x02\x03"))
    assert generate_ja4d(packet) is None


# --- D3 — the domain character of JA4D --------------------------------------------


def test_ja4d_reads_no_domain_from_an_option_81_that_carries_no_name():
    """An empty Client FQDN gives `n`.

    The image caption reads `Has a Domain name (d) or No domain (n)`, and
    `wireshark/source/packet-ja4.c:1521` reads `dhcp.fqdn.name`.
    """
    options = _dhcp_option(53, b"\x01") + _dhcp_option(81, b"\x00\x00\x00")
    assert generate_ja4d(_dhcp_packet(options))[10] == "n"


def test_ja4d_reads_no_domain_from_a_truncated_option_81():
    """A length byte the payload does not honour gives `n`, not `d`.

    No parser trusts a length field it read from the packet. The option below claims ten
    bytes and the payload ends after one, so it carries no name.
    """
    payload = bytes(236) + DHCP_MAGIC + _dhcp_option(53, b"\x01") + bytes([81, 10, 0])
    packet = IP() / UDP(sport=68, dport=67) / Raw(load=payload)
    assert generate_ja4d(packet)[10] == "n"


def test_ja4d_reads_a_truncated_option_57_without_a_raise():
    """A truncated Maximum DHCP Message Size returns a value rather than an IndexError.

    The option claims two bytes and the payload ends after one. A parser that cannot read
    a packet returns nothing; it does not raise.
    """
    payload = bytes(236) + DHCP_MAGIC + _dhcp_option(53, b"\x01") + bytes([57, 2, 5])
    packet = IP() / UDP(sport=68, dport=67) / Raw(load=payload)
    assert generate_ja4d(packet)[5:9] == "0000"


def test_ja4d_reads_a_truncated_option_53_without_a_raise():
    """A truncated DHCP Message Type returns nothing rather than an IndexError."""
    payload = bytes(236) + DHCP_MAGIC + bytes([53, 1])
    packet = IP() / UDP(sport=68, dport=67) / Raw(load=payload)
    assert generate_ja4d(packet) is None


def test_ja4d_reads_a_domain_from_an_option_81_that_carries_a_name():
    """A Client FQDN that holds a name gives `d`."""
    options = _dhcp_option(53, b"\x01") + _dhcp_option(81, b"\x00\x00\x00host")
    assert generate_ja4d(_dhcp_packet(options))[10] == "d"


# --- D4 — a repeated option 57 ----------------------------------------------------


def test_ja4d_keeps_the_first_maximum_message_size():
    """The image gives subfield 2 four characters, so one option 57 decides it.

    `wireshark/source/packet-ja4.c:1508-1512` appends every occurrence, which gives an
    eight-digit subfield and an unreadable part a. This project declines that defect and
    keeps the first occurrence, which is the value the dissector writes first.
    """
    options = (
        _dhcp_option(53, b"\x01")
        + _dhcp_option(57, (1500).to_bytes(2, "big"))
        + _dhcp_option(57, (1200).to_bytes(2, "big"))
    )
    assert generate_ja4d(_dhcp_packet(options))[5:9] == "1500"


# --- D5 — a split option 55 -------------------------------------------------------


def test_ja4d_joins_every_parameter_request_list_occurrence():
    """RFC 3396 lets a long option 55 split, and part c holds the whole list.

    `wireshark/source/packet-ja4.c:1530-1534` appends every
    `dhcp.option.request_list_item`.
    """
    options = (
        _dhcp_option(53, b"\x01")
        + _dhcp_option(55, bytes([1, 3]))
        + _dhcp_option(55, bytes([6, 15]))
    )
    assert generate_ja4d(_dhcp_packet(options)).split("_")[2] == "1-3-6-15"


# --- D6 — the citation of the skip set --------------------------------------------


def test_the_two_dhcp_modules_cite_no_foxio_pull_request():
    """Neither pull request number reads from a checkout at the pinned commit.

    R9 of `docs/specs/foxio/JA4D.md` holds the FoxIO statement instead.
    """
    for name in ("ja4d.py", "ja4d6.py"):
        text = (SOURCE_DIR / name).read_text()
        assert "#267" not in text, "{} still cites FoxIO pull request 267".format(name)
        assert "#270" not in text, "{} still cites FoxIO pull request 270".format(name)


def test_the_ja4d_skip_set_cites_the_transcription():
    """The skip set names the rule that states it."""
    text = (SOURCE_DIR / "ja4d.py").read_text()
    assert "docs/specs/foxio/JA4D.md" in text
    assert "R9" in text


# --- D7 — the JA4D6 port set ------------------------------------------------------


def test_ja4d6_reads_a_dhcpv6_message_on_both_reference_ports():
    """`packet-dhcpv6.c` sets `UDP_PORT_DHCPV6_RANGE "546-547"`, and both ports read."""
    message = _dhcpv6_message(1)
    assert generate_ja4d6(_dhcpv6_packet(message, sport=546, dport=547)) is not None
    assert generate_ja4d6(_dhcpv6_packet(message, sport=547, dport=546)) is not None


def test_ja4d6_reads_no_dhcpv6_message_on_a_port_the_reference_omits():
    """Wireshark claims no DHCPv6 on port 9999, so this project emits nothing there."""
    message = _dhcpv6_message(1)
    assert generate_ja4d6(_dhcpv6_packet(message, sport=1234, dport=9999)) is None


# --- D8 — the DHCPv6 containers part b recurses into -------------------------------


def test_ja4d6_reads_the_options_inside_a_relay_message():
    """Option 9 carries a whole inner message, and part b holds its option codes.

    `wireshark/source/packet-ja4.c:1566` reads every `dhcpv6.option.type`, whatever
    nests it. A Relay-Forward message puts its options after a 34-byte header.
    """
    inner = _dhcpv6_message(1, _dhcpv6_option(1, b"ABCD") + _dhcpv6_option(6, b"\x00\x17\x00\x18"))
    outer = (
        bytes([12, 0])
        + bytes(16)
        + bytes(16)
        + _dhcpv6_option(18, b"eth0")
        + _dhcpv6_option(9, inner)
    )
    fingerprint = generate_ja4d6(_dhcpv6_packet(outer))
    assert fingerprint.startswith("rlayf")
    assert fingerprint.split("_")[1] == "18-9-1-6"


def test_ja4d6_reads_a_deeply_nested_relay_message_without_a_raise():
    """A crafted relay chain returns a value rather than a RecursionError.

    Every packet is hostile input, and D8 lets one relay message nest another. Python
    raises RecursionError near 1000 frames, so `_walk_options` bounds the depth.
    """
    # 1200 relay levels exceed the Python recursion limit and stay inside the 16-bit
    # UDP length field.
    chain_length = 1200
    message = _dhcpv6_message(1)
    for _ in range(chain_length):
        message = bytes([12, 0]) + bytes(16) + bytes(16) + _dhcpv6_option(9, message)
    fingerprint = generate_ja4d6(_dhcpv6_packet(message))
    assert fingerprint.startswith("rlayf")
    # The bound truncates the walk, so part b holds far fewer codes than the chain.
    assert len(fingerprint.split("_")[1].split("-")) < chain_length


# --- D9 — a repeated option 1 -----------------------------------------------------


def test_ja4d6_keeps_the_first_client_duid_length():
    """`wireshark/source/packet-ja4.c:1547-1549` reads the length while it is unset."""
    options = _dhcpv6_option(1, bytes(14)) + _dhcpv6_option(1, bytes(10))
    fingerprint = generate_ja4d6(_dhcpv6_packet(_dhcpv6_message(1, options)))
    assert fingerprint[5:9] == "0014"


# --- D10 — a split option 6 -------------------------------------------------------


def test_ja4d6_joins_every_option_request_occurrence():
    """`wireshark/source/packet-ja4.c:1574-1578` appends every requested option code."""
    options = _dhcpv6_option(6, b"\x00\x17\x00\x18") + _dhcpv6_option(6, b"\x00\x11\x00\x27")
    fingerprint = generate_ja4d6(_dhcpv6_packet(_dhcpv6_message(1, options)))
    assert fingerprint.split("_")[2] == "23-24-17-39"


# --- D11 — DHCPv6 message type 0 --------------------------------------------------


def test_ja4d6_emits_a_value_for_message_type_zero():
    """`wireshark/source/packet-ja4.c:1537-1538` emits for any `dhcpv6.msgtype` field.

    DHCPv6 defines no message type 0, so the five-digit form of R15 reports it.
    """
    fingerprint = generate_ja4d6(_dhcpv6_packet(_dhcpv6_message(0)))
    assert fingerprint == "000000000nn_00_00"
