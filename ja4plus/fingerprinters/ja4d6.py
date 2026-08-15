"""
JA4D6 DHCPv6 Fingerprinting implementation.

`docs/specs/foxio/JA4D.md` holds the transcription of `technical_details/JA4D6.png` and
the rules R14 to R22 that this module builds.

Format: {type:5}{size:4}{ip:1}{fqdn:1}_{options}_{request_list}

Every part reads the DHCPv6 options at any nesting depth. D1 and D2 of #271 rule that
reading, because `wireshark/source/packet-ja4.c:967-969` walks every field of the whole
dissection tree and matches on the field name alone.

Section a:
- type:  5-char abbreviation of msg-type (see DHCPV6_MESSAGE_TYPES)
         unknown -> "%05u"
         The outer message type alone. D3 of #271 declines the concatenation the
         dissector writes for a relay message.
- size:  byte-length of the DUID payload inside option 1 (Client Identifier).
         "%04d", capped at 9999, "0000" if absent.
- ip:    'i' if option 4 (IATA) is present, else 'n'
- fqdn:  'd' if option 39 (Client FQDN) is present, else 'n'

Section b: ALL DHCPv6 option types in PRESENCE ORDER (no exclusions).
           This includes nested options inside IA_NA / IA_PD / etc. and the options
           of the inner message that option 9, Relay Message, carries. It matches
           the Wireshark dissector's iteration of all dhcpv6.option.type fields.
           Default "00".

Section c: items from option 6 (Option Request) in original order. Default "00".
"""

# This import makes every annotation a string. No annotation therefore evaluates at
# import time, and a forward reference needs no quotation mark.
from __future__ import annotations

import logging
from typing import Any

from scapy.all import UDP, Packet

from ja4plus.utils.tunnels import innermost_layer
from ja4plus.fingerprinters.base import BaseFingerprinter

logger = logging.getLogger(__name__)

# DHCPv6 message type to 5-char abbreviation (RFC 8415 + extensions).
DHCPV6_MESSAGE_TYPES = {
    1: "solct",  # SOLICIT
    2: "advrt",  # ADVERTISE
    3: "reqst",  # REQUEST
    4: "confm",  # CONFIRM
    5: "renew",  # RENEW
    6: "rebnd",  # REBIND
    7: "reply",  # REPLY
    8: "relse",  # RELEASE
    9: "decln",  # DECLINE
    10: "recon",  # RECONFIGURE
    11: "inreq",  # INFORMATION-REQUEST
    12: "rlayf",  # RELAY-FORW
    13: "rlayr",  # RELAY-REPL
    14: "query",  # LEASEQUERY
    15: "qrply",  # LEASEQUERY-REPLY
    16: "qdone",  # LEASEQUERY-DONE
    17: "qdata",  # LEASEQUERY-DATA
    18: "rereq",  # RECONFIGURE-REQUEST
    19: "rrply",  # RECONFIGURE-REPLY
    20: "v4qry",  # DHCPV4-QUERY
    21: "v4res",  # DHCPV4-RESPONSE
    22: "acqry",  # ACTIVELEASEQUERY
    23: "sttls",  # STARTTLS
    24: "bdudp",  # BNDUDP
    25: "brply",  # BNDREPLY
    26: "poreq",  # POOLREQ
    27: "pores",  # POOLRESP
    28: "urqst",  # UPDATEREQ
    29: "ureqa",  # UPDATEREQALL
    30: "udone",  # UPDATEDONE
    31: "conne",  # CONNECT
    32: "connr",  # CONNECTREPLY
    33: "dconn",  # DISCONNECT
    34: "state",  # STATE
    35: "conta",  # CONTACT
    36: "arinf",  # ADDR-REG-INFORM
    37: "arrep",  # ADDR-REG-REPLY
}

# DHCPv6 options that carry nested DHCPv6 options after a fixed-size header.
# wireshark/source/packet-ja4.c:1566 reads every "dhcpv6.option.type" field, whatever
# nests it, so part b reaches a nested option code. Each header length comes from
# RFC 8415. Option 17, Vendor-specific Information, holds no entry: its sub-options
# carry an enterprise number and Wireshark reports them under another field name, so
# D8 of docs/specs/foxio/JA4D.md rules on nothing there.
_DHCPV6_NESTED_OPTIONS = {
    3: 12,  # IA_NA:  IAID(4) + T1(4) + T2(4) = 12 bytes header
    4: 4,  # IA_TA:  IAID(4) = 4 bytes header
    25: 12,  # IA_PD:  IAID(4) + T1(4) + T2(4) = 12 bytes header
    5: 24,  # IA Address (within IA_NA/IA_TA): addr(16)+pref-lt(4)+valid-lt(4) = 24
    26: 25,  # IA Prefix (within IA_PD): pref-lt(4)+valid-lt(4)+plen(1)+prefix(16) = 25
}

# Option 9, Relay Message, carries a whole inner DHCPv6 message rather than a fixed
# header and sub-options. D8 of docs/specs/foxio/JA4D.md rules that part b reads the
# options of that inner message.
_DHCPV6_RELAY_MESSAGE_OPTION = 9

# RELAY-FORW and RELAY-REPL put their options after msg-type(1) + hop-count(1) +
# link-address(16) + peer-address(16). Every other message type puts its options after
# msg-type(1) + transaction-id(3).
_DHCPV6_RELAY_TYPES = {12, 13}
_DHCPV6_RELAY_HEADER_LEN = 34
_DHCPV6_MESSAGE_HEADER_LEN = 4

# A crafted message nests one container inside another without limit, and Python raises
# RecursionError near 1000 frames. A parser that cannot read a packet returns nothing,
# so the walk stops at this depth. No FoxIO vector nests a container at all.
_DHCPV6_MAX_NESTING_DEPTH = 32


def _options_offset(data: bytes, start: int, end: int) -> int:
    """Return the offset of the first option of the DHCPv6 message at ``start``.

    Args:
        data: The bytes that hold the message.
        start: The offset of the message type byte.
        end: The offset one past the last byte of the message.

    Returns:
        The offset of the first option. A relay message reports a longer header.
    """
    if start >= end:
        return start + _DHCPV6_MESSAGE_HEADER_LEN
    if data[start] in _DHCPV6_RELAY_TYPES:
        return start + _DHCPV6_RELAY_HEADER_LEN
    return start + _DHCPV6_MESSAGE_HEADER_LEN


def _walk_options(data: bytes, start: int, end: int, found: dict[str, Any], depth: int = 0) -> None:
    """Read every DHCPv6 option between ``start`` and ``end`` into ``found``.

    Args:
        data: The bytes that hold the message.
        start: The offset of the first option.
        end: The offset one past the last option byte.
        found: The record that receives the six inputs, in presence order.
        depth: The count of containers already entered.

    Returns:
        None. A container deeper than _DHCPV6_MAX_NESTING_DEPTH contributes no input.
    """
    if depth > _DHCPV6_MAX_NESTING_DEPTH:
        return
    pos = start
    while pos + 4 <= end:
        opt_code = (data[pos] << 8) | data[pos + 1]
        opt_len = (data[pos + 2] << 8) | data[pos + 3]
        pos += 4
        if pos + opt_len > end:
            break
        found["options_in_order"].append(opt_code)
        _read_subfield_option(data, pos, opt_len, opt_code, found)

        if opt_code == _DHCPV6_RELAY_MESSAGE_OPTION:
            inner_end = pos + opt_len
            inner_start = _options_offset(data, pos, inner_end)
            if inner_start <= inner_end:
                _walk_options(data, inner_start, inner_end, found, depth + 1)
        elif opt_code in _DHCPV6_NESTED_OPTIONS:
            header_len = _DHCPV6_NESTED_OPTIONS[opt_code]
            inner_start = pos + header_len
            inner_end = pos + opt_len
            if inner_start <= inner_end:
                _walk_options(data, inner_start, inner_end, found, depth + 1)

        pos += opt_len


def _read_subfield_option(
    data: bytes, pos: int, opt_len: int, opt_code: int, found: dict[str, Any]
) -> None:
    """Read one DHCPv6 option into the four subfield inputs of ``found``.

    Args:
        data: The bytes that hold the message.
        pos: The offset of the option data.
        opt_len: The length of the option data.
        opt_code: The option code.
        found: The record that receives the four inputs.

    Returns:
        None. An option code outside the four contributes no input.
    """
    if opt_code == 1 and not found["has_duid"]:  # Client Identifier
        # D9 of docs/specs/foxio/JA4D.md: wireshark/source/packet-ja4.c:1547-1549
        # reads the length while the subfield is still empty, so the first
        # occurrence decides it.
        found["duid_len"] = opt_len
        found["has_duid"] = True
    elif opt_code == 4:  # IA_TA
        found["has_iata"] = True
    elif opt_code == 39:  # Client FQDN
        found["has_fqdn"] = True
    elif opt_code == 6:  # Option Request
        # D10 of docs/specs/foxio/JA4D.md: wireshark/source/packet-ja4.c:1574-1578
        # appends every requested option code, so a split option 6 reaches part c
        # whole. Each code holds two bytes, big-endian.
        for i in range(pos, pos + opt_len - 1, 2):
            found["request_list"].append((data[i] << 8) | data[i + 1])


def _parse_dhcpv6_payload(payload: bytes) -> dict[str, Any] | None:
    """Return the JA4D6 inputs the DHCPv6 UDP payload carries.

    One walk reads all six inputs, so each one reaches an inner relay message. D1 and D2
    of docs/specs/foxio/JA4D.md rule that reading, and #271 records it.

    Args:
        payload: The whole UDP payload, message type first.

    Returns:
        A map of the six inputs, or None when the payload is shorter than the header.
    """
    if len(payload) < 4:
        return None

    end = len(payload)
    # A relay message puts its options after a 34-byte header, and every other message
    # type puts them after a 4-byte header.
    options_start = _options_offset(payload, 0, end)

    found: dict[str, Any] = {
        # D3 of #271: subfield 1 holds the outer message type alone. The dissector
        # appends a name for every dhcpv6.msgtype field, which gives a relay message a
        # sixteen-character part a and breaks the eleven characters R2 states.
        "msg_type": payload[0],
        "options_in_order": [],
        "duid_len": 0,
        "has_duid": False,
        "has_iata": False,
        "has_fqdn": False,
        "request_list": [],
    }
    _walk_options(payload, options_start, end, found)
    return found


def _build_option_list(options_in_order: list[int]) -> str:
    if not options_in_order:
        return "00"
    return "-".join(str(c) for c in options_in_order)


def _build_request_list(request_list: list[int]) -> str:
    if not request_list:
        return "00"
    return "-".join(str(c) for c in request_list)


def generate_ja4d6(packet: Packet) -> str | None:
    """
    Generate a JA4D6 fingerprint from a packet.

    Args:
        packet: A Scapy packet potentially containing a DHCPv6 message

    Returns:
        A JA4D6 fingerprint string or None if the packet is not applicable
    """
    # A tunnel carries its own UDP header, and `getlayer` counts from the outside. The
    # DHCPv6 message is the innermost one, so a reader that takes the outer header reads
    # a tunnel port, and the port test below then refuses the packet. The defect shape of
    # this method is therefore an absent value and never a wrong one.
    # `packet_utils.packet_endpoints` reads the same layer, so one result names one port
    # pair.
    udp = innermost_layer(packet, (UDP,))
    if udp is None:
        return None

    # Wireshark hands the JA4 dissector a DHCPv6 message only on the ports its DHCPv6
    # dissector claims. epan/dissectors/packet-dhcpv6.c sets
    # UDP_PORT_DHCPV6_RANGE "546-547" at Wireshark 4.4.2, which
    # .claude/rules/external-apis.md pins. D7 of docs/specs/foxio/JA4D.md rules that this
    # project reads the same two ports.
    if 546 not in (int(udp.sport), int(udp.dport)) and 547 not in (int(udp.sport), int(udp.dport)):
        return None

    payload = bytes(udp.payload)
    parsed = _parse_dhcpv6_payload(payload)
    if parsed is None:
        return None

    # D11 of docs/specs/foxio/JA4D.md: wireshark/source/packet-ja4.c:1537-1538 emits a
    # value for any dhcpv6.msgtype field, and DHCPv6 defines no message type 0, so the
    # five-digit form of R15 reports it.
    msg_type = parsed["msg_type"]

    msg_type_str = DHCPV6_MESSAGE_TYPES.get(msg_type, f"{msg_type:05d}")
    duid_len = min(parsed["duid_len"], 9999)
    size_str = f"{duid_len:04d}"
    ip_flag = "i" if parsed["has_iata"] else "n"
    fqdn_flag = "d" if parsed["has_fqdn"] else "n"

    section_a = f"{msg_type_str}{size_str}{ip_flag}{fqdn_flag}"
    section_b = _build_option_list(parsed["options_in_order"])
    section_c = _build_request_list(parsed["request_list"])

    return f"{section_a}_{section_b}_{section_c}"


class JA4D6Fingerprinter(BaseFingerprinter):
    """Fingerprinter for JA4D6 (DHCPv6)."""

    def process_packet(self, packet: Packet) -> str | None:
        fingerprint = generate_ja4d6(packet)
        if fingerprint:
            self.add_fingerprint(fingerprint, packet)
        return fingerprint

    def cleanup_connection(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str
    ) -> None:
        """No-op: JA4D6 is stateless (per-packet fingerprinter)."""
