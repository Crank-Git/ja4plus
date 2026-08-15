"""
JA4D DHCP Fingerprinting implementation.

Format: {msg_type}{max_msg_size}{request_ip}{fqdn}_{option_list}_{param_list}

Section a: 5-char message type abbreviation + 4-digit max message size +
           'i'/'n' for requested IP + 'd'/'n' for FQDN
Section b: DHCP options present (hyphen-separated decimal), skipping 53/255/50/81
Section c: Parameter Request List contents from option 55 (hyphen-separated decimal)
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

# DHCP message type (option 53) to 5-character abbreviation.
DHCP_MESSAGE_TYPES = {
    1: "disco",  # DHCPDISCOVER
    2: "offer",  # DHCPOFFER
    3: "reqst",  # DHCPREQUEST
    4: "decln",  # DHCPDECLINE
    5: "dpack",  # DHCPACK
    6: "dpnak",  # DHCPNAK
    7: "relse",  # DHCPRELEASE
    8: "infor",  # DHCPINFORM
    9: "frenw",  # DHCPFORCERENEW
    10: "lqery",  # DHCPLEASEQUERY
    11: "lunas",  # DHCPLEASEUNASSIGNED
    12: "lunkn",  # DHCPLEASEUNKNOWN
    13: "lactv",  # DHCPLEASEACTIVE
    14: "blklq",  # DHCPBULKLEASEQUERY
    15: "lqdon",  # DHCPLEASEQUERYDONE
    16: "actlq",  # DHCPACTIVELEASEQUERY
    17: "lqsta",  # DHCPLEASEQUERYSTATUS
    18: "dhtls",  # DHCPTLS
}

# R9 of docs/specs/foxio/JA4D.md holds the FoxIO statement of this set. The image
# caption names codes 50, 53, 81 and 255, and zeek/ja4d/consts.zeek:25-30 names the same
# four. R10 adds the Pad option, code 0, on the dissector alone, and R10 stays uncertain.
# The End option, code 255, breaks the parse loop and never reaches this set.
DHCP_SKIP_OPTIONS = {0, 53, 50, 81}

# DHCP magic cookie
_DHCP_MAGIC = b"\x63\x82\x53\x63"

# Wireshark hands the JA4 dissector a DHCP message only on the ports its DHCP dissector
# claims. epan/dissectors/packet-dhcp.c sets DHCP_UDP_PORT_RANGE "67-68,4011" at
# Wireshark 4.4.2, which .claude/rules/external-apis.md pins.
# Port 4011 carries Proxy DHCP, and D1 of docs/specs/foxio/JA4D.md rules that this
# project reads the same three ports.
_DHCP_PORTS = {67, 68, 4011}

# RFC 4702 puts the domain name of option 81 after one flags byte and two rcode bytes.
_DHCP_FQDN_NAME_OFFSET = 3


def build_option_list(option_codes: list[int]) -> str:
    """
    Format DHCP option codes as hyphen-separated decimals, skipping
    options in DHCP_SKIP_OPTIONS. Returns '00' if nothing remains.

    Args:
        option_codes: list of integer option codes in wire order

    Returns:
        Hyphen-separated string of option codes, or '00'
    """
    parts = [str(code) for code in option_codes if code not in DHCP_SKIP_OPTIONS]
    return "-".join(parts) if parts else "00"


def build_param_list(params: list[int]) -> str:
    """
    Format the Parameter Request List (option 55) as hyphen-separated
    decimals. Returns '00' if empty.

    Args:
        params: list of integer parameter codes

    Returns:
        Hyphen-separated string, or '00'
    """
    if not params:
        return "00"
    return "-".join(str(p) for p in params)


def _parse_dhcp_options(raw_payload: bytes) -> dict[str, Any] | None:
    """
    Parse DHCP options from a raw UDP payload (BOOTP + magic cookie + options).

    Returns a dict with keys:
        msg_type, max_msg_size, has_request_ip, has_fqdn,
        option_codes (in wire order), param_list
    or None if the payload doesn't look like a valid DHCP message.
    """
    # BOOTP fixed header is 236 bytes; magic cookie is 4 bytes
    header_size = 236 + 4
    if len(raw_payload) < header_size:
        return None

    # Verify magic cookie
    if raw_payload[236:240] != _DHCP_MAGIC:
        return None

    msg_type = 0
    max_msg_size = 0
    has_max_msg_size = False
    has_request_ip = False
    has_fqdn = False
    option_codes: list[int] = []
    param_list: list[int] = []

    pos = 240  # start of options
    while pos < len(raw_payload):
        opt_code = raw_payload[pos]
        pos += 1

        if opt_code == 255:  # End marker — terminate; do not record
            break
        if opt_code == 0:  # Pad
            continue

        if pos >= len(raw_payload):
            break
        opt_len = raw_payload[pos]
        pos += 1

        # A truncated option claims more bytes than the payload holds. The slice below
        # would shorten silently, and a later read of opt_data[1] would raise. No parser
        # trusts a length field it read from the packet, so the parse stops here.
        # ja4d6.py:143-144 applies the same guard to a DHCPv6 option.
        if pos + opt_len > len(raw_payload):
            break

        opt_data = raw_payload[pos : pos + opt_len]
        pos += opt_len

        option_codes.append(opt_code)

        if opt_code == 53 and opt_len >= 1:  # Message Type
            msg_type = opt_data[0]
        elif opt_code == 57 and opt_len >= 2 and not has_max_msg_size:  # Max Message Size
            # D4 of docs/specs/foxio/JA4D.md: the image gives subfield 2 four characters,
            # so one occurrence decides it. The dissector appends every occurrence, which
            # gives an eight-digit subfield, and this project declines that defect.
            max_msg_size = (opt_data[0] << 8) | opt_data[1]
            has_max_msg_size = True
        elif opt_code == 50:  # Requested IP Address
            has_request_ip = True
        elif opt_code == 81:  # Client FQDN
            # D3 of docs/specs/foxio/JA4D.md: the image caption reads `Has a Domain name
            # (d) or No domain (n)`, so the name decides the character and not the
            # option. An option 81 that carries no name therefore gives `n`.
            has_fqdn = has_fqdn or len(opt_data) > _DHCP_FQDN_NAME_OFFSET
        elif opt_code == 55:  # Parameter Request List
            # D5 of docs/specs/foxio/JA4D.md: RFC 3396 lets a long option 55 split across
            # several occurrences, and part c holds the whole list.
            param_list.extend(opt_data)

    # D2 of docs/specs/foxio/JA4D.md: a BOOTP message that carries no option 53 produces
    # no JA4D value. wireshark/source/packet-ja4.c:1498 sets the emit flag inside the
    # option 53 block alone, and zeek/ja4d/main.zeek:43-45 emits `00000`. Two references
    # against one keep this reading.
    if msg_type == 0:
        return None

    return {
        "msg_type": msg_type,
        "max_msg_size": max_msg_size,
        "has_request_ip": has_request_ip,
        "has_fqdn": has_fqdn,
        "option_codes": option_codes,
        "param_list": param_list,
    }


def generate_ja4d(packet: Packet) -> str | None:
    """
    Generate a JA4D fingerprint from a packet.

    Args:
        packet: A Scapy packet potentially containing a DHCPv4 message

    Returns:
        A JA4D fingerprint string or None if the packet is not applicable
    """
    # A tunnel carries its own UDP header, and `getlayer` counts from the outside. The
    # DHCP message is the innermost one, so a reader that takes the outer header reads a
    # tunnel port, and the port test below then refuses the packet. The defect shape of
    # this method is therefore an absent value and never a wrong one.
    # `packet_utils.packet_endpoints` reads the same layer, so one result names one port
    # pair.
    udp = innermost_layer(packet, (UDP,))
    if udp is None:
        return None

    if udp.sport not in _DHCP_PORTS and udp.dport not in _DHCP_PORTS:
        return None

    # Get raw UDP payload
    raw_payload = bytes(udp.payload)
    parsed = _parse_dhcp_options(raw_payload)
    if parsed is None:
        return None

    msg_type = parsed["msg_type"]
    max_msg_size = min(parsed["max_msg_size"], 9999)
    has_request_ip = parsed["has_request_ip"]
    has_fqdn = parsed["has_fqdn"]

    # Section a
    msg_type_str = DHCP_MESSAGE_TYPES.get(msg_type, f"{msg_type:05d}")
    request_ip_flag = "i" if has_request_ip else "n"
    fqdn_flag = "d" if has_fqdn else "n"
    section_a = f"{msg_type_str}{max_msg_size:04d}{request_ip_flag}{fqdn_flag}"

    # Section b
    section_b = build_option_list(parsed["option_codes"])

    # Section c
    section_c = build_param_list(parsed["param_list"])

    return f"{section_a}_{section_b}_{section_c}"


class JA4DFingerprinter(BaseFingerprinter):
    """Fingerprinter for JA4D (DHCP)."""

    def process_packet(self, packet: Packet) -> str | None:
        """Process a packet and extract JA4D fingerprint if applicable."""
        fingerprint = generate_ja4d(packet)
        if fingerprint:
            self.add_fingerprint(fingerprint, packet)
        return fingerprint

    def cleanup_connection(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str
    ) -> None:
        """No-op: JA4D is stateless (per-packet fingerprinter)."""
