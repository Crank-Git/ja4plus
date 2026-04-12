"""
JA4D DHCP Fingerprinting implementation.

Format: {msg_type}{max_msg_size}{request_ip}{fqdn}_{option_list}_{param_list}

Section a: 5-char message type abbreviation + 4-digit max message size +
           'i'/'n' for requested IP + 'd'/'n' for FQDN
Section b: DHCP options present (hyphen-separated decimal), skipping 53/255/50/81
Section c: Parameter Request List contents from option 55 (hyphen-separated decimal)
"""

import logging

from scapy.all import UDP

logger = logging.getLogger(__name__)

from ja4plus.fingerprinters.base import BaseFingerprinter

# DHCP message type (option 53) to 5-character abbreviation.
DHCP_MESSAGE_TYPES = {
    1:  "disco",  # DHCPDISCOVER
    2:  "offer",  # DHCPOFFER
    3:  "reqst",  # DHCPREQUEST
    4:  "decln",  # DHCPDECLINE
    5:  "dpack",  # DHCPACK
    6:  "dpnak",  # DHCPNAK
    7:  "relse",  # DHCPRELEASE
    8:  "infor",  # DHCPINFORM
    9:  "frenw",  # DHCPFORCERENEW
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

# Options to skip in section b (already encoded in section a or terminal).
DHCP_SKIP_OPTIONS = {53, 255, 50, 81}

# DHCP magic cookie
_DHCP_MAGIC = b'\x63\x82\x53\x63'

# UDP ports used by DHCP
_DHCP_PORTS = {67, 68}


def build_option_list(option_codes):
    """
    Format DHCP option codes as hyphen-separated decimals, skipping
    options in DHCP_SKIP_OPTIONS. Returns '00' if nothing remains.

    Args:
        option_codes: list of integer option codes in wire order

    Returns:
        Hyphen-separated string of option codes, or '00'
    """
    parts = [str(code) for code in option_codes if code not in DHCP_SKIP_OPTIONS]
    return '-'.join(parts) if parts else "00"


def build_param_list(params):
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
    return '-'.join(str(p) for p in params)


def _parse_dhcp_options(raw_payload):
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
    has_request_ip = False
    has_fqdn = False
    option_codes = []
    param_list = []

    pos = 240  # start of options
    while pos < len(raw_payload):
        opt_code = raw_payload[pos]
        pos += 1

        if opt_code == 255:  # End
            option_codes.append(255)
            break
        if opt_code == 0:    # Pad
            continue

        if pos >= len(raw_payload):
            break
        opt_len = raw_payload[pos]
        pos += 1

        opt_data = raw_payload[pos:pos + opt_len]
        pos += opt_len

        option_codes.append(opt_code)

        if opt_code == 53 and opt_len >= 1:   # Message Type
            msg_type = opt_data[0]
        elif opt_code == 57 and opt_len >= 2:  # Max Message Size
            max_msg_size = (opt_data[0] << 8) | opt_data[1]
        elif opt_code == 50:                   # Requested IP Address
            has_request_ip = True
        elif opt_code == 81:                   # Client FQDN
            has_fqdn = True
        elif opt_code == 55:                   # Parameter Request List
            param_list = list(opt_data)

    if msg_type == 0:
        return None

    return {
        'msg_type': msg_type,
        'max_msg_size': max_msg_size,
        'has_request_ip': has_request_ip,
        'has_fqdn': has_fqdn,
        'option_codes': option_codes,
        'param_list': param_list,
    }


def generate_ja4d(packet):
    """
    Generate a JA4D fingerprint from a packet.

    Args:
        packet: A Scapy packet potentially containing a DHCPv4 message

    Returns:
        A JA4D fingerprint string or None if the packet is not applicable
    """
    udp = packet.getlayer(UDP)
    if udp is None:
        return None

    if (udp.sport not in _DHCP_PORTS and udp.dport not in _DHCP_PORTS):
        return None

    # Get raw UDP payload
    raw_payload = bytes(udp.payload)
    parsed = _parse_dhcp_options(raw_payload)
    if parsed is None:
        return None

    msg_type = parsed['msg_type']
    max_msg_size = min(parsed['max_msg_size'], 9999)
    has_request_ip = parsed['has_request_ip']
    has_fqdn = parsed['has_fqdn']

    # Section a
    msg_type_str = DHCP_MESSAGE_TYPES.get(msg_type, f"{msg_type:05d}")
    request_ip_flag = "i" if has_request_ip else "n"
    fqdn_flag = "d" if has_fqdn else "n"
    section_a = f"{msg_type_str}{max_msg_size:04d}{request_ip_flag}{fqdn_flag}"

    # Section b
    section_b = build_option_list(parsed['option_codes'])

    # Section c
    section_c = build_param_list(parsed['param_list'])

    return f"{section_a}_{section_b}_{section_c}"


class JA4DFingerprinter(BaseFingerprinter):
    """Fingerprinter for JA4D (DHCP)."""

    def process_packet(self, packet):
        """Process a packet and extract JA4D fingerprint if applicable."""
        fingerprint = generate_ja4d(packet)
        if fingerprint:
            self.add_fingerprint(fingerprint, packet)
        return fingerprint

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        """No-op: JA4D is stateless (per-packet fingerprinter)."""
