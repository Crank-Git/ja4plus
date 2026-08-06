"""
JA4D6 DHCPv6 Fingerprinting implementation (FoxIO PR #267 + #270).

Format: {type:5}{size:4}{ip:1}{fqdn:1}_{options}_{request_list}

Section a:
- type:  5-char abbreviation of msg-type (see DHCPV6_MESSAGE_TYPES)
         unknown -> "%05u"
- size:  byte-length of the DUID payload inside option 1 (Client Identifier).
         "%04d", capped at 9999, "0000" if absent.
- ip:    'i' if option 4 (IATA) is present, else 'n'
- fqdn:  'd' if option 39 (Client FQDN) is present, else 'n'

Section b: ALL DHCPv6 option types in PRESENCE ORDER (no exclusions).
           This includes nested options inside IA_NA / IA_PD / etc., matching
           the Wireshark dissector's iteration of all dhcpv6.option.type fields.
           Default "00".

Section c: items from option 6 (Option Request) in original order. Default "00".
"""

import logging

from scapy.all import UDP

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

# DHCPv6 options that carry nested DHCPv6 options inside their data.
# These are recursed into when iterating "dhcpv6.option.type" presence.
# Per RFC 8415: IA_NA (3), IA_TA (4) and IA_PD (25) embed sub-options
# starting after a fixed-size header. Option 17 (Vendor-specific Information)
# carries enterprise-specific sub-options keyed by enterprise-number.
_DHCPV6_NESTED_OPTIONS = {
    3: 12,  # IA_NA:  IAID(4) + T1(4) + T2(4) = 12 bytes header
    4: 4,  # IA_TA:  IAID(4) = 4 bytes header
    25: 12,  # IA_PD:  IAID(4) + T1(4) + T2(4) = 12 bytes header
    5: 24,  # IA Address (within IA_NA/IA_TA): addr(16)+pref-lt(4)+valid-lt(4) = 24
    26: 25,  # IA Prefix (within IA_PD): pref-lt(4)+valid-lt(4)+plen(1)+prefix(16) = 25
}


def _walk_options(data, start, end, out):
    """
    Recursively walk DHCPv6 options between [start, end) bytes,
    appending option codes to ``out`` in presence order.
    """
    pos = start
    while pos + 4 <= end:
        opt_code = (data[pos] << 8) | data[pos + 1]
        opt_len = (data[pos + 2] << 8) | data[pos + 3]
        pos += 4
        if pos + opt_len > end:
            break
        out.append(opt_code)

        if opt_code in _DHCPV6_NESTED_OPTIONS:
            header_len = _DHCPV6_NESTED_OPTIONS[opt_code]
            inner_start = pos + header_len
            inner_end = pos + opt_len
            if inner_start <= inner_end:
                _walk_options(data, inner_start, inner_end, out)

        pos += opt_len


def _parse_dhcpv6_payload(payload):
    """
    Parse a DHCPv6 UDP payload (relay-forw/reply not unwrapped).

    Returns a dict or None.
    """
    if len(payload) < 4:
        return None

    msg_type = payload[0]
    # Skip 3-byte transaction id; options start at offset 4
    options_in_order = []
    _walk_options(payload, 4, len(payload), options_in_order)

    # Walk options non-recursively at top level to extract specific fields
    duid_len = 0
    has_iata = False
    has_fqdn = False
    request_list = []

    pos = 4
    end = len(payload)
    while pos + 4 <= end:
        opt_code = (payload[pos] << 8) | payload[pos + 1]
        opt_len = (payload[pos + 2] << 8) | payload[pos + 3]
        pos += 4
        if pos + opt_len > end:
            break
        opt_data = payload[pos : pos + opt_len]
        pos += opt_len

        if opt_code == 1:  # Client Identifier — DUID is the entire data
            duid_len = len(opt_data)
        elif opt_code == 4:  # IATA
            has_iata = True
        elif opt_code == 39:  # Client FQDN
            has_fqdn = True
        elif opt_code == 6:  # Option Request (ORO)
            # 2-byte big-endian option codes
            rl = []
            for i in range(0, len(opt_data) - 1, 2):
                rl.append((opt_data[i] << 8) | opt_data[i + 1])
            request_list = rl

    return {
        "msg_type": msg_type,
        "options_in_order": options_in_order,
        "duid_len": duid_len,
        "has_iata": has_iata,
        "has_fqdn": has_fqdn,
        "request_list": request_list,
    }


def _build_option_list(options_in_order):
    if not options_in_order:
        return "00"
    return "-".join(str(c) for c in options_in_order)


def _build_request_list(request_list):
    if not request_list:
        return "00"
    return "-".join(str(c) for c in request_list)


def generate_ja4d6(packet):
    """
    Generate a JA4D6 fingerprint from a packet.

    Args:
        packet: A Scapy packet potentially containing a DHCPv6 message

    Returns:
        A JA4D6 fingerprint string or None if the packet is not applicable
    """
    udp = packet.getlayer(UDP)
    if udp is None:
        return None

    # DHCPv6 client port = 546, server port = 547
    if 546 not in (int(udp.sport), int(udp.dport)) and 547 not in (int(udp.sport), int(udp.dport)):
        return None

    payload = bytes(udp.payload)
    parsed = _parse_dhcpv6_payload(payload)
    if parsed is None:
        return None

    msg_type = parsed["msg_type"]
    if msg_type == 0:
        return None

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

    def process_packet(self, packet):
        fingerprint = generate_ja4d6(packet)
        if fingerprint:
            self.add_fingerprint(fingerprint, packet)
        return fingerprint

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        """No-op: JA4D6 is stateless (per-packet fingerprinter)."""
