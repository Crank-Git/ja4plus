"""
JA4H HTTP Request Fingerprinting implementation.

JA4H fingerprints HTTP requests based on:
1. HTTP method, version, cookie flag, referer flag, header count, and language
2. Headers hash in the order they appear
3. Sorted cookie field names hash
4. Sorted cookie fields + values hash
"""

import hashlib
import logging
from scapy.all import IP, IPv6, TCP, Raw

logger = logging.getLogger(__name__)
from ja4plus.utils.http_utils import extract_http_info, is_http_request, parse_http_request
from ja4plus.utils.tcp_stream import TCPStreamReassembler
from ja4plus.utils.packet_utils import get_ip_layer
from ja4plus.fingerprinters.base import BaseFingerprinter


class JA4HFingerprinter(BaseFingerprinter):
    """
    JA4H HTTP Fingerprinting implementation.

    Supports HTTP requests spanning multiple TCP segments via
    stream reassembly.
    """

    def __init__(self):
        super().__init__()
        self.reassembler = TCPStreamReassembler(max_streams=100)

    def process_packet(self, packet):
        """
        Process a packet and extract JA4H fingerprint if applicable.

        Accumulates TCP stream data and attempts HTTP parsing on each
        new segment.
        """
        if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
            return None

        ip_layer = get_ip_layer(packet)
        if ip_layer is None:
            return None

        tcp = packet[TCP]
        raw_data = bytes(packet[Raw])

        stream_key = f"{ip_layer.src}:{tcp.sport}-{ip_layer.dst}:{tcp.dport}"
        seq = tcp.seq if hasattr(tcp, 'seq') else 0

        self.reassembler.add_segment(stream_key, seq, raw_data)
        stream_data = self.reassembler.get_stream(stream_key)

        # Try to parse HTTP from reassembled stream
        if not is_http_request(stream_data):
            # Also try the single packet (backward compat)
            fingerprint = generate_ja4h(packet)
            if fingerprint:
                self.add_fingerprint(fingerprint, packet)
                return fingerprint
            return None

        # Check if headers are complete (double CRLF present)
        if b"\r\n\r\n" not in stream_data:
            return None

        http_info = _extract_http_info_from_bytes(stream_data)
        if not http_info:
            return None

        fingerprint = _generate_ja4h_from_info(http_info)
        if fingerprint:
            self.add_fingerprint(fingerprint, packet)
            self.reassembler.remove_stream(stream_key)
            return fingerprint

        return None

    def reset(self):
        super().reset()
        self.reassembler = TCPStreamReassembler(max_streams=100)


def _extract_http_info_from_bytes(data):
    """Extract HTTP info from raw bytes, preserving original header name casing.

    Mirrors extract_http_info() but operates on a bytes buffer instead of a
    Scapy packet, so it works on reassembled TCP stream data.
    """
    import re
    if not data:
        return None
    try:
        text = data.decode('utf-8', errors='ignore')
        request_line_match = re.match(
            r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH)\s+(\S+)\s+(HTTP/\d+\.\d+)',
            text
        )
        if not request_line_match:
            return None

        method = request_line_match.group(1)
        path = request_line_match.group(2)
        version = request_line_match.group(3)

        headers = {}
        header_names = []
        lines = text.split('\r\n')

        for line in lines[1:]:
            if not line or line.isspace():
                break
            header_match = re.match(r'^([^:]+):\s*(.*)$', line)
            if header_match:
                name = header_match.group(1).strip()
                value = header_match.group(2).strip()
                headers[name.lower()] = value
                header_names.append(name)

        cookies = {}
        cookie_fields = []
        cookie_values = []
        if 'cookie' in headers:
            for pair in headers['cookie'].split(';'):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    k, v = k.strip(), v.strip()
                    cookies[k] = v
                    cookie_fields.append(k)
                    cookie_values.append(v)

        return {
            'method': method,
            'path': path,
            'version': version,
            'headers': header_names,
            'cookies': cookies,
            'cookie_fields': cookie_fields,
            'cookie_values': cookie_values,
            'language': headers.get('accept-language', ''),
            'referer': headers.get('referer', ''),
        }
    except (ValueError, TypeError, UnicodeDecodeError) as e:
        logger.debug(f"Could not parse HTTP from stream bytes: {e}")
        return None


def _convert_parsed_to_extract_format(parsed):
    """Convert parse_http_request output to extract_http_info format."""
    headers = parsed.get('headers', {})
    header_names = list(headers.keys())
    cookies = parsed.get('cookies', {})
    cookie_fields = list(cookies.keys())

    return {
        'method': parsed.get('method', ''),
        'path': parsed.get('path', ''),
        'version': parsed.get('version', ''),
        'headers': header_names,
        'cookies': cookies,
        'cookie_fields': cookie_fields,
        'cookie_values': list(cookies.values()),
        'language': headers.get('accept-language', ''),
        'referer': headers.get('referer', ''),
    }


def _generate_ja4h_from_info(http_info):
    """Generate JA4H from an http_info dict."""
    if not http_info:
        return None

    try:
        method = http_info.get('method', '').lower()
        version = http_info.get('version', '').replace('HTTP/', '')
        version_str = version.replace('.', '')

        has_cookie = 'c' if http_info.get('cookie_fields', []) else 'n'
        has_referer = 'r' if http_info.get('referer', '') else 'n'

        header_count = 0
        for header in http_info.get('headers', []):
            if header.lower() not in ['cookie', 'referer']:
                header_count += 1
        header_count = min(header_count, 99)
        header_count_str = f"{header_count:02d}"

        language = http_info.get('language', '')
        lang_code = '0000'
        if language:
            lang_clean = language.replace('-', '').replace(';', ',').lower().split(',')[0]
            lang_clean = lang_clean[:4]
            lang_code = f"{lang_clean}{'0' * (4 - len(lang_clean))}" if lang_clean else '0000'

        part_a = f"{method[:2]}{version_str}{has_cookie}{has_referer}{header_count_str}{lang_code}"

        headers = http_info.get('headers', [])
        filtered_headers = [
            h for h in headers
            if not h.startswith(':')
            and h.lower() != 'cookie'
            and h.lower() != 'referer'
            and h
        ]
        headers_str = ','.join(filtered_headers)
        part_b = hashlib.sha256(headers_str.encode()).hexdigest()[:12] if headers_str else '000000000000'

        cookie_fields = sorted(http_info.get('cookie_fields', []))
        cookie_fields_str = ','.join(cookie_fields)
        part_c = hashlib.sha256(cookie_fields_str.encode()).hexdigest()[:12] if cookie_fields_str else '000000000000'

        cookie_dict = http_info.get('cookies', {})
        sorted_cookie_pairs = sorted(cookie_dict.items())
        cookie_values_str = ','.join(f"{k}={v}" for k, v in sorted_cookie_pairs)
        part_d = hashlib.sha256(cookie_values_str.encode()).hexdigest()[:12] if cookie_values_str else '000000000000'

        return f"{part_a}_{part_b}_{part_c}_{part_d}"

    except (ValueError, TypeError, IndexError, KeyError, AttributeError) as e:
        logger.debug(f"Packet does not contain JA4H data: {e}")
        return None


def generate_ja4h(packet):
    """
    Generate JA4H fingerprint from HTTP request.

    Args:
        packet: An HTTP request packet

    Returns:
        JA4H fingerprint string if successful, None otherwise
    """
    http_info = extract_http_info(packet)
    if not http_info:
        return None
    return _generate_ja4h_from_info(http_info)
