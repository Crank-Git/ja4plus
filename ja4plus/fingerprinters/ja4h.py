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

from ja4plus.utils.http_utils import (
    REQUEST_LINE_PATTERN,
    can_become_http_request,
    extract_http_info,
    is_http_request,
    parse_cookie_header,
    parse_http_request,
)
from ja4plus.utils.tcp_stream import TCPStreamReassembler
from ja4plus.utils.packet_utils import get_ip_layer, packet_endpoints, packet_seconds
from ja4plus.fingerprinters.base import BaseFingerprinter

logger = logging.getLogger(__name__)


def _http_version_to_str(version):
    """Map an HTTP version string to a JA4H 2-char code per FoxIO PR #288.

    HTTP/1.0 -> '10', HTTP/1.1 -> '11', HTTP/2 -> '20', HTTP/3 -> '30'.
    Falls back to digits-only stripped of dots for unknown versions, padded
    to length 2 with trailing zeros so the result fits the fixed format.
    """
    if not version:
        return "11"
    v = version.replace("HTTP/", "").strip()
    # Normalize: HTTP/2 and HTTP/3 are version strings without the minor
    # part; map them to 20 / 30 explicitly.
    if v == "2" or v == "2.0":
        return "20"
    if v == "3" or v == "3.0":
        return "30"
    digits = v.replace(".", "")
    if len(digits) >= 2:
        return digits[:2]
    if len(digits) == 1:
        return digits + "0"
    return "11"


class JA4HFingerprinter(BaseFingerprinter):
    """
    JA4H HTTP Fingerprinting implementation.

    Supports HTTP requests spanning multiple TCP segments via
    stream reassembly.

    Every entry of ``get_fingerprints()`` carries ``raw_original_order``, the FoxIO
    `JA4H_ro` value, and ``last_raw_original_order`` holds the value of the most recent
    request. FoxIO publishes no `JA4H_r` key, so this fingerprinter computes no sorted
    raw form: a sorted value matches no reference value and no other implementation.
    """

    def __init__(self):
        super().__init__()
        self.reassembler = TCPStreamReassembler(max_streams=100)
        self.last_raw_original_order = None
        self.unusable_base = {}

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
        seq = tcp.seq if hasattr(tcp, "seq") else 0

        self.reassembler.add_segment(stream_key, seq, raw_data, packet_seconds(packet))
        stream_data = self.reassembler.get_stream(stream_key)

        # Try to parse HTTP from reassembled stream
        if not is_http_request(stream_data):
            self._drop_an_unusable_stream(stream_key, stream_data)
            # Also try the single packet (backward compat)
            http_info = extract_http_info(packet)
            if not http_info:
                return None
            fingerprint = _generate_ja4h_from_info(http_info)
            if fingerprint:
                self._record(fingerprint, http_info, packet)
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
            self._record(fingerprint, http_info, packet)
            self.reassembler.remove_stream(stream_key)
            return fingerprint

        return None

    def _drop_an_unusable_stream(self, stream_key, stream_data):
        """Remove a stream whose buffer no later segment turns into an HTTP request.

        A segment that arrives out of order puts the middle of a request at the start of
        the buffer, and that buffer starts no HTTP request. The missing head lowers the
        base sequence number when it arrives, so the removal waits for one further packet
        that leaves the base sequence number where it was.

        Args:
            stream_key: The key of the stream in the reassembler.
            stream_data: The contiguous bytes of the stream.
        """
        if stream_key not in self.reassembler.streams:
            return

        if can_become_http_request(stream_data):
            self.unusable_base.pop(stream_key, None)
            return

        base = self.reassembler.base_seq(stream_key)
        if stream_key in self.unusable_base and self.unusable_base[stream_key] == base:
            # Nothing else reads this buffer. A buffer that stays holds memory for the
            # life of the capture.
            self.reassembler.remove_stream(stream_key)
            self.unusable_base.pop(stream_key, None)
            return

        self.unusable_base[stream_key] = base
        if len(self.unusable_base) > self.reassembler.max_streams:
            # The reassembler evicts a stream on its own. A base sequence number that
            # names an evicted stream is state that nothing reads again, and a flood of
            # streams would otherwise grow the table without a limit.
            self.unusable_base = {
                key: value
                for key, value in self.unusable_base.items()
                if key in self.reassembler.streams
            }

    def _record(self, fingerprint, http_info, packet):
        """Append one JA4H result, with the raw original-order form beside the hash."""
        raw_original_order = _generate_ja4h_raw_from_info(http_info)
        self.last_raw_original_order = raw_original_order
        entry = {
            "fingerprint": fingerprint,
            "raw_original_order": raw_original_order,
        }
        entry.update(packet_endpoints(packet))
        self.fingerprints.append(entry)

    def reset(self):
        super().reset()
        self.reassembler = TCPStreamReassembler(max_streams=100)
        self.last_raw_original_order = None
        self.unusable_base = {}

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        """Remove TCP stream buffer for the given connection."""
        stream_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        self.reassembler.remove_stream(stream_key)
        # Also try reverse direction
        rev_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        self.reassembler.remove_stream(rev_key)
        self.unusable_base.pop(stream_key, None)
        self.unusable_base.pop(rev_key, None)


def _extract_http_info_from_bytes(data):
    """Extract HTTP info from raw bytes, preserving original header name casing.

    Mirrors extract_http_info() but operates on a bytes buffer instead of a
    Scapy packet, so it works on reassembled TCP stream data.
    """
    import re

    if not data:
        return None
    try:
        text = data.decode("utf-8", errors="ignore")
        # The stream path and the packet path read one pattern, so the two report one
        # version for one request line.
        request_line_match = re.match(REQUEST_LINE_PATTERN, text)
        if not request_line_match:
            return None

        method = request_line_match.group(1)
        path = request_line_match.group(2)
        version = request_line_match.group(3)

        headers = {}
        header_names = []
        lines = text.split("\r\n")

        for line in lines[1:]:
            if not line or line.isspace():
                break
            header_match = re.match(r"^([^:]+):\s*(.*)$", line)
            if header_match:
                name = header_match.group(1).strip()
                value = header_match.group(2).strip()
                headers[name.lower()] = value
                header_names.append(name)

        cookies = {}
        cookie_fields = []
        cookie_values = []
        if "cookie" in headers:
            parsed_cookies = parse_cookie_header(headers["cookie"])
            if parsed_cookies is None:
                # A header past a bound produces no request. #175 states the reason.
                return None
            cookies, cookie_fields, cookie_values = parsed_cookies

        return {
            "method": method,
            "path": path,
            "version": version,
            "headers": header_names,
            "cookies": cookies,
            "cookie_fields": cookie_fields,
            "cookie_values": cookie_values,
            "language": headers.get("accept-language", ""),
            "referer": headers.get("referer", ""),
        }
    except (ValueError, TypeError, UnicodeDecodeError) as e:
        logger.debug(f"Could not parse HTTP from stream bytes: {e}")
        return None


def _convert_parsed_to_extract_format(parsed):
    """Convert parse_http_request output to extract_http_info format."""
    headers = parsed.get("headers", {})
    header_names = list(headers.keys())
    cookies = parsed.get("cookies", {})

    return {
        "method": parsed.get("method", ""),
        "path": parsed.get("path", ""),
        "version": parsed.get("version", ""),
        "headers": header_names,
        "cookies": cookies,
        # The keys of the dictionary drop a repeated cookie name. The parser reports the
        # two lists for that reason. #35 records the defect.
        "cookie_fields": parsed.get("cookie_fields", []),
        "cookie_values": parsed.get("cookie_values", []),
        "language": headers.get("accept-language", ""),
        "referer": headers.get("referer", ""),
    }


def _ja4h_part_a(http_info):
    """Return the first section of a JA4H fingerprint.

    Args:
        http_info: A parsed HTTP request.

    Returns:
        The 12-character section that names the method, the version, the cookie flag,
        the referer flag, the header count and the language.
    """
    method = http_info.get("method", "").lower()
    version_str = _http_version_to_str(http_info.get("version", ""))

    has_cookie = "c" if http_info.get("cookie_fields", []) else "n"
    has_referer = "r" if http_info.get("referer", "") else "n"

    header_count = 0
    for header in http_info.get("headers", []):
        if header.lower() not in ["cookie", "referer"]:
            header_count += 1
    header_count = min(header_count, 99)
    header_count_str = f"{header_count:02d}"

    language = http_info.get("language", "")
    lang_code = "0000"
    if language:
        lang_clean = language.replace("-", "").replace(";", ",").lower().split(",")[0]
        lang_clean = lang_clean[:4]
        lang_code = f"{lang_clean}{'0' * (4 - len(lang_clean))}" if lang_clean else "0000"

    return f"{method[:2]}{version_str}{has_cookie}{has_referer}{header_count_str}{lang_code}"


def _ja4h_header_names(http_info):
    """Return the header names that the second section of a JA4H fingerprint holds.

    The hashed form and the raw form read one list, so the raw form explains the hash.

    Args:
        http_info: A parsed HTTP request.

    Returns:
        The header names in wire order. The list drops the Cookie header and the Referer
        header, because the first section already reports both, and it drops an HTTP/2
        pseudo-header, because the reference lists none.
    """
    return [
        h
        for h in http_info.get("headers", [])
        if h and not h.startswith(":") and h.lower() != "cookie" and h.lower() != "referer"
    ]


def _ja4h_cookie_pairs(http_info):
    """Return the cookies of a request as one ordered list of pairs.

    Every section that reports a cookie reads this list, so the cookie-name hash, the
    cookie-value hash and the raw form describe one cookie set.

    Args:
        http_info: A parsed HTTP request.

    Returns:
        The `(name, value)` pairs in wire order. A repeated cookie name holds one pair
        for each occurrence, because HTTP permits a repeated cookie name.
    """
    names = http_info.get("cookie_fields", [])
    values = http_info.get("cookie_values", [])
    return list(zip(names, values))


def _generate_ja4h_from_info(http_info):
    """Generate JA4H from an http_info dict."""
    if not http_info:
        return None

    try:
        part_a = _ja4h_part_a(http_info)

        headers_str = ",".join(_ja4h_header_names(http_info))
        part_b = (
            hashlib.sha256(headers_str.encode()).hexdigest()[:12] if headers_str else "000000000000"
        )

        # Part c and part d read one list of pairs. A dictionary drops a repeated cookie
        # name, which HTTP permits, and the two hashes then describe different cookie
        # sets. #35 records the defect.
        cookie_pairs = _ja4h_cookie_pairs(http_info)

        cookie_fields_str = ",".join(sorted(name for name, _ in cookie_pairs))
        part_c = (
            hashlib.sha256(cookie_fields_str.encode()).hexdigest()[:12]
            if cookie_fields_str
            else "000000000000"
        )

        # Cookie-VALUES hash: pairs sorted by NAME only (FoxIO PR #288). The sort is
        # stable, so two cookies that carry one name keep their wire order.
        sorted_cookie_pairs = sorted(cookie_pairs, key=lambda pair: pair[0])
        cookie_values_str = ",".join(f"{k}={v}" for k, v in sorted_cookie_pairs)
        part_d = (
            hashlib.sha256(cookie_values_str.encode()).hexdigest()[:12]
            if cookie_values_str
            else "000000000000"
        )

        return f"{part_a}_{part_b}_{part_c}_{part_d}"

    except (ValueError, TypeError, IndexError, KeyError, AttributeError) as e:
        logger.debug(f"Packet does not contain JA4H data: {e}")
        return None


def _generate_ja4h_raw_from_info(http_info):
    """Return the JA4H raw original-order form of an http_info dict.

    The form is `<part a>_<header names>_<cookie names>_<cookie pairs>`. Each list holds
    the wire order, which is what makes the value the original-order form. A request that
    carries no cookie ends after the header names and one underscore, as the FoxIO
    reference writes it.

    Args:
        http_info: A parsed HTTP request.

    Returns:
        The FoxIO `JA4H_ro` value, or None when the request is unreadable.
    """
    if not http_info:
        return None

    try:
        part_a = _ja4h_part_a(http_info)
        headers_str = ",".join(_ja4h_header_names(http_info))
        raw = f"{part_a}_{headers_str}_"

        cookie_pairs = _ja4h_cookie_pairs(http_info)
        if cookie_pairs:
            names_str = ",".join(name for name, _ in cookie_pairs)
            pairs_str = ",".join(f"{k}={v}" for k, v in cookie_pairs)
            raw += f"{names_str}_{pairs_str}"

        return raw

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
