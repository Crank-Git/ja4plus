"""
HTTP utility functions for JA4+ fingerprinting.
"""

from scapy.all import Raw, TCP, IP
import re
import logging

logger = logging.getLogger(__name__)

# The version token holds a minor version, or it names major version 2 or 3, which carry
# no minor version. A token such as `HTTP/11` names no HTTP version, and a pattern that
# reads it as `HTTP/1` reports the version code of `HTTP/1.1`. The two requests then
# carry one fingerprint. The lookahead ends the token for that reason. #35 records both
# defects.
REQUEST_LINE_PATTERN = (
    r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH)"
    r"\s+(\S+)\s+(HTTP/(?:\d+\.\d+|[23]))(?=[ \t\r\n]|$)"
)

# The largest number of cookie pairs one request contributes. The largest reading across
# `tests/foxio_vectors/` is 14 pairs on one request, so this bound sits 36 times above
# every vector and no vector reaches it.
MAX_COOKIE_PAIRS = 512

# The largest cookie name and the largest cookie value one request carries, in UTF-8
# bytes. The largest readings across `tests/foxio_vectors/` are 41 name bytes and 264
# value bytes.
MAX_COOKIE_NAME_BYTES = 256
MAX_COOKIE_VALUE_BYTES = 4096


def _cookie_segments(cookie_header):
    """Produce the semicolon-separated segments of a Cookie header, one at a time.

    A caller reads a bounded number of segments and stops. `str.split` would build one
    entry for every segment first, which is the growth the bounds exist to stop.

    Args:
        cookie_header: The value of the Cookie header.

    Yields:
        Each segment, without the semicolon that ends it.
    """
    start = 0
    while True:
        end = cookie_header.find(";", start)
        if end < 0:
            yield cookie_header[start:]
            return
        yield cookie_header[start:end]
        start = end + 1


def _exceeds_byte_length(text, limit):
    """Report whether the UTF-8 form of the text is longer than the limit.

    Args:
        text: The cookie name or the cookie value.
        limit: The maximum number of bytes.

    Returns:
        True when the UTF-8 form holds more than `limit` bytes.
    """
    if len(text) > limit:
        # Every character takes one byte or more, so the byte length passes the limit.
        # This test also bounds the `str.encode` call below to four times the limit.
        return True
    return len(text.encode("utf-8", errors="ignore")) > limit


def parse_cookie_header(cookie_header):
    """Return the cookies of one Cookie header, or None when the header passes a bound.

    Past any bound this function produces no result, and the caller therefore produces
    no JA4H value. It never truncates. The JA4H cookie hash reads the content and the
    order of the list. A truncated list therefore produces a value that compares equal
    to a different sender's. A tool whose purpose is to compare one output against
    another must not emit a value that describes traffic the sender did not send. The
    user decided this on 2026-08-08, on #175.

    A segment that holds no equals sign contributes no entry, and it counts against no
    bound.

    Args:
        cookie_header: The value of the Cookie header.

    Returns:
        A tuple of the cookie dictionary, the cookie names in wire order, and the cookie
        values in wire order. The two lists keep every occurrence of a repeated cookie
        name, which the dictionary drops. Returns None when the header holds more than
        `MAX_COOKIE_PAIRS` pairs, a name longer than `MAX_COOKIE_NAME_BYTES`, or a value
        longer than `MAX_COOKIE_VALUE_BYTES`.
    """
    cookies = {}
    cookie_fields = []
    cookie_values = []
    for segment in _cookie_segments(cookie_header):
        name, separator, value = segment.partition("=")
        if not separator:
            continue
        name = name.strip()
        value = value.strip()
        if len(cookie_fields) == MAX_COOKIE_PAIRS:
            logger.debug("Cookie header holds more than %d pairs", MAX_COOKIE_PAIRS)
            return None
        if _exceeds_byte_length(name, MAX_COOKIE_NAME_BYTES):
            logger.debug("Cookie name holds more than %d bytes", MAX_COOKIE_NAME_BYTES)
            return None
        if _exceeds_byte_length(value, MAX_COOKIE_VALUE_BYTES):
            logger.debug("Cookie value holds more than %d bytes", MAX_COOKIE_VALUE_BYTES)
            return None
        cookies[name] = value
        cookie_fields.append(name)
        cookie_values.append(value)
    return cookies, cookie_fields, cookie_values


def parse_http_request(data):
    """
    Parse an HTTP request from raw data.

    Args:
        data: Raw bytes containing an HTTP request

    Returns:
        Dictionary with HTTP request details or None if not an HTTP request
    """
    if not data:
        return None

    try:
        # Convert bytes to string if needed
        if isinstance(data, bytes):
            data_str = data.decode("utf-8", errors="ignore")
        else:
            data_str = data

        # Split into lines
        lines = data_str.split("\r\n")
        if not lines:
            return None

        # Parse request line
        request_line = lines[0]
        parts = request_line.split(" ")
        if len(parts) < 3:
            return None

        method = parts[0].upper()
        path = parts[1]
        version = parts[2]

        # Check if this is an HTTP request
        http_methods = [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "HEAD",
            "OPTIONS",
            "PATCH",
            "CONNECT",
            "TRACE",
        ]
        if method not in http_methods:
            return None

        # Parse headers
        headers = {}
        for i in range(1, len(lines)):
            line = lines[i]
            if not line or line == "":
                break

            if ":" not in line:
                continue

            header_parts = line.split(":", 1)
            if len(header_parts) != 2:
                continue

            header_name = header_parts[0].strip().lower()
            header_value = header_parts[1].strip()

            headers[header_name] = header_value

        # Extract cookies. The two lists hold the wire order and keep every occurrence
        # of a repeated cookie name, which the dictionary drops. #35 records the defect.
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
            "headers": headers,
            "cookies": cookies,
            "cookie_fields": cookie_fields,
            "cookie_values": cookie_values,
        }
    except (ValueError, TypeError, UnicodeDecodeError) as e:
        logger.debug(f"Not an HTTP request: {e}")
        return None


HTTP_METHOD_TOKENS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)


def is_http_request(data):
    """
    Check if the data appears to be an HTTP request.

    Args:
        data: Raw bytes or string to check

    Returns:
        True if the data appears to be an HTTP request, False otherwise
    """
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")

    for method in HTTP_METHOD_TOKENS:
        if data.startswith(method):
            return True

    return False


def can_become_http_request(data):
    """Report whether a later byte can make the buffer an HTTP request.

    A caller holds a buffer that grows one TCP segment at a time. The buffer is the
    start of an HTTP request while it is a prefix of a method token.

    Args:
        data: The bytes the buffer holds, or the same text as a string.

    Returns:
        True when the buffer is an HTTP request, or when it is the start of one. False
        when no later byte can make it one.
    """
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")

    if not data:
        return True

    for method in HTTP_METHOD_TOKENS:
        if data.startswith(method) or method.startswith(data):
            return True

    return False


def extract_http_info(packet):
    """Extract HTTP information from a packet"""
    if Raw not in packet:
        return None

    try:
        data = bytes(packet[Raw]).decode("utf-8", errors="ignore")

        # Check if this is an HTTP request
        request_line_match = re.match(REQUEST_LINE_PATTERN, data)
        if not request_line_match:
            return None

        method = request_line_match.group(1)
        path = request_line_match.group(2)
        version = request_line_match.group(3)

        # Parse headers
        headers = {}
        header_names = []
        lines = data.split("\r\n")

        for line in lines[1:]:  # Skip request line
            if not line or line.isspace():
                break  # End of headers

            header_match = re.match(r"^([^:]+):\s*(.*)$", line)
            if header_match:
                name = header_match.group(1).strip()
                value = header_match.group(2).strip()
                headers[name.lower()] = value
                header_names.append(name)

        # Extract cookies
        cookies = {}
        cookie_fields = []
        cookie_values = []

        if "cookie" in headers:
            parsed_cookies = parse_cookie_header(headers["cookie"])
            if parsed_cookies is None:
                # A header past a bound produces no request. #175 states the reason.
                return None
            cookies, cookie_fields, cookie_values = parsed_cookies

        # Extract language
        language = headers.get("accept-language", "")

        # Extract referer
        referer = headers.get("referer", "")

        return {
            "method": method,
            "path": path,
            "version": version,
            "headers": header_names,
            "cookies": cookies,
            "cookie_fields": cookie_fields,
            "cookie_values": cookie_values,
            "language": language,
            "referer": referer,
        }

    except (ValueError, TypeError, UnicodeDecodeError) as e:
        logger.debug(f"Packet does not contain HTTP data: {e}")
        return None
