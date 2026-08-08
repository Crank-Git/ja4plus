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

# A sender may end a line with the two bytes `\r\n`, or with one line feed. A parser that
# reads `\r\n` alone reads a line-feed request as one line, so it finds no header and no
# end of the header block. `tests/foxio_vectors/http-empty-useragent.pcap` holds such a
# request, and the reference holds a JA4H value for it. #193 records the defect.
LINE_ENDING_PATTERN = re.compile(r"\r\n|\n")

# The byte groups that end the header block of an HTTP message.
HEADER_BLOCK_TERMINATORS = (b"\r\n\r\n", b"\n\n")


def split_http_lines(text):
    """Return the lines of an HTTP message head.

    Args:
        text: The head of an HTTP message, as text.

    Returns:
        The lines in wire order. A line ends with the two bytes `\\r\\n`, or with one
        line feed.
    """
    return LINE_ENDING_PATTERN.split(text)


def header_block_end(data):
    """Return the offset of the first byte after the header block of an HTTP message.

    Args:
        data: The bytes the caller holds.

    Returns:
        The offset, or None when the bytes hold no complete header block.
    """
    ends = []
    for terminator in HEADER_BLOCK_TERMINATORS:
        offset = data.find(terminator)
        if offset != -1:
            ends.append(offset + len(terminator))
    if not ends:
        return None
    return min(ends)


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
        lines = split_http_lines(data_str)
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
            cookie_str = headers["cookie"]
            cookie_pairs = cookie_str.split(";")
            for pair in cookie_pairs:
                if "=" in pair:
                    cookie_parts = pair.split("=", 1)
                    if len(cookie_parts) == 2:
                        cookie_name = cookie_parts[0].strip()
                        cookie_value = cookie_parts[1].strip()
                        cookies[cookie_name] = cookie_value
                        cookie_fields.append(cookie_name)
                        cookie_values.append(cookie_value)

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
        lines = split_http_lines(data)

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
            cookie_str = headers["cookie"]
            cookie_pairs = cookie_str.split(";")

            for pair in cookie_pairs:
                if "=" in pair:
                    name, value = pair.split("=", 1)
                    name = name.strip()
                    value = value.strip()
                    cookies[name] = value
                    cookie_fields.append(name)
                    cookie_values.append(value)

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
