"""
JA4H HTTP Request Fingerprinting implementation.

JA4H fingerprints HTTP requests based on:
1. HTTP method, version, cookie flag, referer flag, header count, and language
2. Headers hash in the order they appear
3. Sorted cookie field names hash
4. Sorted cookie fields + values hash
"""

import hashlib
from scapy.all import IP, TCP, Raw
from ja4plus.utils.http_utils import extract_http_info
from ja4plus.fingerprinters.base import BaseFingerprinter


class JA4HFingerprinter(BaseFingerprinter):
    """
    JA4H HTTP Fingerprinting implementation.

    JA4H fingerprints HTTP requests based on method, headers, and cookies.
    """

    def process_packet(self, packet):
        """
        Process a packet and extract JA4H fingerprint if applicable.

        Args:
            packet: A network packet to analyze

        Returns:
            The extracted fingerprint if successful, None otherwise
        """
        fingerprint = generate_ja4h(packet)
        if fingerprint:
            self.add_fingerprint(fingerprint, packet)
            return fingerprint
        return None


def generate_ja4h(packet):
    """
    Generate JA4H fingerprint from HTTP request.

    Args:
        packet: An HTTP request packet

    Returns:
        JA4H fingerprint string if successful, None otherwise
    """
    # Extract HTTP info
    http_info = extract_http_info(packet)
    if not http_info:
        return None

    try:
        # Part A: HTTP method, version, cookies, referer, header count, language
        method = http_info.get('method', '').lower()
        version = http_info.get('version', '').replace('HTTP/', '')

        # Format version (e.g., "1.1" to "11", "2.0" to "20")
        version_str = version.replace('.', '')

        # Cookie indicator
        has_cookie = 'c' if http_info.get('cookie_fields', []) else 'n'

        # Referer indicator
        has_referer = 'r' if http_info.get('referer', '') else 'n'

        # Count of headers (excluding Cookie and Referer) - 2 digit format
        header_count = 0
        for header in http_info.get('headers', []):
            if header.lower() not in ['cookie', 'referer']:
                header_count += 1
        header_count = min(header_count, 99)
        header_count_str = f"{header_count:02d}"

        # Extract language code per FoxIO spec:
        # Replace hyphens, replace semicolons with commas, lowercase, take first,
        # truncate to 4 chars, pad with zeros to 4 chars
        language = http_info.get('language', '')
        lang_code = '0000'
        if language:
            lang_clean = language.replace('-', '').replace(';', ',').lower().split(',')[0]
            lang_clean = lang_clean[:4]
            lang_code = f"{lang_clean}{'0' * (4 - len(lang_clean))}" if lang_clean else '0000'

        part_a = f"{method[:2]}{version_str}{has_cookie}{has_referer}{header_count_str}{lang_code}"

        # Part B: Header names hash - keep original order
        # Per FoxIO spec: exclude pseudo-headers (starting with ':'),
        # Cookie, Referer, and empty headers from the hash
        headers = http_info.get('headers', [])
        filtered_headers = [
            h for h in headers
            if not h.startswith(':')
            and h.lower() != 'cookie'
            and h.lower() != 'referer'
            and h
        ]
        headers_str = ','.join(filtered_headers)
        if headers_str:
            part_b = hashlib.sha256(headers_str.encode()).hexdigest()[:12]
        else:
            part_b = '000000000000'

        # Part C: Cookie field names hash (sorted alphabetically)
        cookie_fields = sorted(http_info.get('cookie_fields', []))
        cookie_fields_str = ','.join(cookie_fields)
        if cookie_fields_str:
            part_c = hashlib.sha256(cookie_fields_str.encode()).hexdigest()[:12]
        else:
            part_c = '000000000000'

        # Part D: Cookie values hash - per FoxIO spec, hash the full
        # "name=value" cookie strings sorted alphabetically by name
        cookie_dict = http_info.get('cookies', {})
        sorted_cookie_pairs = sorted(cookie_dict.items())
        cookie_values_str = ','.join(f"{k}={v}" for k, v in sorted_cookie_pairs)
        if cookie_values_str:
            part_d = hashlib.sha256(cookie_values_str.encode()).hexdigest()[:12]
        else:
            part_d = '000000000000'

        # Form the JA4H fingerprint
        ja4h = f"{part_a}_{part_b}_{part_c}_{part_d}"

        return ja4h

    except Exception:
        return None
