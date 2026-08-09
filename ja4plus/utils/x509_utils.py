"""
Enhanced X.509 certificate utility functions for JA4+ fingerprinting.
"""

# Python 3.9 is the floor, and it evaluates no annotation written as `str | None`
# without this import.
from __future__ import annotations

import logging
from typing import Any

# Both names stay at module scope. `extract_certificate_from_bytes` reads them inside a
# branch, and a branch-local import makes each name a local of the whole function. A
# later read of either name then raises `UnboundLocalError`. #309 records the defect and
# #314 removes the second copy of it.
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


def extract_certificate_from_bytes(
    data: bytes, verbose: bool = False, try_asn1: bool = False
) -> bytes | None:
    """Return the DER form of the first certificate the data carries.

    Every packet is hostile input, so the reader returns nothing for data it cannot
    read. It raises nothing for a byte string.

    Args:
        data: Byte data possibly containing a certificate
        verbose: Whether to print verbose debugging info
        try_asn1: Whether to try direct ASN.1 parsing (usually noisy)

    Returns:
        Certificate data as bytes, or None when the data carries no certificate.
        Input that is no sequence of bytes also returns None.
    """
    try:
        # Method 1: Look for TLS handshake certificate message
        i = 0
        while i < len(data) - 10:
            # Check for TLS handshake record with certificate
            if data[i] == 0x16:  # Handshake record type
                # Look for certificate handshake type (11)
                handshake_pos = i + 5
                if handshake_pos < len(data) and data[handshake_pos] == 0x0B:
                    # Found certificate message
                    if verbose:
                        print(f"  Found certificate handshake at position {i}")

                    # TLS Record Header (5 bytes)
                    # Skip to handshake header
                    pos = i + 5

                    # Handshake Header (4 bytes: type(1) + length(3))
                    if pos + 4 <= len(data):
                        handshake_type = data[pos]
                        handshake_length = (
                            (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]
                        )

                        if verbose:
                            print(f"  Handshake type: {handshake_type}, length: {handshake_length}")

                        pos += 4  # Move past handshake header

                        # Certificate List Length (3 bytes)
                        if pos + 3 <= len(data):
                            certs_len = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]

                            if verbose:
                                print(f"  Certificate list length: {certs_len}")

                            pos += 3  # Move past certificate list length

                            # Individual Certificate Length (3 bytes)
                            if pos + 3 <= len(data):
                                cert_len = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]

                                if verbose:
                                    print(f"  First certificate length: {cert_len}")

                                pos += 3  # Move past certificate length

                                # Certificate Data
                                if pos + cert_len <= len(data):
                                    if verbose:
                                        print(
                                            f"  Extracting certificate at offset {pos} with length {cert_len}"
                                        )
                                        print(
                                            f"  Certificate starts with: {data[pos : pos + 16].hex()}"
                                        )

                                    # This is the actual X.509 certificate data
                                    return data[pos : pos + cert_len]
            i += 1

        # Method 2: Look for ASN.1 SEQUENCE that could be a certificate
        # Only attempt this if explicitly requested
        if try_asn1:
            i = 0
            while i < len(data) - 10:
                # Look for ASN.1 SEQUENCE tag (0x30) followed by length
                if data[i] == 0x30:
                    # Check different length encodings
                    if i + 1 < len(data):
                        if data[i + 1] & 0x80 == 0:
                            # Short form length
                            seq_len = data[i + 1]
                            header_size = 2
                        elif data[i + 1] == 0x81 and i + 2 < len(data):
                            # Long form, 1 byte
                            seq_len = data[i + 2]
                            header_size = 3
                        elif data[i + 1] == 0x82 and i + 3 < len(data):
                            # Long form, 2 bytes
                            seq_len = (data[i + 2] << 8) | data[i + 3]
                            header_size = 4
                        elif data[i + 1] == 0x83 and i + 4 < len(data):
                            # Long form, 3 bytes
                            seq_len = (data[i + 2] << 16) | (data[i + 3] << 8) | data[i + 4]
                            header_size = 5
                        else:
                            i += 1
                            continue

                        # Check if we have enough data for the complete sequence
                        if i + header_size + seq_len <= len(data):
                            # Extract the potential certificate
                            candidate = data[i : i + header_size + seq_len]

                            # Check if this looks like a certificate
                            if b"\x06\x03\x55\x04" in candidate:  # Common OID pattern
                                try:
                                    # The call raises on a candidate that is not a
                                    # certificate, so it is the test. The result is
                                    # unused, because the caller wants the raw bytes.
                                    _cert = x509.load_der_x509_certificate(
                                        candidate, default_backend()
                                    )

                                    if verbose:
                                        print(f"  Found ASN.1 certificate at position {i}")

                                    return candidate
                                # The `cryptography` documentation names `ValueError`
                                # for data the loader cannot parse. A measurement of
                                # malformed certificates also raised `InvalidVersion`,
                                # which inherits `Exception` and not `ValueError`, so
                                # a list of `ValueError` alone drops it. #316 holds
                                # the measurement.
                                except (ValueError, x509.InvalidVersion) as e:
                                    if verbose:
                                        print(f"  ASN.1 parse error: {e}")
                i += 1

        return None
    # The scan reads one byte at a time and guards every index, so it raises nothing
    # for a byte string. `len()` raises `TypeError` for input that is no sequence, and
    # `JA4XFingerprinter.read_certificate` names `TypeError` for the same reason. The
    # loader errors stay inside the ASN.1 branch above. #316 names the list.
    except TypeError as e:
        if verbose:
            print(f"  Error finding certificate: {e}")
        return None


def oid_to_hex(oid_string: str) -> str:
    """
    Convert OID dotted string to hex representation using ASN.1 encoding.

    Per FoxIO reference implementation, uses proper ASN.1 OID encoding:
    - First two components combined: first*40 + second
    - Subsequent components use variable-length quantity (VLQ) encoding

    Example: OID 2.5.4.3 -> '550403' (0x55=2*40+5, 0x04=4, 0x03=3)
    """
    parts = [int(p) for p in oid_string.split(".")]
    if len(parts) < 2:
        return "".join(f"{p:02x}" for p in parts)

    # First two components are combined per ASN.1 rules
    encoded = [parts[0] * 40 + parts[1]]

    # Remaining components use VLQ encoding
    for part in parts[2:]:
        if part < 0x80:
            encoded.append(part)
        else:
            # Variable-length quantity encoding for values >= 128
            vlq_bytes = []
            val = part
            vlq_bytes.append(val & 0x7F)
            val >>= 7
            while val > 0:
                vlq_bytes.append((val & 0x7F) | 0x80)
                val >>= 7
            vlq_bytes.reverse()
            encoded.extend(vlq_bytes)

    return "".join(f"{b:02x}" for b in encoded)


def get_cert_details(cert: x509.Certificate) -> dict[str, Any] | None:
    """Extract detailed certificate information for JA4X"""
    try:
        # Extract issuer RDNs in order
        issuer_rdns = []
        for rdn in cert.issuer.rdns:
            for attr in rdn:
                # Convert OID to hex string
                oid_hex = oid_to_hex(attr.oid.dotted_string)
                issuer_rdns.append(oid_hex)

        # Extract subject RDNs in order
        subject_rdns = []
        for rdn in cert.subject.rdns:
            for attr in rdn:
                oid_hex = oid_to_hex(attr.oid.dotted_string)
                subject_rdns.append(oid_hex)

        # Extract extensions in order
        extensions = []
        for ext in cert.extensions:
            oid_hex = oid_to_hex(ext.oid.dotted_string)
            extensions.append(oid_hex)

        return {
            "issuer_rdns": issuer_rdns,
            "subject_rdns": subject_rdns,
            "extensions": extensions,
            "serial": str(cert.serial_number),
            "not_before": cert.not_valid_before_utc,
            "not_after": cert.not_valid_after_utc,
            "version": cert.version.name,
        }
    except (ValueError, TypeError, AttributeError) as e:
        logger.warning(f"Certificate error: {e}")
        return None
