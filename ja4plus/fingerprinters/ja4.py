"""
JA4 TLS Client Hello Fingerprinting implementation.
"""

import hashlib
import logging
from scapy.all import TCP, UDP, Raw, IP

logger = logging.getLogger(__name__)
from ja4plus.utils.tls_utils import extract_tls_info, is_grease_value
from ja4plus.fingerprinters.base import BaseFingerprinter


def _is_alnum_byte(b):
    """ASCII alphanumeric per FoxIO PR #277: 0-9, A-Z, a-z."""
    return (0x30 <= b <= 0x39) or (0x41 <= b <= 0x5A) or (0x61 <= b <= 0x7A)


def compute_alpn_value(first_alpn_bytes):
    """Compute the JA4 ALPN value per FoxIO spec PR #277.

    Rules:
        - empty / None: '00'
        - both first and last byte ASCII alphanumeric: those two bytes as chars
          (single-byte ALPN duplicates the byte, e.g. 'h' -> 'hh')
        - either end non-alphanumeric: first and last char of HEX representation
          of the FULL first ALPN string (lowercase)

    Examples:
        b'\\xab'         -> 'ab'
        b'\\x20'         -> '20'
        b'\\xab\\xcd'    -> 'ad'
        b'\\x20\\x61'    -> '21'
        b'\\x30\\xab'    -> '3b'  (first alnum, last not -> hex)
        b'\\x61\\x20'    -> '60'
        b'\\x30\\x31\\xab\\xcd' -> '3d'
        b'\\x30\\xab\\xcd\\x31' -> '01'  (both ends alnum -> bytes directly)
        b'h2'            -> 'h2'
        b'h'             -> 'hh'
    """
    if not first_alpn_bytes:
        return "00"

    first = first_alpn_bytes[0]
    last = first_alpn_bytes[-1]

    if _is_alnum_byte(first) and _is_alnum_byte(last):
        if len(first_alpn_bytes) == 1:
            ch = chr(first)
            return ch + ch
        return chr(first) + chr(last)

    # Non-alphanumeric at either end: use hex of full first ALPN value.
    hex_str = first_alpn_bytes.hex()  # always lowercase
    return hex_str[0] + hex_str[-1]

def generate_ja4(tls_info):
    """
    Generate a JA4 fingerprint from TLS Client Hello info.
    
    Args:
        tls_info: A dictionary with TLS handshake information
        
    Returns:
        A JA4 fingerprint string or None if not applicable
    """
    if not tls_info or tls_info.get('type') != 'client_hello':
        return None
        
    try:
        # Determine protocol type (q=QUIC, d=DTLS, t=TLS over TCP)
        proto = 'q' if tls_info.get('is_quic') else 'd' if tls_info.get('is_dtls') else 't'
        
        # Get TLS version - prioritize supported_versions extension (0x002b)
        version = tls_info.get('version')
        supported_versions = tls_info.get('supported_versions', [])
        
        # Filter out GREASE values
        supported_versions = [v for v in supported_versions if not is_grease_value(v)]
        
        if supported_versions:
            # Use highest supported version
            version = max(supported_versions)
        
        # Convert version to string format
        if version == 0x0304:  # TLS 1.3
            version_str = '13'
        elif version == 0x0303:  # TLS 1.2
            version_str = '12'
        elif version == 0x0302:  # TLS 1.1
            version_str = '11'
        elif version == 0x0301:  # TLS 1.0
            version_str = '10'
        elif version == 0x0300:  # SSL 3.0
            version_str = 's3'
        elif version == 0x0200:  # SSL 2.0
            version_str = 's2'
        elif version == 0xfeff:  # DTLS 1.0
            version_str = 'd1'
        elif version == 0xfefd:  # DTLS 1.2
            version_str = 'd2'
        elif version == 0xfefc:  # DTLS 1.3
            version_str = 'd3'
        else:
            version_str = '00'
            
        # SNI type - 'd' if SNI exists, 'i' if not
        sni = tls_info.get('sni')
        sni_type = 'd' if sni else 'i'
        
        # Get cipher suites - filter out GREASE values
        ciphers = [c for c in tls_info.get('ciphers', []) if not is_grease_value(c)]
        cipher_count = min(len(ciphers), 99)  # Cap at 99
        cipher_count_str = f"{cipher_count:02d}"
        
        # Get extensions - filter out GREASE values
        extensions = [e for e in tls_info.get('extensions', []) if not is_grease_value(e)]
        ext_count = min(len(extensions), 99)  # Cap at 99
        ext_count_str = f"{ext_count:02d}"
        
        # ALPN value per FoxIO spec PR #277: see compute_alpn_value().
        # Prefer the raw bytes (full byte fidelity) and fall back to the
        # decoded string for backward-compat callers that only set
        # alpn_protocols.
        alpn_raw = tls_info.get('alpn_raw') or []
        alpn_protocols = tls_info.get('alpn_protocols', [])
        if alpn_raw:
            alpn_value = compute_alpn_value(alpn_raw[0])
        elif alpn_protocols and alpn_protocols[0]:
            alpn_value = compute_alpn_value(alpn_protocols[0].encode('latin-1', errors='replace'))
        else:
            alpn_value = '00'
        
        # Form part_a of the fingerprint
        part_a = f"{proto}{version_str}{sni_type}{cipher_count_str}{ext_count_str}{alpn_value}"
        
        # Generate cipher hash - sort ciphers first
        if ciphers:
            sorted_ciphers = sorted(ciphers)
            cipher_str = ','.join([f"{c:04x}" for c in sorted_ciphers])
            cipher_hash = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]
        else:
            cipher_hash = '000000000000'
        
        # Generate extension hash
        # 1. Remove SNI (0x0000) and ALPN (0x0010) from extensions for hashing
        filtered_extensions = [e for e in extensions if e != 0x0000 and e != 0x0010]
        
        # 2. Sort filtered extensions
        sorted_extensions = sorted(filtered_extensions)
        
        # 3. Get signature algorithms in original order
        sig_algs = tls_info.get('signature_algorithms', [])
        
        # 4. Form extension string - sorted extensions + underscore + sig algorithms if present
        ext_str = ','.join([f"{e:04x}" for e in sorted_extensions])
        if sig_algs:
            sig_alg_str = ','.join([f"{s:04x}" for s in sig_algs])
            ext_str = f"{ext_str}_{sig_alg_str}"
            
        # 5. Generate extension hash
        if ext_str:
            ext_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
        else:
            ext_hash = '000000000000'
        
        # Form the complete JA4 fingerprint
        ja4 = f"{part_a}_{cipher_hash}_{ext_hash}"
        
        return ja4
        
    except (ValueError, TypeError, IndexError, KeyError, AttributeError) as e:
        logger.debug(f"Failed to generate JA4 fingerprint: {e}")
        return None

def get_raw_fingerprint(tls_info, original_order=False):
    """
    Generate a raw JA4 fingerprint with all values visible.
    
    Args:
        tls_info: A dictionary with TLS handshake information
        original_order: Whether to maintain original ordering (True) or sort (False)
        
    Returns:
        A raw JA4 fingerprint string or None if not applicable
    """
    if not tls_info or tls_info.get('type') != 'client_hello':
        return None
        
    try:
        # Get the same components as in generate_ja4
        proto = 'q' if tls_info.get('is_quic') else 'd' if tls_info.get('is_dtls') else 't'
        
        # Version
        version = tls_info.get('version')
        supported_versions = tls_info.get('supported_versions', [])
        supported_versions = [v for v in supported_versions if not is_grease_value(v)]
        
        if supported_versions:
            version = max(supported_versions)
            
        # Map version to string format (same as in generate_ja4)
        if version == 0x0304:  # TLS 1.3
            version_str = '13'
        elif version == 0x0303:  # TLS 1.2
            version_str = '12'
        elif version == 0x0302:  # TLS 1.1
            version_str = '11'
        elif version == 0x0301:  # TLS 1.0
            version_str = '10'
        elif version == 0x0300:  # SSL 3.0
            version_str = 's3'
        elif version == 0x0200:  # SSL 2.0
            version_str = 's2'
        elif version == 0xfeff:  # DTLS 1.0
            version_str = 'd1'
        elif version == 0xfefd:  # DTLS 1.2
            version_str = 'd2'
        elif version == 0xfefc:  # DTLS 1.3
            version_str = 'd3'
        else:
            version_str = '00'
            
        # SNI
        sni = tls_info.get('sni')
        sni_type = 'd' if sni else 'i'
        
        # Ciphers - filter GREASE
        ciphers = [c for c in tls_info.get('ciphers', []) if not is_grease_value(c)]
        cipher_count = min(len(ciphers), 99)
        cipher_count_str = f"{cipher_count:02d}"
        
        # Extensions - filter GREASE
        extensions = [e for e in tls_info.get('extensions', []) if not is_grease_value(e)]
        ext_count = min(len(extensions), 99)
        ext_count_str = f"{ext_count:02d}"
        
        # ALPN per FoxIO spec PR #277 — same path as generate_ja4
        alpn_raw = tls_info.get('alpn_raw') or []
        alpn_protocols = tls_info.get('alpn_protocols', [])
        if alpn_raw:
            alpn_value = compute_alpn_value(alpn_raw[0])
        elif alpn_protocols and alpn_protocols[0]:
            alpn_value = compute_alpn_value(alpn_protocols[0].encode('latin-1', errors='replace'))
        else:
            alpn_value = '00'
        
        # First part of fingerprint
        part_a = f"{proto}{version_str}{sni_type}{cipher_count_str}{ext_count_str}{alpn_value}"
        
        # Cipher list - either sorted or original
        if original_order:
            cipher_list = ','.join([f"{c:04x}" for c in tls_info.get('ciphers', []) if not is_grease_value(c)])
        else:
            cipher_list = ','.join([f"{c:04x}" for c in sorted(ciphers)])
        
        # Extension list - either with or without SNI/ALPN based on original_order
        if original_order:
            ext_list = ','.join([f"{e:04x}" for e in tls_info.get('extensions', []) if not is_grease_value(e)])
        else:
            ext_list = ','.join([f"{e:04x}" for e in sorted([e for e in extensions if e != 0x0000 and e != 0x0010])])
        
        # Signature algorithms
        sig_algs = tls_info.get('signature_algorithms', [])
        sig_alg_list = ','.join([f"{s:04x}" for s in sig_algs])
        
        # Final format
        if sig_algs:
            if original_order:
                raw_ja4 = f"{part_a}_{cipher_list}_{ext_list}_{sig_alg_list}"
            else:
                raw_ja4 = f"{part_a}_{cipher_list}_{ext_list}_{sig_alg_list}"
        else:
            raw_ja4 = f"{part_a}_{cipher_list}_{ext_list}"
        
        return raw_ja4
            
    except (ValueError, TypeError, IndexError, KeyError, AttributeError) as e:
        logger.debug(f"Failed to generate JA4 fingerprint: {e}")
        return None

class JA4Fingerprinter(BaseFingerprinter):
    """Fingerprinter for JA4 (TLS Client Hello).

    In addition to the hashed JA4 fingerprint returned by ``process_packet``,
    this fingerprinter exposes the raw (unhashed) variants on every entry in
    ``get_fingerprints()`` and on ``last_raw`` / ``last_raw_original_order``
    for the most recent successful parse, mirroring the Go reference's
    FingerprintResult.Raw / RawOriginalOrder fields.
    """

    def __init__(self):
        super().__init__()
        self.last_raw = None
        self.last_raw_original_order = None
        # DCID -> list[(offset, data)] for multi-datagram QUIC CRYPTO reassembly.
        # Keyed by DCID hex so packets with the same connection ID accumulate
        # together regardless of UDP 5-tuple changes.
        self._quic_fragments = {}
        self._quic_dcid_to_tuple = {}

    def process_packet(self, packet):
        """Process a packet and extract JA4 fingerprint if applicable.

        For QUIC Initials larger than one datagram, CRYPTO frame fragments
        accumulate per Destination Connection ID until a full ClientHello
        can be reassembled. Once parsed, the per-DCID buffer is released.
        """
        tls_info = extract_tls_info(packet)
        if not tls_info:
            tls_info = self._try_quic_multi_packet(packet)
        if not tls_info:
            return None

        fingerprint = generate_ja4(tls_info)
        if fingerprint:
            raw = get_raw_fingerprint(tls_info, original_order=False)
            raw_oo = get_raw_fingerprint(tls_info, original_order=True)
            self.last_raw = raw
            self.last_raw_original_order = raw_oo
            self.fingerprints.append({
                'fingerprint': fingerprint,
                'raw': raw,
                'raw_original_order': raw_oo,
                'packet': packet,
            })

        return fingerprint

    def _try_quic_multi_packet(self, packet):
        """Accumulate QUIC CRYPTO fragments per DCID; return tls_info if a
        full ClientHello has been reassembled."""
        from scapy.all import UDP
        from ja4plus.utils.quic_utils import (
            decrypt_quic_initial_crypto,
            client_hello_from_crypto_fragments,
        )

        udp = packet.getlayer(UDP)
        if udp is None:
            return None
        udp_payload = bytes(udp.payload)
        if not udp_payload:
            return None

        fragments, dcid = decrypt_quic_initial_crypto(udp_payload)
        if dcid is None or fragments is None:
            return None

        dcid_key = dcid.hex()
        existing = self._quic_fragments.setdefault(dcid_key, [])
        existing.extend(fragments)

        # Track DCID -> 5-tuple for cleanup_connection.
        from ja4plus.utils.packet_utils import get_ip_layer
        ip = get_ip_layer(packet)
        if ip is not None:
            tuple_key = f"{ip.src}:{int(udp.sport)}-{ip.dst}:{int(udp.dport)}"
            self._quic_dcid_to_tuple[dcid_key] = tuple_key

        tls_info = client_hello_from_crypto_fragments(existing)
        if tls_info is not None:
            # ClientHello is complete — release the buffer.
            del self._quic_fragments[dcid_key]
            self._quic_dcid_to_tuple.pop(dcid_key, None)
        return tls_info

    def reset(self):
        super().reset()
        self.last_raw = None
        self.last_raw_original_order = None
        self._quic_fragments = {}
        self._quic_dcid_to_tuple = {}

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        """Drop any accumulated QUIC CRYPTO fragments for the given 5-tuple."""
        tuple_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        rev_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        for dcid_key, tup in list(self._quic_dcid_to_tuple.items()):
            if tup == tuple_key or tup == rev_key:
                self._quic_fragments.pop(dcid_key, None)
                self._quic_dcid_to_tuple.pop(dcid_key, None)

    def get_raw_fingerprint(self, packet, original_order=False):
        """
        Get raw JA4 fingerprint with visible components.

        Args:
            packet: A packet containing a TLS Client Hello
            original_order: Whether to maintain original ordering

        Returns:
            Raw JA4 fingerprint string or None
        """
        tls_info = extract_tls_info(packet)
        if not tls_info:
            return None

        return get_raw_fingerprint(tls_info, original_order)
