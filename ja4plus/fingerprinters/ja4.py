"""
JA4 TLS Client Hello Fingerprinting implementation.
"""

import hashlib
import logging
from scapy.all import TCP, UDP, Raw, IP

logger = logging.getLogger(__name__)
from ja4plus.utils.tls_utils import extract_tls_info, is_grease_value
from ja4plus.fingerprinters.base import BaseFingerprinter

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
        
        # Get ALPN value - extract first and last character
        # Per FoxIO spec: first+last alphanumeric char of first ALPN protocol
        # Non-ASCII (ord > 127) -> '99'
        alpn_protocols = tls_info.get('alpn_protocols', [])
        if not alpn_protocols:
            alpn_value = '00'
        else:
            first_alpn = alpn_protocols[0]

            if not first_alpn:
                alpn_value = '00'
            else:
                # FoxIO spec: if first char is non-ASCII, use '99'
                if ord(first_alpn[0]) > 127:
                    alpn_value = '99'
                elif len(first_alpn) == 1:
                    alpn_value = first_alpn[0] + first_alpn[0]
                else:
                    alpn_value = f"{first_alpn[0]}{first_alpn[-1]}"
        
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
        
        # ALPN - same as in generate_ja4
        alpn_protocols = tls_info.get('alpn_protocols', [])
        if not alpn_protocols:
            alpn_value = '00'
        else:
            first_alpn = alpn_protocols[0]

            if not first_alpn:
                alpn_value = '00'
            elif ord(first_alpn[0]) > 127:
                alpn_value = '99'
            elif len(first_alpn) == 1:
                alpn_value = first_alpn[0] + first_alpn[0]
            else:
                alpn_value = f"{first_alpn[0]}{first_alpn[-1]}"
        
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
        
        # Add suffix to indicate format
        if original_order:
            return f"JA4_ro = {raw_ja4}"
        else:
            return f"JA4_r = {raw_ja4}"
            
    except (ValueError, TypeError, IndexError, KeyError, AttributeError) as e:
        logger.debug(f"Failed to generate JA4 fingerprint: {e}")
        return None

class JA4Fingerprinter(BaseFingerprinter):
    """Fingerprinter for JA4 (TLS Client Hello)."""
    
    def process_packet(self, packet):
        """Process a packet and extract JA4 fingerprint if applicable."""
        # First extract TLS info from the packet
        tls_info = extract_tls_info(packet)
        
        if not tls_info:
            return None
        
        # Then generate JA4 from the extracted TLS info
        fingerprint = generate_ja4(tls_info)
        
        if fingerprint:
            self.add_fingerprint(fingerprint, packet)
        
        return fingerprint
        
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