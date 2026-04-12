"""
JA4X X.509 Certificate Fingerprinting implementation.
"""

import hashlib
import logging
import struct
from scapy.all import IP, IPv6, TCP, Raw

logger = logging.getLogger(__name__)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from ja4plus.fingerprinters.base import BaseFingerprinter
from ja4plus.utils.x509_utils import oid_to_hex
import time

def generate_ja4x(cert_info):
    """
    Generate a JA4X fingerprint from certificate info.
    
    Args:
        cert_info: A dictionary with certificate information
        
    Returns:
        A JA4X fingerprint string or None if not applicable
    """
    if not cert_info:
        return None
        
    try:
        # Extract key components
        issuer_rdns = cert_info.get('issuer_rdns', [])
        subject_rdns = cert_info.get('subject_rdns', [])
        extensions = cert_info.get('extensions', [])
        
        # Create a signature based on structural elements
        issuer_str = ','.join(issuer_rdns)
        subject_str = ','.join(subject_rdns)
        ext_str = ','.join(extensions)

        # Hash these elements - SHA256 truncated to 12 hex chars
        # Use '000000000000' sentinel for empty values (consistent with other fingerprinters)
        issuer_hash = hashlib.sha256(issuer_str.encode()).hexdigest()[:12] if issuer_str else '000000000000'
        subject_hash = hashlib.sha256(subject_str.encode()).hexdigest()[:12] if subject_str else '000000000000'
        ext_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:12] if ext_str else '000000000000'
        
        # Form the complete JA4X fingerprint
        ja4x = f"{issuer_hash}_{subject_hash}_{ext_hash}"
        
        return ja4x
        
    except (ValueError, TypeError, KeyError, AttributeError) as e:
        logger.debug(f"Failed to generate JA4X fingerprint: {e}")
        return None

class JA4XFingerprinter(BaseFingerprinter):
    """Fingerprinter for JA4X (X.509 Certificates)."""
    
    def __init__(self):
        """Initialize the fingerprinter with TCP stream tracking."""
        super().__init__()
        from ja4plus.utils.tcp_stream import TCPStreamReassembler
        self.reassembler = TCPStreamReassembler(max_streams=50, max_stream_bytes=1048576)
        self.processed_certs = set()
        self.last_cleanup = time.time()

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        """Remove TCP stream buffer for the given connection."""
        stream_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        self.reassembler.remove_stream(stream_key)
        rev_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        self.reassembler.remove_stream(rev_key)

    def process_packet(self, packet):
        """Process a packet and extract JA4X fingerprint if applicable."""
        if not (TCP in packet and Raw in packet):
            return None

        try:
            from ja4plus.utils.packet_utils import get_ip_layer
            ip_layer = get_ip_layer(packet)
            if ip_layer is None:
                return None
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        except (IndexError, AttributeError):
            return None

        stream_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        raw_data = bytes(packet[Raw])
        seq = packet[TCP].seq if hasattr(packet[TCP], 'seq') else 0

        self.reassembler.add_segment(stream_id, seq, raw_data)
        stream_data = self.reassembler.get_stream(stream_id)

        fingerprint = self._find_certificates_in_stream_data(stream_id, stream_data, packet)

        current_time = time.time()
        if current_time - self.last_cleanup > 30:
            if len(self.processed_certs) > 1000:
                self.processed_certs = set(list(self.processed_certs)[-500:])
            self.last_cleanup = current_time

        return fingerprint
    
    def _find_certificates_in_stream_data(self, stream_id, stream_data, packet):
        """Find and process certificate messages in a TCP stream."""
        result = None

        if not stream_data:
            return None

        i = 0
        # Set a reasonable maximum search length to avoid hanging
        max_search = min(len(stream_data), 200000)  # 200KB search limit

        # Look for TLS records with certificate messages
        while i < max_search - 10:
            # Check for TLS handshake record
            if stream_data[i] == 0x16:  # TLS Handshake
                # Make sure we have enough data for the record header
                if i + 5 < len(stream_data):
                    record_length = (stream_data[i+3] << 8) | stream_data[i+4]

                    # Sanity check the record length
                    if record_length < 4 or record_length > 65535:
                        i += 1
                        continue

                    # Check if we have the complete record
                    if i + 5 + record_length <= len(stream_data):
                        # Check if this is a certificate message
                        if i + 5 < len(stream_data) and stream_data[i+5] == 0x0b:
                            # We found a certificate message, extract it
                            try:
                                cert_data = self._extract_certificate(stream_data[i:i+5+record_length])

                                if cert_data:
                                    for cert_bytes in cert_data:
                                        # Use hash of cert to avoid duplicates
                                        cert_hash = hashlib.sha256(cert_bytes).hexdigest()

                                        if cert_hash not in self.processed_certs:
                                            try:
                                                fingerprint = self.fingerprint_certificate(cert_bytes)
                                                if fingerprint:
                                                    result = fingerprint
                                                    self.add_fingerprint(fingerprint, packet)
                                                    self.processed_certs.add(cert_hash)
                                            except (ValueError, TypeError, Exception) as e:
                                                logger.warning(f"Certificate error: {e}")
                            except (ValueError, IndexError, struct.error) as e:
                                logger.debug(f"Certificate extraction failed: {e}")

                        # Move past this record
                        i += 5 + record_length
                        continue

            # Move to next byte
            i += 1

        # Trim the stream if we've processed a significant amount
        if i > 1000:
            self.reassembler.trim_stream(stream_id, i)

        return result
    
    def _extract_certificate(self, data):
        """Extract certificate data from a TLS Certificate message."""
        try:
            # Skip record header (5 bytes) and handshake header (4 bytes)
            pos = 9
            
            # Check if we have enough data
            if len(data) < pos + 3:
                return None
            
            # Get certificates list length (3 bytes)
            certs_len = (data[pos] << 16) | (data[pos+1] << 8) | data[pos+2]
            pos += 3
            
            if certs_len <= 0 or certs_len > len(data) - pos:
                return None
                
            certificates = []
            end_pos = pos + certs_len
            
            # Extract individual certificates
            while pos < end_pos - 3:  # Need at least 3 bytes for length
                # Each certificate is preceded by a 3-byte length
                cert_len = (data[pos] << 16) | (data[pos+1] << 8) | data[pos+2]
                pos += 3
                
                # Sanity check certificate length - be more lenient
                if cert_len <= 0 or cert_len > 200000:  # 200KB max cert size (increased)
                    break
                
                # Make sure we have the complete certificate
                if pos + cert_len > len(data):
                    break
                
                # Extract the certificate data - ensure this is bytes
                cert_data = bytes(data[pos:pos+cert_len])
                certificates.append(cert_data)
                
                pos += cert_len
            
            return certificates
        except (ValueError, IndexError, struct.error) as e:
            logger.debug(f"Failed to extract certificate from TLS record: {e}")
            return None
    
    def get_cert_details(self, cert):
        """
        Extract certificate details for JA4X fingerprinting.

        Uses hex-encoded OIDs to match FoxIO reference implementation.

        Args:
            cert: A cryptography X.509 certificate object

        Returns:
            Dictionary with certificate details
        """
        if not cert:
            return None

        try:
            issuer_rdns = []
            subject_rdns = []
            extensions = []

            # Process issuer - use hex-encoded OID per FoxIO spec
            for rdn in cert.issuer.rdns:
                for attr in rdn:
                    issuer_rdns.append(oid_to_hex(attr.oid.dotted_string))

            # Process subject
            for rdn in cert.subject.rdns:
                for attr in rdn:
                    subject_rdns.append(oid_to_hex(attr.oid.dotted_string))

            # Process extensions
            for ext in cert.extensions:
                extensions.append(oid_to_hex(ext.oid.dotted_string))

            return {
                'issuer_rdns': issuer_rdns,
                'subject_rdns': subject_rdns,
                'extensions': extensions
            }
        except (ValueError, TypeError, Exception) as e:
            logger.warning(f"Certificate error: {e}")
            return None

    def fingerprint_certificate(self, cert_data):
        """
        Generate a JA4X fingerprint from raw certificate data.
        
        Args:
            cert_data: Raw certificate data in DER format
            
        Returns:
            JA4X fingerprint or None if not applicable
        """
        try:
            # Ensure cert_data is bytes
            if not isinstance(cert_data, bytes):
                cert_data = bytes(cert_data)
            
            # Parse the certificate
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            
            # Extract certificate details
            cert_info = self.get_cert_details(cert)
            
            # Generate fingerprint
            return generate_ja4x(cert_info)
        except (ValueError, TypeError, Exception) as e:
            logger.warning(f"Certificate error: {e}")
            return None
    
    def reset(self):
        """Reset the fingerprinter state."""
        self.fingerprints = []
        from ja4plus.utils.tcp_stream import TCPStreamReassembler
        self.reassembler = TCPStreamReassembler(max_streams=50, max_stream_bytes=1048576)
        self.processed_certs = set()
        self.last_cleanup = time.time()