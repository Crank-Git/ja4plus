"""
JA4X X.509 Certificate Fingerprinting implementation.
"""

import hashlib
import logging
import struct
from scapy.all import IP, IPv6, TCP, Raw

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from ja4plus.fingerprinters.base import BaseFingerprinter
from ja4plus.utils.state_table import BoundedStateTable
from ja4plus.utils.x509_utils import oid_to_hex

logger = logging.getLogger(__name__)

# A TLS record header holds the content type, two version bytes, and a two-byte length.
TLS_RECORD_HEADER_LENGTH = 5
TLS_HANDSHAKE_CONTENT_TYPE = 0x16
# Every TLS version the record layer names carries the major version 3. The check
# rejects a byte pair that the encrypted payload holds by chance.
TLS_RECORD_MAJOR_VERSION = 0x03
# A TLS handshake message header holds the message type and a three-byte length.
TLS_HANDSHAKE_HEADER_LENGTH = 4
TLS_CERTIFICATE_MESSAGE_TYPE = 0x0B
# A certificate entry and a certificate list each carry a three-byte length.
CERTIFICATE_LENGTH_BYTES = 3
# The scan reads at most this many bytes of one stream. A stream grows without a limit,
# and the scan runs again on every packet of the stream.
MAX_SCAN_BYTES = 200000
# A length above this size names no certificate. The reader stops there, because the
# packet is hostile input and the field carries any value.
MAX_CERTIFICATE_BYTES = 200000
# The maximum number of certificates the fingerprinter remembers. The entry key names
# the stream, so a capture of many streams needs more entries than a capture of one.
MAX_PROCESSED_CERTS = 1000


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
        issuer_rdns = cert_info.get("issuer_rdns", [])
        subject_rdns = cert_info.get("subject_rdns", [])
        extensions = cert_info.get("extensions", [])

        # Create a signature based on structural elements
        issuer_str = ",".join(issuer_rdns)
        subject_str = ",".join(subject_rdns)
        ext_str = ",".join(extensions)

        # Hash these elements - SHA256 truncated to 12 hex chars
        # Use '000000000000' sentinel for empty values (consistent with other fingerprinters)
        issuer_hash = (
            hashlib.sha256(issuer_str.encode()).hexdigest()[:12] if issuer_str else "000000000000"
        )
        subject_hash = (
            hashlib.sha256(subject_str.encode()).hexdigest()[:12] if subject_str else "000000000000"
        )
        ext_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:12] if ext_str else "000000000000"

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
        # The table holds one entry for each certificate on each stream, and the
        # certificate of a stream that goes quiet reaches no reader again.
        self.processed_certs = BoundedStateTable(
            max_connections=MAX_PROCESSED_CERTS, eviction_interval=1
        )
        # One entry for each live stream, so the reassembler states the entry count.
        self.scan_offsets = BoundedStateTable(
            max_connections=self.reassembler.max_streams,
            max_connection_age=self.reassembler.max_stream_age,
            eviction_interval=1,
        )

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        """Remove the stream buffer and the certificate state of the connection."""
        stream_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        self.reassembler.remove_stream(stream_key)
        rev_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        self.reassembler.remove_stream(rev_key)
        closed = (stream_key, rev_key)
        for key in self.processed_certs.keys():
            if key[0] in closed:
                del self.processed_certs[key]
        for key in closed:
            self.scan_offsets.pop(key, None)

    def process_packet(self, packet):
        """Process a packet and extract JA4X fingerprint if applicable."""
        if not (TCP in packet and Raw in packet):
            return None

        try:
            from ja4plus.utils.packet_utils import get_ip_layer, packet_seconds

            ip_layer = get_ip_layer(packet)
            if ip_layer is None:
                return None
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        except (IndexError, AttributeError):
            return None

        # The two tables age against the capture clock, so every packet announces its
        # own timestamp. A table that reads the wall clock evicts state a replay needs.
        seconds = packet_seconds(packet)
        self.processed_certs.on_packet(seconds)
        self.scan_offsets.on_packet(seconds)

        stream_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        raw_data = bytes(packet[Raw])
        seq = packet[TCP].seq if hasattr(packet[TCP], "seq") else 0

        self.reassembler.add_segment(stream_id, seq, raw_data, packet_seconds(packet))
        stream_data = self.reassembler.get_stream(stream_id)

        fingerprint = self._find_certificates_in_stream_data(stream_id, stream_data, packet)

        return fingerprint

    def _find_certificates_in_stream_data(self, stream_id, stream_data, packet):
        """Return the last JA4X value the stream yields, or None.

        The scan reads the TLS record layer, then the handshake messages inside it. One
        record carries more than one handshake message, and one handshake message spans
        more than one record. A scan that reads only the first message of a record
        misses the Certificate message that follows a ServerHello.

        The scan resumes where the last packet of the stream left it. A scan that starts
        at zero on every packet costs the square of the stream length, and one TLS 1.3
        stream of the vectors then takes 18 seconds.

        A segment that arrives late lowers the sequence number the reassembled bytes
        start at, which moves every offset. The scan then starts at zero again, because
        the saved offset names a byte the stream no longer holds there.

        Args:
            stream_id: The key of the stream in the reassembler.
            stream_data: The contiguous bytes of the stream.
            packet: The packet that completed the stream data.

        Returns:
            The last JA4X value the scan produced, or None.
        """
        result = None
        if not stream_data:
            return None

        limit = min(len(stream_data), MAX_SCAN_BYTES)
        base_seq = self.reassembler.base_seq(stream_id)
        saved = self.scan_offsets.get(stream_id)
        offset = saved[1] if saved is not None and saved[0] == base_seq else 0
        while offset + TLS_RECORD_HEADER_LENGTH <= limit:
            handshake, next_offset, truncated = self._read_handshake_run(stream_data, offset, limit)
            for message in self._certificate_messages(handshake or b""):
                fingerprint = self._read_certificate_message(stream_id, message, packet)
                if fingerprint:
                    result = fingerprint
            if truncated:
                # A later packet completes the record, and a handshake message spans two
                # records, so the next scan reads this run again from its start.
                break
            if handshake is None:
                # A proxy writes its own handshake before the TLS record layer starts,
                # so the stream does not always start on a record boundary.
                offset += 1
                continue
            offset = next_offset

        # The table holds the entry count and the entry age, and it evicts the least
        # recently read entry on its own.
        self.scan_offsets[stream_id] = (base_seq, offset)
        return result

    def _read_handshake_run(self, stream_data, offset, limit):
        """Return the handshake bytes of the records that start at the offset.

        The run holds the payload of every complete handshake record that follows the
        offset without a gap. A handshake message spans two records, so the reader joins
        the records before it reads the messages.

        Args:
            stream_data: The contiguous bytes of the stream.
            offset: The offset the run starts at.
            limit: The offset the scan stops at.

        Returns:
            A (handshake bytes, next offset, truncated) triple. The bytes are None when
            the offset holds no complete handshake record, and the next offset is then
            the offset. The truncated flag is True when the run stops at a record header
            whose body the stream does not hold yet.
        """
        handshake = bytearray()
        position = offset
        truncated = False
        while position + TLS_RECORD_HEADER_LENGTH <= limit:
            if stream_data[position] != TLS_HANDSHAKE_CONTENT_TYPE:
                break
            if stream_data[position + 1] != TLS_RECORD_MAJOR_VERSION:
                break
            length = (stream_data[position + 3] << 8) | stream_data[position + 4]
            end = position + TLS_RECORD_HEADER_LENGTH + length
            if length == 0:
                break
            if end > limit:
                truncated = True
                break
            handshake.extend(stream_data[position + TLS_RECORD_HEADER_LENGTH : end])
            position = end

        if not handshake:
            return None, offset, truncated
        return bytes(handshake), position, truncated

    def _certificate_messages(self, handshake):
        """Return the body of every Certificate message in the handshake bytes.

        Args:
            handshake: The joined payload of one run of handshake records.

        Returns:
            A list of message bodies. The body starts at the certificate list length.
        """
        messages = []
        position = 0
        while position + TLS_HANDSHAKE_HEADER_LENGTH <= len(handshake):
            message_type = handshake[position]
            length = int.from_bytes(
                handshake[position + 1 : position + TLS_HANDSHAKE_HEADER_LENGTH], "big"
            )
            end = position + TLS_HANDSHAKE_HEADER_LENGTH + length
            if end > len(handshake):
                break
            if message_type == TLS_CERTIFICATE_MESSAGE_TYPE:
                messages.append(handshake[position + TLS_HANDSHAKE_HEADER_LENGTH : end])
            position = end
        return messages

    def _read_certificate_message(self, stream_id, message, packet):
        """Return the last JA4X value of one Certificate message, or None.

        FoxIO computes one JA4X value for each certificate on each stream, and its
        implementation holds no cache. The key names the stream, because a key that
        names only the certificate drops the value of every stream after the first that
        carries the same chain.

        Args:
            stream_id: The key of the stream in the reassembler.
            message: The body of one Certificate message.
            packet: The packet that completed the stream data.

        Returns:
            The last JA4X value the message produced, or None.
        """
        result = None
        for cert_bytes in self._certificates_in_message(message):
            key = (stream_id, hashlib.sha256(cert_bytes).hexdigest())
            if key in self.processed_certs:
                continue
            # The table holds the entry count and the entry age, and it evicts the
            # least recently read entry on its own.
            self.processed_certs[key] = None
            fingerprint = self.fingerprint_certificate(cert_bytes)
            if fingerprint:
                result = fingerprint
                self.add_fingerprint(fingerprint, packet)
        return result

    def _certificates_in_message(self, message):
        """Return the certificates of one Certificate message body.

        The reader trusts no length field it read from the packet. A length that runs
        past the message ends the read, and the reader returns the certificates it
        already holds.

        Args:
            message: The body of one Certificate message, from the list length on.

        Returns:
            A list of certificates in DER form. The list is empty when the message
            carries no complete certificate.
        """
        try:
            if len(message) < CERTIFICATE_LENGTH_BYTES:
                return []

            position = CERTIFICATE_LENGTH_BYTES
            list_length = int.from_bytes(message[:CERTIFICATE_LENGTH_BYTES], "big")
            end = position + list_length
            if list_length <= 0 or end > len(message):
                return []

            certificates = []
            while position + CERTIFICATE_LENGTH_BYTES <= end:
                length = int.from_bytes(
                    message[position : position + CERTIFICATE_LENGTH_BYTES], "big"
                )
                position += CERTIFICATE_LENGTH_BYTES
                if length <= 0 or length > MAX_CERTIFICATE_BYTES:
                    break
                if position + length > end:
                    break
                certificates.append(bytes(message[position : position + length]))
                position += length

            return certificates
        except (ValueError, IndexError, struct.error) as e:
            logger.debug(f"Failed to read the certificates of a TLS message: {e}")
            return []

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
                "issuer_rdns": issuer_rdns,
                "subject_rdns": subject_rdns,
                "extensions": extensions,
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
        # The table holds one entry for each certificate on each stream, and the
        # certificate of a stream that goes quiet reaches no reader again.
        self.processed_certs = BoundedStateTable(
            max_connections=MAX_PROCESSED_CERTS, eviction_interval=1
        )
        # One entry for each live stream, so the reassembler states the entry count.
        self.scan_offsets = BoundedStateTable(
            max_connections=self.reassembler.max_streams,
            max_connection_age=self.reassembler.max_stream_age,
            eviction_interval=1,
        )
