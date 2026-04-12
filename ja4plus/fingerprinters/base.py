"""
Base fingerprinter class for JA4+ fingerprinters.
"""

import logging

logger = logging.getLogger(__name__)


class BaseFingerprinter:
    """Base class for all JA4+ fingerprinters."""
    
    def __init__(self):
        """Initialize the fingerprinter."""
        self.fingerprints = []
    
    def process_packet(self, packet):
        """
        Process a packet and extract fingerprint if applicable.
        This method should be overridden by subclasses.
        
        Args:
            packet: A network packet to analyze
            
        Returns:
            The extracted fingerprint if successful, None otherwise
        """
        raise NotImplementedError("Subclasses must implement this method.")
    
    def add_fingerprint(self, fingerprint, packet):
        """
        Add a fingerprint to the collection.
        
        Args:
            fingerprint: The extracted fingerprint
            packet: The packet that generated this fingerprint
        """
        self.fingerprints.append({
            'fingerprint': fingerprint,
            'packet': packet
        })
    
    def get_fingerprints(self):
        """Return all collected fingerprints."""
        return self.fingerprints
    
    def reset(self):
        """Reset the fingerprinter state."""
        self.fingerprints = []

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        """
        Remove internal state for the given completed or evicted connection.

        Stateless fingerprinters (JA4, JA4T, JA4TS, JA4D) use this no-op.
        Stateful subclasses override to evict per-connection data and prevent
        memory leaks in long-running monitors.

        Args:
            src_ip:   Source IP address string
            src_port: Source port (int)
            dst_ip:   Destination IP address string
            dst_port: Destination port (int)
            proto:    Protocol string, e.g. 'tcp' or 'udp'
        """