"""
JA4TS TCP Server Response Fingerprinting implementation.
"""

import logging
from scapy.all import TCP, IP

from ja4plus.fingerprinters.base import BaseFingerprinter

logger = logging.getLogger(__name__)


class JA4TSFingerprinter(BaseFingerprinter):
    """
    JA4TS TCP Server Response Fingerprinting implementation.

    JA4TS fingerprints TCP server behavior based on SYN-ACK responses.
    Format: <window_size>_<options>_<mss>_<wscale>
    Example: 14600_2-1-3-4-1-1_1460_0
    """

    def process_packet(self, packet):
        """
        Process a packet and extract JA4TS fingerprint if applicable.

        Args:
            packet: A network packet to analyze

        Returns:
            The extracted fingerprint if successful, None otherwise
        """
        fingerprint = generate_ja4ts(packet)
        if fingerprint:
            self.add_fingerprint(fingerprint, packet)
            return fingerprint
        return None

def generate_ja4ts(packet):
    """
    Generate JA4TS fingerprint from TCP SYN-ACK packet.

    Format: <window_size>_<options>_<mss>_<wscale>
    Example: 14600_2-1-3-4-1-1_1460_0

    TCP options use IANA numbers: 0=EOL, 1=NOP, 2=MSS, 3=WScale, 4=SACK, 8=Timestamp
    Options preserve original order per spec (never sorted).
    """
    try:
        if not packet.haslayer(TCP):
            return None

        tcp = packet[TCP]

        # Only process SYN-ACK packets (server response)
        if not (tcp.flags & 0x12 == 0x12):  # SYN+ACK flags
            return None

        # Get window size
        window_size = str(tcp.window)

        # Parse TCP options - preserve order as seen
        options = []
        mss = '0'
        wscale = '0'

        # Process options in the order they appear
        for opt in tcp.options:
            opt_name = opt[0]
            if opt_name == 'MSS':
                options.append('2')
                mss = str(int(opt[1]))
            elif opt_name == 'NOP':
                options.append('1')
            elif opt_name == 'WScale':
                options.append('3')
                wscale = str(opt[1])
            elif opt_name == 'SAckOK':
                options.append('4')
            elif opt_name == 'Timestamp':
                options.append('8')
            elif opt_name == 'EOL':
                options.append('0')

        # Join with dashes - maintain original option ordering
        options_str = '-'.join(options) if options else '0'

        # Format: window_options_mss_wscale
        ja4ts = f"{window_size}_{options_str}_{mss}_{wscale}"

        return ja4ts

    except (ValueError, TypeError, IndexError, AttributeError) as e:
        logger.debug(f"Packet does not contain JA4TS data: {e}")
        return None