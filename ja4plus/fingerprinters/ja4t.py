"""
JA4T TCP Client Fingerprinting implementation.
"""

from scapy.all import TCP, IP
from ja4plus.fingerprinters.base import BaseFingerprinter


class JA4TFingerprinter(BaseFingerprinter):
    """
    JA4T TCP Client Fingerprinting implementation.

    JA4T fingerprints TCP client behavior based on TCP options and window sizes.
    Format: <window_size>_<options>_<mss>_<wscale>
    Example: 29200_2-4-8-1-3_1424_7
    """

    def process_packet(self, packet):
        """
        Process a packet and extract JA4T fingerprint if applicable.

        Args:
            packet: A network packet to analyze

        Returns:
            The extracted fingerprint if successful, None otherwise
        """
        fingerprint = generate_ja4t(packet)
        if fingerprint:
            self.add_fingerprint(fingerprint, packet)
            return fingerprint
        return None

def generate_ja4t(packet):
    """
    Generate JA4T fingerprint from TCP SYN packet.

    Format: <window_size>_<options>_<mss>_<wscale>
    Example: 64240_2-1-3-1-4_1460_8

    TCP options use IANA numbers: 0=EOL, 1=NOP, 2=MSS, 3=WScale, 4=SACK, 8=Timestamp
    Options preserve original order per JA4T spec (never sorted).
    """
    try:
        if not packet.haslayer(TCP):
            return None

        tcp = packet[TCP]

        # Only process SYN packets (not SYN-ACK)
        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
            return None

        # Get window size
        window_size = str(tcp.window)

        # Parse TCP options - preserve original order
        options = []
        mss = '0'
        wscale = '0'

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

        # Preserve original option ordering per JA4T spec
        options_str = '-'.join(options) if options else '0'

        # Format: window_options_mss_wscale
        ja4t = f"{window_size}_{options_str}_{mss}_{wscale}"

        return ja4t

    except Exception:
        return None 