"""Processor aggregator: runs every JA4+ fingerprinter on each packet.

Mirrors the API of ja4plus-go's ja4plus.Processor:

    p = Processor()
    results = p.process_packet(pkt)            # list of result dicts
    p.cleanup_connection(src_ip, src_port, dst_ip, dst_port, "tcp")
    key = p.get_shard_key(pkt)                 # stable connection key
    p.reset()                                  # clear all state

Each result dict contains:
    {
        "type":        "ja4" | "ja4s" | "ja4h" | ...,
        "fingerprint": "<the fingerprint string>",
        "raw":         "<unhashed form>" or None,
        "raw_original_order": "<unhashed original-order form>" or None,
        "src_ip":      "...",
        "src_port":    int,
        "dst_ip":      "...",
        "dst_port":    int,
    }
"""

import logging

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter
from ja4plus.fingerprinters.ja4d import JA4DFingerprinter
from ja4plus.fingerprinters.ja4d6 import JA4D6Fingerprinter

logger = logging.getLogger(__name__)


class Processor:
    """Aggregator that runs every JA4+ fingerprinter on each packet."""

    # The order here drives the iteration order of process_packet()
    _SPEC = [
        ("ja4", JA4Fingerprinter),
        ("ja4s", JA4SFingerprinter),
        ("ja4h", JA4HFingerprinter),
        ("ja4t", JA4TFingerprinter),
        ("ja4ts", JA4TSFingerprinter),
        ("ja4l", JA4LFingerprinter),
        ("ja4x", JA4XFingerprinter),
        ("ja4ssh", JA4SSHFingerprinter),
        ("ja4d", JA4DFingerprinter),
        ("ja4d6", JA4D6Fingerprinter),
    ]

    def __init__(self):
        self.fingerprinters = {name: cls() for name, cls in self._SPEC}

    def __getattr__(self, name):
        # Convenience: processor.ja4 returns the underlying fingerprinter.
        # __getattr__ is only invoked when normal attribute lookup fails,
        # so this doesn't shadow process_packet/reset/etc.
        if "fingerprinters" in self.__dict__ and name in self.__dict__["fingerprinters"]:
            return self.__dict__["fingerprinters"][name]
        raise AttributeError(name)

    def process_packet(self, packet):
        """Run every fingerprinter; return a list of result dicts.

        Errors from individual fingerprinters are logged at DEBUG and
        swallowed so one misbehaving fingerprinter cannot poison the
        whole aggregation.
        """
        results = []
        src_ip, dst_ip, src_port, dst_port = _packet_endpoints(packet)

        for fp_type, fp in self.fingerprinters.items():
            try:
                fingerprint = fp.process_packet(packet)
            except Exception as e:
                logger.debug(f"{fp_type} processing failed: {e}")
                continue
            if not fingerprint:
                continue
            results.append(
                {
                    "type": fp_type,
                    "fingerprint": fingerprint,
                    "raw": getattr(fp, "last_raw", None),
                    "raw_original_order": getattr(fp, "last_raw_original_order", None),
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                }
            )
        return results

    def close_open_windows(self):
        """Emit every window the fingerprinters hold open, and return the results.

        Run this method when the packet source ends. JA4SSH is the only method that
        holds a window, and #214 decided that it emits the window a connection holds
        open at the end of a capture.

        Returns:
            A list of result dicts. Each dict holds the method name, the fingerprint
            and the connection key of the window. It holds no packet endpoint, because
            no packet produces the value.
        """
        results = []
        for fp_type, fp in self.fingerprinters.items():
            try:
                entries = fp.close_open_windows()
            except Exception as e:
                logger.debug(f"{fp_type} close_open_windows failed: {e}")
                continue
            for entry in entries:
                results.append(
                    {
                        "type": fp_type,
                        "fingerprint": entry["fingerprint"],
                        "connection": entry.get("connection"),
                    }
                )
        return results

    def reset(self):
        """Reset every underlying fingerprinter."""
        for fp in self.fingerprinters.values():
            fp.reset()

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        """Drop per-connection state across all fingerprinters.

        Each fingerprinter normalizes the 5-tuple to its own internal key
        format. Call this when a connection is evicted from your tracker
        to prevent state leaks in long-running monitors.
        """
        for fp in self.fingerprinters.values():
            try:
                fp.cleanup_connection(src_ip, src_port, dst_ip, dst_port, proto)
            except Exception as e:
                logger.debug(f"cleanup_connection error in {fp.__class__.__name__}: {e}")

    def get_shard_key(self, packet):
        """Return a stable per-connection key for sharding processors.

        Sorts the 5-tuple so both directions of the same connection map
        to the same shard. Returns "" if the packet is not TCP/UDP/IP.
        """
        from scapy.all import TCP, UDP, IP, IPv6

        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip_layer is None:
            return ""
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)

        if packet.haslayer(TCP):
            proto = "tcp"
            sport = int(packet[TCP].sport)
            dport = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            proto = "udp"
            sport = int(packet[UDP].sport)
            dport = int(packet[UDP].dport)
        else:
            return ""

        if (src_ip > dst_ip) or (src_ip == dst_ip and sport > dport):
            src_ip, dst_ip = dst_ip, src_ip
            sport, dport = dport, sport

        return f"{proto}:{src_ip}:{sport}->{dst_ip}:{dport}"


def _packet_endpoints(packet):
    """Best-effort extraction of (src_ip, dst_ip, src_port, dst_port)."""
    from scapy.all import TCP, UDP, IP, IPv6

    src_ip = dst_ip = ""
    src_port = dst_port = 0

    ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
    if ip_layer is not None:
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)

    if packet.haslayer(TCP):
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    return src_ip, dst_ip, src_port, dst_port
