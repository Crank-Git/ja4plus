#!/usr/bin/env python3
"""
JA4+ Continuous Monitoring Daemon

A long-running service that captures network traffic, generates JA4+
fingerprints, and writes JSON-lines log output with optional file rotation
and periodic stats.

Usage:
    python examples/monitoring_daemon.py -i eth0
    python examples/monitoring_daemon.py -i en0 -f "tcp port 443" -o /var/log/ja4plus.jsonl
    python examples/monitoring_daemon.py -i any --fingerprinters ja4,ja4s,ja4t --stats-interval 30
    python examples/monitoring_daemon.py --help
"""

import argparse
import json
import logging
import logging.handlers
import signal
import sys
import threading
import time
from datetime import datetime, timezone

from scapy.all import IP, IPv6, TCP, UDP, AsyncSniffer

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter

AVAILABLE_FINGERPRINTERS = {
    "ja4": JA4Fingerprinter,
    "ja4s": JA4SFingerprinter,
    "ja4h": JA4HFingerprinter,
    "ja4l": JA4LFingerprinter,
    "ja4x": JA4XFingerprinter,
    "ja4ssh": JA4SSHFingerprinter,
    "ja4t": JA4TFingerprinter,
    "ja4ts": JA4TSFingerprinter,
}


class MonitoringDaemon:
    """Continuous JA4+ fingerprinting service."""

    def __init__(self, args):
        self.args = args
        self.start_time = time.monotonic()
        self.packet_count = 0
        self.fp_counts = {}
        self.lock = threading.Lock()
        self.running = True

        # Initialize fingerprinters
        self.fingerprinters = {}
        for name in args.fingerprinters.split(","):
            name = name.strip().lower()
            if name in AVAILABLE_FINGERPRINTERS:
                self.fingerprinters[name] = AVAILABLE_FINGERPRINTERS[name]()
                self.fp_counts[name] = 0
            else:
                sys.stderr.write(f"Warning: unknown fingerprinter '{name}', skipping\n")

        if not self.fingerprinters:
            sys.exit("Error: no valid fingerprinters enabled")

        # Set up JSON-lines logger
        self.logger = self._setup_logger()

    # ------------------------------------------------------------------
    # Logger
    # ------------------------------------------------------------------

    def _setup_logger(self):
        """Configure a logger that writes JSON lines to file or stdout."""
        logger = logging.getLogger("ja4plus.monitor")
        logger.setLevel(logging.INFO)
        logger.propagate = False

        if self.args.output:
            max_bytes = self.args.rotate_size * 1024 * 1024
            handler = logging.handlers.RotatingFileHandler(
                self.args.output,
                maxBytes=max_bytes,
                backupCount=self.args.rotate_count,
            )
        else:
            handler = logging.StreamHandler(sys.stdout)

        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        return logger

    # ------------------------------------------------------------------
    # Packet processing
    # ------------------------------------------------------------------

    def _extract_meta(self, packet):
        """Extract IP/port metadata from a packet."""
        meta = {}
        if packet.haslayer(IP):
            meta["src_ip"] = packet[IP].src
            meta["dst_ip"] = packet[IP].dst
        elif packet.haslayer(IPv6):
            meta["src_ip"] = packet[IPv6].src
            meta["dst_ip"] = packet[IPv6].dst
        if packet.haslayer(TCP):
            meta["src_port"] = packet[TCP].sport
            meta["dst_port"] = packet[TCP].dport
        elif packet.haslayer(UDP):
            meta["src_port"] = packet[UDP].sport
            meta["dst_port"] = packet[UDP].dport
        return meta

    def process_packet(self, packet):
        """Run enabled fingerprinters on a packet and log results."""
        with self.lock:
            self.packet_count += 1

        meta = self._extract_meta(packet)

        for name, fp in self.fingerprinters.items():
            try:
                result = fp.process_packet(packet)
            except Exception as e:
                sys.stderr.write(f"Error in {name}: {e}\n")
                continue
            if not result:
                continue

            record = {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "type": name,
                "fingerprint": result,
            }
            record.update(meta)

            self.logger.info(json.dumps(record, default=str))

            with self.lock:
                self.fp_counts[name] = self.fp_counts.get(name, 0) + 1

    # ------------------------------------------------------------------
    # Periodic stats
    # ------------------------------------------------------------------

    def _stats_loop(self):
        """Periodically write summary stats to stderr."""
        while self.running:
            time.sleep(self.args.stats_interval)
            if not self.running:
                break
            self._print_stats()

    def _print_stats(self):
        elapsed = time.monotonic() - self.start_time
        mins, secs = divmod(int(elapsed), 60)
        hours, mins = divmod(mins, 60)
        if hours:
            uptime = f"{hours}h{mins}m"
        elif mins:
            uptime = f"{mins}m{secs}s"
        else:
            uptime = f"{secs}s"

        with self.lock:
            pkt = self.packet_count
            parts = " ".join(f"{n.upper()}={c}" for n, c in sorted(self.fp_counts.items()))

        sys.stderr.write(f"[STATS] Uptime: {uptime} | Packets: {pkt} | Fingerprints: {parts}\n")
        sys.stderr.flush()

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self):
        """Start capture and stats threads."""
        # Signal handling
        def shutdown(signum, frame):
            sys.stderr.write("\nReceived signal, shutting down ...\n")
            self.running = False

        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)

        iface = self.args.interface if self.args.interface != "any" else None
        bpf = self.args.filter

        sys.stderr.write(f"Starting JA4+ monitoring daemon\n")
        sys.stderr.write(f"  Interface:      {self.args.interface}\n")
        sys.stderr.write(f"  BPF filter:     {bpf or '(none)'}\n")
        sys.stderr.write(f"  Fingerprinters: {', '.join(self.fingerprinters)}\n")
        sys.stderr.write(f"  Output:         {self.args.output or 'stdout'}\n")
        if self.args.output:
            sys.stderr.write(f"  Rotation:       {self.args.rotate_size} MB x {self.args.rotate_count} backups\n")
        sys.stderr.write(f"  Stats interval: {self.args.stats_interval}s\n")
        sys.stderr.write(f"Press Ctrl+C to stop.\n\n")

        # Start stats thread
        stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        stats_thread.start()

        # Start async sniffer
        sniffer = AsyncSniffer(
            prn=self.process_packet,
            filter=bpf,
            iface=iface,
            store=0,
        )
        sniffer.start()

        # Wait until signalled to stop
        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.running = False

        sniffer.stop()

        # Final report
        sys.stderr.write("\n")
        self._print_stats()
        sys.stderr.write("Daemon stopped.\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    all_fps = ",".join(AVAILABLE_FINGERPRINTERS)

    parser = argparse.ArgumentParser(
        description="JA4+ Continuous Monitoring Daemon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s -i eth0\n"
            "  %(prog)s -i en0 -f 'tcp port 443' -o /var/log/ja4plus.jsonl\n"
            "  %(prog)s -i any --fingerprinters ja4,ja4s --stats-interval 30\n"
        ),
    )
    parser.add_argument("--interface", "-i", default="any",
                        help="Network interface (default: any)")
    parser.add_argument("--filter", "-f", default="tcp or udp",
                        help="BPF filter expression (default: 'tcp or udp')")
    parser.add_argument("--output", "-o", default=None,
                        help="Log file path for JSON-lines output (default: stdout)")
    parser.add_argument("--rotate-size", type=int, default=100,
                        help="Max log file size in MB before rotation (default: 100)")
    parser.add_argument("--rotate-count", type=int, default=5,
                        help="Number of rotated log files to keep (default: 5)")
    parser.add_argument("--stats-interval", type=int, default=60,
                        help="Seconds between stats output to stderr (default: 60)")
    parser.add_argument("--fingerprinters", default=all_fps,
                        help=f"Comma-separated fingerprinters to enable (default: {all_fps})")

    args = parser.parse_args()
    daemon = MonitoringDaemon(args)
    daemon.run()


if __name__ == "__main__":
    main()
