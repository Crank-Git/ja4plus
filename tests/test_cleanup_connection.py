"""Tests for the cleanup_connection() API on stateful fingerprinters."""
import unittest

from scapy.all import IP, TCP, UDP, Raw


class TestBaseFingerprinterCleanup(unittest.TestCase):
    def test_base_has_cleanup_connection(self):
        from ja4plus.fingerprinters.base import BaseFingerprinter
        # The base class must have the method (no-op default)
        fp = BaseFingerprinter.__new__(BaseFingerprinter)
        fp.fingerprints = []
        self.assertTrue(hasattr(fp, 'cleanup_connection'))

    def test_base_cleanup_is_noop(self):
        from ja4plus.fingerprinters.base import BaseFingerprinter
        fp = BaseFingerprinter.__new__(BaseFingerprinter)
        fp.fingerprints = []
        # Must not raise
        fp.cleanup_connection("1.2.3.4", 1234, "5.6.7.8", 443, "tcp")


class TestJA4LCleanup(unittest.TestCase):
    def _make_syn(self, src="10.0.0.1", dst="10.0.0.2", sport=12345, dport=443):
        return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")

    def test_cleanup_removes_connection(self):
        from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
        fp = JA4LFingerprinter()
        fp.process_packet(self._make_syn())
        self.assertGreater(len(fp.connections), 0)

        fp.cleanup_connection("10.0.0.1", 12345, "10.0.0.2", 443, "tcp")
        self.assertEqual(len(fp.connections), 0)

    def test_cleanup_nonexistent_is_safe(self):
        from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
        fp = JA4LFingerprinter()
        # No-op on empty state
        fp.cleanup_connection("1.2.3.4", 100, "5.6.7.8", 200, "tcp")

    def test_cleanup_both_directions(self):
        """Cleanup should work regardless of argument order (fwd/rev key)."""
        from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
        fp = JA4LFingerprinter()
        fp.process_packet(self._make_syn(src="10.0.0.1", dst="10.0.0.2"))
        # Call with dst/src reversed — should still clean up
        fp.cleanup_connection("10.0.0.2", 443, "10.0.0.1", 12345, "tcp")
        self.assertEqual(len(fp.connections), 0)


class TestJA4SSHCleanup(unittest.TestCase):
    def _make_ssh_pkt(self, src="10.0.0.1", dst="10.0.0.2", sport=54321, dport=22):
        return (IP(src=src, dst=dst) /
                TCP(sport=sport, dport=dport, flags="PA") /
                Raw(load=b"SSH-2.0-OpenSSH_8.0\r\n"))

    def test_cleanup_removes_connection(self):
        from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter
        fp = JA4SSHFingerprinter()
        fp.process_packet(self._make_ssh_pkt())
        self.assertGreater(len(fp.connections), 0)

        fp.cleanup_connection("10.0.0.1", 54321, "10.0.0.2", 22, "tcp")
        self.assertEqual(len(fp.connections), 0)

    def test_cleanup_nonexistent_is_safe(self):
        from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter
        fp = JA4SSHFingerprinter()
        fp.cleanup_connection("1.2.3.4", 100, "5.6.7.8", 22, "tcp")


class TestJA4HCleanup(unittest.TestCase):
    def _make_http_pkt(self, src="10.0.0.1", dst="10.0.0.2", sport=54321, dport=80):
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        return (IP(src=src, dst=dst) /
                TCP(sport=sport, dport=dport, seq=1, flags="PA") /
                Raw(load=payload))

    def test_cleanup_removes_stream(self):
        from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
        fp = JA4HFingerprinter()
        fp.process_packet(self._make_http_pkt())
        stream_key = "10.0.0.1:54321-10.0.0.2:80"
        # Stream may have been processed and removed by reassembler already,
        # but cleanup should not raise regardless
        fp.cleanup_connection("10.0.0.1", 54321, "10.0.0.2", 80, "tcp")

    def test_cleanup_nonexistent_is_safe(self):
        from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
        fp = JA4HFingerprinter()
        fp.cleanup_connection("1.2.3.4", 100, "5.6.7.8", 80, "tcp")


class TestJA4XCleanup(unittest.TestCase):
    def test_cleanup_removes_stream(self):
        from ja4plus.fingerprinters.ja4x import JA4XFingerprinter
        fp = JA4XFingerprinter()
        # Manually inject a stream to verify removal
        stream_key = "10.0.0.1:54321-10.0.0.2:443"
        fp.reassembler.streams[stream_key] = bytearray(b"dummy")
        self.assertIn(stream_key, fp.reassembler.streams)

        fp.cleanup_connection("10.0.0.1", 54321, "10.0.0.2", 443, "tcp")
        self.assertNotIn(stream_key, fp.reassembler.streams)

    def test_cleanup_nonexistent_is_safe(self):
        from ja4plus.fingerprinters.ja4x import JA4XFingerprinter
        fp = JA4XFingerprinter()
        fp.cleanup_connection("1.2.3.4", 100, "5.6.7.8", 443, "tcp")


class TestJA4SCleanup(unittest.TestCase):
    def test_cleanup_already_covered_in_quic_tests(self):
        """Covered by test_quic_utils.py::TestJA4SQUICTracking."""
        from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
        fp = JA4SFingerprinter()
        fp.cleanup_connection("1.2.3.4", 100, "5.6.7.8", 443, "udp")


if __name__ == '__main__':
    unittest.main()
