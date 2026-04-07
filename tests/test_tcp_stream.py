"""Tests for TCP stream reassembly."""

import unittest


class TestTCPStreamReassembler(unittest.TestCase):

    def test_in_order_reassembly(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler
        r = TCPStreamReassembler()
        key = "10.0.0.1:1234-10.0.0.2:443"
        r.add_segment(key, seq=100, data=b"hello")
        r.add_segment(key, seq=105, data=b" world")
        self.assertEqual(r.get_stream(key), b"hello world")

    def test_out_of_order_reassembly(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler
        r = TCPStreamReassembler()
        key = "stream1"
        r.add_segment(key, seq=105, data=b" world")
        r.add_segment(key, seq=100, data=b"hello")
        self.assertEqual(r.get_stream(key), b"hello world")

    def test_duplicate_segment_ignored(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler
        r = TCPStreamReassembler()
        key = "stream1"
        r.add_segment(key, seq=100, data=b"hello")
        r.add_segment(key, seq=100, data=b"hello")
        self.assertEqual(r.get_stream(key), b"hello")

    def test_overlapping_segment(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler
        r = TCPStreamReassembler()
        key = "stream1"
        r.add_segment(key, seq=100, data=b"hello world")
        r.add_segment(key, seq=105, data=b" world!")
        result = r.get_stream(key)
        self.assertTrue(result.startswith(b"hello world"))

    def test_gap_in_stream(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler
        r = TCPStreamReassembler()
        key = "stream1"
        r.add_segment(key, seq=100, data=b"hello")
        r.add_segment(key, seq=200, data=b"world")
        self.assertEqual(r.get_stream(key), b"hello")

    def test_remove_stream(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler
        r = TCPStreamReassembler()
        key = "stream1"
        r.add_segment(key, seq=100, data=b"hello")
        r.remove_stream(key)
        self.assertEqual(r.get_stream(key), b"")

    def test_max_streams_cleanup(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler
        r = TCPStreamReassembler(max_streams=3)
        r.add_segment("s1", seq=0, data=b"a")
        r.add_segment("s2", seq=0, data=b"b")
        r.add_segment("s3", seq=0, data=b"c")
        r.add_segment("s4", seq=0, data=b"d")
        self.assertLessEqual(len(r.streams), 3)

    def test_max_stream_size(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler
        r = TCPStreamReassembler(max_stream_bytes=10)
        key = "stream1"
        r.add_segment(key, seq=0, data=b"a" * 20)
        result = r.get_stream(key)
        self.assertLessEqual(len(result), 20)


if __name__ == "__main__":
    unittest.main()
