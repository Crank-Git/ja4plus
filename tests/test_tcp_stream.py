"""Tests for TCP stream reassembly."""

import time
import unittest

# A TCP sequence number is 32 bits. 0xFFFFFFFE puts the next four bytes across the
# boundary, so a reassembler that compares raw numbers orders these segments backwards.
WRAP_SEQ = 0xFFFFFFFE


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

    def test_the_base_sequence_names_the_first_byte_of_the_stream(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler()
        key = "stream1"
        r.add_segment(key, seq=100, data=b"hello")
        self.assertEqual(r.base_seq(key), 100)

    def test_a_late_segment_lowers_the_base_sequence(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler()
        key = "stream1"
        r.add_segment(key, seq=105, data=b" world")
        self.assertEqual(r.base_seq(key), 105)
        r.add_segment(key, seq=100, data=b"hello")
        self.assertEqual(r.base_seq(key), 100)

    def test_the_base_sequence_of_an_unknown_stream_is_none(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler()
        self.assertIsNone(r.base_seq("stream1"))

    def test_reassembly_across_the_sequence_wrap_keeps_the_byte_order(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler()
        key = "stream1"
        r.add_segment(key, seq=WRAP_SEQ, data=b"abcd")
        r.add_segment(key, seq=2, data=b"efgh")
        self.assertEqual(r.get_stream(key), b"abcdefgh")

    def test_a_late_segment_across_the_sequence_wrap_keeps_the_byte_order(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler()
        key = "stream1"
        r.add_segment(key, seq=2, data=b"efgh")
        r.add_segment(key, seq=WRAP_SEQ, data=b"abcd")
        self.assertEqual(r.get_stream(key), b"abcdefgh")

    def test_a_gap_across_the_sequence_wrap_stops_the_stream(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler()
        key = "stream1"
        r.add_segment(key, seq=WRAP_SEQ, data=b"abcd")
        r.add_segment(key, seq=100, data=b"efgh")
        self.assertEqual(r.get_stream(key), b"abcd")

    def test_an_overlap_across_the_sequence_wrap_drops_the_repeated_bytes(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler()
        key = "stream1"
        # The first segment puts "d" at sequence number 1, and the second repeats it.
        r.add_segment(key, seq=WRAP_SEQ, data=b"abcd")
        r.add_segment(key, seq=1, data=b"def")
        self.assertEqual(r.get_stream(key), b"abcdef")

    def test_the_base_sequence_across_the_sequence_wrap_names_the_first_byte(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler()
        key = "stream1"
        r.add_segment(key, seq=2, data=b"efgh")
        r.add_segment(key, seq=WRAP_SEQ, data=b"abcd")
        self.assertEqual(r.base_seq(key), WRAP_SEQ)

    def test_ten_thousand_segments_take_less_than_one_second(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler()
        key = "stream1"
        start = time.perf_counter()
        for i in range(10000):
            r.add_segment(key, seq=i * 4, data=b"abcd")
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 1.0)

    def test_the_cost_of_a_segment_does_not_grow_with_the_segment_count(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        def elapsed(count):
            r = TCPStreamReassembler()
            start = time.perf_counter()
            for i in range(count):
                r.add_segment("stream1", seq=i * 4, data=b"abcd")
            return time.perf_counter() - start

        # A scan of every stored segment costs the square of the count, so four times
        # the segments costs sixteen times the time. A constant-cost check costs four.
        # The threshold sits between the two readings, clear of the noise of either.
        self.assertLess(elapsed(20000), elapsed(5000) * 8)

    def test_the_segment_order_does_not_depend_on_the_arrival_order(self):
        import itertools

        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        # The three sequence numbers spread across the whole sequence space, so no
        # 2**31 window holds them. A fingerprint that moved with the arrival order
        # would describe the capture file rather than the connection.
        spread = [(0x00000000, b"a"), (0x60000000, b"b"), (0xC0000000, b"c")]
        bases = set()
        for arrival in itertools.permutations(spread):
            r = TCPStreamReassembler()
            for seq, data in arrival:
                r.add_segment("stream1", seq=seq, data=data)
            bases.add(r.base_seq("stream1"))
        self.assertEqual(len(bases), 1)

    def test_a_trimmed_segment_reassembles_when_it_arrives_again(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler()
        key = "stream1"
        r.add_segment(key, seq=100, data=b"hello")
        r.trim_stream(key, 105)
        self.assertEqual(r.get_stream(key), b"")
        r.add_segment(key, seq=100, data=b"hello")
        self.assertEqual(r.get_stream(key), b"hello")

    def test_a_trim_of_an_unknown_stream_does_nothing(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler()
        r.trim_stream("stream1", 100)
        self.assertEqual(r.get_stream("stream1"), b"")

    def test_a_stream_holds_no_more_than_the_byte_cap(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler(max_stream_bytes=100)
        key = "stream1"
        for i in range(200):
            r.add_segment(key, seq=i * 10, data=b"a" * 10)
        stored = sum(len(data) for _, data in r.streams[key]["segments"])
        self.assertLessEqual(stored, 100)

    def test_a_stream_holds_no_more_than_the_segment_cap(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler(max_stream_segments=8)
        key = "stream1"
        for i in range(200):
            r.add_segment(key, seq=i, data=b"a")
        self.assertLessEqual(len(r.streams[key]["segments"]), 8)

    def test_one_hundred_thousand_one_byte_segments_stay_inside_the_segment_cap(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler()
        key = "stream1"
        for i in range(100000):
            r.add_segment(key, seq=i, data=b"a")
        self.assertLessEqual(len(r.streams[key]["segments"]), r.max_stream_segments)

    def test_a_refused_segment_reassembles_when_the_stream_has_room_again(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler(max_stream_segments=2)
        key = "stream1"
        r.add_segment(key, seq=100, data=b"he")
        r.add_segment(key, seq=102, data=b"ll")
        # The cap refuses this segment, so the set of seen segments must not hold it.
        r.add_segment(key, seq=104, data=b"o!")
        r.trim_stream(key, 102)
        r.add_segment(key, seq=104, data=b"o!")
        self.assertEqual(r.get_stream(key), b"llo!")

    def test_a_trim_across_the_sequence_wrap_removes_the_earlier_segment(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler()
        key = "stream1"
        r.add_segment(key, seq=WRAP_SEQ, data=b"abcd")
        r.add_segment(key, seq=2, data=b"efgh")
        # The first segment ends at sequence number 2, so the trim removes it and keeps
        # the second. A comparison of the raw numbers keeps both.
        r.trim_stream(key, 2)
        self.assertEqual(r.get_stream(key), b"efgh")

    def test_a_trim_lowers_the_stored_byte_count_of_the_stream(self):
        from ja4plus.utils.tcp_stream import TCPStreamReassembler

        r = TCPStreamReassembler()
        key = "stream1"
        r.add_segment(key, seq=100, data=b"hello")
        self.assertEqual(r.streams[key]["bytes"], 5)
        # A stored byte count that a trim leaves high refuses a later segment for room
        # the stream no longer uses.
        r.trim_stream(key, 105)
        self.assertEqual(r.streams[key]["bytes"], 0)

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
        # An earlier form of this test compared against 20, which the reassembler met
        # before the cap existed. The cap is 10, so the comparison names 10.
        self.assertLessEqual(len(result), 10)


if __name__ == "__main__":
    unittest.main()
