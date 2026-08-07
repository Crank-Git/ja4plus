"""Sequence-aware TCP stream reassembly for JA4+ fingerprinting.

Used by JA4H (HTTP) and JA4X (certificates) to handle multi-segment
payloads and out-of-order TCP delivery.
"""

import logging
from collections import OrderedDict

logger = logging.getLogger(__name__)

# A TCP sequence number is 32 bits and wraps back to zero. RFC 1982 orders two such
# numbers on the difference between them, not on the numbers themselves.
_SEQ_MASK = 0xFFFFFFFF
_SEQ_HALF = 0x80000000


def _seq_before(a, b):
    """Report whether sequence number a comes before sequence number b.

    The two numbers must lie within 2**31 of each other. A stream holds at most
    `max_stream_bytes`, so every sequence number in one stream meets that condition.

    Args:
        a: A 32-bit TCP sequence number.
        b: A 32-bit TCP sequence number.

    Returns:
        True when a comes before b, and False when a equals b or comes after b.
    """
    return ((a - b) & _SEQ_MASK) > _SEQ_HALF


class TCPStreamReassembler:
    """Reassembles TCP streams using sequence numbers.

    Handles out-of-order segments, duplicates, and overlaps.
    Evicts oldest streams when max_streams is exceeded.
    """

    def __init__(self, max_streams=100, max_stream_bytes=1048576):
        self.streams = OrderedDict()
        self.max_streams = max_streams
        self.max_stream_bytes = max_stream_bytes

    def add_segment(self, key, seq, data):
        """Add a TCP segment to a stream."""
        if not data:
            return

        if key not in self.streams:
            if len(self.streams) >= self.max_streams:
                self.streams.popitem(last=False)
            self.streams[key] = {"segments": [], "seen": set()}

        stream = self.streams[key]

        # A scan of every stored segment costs the square of the segment count. A
        # retransmission-heavy stream reaches thousands of segments.
        fingerprint = (seq, len(data))
        if fingerprint in stream["seen"]:
            return

        stream["seen"].add(fingerprint)
        stream["segments"].append((seq, data))
        self.streams.move_to_end(key)

    def _ordered_segments(self, stream):
        """Return the segments of a stream in sequence order, earliest first.

        The order holds across a wrap of the 32-bit sequence number. The method finds
        the earliest sequence number, then sorts on the distance from it.

        Args:
            stream: A stream entry from `self.streams`.

        Returns:
            A list of (seq, data) pairs, which is empty when the stream holds none.
        """
        segments = stream["segments"]
        if not segments:
            return []

        first = segments[0][0]
        for seq, _ in segments:
            if _seq_before(seq, first):
                first = seq

        return sorted(segments, key=lambda s: (s[0] - first) & _SEQ_MASK)

    def get_stream(self, key):
        """Reassemble and return contiguous stream data from base_seq.

        Returns data from the earliest sequence number up to the first gap. The order
        holds across a wrap of the 32-bit sequence number.
        """
        if key not in self.streams:
            return b""

        segments = self._ordered_segments(self.streams[key])

        if not segments:
            return b""

        result = bytearray()
        next_seq = segments[0][0]

        for seq, data in segments:
            # A gap and an overlap differ by the direction of the difference, which a
            # subtraction of the raw numbers reports wrongly across a wrap.
            if seq == next_seq or _seq_before(seq, next_seq):
                overlap = (next_seq - seq) & _SEQ_MASK
                if overlap < len(data):
                    result.extend(data[overlap:])
                    next_seq = (seq + len(data)) & _SEQ_MASK
            else:
                break

            if len(result) > self.max_stream_bytes:
                result = result[: self.max_stream_bytes]
                break

        return bytes(result)

    def base_seq(self, key):
        """Return the sequence number the reassembled stream starts at, or None.

        `get_stream` starts at the earliest sequence number the stream holds, and a
        segment that arrives late moves it earlier. A caller that remembers an offset
        into the reassembled bytes needs this value to know that every offset moved.

        Args:
            key: The stream key.

        Returns:
            The earliest sequence number the stream holds, or None when it holds no
            segment.
        """
        stream = self.streams.get(key)
        if not stream:
            return None
        segments = self._ordered_segments(stream)
        if not segments:
            return None
        return segments[0][0]

    def remove_stream(self, key):
        """Remove a stream from tracking."""
        self.streams.pop(key, None)

    def trim_stream(self, key, up_to_seq):
        """Remove segments before up_to_seq to free memory."""
        if key not in self.streams:
            return
        stream = self.streams[key]
        stream["segments"] = [
            (seq, data) for seq, data in stream["segments"] if seq + len(data) > up_to_seq
        ]
        # `add_segment` reads this set to detect a duplicate. A trimmed segment that
        # stays in the set makes `add_segment` drop that segment when it arrives again.
        stream["seen"] = {(seq, len(data)) for seq, data in stream["segments"]}
