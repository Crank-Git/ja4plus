"""Sequence-aware TCP stream reassembly for JA4+ fingerprinting.

Used by JA4H (HTTP) and JA4X (certificates) to handle multi-segment
payloads and out-of-order TCP delivery.
"""

import logging
from collections import OrderedDict

logger = logging.getLogger(__name__)


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
            self.streams[key] = {"segments": [], "base_seq": seq}

        stream = self.streams[key]

        for existing_seq, existing_data in stream["segments"]:
            if existing_seq == seq and len(existing_data) == len(data):
                return

        stream["segments"].append((seq, data))
        self.streams.move_to_end(key)

    def get_stream(self, key):
        """Reassemble and return contiguous stream data from base_seq.

        Returns data from the lowest sequence number up to the first gap.
        """
        if key not in self.streams:
            return b""

        stream = self.streams[key]
        segments = sorted(stream["segments"], key=lambda s: s[0])

        if not segments:
            return b""

        result = bytearray()
        next_seq = segments[0][0]

        for seq, data in segments:
            if seq <= next_seq:
                overlap = next_seq - seq
                if overlap < len(data):
                    result.extend(data[overlap:])
                    next_seq = seq + len(data)
            else:
                break

            if len(result) > self.max_stream_bytes:
                result = result[: self.max_stream_bytes]
                break

        return bytes(result)

    def base_seq(self, key):
        """Return the sequence number the reassembled stream starts at, or None.

        `get_stream` starts at the lowest sequence number the stream holds, and a
        segment that arrives late lowers it. A caller that remembers an offset into the
        reassembled bytes needs this value to know that every offset moved.

        Args:
            key: The stream key.

        Returns:
            The lowest sequence number the stream holds, or None when it holds no
            segment.
        """
        stream = self.streams.get(key)
        if not stream or not stream["segments"]:
            return None
        return min(seq for seq, _ in stream["segments"])

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
