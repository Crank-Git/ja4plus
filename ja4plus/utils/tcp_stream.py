"""
TCP stream reassembly utilities for sequence-aware packet reassembly.
"""

import logging

logger = logging.getLogger(__name__)


class TCPStreamReassembler:
    """Sequence-aware TCP stream reassembler that handles out-of-order segments."""

    def __init__(self, max_streams=50, max_stream_bytes=1048576):
        """
        Initialize the reassembler.

        Args:
            max_streams: Maximum number of concurrent streams to track.
            max_stream_bytes: Maximum bytes to buffer per stream (default 1MB).
        """
        self.max_streams = max_streams
        self.max_stream_bytes = max_stream_bytes
        # Each stream: {'base_seq': int, 'data': bytes, 'segments': {offset: bytes}}
        self._streams = {}

    def add_segment(self, stream_id, seq, data):
        """
        Add a TCP segment to the reassembler.

        Args:
            stream_id: Unique stream identifier string.
            seq: TCP sequence number of this segment.
            data: Raw bytes of the segment payload.
        """
        if not data:
            return

        if stream_id not in self._streams:
            # Evict oldest stream if at capacity
            if len(self._streams) >= self.max_streams:
                oldest = next(iter(self._streams))
                del self._streams[oldest]
            self._streams[stream_id] = {
                'base_seq': seq,
                'data': b'',
                'segments': {},
            }

        stream = self._streams[stream_id]
        base_seq = stream['base_seq']

        # Compute byte offset from base sequence number (handles wrap-around)
        offset = (seq - base_seq) & 0xFFFFFFFF

        # Ignore absurdly large offsets (likely a new connection reusing the key)
        if offset > self.max_stream_bytes:
            return

        # Store the segment keyed by offset
        stream['segments'][offset] = data

        # Reassemble contiguous data from offset 0
        assembled = stream['data']
        next_offset = len(assembled)

        changed = True
        while changed:
            changed = False
            if next_offset in stream['segments']:
                chunk = stream['segments'].pop(next_offset)
                assembled += chunk
                next_offset = len(assembled)
                changed = True

        # Enforce per-stream size cap
        if len(assembled) > self.max_stream_bytes:
            assembled = assembled[-self.max_stream_bytes:]

        stream['data'] = assembled

    def get_stream(self, stream_id):
        """
        Return the currently assembled bytes for a stream.

        Args:
            stream_id: Unique stream identifier string.

        Returns:
            Assembled bytes, or b'' if stream is unknown.
        """
        stream = self._streams.get(stream_id)
        if stream is None:
            return b''
        return stream['data']

    def trim_stream(self, stream_id, offset):
        """
        Discard the first `offset` bytes of the assembled stream data.

        Args:
            stream_id: Unique stream identifier string.
            offset: Number of bytes to discard from the front.
        """
        stream = self._streams.get(stream_id)
        if stream is None:
            return
        if offset > 0 and offset <= len(stream['data']):
            discarded = stream['data'][:offset]
            stream['data'] = stream['data'][offset:]
            # Advance base_seq by the number of bytes discarded
            stream['base_seq'] = (stream['base_seq'] + len(discarded)) & 0xFFFFFFFF

    def remove_stream(self, stream_id):
        """Remove a stream entirely."""
        self._streams.pop(stream_id, None)

    def stream_count(self):
        """Return the number of active streams."""
        return len(self._streams)
