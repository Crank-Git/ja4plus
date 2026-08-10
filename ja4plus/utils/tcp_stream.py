"""Sequence-aware TCP stream reassembly for JA4+ fingerprinting.

Used by JA4H (HTTP) and JA4X (certificates) to handle multi-segment
payloads and out-of-order TCP delivery.
"""

# Python 3.9 is the floor, and it evaluates no annotation written as `str | None`
# without this import.
from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Any

from ja4plus.utils.state_table import StateTable, TableStats

logger = logging.getLogger(__name__)

# A TCP sequence number is 32 bits and wraps back to zero. RFC 1982 orders two such
# numbers on the difference between them, not on the numbers themselves.
SEQUENCE_MASK = 0xFFFFFFFF
_SEQ_HALF = 0x80000000


def sequence_before(a: int, b: int) -> bool:
    """Report whether sequence number a comes before sequence number b.

    The two numbers must lie within 2**31 of each other. A stream holds at most
    `max_stream_bytes`, so every sequence number in one stream meets that condition.

    Args:
        a: A 32-bit TCP sequence number.
        b: A 32-bit TCP sequence number.

    Returns:
        True when a comes before b, and False when a equals b or comes after b.
    """
    return ((a - b) & SEQUENCE_MASK) > _SEQ_HALF


# The largest stream of the FoxIO vectors holds 1336 segments without a byte cap, and
# 788 with one, both in `http2-with-cookies.pcapng`. This cap sits three times above the
# larger reading, so no vector reaches it. The byte cap alone leaves a sender of one-byte
# segments a million entries in the segment list, so this cap carries the second bound.
DEFAULT_MAX_STREAM_SEGMENTS = 4096

# The maximum age of one stream, in seconds. `ssh-r.pcap` holds the longest gap between
# two segments of one stream across `tests/foxio_vectors/`, at 320.714503 seconds. This
# age sits above that gap, so no eviction reaches a vector stream.
DEFAULT_MAX_STREAM_AGE = 600


class TCPStreamReassembler(StateTable):
    """Reassembles TCP streams using sequence numbers.

    Handles out-of-order segments, duplicates, and overlaps.
    Evicts oldest streams when max_streams is exceeded.

    A stream also leaves the reassembler once it receives no segment for
    `max_stream_age` seconds. The age reads the packet timestamp the caller states, and
    this module imports no clock. A capture file replays faster than real time, so a
    wall clock would evict state the capture still needs.

    The class holds per-connection data across packets, so the `## Terms` table of
    `docs/specs/spec.md` names it a state table. It therefore reports the six counts
    every state table reports, and `Processor.stats` collects them under #41. Its
    bounds predate `BoundedStateTable`, and #39 left them where they are, so this class
    counts its own evictions rather than inheriting the count.
    """

    def __init__(
        self,
        max_streams: int = 100,
        max_stream_bytes: int = 1048576,
        max_stream_segments: int = DEFAULT_MAX_STREAM_SEGMENTS,
        max_stream_age: float = DEFAULT_MAX_STREAM_AGE,
    ) -> None:
        StateTable.__init__(self, max_evicted_keys=max_streams)
        self.streams: OrderedDict[Any, dict[str, Any]] = OrderedDict()
        self.max_streams = max_streams
        self.max_stream_bytes = max_stream_bytes
        self.max_stream_segments = max_stream_segments
        self.max_stream_age = max_stream_age

    def _evict_aged_streams(self, now: float) -> None:
        """Remove every stream that receives no segment for `max_stream_age` seconds.

        The removal drops the whole entry, so the segment list, the set of seen
        segments and the stored byte count leave together. A partial removal would make
        `add_segment` drop a later segment as a duplicate.

        Args:
            now: The packet timestamp of the current segment, in seconds.
        """
        # `max_streams` bounds this scan at 100 entries, so the cost per packet is flat.
        for key, stream in list(self.streams.items()):
            last_seen = stream["last_seen"]
            if last_seen is not None and now - last_seen > self.max_stream_age:
                del self.streams[key]
                self.count_eviction(key)

    def add_segment(self, key: Any, seq: int, data: bytes, timestamp: float | None = None) -> None:
        """Add a TCP segment to a stream.

        The stream refuses the segment once it holds `max_stream_bytes` bytes, or
        `max_stream_segments` segments. A refused segment leaves no trace, so the stream
        accepts it again after a trim frees the room.

        Args:
            key: The stream key.
            seq: The 32-bit TCP sequence number of the first byte of the segment.
            data: The payload bytes of the segment.
            timestamp: The packet timestamp of the segment, in seconds. A caller that
                states None gives the reassembler no age to read, and the age evicts no
                stream of that reassembler.
        """
        if not data:
            return

        if timestamp is not None:
            self._evict_aged_streams(timestamp)

        if key not in self.streams:
            returned = self.take_evicted_key(key)
            if len(self.streams) >= self.max_streams:
                evicted_key, _ = self.streams.popitem(last=False)
                self.count_eviction(evicted_key)
            self.streams[key] = {"segments": [], "seen": set(), "bytes": 0, "last_seen": None}
            self.count_insert(returned)

        stream = self.streams[key]

        # The stream still sends while a cap refuses its segments, so the age follows
        # every segment the stream receives, not the segments the reassembler stores.
        if timestamp is not None:
            stream["last_seen"] = timestamp

        # A scan of every stored segment costs the square of the segment count. A
        # retransmission-heavy stream reaches thousands of segments.
        fingerprint = (seq, len(data))
        if fingerprint in stream["seen"]:
            return

        # `get_stream` bounds the bytes it returns, and nothing bounded the bytes the
        # stream stores. A sender of many small segments then grows one stream without a
        # limit. The stream keeps the bytes it holds, because `get_stream` reads the
        # earliest of them and a fingerprinter reads the earliest of those.
        if stream["bytes"] + len(data) > self.max_stream_bytes:
            return
        if len(stream["segments"]) >= self.max_stream_segments:
            return

        stream["seen"].add(fingerprint)
        stream["segments"].append((seq, data))
        stream["bytes"] += len(data)
        self.streams.move_to_end(key)

    def _ordered_segments(self, stream: dict[str, Any]) -> list[tuple[int, bytes]]:
        """Return the segments of a stream in sequence order, earliest first.

        The order holds across a wrap of the 32-bit sequence number. The order depends
        only on the sequence numbers, never on the order the capture delivered them.

        Args:
            stream: A stream entry from `self.streams`.

        Returns:
            A list of (seq, data) pairs, which is empty when the stream holds none.
        """
        segments = stream["segments"]
        if not segments:
            return []

        by_seq = sorted(segments, key=lambda s: s[0])
        if len(by_seq) == 1:
            return by_seq

        # A stream occupies one arc of the sequence space, and one step between two
        # neighbours closes that arc. The widest step is that one, so the segment after
        # it holds the first byte. A comparison of each segment against a running
        # earliest value gives a different answer for a different arrival order,
        # because the comparison is not transitive once the segments span the space.
        start = 0
        widest = (by_seq[0][0] - by_seq[-1][0]) & SEQUENCE_MASK
        for i in range(1, len(by_seq)):
            step = by_seq[i][0] - by_seq[i - 1][0]
            if step > widest:
                widest = step
                start = i

        return by_seq[start:] + by_seq[:start]

    def get_stream(self, key: Any) -> bytes:
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
            if seq == next_seq or sequence_before(seq, next_seq):
                overlap = (next_seq - seq) & SEQUENCE_MASK
                if overlap < len(data):
                    result.extend(data[overlap:])
                    next_seq = (seq + len(data)) & SEQUENCE_MASK
            else:
                break

        # `add_segment` bounds the bytes the stream stores, and the result never holds
        # more than the stream stores, so this method needs no bound of its own.
        return bytes(result)

    def base_seq(self, key: Any) -> int | None:
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

    def remove_stream(self, key: Any) -> None:
        """Remove a stream from tracking.

        The removal belongs to the caller, so it evicts nothing. A stream that arrives
        again after this call counts as a first sighting.

        Args:
            key: The stream key. A key the reassembler does not hold removes nothing.
        """
        if self.streams.pop(key, None) is not None:
            self.count_removals()

    def stats(self) -> TableStats:
        """Return the counts this reassembler reports.

        Returns:
            A `TableStats`. The caller holds the lock of the fingerprinter across this
            call, because the six counts describe one instant.
        """
        return self.build_stats(len(self.streams), self.max_streams)

    def trim_stream(self, key: Any, up_to_seq: int) -> None:
        """Remove the segments that end at or before up_to_seq, to free memory.

        The comparison holds across a wrap of the 32-bit sequence number, the way
        `get_stream` orders its segments.

        Args:
            key: The stream key.
            up_to_seq: An absolute 32-bit sequence number, never a byte offset. A byte
                offset removes no segment for a realistic initial sequence number.
        """
        if key not in self.streams:
            return
        stream = self.streams[key]
        stream["segments"] = [
            (seq, data)
            for seq, data in stream["segments"]
            if sequence_before(up_to_seq, (seq + len(data)) & SEQUENCE_MASK)
        ]
        # `add_segment` reads this set to detect a duplicate. A trimmed segment that
        # stays in the set makes `add_segment` drop that segment when it arrives again.
        stream["seen"] = {(seq, len(data)) for seq, data in stream["segments"]}
        # `add_segment` reads this count against the byte cap. A count that the trim
        # leaves high refuses a later segment for room the stream no longer uses.
        stream["bytes"] = sum(len(data) for _, data in stream["segments"])
