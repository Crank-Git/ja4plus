"""
JA4 TLS Client Hello Fingerprinting implementation.
"""

# This import makes every annotation a string. No annotation therefore evaluates at
# import time, and a forward reference needs no quotation mark.
from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

from scapy.all import UDP, Packet

from ja4plus.utils.tls_utils import extract_tls_info, is_grease_value
from ja4plus.utils.packet_utils import packet_endpoints
from ja4plus.utils.state_table import BoundedStateTable
from ja4plus.utils.tunnels import innermost_layer
from ja4plus.fingerprinters.base import BaseFingerprinter

logger = logging.getLogger(__name__)

# The highest number of connections whose QUIC CRYPTO fragments one fingerprinter
# holds. The table holds one entry for each Destination Connection ID, and a sender
# names a new one on each datagram at no cost, so the table needs a limit.
MAX_QUIC_FRAGMENT_CONNECTIONS = 1000

# The longest a connection holds its fragments without a further packet. A ClientHello
# that spans several datagrams arrives inside one round trip, so a connection that adds
# no fragment for this long has abandoned its handshake.
MAX_QUIC_FRAGMENT_AGE_SECONDS = 30


def quic_fragment_table() -> BoundedStateTable:
    """Return one bounded table for the QUIC CRYPTO fragments of one fingerprinter.

    The age pass runs on each packet, because the maximum age is 30 seconds and the
    default pass of `BoundedStateTable` waits for 1000 packets. A pass that waits longer
    than the age it applies evicts nothing on a connection that sends few packets.

    Returns:
        A `BoundedStateTable` that holds the two QUIC fragment limits.
    """
    return BoundedStateTable(
        max_connections=MAX_QUIC_FRAGMENT_CONNECTIONS,
        max_connection_age=MAX_QUIC_FRAGMENT_AGE_SECONDS,
        eviction_interval=1,
    )


def _is_printable_ascii_byte(b: int) -> bool:
    """Return True when the byte is printable ASCII: 0x20-0x7E."""
    return 0x20 <= b <= 0x7E


def _alpn_end_character(b: int) -> str | None:
    """Return the character that one end byte of an ALPN value writes.

    Args:
        b: The first byte or the last byte of the first ALPN value.

    Returns:
        The byte itself for printable ASCII, `9` for a byte of `0x80` or higher, and
        None for a control byte below `0x20` or the byte `0x7F`.
    """
    if _is_printable_ascii_byte(b):
        return chr(b)
    if b >= 0x80:
        return "9"
    return None


def compute_alpn_value(first_alpn_bytes: bytes | None) -> str:
    """Return the two-character ALPN value that JA4 and JA4S carry.

    The value is `00` for an absent ALPN extension and for an empty first ALPN value.
    Otherwise the value holds one character for the first byte and one character for the
    last byte. A one-byte value therefore writes its character twice.

    - A printable ASCII byte, which is `0x20-0x7E`, writes itself.
    - A byte of `0x80` or higher writes `9`.
    - A control byte below `0x20`, or the byte `0x7F`, at either end makes the value `99`.

    Args:
        first_alpn_bytes: The bytes of the first ALPN value, or None.

    Returns:
        A two-character string.
    """
    if not first_alpn_bytes:
        return "00"

    # #789: the maintainer ruled the first two rules on 2026-10-01 UTC, and the ruling
    # binds both repositories. `Crank-Git/ja4plus-go#801` holds the Go half. The ruling
    # follows `python/ja4.py:156-157` and `rust/ja4/src/tls.rs:635-647` at the FoxIO
    # commit `16b96d95`. It reverses #127, #141 and #162 for those inputs. The vector
    # `tls-non-ascii-alpn.pcapng` holds `ba ad`, and both ends of it write `9`, so it
    # still reads `99`.
    #
    # #789: the maintainer ruled a control byte on the same day, and a control byte at
    # either end still writes the `99` of #162. The FoxIO Rust implementation reads a
    # control byte as the tshark escape text, so it reads `h\x1f` as five characters and
    # writes `hf`.
    first = _alpn_end_character(first_alpn_bytes[0])
    last = _alpn_end_character(first_alpn_bytes[-1])
    if first is None or last is None:
        return "99"
    return first + last


def generate_ja4(tls_info: dict[str, Any] | None, original_order: bool = False) -> str | None:
    """Return the JA4 fingerprint of one TLS Client Hello.

    Args:
        tls_info: A dictionary with TLS handshake information.
        original_order: True returns the `JA4_o` value, which hashes the wire
            order. False returns the `JA4` value, which hashes the sorted order.

    Returns:
        A JA4 fingerprint string, or None when the info describes no Client Hello.
    """
    if not tls_info or tls_info.get("type") != "client_hello":
        return None

    try:
        # Determine protocol type (q=QUIC, d=DTLS, t=TLS over TCP)
        proto = "q" if tls_info.get("is_quic") else "d" if tls_info.get("is_dtls") else "t"

        # Get TLS version - prioritize supported_versions extension (0x002b)
        version = tls_info.get("version")
        supported_versions = tls_info.get("supported_versions", [])

        # Filter out GREASE values
        supported_versions = [v for v in supported_versions if not is_grease_value(v)]

        if supported_versions:
            # Use highest supported version
            version = max(supported_versions)

        # Convert version to string format
        if version == 0x0304:  # TLS 1.3
            version_str = "13"
        elif version == 0x0303:  # TLS 1.2
            version_str = "12"
        elif version == 0x0302:  # TLS 1.1
            version_str = "11"
        elif version == 0x0301:  # TLS 1.0
            version_str = "10"
        elif version == 0x0300:  # SSL 3.0
            version_str = "s3"
        # FoxIO commit `3e02a27` corrected the SSL 2.0 value from `0x0200` to `0x0002`,
        # and `technical_details/JA4.md:65` states the corrected value. #227 holds the
        # reading. A hello that names `0x0200` reaches the `00` fallback.
        elif version == 0x0002:  # SSL 2.0
            version_str = "s2"
        elif version == 0xFEFF:  # DTLS 1.0
            version_str = "d1"
        elif version == 0xFEFD:  # DTLS 1.2
            version_str = "d2"
        elif version == 0xFEFC:  # DTLS 1.3
            version_str = "d3"
        else:
            version_str = "00"

        # SNI type - 'd' if SNI exists, 'i' if not
        sni = tls_info.get("sni")
        sni_type = "d" if sni else "i"

        # Get cipher suites - filter out GREASE values
        ciphers = [c for c in tls_info.get("ciphers", []) if not is_grease_value(c)]
        cipher_count = min(len(ciphers), 99)  # Cap at 99
        cipher_count_str = f"{cipher_count:02d}"

        # Get extensions - filter out GREASE values
        extensions = [e for e in tls_info.get("extensions", []) if not is_grease_value(e)]
        ext_count = min(len(extensions), 99)  # Cap at 99
        ext_count_str = f"{ext_count:02d}"

        # ALPN value per FoxIO spec PR #277: see compute_alpn_value().
        # Prefer the raw bytes (full byte fidelity) and fall back to the
        # decoded string for backward-compat callers that only set
        # alpn_protocols.
        alpn_raw = tls_info.get("alpn_raw") or []
        alpn_protocols = tls_info.get("alpn_protocols", [])
        if alpn_raw:
            alpn_value = compute_alpn_value(alpn_raw[0])
        elif alpn_protocols and alpn_protocols[0]:
            alpn_value = compute_alpn_value(alpn_protocols[0].encode("latin-1", errors="replace"))
        else:
            alpn_value = "00"

        # Form part_a of the fingerprint
        part_a = f"{proto}{version_str}{sni_type}{cipher_count_str}{ext_count_str}{alpn_value}"

        # Generate cipher hash. The original-order form hashes the wire order.
        if ciphers:
            hashed_ciphers = ciphers if original_order else sorted(ciphers)
            cipher_str = ",".join([f"{c:04x}" for c in hashed_ciphers])
            cipher_hash = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]
        else:
            cipher_hash = "000000000000"

        # Generate extension hash
        # 1. Select the extensions to hash. The sorted form removes SNI (0x0000)
        #    and ALPN (0x0010), because both appear in part_a. The original-order
        #    form keeps every extension, as `JA4_ro` in the FoxIO vectors shows.
        sorted_extensions = sorted(e for e in extensions if e != 0x0000 and e != 0x0010)
        hashed_extensions = extensions if original_order else sorted_extensions

        # 2. Get signature algorithms in original order. FoxIO removes GREASE values
        #    here too, in Rust commit `d66336ef`. `extract_tls_info` keeps them as a
        #    record of the wire, so the fingerprinter removes them.
        sig_algs = [s for s in tls_info.get("signature_algorithms", []) if not is_grease_value(s)]

        # 3. Form extension string - extensions + underscore + sig algorithms if present
        ext_str = ",".join([f"{e:04x}" for e in hashed_extensions])
        sorted_ext_str = ",".join([f"{e:04x}" for e in sorted_extensions])
        if sig_algs:
            sig_alg_str = ",".join([f"{s:04x}" for s in sig_algs])
            ext_str = f"{ext_str}_{sig_alg_str}"
            sorted_ext_str = f"{sorted_ext_str}_{sig_alg_str}"

        # 4. Generate extension hash. FoxIO reads the sorted list for the zero sentinel,
        #    and it sets both extension hashes from that one test. A client hello that
        #    carries SNI alone therefore gives `JA4_o` the zero sentinel, and `JA4_ro`
        #    still shows `0000`. #132 holds the measurement.
        if sorted_ext_str:
            ext_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
        else:
            ext_hash = "000000000000"

        # Form the complete JA4 fingerprint
        ja4 = f"{part_a}_{cipher_hash}_{ext_hash}"

        return ja4

    except (ValueError, TypeError, IndexError, KeyError, AttributeError) as e:
        logger.debug(f"Failed to generate JA4 fingerprint: {e}")
        return None


def get_raw_fingerprint(
    tls_info: dict[str, Any] | None, original_order: bool = False
) -> str | None:
    """
    Generate a raw JA4 fingerprint with all values visible.

    Args:
        tls_info: A dictionary with TLS handshake information
        original_order: Whether to maintain original ordering (True) or sort (False)

    Returns:
        A raw JA4 fingerprint string or None if not applicable
    """
    if not tls_info or tls_info.get("type") != "client_hello":
        return None

    try:
        # Get the same components as in generate_ja4
        proto = "q" if tls_info.get("is_quic") else "d" if tls_info.get("is_dtls") else "t"

        # Version
        version = tls_info.get("version")
        supported_versions = tls_info.get("supported_versions", [])
        supported_versions = [v for v in supported_versions if not is_grease_value(v)]

        if supported_versions:
            version = max(supported_versions)

        # Map version to string format (same as in generate_ja4)
        if version == 0x0304:  # TLS 1.3
            version_str = "13"
        elif version == 0x0303:  # TLS 1.2
            version_str = "12"
        elif version == 0x0302:  # TLS 1.1
            version_str = "11"
        elif version == 0x0301:  # TLS 1.0
            version_str = "10"
        elif version == 0x0300:  # SSL 3.0
            version_str = "s3"
        # The raw form reads the same table as `generate_ja4`, and #227 holds the reading.
        elif version == 0x0002:  # SSL 2.0
            version_str = "s2"
        elif version == 0xFEFF:  # DTLS 1.0
            version_str = "d1"
        elif version == 0xFEFD:  # DTLS 1.2
            version_str = "d2"
        elif version == 0xFEFC:  # DTLS 1.3
            version_str = "d3"
        else:
            version_str = "00"

        # SNI
        sni = tls_info.get("sni")
        sni_type = "d" if sni else "i"

        # Ciphers - filter GREASE
        ciphers = [c for c in tls_info.get("ciphers", []) if not is_grease_value(c)]
        cipher_count = min(len(ciphers), 99)
        cipher_count_str = f"{cipher_count:02d}"

        # Extensions - filter GREASE
        extensions = [e for e in tls_info.get("extensions", []) if not is_grease_value(e)]
        ext_count = min(len(extensions), 99)
        ext_count_str = f"{ext_count:02d}"

        # ALPN per FoxIO spec PR #277 — same path as generate_ja4
        alpn_raw = tls_info.get("alpn_raw") or []
        alpn_protocols = tls_info.get("alpn_protocols", [])
        if alpn_raw:
            alpn_value = compute_alpn_value(alpn_raw[0])
        elif alpn_protocols and alpn_protocols[0]:
            alpn_value = compute_alpn_value(alpn_protocols[0].encode("latin-1", errors="replace"))
        else:
            alpn_value = "00"

        # First part of fingerprint
        part_a = f"{proto}{version_str}{sni_type}{cipher_count_str}{ext_count_str}{alpn_value}"

        # Cipher list - either sorted or original
        if original_order:
            cipher_list = ",".join(
                [f"{c:04x}" for c in tls_info.get("ciphers", []) if not is_grease_value(c)]
            )
        else:
            cipher_list = ",".join([f"{c:04x}" for c in sorted(ciphers)])

        # Extension list - either with or without SNI/ALPN based on original_order
        if original_order:
            ext_list = ",".join(
                [f"{e:04x}" for e in tls_info.get("extensions", []) if not is_grease_value(e)]
            )
        else:
            ext_list = ",".join(
                [f"{e:04x}" for e in sorted([e for e in extensions if e != 0x0000 and e != 0x0010])]
            )

        # Signature algorithms, with GREASE values removed as in `generate_ja4`.
        # FoxIO `JA4_r` and `JA4_ro` print no GREASE value, since Rust commit `d66336ef`.
        sig_algs = [s for s in tls_info.get("signature_algorithms", []) if not is_grease_value(s)]
        sig_alg_list = ",".join([f"{s:04x}" for s in sig_algs])

        # Final format. FoxIO holds the signature algorithms in wire order for both
        # `JA4_r` and `JA4_o`, so `original_order` selects nothing here. The cipher list
        # and the extension list above carry the whole difference between the two.
        if sig_algs:
            raw_ja4 = f"{part_a}_{cipher_list}_{ext_list}_{sig_alg_list}"
        else:
            raw_ja4 = f"{part_a}_{cipher_list}_{ext_list}"

        return raw_ja4

    except (ValueError, TypeError, IndexError, KeyError, AttributeError) as e:
        logger.debug(f"Failed to generate JA4 fingerprint: {e}")
        return None


class JA4Fingerprinter(BaseFingerprinter):
    """Fingerprinter for JA4 (TLS Client Hello).

    In addition to the hashed JA4 fingerprint returned by ``process_packet``,
    this fingerprinter exposes the raw (unhashed) variants on every entry in
    ``get_fingerprints()`` and on ``last_raw`` / ``last_raw_original_order``
    for the most recent successful parse, mirroring the Go reference's
    FingerprintResult.Raw / RawOriginalOrder fields.

    Every entry also carries ``fingerprint_original_order``, the FoxIO `JA4_o`
    value. It is the hashed form of ``raw_original_order``, and the most recent
    one is on ``last_fingerprint_original_order``.
    """

    def __init__(self, thread_safe: bool = True) -> None:
        super().__init__(thread_safe=thread_safe)
        self.last_raw: str | None = None
        self.last_raw_original_order: str | None = None
        self.last_fingerprint_original_order: str | None = None
        # DCID -> list[(offset, data)] for multi-datagram QUIC CRYPTO reassembly.
        # Keyed by DCID hex so packets with the same connection ID accumulate
        # together regardless of UDP 5-tuple changes.
        self._quic_fragments = quic_fragment_table()
        self._quic_dcid_to_tuple = quic_fragment_table()
        self._tcp_hellos = tcp_hello_table()

    def process_packet(self, packet: Packet) -> str | None:
        """Process a packet and extract JA4 fingerprint if applicable.

        For QUIC Initials larger than one datagram, CRYPTO frame fragments
        accumulate per Destination Connection ID until a full ClientHello
        can be reassembled. Once parsed, the per-DCID buffer is released.
        """
        with self._lock:
            tls_info = extract_tls_info(packet)
            if not tls_info:
                tls_info = self._try_quic_multi_packet(packet) or self._try_tcp_segments(packet)
            if not tls_info:
                return None

            fingerprint = generate_ja4(tls_info)
            if fingerprint:
                raw = get_raw_fingerprint(tls_info, original_order=False)
                raw_oo = get_raw_fingerprint(tls_info, original_order=True)
                fingerprint_oo = generate_ja4(tls_info, original_order=True)
                self.last_raw = raw
                self.last_raw_original_order = raw_oo
                self.last_fingerprint_original_order = fingerprint_oo
                entry: dict[str, Any] = {
                    "fingerprint": fingerprint,
                    "fingerprint_original_order": fingerprint_oo,
                    "raw": raw,
                    "raw_original_order": raw_oo,
                }
                entry.update(packet_endpoints(packet))
                self.fingerprints.append(entry)

            return fingerprint

    def _try_quic_multi_packet(self, packet: Packet) -> dict[str, Any] | None:
        """Accumulate QUIC CRYPTO fragments per DCID; return tls_info if a
        full ClientHello has been reassembled."""
        from ja4plus.utils.quic_utils import (
            decrypt_quic_initial_crypto,
            client_hello_from_crypto_fragments,
            collect_crypto_fragments,
        )

        # A tunnel carries its own UDP header, and `getlayer` counts from the outside. The
        # QUIC layer is the innermost one, so a reader that takes the outer header decodes
        # the tunnel bytes and produces no value. `packet_utils.packet_endpoints` reads the
        # same layer, so one result names one port pair.
        udp = innermost_layer(packet, (UDP,))
        if udp is None:
            return None
        udp_payload = bytes(udp.payload)
        if not udp_payload:
            return None

        fragments, dcid = decrypt_quic_initial_crypto(udp_payload)
        if dcid is None or fragments is None:
            return None

        # ja4l.py reads the packet clock the same way. The announcement precedes the
        # first table operation, so the entry it writes carries the capture time.
        seconds = float(packet.time) if hasattr(packet, "time") else time.time()
        self._quic_fragments.on_packet(seconds)
        self._quic_dcid_to_tuple.on_packet(seconds)

        dcid_key = dcid.hex()
        existing = self._quic_fragments.setdefault(dcid_key, [])
        collect_crypto_fragments(existing, fragments)

        # Track DCID -> 5-tuple for cleanup_connection.
        from ja4plus.utils.packet_utils import get_ip_layer

        ip = get_ip_layer(packet)
        if ip is not None:
            tuple_key = f"{ip.src}:{int(udp.sport)}-{ip.dst}:{int(udp.dport)}"
            self._quic_dcid_to_tuple[dcid_key] = tuple_key

        # scapy and the untyped QUIC reader each give this value as `Any`. The local
        # annotation states the type the value holds, and it changes no value.
        tls_info: dict[str, Any] | None = client_hello_from_crypto_fragments(existing)
        if tls_info is not None:
            # ClientHello is complete — release the buffer.
            self._drop_quic_fragments(dcid_key)
        return tls_info

    def _drop_quic_fragments(self, dcid_key: str) -> None:
        """Drop every table entry one connection holds."""
        self._quic_fragments.pop(dcid_key, None)
        self._quic_dcid_to_tuple.pop(dcid_key, None)

    def _try_tcp_segments(self, packet: Packet) -> dict[str, Any] | None:
        """Return the ClientHello fields the collected TCP segments complete, or None.

        A segment that opens a ClientHello and cuts it starts a stream. A later segment
        of the same direction extends the stream. The stream stops at the first byte
        that no segment carries, so a gap never reads as zeros.

        Args:
            packet: The packet the caller processes.

        Returns:
            The parsed ClientHello fields on the segment that completes the hello.
            Returns None on every other segment, and for a packet that carries no TCP.
        """
        # The port pair names the innermost layer, as `packet_endpoints` does, so a
        # tunnel keys one stream on the ports the result reports.
        tcp = innermost_layer(packet, (TCP, UDP))
        if not isinstance(tcp, TCP):
            return None
        endpoints = packet_endpoints(packet)
        key = f"{endpoints['src']}:{endpoints['srcport']}-{endpoints['dst']}:{endpoints['dstport']}"

        tls_info = None
        if Raw in packet:
            tls_info = self._add_tcp_segment(key, int(tcp.seq), bytes(packet[Raw]), packet)

        if int(tcp.flags) & (FIN_FLAG | RST_FLAG):
            reverse = f"{endpoints['dst']}:{endpoints['dstport']}-{endpoints['src']}:{endpoints['srcport']}"
            self._tcp_hellos.remove_stream(key)
            self._tcp_hellos.remove_stream(reverse)
        return tls_info

    def _add_tcp_segment(
        self, key: str, seq: int, payload: bytes, packet: Packet
    ) -> dict[str, Any] | None:
        """Add one segment to the stream of its direction, and parse a complete hello.

        Args:
            key: The stream key of the direction.
            seq: The 32-bit sequence number of the first payload byte.
            payload: The payload bytes of the segment.
            packet: The packet that carries the segment, for its timestamp.

        Returns:
            The parsed ClientHello fields, or None while the hello is incomplete.
        """
        base = self._tcp_hellos.base_seq(key)
        if base is None:
            end = client_hello_end(payload)
            # A hello the segment holds whole needs no stream. The single-segment
            # reader already read it, and it found no ClientHello.
            if end is None or end <= len(payload) or end > MAX_TCP_HELLO_BYTES:
                return None
        elif sequence_before(seq, base):
            # A byte before the first hello byte would move the start of the stream, and
            # the stream would then open with no TLS record.
            return None

        self._tcp_hellos.add_segment(key, seq, payload, packet_seconds(packet))
        data = self._tcp_hellos.get_stream(key)
        end = client_hello_end(data)
        if end is not None and len(data) < end <= MAX_TCP_HELLO_BYTES:
            # A stream at the segment cap accepts no further segment, so it waits for
            # nothing that can arrive.
            if len(self._tcp_hellos.streams[key]["segments"]) < MAX_TCP_HELLO_SEGMENTS:
                return None

        self._tcp_hellos.remove_stream(key)
        if end is None or end > len(data):
            return None
        # The untyped TLS reader gives this value as `Any`. The local annotation states
        # the type the value holds, and it changes no value.
        tls_info: dict[str, Any] | None = parse_tls_handshake(data)
        if not tls_info or tls_info.get("type") != "client_hello":
            return None
        return tls_info

    def reset(self) -> None:
        with self._lock:
            super().reset()
            self.last_raw = None
            self.last_raw_original_order = None
            self.last_fingerprint_original_order = None
            self._quic_fragments = quic_fragment_table()
            self._quic_dcid_to_tuple = quic_fragment_table()
            self._tcp_hellos = tcp_hello_table()

    def cleanup_connection(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str
    ) -> None:
        """Drop the QUIC CRYPTO fragments and the partial TCP ClientHello of the 5-tuple."""
        with self._lock:
            tuple_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            rev_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
            for dcid_key, tup in list(self._quic_dcid_to_tuple.items()):
                if tup == tuple_key or tup == rev_key:
                    self._drop_quic_fragments(dcid_key)
            self._tcp_hellos.remove_stream(tuple_key)
            self._tcp_hellos.remove_stream(rev_key)

    def get_raw_fingerprint(self, packet: Packet, original_order: bool = False) -> str | None:
        """
        Get raw JA4 fingerprint with visible components.

        Args:
            packet: A packet containing a TLS Client Hello
            original_order: Whether to maintain original ordering

        Returns:
            Raw JA4 fingerprint string or None
        """
        tls_info = extract_tls_info(packet)
        if not tls_info:
            return None

        return get_raw_fingerprint(tls_info, original_order)


# The imports, the constants and the table below serve the TCP ClientHello path. They
# stand at the end of the module, so every line that a document cites above keeps its
# number. No module they import reads this one, so the late import binds no cycle.
from scapy.all import TCP, Raw  # noqa: E402

from ja4plus.utils.packet_utils import RST_FLAG, packet_seconds  # noqa: E402
from ja4plus.utils.tcp_stream import TCPStreamReassembler, sequence_before  # noqa: E402
from ja4plus.utils.tls_utils import client_hello_end, parse_tls_handshake  # noqa: E402

# The highest number of TCP connections whose partial ClientHello one fingerprinter
# holds. A sender opens a new connection at the cost of one segment, so the table needs
# a limit. The QUIC fragment table holds the same limit.
MAX_TCP_HELLO_STREAMS = 1000

# The longest a connection holds a partial ClientHello without a further segment. The
# segments of one hello arrive inside one round trip, and the QUIC fragment table holds
# the same age.
MAX_TCP_HELLO_AGE_SECONDS = 30

# The most bytes one partial ClientHello holds. RFC 8446 Section 5.1 limits the
# plaintext of one record to 2**14 bytes, and the record header adds 5. The last 6 bytes
# hold the ChangeCipherSpec record that a client sends before its second hello.
MAX_TCP_HELLO_BYTES = 2**14 + 5 + 6

# The most segments one partial ClientHello holds. A hello at the byte cap spans 31
# segments of 536 bytes, which is the least segment size RFC 9293 lets a host assume.
# The cap stops a sender of one-byte segments from holding 16395 list entries.
MAX_TCP_HELLO_SEGMENTS = 64

# A segment with FIN or RST ends the stream, so no later segment completes its hello.
FIN_FLAG = 0x01


def tcp_hello_table() -> TCPStreamReassembler:
    """Return one bounded reassembler for the partial TCP ClientHello of each stream.

    A ClientHello that spans several TCP segments collects here, once for each direction
    of a connection. The segment that completes it gives the value.

    Returns:
        A `TCPStreamReassembler` that holds the four TCP ClientHello limits.
    """
    return TCPStreamReassembler(
        max_streams=MAX_TCP_HELLO_STREAMS,
        max_stream_bytes=MAX_TCP_HELLO_BYTES,
        max_stream_segments=MAX_TCP_HELLO_SEGMENTS,
        max_stream_age=MAX_TCP_HELLO_AGE_SECONDS,
    )
