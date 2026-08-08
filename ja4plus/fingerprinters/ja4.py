"""
JA4 TLS Client Hello Fingerprinting implementation.
"""

# Python 3.9 is the floor, and it evaluates no annotation written as `str | None`
# without this import.
from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

from scapy.all import TCP, UDP, Raw, IP, Packet

from ja4plus.utils.tls_utils import extract_tls_info, is_grease_value
from ja4plus.utils.packet_utils import packet_endpoints
from ja4plus.utils.state_table import BoundedStateTable
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


def _is_alnum_byte(b: int) -> bool:
    """Return True when the byte is an ASCII alphanumeric: 0-9, A-Z, a-z."""
    return (0x30 <= b <= 0x39) or (0x41 <= b <= 0x5A) or (0x61 <= b <= 0x7A)


def _is_printable_ascii_byte(b: int) -> bool:
    """Return True when the byte is printable ASCII: 0x20-0x7E."""
    return 0x20 <= b <= 0x7E


def compute_alpn_value(first_alpn_bytes: bytes | None) -> str:
    """Return the two-character ALPN value that JA4 and JA4S carry.

    The value is `00` for an absent ALPN extension. The value is the first byte and
    the last byte when both bytes are printable ASCII, which is `0x20-0x7E`. A one-byte
    value repeats that byte when the byte is ASCII alphanumeric. The value is `99` in
    every other case.

    Args:
        first_alpn_bytes: The bytes of the first ALPN value, or None.

    Returns:
        A two-character string.
    """
    if not first_alpn_bytes:
        return "00"

    first = first_alpn_bytes[0]
    last = first_alpn_bytes[-1]

    # #141: the two FoxIO implementations disagree on a one-byte value. `python/ja4.py`
    # writes one character and `rust/tls.rs` writes the byte and `0`. No measurement
    # settles the case, so this project holds the value it wrote before #141.
    if len(first_alpn_bytes) == 1:
        if _is_alnum_byte(first):
            ch = chr(first)
            return ch + ch
        return "99"

    # #141: the FoxIO prose tests for an alphanumeric byte, and the measurement
    # contradicts it. Both FoxIO implementations pass a printable ASCII byte through, so
    # `h\x20` reads `h ` and not `99`. `tests/foxio_vectors/alpn-condition.pcap` holds
    # the measurement.
    #
    # The range stops at `0x7E`, because the two implementations agree only inside it.
    # The FoxIO Rust implementation reads a control byte as the tshark escape text, so
    # it reads `h\x1f` as five characters and writes `hf`.
    if _is_printable_ascii_byte(first) and _is_printable_ascii_byte(last):
        return chr(first) + chr(last)

    # #127: the FoxIO prose gives the first and the last character of the hex form. The
    # FoxIO Python implementation and the FoxIO Rust implementation give `99`, and the
    # vector `tls-non-ascii-alpn.pcapng` holds `99`. This project follows the vector.
    #
    # #141: the two implementations disagree on every byte outside `0x20-0x7E` that
    # sits in a position other than the first. This project holds `99` until the user
    # decides.
    return "99"


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

        # 2. Get signature algorithms in original order
        sig_algs = tls_info.get("signature_algorithms", [])

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

        # Signature algorithms
        sig_algs = tls_info.get("signature_algorithms", [])
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

    def process_packet(self, packet: Packet) -> str | None:
        """Process a packet and extract JA4 fingerprint if applicable.

        For QUIC Initials larger than one datagram, CRYPTO frame fragments
        accumulate per Destination Connection ID until a full ClientHello
        can be reassembled. Once parsed, the per-DCID buffer is released.
        """
        with self._lock:
            tls_info = extract_tls_info(packet)
            if not tls_info:
                tls_info = self._try_quic_multi_packet(packet)
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

        udp = packet.getlayer(UDP)
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

    def reset(self) -> None:
        with self._lock:
            super().reset()
            self.last_raw = None
            self.last_raw_original_order = None
            self.last_fingerprint_original_order = None
            self._quic_fragments = quic_fragment_table()
            self._quic_dcid_to_tuple = quic_fragment_table()

    def cleanup_connection(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str
    ) -> None:
        """Drop any accumulated QUIC CRYPTO fragments for the given 5-tuple."""
        with self._lock:
            tuple_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            rev_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
            for dcid_key, tup in list(self._quic_dcid_to_tuple.items()):
                if tup == tuple_key or tup == rev_key:
                    self._drop_quic_fragments(dcid_key)

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
