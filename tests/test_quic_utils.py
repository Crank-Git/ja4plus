"""Tests for QUIC Initial packet parsing utilities."""

import unittest


class TestDecodeVarint(unittest.TestCase):
    def test_1byte(self):
        from ja4plus.utils.quic_utils import _decode_varint

        val, consumed = _decode_varint(b"\x25")
        self.assertEqual(val, 37)
        self.assertEqual(consumed, 1)

    def test_2byte(self):
        from ja4plus.utils.quic_utils import _decode_varint

        val, consumed = _decode_varint(b"\x7b\xbd")
        self.assertEqual(val, 15293)
        self.assertEqual(consumed, 2)

    def test_4byte(self):
        from ja4plus.utils.quic_utils import _decode_varint

        val, consumed = _decode_varint(b"\x9d\x7f\x3e\x7d")
        self.assertEqual(val, 494878333)
        self.assertEqual(consumed, 4)

    def test_zero(self):
        from ja4plus.utils.quic_utils import _decode_varint

        val, consumed = _decode_varint(b"\x00")
        self.assertEqual(val, 0)
        self.assertEqual(consumed, 1)


class TestHKDFExpandLabel(unittest.TestCase):
    def test_output_length(self):
        from ja4plus.utils.quic_utils import hkdf_expand_label

        result = hkdf_expand_label(b"\x00" * 32, b"quic key", b"", 16)
        self.assertEqual(len(result), 16)

    def test_iv_length(self):
        from ja4plus.utils.quic_utils import hkdf_expand_label

        result = hkdf_expand_label(b"\x00" * 32, b"quic iv", b"", 12)
        self.assertEqual(len(result), 12)


class TestDeriveInitialSecrets(unittest.TestCase):
    DCID = bytes.fromhex("8394c8f03e515708")

    def test_secret_lengths(self):
        from ja4plus.utils.quic_utils import derive_initial_secrets

        cs, ss = derive_initial_secrets(self.DCID, version=1)
        self.assertEqual(len(cs), 32)
        self.assertEqual(len(ss), 32)

    def test_key_iv_hp_lengths(self):
        from ja4plus.utils.quic_utils import derive_initial_secrets, derive_key_iv_hp

        cs, _ = derive_initial_secrets(self.DCID, version=1)
        key, iv, hp = derive_key_iv_hp(cs)
        self.assertEqual(len(key), 16)
        self.assertEqual(len(iv), 12)
        self.assertEqual(len(hp), 16)


class TestFindPnOffset(unittest.TestCase):
    def test_minimal_initial(self):
        from ja4plus.utils.quic_utils import _find_pn_offset

        packet = bytearray()
        packet.append(0xC0)
        packet += b"\x00\x00\x00\x01"
        packet.append(8)
        packet += b"\x00" * 8
        packet.append(0)
        packet.append(0)
        packet += b"\x40\x02"
        packet += b"\x00" * 20
        self.assertEqual(_find_pn_offset(bytes(packet)), 18)


class TestParseQuicInitial(unittest.TestCase):
    # A packet of dummy bytes makes the reader return None whichever guard runs, so such
    # a case measures the decryption rather than the guard it names. Every guard case
    # below therefore carries a protected ClientHello the reader decrypts. The AEAD tag
    # covers the header, so each case builds the rejected header rather than changing a
    # byte of a built packet. #348 records the measurement.
    DCID = bytes.fromhex("8394c8f03e515708")

    def rejected_packet(self, **header):
        """Return one client Initial packet that decrypts and carries a ClientHello.

        Args:
            header: The header fields `client_initial_crypto` writes.

        Returns:
            The bytes of the UDP payload.
        """
        from tests.quic_builder import client_hello, client_initial_crypto, crypto_frame

        return client_initial_crypto(
            self.DCID, crypto_frame(0, client_hello("guard.example.com")), **header
        )

    def test_too_short(self):
        from ja4plus.utils.quic_utils import parse_quic_initial

        self.assertIsNone(parse_quic_initial(b"\x00" * 10))

    def test_a_truncated_long_header_returns_none_rather_than_raising(self):
        """The reader returns None for a long header that holds three version bytes.

        The reader unpacks the version field outside its `try` block, so the length
        guard is the only thing that stops a `struct.error` reaching the caller. No
        packet under 20 bytes can carry a ClientHello, so this case measures the length
        guard by the exception it prevents rather than by a result.
        """
        from ja4plus.utils.quic_utils import parse_quic_initial

        self.assertIsNone(parse_quic_initial(b"\xc0\x00\x00\x00"))

    def test_short_header(self):
        """A packet whose header form bit is clear produces no ClientHello."""
        from ja4plus.utils.quic_utils import parse_quic_initial

        self.assertIsNone(parse_quic_initial(self.rejected_packet(long_header=False)))

    def test_version_negotiation(self):
        """A packet whose version number is zero produces no ClientHello."""
        from ja4plus.utils.quic_utils import parse_quic_initial

        # The reader reads version 0 as version 1, so the builder protects the packet
        # under the version 1 salt. The version guard is then the only rejection.
        packet = self.rejected_packet(version=0, type_code=0, key_version=1)
        self.assertIsNone(parse_quic_initial(packet))

    def test_non_initial_type(self):
        """A QUIC version 1 Handshake packet produces no ClientHello."""
        from ja4plus.utils.quic_utils import parse_quic_initial

        # The packet holds the type code 2, which version 1 gives a Handshake packet.
        self.assertIsNone(parse_quic_initial(self.rejected_packet(type_code=2)))

    # QUIC version 2 gives an Initial packet the long-header type code 1, where version 1
    # gives it the code 0. RFC 9369 Section 3.2 states both codes.

    def test_v2_initial_yields_the_client_hello(self):
        """A QUIC version 2 Initial packet produces the ClientHello it carries."""
        from ja4plus.utils.quic_utils import parse_quic_initial
        from tests.quic_builder import (
            QUIC_VERSION_2,
            client_hello,
            client_initial_crypto,
            crypto_frame,
        )

        packet = client_initial_crypto(
            self.DCID,
            crypto_frame(0, client_hello("v2.example.com")),
            version=QUIC_VERSION_2,
        )
        tls_info = parse_quic_initial(packet)
        self.assertIsNotNone(tls_info)
        self.assertEqual(tls_info["sni"], "v2.example.com")
        self.assertTrue(tls_info["is_quic"])

    def test_v1_initial_yields_the_client_hello(self):
        """A QUIC version 1 Initial packet produces the ClientHello it carries."""
        from ja4plus.utils.quic_utils import parse_quic_initial
        from tests.quic_builder import client_hello, client_initial_crypto, crypto_frame

        packet = client_initial_crypto(self.DCID, crypto_frame(0, client_hello("v1.example.com")))
        tls_info = parse_quic_initial(packet)
        self.assertIsNotNone(tls_info)
        self.assertEqual(tls_info["sni"], "v1.example.com")

    def test_v2_non_initial_rejected(self):
        """A QUIC version 2 Handshake packet produces no ClientHello."""
        from ja4plus.utils.quic_utils import parse_quic_initial
        from tests.quic_builder import (
            QUIC_VERSION_2,
            client_hello,
            client_initial_crypto,
            crypto_frame,
        )

        # The packet holds the type code 3, which version 2 gives a Handshake packet, and
        # it carries the same protected ClientHello as the Initial case. A reader that
        # drops the type check therefore returns that ClientHello, so this case measures
        # the type check and nothing else.
        packet = client_initial_crypto(
            self.DCID,
            crypto_frame(0, client_hello("v2.example.com")),
            version=QUIC_VERSION_2,
            type_code=3,
        )
        self.assertIsNone(parse_quic_initial(packet))


class TestExtractCryptoFrames(unittest.TestCase):
    def test_single_crypto_frame(self):
        from ja4plus.utils.quic_utils import extract_crypto_frames

        result = extract_crypto_frames(b"\x06\x00\x05hello")
        self.assertEqual(result, b"hello")

    def test_padding_then_crypto(self):
        from ja4plus.utils.quic_utils import extract_crypto_frames

        result = extract_crypto_frames(b"\x00\x06\x00\x03abc")
        self.assertEqual(result, b"abc")

    def test_no_crypto_returns_none(self):
        from ja4plus.utils.quic_utils import extract_crypto_frames

        self.assertIsNone(extract_crypto_frames(b"\x00\x00\x00"))

    def test_multiple_frames_reassembled(self):
        from ja4plus.utils.quic_utils import extract_crypto_frames

        result = extract_crypto_frames(b"\x06\x00\x03abc\x06\x03\x03def")
        self.assertEqual(result, b"abcdef")


class TestParseQuicServerInitial(unittest.TestCase):
    """Tests for parse_quic_server_initial() — the server-side QUIC Initial decoder."""

    # Every guard case below carries a protected ServerHello the reader decrypts, so the
    # guard the case names is the only reason the reader returns None. The AEAD tag
    # covers the header, so each case builds the rejected header rather than changing a
    # byte of a built packet. #348 records the measurement.
    CLIENT_DCID = bytes.fromhex("203f9e9f68698274")

    def rejected_packet(self, client_dcid=None, **header):
        """Return one server Initial packet that decrypts and carries a ServerHello.

        Args:
            client_dcid: The connection ID the server Initial keys derive from. The
                default is `CLIENT_DCID`.
            header: The header fields `server_initial` writes.

        Returns:
            The bytes of the UDP payload.
        """
        from tests.quic_builder import crypto_frame, server_hello, server_initial

        if client_dcid is None:
            client_dcid = self.CLIENT_DCID
        return server_initial(client_dcid, crypto_frame(0, server_hello()), **header)

    def test_an_initial_packet_yields_the_server_hello(self):
        """A server Initial packet produces the ServerHello it carries.

        Every rejection case below builds the same packet under a rejected header, so
        this case states what those cases would produce if their guard were absent.
        """
        from ja4plus.utils.quic_utils import parse_quic_server_initial

        tls_info = parse_quic_server_initial(self.rejected_packet(), self.CLIENT_DCID)
        self.assertIsNotNone(tls_info)
        self.assertEqual(tls_info["handshake_type"], "server_hello")

    def test_too_short_returns_none(self):
        from ja4plus.utils.quic_utils import parse_quic_server_initial

        self.assertIsNone(parse_quic_server_initial(b"\x00" * 4, b"\x01" * 8))

    def test_a_truncated_long_header_returns_none_rather_than_raising(self):
        """The reader returns None for a long header that holds three version bytes.

        The reader unpacks the version field outside its `try` block, so the length
        guard is the only thing that stops a `struct.error` reaching the caller. No
        packet under five bytes can carry a ServerHello, so this case measures the
        length guard by the exception it prevents rather than by a result.
        """
        from ja4plus.utils.quic_utils import parse_quic_server_initial

        self.assertIsNone(parse_quic_server_initial(b"\xc0\x00\x00\x00", b"\x01" * 8))

    def test_empty_client_dcid_returns_none(self):
        """The reader returns None when the caller passes no connection ID."""
        from ja4plus.utils.quic_utils import parse_quic_server_initial

        # The packet derives its keys from the empty connection ID, so a reader that
        # drops this guard derives the keys the packet holds and returns the ServerHello.
        self.assertIsNone(parse_quic_server_initial(self.rejected_packet(b""), b""))

    def test_short_header_returns_none(self):
        """A packet whose header form bit is clear produces no ServerHello."""
        from ja4plus.utils.quic_utils import parse_quic_server_initial

        packet = self.rejected_packet(long_header=False)
        self.assertIsNone(parse_quic_server_initial(packet, self.CLIENT_DCID))

    def test_version_negotiation_returns_none(self):
        """A packet whose version number is zero produces no ServerHello."""
        from ja4plus.utils.quic_utils import parse_quic_server_initial

        # The reader reads version 0 as version 1, so the builder protects the packet
        # under the version 1 salt. The version guard is then the only rejection.
        packet = self.rejected_packet(version=0, type_code=0, key_version=1)
        self.assertIsNone(parse_quic_server_initial(packet, self.CLIENT_DCID))

    def test_wrong_packet_type_returns_none(self):
        """A QUIC version 1 Handshake packet produces no ServerHello."""
        from ja4plus.utils.quic_utils import parse_quic_server_initial

        # The packet holds the type code 2, which version 1 gives a Handshake packet.
        packet = self.rejected_packet(type_code=2)
        self.assertIsNone(parse_quic_server_initial(packet, self.CLIENT_DCID))

    def test_a_version_2_wrong_packet_type_returns_none(self):
        """A QUIC version 2 Handshake packet produces no ServerHello."""
        from ja4plus.utils.quic_utils import parse_quic_server_initial
        from tests.quic_builder import QUIC_VERSION_2

        # Version 2 gives a Handshake packet the type code 3. RFC 9369 Section 3.2
        # states the code. The version 2 arm of the type guard rejects it.
        packet = self.rejected_packet(version=QUIC_VERSION_2, type_code=3)
        self.assertIsNone(parse_quic_server_initial(packet, self.CLIENT_DCID))

    def test_a_version_2_initial_packet_yields_the_server_hello(self):
        """A QUIC version 2 server Initial packet produces the ServerHello it carries."""
        from ja4plus.utils.quic_utils import parse_quic_server_initial
        from tests.quic_builder import QUIC_VERSION_2

        packet = self.rejected_packet(version=QUIC_VERSION_2)
        tls_info = parse_quic_server_initial(packet, self.CLIENT_DCID)
        self.assertIsNotNone(tls_info)
        self.assertEqual(tls_info["handshake_type"], "server_hello")

    def test_invalid_encrypted_data_returns_none(self):
        """A structurally valid but undecryptable packet returns None (not an exception)."""
        from ja4plus.utils.quic_utils import parse_quic_server_initial
        import struct

        # Build a minimal QUIC v1 Initial long header (server direction)
        dcid = b"\x01" * 8  # fake DCID
        scid = b"\x02" * 4  # fake SCID
        payload = b"\x00" * 80  # garbage (will fail AES-GCM decryption)

        pkt = bytearray()
        pkt.append(0xC0)  # long header, Initial type
        pkt += struct.pack("!I", 0x00000001)  # QUIC v1
        pkt.append(len(dcid))
        pkt += dcid
        pkt.append(len(scid))
        pkt += scid
        pkt.append(0)  # token length = 0
        # payload length as varint (2-byte form for safety)
        pkt.append(0x40 | (len(payload) >> 8))
        pkt.append(len(payload) & 0xFF)
        pkt += payload

        client_dcid = b"\xaa" * 8
        result = parse_quic_server_initial(bytes(pkt), client_dcid)
        # Decryption fails on garbage ciphertext — must return None, not raise
        self.assertIsNone(result)


class TestJA4SQUICTracking(unittest.TestCase):
    """Tests for JA4SFingerprinter DCID state tracking."""

    def _make_quic_client_initial(self, dcid=b"\xab" * 8, sport=54321, dport=443):
        """Build a fake QUIC v1 client Initial UDP packet with a known DCID."""
        import struct
        from scapy.all import IP, UDP, Raw

        pkt = bytearray()
        pkt.append(0xC0)  # long header, Initial (type 0x00)
        pkt += struct.pack("!I", 0x00000001)  # QUIC v1
        pkt.append(len(dcid))
        pkt += dcid
        pkt.append(0)  # SCID length = 0
        pkt.append(0)  # token length = 0
        pkt += b"\x40\x01"  # payload length = 1 (varint)
        pkt += b"\x00"  # dummy payload (will fail to parse ClientHello)

        return (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=sport, dport=dport)
            / Raw(load=bytes(pkt))
        )

    def test_client_initial_does_not_produce_ja4s(self):
        """Client Initial packet should not generate a JA4S fingerprint."""
        from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

        fp = JA4SFingerprinter()
        result = fp.process_packet(self._make_quic_client_initial())
        self.assertIsNone(result)

    def test_dcid_captured_from_client_initial(self):
        """Fingerprinter captures the DCID from a client Initial for later server decryption."""
        from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

        fp = JA4SFingerprinter()
        dcid = b"\xde\xad\xbe\xef" * 2
        pkt = self._make_quic_client_initial(dcid=dcid, sport=54321, dport=443)
        fp.process_packet(pkt)
        # Check internal state: the forward connection key should map to the DCID
        conn_key = "10.0.0.1:54321-10.0.0.2:443"
        self.assertIn(conn_key, fp._quic_dcids)
        self.assertEqual(fp._quic_dcids[conn_key], dcid)

    def test_cleanup_connection_removes_dcid(self):
        """cleanup_connection() removes the stored DCID for that flow."""
        from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

        fp = JA4SFingerprinter()
        dcid = b"\xde\xad\xbe\xef" * 2
        pkt = self._make_quic_client_initial(dcid=dcid, sport=54321, dport=443)
        fp.process_packet(pkt)

        fp.cleanup_connection("10.0.0.1", 54321, "10.0.0.2", 443, "udp")
        self.assertNotIn("10.0.0.1:54321-10.0.0.2:443", fp._quic_dcids)
        self.assertNotIn("10.0.0.2:443-10.0.0.1:54321", fp._quic_dcids)

    def test_reset_clears_dcid_state(self):
        """reset() clears all stored DCID state."""
        from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

        fp = JA4SFingerprinter()
        pkt = self._make_quic_client_initial()
        fp.process_packet(pkt)
        fp.reset()
        self.assertEqual(fp._quic_dcids, {})


if __name__ == "__main__":
    unittest.main()
