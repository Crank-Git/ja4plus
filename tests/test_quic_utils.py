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
    def test_too_short(self):
        from ja4plus.utils.quic_utils import parse_quic_initial

        self.assertIsNone(parse_quic_initial(b"\x00" * 10))

    def test_short_header(self):
        from ja4plus.utils.quic_utils import parse_quic_initial

        self.assertIsNone(parse_quic_initial(b"\x40" + b"\x00" * 30))

    def test_version_negotiation(self):
        from ja4plus.utils.quic_utils import parse_quic_initial

        pkt = bytearray(b"\xc0") + b"\x00\x00\x00\x00" + b"\x00" * 30
        self.assertIsNone(parse_quic_initial(bytes(pkt)))

    def test_non_initial_type(self):
        from ja4plus.utils.quic_utils import parse_quic_initial

        pkt = bytearray()
        pkt.append(0xC0 | (0x02 << 4))
        pkt += b"\x00\x00\x00\x01" + b"\x00" * 30
        self.assertIsNone(parse_quic_initial(bytes(pkt)))

    # QUIC version 2 gives an Initial packet the long-header type code 1, where version 1
    # gives it the code 0. RFC 9369 Section 3.2 states both codes. The three cases below
    # build a packet that decrypts, because a packet that fails decryption returns None
    # for two reasons, and the type check is only one of them.
    DCID = bytes.fromhex("8394c8f03e515708")

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

    def test_too_short_returns_none(self):
        from ja4plus.utils.quic_utils import parse_quic_server_initial

        self.assertIsNone(parse_quic_server_initial(b"\x00" * 4, b"\x01" * 8))

    def test_empty_client_dcid_returns_none(self):
        from ja4plus.utils.quic_utils import parse_quic_server_initial

        self.assertIsNone(parse_quic_server_initial(b"\xc0" + b"\x00" * 40, b""))

    def test_short_header_returns_none(self):
        from ja4plus.utils.quic_utils import parse_quic_server_initial

        # Short header: bit 7 clear
        pkt = b"\x40" + b"\x00\x00\x00\x01" + b"\x00" * 40
        self.assertIsNone(parse_quic_server_initial(pkt, b"\x01" * 8))

    def test_version_negotiation_returns_none(self):
        from ja4plus.utils.quic_utils import parse_quic_server_initial

        pkt = b"\xc0" + b"\x00\x00\x00\x00" + b"\x00" * 40
        self.assertIsNone(parse_quic_server_initial(pkt, b"\x01" * 8))

    def test_wrong_packet_type_returns_none(self):
        from ja4plus.utils.quic_utils import parse_quic_server_initial

        # QUIC v1 Handshake type (0x02 in bits 4-5), not Initial (0x00)
        first_byte = 0xC0 | (0x02 << 4)
        pkt = bytes([first_byte]) + b"\x00\x00\x00\x01" + b"\x00" * 40
        self.assertIsNone(parse_quic_server_initial(pkt, b"\x01" * 8))

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
