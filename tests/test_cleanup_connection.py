"""Tests for the cleanup_connection() API on stateful fingerprinters.

`Processor.cleanup_connection` is the call the watch command runs for every connection
it evicts, so the memory ceiling #279 states rests on it. #339 records that the earlier
cases asserted nothing about the state after the call, and that a call which removes the
wrong key, leaves the entry, or removes a neighbouring connection passed every one.

Every case that holds state builds two connections. The target connection holds the
addresses `state_readers.TARGET_CLIENT` and `state_readers.TARGET_SERVER`. The
neighbouring connection holds two other addresses, and no case removes it. The reader
then compares the whole key set of every state table against the key set a correct call
leaves, which catches all three failure modes at once. The remaining cases run against a
fingerprinter that holds no state, and each one reads that the call adds no key.
"""

import struct
import unittest

from scapy.all import IP, TCP, UDP, Raw

from tests.state_readers import (
    NEIGHBOUR_CLIENT,
    NEIGHBOUR_SERVER,
    TARGET_CLIENT,
    TARGET_SERVER,
    count_keys,
    keys_without_the_target,
    state_keys,
    target_keys,
)

# The two address pairs every case builds, target first.
CONNECTIONS = ((TARGET_CLIENT, TARGET_SERVER), (NEIGHBOUR_CLIENT, NEIGHBOUR_SERVER))

# An address pair no case builds. A call that names it reaches no entry.
ABSENT_CLIENT = "172.31.0.1"
ABSENT_SERVER = "172.31.0.2"


def quic_client_initial(src, dst, dcid, sport=54321):
    """Return one QUIC version 1 client Initial packet that carries the given DCID.

    The datagram parses to no ClientHello, so JA4S records the DCID of the connection
    and emits nothing. `tests/test_quic_utils.py` builds the same datagram.

    Args:
        src: The source address.
        dst: The destination address.
        dcid: The destination connection identifier.
        sport: The source port.

    Returns:
        One scapy packet.
    """
    datagram = bytearray()
    datagram.append(0xC0)  # A long header that names the Initial packet type.
    datagram += struct.pack("!I", 0x00000001)  # QUIC version 1.
    datagram.append(len(dcid))
    datagram += dcid
    datagram.append(0)  # The SCID length.
    datagram.append(0)  # The token length.
    datagram += b"\x40\x01"  # The payload length, as a varint.
    datagram += b"\x00"
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=443) / Raw(load=bytes(datagram))


class CleanupReaderMixin:
    """The three readers every `cleanup_connection` case runs."""

    def assert_cleanup_removes_only_the_target(self, fingerprinter, target):
        """Fail unless the call removes every target key and holds every other key.

        The comparison covers the three failure modes #339 names. A call that leaves the
        entry holds a target key. A call that removes the wrong key drops a key the
        comparison expects. A call that removes a neighbouring connection drops one too.

        Args:
            fingerprinter: The fingerprinter under test, with both connections built.
            target: The five arguments of the `cleanup_connection` call.
        """
        # A fingerprinter that holds no state for either connection passes the
        # comparison below without measuring anything.
        self.assertGreater(
            count_keys(target_keys(fingerprinter)),
            0,
            "the fingerprinter holds no state for the target connection",
        )
        expected = keys_without_the_target(fingerprinter)
        self.assertGreater(
            count_keys(expected),
            0,
            "the fingerprinter holds no state for the neighbouring connection",
        )

        fingerprinter.cleanup_connection(*target)

        self.assertEqual(state_keys(fingerprinter), expected)

    def assert_cleanup_holds_every_key(self, fingerprinter, absent):
        """Fail unless a call that names an absent connection changes no key.

        Args:
            fingerprinter: The fingerprinter under test, with both connections built.
            absent: The five arguments of the `cleanup_connection` call. They name a
                connection the fingerprinter holds no state for.
        """
        before = state_keys(fingerprinter)
        self.assertGreater(count_keys(before), 0, "the fingerprinter holds no state")

        fingerprinter.cleanup_connection(*absent)

        self.assertEqual(state_keys(fingerprinter), before)

    def assert_cleanup_on_empty_state_holds_the_empty_tables(self, fingerprinter, absent):
        """Fail unless a call against an empty fingerprinter leaves every table empty.

        Args:
            fingerprinter: A fingerprinter that processed no packet.
            absent: The five arguments of the `cleanup_connection` call.
        """
        before = state_keys(fingerprinter)
        self.assertEqual(count_keys(before), 0, "the fingerprinter holds state already")

        fingerprinter.cleanup_connection(*absent)

        self.assertEqual(state_keys(fingerprinter), before)


class TestBaseFingerprinterCleanup(unittest.TestCase):
    def test_the_base_class_holds_the_cleanup_method(self):
        from ja4plus.fingerprinters.base import BaseFingerprinter

        self.assertTrue(hasattr(BaseFingerprinter, "cleanup_connection"))

    def test_the_base_no_op_holds_no_state_table_and_holds_every_fingerprint(self):
        """The base class holds nothing per connection, so its call removes nothing.

        The fingerprint list is not per-connection data, and the `## Terms` table names
        it no state table. A call that empties it therefore fails this case.
        """
        from ja4plus.fingerprinters.base import BaseFingerprinter

        fingerprinter = BaseFingerprinter()
        fingerprinter.add_fingerprint(
            "q13d0310h3_55b375c5d22e_cd85d2d88918",
            IP(src=TARGET_CLIENT, dst=TARGET_SERVER) / TCP(sport=1234, dport=443),
        )
        # A shallow copy shares the entry objects, so a call that rewrites one entry in
        # place would change this value too and the comparison below would pass.
        before = [dict(entry) for entry in fingerprinter.get_fingerprints()]
        self.assertEqual(len(before), 1)
        self.assertEqual(fingerprinter.state_tables(), {})

        fingerprinter.cleanup_connection(TARGET_CLIENT, 1234, TARGET_SERVER, 443, "tcp")

        self.assertEqual(fingerprinter.state_tables(), {})
        self.assertEqual(fingerprinter.get_fingerprints(), before)


class TestJA4LCleanup(CleanupReaderMixin, unittest.TestCase):
    def _build(self):
        """Return a JA4L fingerprinter that holds both connections."""
        from ja4plus.fingerprinters.ja4l import JA4LFingerprinter

        fingerprinter = JA4LFingerprinter()
        for src, dst in CONNECTIONS:
            fingerprinter.process_packet(
                IP(src=src, dst=dst) / TCP(sport=12345, dport=443, flags="S")
            )
        return fingerprinter

    def test_cleanup_removes_only_the_target_connection(self):
        self.assert_cleanup_removes_only_the_target(
            self._build(), (TARGET_CLIENT, 12345, TARGET_SERVER, 443, "tcp")
        )

    def test_cleanup_removes_the_target_named_in_the_reverse_direction(self):
        """JA4L normalizes the key, so either argument order reaches the same entry."""
        self.assert_cleanup_removes_only_the_target(
            self._build(), (TARGET_SERVER, 443, TARGET_CLIENT, 12345, "tcp")
        )

    def test_cleanup_of_an_absent_connection_holds_every_key(self):
        self.assert_cleanup_holds_every_key(
            self._build(), (ABSENT_CLIENT, 100, ABSENT_SERVER, 200, "tcp")
        )

    def test_cleanup_on_an_empty_fingerprinter_holds_the_empty_tables(self):
        from ja4plus.fingerprinters.ja4l import JA4LFingerprinter

        self.assert_cleanup_on_empty_state_holds_the_empty_tables(
            JA4LFingerprinter(), (ABSENT_CLIENT, 100, ABSENT_SERVER, 200, "tcp")
        )

    def test_cleanup_removes_a_tunnelled_connection_by_the_reported_address(self):
        """A caller of a tunnelled connection holds the outer address pair.

        JA4L groups a tunnelled connection under its inner address pair, so a caller
        that names the outer pair reaches no entry without the map of the two keys.

        The generic reader compares a key against the target address, and the outer key
        of a tunnel holds neither target address. This case therefore names its four
        keys itself.
        """
        from scapy.layers.inet import GRE

        from ja4plus.fingerprinters.ja4l import JA4LFingerprinter

        outer = (("1.1.1.1", "2.2.2.2"), ("3.3.3.3", "4.4.4.4"))
        fingerprinter = JA4LFingerprinter()
        for (outer_src, outer_dst), (src, dst) in zip(outer, CONNECTIONS):
            fingerprinter.process_packet(
                IP(src=outer_src, dst=outer_dst)
                / GRE()
                / IP(src=src, dst=dst)
                / TCP(sport=12345, dport=443, flags="S")
            )
        target_inner = f"tcp_{TARGET_CLIENT}:12345_{TARGET_SERVER}:443"
        neighbour_inner = f"tcp_{NEIGHBOUR_CLIENT}:12345_{NEIGHBOUR_SERVER}:443"
        self.assertEqual(set(fingerprinter.connections.keys()), {target_inner, neighbour_inner})
        self.assertEqual(
            set(fingerprinter.grouping_keys.keys()),
            {"tcp_1.1.1.1:12345_2.2.2.2:443", "tcp_3.3.3.3:12345_4.4.4.4:443"},
        )

        fingerprinter.cleanup_connection("1.1.1.1", 12345, "2.2.2.2", 443, "tcp")

        self.assertEqual(set(fingerprinter.connections.keys()), {neighbour_inner})
        self.assertEqual(set(fingerprinter.grouping_keys.keys()), {"tcp_3.3.3.3:12345_4.4.4.4:443"})


class TestJA4SSHCleanup(CleanupReaderMixin, unittest.TestCase):
    def _build(self, dport=2222):
        """Return a JA4SSH fingerprinter that holds both connections.

        The default port is 2222 and not 22, because `_record_handshake` records no
        client for a connection that port 22 already decides. A port other than 22
        therefore fills both tables of the method.
        """
        from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter

        fingerprinter = JA4SSHFingerprinter()
        for src, dst in CONNECTIONS:
            fingerprinter.process_packet(
                IP(src=src, dst=dst) / TCP(sport=54321, dport=dport, flags="S")
            )
            fingerprinter.process_packet(
                IP(src=src, dst=dst)
                / TCP(sport=54321, dport=dport, flags="PA")
                / Raw(load=b"SSH-2.0-OpenSSH_8.0\r\n")
            )
        return fingerprinter

    def test_cleanup_removes_only_the_target_connection(self):
        self.assert_cleanup_removes_only_the_target(
            self._build(), (TARGET_CLIENT, 54321, TARGET_SERVER, 2222, "tcp")
        )

    def test_cleanup_removes_the_target_named_in_the_reverse_direction(self):
        self.assert_cleanup_removes_only_the_target(
            self._build(), (TARGET_SERVER, 2222, TARGET_CLIENT, 54321, "tcp")
        )

    def test_cleanup_removes_only_the_target_connection_on_port_22(self):
        self.assert_cleanup_removes_only_the_target(
            self._build(dport=22), (TARGET_CLIENT, 54321, TARGET_SERVER, 22, "tcp")
        )

    def test_cleanup_of_an_absent_connection_holds_every_key(self):
        self.assert_cleanup_holds_every_key(
            self._build(), (ABSENT_CLIENT, 100, ABSENT_SERVER, 22, "tcp")
        )

    def test_cleanup_on_an_empty_fingerprinter_holds_the_empty_tables(self):
        from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter

        self.assert_cleanup_on_empty_state_holds_the_empty_tables(
            JA4SSHFingerprinter(), (ABSENT_CLIENT, 100, ABSENT_SERVER, 22, "tcp")
        )


class TestJA4HCleanup(CleanupReaderMixin, unittest.TestCase):
    def _build(self):
        """Return a JA4H fingerprinter that holds both connections.

        The first request completes, which fills `consumed_seq`. The bytes that follow
        it read as no request, which holds a stream in the reassembler and records the
        base sequence in `unusable_base`. All three tables of the method then hold one
        key for each connection.
        """
        from ja4plus.fingerprinters.ja4h import JA4HFingerprinter

        complete = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        unreadable = b"\x00\x01\x02\x03"
        fingerprinter = JA4HFingerprinter()
        for src, dst in CONNECTIONS:
            fingerprinter.process_packet(
                IP(src=src, dst=dst)
                / TCP(sport=54321, dport=80, seq=1, flags="PA")
                / Raw(load=complete)
            )
            fingerprinter.process_packet(
                IP(src=src, dst=dst)
                / TCP(sport=54321, dport=80, seq=1 + len(complete), flags="PA")
                / Raw(load=unreadable)
            )
        return fingerprinter

    def test_cleanup_removes_only_the_target_stream(self):
        self.assert_cleanup_removes_only_the_target(
            self._build(), (TARGET_CLIENT, 54321, TARGET_SERVER, 80, "tcp")
        )

    def test_cleanup_removes_the_target_stream_named_in_the_reverse_direction(self):
        self.assert_cleanup_removes_only_the_target(
            self._build(), (TARGET_SERVER, 80, TARGET_CLIENT, 54321, "tcp")
        )

    def test_cleanup_of_an_absent_connection_holds_every_key(self):
        self.assert_cleanup_holds_every_key(
            self._build(), (ABSENT_CLIENT, 100, ABSENT_SERVER, 80, "tcp")
        )

    def test_cleanup_on_an_empty_fingerprinter_holds_the_empty_tables(self):
        from ja4plus.fingerprinters.ja4h import JA4HFingerprinter

        self.assert_cleanup_on_empty_state_holds_the_empty_tables(
            JA4HFingerprinter(), (ABSENT_CLIENT, 100, ABSENT_SERVER, 80, "tcp")
        )


class TestJA4XCleanup(CleanupReaderMixin, unittest.TestCase):
    def _build(self):
        """Return a JA4X fingerprinter that holds both connections.

        The packet carries a truncated TLS Certificate record, which holds a stream in
        the reassembler and records a scan offset. `processed_certs` reads a whole
        certificate, so each connection receives one entry by hand instead.
        """
        from ja4plus.fingerprinters.ja4x import JA4XFingerprinter

        fingerprinter = JA4XFingerprinter()
        for src, dst in CONNECTIONS:
            fingerprinter.process_packet(
                IP(src=src, dst=dst)
                / TCP(sport=443, dport=12345, seq=100)
                / Raw(load=b"\x16\x03\x01\x00\x05\x0b\x00\x00\x01\x00")
            )
            fingerprinter.processed_certs[(f"{src}:443-{dst}:12345", "00" * 32)] = None
        return fingerprinter

    def test_cleanup_removes_only_the_target_stream(self):
        self.assert_cleanup_removes_only_the_target(
            self._build(), (TARGET_CLIENT, 443, TARGET_SERVER, 12345, "tcp")
        )

    def test_cleanup_removes_the_target_stream_named_in_the_reverse_direction(self):
        self.assert_cleanup_removes_only_the_target(
            self._build(), (TARGET_SERVER, 12345, TARGET_CLIENT, 443, "tcp")
        )

    def test_cleanup_of_an_absent_connection_holds_every_key(self):
        self.assert_cleanup_holds_every_key(
            self._build(), (ABSENT_CLIENT, 100, ABSENT_SERVER, 443, "tcp")
        )

    def test_cleanup_on_an_empty_fingerprinter_holds_the_empty_tables(self):
        from ja4plus.fingerprinters.ja4x import JA4XFingerprinter

        self.assert_cleanup_on_empty_state_holds_the_empty_tables(
            JA4XFingerprinter(), (ABSENT_CLIENT, 100, ABSENT_SERVER, 443, "tcp")
        )


class TestJA4SCleanup(CleanupReaderMixin, unittest.TestCase):
    def _build(self):
        """Return a JA4S fingerprinter that holds both QUIC connections.

        The client Initial packet records the DCID of the connection. The server CRYPTO
        table fills from a ServerHello that two Initial packets split, so each
        connection receives one entry by hand instead.
        """
        from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

        fingerprinter = JA4SFingerprinter()
        for index, (src, dst) in enumerate(CONNECTIONS):
            fingerprinter.process_packet(quic_client_initial(src, dst, bytes([0xA0 + index]) * 8))
            fingerprinter._quic_server_crypto[f"{dst}:443-{src}:54321"] = [(0, b"\x00")]
        return fingerprinter

    def test_cleanup_removes_only_the_target_connection(self):
        self.assert_cleanup_removes_only_the_target(
            self._build(), (TARGET_CLIENT, 54321, TARGET_SERVER, 443, "udp")
        )

    def test_cleanup_removes_the_target_named_in_the_reverse_direction(self):
        self.assert_cleanup_removes_only_the_target(
            self._build(), (TARGET_SERVER, 443, TARGET_CLIENT, 54321, "udp")
        )

    def test_cleanup_of_an_absent_connection_holds_every_key(self):
        self.assert_cleanup_holds_every_key(
            self._build(), (ABSENT_CLIENT, 100, ABSENT_SERVER, 443, "udp")
        )

    def test_cleanup_on_an_empty_fingerprinter_holds_the_empty_tables(self):
        from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

        self.assert_cleanup_on_empty_state_holds_the_empty_tables(
            JA4SFingerprinter(), (ABSENT_CLIENT, 100, ABSENT_SERVER, 443, "udp")
        )


class TestJA4TSCleanup(CleanupReaderMixin, unittest.TestCase):
    def _build(self):
        """Return a JA4TS fingerprinter that holds both connections.

        Every SYN-ACK travels from the server, so the server address leads the packet.
        """
        from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter

        fingerprinter = JA4TSFingerprinter()
        for client, server in CONNECTIONS:
            fingerprinter.process_packet(
                IP(src=server, dst=client) / TCP(sport=443, dport=12345, flags="SA", window=1024)
            )
        return fingerprinter

    def test_cleanup_removes_only_the_target_connection(self):
        self.assert_cleanup_removes_only_the_target(
            self._build(), (TARGET_SERVER, 443, TARGET_CLIENT, 12345, "tcp")
        )

    def test_cleanup_removes_the_target_named_in_the_reverse_direction(self):
        self.assert_cleanup_removes_only_the_target(
            self._build(), (TARGET_CLIENT, 12345, TARGET_SERVER, 443, "tcp")
        )

    def test_cleanup_of_an_absent_connection_holds_every_key(self):
        self.assert_cleanup_holds_every_key(
            self._build(), (ABSENT_SERVER, 443, ABSENT_CLIENT, 12345, "tcp")
        )

    def test_cleanup_on_an_empty_fingerprinter_holds_the_empty_tables(self):
        from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter

        self.assert_cleanup_on_empty_state_holds_the_empty_tables(
            JA4TSFingerprinter(), (ABSENT_SERVER, 443, ABSENT_CLIENT, 12345, "tcp")
        )


class TestJA4Cleanup(unittest.TestCase):
    """JA4 keys its two QUIC tables by the DCID and not by the address pair.

    `state_readers.names_the_target` reads a key for an address, so it finds no JA4 key.
    Each case here therefore names the two DCID keys itself.
    """

    TARGET_DCID = "a0a0a0a0a0a0a0a0"
    NEIGHBOUR_DCID = "b1b1b1b1b1b1b1b1"

    def _build(self):
        """Return a JA4 fingerprinter that holds both QUIC connections.

        The two tables fill from a client Initial that carries a CRYPTO frame this
        project can decrypt. Each connection receives its two entries by hand instead,
        which reaches the same key shape.
        """
        from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

        fingerprinter = JA4Fingerprinter()
        pairs = (
            (self.TARGET_DCID, f"{TARGET_CLIENT}:54321-{TARGET_SERVER}:443"),
            (self.NEIGHBOUR_DCID, f"{NEIGHBOUR_CLIENT}:54321-{NEIGHBOUR_SERVER}:443"),
        )
        for dcid, tuple_key in pairs:
            fingerprinter._quic_fragments[dcid] = [(0, b"\x00")]
            fingerprinter._quic_dcid_to_tuple[dcid] = tuple_key
        return fingerprinter

    def _assert_holds_only_the_neighbour(self, fingerprinter):
        """Fail unless both tables hold the neighbouring DCID alone."""
        self.assertEqual(set(fingerprinter._quic_fragments.keys()), {self.NEIGHBOUR_DCID})
        self.assertEqual(set(fingerprinter._quic_dcid_to_tuple.keys()), {self.NEIGHBOUR_DCID})

    def test_cleanup_removes_only_the_target_connection(self):
        fingerprinter = self._build()

        fingerprinter.cleanup_connection(TARGET_CLIENT, 54321, TARGET_SERVER, 443, "udp")

        self._assert_holds_only_the_neighbour(fingerprinter)

    def test_cleanup_removes_the_target_named_in_the_reverse_direction(self):
        fingerprinter = self._build()

        fingerprinter.cleanup_connection(TARGET_SERVER, 443, TARGET_CLIENT, 54321, "udp")

        self._assert_holds_only_the_neighbour(fingerprinter)

    def test_cleanup_of_an_absent_connection_holds_every_key(self):
        fingerprinter = self._build()

        fingerprinter.cleanup_connection(ABSENT_CLIENT, 100, ABSENT_SERVER, 443, "udp")

        self.assertEqual(
            set(fingerprinter._quic_fragments.keys()),
            {self.TARGET_DCID, self.NEIGHBOUR_DCID},
        )
        self.assertEqual(
            set(fingerprinter._quic_dcid_to_tuple.keys()),
            {self.TARGET_DCID, self.NEIGHBOUR_DCID},
        )

    def test_cleanup_on_an_empty_fingerprinter_holds_the_empty_tables(self):
        from ja4plus.fingerprinters.ja4 import JA4Fingerprinter

        fingerprinter = JA4Fingerprinter()

        fingerprinter.cleanup_connection(ABSENT_CLIENT, 100, ABSENT_SERVER, 443, "udp")

        self.assertEqual(fingerprinter._quic_fragments.keys(), [])
        self.assertEqual(fingerprinter._quic_dcid_to_tuple.keys(), [])


if __name__ == "__main__":
    unittest.main()
