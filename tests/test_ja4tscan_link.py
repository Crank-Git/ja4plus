"""Measure the link-layer network of the scanner against a fake `scapy` socket.

`ja4plus/scan/link.py` opens the one socket of `ja4plus` that sends. No case opens a
real one: each case replaces the socket class, the routing table and the address
resolver of `scapy` with fakes, and reads the frames the module hands to the socket.
"""

from __future__ import annotations

import errno
import types

import pytest
from scapy.error import Scapy_Exception

from ja4plus.scan import link
from ja4plus.scan.frames import parse_frame

IFACE = "en9"
SCANNER_IP = "198.51.100.1"
SCANNER_MAC = "02:00:00:00:00:01"
GATEWAY = "198.51.100.254"
GATEWAY_MAC = "02:00:00:00:00:fe"
NEIGHBOR = "198.51.100.7"
NEIGHBOR_MAC = "02:00:00:00:00:07"


class FakeSocket:
    """Records every frame sent, and returns queued frames to `recv_raw`."""

    instances: list["FakeSocket"] = []
    refuse_filter: BaseException | None = None

    def __init__(self, iface: str, filter: str | None = None) -> None:
        if filter is not None and FakeSocket.refuse_filter is not None:
            raise FakeSocket.refuse_filter
        self.iface = iface
        self.filter = filter
        self.sent: list[bytes] = []
        self.inbox: list[tuple[bytes | None, float | None]] = []
        self.closed = False
        FakeSocket.instances.append(self)

    def send(self, frame: bytes) -> int:
        self.sent.append(bytes(frame))
        return len(frame)

    @staticmethod
    def select(sockets, remain=None):
        return [sock for sock in sockets if sock.inbox]

    def recv_raw(self):
        data, seconds = self.inbox.pop(0)
        return None, data, seconds

    def close(self) -> None:
        self.closed = True


class FakeRoute:
    def route(self, target: str):
        if target.startswith("127."):
            return "lo0", "127.0.0.1", "0.0.0.0"
        if target.startswith("203.0.113."):
            return "en7", "203.0.113.1", "0.0.0.0"
        if target.startswith("198.51.100."):
            return IFACE, SCANNER_IP, "0.0.0.0"
        return IFACE, SCANNER_IP, GATEWAY


@pytest.fixture
def fake_scapy(monkeypatch):
    """Replace every `scapy` name the module reads, and return the resolver log."""
    FakeSocket.instances = []
    FakeSocket.refuse_filter = None
    resolved: list[str] = []
    macs = {GATEWAY: GATEWAY_MAC, NEIGHBOR: NEIGHBOR_MAC}

    def getmacbyip(address: str):
        resolved.append(address)
        return macs.get(address)

    monkeypatch.setattr(
        link,
        "conf",
        types.SimpleNamespace(route=FakeRoute(), L2socket=FakeSocket, loopback_name="lo0"),
    )
    monkeypatch.setattr(link, "get_if_hwaddr", lambda iface: SCANNER_MAC)
    monkeypatch.setattr(link, "getmacbyip", getmacbyip)
    return resolved


def network(port: int = 443, first: str = "192.0.2.10"):
    warnings: list[str] = []
    return link.LinkNetwork(port, first, warnings.append), warnings


class TestTheSocket:
    def test_the_socket_opens_on_the_interface_of_the_first_target(self, fake_scapy):
        net, _ = network()
        (sock,) = FakeSocket.instances
        assert sock.iface == IFACE
        assert sock.filter == "tcp and src port 443"
        assert net.mac == bytes.fromhex("020000000001")

    def test_a_filter_the_host_cannot_compile_leaves_a_socket_with_no_filter(self, fake_scapy):
        FakeSocket.refuse_filter = Scapy_Exception("Failed to compile filter expression")
        net, _ = network()
        assert net.socket.filter is None

    def test_a_refused_privilege_on_the_filtered_socket_reaches_the_caller(self, fake_scapy):
        FakeSocket.refuse_filter = Scapy_Exception("/dev/bpf0: Permission denied")
        with pytest.raises(Scapy_Exception):
            network()

    def test_close_closes_the_socket(self, fake_scapy):
        net, _ = network()
        net.close()
        assert net.socket.closed


class TestTheSend:
    def test_a_target_behind_the_gateway_gets_one_frame_to_the_gateway(self, fake_scapy):
        net, warnings = network()
        assert net.send("192.0.2.10", 50001, 1234) == SCANNER_IP
        (frame,) = net.socket.sent
        assert frame[:6] == bytes.fromhex("0200000000fe")
        assert frame[6:12] == bytes.fromhex("020000000001")
        assert frame[30:34] == bytes([192, 0, 2, 10])
        assert int.from_bytes(frame[36:38], "big") == 443
        assert warnings == []

    def test_a_target_on_the_link_gets_a_frame_to_its_own_address(self, fake_scapy):
        net, _ = network(first=NEIGHBOR)
        net.send(NEIGHBOR, 50001, 1)
        assert net.socket.sent[0][:6] == bytes.fromhex("020000000007")

    def test_the_address_of_one_next_hop_resolves_once(self, fake_scapy):
        net, _ = network()
        net.send("192.0.2.10", 50001, 1)
        net.send("192.0.2.11", 50002, 2)
        assert fake_scapy == [GATEWAY]
        assert len(net.socket.sent) == 2

    def test_a_next_hop_with_no_address_gets_no_frame_and_one_warning(self, fake_scapy):
        net, warnings = network(first="198.51.100.9")
        assert net.send("198.51.100.9", 50001, 1) is None
        assert net.socket.sent == []
        assert len(warnings) == 1
        assert "198.51.100.9" in warnings[0]

    @pytest.mark.parametrize("target", ["203.0.113.5", "127.0.0.1"])
    def test_a_target_on_another_interface_gets_no_frame_and_one_warning(self, fake_scapy, target):
        net, warnings = network()
        assert net.send(target, 50001, 1) is None
        assert net.socket.sent == []
        assert len(warnings) == 1

    def test_a_first_target_on_the_loopback_interface_sends_nothing(self, fake_scapy):
        net, warnings = network(first="127.0.0.1")
        assert net.send("127.0.0.1", 50001, 1) is None
        assert net.socket.sent == []
        assert len(warnings) == 1


class TestTheReceive:
    def test_no_frame_within_the_timeout_returns_none(self, fake_scapy):
        net, _ = network()
        assert net.receive(0.5) is None

    def test_a_frame_returns_its_capture_time_and_its_bytes(self, fake_scapy):
        net, _ = network()
        net.socket.inbox.append((b"\x01\x02", 1234.5))
        assert net.receive(0.5) == (1234.5, b"\x01\x02")

    def test_a_frame_with_no_capture_time_reads_the_clock(self, fake_scapy, monkeypatch):
        net, _ = network()
        monkeypatch.setattr(link.time, "time", lambda: 99.0)
        net.socket.inbox.append((b"\x01", None))
        assert net.receive(0.5) == (99.0, b"\x01")

    def test_a_socket_that_returns_no_data_returns_none(self, fake_scapy):
        net, _ = network()
        net.socket.inbox.append((None, None))
        assert net.receive(0.5) is None

    def test_the_sent_frame_parses_as_the_syn_of_the_target(self, fake_scapy):
        net, _ = network()
        net.send("192.0.2.10", 50001, 1234)
        reply = parse_frame(net.socket.sent[0])
        assert reply is not None
        assert (reply.src_ip, reply.dst_ip, reply.flags) == (SCANNER_IP, "192.0.2.10", 0x02)


@pytest.mark.parametrize(
    ("error", "refused"),
    [
        (PermissionError(errno.EPERM, "Operation not permitted"), True),
        (OSError(errno.EACCES, "Permission denied"), True),
        (Scapy_Exception("/dev/bpf3: Permission denied"), True),
        (OSError(errno.ENODEV, "No such device"), False),
        (Scapy_Exception("No /dev/bpf handle is available"), False),
    ],
)
def test_privilege_refused_reads_the_error_number_and_the_text(error, refused):
    assert link.privilege_refused(error) is refused


class TestTheNextHopAge:
    """The next-hop cache holds each entry for at most `NEXT_HOP_MAX_AGE` seconds unread.

    CLAUDE.md requires a maximum age on every state table. A case moves the clock of the
    module, and it runs the age pass on every send so that one send reads the bound.
    """

    @pytest.fixture
    def clock(self, monkeypatch):
        now = [1_000_000.0]
        monkeypatch.setattr(link, "time", types.SimpleNamespace(time=lambda: now[0]))
        monkeypatch.setattr(link, "NEXT_HOP_EVICTION_INTERVAL", 1)
        return now

    def test_a_next_hop_unread_past_the_maximum_age_leaves_the_cache(self, fake_scapy, clock):
        net, _ = network(first=NEIGHBOR)
        net.send(NEIGHBOR, 50001, 1)
        clock[0] += link.NEXT_HOP_MAX_AGE + 1
        net.send("198.51.100.8", 50002, 2)
        assert NEIGHBOR not in net.next_hops.keys()

    def test_a_next_hop_past_the_maximum_age_is_resolved_again(self, fake_scapy, clock):
        net, _ = network(first=NEIGHBOR)
        net.send(NEIGHBOR, 50001, 1)
        clock[0] += link.NEXT_HOP_MAX_AGE + 1
        net.send("198.51.100.8", 50002, 2)
        net.send(NEIGHBOR, 50003, 3)
        assert fake_scapy.count(NEIGHBOR) == 2

    def test_a_next_hop_inside_the_maximum_age_stays_in_the_cache(self, fake_scapy, clock):
        net, _ = network(first=NEIGHBOR)
        net.send(NEIGHBOR, 50001, 1)
        clock[0] += link.NEXT_HOP_MAX_AGE - 1
        net.send("198.51.100.8", 50002, 2)
        net.send(NEIGHBOR, 50003, 3)
        assert fake_scapy.count(NEIGHBOR) == 1


def test_the_next_hop_cache_holds_at_most_the_target_bound(fake_scapy, monkeypatch):
    monkeypatch.setattr(link, "MAX_TARGETS", 2)
    net, _ = network(first=NEIGHBOR)
    sizes = []
    for index in range(5):
        net.send(f"198.51.100.{10 + index}", 50000 + index, index)
        sizes.append(len(net.next_hops))
    assert max(sizes) == 2
