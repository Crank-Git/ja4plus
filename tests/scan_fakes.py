"""A fake network for the scanner cases, which sends no packet and opens no socket.

`docs/specs/features/12-active-scan.md` states that the scan loop takes the send
function and the receive function as parameters. `FakeNetwork` supplies both, plus a
clock that moves only when the loop waits, so a scan of 120 seconds runs in no time.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field

from scapy.all import IP, TCP, Ether

SCANNER_IP = "198.51.100.1"


@dataclass
class Script:
    """Holds what one fake target sends after it receives the SYN.

    Attributes:
        offsets: The seconds after the SYN at which the target sends each response.
        flags: The TCP flags of each response, in the same order.
        window: The window field of every response.
        options: The option list of every response, in the form `scapy` accepts.
        ack_delta: The acknowledgment number minus the sequence number of the SYN.
        src_port: The source port of each response, or None for the scanned port.
    """

    offsets: list[float]
    flags: list[str] = field(default_factory=list)
    window: int = 64240
    options: list = field(default_factory=lambda: [("MSS", 1460)])
    ack_delta: int = 1
    src_port: int | None = None


def syn_ack_script(*offsets: float) -> Script:
    """Return a script of one SYN-ACK at each offset."""
    return Script(list(offsets), ["SA"] * len(offsets))


class FakeNetwork:
    """Holds a fake clock, the frames the loop sent and the frames the targets send back."""

    def __init__(self, scripts: dict[str, Script] | None = None, port: int = 80) -> None:
        self.now = 1_000_000.0
        self.scripts = scripts or {}
        self.port = port
        self.sent: list[tuple[str, int, int]] = []
        self.queue: list[tuple[float, int, bytes]] = []
        self.order = 0
        self.on_send = None
        self.closed = False

    def clock(self) -> float:
        return self.now

    def close(self) -> None:
        self.closed = True

    def send(self, target: str, src_port: int, sequence: int) -> str | None:
        if self.on_send is not None:
            self.on_send(target)
        self.sent.append((target, src_port, sequence))
        script = self.scripts.get(target)
        if script is not None:
            for offset, flags in zip(script.offsets, script.flags):
                tcp = TCP(
                    sport=script.src_port if script.src_port is not None else self.port,
                    dport=src_port,
                    seq=5000,
                    ack=(sequence + script.ack_delta) & 0xFFFFFFFF,
                    flags=flags,
                    window=script.window,
                    options=script.options if "S" in flags else [],
                )
                frame = bytes(Ether() / IP(src=target, dst=SCANNER_IP) / tcp)
                self.push(self.now + offset, frame)
        return SCANNER_IP

    def push(self, when: float, frame: bytes) -> None:
        heapq.heappush(self.queue, (when, self.order, frame))
        self.order += 1

    def receive(self, timeout: float) -> tuple[float, bytes] | None:
        if self.queue and self.queue[0][0] <= self.now + timeout:
            when, _, frame = heapq.heappop(self.queue)
            self.now = max(self.now, when)
            return when, frame
        self.now += timeout
        return None
