"""Send each SYN as a link-layer frame, and read each response from the same interface.

FR-active-scan-25 states that the scanner sends the SYN as a link-layer frame, as zmap
does. #776 measured the reason on 2026-09-30, on Linux 6.11 with iptables 1.8.10 and
the four FoxIO rules. A SYN from a raw IP socket passed the connection tracker. The
first rule then accepted the SYN-ACK, and the kernel sent a RST. A SYN from an
`AF_PACKET` socket left no tracker state, so the last rule dropped the SYN-ACK and the
target retransmitted it three times in eight seconds.

This module is the one place in `ja4plus` that opens a socket to send. It needs the
privilege to open a raw socket, and no case of the suite opens one.

Verified against `scapy` 2.7.0: `conf.L2socket`, `SuperSocket.select`,
`SuperSocket.recv_raw`, `conf.route.route` and `getmacbyip` in `scapy/layers/l2.py`,
read on 2026-09-30.
"""

from __future__ import annotations

import errno
import logging
import time
from collections.abc import Callable
from typing import Any

from scapy.all import conf, get_if_hwaddr, getmacbyip
from scapy.error import Scapy_Exception

from ja4plus.scan.frames import build_syn

__all__ = ["LinkNetwork", "privilege_refused"]

logger = logging.getLogger(__name__)

# Linux returns `EPERM` from the `AF_PACKET` socket call, and macOS returns `EACCES` from
# the `/dev/bpf` open. `ja4plus/watch.py` reads the same two numbers and the same text.
_PRIVILEGE_ERRNOS = frozenset({errno.EPERM, errno.EACCES})
_PRIVILEGE_TEXT = "permission denied"

# `conf.route.route` names no gateway with this address when the target is on the link.
_NO_GATEWAY = "0.0.0.0"


def privilege_refused(error: BaseException) -> bool:
    """Return True when the error states that the host refused the raw-socket privilege.

    Args:
        error: The failure that the socket layer raised.
    """
    number = error.errno if isinstance(error, OSError) else None
    return number in _PRIVILEGE_ERRNOS or _PRIVILEGE_TEXT in str(error).lower()


def _mac_bytes(text: str) -> bytes:
    """Return the six bytes of a link-layer address written as `aa:bb:cc:dd:ee:ff`."""
    return bytes.fromhex(text.replace(":", ""))


class LinkNetwork:
    """Holds one link-layer socket on the interface that routes to the first target.

    Args:
        port: The TCP port of every target. The capture filter reads it.
        first_target: The first target. Its route names the interface.
        on_warning: The function that takes each warning line.

    Raises:
        OSError: The host refused the socket. `privilege_refused` reads the cause.
        Scapy_Exception: The host refused the `/dev/bpf` device.
    """

    def __init__(self, port: int, first_target: str, on_warning: Callable[[str], None]) -> None:
        self.port = port
        self.iface: str = conf.route.route(first_target)[0]
        self.on_warning = on_warning
        self.socket: Any = self._open()
        self.mac = _mac_bytes(get_if_hwaddr(self.iface))
        self.next_hops: dict[str, bytes | None] = {}

    def _open(self) -> Any:
        """Return a link-layer socket that reads the responses of the scanned port.

        A capture filter needs `libpcap` or `tcpdump`. Where the host holds neither, the
        socket reads every frame, and the parser drops each one that answers no SYN.
        """
        try:
            return conf.L2socket(iface=self.iface, filter=f"tcp and src port {self.port}")
        except Scapy_Exception as error:
            if privilege_refused(error):
                raise
            logger.debug("The capture filter failed, so the socket reads every frame: %s", error)
            return conf.L2socket(iface=self.iface)

    def send(self, target: str, src_port: int, sequence: int) -> str | None:
        """Send one SYN frame to the target.

        Args:
            target: The IPv4 address of the target.
            src_port: The TCP source port.
            sequence: The TCP sequence number.

        Returns:
            The source address of the SYN, or None when the call sent nothing. A target
            that routes through another interface or through the loopback interface
            gets no SYN, and so does a target whose next hop names no link-layer address.
        """
        iface, src_ip, gateway = conf.route.route(target)
        if iface == conf.loopback_name:
            # The loopback interface of macOS carries no Ethernet header, so an Ethernet
            # frame there reaches no stack.
            self.on_warning(
                f"Warning: {target} routes through the loopback interface. The scan sends "
                "it no SYN."
            )
            return None
        if iface != self.iface:
            self.on_warning(
                f"Warning: {target} routes through the interface {iface}, and the scan "
                f"sends through {self.iface}. The scan sends it no SYN."
            )
            return None
        hop = target if gateway == _NO_GATEWAY else gateway
        if hop not in self.next_hops:
            mac = getmacbyip(hop)
            self.next_hops[hop] = _mac_bytes(mac) if mac else None
        dst_mac = self.next_hops[hop]
        if dst_mac is None:
            self.on_warning(
                f"Warning: the next hop {hop} of {target} answered no address request. "
                "The scan sends it no SYN."
            )
            return None
        frame = build_syn(
            src_mac=self.mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=target,
            src_port=src_port,
            dst_port=self.port,
            sequence=sequence,
            timestamp=int(time.time()),
        )
        self.socket.send(frame)
        return str(src_ip)

    def receive(self, timeout: float) -> tuple[float, bytes] | None:
        """Wait at most the given seconds for one frame.

        Args:
            timeout: The longest wait, in seconds.

        Returns:
            The receive time and the frame, or None when no frame arrived.
        """
        if not self.socket.select([self.socket], timeout):
            return None
        _, data, seconds = self.socket.recv_raw()
        if data is None:
            return None
        return (seconds if seconds is not None else time.time()), bytes(data)

    def close(self) -> None:
        """Close the socket."""
        self.socket.close()
