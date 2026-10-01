"""Send one SYN to each target, read the responses, and write one value for each target.

`docs/specs/features/12-active-scan.md` states the loop. The loop takes the send
function, the receive function and the clock as parameters, so a case runs it on a fake
network. `ja4plus/scan/link.py` supplies the real pair.

**The loop sends one SYN to each target and no other packet.** It never answers a
response. A target that retransmits its SYN-ACK therefore produces part e.
"""

from __future__ import annotations

import ipaddress
import logging
import random
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from ja4plus.fingerprinters.ja4ts import MAX_SYN_ACK_DELAYS, TCP_RST_FLAG, TCP_SYN_ACK_FLAGS
from ja4plus.scan.frames import Reply, parse_frame
from ja4plus.scan.value import Response, ja4tscan_value

__all__ = [
    "MAX_TARGETS",
    "NO_RETRANSMIT_WAIT_SECONDS",
    "RETRANSMIT_WAIT_SECONDS",
    "ScanResult",
    "Scanner",
    "TargetError",
    "firewall_rules",
    "parse_targets",
]

logger = logging.getLogger(__name__)

# S13 of `docs/specs/foxio/JA4TScan.md`: the wrapper passes a cooldown of 120 seconds, and
# the zmap default of 8 seconds applies when retransmissions are off.
RETRANSMIT_WAIT_SECONDS = 120.0
NO_RETRANSMIT_WAIT_SECONDS = 8.0

# FR-active-scan-18. S4 of `docs/specs/foxio/JA4TScan.md` records the same count for the
# FoxIO table, at `ja4tscan/module_ja4tscan.c:169`.
MAX_TARGETS = 10000

# RFC 6335 section 6 names 49152 to 65535 as the dynamic ports, so a source port in that
# range names no service of the scanning host.
SOURCE_PORT_LOW = 49152
SOURCE_PORT_HIGH = 65535

# A RST may acknowledge the sequence number itself or the sequence number plus one.
# `ja4tscan/module_ja4tscan.c:250-262` accepts both, and every other response needs the
# second.
SEQUENCE_SPACE = 1 << 32

TCP_ACK_FLAG = 0x10

# A target can send any segment with the acknowledgment number the SYN expects, so that
# number alone names no answer to the SYN. The mask covers FIN, SYN, RST, PSH, ACK and URG.
# It leaves out ECE and CWR, because RFC 3168 section 6.1.1 lets a SYN-ACK carry ECE.
SEGMENT_FLAG_MASK = 0x3F
# The loop reads a SYN-ACK, a RST, and a RST that carries ACK. Every other combination
# answers no SYN, and the loop drops it.
ANSWER_FLAGS = frozenset({TCP_SYN_ACK_FLAGS, TCP_RST_FLAG, TCP_RST_FLAG | TCP_ACK_FLAG})

SendFunction = Callable[[str, int, int], "str | None"]
ReceiveFunction = Callable[[float], "tuple[float, bytes] | None"]


class TargetError(ValueError):
    """The operator named a target the scanner cannot read."""


@dataclass
class Probe:
    """Holds one target from its SYN until its wait ends.

    Attributes:
        target: The IPv4 address of the target.
        src_port: The source port of the SYN.
        sequence: The sequence number of the SYN.
        sent_at: The clock time of the SYN.
        scanner_ip: The IPv4 address the SYN left from.
        responses: The responses the value reads. A bound keeps the list short.
        closed: True once a response ends the reading of the target.
    """

    target: str
    src_port: int
    sequence: int
    sent_at: float
    scanner_ip: str
    responses: list[Response] = field(default_factory=list)
    closed: bool = False


@dataclass(frozen=True)
class ScanResult:
    """Holds the value of one target and the endpoints of its responses.

    Attributes:
        value: The JA4TScan value.
        src_ip: The target, which sent the responses.
        src_port: The port the scanner sent to.
        dst_ip: The address of the scanning host.
        dst_port: The source port of the SYN.
        seconds: The receive time of the last response the value reads.
    """

    value: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    seconds: float


def _ipv4(text: str, where: str) -> str:
    """Return the IPv4 address in the text, or raise `TargetError`.

    Args:
        text: One address.
        where: The words that name the place of the text, for the message.
    """
    try:
        address = ipaddress.ip_address(text)
    except ValueError as error:
        raise TargetError(f"{where} holds no IPv4 address: {text!r}") from error
    if address.version != 4:
        raise TargetError(f"{where} holds {text}, and the scanner reads IPv4 alone")
    return str(address)


def parse_targets(text: str) -> Iterable[str]:
    """Return the IPv4 targets that one TARGET argument names.

    FR-active-scan-14 names three forms: one address, one network in CIDR form, or a file
    of one address on each line. A network names every address it holds, as zmap does.

    Args:
        text: The TARGET argument.

    Returns:
        The targets, in order. A file names each address once, whatever its line count.

    Raises:
        TargetError: The scanner reads every target before it sends a SYN, and it
            raises in three cases.

            - The argument names an IPv6 target.
            - A file line holds no IPv4 address.
            - The argument is no address, no network and no readable file.
    """
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        network = None
    if network is not None:
        if network.version != 4:
            raise TargetError(f"the target {text} is IPv6, and the scanner reads IPv4 alone")
        return _addresses(network)
    path = Path(text)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise TargetError(
            f"the target {text!r} is no IPv4 address, no IPv4 network and no readable file"
        ) from error
    targets: dict[str, None] = {}
    for number, line in enumerate(lines, start=1):
        line = line.strip()
        if line:
            targets[_ipv4(line, f"line {number} of {text}")] = None
    return list(targets)


def _addresses(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> Iterator[str]:
    """Yield every address of the network, so a large network needs no list in memory."""
    for address in network:
        yield str(address)


# The four rules of `ja4tscan/ja4tscan.py:15-18`, and the four removals of
# `ja4tscan/ja4tscan.py:22-25` in the order the wrapper runs them.
IPTABLES_RULES = (
    "iptables -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
    "iptables -t filter -A INPUT -p icmp -j ACCEPT",
    "iptables -t filter -A INPUT -i lo -j ACCEPT",
    "iptables -t filter -A INPUT -j DROP",
)
IPTABLES_REMOVALS = (
    "iptables -t filter -D INPUT -j DROP",
    "iptables -t filter -D INPUT -i lo -j ACCEPT",
    "iptables -t filter -D INPUT -p icmp -j ACCEPT",
    "iptables -t filter -D INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
)
# `docs/specs/features/12-active-scan.md` states the pf equivalent, one line for each
# rule above.
PF_RULES = (
    "pass out all",
    "pass in quick inet proto icmp all",
    "pass in quick on lo0 all",
    "block drop in all",
)

_RULE_PREAMBLE = (
    "ja4plus scan changes no firewall state. The kernel of this host answers each "
    "SYN-ACK with a RST, and the RST stops the retransmissions that part e reads.\n"
    "The last rule drops every other inbound packet until you remove it."
)


def firewall_rules(platform: str) -> str:
    """Return the firewall rules the operator adds before a scan, as lines of text.

    The maintainer ruled on 2026-09-30 that the library states the rules and never
    applies them. FR-active-scan-8 states when the scanner writes them.

    Args:
        platform: The value of `sys.platform` on this host.

    Returns:
        The iptables rules and their removals on Linux, and the pf rules elsewhere.
    """
    if platform.startswith("linux"):
        lines = [_RULE_PREAMBLE, "Add these rules before the scan:", *IPTABLES_RULES]
        lines += ["Remove them after the scan:", *IPTABLES_REMOVALS]
    else:
        lines = [_RULE_PREAMBLE, "Add these pf rules before the scan:", *PF_RULES]
        lines += ["Remove them after the scan."]
    return "\n".join(lines)


class Scanner:
    """Sends one SYN to each target and writes one result for each target that answers.

    `table` holds each target from its SYN until its wait ends, in send order. Its entry
    count holds at most `MAX_TARGETS`, and its entry age holds at most the wait. The
    loop sends no SYN while the table is full, so no target loses its wait.

    Args:
        port: The TCP port of every target.
        rate: The SYN count for each second.
        retransmit: True to read every retransmission for 120 seconds. False to read the
            first response alone for 8 seconds.
        send: The function that sends one SYN. It takes the target, the source port and
            the sequence number, and it returns the source address, or None when it sent
            nothing.
        receive: The function that waits at most the given seconds for one frame. It
            returns the receive time and the frame, or None.
        clock: The function that returns the time the wait reads, in seconds.
        on_result: The function that takes each result.
        on_warning: The function that takes each warning line.
        rng: The source of the source port and the sequence number.
    """

    def __init__(
        self,
        *,
        port: int,
        rate: float,
        retransmit: bool,
        send: SendFunction,
        receive: ReceiveFunction,
        clock: Callable[[], float],
        on_result: Callable[[ScanResult], None],
        on_warning: Callable[[str], None],
        rng: random.Random | None = None,
    ) -> None:
        self.port = port
        self.interval = 1.0 / rate
        self.retransmit = retransmit
        self.wait = RETRANSMIT_WAIT_SECONDS if retransmit else NO_RETRANSMIT_WAIT_SECONDS
        self.send = send
        self.receive = receive
        self.clock = clock
        self.on_result = on_result
        self.on_warning = on_warning
        self.rng = rng or random.SystemRandom()
        self.table: OrderedDict[str, Probe] = OrderedDict()

    def run(self, targets: Iterable[str]) -> None:
        """Send one SYN to each target, then wait until the wait of the last one ends.

        Args:
            targets: The IPv4 addresses, each one once.
        """
        next_send = self.clock()
        for target in targets:
            while len(self.table) >= MAX_TARGETS:
                oldest = next(iter(self.table.values()))
                self.receive_until(oldest.sent_at + self.wait)
            self.receive_until(next_send)
            self.start(target)
            next_send = max(next_send + self.interval, self.clock())
        while self.table:
            oldest = next(iter(self.table.values()))
            self.receive_until(oldest.sent_at + self.wait)

    def start(self, target: str) -> None:
        """Send the SYN to one target and add the target to the table.

        Args:
            target: The IPv4 address of the target.
        """
        src_port = self.rng.randint(SOURCE_PORT_LOW, SOURCE_PORT_HIGH)
        sequence = self.rng.getrandbits(32)
        scanner_ip = self.send(target, src_port, sequence)
        if scanner_ip is None:
            return
        self.table[target] = Probe(target, src_port, sequence, self.clock(), scanner_ip)

    def receive_until(self, deadline: float) -> None:
        """Read responses until the clock reaches the deadline, and end each expired wait.

        Args:
            deadline: The clock time at which the call returns.
        """
        while True:
            now = self.clock()
            self._expire(now)
            if now >= deadline:
                return
            received = self.receive(deadline - now)
            if received is not None:
                seconds, frame = received
                reply = parse_frame(frame)
                if reply is not None:
                    self._accept(seconds, reply)

    def flush(self) -> None:
        """End the wait of every target now, and write each result."""
        while self.table:
            _, probe = self.table.popitem(last=False)
            self._finish(probe)

    def _expire(self, now: float) -> None:
        """End the wait of each target whose wait ended at or before the clock time."""
        while self.table:
            oldest = next(iter(self.table.values()))
            if oldest.sent_at + self.wait > now:
                return
            del self.table[oldest.target]
            self._finish(oldest)

    def _accept(self, seconds: float, reply: Reply) -> None:
        """Store one reply where it answers the SYN of a target in the table.

        Args:
            seconds: The receive time of the reply.
            reply: The parsed fields of the reply.
        """
        probe = self.table.get(reply.src_ip)
        if probe is None or probe.closed:
            return
        if reply.src_port != self.port or reply.dst_port != probe.src_port:
            return
        if reply.flags & SEGMENT_FLAG_MASK not in ANSWER_FLAGS:
            return
        is_rst = bool(reply.flags & TCP_RST_FLAG)
        expected = {(probe.sequence + 1) % SEQUENCE_SPACE}
        if is_rst:
            expected.add(probe.sequence)
        if reply.acknowledgment not in expected:
            return
        response = Response(seconds, reply.flags, reply.window, reply.options)
        if is_rst:
            probe.responses.append(response)
            probe.closed = True
        # The first response and ten retransmissions fill part e, and R12 rule 4 of
        # `docs/specs/foxio/JA4T.md` counts no more. A target that floods therefore
        # grows no list.
        elif len(probe.responses) <= MAX_SYN_ACK_DELAYS:
            probe.responses.append(response)
        if not self.retransmit:
            probe.closed = True

    def _finish(self, probe: Probe) -> None:
        """Write the result of one target, and warn where the target never retransmitted.

        Args:
            probe: The target whose wait ended.
        """
        value = ja4tscan_value(probe.responses)
        if value is None:
            return
        self.on_result(
            ScanResult(
                value=value,
                src_ip=probe.target,
                src_port=self.port,
                dst_ip=probe.scanner_ip,
                dst_port=probe.src_port,
                seconds=probe.responses[-1].seconds,
            )
        )
        first = probe.responses[0]
        if self.retransmit and len(probe.responses) == 1 and not first.flags & TCP_RST_FLAG:
            self.on_warning(
                f"Warning: {probe.target} sent one SYN-ACK and no retransmission in "
                f"{int(self.wait)} seconds. The kernel of this host may have sent it a "
                "RST, so check the firewall rules above."
            )
