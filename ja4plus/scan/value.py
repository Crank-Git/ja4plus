"""Turn the responses of one target into a JA4TScan value.

The maintainer ruled the form on 2026-09-30, at
https://github.com/Crank-Git/ja4plus/issues/775#issuecomment-5921253786. Part a to part d
are the JA4TS parts of the first response. A scan value and the passive JA4TS value of the
same SYN-ACK therefore hold the same four parts. Part e follows the JA4TS delay rule, R12
and R13 of `docs/specs/foxio/JA4T.md`.

This module reads no packet. The scanner parses each packet into a `Response` first, so
every value here comes from a field that a bounded parser already read.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

# The ruling of 2026-09-30 names the JA4TS delay rule for part e. The scanner imports the
# one function that states it, so a repair of that rule reaches both methods.
from ja4plus.fingerprinters.ja4ts import MAX_SYN_ACK_DELAYS, TCP_RST_FLAG
from ja4plus.fingerprinters.ja4ts import _delay_seconds as delay_seconds
from ja4plus.utils.tcp_options import tcp_prefix_from_fields

__all__ = ["RST_ACK_VALUE", "Response", "ja4tscan_value"]

# The FoxIO wrapper publishes this value for a target whose first response carries RST,
# at `ja4tscan/ja4tscan.py:44-45`. The maintainer ruled it for every such target.
RST_ACK_VALUE = "0_rst-ack"


@dataclass(frozen=True)
class Response:
    """Holds the four fields of one TCP response that the value reads.

    Attributes:
        seconds: The receive time, in seconds.
        flags: The TCP flags byte.
        window: The window field of the TCP header.
        options: The raw TCP option bytes.
    """

    seconds: float
    flags: int
    window: int
    options: bytes


def ja4tscan_value(responses: Sequence[Response]) -> str | None:
    """Return the JA4TScan value of one target.

    Args:
        responses: The responses of the target that answer the SYN, in arrival order.

    Returns:
        The value, or None when the target sent no response. A first response that
        carries RST produces `0_rst-ack`. A first response of any other kind sets part a
        to part d, and each later response adds one delay to part e.
    """
    if not responses:
        return None
    first = responses[0]
    if first.flags & TCP_RST_FLAG:
        return RST_ACK_VALUE
    prefix = tcp_prefix_from_fields(first.window, first.options)
    delays: list[str] = []
    previous = first.seconds
    for response in responses[1:]:
        delay = delay_seconds(response.seconds, previous)
        # R13 of `docs/specs/foxio/JA4T.md` reads the RST as the final packet, so a
        # response after it adds nothing. R13 rule 2 writes no reset letter where no
        # retransmission came before the RST.
        if response.flags & TCP_RST_FLAG:
            if delays:
                delays.append(f"R{delay}")
            break
        # R12 rule 4 counts ten retransmissions. A later one adds no delay, and a RST
        # after it still counts from the tenth.
        if len(delays) < MAX_SYN_ACK_DELAYS:
            delays.append(str(delay))
            previous = response.seconds
    if not delays:
        return prefix
    return f"{prefix}_{'-'.join(delays)}"
