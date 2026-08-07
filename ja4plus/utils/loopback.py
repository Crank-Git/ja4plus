"""Bind every BSD address family value of a loopback frame to the IPv6 layer.

A capture whose link type is `DLT_NULL` starts each frame with a four-byte address
family value. libpcap writes the value of the host that captured the frame. The value
of `AF_INET6` is 24 on NetBSD and OpenBSD, 28 on FreeBSD, and 30 on Darwin.

scapy binds one of those values, `socket.AF_INET6`. That value is 30 on Darwin and 10
on Linux, and no capture holds 10. A loopback capture that carries IPv6 therefore
dissects on Darwin and returns raw bytes on Linux, and the same capture then produces a
different set of fingerprints on each host.

Verified against:
https://github.com/the-tcpdump-group/libpcap/blob/f98637ad7f086a34c4027339c9639ae1ef842df3/gencode.c#L3333-L3354
(retrieved 2026-08-06).
"""

import logging

logger = logging.getLogger(__name__)

# The address family value each BSD family writes into a `DLT_NULL` frame. scapy names
# all three as IPv6 in `LOOPBACK_TYPES`, and binds only the value of the reading host.
BSD_AF_INET6_VALUES = (0x18, 0x1C, 0x1E)

# A second bind appends a second entry to the scapy dissection table. The entry is
# harmless and it is also waste, so the module binds once.
_bound = False


def bind_loopback_ipv6():
    """Bind the BSD address family values of a loopback frame to the IPv6 layer.

    The bind reaches the dissection path alone. A caller that builds a loopback frame
    keeps the scapy default, so this call changes no packet this library writes.

    Returns:
        None.
    """
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Loopback
    from scapy.packet import bind_bottom_up

    global _bound
    if _bound:
        return
    for family_value in BSD_AF_INET6_VALUES:
        bind_bottom_up(Loopback, IPv6, type=family_value)
    _bound = True
    logger.debug("bound the BSD AF_INET6 values %s to IPv6", BSD_AF_INET6_VALUES)
