"""The scapy tunnel dissectors this project needs, and the reader of an inner layer.

`scapy.all` binds the common protocols, and it leaves Geneve, VXLAN and ERSPAN to a
separate import. Without that import scapy stops at the tunnel header, so a
fingerprinter reads no TCP layer and emits nothing for a mirrored capture.
`tcpdump-geneve.pcap` and `gre-erspan-vxlan.pcap` are two such vectors.

A scapy dissector binds itself to a port or a protocol number at import time, so one
import of this module changes what every fingerprinter sees. `ja4plus/__init__.py`
imports it once.

An older scapy release ships no `erspan` module, so a missing module is not a defect
here. The fingerprinter then reads no value for that capture, which is the same
result as before the import.
"""

# This import makes every annotation a string. No annotation therefore evaluates at
# import time, and a forward reference needs no quotation mark.
from __future__ import annotations

import logging

from scapy.packet import NoPayload, Packet

logger = logging.getLogger(__name__)

TUNNEL_MODULES = ("scapy.contrib.geneve", "scapy.layers.vxlan", "scapy.contrib.erspan")


def register_tunnel_dissectors() -> tuple[str, ...]:
    """Import every tunnel dissector and return the names that loaded.

    Returns:
        The tuple of module names scapy now holds. A module the installed scapy does
        not ship is absent from the tuple.
    """
    import importlib

    loaded: list[str] = []
    for name in TUNNEL_MODULES:
        try:
            importlib.import_module(name)
        except ImportError as error:
            logger.debug("scapy ships no %s: %s", name, error)
            continue
        loaded.append(name)
    return tuple(loaded)


def innermost_layer(packet: Packet, layer_classes: tuple[type[Packet], ...]) -> Packet | None:
    """Return the deepest layer of one packet that has one of the classes, or None.

    A tunnel carries a second address layer and a second port layer inside the first
    one. A mirror sends both directions of one session from one outer address to one
    other outer address, so only the inner layer separates the two directions.

    Args:
        packet: A network packet.
        layer_classes: A tuple of scapy layer classes to look for.

    Returns:
        The deepest layer with one of the classes, or None when the packet holds none.
    """
    found = None
    layer = packet
    while not isinstance(layer, NoPayload):
        if isinstance(layer, layer_classes):
            found = layer
        layer = layer.payload
    return found
