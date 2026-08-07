"""Registration of the scapy tunnel dissectors this project needs.

`scapy.all` binds the common protocols, and it leaves Geneve, VXLAN and ERSPAN to a
separate import. Without that import scapy stops at the tunnel header, so a
fingerprinter reads no TCP layer and produces nothing for a mirrored capture.
`tcpdump-geneve.pcap` and `gre-erspan-vxlan.pcap` are two such vectors.

A scapy dissector binds itself to a port or a protocol number at import time, so one
import of this module changes what every fingerprinter sees. `ja4plus/__init__.py`
imports it once.

An older scapy release ships no `erspan` module, so a missing module is not a defect
here. The fingerprinter then reads no value for that capture, which is the same
result as before the import.
"""

import logging

logger = logging.getLogger(__name__)

TUNNEL_MODULES = ("scapy.contrib.geneve", "scapy.layers.vxlan", "scapy.contrib.erspan")


def register_tunnel_dissectors():
    """Import every tunnel dissector and return the names that loaded.

    Returns:
        The tuple of module names scapy now holds. A module the installed scapy does
        not ship is absent from the tuple.
    """
    import importlib

    loaded = []
    for name in TUNNEL_MODULES:
        try:
            importlib.import_module(name)
        except ImportError as error:
            logger.debug("scapy ships no %s: %s", name, error)
            continue
        loaded.append(name)
    return tuple(loaded)
