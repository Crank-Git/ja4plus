"""Group JA4+ fingerprints by stream, method and occurrence.

The FoxIO expected-output file is a JSON array. Each element describes one event on
one stream. A key is a method name, and an optional occurrence counter follows a dot.
`JA4SSH.1` is the first JA4SSH fingerprint on the stream, and `JA4SSH.2` is the second.
A key without a counter, such as `JA4H`, holds one occurrence, and the reference writes
one such element for each occurrence.

This module reads that file into a map of stream to method to occurrence, and it builds
the same shape from the fingerprints ja4plus produces. The conformance suite then
compares one method on one stream at a time.

A stream identity holds the address pair and the port pair, and it ignores the
direction. The reference records the client direction and the server direction under
one stream index, so a direction-sensitive identity would split one stream into two.

A produced value reaches the index under the method the reference names. The JA4L
fingerprinter writes its method name into the value, as `JA4L-S=21105_64`, and
`method_and_value` reads the method name and returns the value alone.

A raw key, such as `JA4_r`, names its own method. The index holds it beside the hashed
form, and the suite compares it the same way. A raw form exists so that a person can
read what produced a hash, and a raw form no case reads is a value this project never
compares.
"""

import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

# The raw keys the reference publishes, per fingerprinter. Each pair names the reference
# method and the key of the produced entry that holds the value. A raw form no case reads
# is a value this project never compares, so the index carries these beside the hashed
# form. `JA4_o` holds a hash of the original-order fields rather than a raw form, and the
# reference publishes it beside `JA4_ro`, so the index treats the two the same way.
#
# JA4H names only `JA4H_ro`, because the reference publishes no `JA4H_r` key.
RAW_METHODS = {
    "JA4": (
        ("JA4_r", "raw"),
        ("JA4_ro", "raw_original_order"),
        ("JA4_o", "fingerprint_original_order"),
    ),
    "JA4S": (("JA4S_r", "raw"),),
    "JA4H": (("JA4H_ro", "raw_original_order"),),
}

# The methods the conformance suite reports. One fingerprinter produces one method,
# except JA4L: the JA4L fingerprinter produces both JA4L-C and JA4L-S, and the prefix of
# the produced value names which one.
FINGERPRINTER_METHODS = ("JA4", "JA4S", "JA4H", "JA4X", "JA4SSH", "JA4L-C", "JA4L-S")

# The protocol names a JA4L connection key starts with.
CONNECTION_PROTOCOLS = ("tcp", "udp")


class ReferenceStream:
    """One stream of a FoxIO expected-output file.

    Attributes:
        identity: The direction-free stream identity.
        index: The stream index the reference gives.
        label: A one-line description that names the index and both endpoints.
        src_port: The source port of the first record on the stream.
        methods: A map of method name to a map of occurrence number to value.
    """

    def __init__(self, identity, index, label, src_port, methods):
        self.identity = identity
        self.index = index
        self.label = label
        self.src_port = src_port
        self.methods = methods

    def __repr__(self):
        return "ReferenceStream({!r})".format(self.label)


def stream_identity(src, src_port, dst, dst_port):
    """Return the direction-free identity of one stream.

    Args:
        src: The source address.
        src_port: The source port, as a string or an integer.
        dst: The destination address.
        dst_port: The destination port, as a string or an integer.

    Returns:
        A sorted pair of (address, port) pairs. The identity of one direction equals
        the identity of the other direction.
    """
    endpoints = ((str(src), str(src_port)), (str(dst), str(dst_port)))
    return tuple(sorted(endpoints))


def method_and_occurrence(key):
    """Return the method name and the occurrence number of a reference key.

    Args:
        key: A key of one expected-output record, such as `JA4SSH.2` or `JA4H`.

    Returns:
        A (method, occurrence) pair. The occurrence is None when the key carries no
        counter. A raw key, such as `JA4_r`, gives its own method name. Returns None
        when the key names no method.
    """
    head, _, tail = key.rpartition(".")
    if head and tail.isdigit():
        method, occurrence = head, int(tail)
    else:
        method, occurrence = key, None
    if not method.startswith("JA4"):
        return None
    return method, occurrence


def method_and_value(fingerprinter, fingerprint):
    """Return the method name and the value of one produced fingerprint.

    The JA4L fingerprinter writes the method name into the value, as `JA4L-S=21105_64`.
    The reference holds the value alone, so the comparison needs the value alone.

    Args:
        fingerprinter: The name of the fingerprinter that produced the value.
        fingerprint: The value the fingerprinter produced.

    Returns:
        A (method, value) pair. The method is the prefix when the value carries one,
        and the name of the fingerprinter when it does not.
    """
    prefix, separator, value = fingerprint.partition("=")
    if separator and prefix.startswith("JA4"):
        return prefix, value
    return fingerprinter, fingerprint


def index_expected(records):
    """Return the streams of one FoxIO expected-output file.

    Args:
        records: The expected-output records, as read from the JSON file.

    Returns:
        A map of stream identity to ReferenceStream.
    """
    streams = {}
    for record in records:
        identity = stream_identity(
            record["src"], record["srcport"], record["dst"], record["dstport"]
        )
        stream = streams.get(identity)
        if stream is None:
            stream = ReferenceStream(
                identity=identity,
                index=record.get("stream", "?"),
                label="stream={} {}:{} -> {}:{}".format(
                    record.get("stream", "?"),
                    record["src"],
                    record["srcport"],
                    record["dst"],
                    record["dstport"],
                ),
                src_port=str(record["srcport"]),
                methods={},
            )
            streams[identity] = stream
        for key, value in record.items():
            parsed = method_and_occurrence(key)
            if parsed is None:
                continue
            method, occurrence = parsed
            occurrences = stream.methods.setdefault(method, {})
            if occurrence is None:
                # A key without a counter holds one occurrence. The reference writes
                # one record for each occurrence, so record order gives the number.
                occurrence = len(occurrences) + 1
            occurrences[occurrence] = value
    return streams


@lru_cache(maxsize=None)
def index_produced(pcap_path):
    """Return the fingerprints ja4plus produces for one capture, grouped by stream.

    The result is cached on the capture path, because one capture carries many test
    cases and a capture is read once for all of them. Do not change the result.

    Args:
        pcap_path: The path of the capture file.

    Returns:
        A map of stream identity to a map of method name to a tuple of values. The
        tuple holds the values in the order the fingerprinter produced them. The map
        holds one name for each raw key `RAW_METHODS` names. A fingerprint whose stream
        the suite cannot identify is held under the identity None.
    """
    from scapy.all import rdpcap

    from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
    from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
    from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
    from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
    from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter
    from ja4plus.fingerprinters.ja4t import JA4TFingerprinter
    from ja4plus.fingerprinters.ja4x import JA4XFingerprinter

    # The FoxIO Python expected-output file holds no JA4T value, so no case of
    # `tests/test_spec_validation.py` reads this name. `tests/test_foxio_rust_parity.py`
    # reads it, because the FoxIO Rust snapshot holds 38 JA4T values.
    fingerprinters = {
        "JA4": JA4Fingerprinter(),
        "JA4S": JA4SFingerprinter(),
        "JA4H": JA4HFingerprinter(),
        "JA4X": JA4XFingerprinter(),
        "JA4SSH": JA4SSHFingerprinter(),
        "JA4L": JA4LFingerprinter(),
        "JA4T": JA4TFingerprinter(),
    }

    for packet in rdpcap(str(pcap_path)):
        for name, fingerprinter in fingerprinters.items():
            try:
                fingerprinter.process_packet(packet)
            except Exception as error:  # noqa: BLE001 - a parser crash is a finding
                logger.debug("%s raised on a packet of %s: %s", name, pcap_path.name, error)

    produced = {}
    for name, fingerprinter in fingerprinters.items():
        for entry in fingerprinter.get_fingerprints():
            identity = _entry_identity(entry)
            method, value = method_and_value(name, entry["fingerprint"])
            methods = produced.setdefault(identity, {})
            methods.setdefault(method, []).append(value)
            for raw_method, entry_key in RAW_METHODS.get(name, ()):
                raw_value = entry.get(entry_key)
                if raw_value is not None:
                    methods.setdefault(raw_method, []).append(raw_value)

    return {
        identity: {name: tuple(values) for name, values in methods.items()}
        for identity, methods in produced.items()
    }


def _entry_identity(entry):
    """Return the stream identity of one fingerprint entry, or None.

    A stateless fingerprinter holds the endpoints of the packet that produced the
    value. JA4SSH holds the connection key of the window instead.
    """
    connection = entry.get("connection")
    if connection:
        return _connection_identity(connection)
    if entry.get("src") is not None and entry.get("srcport") is not None:
        return stream_identity(entry["src"], entry["srcport"], entry["dst"], entry["dstport"])
    return None


def _connection_identity(connection):
    """Return the stream identity of a connection key, or None.

    Two fingerprinters write a connection key, and the two forms differ. JA4SSH writes
    `<address>:<port>-<address>:<port>`, and an IPv6 address holds a colon and no
    hyphen, so the hyphen separates the two endpoints. JA4L writes
    `<protocol>_<address>:<port>_<address>:<port>`, and no address holds an underscore,
    so the underscore separates the protocol name and the two endpoints.
    """
    protocol, separator, endpoints = connection.partition("_")
    if separator and protocol in CONNECTION_PROTOCOLS:
        client, separator, server = endpoints.partition("_")
    else:
        client, separator, server = connection.partition("-")
    if not separator:
        return None
    client_host, _, client_port = client.rpartition(":")
    server_host, _, server_port = server.rpartition(":")
    if not client_host or not server_host:
        return None
    return stream_identity(client_host, client_port, server_host, server_port)
