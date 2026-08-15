"""JA4L reads the header block terminator that `ja4plus.utils.http_utils` publishes.

The reference routes a packet that holds a whole HTTP request to a cache. That cache holds
no measurement point, so such a packet completes no client value. `ja4plus/utils/http_utils.py`
holds the one rule that reads the end of a header block. A second copy of that rule stood
inside the fingerprinter, and it declined the terminator `\\n\\r\\n`. A request that ends
its header block that way therefore completed a client value the reference does not
publish. #630 records the defect and `Crank-Git/ja4plus-go#685` records the Go half.

No FoxIO vector holds a mixed line ending, so each case here builds the packets.
"""

from scapy.all import IP, Raw, TCP

from ja4plus.fingerprinters.ja4l import JA4LFingerprinter, _holds_a_complete_http_request

CLIENT, SERVER = "1.1.1.1", "2.2.2.2"
CLIENT_PORT, SERVER_PORT = 50000, 80

# The head of the request every case sends. Each case appends one terminator and a body.
REQUEST_HEAD = b"GET / HTTP/1.1\r\nHost: example.com"

# The four terminators one line ending followed by another line ending builds. A line
# ending is the two bytes `\r\n`, or one line feed.
TERMINATORS = (b"\r\n\r\n", b"\n\n", b"\n\r\n", b"\r\n\n")


def _client(flags, sequence, acknowledgement, when, payload=b""):
    """Build one packet the client sends."""
    packet = (
        IP(src=CLIENT, dst=SERVER, ttl=128)
        / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags=flags, seq=sequence, ack=acknowledgement)
        / Raw(payload)
    )
    packet.time = when
    return packet


def _server(flags, sequence, acknowledgement, when, payload=b""):
    """Build one packet the server sends."""
    packet = (
        IP(src=SERVER, dst=CLIENT, ttl=64)
        / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags=flags, seq=sequence, ack=acknowledgement)
        / Raw(payload)
    )
    packet.time = when
    return packet


def _values(packets):
    """Return the values one packet list leaves in the fingerprinter."""
    fingerprinter = JA4LFingerprinter()
    for packet in packets:
        fingerprinter.process_packet(packet)
    return [entry["fingerprint"] for entry in fingerprinter.get_fingerprints()]


def _client_values(payload):
    """Return the client values a connection gives whose first payload packet is the request.

    Args:
        payload: The TCP payload of the packet the client sends after the handshake.

    Returns:
        The `JA4L-C` values in report order. The server value stands outside this
        reading, because the request packet moves the client point alone.
    """
    values = _values(
        [
            _client("S", 0, 0, 0.000),
            _server("SA", 0, 1, 0.001),
            _client("PA", 1, 1, 0.051, payload),
        ]
    )
    return [value for value in values if value.startswith("JA4L-C=")]


def test_the_gate_reads_a_request_that_ends_its_header_block_with_a_mixed_line_ending():
    """A header block that ends `\\n\\r\\n` reads as complete."""
    assert _holds_a_complete_http_request(REQUEST_HEAD + b"\n\r\n" + b"BODY") is True


def test_a_mixed_line_ending_request_completes_no_client_value():
    """A request whose header block ends `\\n\\r\\n` moves the client measurement point nowhere."""
    assert _client_values(REQUEST_HEAD + b"\n\r\n" + b"BODY") == []


def test_the_gate_reads_every_terminator_two_line_endings_build():
    """The gate reads each of the four terminators as a complete header block."""
    for terminator in TERMINATORS:
        assert _holds_a_complete_http_request(REQUEST_HEAD + terminator + b"BODY") is True


def test_no_terminator_two_line_endings_build_completes_a_client_value():
    """No request of the four terminators moves the client measurement point."""
    for terminator in TERMINATORS:
        assert _client_values(REQUEST_HEAD + terminator + b"BODY") == []


def test_a_request_that_holds_no_whole_header_block_moves_the_client_point():
    """A packet that holds the first part of a request completes a client value."""
    assert _client_values(REQUEST_HEAD + b"\r\nAccept: */*\r\n") == ["JA4L-C=25000_128"]


def test_a_payload_that_starts_no_request_moves_the_client_point():
    """A payload that starts no HTTP request completes a client value, terminator or not."""
    assert _client_values(b"\x16\x03\x01\x00\x05\n\r\n") == ["JA4L-C=25000_128"]


def test_the_fingerprinter_holds_no_second_copy_of_the_terminator_rule():
    """The JA4L module names no header block terminator of its own."""
    from pathlib import Path

    import ja4plus.fingerprinters.ja4l as ja4l_module

    source = Path(ja4l_module.__file__).read_text(encoding="utf-8")
    assert '"\\r\\n\\r\\n"' not in source
    assert '"\\n\\n"' not in source
