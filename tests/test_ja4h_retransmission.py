"""JA4H tests for a request the sender transmits more than once.

`technical_details/JA4H.md` states that JA4H fingerprints the HTTP client "based on each
HTTP request". A retransmitted TCP segment carries no new request, so it produces no
second value. `tests/foxio_vectors/CVE-2018-6794.pcap` holds two streams, and the sender
repeats each request six times. The FoxIO expected-output file holds one value on each
stream, and this project produced six. #193 records the defect.
"""

from pathlib import Path

import pytest
from scapy.all import IP, TCP, Raw, rdpcap

from ja4plus.fingerprinters.ja4h import JA4HFingerprinter

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"

# The values `tests/foxio_vectors/CVE-2018-6794.pcap.json` holds, keyed by client port.
EXPECTED = {
    53649: (
        "ge11nn07ruru_6cd0fb54989b_000000000000_000000000000",
        "ge11nn07ruru_Host,Connection,User-Agent,Upgrade-Insecure-Requests,Accept,"
        "Accept-Encoding,Accept-Language_",
    ),
    53656: (
        "ge11nr06ruru_cc6ec9a91856_000000000000_000000000000",
        "ge11nr06ruru_Host,Connection,User-Agent,Accept,Accept-Encoding,Accept-Language_",
    ),
}


@pytest.fixture(scope="module")
def cve_results():
    """Return the JA4H entries `CVE-2018-6794.pcap` produces, grouped by client port."""
    fingerprinter = JA4HFingerprinter()
    for packet in rdpcap(str(VECTORS_DIR / "CVE-2018-6794.pcap")):
        fingerprinter.process_packet(packet)
    grouped = {}
    for entry in fingerprinter.get_fingerprints():
        grouped.setdefault(entry["srcport"], []).append(entry)
    return grouped


def test_a_retransmitted_request_produces_one_value_on_each_stream(cve_results):
    assert {port: len(entries) for port, entries in cve_results.items()} == {
        53649: 1,
        53656: 1,
    }


@pytest.mark.parametrize("port", sorted(EXPECTED))
def test_the_one_value_on_each_stream_equals_the_reference(cve_results, port):
    fingerprint, raw_original_order = EXPECTED[port]
    entry = cve_results[port][0]
    assert entry["fingerprint"] == fingerprint
    assert entry["raw_original_order"] == raw_original_order


def _request(path):
    """Return one HTTP request as bytes.

    Args:
        path: The request target.

    Returns:
        The request bytes, header block included.
    """
    return "GET {} HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n".format(path).encode()


def _segment(seq, payload):
    """Return one TCP segment of the client direction.

    Args:
        seq: The sequence number of the first payload byte.
        payload: The payload bytes.

    Returns:
        A scapy packet.
    """
    return (
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=seq) / Raw(load=payload)
    )


def test_a_second_request_on_one_connection_still_produces_a_second_value():
    """A pipelined request sits above the consumed sequence range, so it still counts."""
    fingerprinter = JA4HFingerprinter()
    first = _request("/one")
    second = _request("/two")
    fingerprinter.process_packet(_segment(100, first))
    fingerprinter.process_packet(_segment(100 + len(first), second))
    assert len(fingerprinter.get_fingerprints()) == 2


def test_a_repeated_segment_produces_no_second_value():
    """The same segment twice carries one request, so the second copy produces nothing."""
    fingerprinter = JA4HFingerprinter()
    payload = _request("/one")
    fingerprinter.process_packet(_segment(100, payload))
    assert fingerprinter.process_packet(_segment(100, payload)) is None
    assert len(fingerprinter.get_fingerprints()) == 1


@pytest.mark.parametrize(
    "first_sequence,second_sequence",
    [(2000000000, 1000000000), (1000, 500), (3000000000, 2000000000)],
)
def test_a_new_connection_on_one_address_pair_still_produces_a_value(
    first_sequence, second_sequence
):
    """A second connection carries its own initial sequence number.

    That number sits below the stored one about half the time, and the guard must not
    read the first request of the second connection as a retransmission.
    """
    fingerprinter = JA4HFingerprinter()
    payload = _request("/one")
    fingerprinter.process_packet(_segment(first_sequence, payload))
    fingerprinter.process_packet(_segment(second_sequence, payload))
    assert len(fingerprinter.get_fingerprints()) == 2


def test_the_consumed_request_table_stays_inside_the_stream_cap():
    """`CLAUDE.md` states that every state table holds a maximum entry count."""
    fingerprinter = JA4HFingerprinter()
    payload = _request("/one")
    for port in range(1024, 1024 + 300):
        packet = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=port, dport=80, seq=100)
            / Raw(load=payload)
        )
        fingerprinter.process_packet(packet)
    assert len(fingerprinter.consumed_seq) <= fingerprinter.reassembler.max_streams


def test_a_consumed_request_leaves_the_table_after_the_maximum_stream_age():
    """`CLAUDE.md` states that every state table holds a maximum age.

    The age reads the packet timestamp, because a capture file replays faster than real
    time.
    """
    # A capture time from 2001, far from the wall clock.
    capture_time = 1000000000.0
    fingerprinter = JA4HFingerprinter()
    first = _segment(100, _request("/one"))
    first.time = capture_time
    fingerprinter.process_packet(first)
    assert "10.0.0.1:12345-10.0.0.2:80" in fingerprinter.consumed_seq

    later = _segment(100, _request("/one"))
    later.time = capture_time + fingerprinter.reassembler.max_stream_age + 1
    fingerprinter.process_packet(later)
    assert len(fingerprinter.get_fingerprints()) == 2
