"""The JA4L return path reports more client values than the stored list holds.

`process_packet` returns a client value for every packet that moves the client
measurement point. The stored list holds one client value for one connection, because
a later point replaces the value the fingerprinter already stored. The reference reports
one client value for one connection. The stored list is therefore correct, and the
return path reports the same value more than once.

`tests/conformance_index.py` reads the stored list, so the conformance suite measures
the correct value. No case there reads the return value of `process_packet`, and the
divergence is therefore a comparison that never runs. This module runs it.

#156 measured three candidate end-of-connection points that would close the gap. A FIN
or a RST reports 26 of the 60 client values, because 34 connections never close inside
their capture. Only a read of the stored list at the end of a capture reports all 60,
and that is not a `process_packet` return. The user chose to record the divergence and
to leave the return path as it is. `docs/specs/spec.md` holds the register row.

These cases hold both counts, so they fail when either one moves.
"""

from functools import lru_cache
from pathlib import Path

import pytest
from scapy.all import rdpcap

from ja4plus.fingerprinters.ja4l import JA4LFingerprinter

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"

# The client value counts of every committed vector that produces one, as
# (returned, stored). `returned` counts the packets for which `process_packet` returns a
# client value. `stored` counts the entries the fingerprinter holds when the capture
# ends. A capture whose two counts are equal holds one client measurement point per
# connection, and no packet moves it.
CLIENT_VALUE_COUNTS = {
    "CVE-2018-6794.pcap": (3, 3),
    "badcurveball.pcap": (2, 1),
    "browsers-x509.pcapng": (6, 3),
    "chrome-cloudflare-quic-with-secrets.pcapng": (3, 2),
    "gre-erspan-vxlan.pcap": (1, 1),
    "gre-sample.pcap": (2, 1),
    "http-empty-useragent.pcap": (3, 1),
    "http1-with-cookies.pcapng": (2, 1),
    "http2-with-cookies.pcapng": (2, 1),
    "https-connect.pcap": (1, 1),
    "https3-301-get.pcap": (2, 1),
    "ipv6.pcapng": (2, 1),
    "latest.pcapng": (11, 6),
    "macos_tcp_flags.pcap": (2, 1),
    "socks-https-example.pcap": (6, 3),
    "socks4-https.pcap": (2, 1),
    "ssh-r.pcap": (6, 3),
    "ssh-scp-1050.pcap": (2, 1),
    "ssh2-malformed.pcap": (2, 1),
    "ssh2-moloch-crash.pcap": (2, 1),
    "ssh2.pcapng": (15, 9),
    "sshv1.pcap": (2, 1),
    "tcpdump-geneve.pcap": (2, 1),
    "tls-alpn-h2.pcap": (2, 1),
    "tls3.pcapng": (20, 13),
    "v6.pcap": (2, 1),
}

# The totals of the table above. The reference reports one client value for one
# connection, so 60 is the count that matches the reference and 105 is the divergence.
RETURNED_TOTAL = 105
STORED_TOTAL = 60


@lru_cache(maxsize=None)
def client_value_counts(capture_name):
    """Return the client value counts of one capture, as (returned, stored).

    The result is cached on the capture name, because two cases read one capture. Do
    not change the result.

    Args:
        capture_name: The file name of a capture under `tests/foxio_vectors`.

    Returns:
        A (returned, stored) pair. `returned` counts the packets for which
        `process_packet` returns a `JA4L-C=` value. `stored` counts the `JA4L-C=`
        entries the fingerprinter holds when the capture ends.
    """
    fingerprinter = JA4LFingerprinter()
    returned = 0
    for packet in rdpcap(str(VECTORS_DIR / capture_name)):
        value = fingerprinter.process_packet(packet)
        if value and value.startswith("JA4L-C="):
            returned += 1
    stored = sum(
        1
        for entry in fingerprinter.get_fingerprints()
        if entry["fingerprint"].startswith("JA4L-C=")
    )
    return returned, stored


@pytest.mark.skipif(
    not (VECTORS_DIR / "badcurveball.pcap").exists(), reason="FoxIO vectors are absent"
)
class TestTheJA4LReturnPathAgainstTheStoredList:
    """Measure the client values the return path reports against the stored list."""

    @pytest.mark.parametrize("capture_name", sorted(CLIENT_VALUE_COUNTS))
    def test_one_capture_reports_the_counts_the_register_row_holds(self, capture_name):
        # A move in either count changes the divergence `docs/specs/spec.md` records,
        # so it needs a new measurement and a new register row.
        assert client_value_counts(capture_name) == CLIENT_VALUE_COUNTS[capture_name]

    def test_the_return_path_reports_more_client_values_than_the_stored_list(self):
        # The counts of #156. The return path reports 105 client values and the stored
        # list holds 60, across the committed vectors.
        returned = sum(client_value_counts(name)[0] for name in CLIENT_VALUE_COUNTS)
        stored = sum(client_value_counts(name)[1] for name in CLIENT_VALUE_COUNTS)
        assert (returned, stored) == (RETURNED_TOTAL, STORED_TOTAL)

    def test_the_return_path_never_reports_fewer_values_than_the_stored_list(self):
        # The return path reports a value each time the client point moves, so it
        # reports the stored value at least once for every connection. A capture that
        # broke this rule would drop a client value the stored list holds.
        for name in CLIENT_VALUE_COUNTS:
            returned, stored = client_value_counts(name)
            assert returned >= stored, name
