"""The four FoxIO malformed captures produce no exception.

`FR-correctness-audit-9` states the contract. Each case names the parser it reaches,
because a case that reaches no parser proves nothing.
"""

import pytest

import ja4plus.utils.ssh_utils as ssh_utils
import ja4plus.utils.tls_utils as tls_utils
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter
from tests.fuzz.support import (
    MALFORMED_CAPTURES,
    read_capture,
    run_fingerprinters,
    spy_on,
)

# The parser each capture exists to exercise.
NAMED_PARSER = {
    "ssh2-malformed.pcap": (ssh_utils, "parse_ssh_packet"),
    "ssh2-moloch-crash.pcap": (ssh_utils, "parse_ssh_packet"),
    "badcurveball.pcap": (tls_utils, "parse_tls_handshake"),
    "CVE-2018-6794.pcap": (tls_utils, "parse_tls_handshake"),
}

# The distinct fingerprints each capture produces today. The suite pins the methods
# that read a packet payload, and it pins JA4T and JA4TS because they read the TCP
# header. It pins no JA4L value, because register row 5 stays open and JA4L still
# emits a second client value.
#
# #215 moved two JA4T values and one JA4TS value here. `badcurveball.pcap` gains the
# second End of Option List entry that D2 counts, and `CVE-2018-6794.pcap` takes the
# two-digit form that D1 states for a SYN-ACK that carries no option.
RECORDED_FINGERPRINTS = {
    "ssh2-malformed.pcap": {
        "ja4t": {"14600_2-1-1-4-1-3_1460_9"},
        "ja4ts": {"5840_2-1-1-4-1-3_1460_2"},
    },
    "ssh2-moloch-crash.pcap": {
        "ja4t": {"14600_2-1-1-4-1-3_1460_9"},
        "ja4ts": {"5840_2-1-1-4-1-3_1460_2"},
    },
    "badcurveball.pcap": {
        "ja4t": {"65535_2-1-3-1-1-8-4-0-0_1386_6"},
        "ja4ts": {"26847_2-4-8-1-3_1460_7"},
        "ja4": {"t13d1615h2_46e7e9700bed_45f260be83e2"},
        "ja4s": {"t1205h1_c02b_845f7282a956"},
        "ja4x": {"2e9214a636bc_2e9214a636bc_795797892f9c"},
    },
    "CVE-2018-6794.pcap": {
        "ja4t": {"8192_2-1-3-1-1-4_1460_8"},
        "ja4ts": {"15500_00_00_00"},
        "ja4h": {
            "ge11nn07ruru_6cd0fb54989b_000000000000_000000000000",
            "ge11nr06ruru_cc6ec9a91856_000000000000_000000000000",
        },
    },
}


@pytest.mark.parametrize("capture", MALFORMED_CAPTURES)
def test_a_foxio_malformed_capture_produces_no_exception(vector_dir, capture):
    _, failures = run_fingerprinters(read_capture(vector_dir, capture))
    assert failures == []


@pytest.mark.parametrize("capture", MALFORMED_CAPTURES)
def test_a_foxio_malformed_capture_reaches_the_parser_it_names(monkeypatch, vector_dir, capture):
    module, name = NAMED_PARSER[capture]
    counter = spy_on(monkeypatch, module, name)

    run_fingerprinters(read_capture(vector_dir, capture))

    assert counter.calls > 0, f"{capture} reaches {counter.target} zero times."


@pytest.mark.parametrize("capture", MALFORMED_CAPTURES)
def test_a_foxio_malformed_capture_produces_the_recorded_fingerprints(vector_dir, capture):
    produced, _ = run_fingerprinters(read_capture(vector_dir, capture))

    for method, expected in RECORDED_FINGERPRINTS[capture].items():
        assert set(produced.get(method, [])) == expected, method


@pytest.mark.parametrize("capture", MALFORMED_CAPTURES)
def test_a_foxio_malformed_capture_produces_a_ja4l_value(vector_dir, capture):
    produced, _ = run_fingerprinters(read_capture(vector_dir, capture))

    assert produced.get("ja4l")


def test_the_harness_reports_a_fingerprinter_that_raises(monkeypatch, vector_dir):
    """The harness observes a raise, so every "no exception" case above can fail.

    `Processor.process_packet` catches every exception. This case proves that the
    suite reads each fingerprinter directly instead.
    """

    def raise_instead(self, packet):
        raise ValueError("the harness must report this")

    monkeypatch.setattr(JA4TFingerprinter, "process_packet", raise_instead)

    _, failures = run_fingerprinters(read_capture(vector_dir, "badcurveball.pcap"))

    assert failures
    assert all("ja4t raised on packet" in failure for failure in failures)
