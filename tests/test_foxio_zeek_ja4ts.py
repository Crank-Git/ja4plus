"""Compare the JA4TS values of ja4plus against the FoxIO Zeek baselines.

JA4TS reached no FoxIO-produced expected value in this repository until #515. Every other
method held one. JA4, JA4S, JA4H, JA4X and JA4L read the FoxIO Python expected-output
files, JA4T reads the FoxIO Rust snapshots, and JA4D and JA4D6 read the Wireshark
dissector. JA4TS read the transcribed prose of a file FoxIO deleted, plus a capture this
project builds itself, and a capture this project builds proves the implementation against
itself.

`tests/foxio_vectors/zeek_expected/` now holds the seven Zeek baselines of
`FoxIO-LLC/ja4` at the pinned commit. Three of them are a `conn.log`, and those three
carry ten JA4TS values that the FoxIO Zeek package produced. This module compares nine of
the ten against ja4plus, and it measures the tenth as the proven Zeek defect that
`docs/specs/foxio/zeek.md` records.

Two FoxIO implementations write a JA4TS value, and the FoxIO Zeek package outranks
neither. `tests/test_foxio_wireshark_ja4ts.py` reads the 58 values of the other one.
`.claude/rules/external-apis.md` states the precedence, and `docs/specs/foxio/zeek.md`
states which baseline is usable as a vector.
"""

import logging
from pathlib import Path
from typing import NamedTuple

import pytest

from tests.compare_zeek_baselines import BASELINE_DIR, BASELINES, read_zeek_log
from tests.conformance_index import index_produced, stream_identity

logger = logging.getLogger(__name__)

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"

# The Zeek log column that holds JA4TS, and the method name the produced index holds.
ZEEK_COLUMN = "ja4ts"
METHOD = "JA4TS"

# The btest directory of every baseline this module bars as a vector, beside the reason.
# `docs/specs/foxio/zeek.md` rates the value of this baseline as None, because
# `zeek/ja4t/main.zeek:66-68` returns an empty option record when the link layer is not
# Ethernet, and the link type of `ipv6.pcapng` is `DLT_NULL`. #198 proved the defect and
# `TestTheBarredBaselineRestsOnAProvenZeekDefect` below measures every part of it.
BARRED_BASELINES = {
    "Scripts.ja4-conn": (
        "zeek/ja4t/main.zeek:66-68 reads no TCP option when the link type is not Ethernet"
    ),
}

# The link type of a capture that Zeek reads with no option. `DLT_NULL` is 0.
LINK_TYPE_NULL = 0

# The capture the barred baseline reads, and the two values the two implementations write.
BARRED_CAPTURE = "ipv6.pcapng"
BARRED_ZEEK_VALUE = "65535_00_00_00"
BARRED_JA4PLUS_VALUE = "65535_2-1-1-4-1-3_1346_10"

# The count of JA4TS values the three `conn.log` baselines hold. `docs/specs/foxio/zeek.md`
# records the same count, and a baseline refresh that moves it fails a case here.
JA4TS_VALUE_COUNT = 10


class Ja4tsCase(NamedTuple):
    """One JA4TS value that a FoxIO Zeek baseline holds.

    Attributes:
        directory: The btest directory name, such as `Scripts.ja4-conn-tls3`.
        capture: The capture file name the baseline read.
        identity: The direction-free stream identity.
        label: A one-line description of the connection.
        value: The JA4TS value the Zeek baseline holds.
    """

    directory: str
    capture: str
    identity: tuple
    label: str
    value: str


def _connection_baselines():
    """Return every baseline whose log carries a `ja4ts` column."""
    return [entry for entry in BASELINES if entry[1] == "conn.log"]


def _read_cases():
    """Return every JA4TS value the committed Zeek baselines hold.

    Returns:
        A list of Ja4tsCase entries, sorted by baseline and then by connection.
    """
    cases = []
    for directory, log_name, capture in _connection_baselines():
        log = BASELINE_DIR / directory / log_name
        if not log.is_file():
            continue
        for row in read_zeek_log(log):
            value = row.get(ZEEK_COLUMN, "")
            # `(empty)` is the btest rendering of an empty string, `-` of an unset field.
            if value in ("", "(empty)", "-"):
                continue
            cases.append(
                Ja4tsCase(
                    directory=directory,
                    capture=capture,
                    identity=stream_identity(
                        row["id.orig_h"], row["id.orig_p"], row["id.resp_h"], row["id.resp_p"]
                    ),
                    label="{}:{} -> {}:{}".format(
                        row["id.orig_h"], row["id.orig_p"], row["id.resp_h"], row["id.resp_p"]
                    ),
                    value=value,
                )
            )
    return sorted(cases, key=lambda case: (case.directory, case.label))


CASES = _read_cases()

ADOPTED_CASES = [case for case in CASES if case.directory not in BARRED_BASELINES]

BARRED_CASES = [case for case in CASES if case.directory in BARRED_BASELINES]


def _adopted_params():
    """Return one parameter set for every JA4TS value this module adopts as a vector."""
    return [
        pytest.param(
            case,
            id="{}-{}".format(case.capture, case.label.replace(" ", "")),
        )
        for case in ADOPTED_CASES
    ]


@pytest.mark.spec_validation
class TestTheZeekBaselineHoldsWhatJa4plusProduces:
    """Compare each adopted JA4TS value of a FoxIO Zeek baseline against ja4plus.

    Each case names one connection and one value, so a JA4TS value that moves fails a
    case that names the connection it moved on.
    """

    @pytest.mark.parametrize("case", _adopted_params())
    def test_ja4plus_produces_the_zeek_ja4ts_value(self, case):
        """ja4plus produces the JA4TS value the FoxIO Zeek baseline holds."""
        produced = index_produced(VECTORS_DIR / case.capture).get(case.identity, {})
        assert produced.get(METHOD, ()) == (case.value,), "{} {}: zeek={!r} ja4plus={!r}".format(
            case.capture, case.label, case.value, list(produced.get(METHOD, ()))
        )

    def test_the_baselines_hold_the_ten_ja4ts_values_the_reading_counts(self):
        """The three `conn.log` baselines hold ten JA4TS values."""
        assert len(CASES) == JA4TS_VALUE_COUNT

    def test_the_suite_adopts_nine_of_the_ten_values(self):
        """Nine values reach a comparison and one baseline is barred."""
        assert len(ADOPTED_CASES) == JA4TS_VALUE_COUNT - 1
        assert len(BARRED_CASES) == 1

    def test_every_adopted_case_names_a_capture_this_repository_holds(self):
        """A case that names no local capture compares nothing, so it fails here."""
        absent = sorted(
            {case.capture for case in CASES if not (VECTORS_DIR / case.capture).is_file()}
        )
        assert not absent, "the vector set holds no {}".format(absent)


@pytest.mark.spec_validation
class TestTheBarredBaselineRestsOnAProvenZeekDefect:
    """Measure every part of the reading that bars one baseline from the vector set.

    A vector set that drops the value it disagrees with proves nothing. This class
    therefore measures the four facts that bar the row, so the bar fails a case the
    moment any one of them stops holding. #198 proved the defect and
    `docs/specs/foxio/zeek.md` records it.
    """

    def test_the_barred_baseline_reads_the_capture_this_reading_names(self):
        """The one barred case reads `ipv6.pcapng`."""
        assert [case.capture for case in BARRED_CASES] == [BARRED_CAPTURE]

    def test_the_zeek_baseline_holds_the_empty_form(self):
        """The Zeek baseline writes the form that names no option, no size and no scale."""
        assert [case.value for case in BARRED_CASES] == [BARRED_ZEEK_VALUE]

    def test_ja4plus_reads_the_options_the_synack_carries(self):
        """ja4plus writes the option list, the segment size and the window scale."""
        case = BARRED_CASES[0]
        produced = index_produced(VECTORS_DIR / case.capture).get(case.identity, {})
        assert produced.get(METHOD, ()) == (BARRED_JA4PLUS_VALUE,)

    def test_the_capture_carries_a_link_type_that_is_not_ethernet(self):
        """The link type of the capture is `DLT_NULL`, which is the cause of the defect."""
        from scapy.all import PcapReader

        with PcapReader(str(VECTORS_DIR / BARRED_CAPTURE)) as reader:
            assert reader.linktype == LINK_TYPE_NULL

    def test_the_server_answered_with_a_packet_that_carries_tcp_options(self):
        """The SYN-ACK packet carries options, so the Zeek script drops what the wire holds."""
        from scapy.all import TCP, rdpcap

        options = []
        for packet in rdpcap(str(VECTORS_DIR / BARRED_CAPTURE)):
            if TCP in packet and packet[TCP].flags & 0x12 == 0x12:
                options = packet[TCP].options
                break
        assert options, "the SYN-ACK of {} carries no option".format(BARRED_CAPTURE)
