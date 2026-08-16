"""What the conformance suite measures about the frame that carries a value.

**A comparison that is never made reads as a comparison that passes.** #736 measured one.
#606 moved the QUIC `JA4L-S` emission to the packet that fills point `D`, from the packet
that fills point `B`. Seven values changed frame. The conformance suite reported the
identical three counts under the restored defect, so it discriminated none of them.

This module holds the reading #736 took, so that no later reader derives it again.

- The FoxIO Python expected output states no frame, and it is the source the conformance
  value comparison reads.
- The FoxIO Rust snapshots state no frame.
- The Zeek baselines state no frame.
- The FoxIO Wireshark dissector states the frame of every value it writes.

**The dissector is therefore the one source a per-frame comparison could read**, and
`.claude/rules/conformance.md` records why this project does not build that comparison
into the conformance suite. `tests/test_ja4l_quic_point_d_emission.py` holds the frame of
the QUIC `JA4L` values, and it runs in the unit suite.

Run with: pytest -m spec_validation -k frame_discrimination
"""

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

RULE_FILE = REPO_ROOT / ".claude" / "rules" / "conformance.md"

# The heading of the section that records this reading.
RULE_SECTION = "## What a green conformance run does not measure"

# A key of a reference source that would state the frame that carries a value. The
# dissector writes `frame.number`, and this module reads every other source for a key of
# the same kind. A frame states the position of one packet in the capture.
FRAME_WORDS = ("frame", "packet_number", "packet_num", "packetno", "pkt_num", "pktno")

# The two Zeek fields that count packets. A count states how many packets a connection
# holds, and it names none of them, so neither field states a frame.
ZEEK_PACKET_COUNTS = ("orig_pkts", "resp_pkts")

# The key of a method value in a FoxIO Rust snapshot. The rule file states the count these
# keys reach, so a snapshot that gains or loses a value fails a case rather than leaves
# that count stale.
RUST_METHOD_KEYS = frozenset({"ja4", "ja4s", "ja4h", "ja4t", "ja4x", "ja4ssh", "ja4l_c", "ja4l_s"})

# The frame each of the seven values of #606 moved to. The dissector writes the QUIC
# `ja4.ja4ls` value on each one, and `tests/test_ja4l_quic_point_d_emission.py` holds
# this project against the same frames.
FRAME_MOVES = {
    "chrome-cloudflare-quic-with-secrets.pcapng": ((49, 52),),
    "ssh2.pcapng": ((1140, 1147),),
    "tls3.pcapng": ((144, 147), (149, 153), (155, 162), (159, 167), (303, 312)),
}

QUIC_SUFFIX = "_quic"


def _python_expected_files():
    """Return every FoxIO Python expected-output file."""
    return sorted(VECTORS.glob("*.json"))


def _rust_snapshot_files():
    """Return every FoxIO Rust snapshot file."""
    return sorted((VECTORS / "rust_expected").glob("*.snap"))


def _zeek_baseline_files():
    """Return every Zeek baseline file."""
    return sorted((VECTORS / "zeek_expected").rglob("*.log"))


def _wireshark_files():
    """Return every FoxIO Wireshark dissector output file."""
    return sorted((VECTORS / "wireshark_expected").glob("*.json"))


def _names_a_frame(key):
    """Report whether one key of a reference source states a frame."""
    folded = key.lower()
    return any(word in folded for word in FRAME_WORDS)


@pytest.mark.spec_validation
class TestTheSourcesThatStateNoFrame:
    """Hold the clean negative of each source that frames no value."""

    def test_the_foxio_python_expected_output_states_no_frame(self):
        """The source the conformance value comparison reads frames nothing.

        The key of a record names the method and the occurrence, and the record names the
        stream. A value therefore rests on a connection and never on a packet.
        """
        files = _python_expected_files()
        assert len(files) == 38, "the reading covered 38 expected-output files"
        named = set()
        for path in files:
            for record in json.loads(path.read_text()):
                named.update(key for key in record if _names_a_frame(key))
        assert named == set(), (
            "the FoxIO Python expected output now states a frame under {}".format(sorted(named))
        )

    def test_the_foxio_rust_snapshot_states_no_frame(self):
        """The Rust snapshots key a value on the stream, and they state no frame.

        The reader matches a key of any letter case, so a key the snapshots later spell
        with a capital reaches the heuristic too.
        """
        files = _rust_snapshot_files()
        assert len(files) == 11, "the reading covered 11 snapshots"
        named = set()
        values = 0
        for path in files:
            for line in path.read_text().splitlines():
                match = re.match(r"^[- ]*([A-Za-z0-9_-]+):", line)
                if not match:
                    continue
                key = match.group(1)
                if _names_a_frame(key):
                    named.add(key)
                if key in RUST_METHOD_KEYS:
                    values += 1
        assert named == set(), "a Rust snapshot now states a frame under {}".format(sorted(named))
        assert values == 460, "the reading measured 460 method-keyed values"

    def test_the_zeek_baseline_states_no_frame(self):
        """A Zeek baseline keys a value on the connection, and it states no frame.

        The `ts` field of a baseline states the time of the connection. A reader takes no
        frame number from it, because a capture holds several packets at one time.
        """
        files = _zeek_baseline_files()
        assert len(files) == 7, "the reading covered 7 baselines"
        named = set()
        for path in files:
            for line in path.read_text().splitlines():
                if line.startswith("#fields"):
                    named.update(field for field in line.split("\t")[1:] if _names_a_frame(field))
        assert named == set(), "a Zeek baseline now states a frame under {}".format(sorted(named))

    def test_the_packet_count_of_a_zeek_baseline_states_no_frame(self):
        """`orig_pkts` and `resp_pkts` count packets, and they name no packet.

        A reader who searches a baseline for the word `pkt` finds these two fields. A
        count of the packets of a connection locates no value in the capture. Neither
        field therefore states a frame.
        """
        baseline = VECTORS / "zeek_expected" / "Scripts.ja4-conn" / "conn.log"
        fields = []
        for line in baseline.read_text().splitlines():
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                break
        for name in ZEEK_PACKET_COUNTS:
            assert name in fields, name
            assert not _names_a_frame(name), name


@pytest.mark.spec_validation
class TestTheSourceThatStatesTheFrame:
    """Hold the one source a per-frame comparison could read."""

    def test_the_wireshark_dissector_states_the_frame_of_every_value(self):
        """Every value the dissector writes carries the frame that produced it."""
        files = _wireshark_files()
        assert len(files) == 26, "the reading covered 26 dissector output files"
        framed = 0
        unframed = 0
        for path in files:
            for row in json.loads(path.read_text()):
                layers = row["_source"]["layers"]
                carries = "frame.number" in layers
                for key, values in layers.items():
                    if key == "frame.number":
                        continue
                    for _ in values:
                        if carries:
                            framed += 1
                        else:
                            unframed += 1
        assert unframed == 0, "{} dissector value(s) now carry no frame".format(unframed)
        assert framed == 724, "the reading measured 724 framed values"

    def test_the_dissector_names_the_destination_frame_of_every_move_of_606(self):
        """The seven frames #606 moved to are the frames the dissector writes.

        A move that no reference names would be a change this project made on its own.
        The dissector names all seven, so #606 followed one source.
        """
        for capture, moves in FRAME_MOVES.items():
            rows = json.loads((VECTORS / "wireshark_expected" / f"{capture}.json").read_text())
            frames = set()
            for row in rows:
                layers = row["_source"]["layers"]
                values = layers.get("ja4.ja4ls", [])
                if values and values[0].endswith(QUIC_SUFFIX):
                    frames.add(int(layers["frame.number"][0]))
            for source, destination in moves:
                assert destination in frames, (capture, destination)
                assert source not in frames, (capture, source)


@pytest.mark.spec_validation
class TestWhatTheConformanceSuiteCompares:
    """Hold what the conformance value comparison reads, and what it therefore misses."""

    def test_the_conformance_value_comparison_reads_a_source_that_frames_nothing(self):
        """Every value case of the conformance suite comes from the unframed source.

        `tests/test_spec_validation.py` builds one case for each value of the FoxIO Python
        expected output. That source states no frame, so no case of the suite can read
        one. A frame move therefore passes the suite whatever it moved.
        """
        from tests.test_spec_validation import _value_params

        cases = _value_params()
        assert len(cases) == 1203, "the reading measured 1203 value cases"
        for parameters in cases:
            json_path = VECTORS / "{}.json".format(parameters.values[0].name)
            assert json_path in _python_expected_files(), json_path

    def test_the_rule_file_records_what_a_green_conformance_run_does_not_measure(self):
        """`.claude/rules/conformance.md` states the limit and names the measurement.

        A reading that lives only in a closed issue is a reading the next reader derives
        again. #736 records this one in the rule file, and this case holds it there.
        """
        text = RULE_FILE.read_text()
        assert RULE_SECTION in text, "{} holds no section {!r}".format(RULE_FILE, RULE_SECTION)
        section = text.split(RULE_SECTION, 1)[1].split("\n## ", 1)[0]
        assert "#606" in section, "the section names no measurement that earned it"
        for capture, moves in FRAME_MOVES.items():
            assert capture in section, "the section names no move of {}".format(capture)
            for source, destination in moves:
                assert "{} to {}".format(source, destination) in section, (capture, source)
