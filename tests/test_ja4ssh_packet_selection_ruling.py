"""The JA4SSH packet selection the divergence register records under #608.

A JA4SSH window counts the segment that completes an SSH message. The `ssh.direction`
label of the `tshark` SSH dissector counts fewer frames on two captures, because the
reassembly of the dissector stalls and its later frames reach no SSH dissection.

**A ruling that lives only in a closed issue is a ruling the next reader reverses by
accident.** These cases hold the register row against the code it describes. A change to
the selection line fails a case here, and so does a deletion of the row.
"""

from pathlib import Path
import re

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import rdpcap

from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter

REPO_ROOT = Path(__file__).resolve().parent.parent

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

FINGERPRINTER = REPO_ROOT / "ja4plus" / "fingerprinters" / "ja4ssh.py"

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

# The heading of the register, and the line that closes it.
# `tests/test_ja4h_emission_frame_ruling.py` reads the same two markers.
REGISTER_HEADING = "### Divergence register"
REGISTER_END = "Verified against: https://github.com/Crank-Git/ja4plus-go"

REGISTER_SEPARATOR = re.compile(r"^\|[\s\-|]+\|$")

# The first cell of the row this issue writes.
RULING_ITEM = "The packets a JA4SSH window counts"

# The line of the fingerprinter that selects a packet, and the text it holds.
SELECTION_LINE = 247
SELECTION_TEXT = (
    'if completed and (is_ssh_packet(payload) or conn["client_id"] or conn["server_id"]):'
)

# The frames of `sshv1.pcap` that this project counts and `ssh.direction` leaves
# unlabeled. The dissector reassembles 480 bytes across frame 63 and frame 65, its own
# framing asks for 484, and frame 68 and frame 70 then reach no SSH dissection.
SSHV1_EXTRA_FRAMES = (63, 65, 68, 70)

# The count of frames this project counts on `sshv1.pcap`.
SSHV1_COUNTED = 43

# The value `sshv1.pcap` produces here. `testdata/deviations.json` of the port records
# the same value under the key `sshv1.pcap/72/JA4SSH.1`.
SSHV1_VALUE = "c20s20_c18s25_c10s1"

# The frames of `ssh2-malformed.pcap` that this project counts and `ssh.direction`
# leaves unlabeled.
MALFORMED_EXTRA_FRAMES = (14, 19, 21)

# The count of frames this project counts on `ssh2-malformed.pcap`.
MALFORMED_COUNTED = 13

# The addresses and the ports of the connection the two synthetic cases read.
CLIENT_IP = "192.168.1.50"
SERVER_IP = "10.0.0.1"
CLIENT_PORT = 50000
SERVER_PORT = 22

# The first sequence number of the synthetic connection.
FIRST_SEQUENCE = 1000

# One SSH binary packet of 16 bytes: the length field 12, the padding length 8, the
# message type 20, and 11 bytes that follow.
SSH_MESSAGE = b"\x00\x00\x00\x0c\x08\x14" + b"\x00" * 10


class _CountingFingerprinter(JA4SSHFingerprinter):
    """Report how many packets one JA4SSH window has counted since the first packet.

    `_close_window` clears the counters of the window it emits, so a reader of the state
    table alone loses every count an emission cleared. This subclass adds the cleared
    counts to a running total, and the total therefore never falls.
    """

    def __init__(self) -> None:
        """Build the fingerprinter, and start the running total at zero."""
        super().__init__()
        self.emitted_packets = 0

    def _close_window(self, conn_key: str) -> str | None:
        """Emit the open window, and keep the count of the packets it held.

        Args:
            conn_key: The connection key of the window.

        Returns:
            The result of the method this class extends.
        """
        conn = self.connections.get(conn_key)
        if conn is not None:
            self.emitted_packets += len(conn["ssh_packets"]["client"]) + len(
                conn["ssh_packets"]["server"]
            )
        return super()._close_window(conn_key)

    def counted_packets(self) -> int:
        """Return the count of the packets every window of this fingerprinter counted.

        Returns:
            The running total.
        """
        live = sum(
            len(conn["ssh_packets"]["client"]) + len(conn["ssh_packets"]["server"])
            for conn in self.connections.values()
        )
        return self.emitted_packets + live


def _counted_frames(capture: str) -> list[int]:
    """Return the frame number of every packet that a JA4SSH window counts.

    Args:
        capture: The file name of the capture, under `tests/foxio_vectors/`.

    Returns:
        The frame numbers, in capture order. A frame that completes two SSH messages
        appears once.
    """
    fingerprinter = _CountingFingerprinter()
    counted = []
    total = 0
    for number, packet in enumerate(rdpcap(str(VECTORS / capture)), start=1):
        fingerprinter.process_packet(packet)
        after = fingerprinter.counted_packets()
        if after > total:
            counted.append(number)
        total = after
    return counted


def _register_row() -> str:
    """Return the register row that records the JA4SSH packet selection.

    Returns:
        The whole text of the row.

    Raises:
        AssertionError: The page holds no register, or the register holds no such row.
    """
    page = SPECIFICATION.read_text(encoding="utf-8")
    assert REGISTER_HEADING in page, f"the specification holds no {REGISTER_HEADING!r}"
    section = page[page.index(REGISTER_HEADING) : page.index(REGISTER_END)]
    for line in section.splitlines():
        if not line.startswith("|") or REGISTER_SEPARATOR.match(line):
            continue
        if line.split("|")[1].strip() == RULING_ITEM:
            return line
    raise AssertionError(f"the divergence register holds no row named {RULING_ITEM!r}")


def _client_packet(payload: bytes, sequence: int, moment: float) -> Raw:
    """Return one client packet that carries the payload at the moment.

    Args:
        payload: The bytes of the TCP payload.
        sequence: The sequence number of the first byte.
        moment: The capture time, in seconds.

    Returns:
        The packet.
    """
    packet = (
        IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="PA", seq=sequence)
        / Raw(load=payload)
    )
    packet.time = moment
    return packet


def test_the_register_holds_a_row_for_the_packets_a_ja4ssh_window_counts() -> None:
    """The divergence register holds the row that records the packet selection."""
    assert RULING_ITEM in _register_row()


def test_the_register_names_the_line_that_selects_a_packet() -> None:
    """The row names the line of the selection and the function it calls."""
    row = _register_row()
    absent = [
        citation
        for citation in (
            "`ja4plus/fingerprinters/ja4ssh.py:247`",
            "`ja4plus/utils/ssh_utils.py:504`",
        )
        if citation not in row
    ]
    assert absent == [], f"the row names none of these lines: {absent}"


def test_the_register_names_the_two_captures_that_disagree() -> None:
    """The row names each capture where the two selections count different frames."""
    row = _register_row()
    absent = [
        capture
        for capture in ("`sshv1.pcap`", "`v6.pcap`", "`ssh2-malformed.pcap`")
        if capture not in row
    ]
    assert absent == [], f"the row names none of these captures: {absent}"


def test_the_register_names_the_counts_of_both_selections() -> None:
    """The row states the frame count of each selection on the two captures."""
    row = _register_row()
    absent = [count for count in ("43", "39", "13", "10") if count not in row]
    assert absent == [], f"the row states none of these counts: {absent}"


def test_the_register_names_the_records_that_hold_the_ruling() -> None:
    """The row names this issue and the issue of the port that carries the other half."""
    row = _register_row()
    absent = [
        citation for citation in ("#608", "`Crank-Git/ja4plus-go#491`") if citation not in row
    ]
    assert absent == [], f"the row names none of these records: {absent}"


def test_the_register_names_the_line_of_the_port_that_selects_a_packet() -> None:
    """The row names the line of the port that holds the same selection."""
    assert "`ja4ssh.go:359`" in _register_row()


def test_the_register_row_reads_parity_rule_one() -> None:
    """The row states rule 1, because FoxIO governs the behaviour of a fingerprinter."""
    assert _register_row().split("|")[4].strip() == "1"


def test_the_register_row_states_that_the_two_libraries_agree() -> None:
    """The row records a declined defect against FoxIO and no divergence from the port."""
    assert "this row records no divergence from the port" in _register_row()


def test_the_register_row_states_that_the_ruling_is_reversible() -> None:
    """The row states that a source which states a framing rule reopens the ruling."""
    assert "The ruling is reversible" in _register_row()


def test_the_module_selects_a_packet_at_the_cited_line() -> None:
    """The line the row names holds the test that selects a packet."""
    lines = FINGERPRINTER.read_text(encoding="utf-8").splitlines()
    assert lines[SELECTION_LINE - 1].strip() == SELECTION_TEXT


def test_the_selection_counts_four_frames_the_dissector_leaves_unlabeled() -> None:
    """`sshv1.pcap` counts 43 frames, and four of them carry no `ssh.direction` label."""
    counted = _counted_frames("sshv1.pcap")
    assert len(counted) == SSHV1_COUNTED
    absent = [frame for frame in SSHV1_EXTRA_FRAMES if frame not in counted]
    assert absent == [], f"the selection counts none of these frames: {absent}"


def test_the_sshv1_capture_produces_the_value_of_the_present_selection() -> None:
    """`sshv1.pcap` produces one JA4SSH value, and the port records that same value."""
    fingerprinter = JA4SSHFingerprinter()
    values = [
        value
        for value in (
            fingerprinter.process_packet(packet) for packet in rdpcap(str(VECTORS / "sshv1.pcap"))
        )
        if value
    ]
    assert values == [SSHV1_VALUE]


def test_the_malformed_capture_counts_three_frames_the_dissector_leaves_unlabeled() -> None:
    """`ssh2-malformed.pcap` counts 13 frames, and three of them carry no label."""
    counted = _counted_frames("ssh2-malformed.pcap")
    assert len(counted) == MALFORMED_COUNTED
    absent = [frame for frame in MALFORMED_EXTRA_FRAMES if frame not in counted]
    assert absent == [], f"the selection counts none of these frames: {absent}"


def test_a_segment_that_holds_part_of_a_message_counts_no_packet() -> None:
    """The first half of one SSH message reaches no window, because it completes none."""
    fingerprinter = _CountingFingerprinter()
    fingerprinter.process_packet(_client_packet(b"SSH-2.0-probe\r\n", FIRST_SEQUENCE, 0.0))
    before = fingerprinter.counted_packets()
    fingerprinter.process_packet(_client_packet(SSH_MESSAGE[:8], FIRST_SEQUENCE + 15, 0.010))
    assert fingerprinter.counted_packets() == before


def test_the_segment_that_completes_a_message_counts_one_packet() -> None:
    """The second half of one SSH message counts one packet, because it completes it."""
    fingerprinter = _CountingFingerprinter()
    fingerprinter.process_packet(_client_packet(b"SSH-2.0-probe\r\n", FIRST_SEQUENCE, 0.0))
    fingerprinter.process_packet(_client_packet(SSH_MESSAGE[:8], FIRST_SEQUENCE + 15, 0.010))
    before = fingerprinter.counted_packets()
    fingerprinter.process_packet(_client_packet(SSH_MESSAGE[8:], FIRST_SEQUENCE + 23, 0.020))
    assert fingerprinter.counted_packets() == before + 1
