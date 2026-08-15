"""The reference citations of `docs/specs/foxio/JA4T.md`, read at the pinned commit.

**A `file:line` citation is evidence, and a reader who follows one and lands on a comment
cannot tell a stale citation from a moved reference.** #603 found two such citations while
it wrote the divergence register row for the JA4T SYN selection, and #637 read every
citation of the page at the pinned commit and moved six.

This repository holds no copy of `wireshark/source/packet-ja4.c` and no copy of
`zeek/ja4t/main.zeek`, so no case here reads either file. **These cases hold the recorded
reading instead.** `RECORDED_CITATIONS` names every citation the page carries, and it
states the source line each one holds at the pinned commit
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`. A citation the page adds, moves or drops fails
a case here, so the author reads the new line at the pin and records it.

`STALE_CITATIONS` and `STALE_PROSE_LINES` name the three comment lines #637 moved away
from. A reader who follows one of them lands above the statement the page describes.

Verified against: https://github.com/FoxIO-LLC/ja4 (`wireshark/source/packet-ja4.c` and
`zeek/ja4t/main.zeek`, at the pinned commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`,
retrieved 2026-08-15)
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

TRANSCRIPTION = REPO_ROOT / "docs" / "specs" / "foxio" / "JA4T.md"

SPECIFICATION = REPO_ROOT / "docs" / "specs" / "spec.md"

PINNED_COMMIT = "27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8"

# The three FoxIO reference files the page cites by line. `README.md` and
# `technical_details/README.md` carry their line numbers in prose, so this pattern reads
# neither one.
CITATION_PATTERN = re.compile(
    r"(?:wireshark/source/packet-ja4\.c|zeek/ja4t/main\.zeek|rust/ja4/src/tcp\.rs)"
    r":\d+(?:-\d+)?"
)

# Every citation the page carries, with the count of its occurrences and the first source
# line it names at the pinned commit. #637 read all of them.
RECORDED_CITATIONS = {
    "wireshark/source/packet-ja4.c:234": (1, "#define MAX_SYN_ACK_TIMES 10"),
    "wireshark/source/packet-ja4.c:664": (
        2,
        "static char *ja4t(wmem_allocator_t *scope, ja4t_info_t *data, conn_info_t *conn) {",
    ),
    "wireshark/source/packet-ja4.c:668": (1, "if (data->window_scale == 0) {"),
    "wireshark/source/packet-ja4.c:684": (
        1,
        "if ((conn != NULL) && (conn->syn_ack_count > 1)) {",
    ),
    "wireshark/source/packet-ja4.c:693": (1, "if (!nstime_is_zero(&conn->rst_time)) {"),
    "wireshark/source/packet-ja4.c:694": (
        1,
        "int64_t diff = timediff(&conn->rst_time, &conn->syn_ack_times[conn->syn_ack_count - 1]);",
    ),
    "wireshark/source/packet-ja4.c:1258": (
        1,
        "ja4t_data.window_size = fvalue_get_uinteger(get_value_ptr(field));",
    ),
    "wireshark/source/packet-ja4.c:1266": (2, "if (tcp_flags == 0x02) {"),
    "wireshark/source/packet-ja4.c:1296": (
        3,
        "if ((packet_time != NULL) && (tcp_flags == 0x004)) {",
    ),
    "wireshark/source/packet-ja4.c:1458": (
        2,
        'ja4t_data.tcp_options, "%d-", fvalue_get_uinteger(get_value_ptr(field))',
    ),
    "wireshark/source/packet-ja4.c:1595": (
        2,
        'update_tree_item(pinfo->num, hf_ja4ts, ja4t(pinfo->pool, &ja4t_data, conn), "tcp");',
    ),
    "wireshark/source/packet-ja4.c:1599": (1, "if (syn == 3) {"),
    "wireshark/source/packet-ja4.c:1608": (
        1,
        'update_tree_item(pinfo->num, hf_ja4ts, ja4t(pinfo->pool, &ja4t_data, conn), "tcp");',
    ),
    "zeek/ja4t/main.zeek:162": (
        1,
        "if (ts - c$fp$ja4t$last_ts > 120000000) { # Timeout.",
    ),
    "zeek/ja4t/main.zeek:167": (1, "if (rph$tcp$flags & TH_RST != 0) {"),
    "zeek/ja4t/main.zeek:177-178": (
        1,
        "c$fp$ja4t$synack_window_size = rph$tcp$win;",
    ),
    "zeek/ja4t/main.zeek:180": (
        1,
        "c$fp$ja4t$synack_delays += double_to_count(ts - c$fp$ja4t$last_ts)/1000000;",
    ),
    "zeek/ja4t/main.zeek:185": (2, "if (|c$fp$ja4t$synack_delays| == 10) {"),
    "zeek/ja4t/main.zeek:189": (
        1,
        "ConnThreshold::set_packets_threshold(c,threshold + 1,F);",
    ),
    "zeek/ja4t/main.zeek:195-211": (1, "if(c$fp$ja4t$syn_window_size > 0) {"),
    "zeek/ja4t/main.zeek:195-236": (1, "if(c$fp$ja4t$syn_window_size > 0) {"),
    "zeek/ja4t/main.zeek:206-210": (
        1,
        "if(c$fp$ja4t$syn_opts$window_scale == 0) {",
    ),
    "zeek/ja4t/main.zeek:229": (1, "if (|c$fp$ja4t$synack_delays| > 0) {"),
    "zeek/ja4t/main.zeek:229-235": (1, "if (|c$fp$ja4t$synack_delays| > 0) {"),
    "zeek/ja4t/main.zeek:232": (1, "if(c$fp$ja4t$rst_ts > 0) {"),
    "zeek/ja4t/main.zeek:233": (
        1,
        'c$conn$ja4ts += fmt("-R%d", double_to_count(c$fp$ja4t$rst_ts - '
        "c$fp$ja4t$last_ts)/1000000);",
    ),
}

# The lines #637 moved away from. Each one holds a comment above the statement the page
# describes, so the page cites none of them.
STALE_CITATIONS = {
    "wireshark/source/packet-ja4.c:1265": "// SYN for this stream - signal JA4T",
    "wireshark/source/packet-ja4.c:1295": "// Add RST for JA4T",
}

# The two comment lines the page cited in prose, as `Line <n>`.
STALE_PROSE_LINES = {
    "Line 1278": "// SYN ACK for JA4TS - server latency",
    "line 1278": "// SYN ACK for JA4TS - server latency",
}


def read_transcription() -> str:
    return TRANSCRIPTION.read_text(encoding="utf-8")


def counted_citations() -> dict[str, int]:
    """Return the count of every reference citation the transcription carries."""
    counts: dict[str, int] = {}
    for citation in CITATION_PATTERN.findall(read_transcription()):
        counts[citation] = counts.get(citation, 0) + 1
    return counts


def test_the_transcription_cites_only_the_lines_this_record_holds() -> None:
    unrecorded = sorted(set(counted_citations()) - set(RECORDED_CITATIONS))
    assert unrecorded == [], (
        "the transcription cites a line no record names; read each one at the pinned "
        f"commit {PINNED_COMMIT} and add it to RECORDED_CITATIONS: {unrecorded}"
    )


def test_this_record_names_no_line_the_transcription_dropped() -> None:
    dropped = sorted(set(RECORDED_CITATIONS) - set(counted_citations()))
    assert dropped == [], (
        f"this record names a citation the transcription no longer carries: {dropped}"
    )


def test_the_transcription_repeats_each_citation_the_expected_number_of_times() -> None:
    counts = counted_citations()
    expected = {citation: count for citation, (count, _) in RECORDED_CITATIONS.items()}
    wrong = {
        citation: (counts.get(citation, 0), want)
        for citation, want in expected.items()
        if counts.get(citation, 0) != want
    }
    assert wrong == {}, f"a citation count moved, as <citation>: (found, recorded): {wrong}"


def test_the_transcription_cites_no_comment_line_of_the_dissector() -> None:
    text = read_transcription()
    found = {citation: comment for citation, comment in STALE_CITATIONS.items() if citation in text}
    assert found == {}, (
        "the transcription cites a line that holds a comment above the statement it "
        f"describes, as <citation>: <the comment that line holds>: {found}"
    )


def test_the_transcription_names_no_comment_line_in_prose() -> None:
    text = read_transcription()
    found = {phrase: comment for phrase, comment in STALE_PROSE_LINES.items() if phrase in text}
    assert found == {}, f"the transcription names a comment line in prose: {found}"


def test_every_recorded_citation_states_the_source_line_it_names() -> None:
    empty = sorted(
        citation for citation, (_, line) in RECORDED_CITATIONS.items() if not line.strip()
    )
    assert empty == [], f"a record states no source line, so nobody read it at the pin: {empty}"


def test_the_transcription_and_the_register_agree_on_the_dissector_flag_test() -> None:
    citation = "`wireshark/source/packet-ja4.c:1266`"
    register = SPECIFICATION.read_text(encoding="utf-8")
    assert citation in read_transcription(), (
        f"R10 of the transcription cites the dissector flag test at {citation} nowhere"
    )
    assert citation in register, (
        f"the divergence register cites the dissector flag test at {citation} nowhere"
    )


def test_the_transcription_names_the_pinned_commit_the_citations_were_read_at() -> None:
    assert PINNED_COMMIT in read_transcription(), (
        "a line number is meaningless without the commit it was read at, and the "
        f"transcription names {PINNED_COMMIT} nowhere"
    )
