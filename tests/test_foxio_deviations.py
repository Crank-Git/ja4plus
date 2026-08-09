"""Check the deviation register and its reader.

The register records a conformance case that this project fails today. The suite reads
it and marks the matching case `xfail(strict=True)`. These tests check the reader, the
key forms and the shape of the committed register.
"""

import json
import re

import pytest

from tests.foxio_deviations import (
    OWNERS_PATH,
    REGISTER_PATH,
    Deviation,
    Owner,
    load_owners,
    load_register,
    occurrence_key,
    value_key,
)


# The four forms of citation that record a decision a person made. Each one is past
# tense, because a decision that was made is the only evidence that somebody read the
# entry. The present tense names the issue that will decide, as `#215 decides whether
# ja4plus reads the raw option bytes` does, and that names no decision. The lookbehind
# drops a denied citation, because the six JA4L entries hold `no Changelog round
# settled it`. The guard reads the word before the citation alone. A cause that denies a
# citation in other words fails the gate, and the repair is to reword the cause, because
# a gate that misses a decision costs more than a gate that asks a question.
DECISION_CITATION = re.compile(
    r"(?<![Nn]o )(?<![Nn]ot )"
    r"(?:Changelog round \d+"
    r"|decided on (?:#\d+|\d{4}-\d{2}-\d{2})"
    r"|#\d+ decided"
    r"|#\d+ records the decision)"
)


def unmarked_decisions(register):
    """Return one message for every entry that cites a decision and carries no marker.

    A cause that names a Changelog round by number, or names the issue or the date a
    decision was made on, records that a person read the entry. Such an entry carries
    `decided`. A cause that cites no decision stays unmarked, and that is the correct
    state for an entry that stays open.

    Args:
        register: The register that `load_register` returns.

    Returns:
        A list of messages, sorted by key. An empty list means every entry that cites a
        decision carries the marker.
    """
    messages = []
    for key, deviation in sorted(register.items()):
        if deviation.decided:
            continue
        citation = DECISION_CITATION.search(deviation.cause)
        if citation is None:
            continue
        messages.append(
            "{} names {}, and the entry carries no decided marker".format(key, citation.group())
        )
    return messages


def unrecorded_kinds(entries):
    """Return one message for every decided entry that records no kind of decline.

    A decided entry records a decline, and the kind of that decline decides whether the
    source-neutral precedence exception reaches the row. An entry that omits the
    `capability` field states no kind, so the reader falls back on the default and the
    exception rests on an absence rather than on a fact somebody recorded.

    Args:
        entries: The register file as `json.load` returns it, key to table.

    Returns:
        A list of messages, sorted by key. An empty list means every decided entry
        records the kind of its decline.
    """
    messages = []
    for key, entry in sorted(entries.items()):
        if not entry.get("decided"):
            continue
        if "capability" not in entry:
            messages.append("{} is decided and records no kind of decline".format(key))
    return messages


def unusable_owners(register, owners):
    """Return one message for every entry whose owner no worker can act on.

    An epic is never an owner, because an epic is not schedulable. A closed issue is an
    owner only when the entry is decided, which records a permanent divergence.

    Args:
        register: The register that `load_register` returns.
        owners: The owner map that `load_owners` returns.

    Returns:
        A list of messages. An empty list means every entry names a usable owner.
    """
    messages = []
    for key, deviation in sorted(register.items()):
        owner = owners.get(deviation.issue)
        if owner is None:
            messages.append(
                "{} names #{}, and the owner list holds no state for it".format(
                    key, deviation.issue
                )
            )
            continue
        if owner.epic:
            messages.append(
                "{} names the epic #{}, and an epic is not schedulable".format(key, owner.number)
            )
            continue
        if owner.state == "closed" and not deviation.decided:
            messages.append(
                "{} names the closed issue #{}, and the entry is not decided".format(
                    key, owner.number
                )
            )
    return messages


class TestTheKeyForms:
    """Check the two key forms the register holds."""

    def test_the_value_key_names_the_vector_the_stream_and_the_occurrence(self):
        assert value_key("tls-sni.pcapng", 38, "57377", "JA4", 1) == (
            "tls-sni.pcapng/38:57377/JA4.1"
        )

    def test_the_value_key_separates_two_streams_that_share_one_index(self):
        first = value_key("quic.pcapng", 0, "57098", "JA4L-C", 1)
        second = value_key("quic.pcapng", 0, "50280", "JA4L-C", 1)
        assert first != second

    def test_the_value_key_accepts_an_unknown_stream_index(self):
        assert value_key("tls-sni.pcapng", "?", "443", "JA4", 2) == "tls-sni.pcapng/?:443/JA4.2"

    def test_the_occurrence_key_names_the_vector_and_the_method(self):
        assert occurrence_key("ssh2.pcapng", "JA4") == "ssh2.pcapng/JA4"

    def test_the_two_key_forms_never_collide(self):
        assert value_key("a.pcap", 0, "443", "JA4", 1) != occurrence_key("a.pcap", "JA4")


class TestTheRegisterReader:
    """Check the reader that turns the register file into Deviation entries."""

    def _write(self, tmp_path, content):
        path = tmp_path / "deviations.json"
        path.write_text(json.dumps(content))
        return path

    def test_the_reader_returns_one_entry_for_one_key(self, tmp_path):
        path = self._write(
            tmp_path,
            {"a.pcap/0/JA4.1": {"issue": 13, "cause": "The extension count differs."}},
        )
        register = load_register(path)
        assert register["a.pcap/0/JA4.1"] == Deviation(
            issue=13, cause="The extension count differs."
        )

    def test_the_reader_returns_an_empty_register_for_an_empty_file(self, tmp_path):
        assert load_register(self._write(tmp_path, {})) == {}

    def test_the_reader_rejects_an_entry_that_names_no_issue(self, tmp_path):
        path = self._write(tmp_path, {"a.pcap/0/JA4.1": {"cause": "The count differs."}})
        with pytest.raises(ValueError, match="a.pcap/0/JA4.1"):
            load_register(path)

    def test_the_reader_rejects_an_issue_number_that_is_not_a_number(self, tmp_path):
        path = self._write(tmp_path, {"a.pcap/0/JA4.1": {"issue": "13", "cause": "x"}})
        with pytest.raises(ValueError, match="a.pcap/0/JA4.1"):
            load_register(path)

    def test_the_reader_rejects_an_entry_that_states_no_cause(self, tmp_path):
        path = self._write(tmp_path, {"a.pcap/0/JA4.1": {"issue": 13}})
        with pytest.raises(ValueError, match="a.pcap/0/JA4.1"):
            load_register(path)

    def test_the_reader_rejects_an_entry_that_is_not_a_table(self, tmp_path):
        path = self._write(tmp_path, {"a.pcap/0/JA4.1": "The count differs."})
        with pytest.raises(ValueError, match="a.pcap/0/JA4.1"):
            load_register(path)

    def test_the_reader_returns_an_empty_register_for_a_missing_file(self, tmp_path):
        assert load_register(tmp_path / "absent.json") == {}

    def test_the_reader_reads_no_decided_flag_as_false(self, tmp_path):
        path = self._write(tmp_path, {"a.pcap/0/JA4.1": {"issue": 13, "cause": "x"}})
        assert load_register(path)["a.pcap/0/JA4.1"].decided is False

    def test_the_reader_reads_the_decided_flag(self, tmp_path):
        path = self._write(
            tmp_path, {"a.pcap/0/JA4.1": {"issue": 13, "cause": "x", "decided": True}}
        )
        assert load_register(path)["a.pcap/0/JA4.1"].decided is True

    def test_the_reader_rejects_a_decided_flag_that_is_not_a_boolean(self, tmp_path):
        path = self._write(
            tmp_path, {"a.pcap/0/JA4.1": {"issue": 13, "cause": "x", "decided": "yes"}}
        )
        with pytest.raises(ValueError, match="a.pcap/0/JA4.1"):
            load_register(path)

    def test_the_reader_reads_no_capability_flag_as_false(self, tmp_path):
        path = self._write(tmp_path, {"a.pcap/0/JA4.1": {"issue": 13, "cause": "x"}})
        assert load_register(path)["a.pcap/0/JA4.1"].capability is False

    def test_the_reader_reads_the_capability_flag(self, tmp_path):
        path = self._write(
            tmp_path, {"a.pcap/0/JA4.1": {"issue": 13, "cause": "x", "capability": True}}
        )
        assert load_register(path)["a.pcap/0/JA4.1"].capability is True

    def test_the_reader_rejects_a_capability_flag_that_is_not_a_boolean(self, tmp_path):
        path = self._write(
            tmp_path, {"a.pcap/0/JA4.1": {"issue": 13, "cause": "x", "capability": "yes"}}
        )
        with pytest.raises(ValueError, match="a.pcap/0/JA4.1"):
            load_register(path)

    def test_the_reason_names_the_issue_and_the_cause(self):
        deviation = Deviation(issue=30, cause="JA4L needs the hop count.")
        assert deviation.reason() == "issue #30: JA4L needs the hop count."


class TestTheCommittedRegister:
    """Check the register this repository ships."""

    def test_the_register_reads(self):
        assert isinstance(load_register(), dict)

    def test_every_entry_names_an_issue(self):
        for key, deviation in load_register().items():
            assert deviation.issue > 0, "{} names no issue".format(key)

    def test_every_entry_states_a_cause(self):
        for key, deviation in load_register().items():
            assert deviation.cause.strip(), "{} states no cause".format(key)

    def test_the_register_holds_no_duplicate_key(self):
        with open(REGISTER_PATH) as handle:
            text = handle.read()
        pairs = json.loads(text, object_pairs_hook=lambda items: items)
        keys = [key for key, _ in pairs]
        assert len(keys) == len(set(keys))


# Two vectors carry a Decryption Secrets Block, and the reference reads the HTTP
# messages that the block decrypts. ja4plus reads no key material, so issue #129 owns
# every JA4H case of those two vectors, the hashed form and the raw form alike.
ENCRYPTED_HTTP_KEYS = (
    ["http2-with-cookies.pcapng/JA4H", "http2-with-cookies.pcapng/JA4H_ro"]
    + ["http2-with-cookies.pcapng/0:58847/JA4H.{}".format(count) for count in range(1, 16)]
    + ["http2-with-cookies.pcapng/0:58847/JA4H_ro.{}".format(count) for count in range(1, 16)]
    + [
        "chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4H.1",
        "chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4H_ro.1",
        "chrome-cloudflare-quic-with-secrets.pcapng/JA4H",
        "chrome-cloudflare-quic-with-secrets.pcapng/JA4H_ro",
    ]
)


class TestTheEncryptedHttpDeviations:
    """Check the JA4H entries of the two vectors that carry a secrets block."""

    @pytest.mark.parametrize("key", ENCRYPTED_HTTP_KEYS)
    def test_the_entry_names_the_no_decryption_issue(self, key):
        assert load_register()[key].issue == 129

    @pytest.mark.parametrize("key", ENCRYPTED_HTTP_KEYS)
    def test_the_entry_states_that_ja4plus_reads_no_encrypted_request(self, key):
        assert "reads no encrypted request" in load_register()[key].cause

    def test_the_cleartext_http1_vector_carries_no_entry(self):
        """#131 computed the JA4H raw form, so the cleartext vector matches and left.

        The check exists to prove that the entries above name the encrypted vectors
        alone. A cleartext vector that reappears here is a defect.
        """
        assert "http1-with-cookies.pcapng/JA4H_ro" not in load_register()


# The capture whose omitted stream no FoxIO implementation reads. The rule that settles
# every other #138 entry rests on a reference that holds the value, and this one has
# none, so its cause states the decision rather than the rule.
TUNNEL_SCAN_KEY = "socks4-https.pcap/JA4X"


class TestTheReferenceOmitsTheStreamDeviations:
    """Check the entries issue #138 settles.

    The FoxIO Python implementation reads no QUIC handshake, and it reads no TLS on a
    port it does not know. The FoxIO Rust implementation reads both, and it holds the
    exact value ja4plus produces. The omission is a gap in the FoxIO Python
    implementation, so the entries record a permanent divergence.
    `tests/test_foxio_rust_parity.py` holds the measurement.
    """

    def _entries(self):
        return {
            key: deviation for key, deviation in load_register().items() if deviation.issue == 138
        }

    def test_the_issue_owns_every_entry_it_settled(self):
        assert len(self._entries()) == 34

    def test_every_settled_entry_is_decided(self):
        undecided = sorted(
            key for key, deviation in self._entries().items() if not deviation.decided
        )
        assert undecided == []

    def test_every_decided_entry_names_the_implementation_that_holds_the_value(self):
        for key, deviation in self._entries().items():
            if key == TUNNEL_SCAN_KEY:
                continue
            assert "FoxIO Rust snapshot" in deviation.cause, key

    def test_every_decided_entry_states_why_the_python_file_omits_the_stream(self):
        for key, deviation in self._entries().items():
            if key == TUNNEL_SCAN_KEY:
                continue
            reads_no_quic = "reads no QUIC handshake" in deviation.cause
            reads_no_tunnel = "reads no TLS on port 8080" in deviation.cause
            assert reads_no_quic or reads_no_tunnel, key

    def test_no_settled_entry_names_the_epic(self):
        assert 13 not in {deviation.issue for deviation in load_register().values()}

    def test_the_tunnel_scan_entry_states_the_decision_that_keeps_the_values(self):
        """The SOCKS4 tunnel is the one case the rule does not reach.

        Every other entry rests on a FoxIO implementation that holds the value, and no
        FoxIO implementation holds this one. ja4plus reads the record layer without
        regard to the tunnel protocol, and that one behaviour also produces the
        `https-connect.pcap` values two FoxIO implementations hold. #138 keeps the
        values, so the entry is decided.
        """
        deviation = load_register()[TUNNEL_SCAN_KEY]
        assert deviation.decided is True
        assert "no FoxIO implementation holds one" in deviation.cause
        assert "without regard to the tunnel protocol" in deviation.cause


# Changelog round 66 settled the JA4L protocol marker on 2026-08-08, and #225 holds the
# decision. These are the 16 entries the decision reaches. The list names each key, and
# `test_the_issue_owns_the_sixteen_keys_the_round_names` compares it against the entries
# that name #225. An entry that joins or leaves #225 therefore fails that check.
QUIC_MARKER_KEYS = (
    "chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4L-C.1",
    "chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4L-S.1",
    "ssh2.pcapng/33:51810/JA4L-S.1",
    "ssh2.pcapng/36:61861/JA4L-C.1",
    "ssh2.pcapng/36:61861/JA4L-S.1",
    "tls3.pcapng/21:62481/JA4L-C.1",
    "tls3.pcapng/21:62481/JA4L-S.1",
    "tls3.pcapng/22:61732/JA4L-C.1",
    "tls3.pcapng/22:61732/JA4L-S.1",
    "tls3.pcapng/23:49791/JA4L-C.1",
    "tls3.pcapng/23:49791/JA4L-S.1",
    "tls3.pcapng/24:56684/JA4L-C.1",
    "tls3.pcapng/24:56684/JA4L-S.1",
    "tls3.pcapng/25:61884/JA4L-S.1",
    "tls3.pcapng/28:58117/JA4L-C.1",
    "tls3.pcapng/28:58117/JA4L-S.1",
)


class TestTheQuicMarkerDeviations:
    """Check the entries Changelog round 66 settled.

    ja4plus writes the `quic` marker as a third part on a QUIC connection, and the FoxIO
    Python reference writes two parts. The user decided on 2026-08-08 that the marker
    stays, so the entries record a permanent divergence.
    """

    def _entries(self):
        return {
            key: deviation for key, deviation in load_register().items() if deviation.issue == 225
        }

    def test_the_issue_owns_the_sixteen_keys_the_round_names(self):
        assert sorted(self._entries()) == sorted(QUIC_MARKER_KEYS)

    def test_every_settled_entry_is_decided(self):
        undecided = sorted(
            key for key, deviation in self._entries().items() if not deviation.decided
        )
        assert undecided == []

    def test_every_settled_entry_names_the_changelog_round(self):
        for key, deviation in self._entries().items():
            assert "Changelog round 66" in deviation.cause, key

    def test_every_settled_entry_states_that_the_marker_is_the_whole_difference(self):
        for key, deviation in self._entries().items():
            assert "the marker is the whole difference" in deviation.cause, key


# The five entries whose expected-output file publishes no JA4L key. The FoxIO Python
# implementation deletes both JA4L keys when the run names another method, so the count
# ja4plus produces has nothing to compare against.
METHOD_FILTER_KEYS = (
    "CVE-2018-6794.pcap/JA4L-C",
    "CVE-2018-6794.pcap/JA4L-S",
    "https-connect.pcap/JA4L-C",
    "https-connect.pcap/JA4L-S",
    "tls-handshake.pcapng/JA4L-S",
)

# The one entry of the six that compared two measured counts. #272 repaired the defect it
# recorded, so the case passes and the register holds the key no longer.
DUPLICATE_SERVER_VALUE_KEY = "ssh2.pcapng/JA4L-S"

# The three entries that awaited the #215 decision on the JA4T form left the open set.
# #215 landed the decision: the D2 entry and the D4 entry resolve to a pass and leave the
# register, and the `gre-erspan-vxlan.pcap` entry stays as a decided divergence from the
# FoxIO Rust implementation.
TCP_OPTION_KEYS = ()

JA4L_OWNER = 272

# Every entry that stays open. #272 decided the five method filter entries and repaired
# the sixth, and no JA4T entry stays open after #215.
OPEN_KEYS = TCP_OPTION_KEYS


class TestTheOpenRegisterEntries:
    """Check the entries no Changelog round settled.

    An unmarked entry states that nobody read it, and that is the register's only job.
    #193 marked 43 entries a round had settled, and batch 18 added 16 more unmarked. These
    checks hold the count of entries that stay open, and the reason each one is open.
    """

    def _undecided(self):
        return {
            key: deviation for key, deviation in load_register().items() if not deviation.decided
        }

    def test_the_register_holds_no_undecided_entry(self):
        assert len(self._undecided()) == 0

    def test_the_undecided_keys_are_the_ones_no_round_settled(self):
        assert sorted(self._undecided()) == sorted(OPEN_KEYS)

    def test_every_undecided_entry_names_the_issue_that_decides_it(self):
        for key, deviation in self._undecided().items():
            assert "#{}".format(deviation.issue) in deviation.cause, key

    def test_every_method_filter_entry_names_the_issue_that_declined_it(self):
        """#34 closed on 2026-08-07 and left the six entries with no owner.

        An entry whose owner is closed names nobody a worker can reach. #272 took the six,
        it declined the five the method filter produced, and it repaired the sixth.
        """
        for key in METHOD_FILTER_KEYS:
            assert load_register()[key].issue == JA4L_OWNER, key

    def test_every_method_filter_entry_records_a_decided_value_decline(self):
        for key in METHOD_FILTER_KEYS:
            deviation = load_register()[key]
            assert deviation.decided is True, key
            assert deviation.capability is False, key

    def test_every_method_filter_entry_names_the_reference_line_that_deletes_the_key(self):
        for key in METHOD_FILTER_KEYS:
            assert "python/ja4.py:339" in load_register()[key].cause, key

    def test_every_method_filter_entry_states_that_the_comparison_is_unreachable(self):
        """The wrong wording makes the decline read as a pass, so the cause states it.

        This project was never emitting more than the reference on these five. The
        reference published nothing to compare, because the method filter deleted the key.
        """
        for key in METHOD_FILTER_KEYS:
            cause = load_register()[key].cause
            assert "unreachable and not satisfied" in cause, key
            assert "published nothing to compare" in cause, key

    def test_the_register_holds_no_duplicate_server_value_entry(self):
        """#272 repaired the defect, so the case passes and needs no register entry.

        `ssh2.pcapng` stream 15 produced `JA4L-S=6252_58` twice where the reference holds
        it once. A retransmitted SYN-ACK now gives no value, so the counts agree.
        """
        assert DUPLICATE_SERVER_VALUE_KEY not in load_register()


class TestTheRegisterMarkerRule:
    """Check that every entry a person decided carries the marker.

    The register gained 21 entries in batch 18, and 16 of them named a decision the user
    had made while carrying no marker. #193 repaired the same fault earlier the same day,
    and #251 repaired it again. An unmarked entry states that nobody read it, so a cause
    that cites a decision and carries no marker is a defect.
    """

    def test_the_committed_register_hides_no_decision(self):
        assert unmarked_decisions(load_register()) == []

    def test_the_check_reports_an_entry_that_names_a_changelog_round(self):
        register = {"a.pcap/JA4": Deviation(issue=225, cause="Changelog round 66 keeps the part.")}
        assert unmarked_decisions(register) == [
            "a.pcap/JA4 names Changelog round 66, and the entry carries no decided marker"
        ]

    def test_the_check_reports_an_entry_that_names_the_issue_the_user_decided_on(self):
        register = {"a.pcap/JA4": Deviation(issue=105, cause="A defect, decided on #105.")}
        assert unmarked_decisions(register) == [
            "a.pcap/JA4 names decided on #105, and the entry carries no decided marker"
        ]

    def test_the_check_reports_an_entry_that_names_the_issue_that_records_the_decision(self):
        """The 16 entries of #162 close their cause with this form.

        A future entry that copies the form and carries no marker must fail the gate.
        """
        register = {"a.pcap/JA4": Deviation(issue=162, cause="#162 records the decision.")}
        assert unmarked_decisions(register) == [
            "a.pcap/JA4 names #162 records the decision, and the entry carries no decided marker"
        ]

    def test_the_check_reports_an_entry_that_names_the_date_of_the_decision(self):
        register = {"a.pcap/JA4": Deviation(issue=162, cause="The user decided on 2026-08-07.")}
        assert unmarked_decisions(register) == [
            "a.pcap/JA4 names decided on 2026-08-07, and the entry carries no decided marker"
        ]

    def test_the_check_reports_an_entry_that_names_the_issue_that_decided_it(self):
        register = {"a.pcap/JA4X": Deviation(issue=138, cause="#138 decided to keep the values.")}
        assert unmarked_decisions(register) == [
            "a.pcap/JA4X names #138 decided, and the entry carries no decided marker"
        ]

    def test_the_check_names_every_offending_key(self):
        register = {
            "b.pcap/JA4S": Deviation(issue=225, cause="Changelog round 66 keeps the part."),
            "a.pcap/JA4": Deviation(issue=105, cause="A defect, decided on #105."),
        }
        assert unmarked_decisions(register) == [
            "a.pcap/JA4 names decided on #105, and the entry carries no decided marker",
            "b.pcap/JA4S names Changelog round 66, and the entry carries no decided marker",
        ]

    def test_the_check_accepts_a_marked_entry_that_names_a_round(self):
        register = {
            "a.pcap/JA4": Deviation(issue=225, cause="Changelog round 66 keeps it.", decided=True)
        }
        assert unmarked_decisions(register) == []

    def test_the_check_accepts_an_open_entry_that_names_the_issue_that_will_decide_it(self):
        """The present tense names a decision nobody has made yet.

        The three JA4T entries read `#215 decides whether ja4plus reads the raw option
        bytes`. An entry that names the issue that will decide it names no decision.
        """
        register = {"a.pcap/JA4T": Deviation(issue=215, cause="#215 decides the JA4T form.")}
        assert unmarked_decisions(register) == []

    def test_the_check_accepts_an_open_entry_that_states_no_round_settled_it(self):
        """The six JA4L entries hold this sentence."""
        register = {
            "a.pcap/JA4L-S": Deviation(
                issue=272,
                cause="The entry stays open under #272, and no Changelog round settled it.",
            )
        }
        assert unmarked_decisions(register) == []

    def test_the_check_accepts_an_open_entry_that_denies_a_numbered_round(self):
        """A denied citation is not a citation.

        The JA4L sentence names no number today. A future author who writes the number
        into it must not make the gate demand a marker on an open entry.
        """
        register = {
            "a.pcap/JA4L-S": Deviation(issue=272, cause="No Changelog round 76 settled the entry.")
        }
        assert unmarked_decisions(register) == []

    def test_the_check_reads_a_citation_that_follows_a_denied_citation(self):
        """A denied citation hides no decision that the same cause states later.

        The check reads the whole cause. A cause that opens with a denial and then records
        a decision still names the decision.
        """
        register = {
            "a.pcap/JA4": Deviation(
                issue=162,
                cause="No Changelog round 76 settled it. The user decided on 2026-08-07.",
            )
        }
        assert unmarked_decisions(register) == [
            "a.pcap/JA4 names decided on 2026-08-07, and the entry carries no decided marker"
        ]


# The one issue whose entries record a capability this project chose not to build. #129
# declines the decrypted values the reference reads from a Decryption Secrets Block, and
# `ja4plus` reads no encrypted request by decision. #341 read the recorded cause of all
# 135 entries and found this one issue.
#
# Warning: these two constants record the state of the register today, and they carry no
# bar. `tests/test_precedence_exception.py` reads the field of each entry. A new
# capability decline fails the two cases below and the repair is to correct the state
# they record, never to read the kind from an issue number again.
CAPABILITY_ISSUE = 129

# The count of entries that record a capability decline. All 43 name #129.
CAPABILITY_ENTRIES = 43


class TestTheKindOfDecline:
    """Check the field that separates a value decline from a capability decline.

    The source-neutral precedence exception reaches a value decline and passes over a
    capability decline. #334 shipped that bar as a set of issue numbers in
    `tests/test_precedence_exception.py`, and reported that the register recorded no
    field the check could read. A rule stated where nothing checks it is the failure mode
    this project keeps meeting, so #341 moved the fact into the register and this gate
    holds it there.
    """

    def _entries(self):
        with open(REGISTER_PATH) as handle:
            return json.load(handle)

    def test_the_committed_register_records_a_kind_for_every_decided_entry(self):
        assert unrecorded_kinds(self._entries()) == []

    def test_the_check_reports_a_decided_entry_that_records_no_kind(self):
        entries = {"a.pcap/JA4": {"issue": 129, "cause": "x", "decided": True}}
        assert unrecorded_kinds(entries) == ["a.pcap/JA4 is decided and records no kind of decline"]

    def test_the_check_accepts_a_decided_entry_that_records_a_value_decline(self):
        entries = {"a.pcap/JA4": {"issue": 96, "cause": "x", "decided": True, "capability": False}}
        assert unrecorded_kinds(entries) == []

    def test_the_check_accepts_a_decided_entry_that_records_a_capability_decline(self):
        entries = {"a.pcap/JA4": {"issue": 129, "cause": "x", "decided": True, "capability": True}}
        assert unrecorded_kinds(entries) == []

    def test_the_check_accepts_an_undecided_entry_that_records_no_kind(self):
        """An undecided entry declines nothing, so it states no kind of decline.

        The six #272 entries carry the field today, and a new open entry may omit it. The
        gate demands the kind at the moment a person decides the entry.
        """
        entries = {"a.pcap/JA4L-S": {"issue": 272, "cause": "x"}}
        assert unrecorded_kinds(entries) == []

    def test_the_check_names_every_offending_key(self):
        entries = {
            "b.pcap/JA4S": {"issue": 96, "cause": "x", "decided": True},
            "a.pcap/JA4": {"issue": 129, "cause": "x", "decided": True},
        }
        assert unrecorded_kinds(entries) == [
            "a.pcap/JA4 is decided and records no kind of decline",
            "b.pcap/JA4S is decided and records no kind of decline",
        ]

    def test_the_encryption_boundary_owns_every_capability_decline(self):
        register = load_register()
        owners = {entry.issue for entry in register.values() if entry.capability}
        assert owners == {CAPABILITY_ISSUE}

    def test_every_entry_of_the_encryption_boundary_records_a_capability_decline(self):
        for key, entry in load_register().items():
            if entry.issue == CAPABILITY_ISSUE:
                assert entry.capability is True, key

    def test_the_register_holds_forty_three_capability_declines(self):
        capability = [key for key, entry in load_register().items() if entry.capability]
        assert len(capability) == CAPABILITY_ENTRIES


class TestTheOwnerReader:
    """Check the reader of the checked-in owner list."""

    def _write(self, tmp_path, owners):
        path = tmp_path / "owners.json"
        path.write_text(json.dumps({"owners": owners}))
        return path

    def test_the_reader_keys_the_map_by_issue_number(self, tmp_path):
        path = self._write(tmp_path, {"13": {"state": "open", "epic": True, "title": "Epic 2"}})
        assert load_owners(path)[13] == Owner(number=13, state="open", epic=True, title="Epic 2")

    def test_the_reader_reads_no_epic_flag_as_false(self, tmp_path):
        path = self._write(tmp_path, {"34": {"state": "open", "title": "Emit one value"}})
        assert load_owners(path)[34].epic is False

    def test_the_reader_rejects_a_state_it_does_not_allow(self, tmp_path):
        path = self._write(tmp_path, {"34": {"state": "merged", "title": "Emit one value"}})
        with pytest.raises(ValueError, match="34"):
            load_owners(path)


class TestTheRegisterOwners:
    """Check that every register entry names an issue a worker can act on.

    The register named the epic #13 for five batches, and no test caught it. An epic
    holds sub-issues, so no worker is assigned to it and no fix removes the entry.
    """

    def test_the_owner_list_reads(self):
        assert load_owners()

    def test_the_owner_list_holds_every_issue_the_register_names(self):
        named = {deviation.issue for deviation in load_register().values()}
        missing = sorted(named - set(load_owners()))
        assert not missing, "the owner list holds no state for {}".format(missing)

    def test_no_entry_names_an_epic_or_a_closed_issue(self):
        messages = unusable_owners(load_register(), load_owners())
        assert not messages, "\n".join(messages)

    def test_the_check_reports_an_entry_that_names_an_epic(self):
        register = {"a.pcap/JA4": Deviation(issue=13, cause="x")}
        owners = {13: Owner(number=13, state="open", epic=True, title="Epic 2")}
        assert unusable_owners(register, owners) == [
            "a.pcap/JA4 names the epic #13, and an epic is not schedulable"
        ]

    def test_the_check_reports_an_entry_that_names_a_closed_issue(self):
        register = {"a.pcap/JA4": Deviation(issue=78, cause="x")}
        owners = {78: Owner(number=78, state="closed", epic=False, title="Fix JA4X")}
        assert unusable_owners(register, owners) == [
            "a.pcap/JA4 names the closed issue #78, and the entry is not decided"
        ]

    def test_the_check_accepts_a_decided_entry_that_names_a_closed_issue(self):
        register = {"a.pcap/JA4SSH": Deviation(issue=96, cause="x", decided=True)}
        owners = {96: Owner(number=96, state="closed", epic=False, title="Decide the mode")}
        assert unusable_owners(register, owners) == []

    def test_the_check_reports_an_owner_the_list_does_not_hold(self):
        register = {"a.pcap/JA4": Deviation(issue=999, cause="x")}
        assert unusable_owners(register, {}) == [
            "a.pcap/JA4 names #999, and the owner list holds no state for it"
        ]

    def test_the_check_accepts_an_open_issue(self):
        register = {"a.pcap/JA4": Deviation(issue=137, cause="x")}
        owners = {137: Owner(number=137, state="open", epic=False, title="Produce the values")}
        assert unusable_owners(register, owners) == []

    def test_the_owner_list_records_where_it_came_from(self):
        with open(OWNERS_PATH) as handle:
            document = json.load(handle)
        assert document["source"].startswith("gh issue list")
        assert document["retrieved"]
