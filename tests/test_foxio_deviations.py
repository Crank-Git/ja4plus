"""Check the deviation register and its reader.

The register records a conformance case that this project fails today. The suite reads
it and marks the matching case `xfail(strict=True)`. These tests check the reader, the
key forms and the shape of the committed register.
"""

import json

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
