"""The lookup client reaches no network until the operator opts in, issue #57.

A fingerprint describes traffic the operator observed. A request to `ja4db.com`
discloses that traffic to a third party. The cases below prove that the default client
attempts no request, and that `allow_remote=True` permits one.
"""

import socket
from unittest.mock import patch

import pytest

from ja4plus.ja4db import _REMOTE_TIMEOUT, JA4DBClient

# A fingerprint the bundled mapping file holds.
KNOWN_FINGERPRINT = "t13d1516h2_8daaf6152771_02713d6af862"

# A fingerprint the bundled mapping file holds no entry for.
MISSING_FINGERPRINT = "t99z9999h0_000000000000_000000000000"


class SocketAttempted(RuntimeError):
    """A case blocked an outbound socket that the code under test opened."""


class StubResponse:
    """A stand-in for one `requests` response.

    Args:
        status_code: The status the response reports.
        payload: The value `json` returns.
        error: The failure `json` raises, or None.
    """

    def __init__(self, status_code=200, payload=None, error=None):
        self.status_code = status_code
        self._payload = payload
        self._error = error

    def json(self):
        """Return the payload, or raise the failure the case holds."""
        if self._error is not None:
            raise self._error
        return self._payload


class RecordingRequests:
    """A stand-in for the `requests` module that records every call.

    It reaches no network, so a case that installs it measures the attempt rather than
    the result.

    Args:
        response: The response `get` returns.
        error: The failure `get` raises, or None.
    """

    def __init__(self, response=None, error=None):
        self.calls = []
        self._response = response
        self._error = error

    def get(self, url, **kwargs):
        """Record the call, then return the response or raise the failure."""
        self.calls.append((url, kwargs))
        if self._error is not None:
            raise self._error
        return self._response


@pytest.fixture
def no_network(monkeypatch):
    """Make every outbound socket raise `SocketAttempted`.

    Args:
        monkeypatch: The pytest fixture that restores each name after the case.
    """

    def refuse(*args, **kwargs):
        raise SocketAttempted("the case blocks every outbound socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


class TestTheDefaultClientReachesNoNetwork:
    """`JA4DBClient()` performs no network request, FR-db-enrichment-1."""

    def test_the_fixture_blocks_an_outbound_socket(self, no_network):
        """The case that follows measures the client, and not a fixture that lets a
        socket through."""
        with pytest.raises(SocketAttempted):
            socket.socket()

    def test_the_default_client_looks_1000_fingerprints_up_while_every_socket_fails(
        self, no_network
    ):
        """The `lookup` extra is absent from this environment, so the case installs a
        stand-in that opens a socket. Without it, a run against the unrepaired client
        passes on the missing package."""
        recorder = RecordingRequests(error=SocketAttempted("the stand-in opens no port"))
        client = JA4DBClient()
        with patch.dict("sys.modules", {"requests": recorder}):
            for index in range(1000):
                assert client.lookup(f"t13d1516h2_000000000000_{index:012d}") is None
        assert recorder.calls == []

    def test_the_default_client_attempts_no_request(self):
        """The case measures the attempt, and not a request that failed."""
        recorder = RecordingRequests(response=StubResponse(payload={}))
        client = JA4DBClient()
        with patch.dict("sys.modules", {"requests": recorder}):
            assert client.lookup(MISSING_FINGERPRINT) is None
        assert recorder.calls == []

    def test_the_default_client_reads_the_mapping_file(self, no_network):
        """A local hit needs no network, so the default client still identifies it."""
        client = JA4DBClient()
        result = client.lookup(KNOWN_FINGERPRINT)
        assert result is not None
        assert "Chromium" in result["application"]

    def test_the_module_level_lookup_function_attempts_no_request(self):
        """`ja4plus.ja4db.lookup` builds a client that holds the default."""
        import ja4plus.ja4db as ja4db

        recorder = RecordingRequests(response=StubResponse(payload={}))
        with patch.object(ja4db, "_default_client", None):
            with patch.dict("sys.modules", {"requests": recorder}):
                assert ja4db.lookup(MISSING_FINGERPRINT) is None
        assert recorder.calls == []


class TestTheOptInClient:
    """`JA4DBClient(allow_remote=True)` permits the remote lookup, FR-db-enrichment-2."""

    def test_the_opt_in_client_performs_the_remote_lookup_on_a_miss(self):
        payload = {"application": "Test Client", "type": "ja4", "notes": "a note"}
        recorder = RecordingRequests(response=StubResponse(payload=payload))
        client = JA4DBClient(allow_remote=True)
        with patch.dict("sys.modules", {"requests": recorder}):
            result = client.lookup(MISSING_FINGERPRINT)
        assert result == payload
        assert len(recorder.calls) == 1
        assert recorder.calls[0][0].endswith(MISSING_FINGERPRINT)

    def test_the_opt_in_client_attempts_no_request_for_a_local_hit(self):
        """The mapping file answers first, so a hit costs no request."""
        recorder = RecordingRequests(response=StubResponse(payload={}))
        client = JA4DBClient(allow_remote=True)
        with patch.dict("sys.modules", {"requests": recorder}):
            assert client.lookup(KNOWN_FINGERPRINT) is not None
        assert recorder.calls == []

    def test_the_remote_lookup_carries_a_timeout_of_five_seconds(self):
        """The remote lookup has a timeout, FR-db-enrichment-14."""
        payload = {"application": "Test Client", "type": "ja4", "notes": ""}
        recorder = RecordingRequests(response=StubResponse(payload=payload))
        client = JA4DBClient(allow_remote=True)
        with patch.dict("sys.modules", {"requests": recorder}):
            client.lookup(MISSING_FINGERPRINT)
        assert recorder.calls[0][1]["timeout"] == _REMOTE_TIMEOUT
        assert _REMOTE_TIMEOUT == 5.0


class TestARemoteLookupFailure:
    """A remote lookup failure returns nothing and does not raise,
    FR-db-enrichment-15."""

    def test_a_remote_lookup_that_times_out_returns_none(self):
        class Timeout(OSError):
            """The failure `requests` raises when the service answers too late."""

        recorder = RecordingRequests(error=Timeout("Connection timed out"))
        client = JA4DBClient(allow_remote=True)
        with patch.dict("sys.modules", {"requests": recorder}):
            assert client.lookup(MISSING_FINGERPRINT) is None

    def test_a_status_other_than_200_returns_none(self):
        recorder = RecordingRequests(response=StubResponse(status_code=404, payload={}))
        client = JA4DBClient(allow_remote=True)
        with patch.dict("sys.modules", {"requests": recorder}):
            assert client.lookup(MISSING_FINGERPRINT) is None

    def test_a_body_that_holds_no_json_returns_none(self):
        recorder = RecordingRequests(
            response=StubResponse(error=ValueError("no JSON object could be decoded"))
        )
        client = JA4DBClient(allow_remote=True)
        with patch.dict("sys.modules", {"requests": recorder}):
            assert client.lookup(MISSING_FINGERPRINT) is None

    @pytest.mark.parametrize(
        "payload",
        [
            None,
            [],
            [{"application": "Test Client"}],
            "Test Client",
            {},
            {"error": "no such fingerprint"},
            {"application": ""},
            {"application": None},
            {"application": 7},
        ],
        ids=[
            "none",
            "empty list",
            "list of one match",
            "string",
            "empty object",
            "error object",
            "empty application",
            "null application",
            "numeric application",
        ],
    )
    def test_a_response_with_an_unexpected_shape_returns_none(self, payload):
        """The service publishes no versioned API document, so an unexpected shape is a
        miss."""
        recorder = RecordingRequests(response=StubResponse(payload=payload))
        client = JA4DBClient(allow_remote=True)
        with patch.dict("sys.modules", {"requests": recorder}):
            assert client.lookup(MISSING_FINGERPRINT) is None

    def test_a_response_that_holds_no_type_and_no_notes_returns_empty_strings(self):
        """The application name is the one field the client needs."""
        recorder = RecordingRequests(response=StubResponse(payload={"application": "Test Client"}))
        client = JA4DBClient(allow_remote=True)
        with patch.dict("sys.modules", {"requests": recorder}):
            result = client.lookup(MISSING_FINGERPRINT)
        assert result == {"application": "Test Client", "type": "", "notes": ""}

    def test_a_response_with_a_numeric_type_returns_an_empty_type(self):
        """The client never lets an unexpected field shape reach the caller."""
        recorder = RecordingRequests(
            response=StubResponse(payload={"application": "Test Client", "type": 4})
        )
        client = JA4DBClient(allow_remote=True)
        with patch.dict("sys.modules", {"requests": recorder}):
            result = client.lookup(MISSING_FINGERPRINT)
        assert result == {"application": "Test Client", "type": "", "notes": ""}

    def test_an_absent_requests_package_returns_none(self):
        """The `lookup` extra installs `requests`, and the client works without it."""
        client = JA4DBClient(allow_remote=True)
        with patch.dict("sys.modules", {"requests": None}):
            assert client.lookup(MISSING_FINGERPRINT) is None
