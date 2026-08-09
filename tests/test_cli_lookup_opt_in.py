"""The command reaches the lookup service only when the operator asks for it, issue #58.

A fingerprint describes traffic the operator observed. A request to the lookup service
discloses that traffic to a third party. The cases below prove that `--lookup` attempts
no request, that `--lookup-remote` and `JA4PLUS_DB_LOOKUP=1` each permit one, and that
the notice appears once for a run that performs several lookups.

The cases measure the attempt and not the result. They install the recording stand-in of
`tests/test_db_offline.py` in `sys.modules`, so a run against an unrepaired command
records every request it tries to send.
"""

import io
import os
import sys
from unittest.mock import patch

import pytest

from tests.test_db_offline import RecordingRequests, StubResponse

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
HTTP_CAP = os.path.join(DATA_DIR, "http.cap")
CERT_DER = os.path.join(DATA_DIR, "test_cert.der")

# The name of the environment variable FR-db-enrichment-5 states.
ENV_NAME = "JA4PLUS_DB_LOOKUP"


def run_cli(*argv):
    """Run the command and return its standard output, standard error and exit status.

    Args:
        *argv: The arguments that follow the program name.

    Returns:
        A tuple of the standard output, the standard error and the exit status. The
        status is zero when `main` returns.
    """
    from ja4plus.cli import main

    captured_out = io.StringIO()
    captured_err = io.StringIO()
    exit_code = 0
    with (
        patch("sys.argv", ["ja4plus"] + list(argv)),
        patch("sys.stdout", captured_out),
        patch("sys.stderr", captured_err),
    ):
        try:
            main()
        except SystemExit as e:
            exit_code = e.code if e.code is not None else 0
    return captured_out.getvalue(), captured_err.getvalue(), exit_code


@pytest.fixture
def recorder():
    """Return a stand-in for `requests` that records every call and reaches no network.

    Every response reports a miss, so the run writes the output it writes without a
    lookup and the case measures the requests alone.
    """
    return RecordingRequests(response=StubResponse(status_code=200, payload=None))


@pytest.fixture
def no_env(monkeypatch):
    """Remove the opt-in environment variable that the host may hold.

    Args:
        monkeypatch: The pytest fixture that restores the environment after the case.
    """
    monkeypatch.delenv(ENV_NAME, raising=False)


def analyze(recorder, *argv):
    """Run `analyze` over the bundled capture with the stand-in installed.

    Args:
        recorder: The stand-in for `requests`.
        *argv: The options the case passes.

    Returns:
        The tuple that `run_cli` returns.
    """
    with patch.dict(sys.modules, {"requests": recorder}):
        return run_cli("analyze", HTTP_CAP, *argv)


def notice_count(stderr):
    """Return the count of disclosure notices the standard error holds.

    Args:
        stderr: The standard error of one run.

    Returns:
        The count of notices.
    """
    from ja4plus.cli import _REMOTE_LOOKUP_NOTICE

    return stderr.count(_REMOTE_LOOKUP_NOTICE)


class TestTheLocalOption:
    """`--lookup` performs a local lookup only, FR-db-enrichment-3."""

    def test_the_local_option_attempts_no_request(self, recorder, no_env):
        out, err, code = analyze(recorder, "--lookup")
        assert code == 0, err
        assert recorder.calls == []

    def test_the_local_option_writes_no_notice(self, recorder, no_env):
        """An operator who asked for no disclosure reads no notice about one."""
        out, err, code = analyze(recorder, "--lookup")
        assert notice_count(err) == 0

    def test_the_local_option_identifies_a_fingerprint_from_the_mapping_file(
        self, recorder, no_env
    ):
        """The local lookup still names the applications the mapping file holds."""
        out, err, code = analyze(recorder, "--lookup")
        assert code == 0, err
        assert out.strip() != ""

    def test_no_option_attempts_no_request(self, recorder, no_env):
        """A run without `--lookup` builds no client at all."""
        out, err, code = analyze(recorder)
        assert code == 0, err
        assert recorder.calls == []
        assert notice_count(err) == 0


class TestTheRemoteOption:
    """`--lookup-remote` permits the remote lookup, FR-db-enrichment-4."""

    def test_the_remote_option_permits_the_request(self, recorder, no_env):
        out, err, code = analyze(recorder, "--lookup-remote")
        assert code == 0, err
        assert recorder.calls != []

    def test_the_remote_option_needs_no_local_option(self, recorder, no_env):
        """`--lookup-remote` asks for the lookup as well as for the disclosure."""
        out, err, code = analyze(recorder, "--lookup-remote")
        assert notice_count(err) == 1

    def test_the_two_options_together_build_one_client_and_write_one_notice(self, recorder, no_env):
        """An operator who passes both options asks for one lookup and one disclosure."""
        out, err, code = analyze(recorder, "--lookup", "--lookup-remote")
        assert code == 0, err
        assert recorder.calls != []
        assert notice_count(err) == 1

    def test_the_remote_option_reaches_the_lookup_service(self, recorder, no_env):
        """Every request the run sends names the service the notice names."""
        analyze(recorder, "--lookup-remote")
        for url, _kwargs in recorder.calls:
            assert url.startswith("https://ja4db.com/api/read/")

    def test_the_remote_option_runs_before_the_subcommand_name_too(self, recorder, no_env):
        """The output options run on both sides of the subcommand name."""
        with patch.dict(sys.modules, {"requests": recorder}):
            out, err, code = run_cli("--lookup-remote", "analyze", HTTP_CAP)
        assert code == 0, err
        assert recorder.calls != []
        assert notice_count(err) == 1

    def test_the_remote_option_permits_the_request_for_the_cert_command(self, recorder, no_env):
        """`cert` builds the client from the same options."""
        with patch.dict(sys.modules, {"requests": recorder}):
            out, err, code = run_cli("cert", CERT_DER, "--lookup-remote")
        assert code == 0, err
        assert notice_count(err) == 1


class TestTheNotice:
    """The command reports the disclosure once, on standard error, FR-db-enrichment-6."""

    def test_the_run_performs_several_lookups(self, recorder, no_env):
        """The case below cannot separate one notice per run from one notice per lookup
        unless the run performs more than one lookup."""
        analyze(recorder, "--lookup-remote")
        assert len(recorder.calls) > 1

    def test_the_notice_appears_once_for_a_run_that_performs_several_lookups(
        self, recorder, no_env
    ):
        out, err, code = analyze(recorder, "--lookup-remote")
        assert len(recorder.calls) > 1
        assert notice_count(err) == 1

    def test_the_notice_goes_to_standard_error(self, recorder, no_env):
        """A notice on standard output would enter the pipe that carries the results."""
        out, err, code = analyze(recorder, "--lookup-remote", "--format", "json")
        assert notice_count(err) == 1
        assert notice_count(out) == 0

    def test_the_notice_names_the_lookup_service(self, recorder, no_env):
        """An operator learns which third party the run tells about the traffic."""
        out, err, code = analyze(recorder, "--lookup-remote")
        assert "ja4db.com" in err

    def test_the_notice_names_the_option_that_causes_the_disclosure(self, recorder, no_env):
        """An operator learns how to stop the disclosure from the notice itself."""
        out, err, code = analyze(recorder, "--lookup-remote")
        assert "--lookup-remote" in err
        assert ENV_NAME in err


class TestTheEnvironmentVariable:
    """`JA4PLUS_DB_LOOKUP` set to 1 permits the remote lookup, FR-db-enrichment-5."""

    def test_the_value_one_permits_the_request(self, recorder, monkeypatch):
        monkeypatch.setenv(ENV_NAME, "1")
        out, err, code = analyze(recorder, "--lookup")
        assert code == 0, err
        assert recorder.calls != []

    def test_the_value_one_writes_the_notice_once(self, recorder, monkeypatch):
        """An opt-in that the operator can enable in silence is the defect Epic 7
        closes."""
        monkeypatch.setenv(ENV_NAME, "1")
        out, err, code = analyze(recorder, "--lookup")
        assert len(recorder.calls) > 1
        assert notice_count(err) == 1

    @pytest.mark.parametrize("value", ["0", "", "true", "yes", "2", "01"], ids=repr)
    def test_a_value_other_than_one_attempts_no_request(self, recorder, monkeypatch, value):
        """FR-db-enrichment-5 names the value 1 and no other value."""
        monkeypatch.setenv(ENV_NAME, value)
        out, err, code = analyze(recorder, "--lookup")
        assert recorder.calls == []
        assert notice_count(err) == 0

    def test_the_variable_alone_performs_no_lookup(self, recorder, monkeypatch):
        """The variable permits the disclosure. It asks for no lookup, so a run that
        names no option looks nothing up and discloses nothing."""
        monkeypatch.setenv(ENV_NAME, "1")
        out, err, code = analyze(recorder)
        assert code == 0, err
        assert recorder.calls == []
        assert notice_count(err) == 0

    def test_the_value_zero_cancels_no_option(self, recorder, monkeypatch):
        """The option and the variable each permit the disclosure, and neither one
        refuses it. `--lookup-remote` therefore holds against any value."""
        monkeypatch.setenv(ENV_NAME, "0")
        out, err, code = analyze(recorder, "--lookup-remote")
        assert recorder.calls != []
        assert notice_count(err) == 1


class TestTheAbsentRequestsPackage:
    """`requests` is absent while the operator asks for the remote lookup."""

    def test_the_remote_option_exits_with_status_1(self, no_env):
        with patch.dict(sys.modules, {"requests": None}):
            out, err, code = run_cli("analyze", HTTP_CAP, "--lookup-remote")
        assert code == 1

    def test_the_remote_option_names_the_extra_to_install(self, no_env):
        with patch.dict(sys.modules, {"requests": None}):
            out, err, code = run_cli("analyze", HTTP_CAP, "--lookup-remote")
        assert "ja4plus[lookup]" in err

    def test_the_environment_variable_exits_with_status_1_too(self, monkeypatch):
        monkeypatch.setenv(ENV_NAME, "1")
        with patch.dict(sys.modules, {"requests": None}):
            out, err, code = run_cli("analyze", HTTP_CAP, "--lookup")
        assert code == 1
        assert "ja4plus[lookup]" in err

    def test_the_local_option_runs_without_the_package(self, no_env):
        """The local lookup reads the mapping file, which needs no package."""
        with patch.dict(sys.modules, {"requests": None}):
            out, err, code = run_cli("analyze", HTTP_CAP, "--lookup")
        assert code == 0, err
        assert out.strip() != ""
