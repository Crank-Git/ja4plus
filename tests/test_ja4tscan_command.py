"""Measure the `ja4plus scan` subcommand on a fake network.

`docs/specs/features/12-active-scan.md` states the command. No case sends a packet or
opens a raw socket. Each case either stops before the network opens, or it passes the
fake network of `tests/scan_fakes.py` in place of the link-layer socket.
"""

from __future__ import annotations

import argparse
import errno
import io
import json
import random
import sys

import pytest

import ja4plus.cli as cli
from ja4plus.output import CSV_COLUMNS
from ja4plus.scan import command
from ja4plus.scan.command import scan_command
from tests.scan_fakes import FakeNetwork, syn_ack_script

TARGET = "192.0.2.10"

LINUX_RULES = [
    "iptables -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
    "iptables -t filter -A INPUT -p icmp -j ACCEPT",
    "iptables -t filter -A INPUT -i lo -j ACCEPT",
    "iptables -t filter -A INPUT -j DROP",
]
LINUX_REMOVALS = [
    "iptables -t filter -D INPUT -j DROP",
    "iptables -t filter -D INPUT -i lo -j ACCEPT",
    "iptables -t filter -D INPUT -p icmp -j ACCEPT",
    "iptables -t filter -D INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
]
PF_RULES = [
    "pass out all",
    "pass in quick inet proto icmp all",
    "pass in quick on lo0 all",
    "block drop in all",
]


def namespace(**overrides: object) -> argparse.Namespace:
    """Return the parsed command line of one scan, with the defaults of the parser."""
    fields: dict[str, object] = {
        "command": "scan",
        "target": TARGET,
        "port": 80,
        "rate": 10.0,
        "retransmit": "yes",
        "format": "json",
        "output": None,
        "force": False,
    }
    fields.update(overrides)
    return argparse.Namespace(**fields)


class Run:
    """Holds what one fake scan wrote to standard output and standard error."""

    def __init__(self, stdout: str, stderr: str, stderr_at_first_send: str | None) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.stderr_at_first_send = stderr_at_first_send


def fake_scan(
    monkeypatch: pytest.MonkeyPatch,
    network: FakeNetwork,
    *,
    platform: str = "linux",
    **overrides: object,
) -> Run:
    """Run `scan_command` over the fake network, and return what it wrote."""
    stdout, stderr = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)
    snapshot: list[str] = []

    def on_send(target: str) -> None:
        if not snapshot:
            snapshot.append(stderr.getvalue())

    network.on_send = on_send
    scan_command(
        namespace(**overrides),
        result_stream=cli._result_stream,
        platform=platform,
        open_network=lambda port, first, warn: network,
        clock=network.clock,
        rng=random.Random(3),
    )
    return Run(stdout.getvalue(), stderr.getvalue(), snapshot[0] if snapshot else None)


def run_main(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture, *argv: str):
    """Run `ja4plus.cli.main` with the arguments, and return the exit status and the output."""
    monkeypatch.setattr(sys, "argv", ["ja4plus", *argv])
    code = 0
    try:
        cli.main()
    except SystemExit as exit_:
        code = exit_.code if isinstance(exit_.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    """Replace the link-layer socket, and record every open of it."""
    opened: list[tuple] = []

    def refuse(*args: object) -> None:
        opened.append(args)
        raise AssertionError("the case opened the network")

    monkeypatch.setattr(command, "LinkNetwork", refuse)
    return opened


class TestTheInterface:
    def test_the_help_names_every_option_of_the_interface(self, monkeypatch, capsys):
        code, out, _ = run_main(monkeypatch, capsys, "scan", "--help")
        assert code == 0
        for option in ("--port", "--rate", "--retransmit", "--format", "--output", "--force"):
            assert option in out

    def test_the_defaults_are_the_foxio_defaults(self):
        assert (cli.SCAN_DEFAULT_PORT, cli.SCAN_DEFAULT_RATE) == (80, 10.0)

    @pytest.mark.parametrize("value", ["0", "65536", "http"])
    def test_a_port_outside_1_to_65535_is_refused(self, monkeypatch, capsys, no_network, value):
        code, _, err = run_main(monkeypatch, capsys, "scan", TARGET, "--port", value)
        assert code == 2
        assert "--port" in err
        assert no_network == []

    @pytest.mark.parametrize("value", ["0", "-1", "nan", "fast"])
    def test_a_rate_that_is_not_above_zero_is_refused(self, monkeypatch, capsys, no_network, value):
        code, _, err = run_main(monkeypatch, capsys, "scan", TARGET, "--rate", value)
        assert code == 2
        assert "--rate" in err
        assert no_network == []


class TestARefusalSendsNothing:
    def test_an_ipv6_target_exits_with_status_1_and_sends_nothing(
        self, monkeypatch, capsys, no_network
    ):
        code, out, err = run_main(monkeypatch, capsys, "scan", "2001:db8::1")
        assert code == 1
        assert "IPv4 alone" in err
        assert out == ""
        assert no_network == []

    def test_a_file_line_that_is_no_ipv4_address_exits_with_status_1_and_sends_nothing(
        self, monkeypatch, capsys, no_network, tmp_path
    ):
        path = tmp_path / "hosts.txt"
        path.write_text("192.0.2.1\n192.0.2.300\n", encoding="utf-8")
        code, _, err = run_main(monkeypatch, capsys, "scan", str(path))
        assert code == 1
        assert "line 2" in err
        assert "192.0.2.300" in err
        assert no_network == []

    def test_an_empty_target_file_exits_with_status_1(
        self, monkeypatch, capsys, no_network, tmp_path
    ):
        path = tmp_path / "hosts.txt"
        path.write_text("\n", encoding="utf-8")
        code, _, err = run_main(monkeypatch, capsys, "scan", str(path))
        assert code == 1
        assert "names no address" in err

    @pytest.mark.parametrize("number", [errno.EPERM, errno.EACCES])
    def test_no_raw_socket_privilege_exits_with_status_1_and_sends_nothing(
        self, monkeypatch, capsys, number
    ):
        network = FakeNetwork()

        def refused(port, first, warn):
            raise PermissionError(number, "Operation not permitted")

        with pytest.raises(SystemExit) as exit_:
            scan_command(
                namespace(),
                result_stream=cli._result_stream,
                platform="linux",
                open_network=refused,
                clock=lambda: 0.0,
            )
        err = capsys.readouterr().err
        assert exit_.value.code == 1
        assert "privilege to open a raw socket" in err
        assert "CAP_NET_RAW" in err
        assert "iptables" not in err
        assert network.sent == []

    def test_another_socket_failure_exits_with_status_1(self, monkeypatch, capsys):
        def broken(port, first, warn):
            raise OSError(errno.ENODEV, "No such device")

        with pytest.raises(SystemExit) as exit_:
            scan_command(
                namespace(),
                result_stream=cli._result_stream,
                platform="linux",
                open_network=broken,
                clock=lambda: 0.0,
            )
        assert exit_.value.code == 1
        assert "could not open a raw socket" in capsys.readouterr().err

    def test_windows_exits_with_status_1(self, monkeypatch, capsys, no_network):
        with pytest.raises(SystemExit) as exit_:
            scan_command(
                namespace(),
                result_stream=cli._result_stream,
                platform="win32",
                open_network=command.LinkNetwork,
                clock=lambda: 0.0,
            )
        assert exit_.value.code == 1
        assert no_network == []

    def test_an_installation_without_the_scanner_names_the_scan_extra(self, monkeypatch, capsys):
        monkeypatch.setattr(cli, "entry_points", lambda **kwargs: [])
        code, _, err = run_main(monkeypatch, capsys, "scan", TARGET)
        assert code == 1
        assert "pip install ja4plus[scan]" in err

    def test_a_scanner_that_fails_to_import_names_the_scan_extra(self, monkeypatch, capsys):
        class Broken:
            def load(self):
                raise ImportError("No module named 'ja4plus.scan'")

        monkeypatch.setattr(cli, "entry_points", lambda **kwargs: [Broken()])
        code, _, err = run_main(monkeypatch, capsys, "scan", TARGET)
        assert code == 1
        assert "pip install ja4plus[scan]" in err

    def test_the_installed_entry_point_names_the_scan_command(self):
        (entry,) = cli.entry_points(group=cli.COMMAND_ENTRY_POINTS, name="scan")
        assert entry.value == "ja4plus.scan.command:run"
        assert entry.load() is command.run


class TestTheFirewallRules:
    def test_linux_writes_the_four_iptables_rules_before_the_first_syn(self, monkeypatch):
        run = fake_scan(monkeypatch, FakeNetwork(), platform="linux")
        before = run.stderr_at_first_send.splitlines()
        for rule in LINUX_RULES:
            assert rule in before

    def test_linux_writes_the_four_removal_commands(self, monkeypatch):
        run = fake_scan(monkeypatch, FakeNetwork(), platform="linux")
        lines = run.stderr.splitlines()
        for rule in LINUX_REMOVALS:
            assert rule in lines

    def test_macos_writes_the_four_pf_rules_before_the_first_syn(self, monkeypatch):
        run = fake_scan(monkeypatch, FakeNetwork(), platform="darwin")
        before = run.stderr_at_first_send.splitlines()
        for rule in PF_RULES:
            assert rule in before
        assert "iptables" not in run.stderr

    def test_no_retransmission_mode_writes_no_firewall_rule(self, monkeypatch):
        run = fake_scan(monkeypatch, FakeNetwork(), platform="linux", retransmit="no")
        assert "iptables" not in run.stderr
        assert "pass out all" not in run.stderr

    def test_the_rules_reach_standard_error_and_never_standard_output(self, monkeypatch):
        run = fake_scan(monkeypatch, FakeNetwork(), platform="linux", format="table")
        assert "iptables" not in run.stdout


class TestTheResult:
    def test_the_json_object_holds_the_eleven_fields_with_the_type_ja4tscan(self, monkeypatch):
        network = FakeNetwork({TARGET: syn_ack_script(0.1, 1.1)})
        run = fake_scan(monkeypatch, network)
        (line,) = run.stdout.splitlines()
        record = json.loads(line)
        assert set(record) == set(CSV_COLUMNS)
        assert len(record) == 11
        assert record["type"] == "ja4tscan"
        assert record["fingerprint"] == "64240_2_1460_00_1"
        assert (record["src_ip"], record["src_port"]) == (TARGET, 80)
        assert record["dst_ip"] == "198.51.100.1"
        assert record["raw"] is None and record["identified_as"] is None
        assert record["schema_version"] == 1

    def test_a_target_that_sends_one_syn_ack_writes_one_warning_line(self, monkeypatch):
        run = fake_scan(monkeypatch, FakeNetwork({TARGET: syn_ack_script(0.1)}))
        warnings = [line for line in run.stderr.splitlines() if line.startswith("Warning:")]
        assert len(warnings) == 1
        assert TARGET in warnings[0]

    def test_no_retransmission_mode_writes_no_warning_line(self, monkeypatch):
        network = FakeNetwork({TARGET: syn_ack_script(0.1)})
        run = fake_scan(monkeypatch, network, retransmit="no")
        assert "Warning:" not in run.stderr
        assert len(run.stdout.splitlines()) == 1

    def test_the_csv_format_writes_a_header_and_one_row(self, monkeypatch):
        network = FakeNetwork({TARGET: syn_ack_script(0.1, 1.1)})
        run = fake_scan(monkeypatch, network, format="csv")
        lines = run.stdout.splitlines()
        assert len(lines) == 2
        assert "ja4tscan" in lines[1]

    def test_an_output_file_that_exists_is_refused_before_the_first_syn(
        self, monkeypatch, tmp_path
    ):
        path = tmp_path / "out.json"
        path.write_text("keep", encoding="utf-8")
        network = FakeNetwork()
        with pytest.raises(SystemExit):
            fake_scan(monkeypatch, network, output=str(path))
        assert network.sent == []
        assert path.read_text(encoding="utf-8") == "keep"

    def test_an_interrupt_writes_the_result_of_each_target_that_answered(self, monkeypatch):
        network = FakeNetwork({TARGET: syn_ack_script(0.1, 1.1)})
        receive = network.receive

        def interrupt_after_two(timeout):
            if len(network.queue) == 0:
                raise KeyboardInterrupt
            return receive(timeout)

        network.receive = interrupt_after_two
        stdout = io.StringIO()
        monkeypatch.setattr(sys, "stdout", stdout)
        monkeypatch.setattr(sys, "stderr", io.StringIO())
        with pytest.raises(KeyboardInterrupt):
            scan_command(
                namespace(),
                result_stream=cli._result_stream,
                platform="linux",
                open_network=lambda port, first, warn: network,
                clock=network.clock,
            )
        (line,) = stdout.getvalue().splitlines()
        assert json.loads(line)["fingerprint"] == "64240_2_1460_00_1"
