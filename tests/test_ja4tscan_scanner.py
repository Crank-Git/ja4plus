"""Measure the scan loop on a fake network, with no packet sent and no socket open.

`docs/specs/features/12-active-scan.md` states each requirement these cases name. The
loop takes the send function, the receive function and the clock as parameters, so a
case scripts what each target answers and reads what the loop writes.
"""

from __future__ import annotations

import random

import pytest
from scapy.all import ICMP, IP, TCP, Ether

from ja4plus.scan.scanner import (
    MAX_TARGETS,
    NO_RETRANSMIT_WAIT_SECONDS,
    RETRANSMIT_WAIT_SECONDS,
    Scanner,
    ScanResult,
    TargetError,
    firewall_rules,
    parse_targets,
)
from tests.scan_fakes import SCANNER_IP, FakeNetwork, Script, syn_ack_script

TARGET = "192.0.2.10"


def scan(
    network: FakeNetwork,
    targets: list[str],
    *,
    retransmit: bool = True,
    rate: float = 10.0,
    port: int = 80,
) -> tuple[list[ScanResult], list[str], Scanner]:
    """Run one scan over the fake network, and return the results, the warnings and the scanner."""
    results: list[ScanResult] = []
    warnings: list[str] = []
    scanner = Scanner(
        port=port,
        rate=rate,
        retransmit=retransmit,
        send=network.send,
        receive=network.receive,
        clock=network.clock,
        on_result=results.append,
        on_warning=warnings.append,
        rng=random.Random(7),
    )
    scanner.run(targets)
    return results, warnings, scanner


class TestOneSynForEachTarget:
    def test_a_target_that_sends_one_syn_ack_receives_one_send(self):
        network = FakeNetwork({TARGET: syn_ack_script(0.05)})
        scan(network, [TARGET])
        assert len(network.sent) == 1

    def test_a_target_that_answers_with_retransmissions_receives_one_send(self):
        network = FakeNetwork({TARGET: syn_ack_script(0.05, 1.05, 3.05)})
        scan(network, [TARGET])
        assert [target for target, _, _ in network.sent] == [TARGET]

    def test_the_loop_sends_to_each_named_target_once_and_to_no_other_address(self):
        targets = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
        network = FakeNetwork()
        scan(network, targets)
        assert [target for target, _, _ in network.sent] == targets


class TestResults:
    def test_a_syn_ack_and_four_retransmissions_write_one_result(self):
        network = FakeNetwork({TARGET: syn_ack_script(0.1, 1.1, 3.1, 7.1, 15.1)})
        results, warnings, _ = scan(network, [TARGET])
        assert len(results) == 1
        assert results[0].value == "64240_2_1460_00_1-2-4-8"
        assert warnings == []

    def test_the_result_names_the_target_as_the_source_and_the_scanner_as_the_destination(self):
        network = FakeNetwork({TARGET: syn_ack_script(0.1)}, port=443)
        results, _, _ = scan(network, [TARGET], port=443)
        (_, src_port, _) = network.sent[0]
        result = results[0]
        assert (result.src_ip, result.src_port) == (TARGET, 443)
        assert (result.dst_ip, result.dst_port) == (SCANNER_IP, src_port)

    def test_the_result_time_is_the_receive_time_of_the_last_response(self):
        network = FakeNetwork({TARGET: syn_ack_script(0.1, 1.1, 3.1)})
        start = network.now
        results, _, _ = scan(network, [TARGET])
        assert results[0].seconds == pytest.approx(start + 3.1)

    def test_a_target_that_sends_no_response_writes_no_result(self):
        results, warnings, _ = scan(FakeNetwork(), [TARGET])
        assert results == []
        assert warnings == []

    def test_a_first_response_that_carries_rst_writes_rst_ack(self):
        network = FakeNetwork({TARGET: Script([0.1], ["R"], window=0)})
        results, warnings, _ = scan(network, [TARGET])
        assert [result.value for result in results] == ["0_rst-ack"]
        assert warnings == []

    def test_a_rst_ack_with_a_window_of_512_writes_rst_ack(self):
        network = FakeNetwork({TARGET: Script([0.1], ["RA"], window=512)})
        results, _, _ = scan(network, [TARGET])
        assert [result.value for result in results] == ["0_rst-ack"]

    def test_a_syn_ack_then_a_rst_writes_the_rst_delay(self):
        network = FakeNetwork({TARGET: Script([0.1, 1.1, 7.1], ["SA", "SA", "R"])})
        results, warnings, _ = scan(network, [TARGET])
        assert [result.value for result in results] == ["64240_2_1460_00_1-R6"]
        assert warnings == []

    def test_an_icmp_message_that_answers_the_syn_writes_no_result(self):
        network = FakeNetwork()
        quoted = IP(src=SCANNER_IP, dst=TARGET) / TCP(sport=50000, dport=80, flags="S")
        frame = bytes(Ether() / IP(src=TARGET, dst=SCANNER_IP) / ICMP(type=3, code=3) / quoted)
        network.push(network.now + 0.1, frame)
        results, warnings, _ = scan(network, [TARGET])
        assert results == []
        assert warnings == []

    def test_every_truncation_of_a_response_raises_nothing_and_writes_nothing(self):
        network = FakeNetwork()
        frame = bytes(
            Ether()
            / IP(src=TARGET, dst=SCANNER_IP)
            / TCP(sport=80, flags="SA", options=[("MSS", 1460)])
        )
        for end in range(len(frame)):
            network.push(network.now + 0.001 * end, frame[:end])
        results, _, _ = scan(network, [TARGET])
        assert results == []


class TestTheAcknowledgmentRule:
    def test_a_syn_ack_that_acknowledges_another_sequence_number_writes_nothing(self):
        network = FakeNetwork({TARGET: Script([0.1], ["SA"], ack_delta=2)})
        results, _, _ = scan(network, [TARGET])
        assert results == []

    def test_a_syn_ack_that_acknowledges_the_sequence_number_itself_writes_nothing(self):
        network = FakeNetwork({TARGET: Script([0.1], ["SA"], ack_delta=0)})
        results, _, _ = scan(network, [TARGET])
        assert results == []

    def test_a_rst_that_acknowledges_the_sequence_number_itself_is_a_response(self):
        network = FakeNetwork({TARGET: Script([0.1], ["R"], ack_delta=0)})
        results, _, _ = scan(network, [TARGET])
        assert [result.value for result in results] == ["0_rst-ack"]

    def test_a_response_from_another_port_writes_nothing(self):
        network = FakeNetwork({TARGET: Script([0.1], ["SA"], src_port=81)})
        results, _, _ = scan(network, [TARGET])
        assert results == []

    def test_a_response_from_an_address_the_scan_never_named_writes_nothing(self):
        network = FakeNetwork({"192.0.2.99": syn_ack_script(0.1)})
        network.send("192.0.2.99", 50000, 1)
        results, _, _ = scan(network, [TARGET])
        assert results == []


class TestTheWarning:
    def test_one_syn_ack_and_no_later_response_writes_one_warning_line(self):
        network = FakeNetwork({TARGET: syn_ack_script(0.1)})
        results, warnings, _ = scan(network, [TARGET])
        assert [result.value for result in results] == ["64240_2_1460_00"]
        assert len(warnings) == 1
        assert TARGET in warnings[0]
        assert "\n" not in warnings[0]

    def test_no_retransmission_mode_writes_no_warning(self):
        network = FakeNetwork({TARGET: syn_ack_script(0.1)})
        results, warnings, _ = scan(network, [TARGET], retransmit=False)
        assert len(results) == 1
        assert warnings == []


class TestTheWait:
    def test_the_loop_waits_120_seconds_after_the_last_syn(self):
        network = FakeNetwork()
        start = network.now
        scan(network, [TARGET])
        assert RETRANSMIT_WAIT_SECONDS == 120
        assert network.now == pytest.approx(start + 120)

    def test_no_retransmission_mode_waits_8_seconds_after_the_last_syn(self):
        network = FakeNetwork()
        start = network.now
        scan(network, [TARGET], retransmit=False)
        assert NO_RETRANSMIT_WAIT_SECONDS == 8
        assert network.now == pytest.approx(start + 8)

    def test_a_response_after_the_wait_changes_nothing(self):
        network = FakeNetwork({TARGET: syn_ack_script(0.1, 121.0)})
        results, _, _ = scan(network, [TARGET])
        assert [result.value for result in results] == ["64240_2_1460_00"]

    def test_no_retransmission_mode_reads_the_first_response_alone(self):
        network = FakeNetwork({TARGET: syn_ack_script(0.1, 1.1, 3.1)})
        results, _, _ = scan(network, [TARGET], retransmit=False)
        assert [result.value for result in results] == ["64240_2_1460_00"]

    def test_the_rate_sets_the_syn_count_for_each_second(self):
        network = FakeNetwork()
        start = network.now
        times: list[float] = []
        network.on_send = lambda target: times.append(network.now - start)
        scan(network, ["192.0.2.1", "192.0.2.2", "192.0.2.3"], rate=4)
        assert times == pytest.approx([0.0, 0.25, 0.5])


class TestTheStateTable:
    def test_the_state_table_holds_at_most_10000_targets_under_20000_targets(self):
        network = FakeNetwork()
        sizes: list[int] = []
        results: list[ScanResult] = []
        scanner = Scanner(
            port=80,
            rate=1_000_000,
            retransmit=True,
            send=network.send,
            receive=network.receive,
            clock=network.clock,
            on_result=results.append,
            on_warning=lambda line: None,
            rng=random.Random(1),
        )
        network.on_send = lambda target: sizes.append(len(scanner.table))
        targets = [
            f"10.{index >> 16 & 255}.{index >> 8 & 255}.{index & 255}" for index in range(20000)
        ]
        scanner.run(targets)
        assert MAX_TARGETS == 10000
        assert len(network.sent) == 20000
        assert max(sizes) == MAX_TARGETS - 1
        assert len(scanner.table) == 0

    def test_a_target_leaves_the_table_when_its_wait_ends(self):
        network = FakeNetwork({TARGET: syn_ack_script(0.1)})
        _, _, scanner = scan(network, [TARGET])
        assert scanner.table == {}

    def test_a_flooding_target_holds_a_bounded_response_list(self):
        offsets = [0.1 + index * 0.001 for index in range(500)]
        network = FakeNetwork({TARGET: syn_ack_script(*offsets)})
        stored: list[int] = []
        results: list[ScanResult] = []
        scanner = Scanner(
            port=80,
            rate=10,
            retransmit=True,
            send=network.send,
            receive=network.receive,
            clock=network.clock,
            on_result=results.append,
            on_warning=lambda line: None,
            rng=random.Random(1),
        )
        original = scanner._finish

        def finish(probe):
            stored.append(len(probe.responses))
            original(probe)

        scanner._finish = finish
        scanner.run([TARGET])
        assert stored == [11]
        assert results[0].value.count("-") == 9

    def test_flush_writes_the_result_of_every_target_the_table_holds(self):
        network = FakeNetwork({TARGET: syn_ack_script(0.1, 1.1)})
        results: list[ScanResult] = []
        scanner = Scanner(
            port=80,
            rate=10,
            retransmit=True,
            send=network.send,
            receive=network.receive,
            clock=network.clock,
            on_result=results.append,
            on_warning=lambda line: None,
            rng=random.Random(1),
        )
        scanner.start(TARGET)
        scanner.receive_until(network.now + 2)
        scanner.flush()
        assert [result.value for result in results] == ["64240_2_1460_00_1"]
        assert scanner.table == {}


class TestTargets:
    def test_one_ipv4_address_is_one_target(self):
        assert list(parse_targets("192.0.2.7")) == ["192.0.2.7"]

    def test_an_ipv4_network_names_every_address_it_holds(self):
        targets = list(parse_targets("203.0.113.0/30"))
        assert targets == ["203.0.113.0", "203.0.113.1", "203.0.113.2", "203.0.113.3"]

    def test_a_file_names_one_address_on_each_line(self, tmp_path):
        path = tmp_path / "hosts.txt"
        path.write_text("192.0.2.1\n\n192.0.2.2\n192.0.2.1\n", encoding="utf-8")
        assert list(parse_targets(str(path))) == ["192.0.2.1", "192.0.2.2"]

    def test_a_file_line_that_is_no_ipv4_address_names_the_line(self, tmp_path):
        path = tmp_path / "hosts.txt"
        path.write_text("192.0.2.1\nnot-an-address\n", encoding="utf-8")
        with pytest.raises(TargetError, match="line 2.*not-an-address"):
            parse_targets(str(path))

    @pytest.mark.parametrize("text", ["2001:db8::1", "2001:db8::/64"])
    def test_an_ipv6_target_states_that_the_scanner_reads_ipv4_alone(self, text):
        with pytest.raises(TargetError, match="IPv4 alone"):
            parse_targets(text)

    def test_an_ipv6_line_in_a_file_states_that_the_scanner_reads_ipv4_alone(self, tmp_path):
        path = tmp_path / "hosts.txt"
        path.write_text("2001:db8::1\n", encoding="utf-8")
        with pytest.raises(TargetError, match="IPv4 alone"):
            parse_targets(str(path))

    def test_a_target_that_is_no_address_no_network_and_no_file_is_refused(self, tmp_path):
        with pytest.raises(TargetError, match="no IPv4 address"):
            parse_targets(str(tmp_path / "absent.txt"))


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


class TestTheFirewallRules:
    def test_linux_states_the_four_foxio_rules_and_the_four_removals(self):
        lines = firewall_rules("linux").splitlines()
        for rule in LINUX_RULES + LINUX_REMOVALS:
            assert rule in lines
        assert lines.index(LINUX_RULES[-1]) < lines.index(LINUX_REMOVALS[0])

    def test_macos_states_the_four_pf_rules(self):
        lines = firewall_rules("darwin").splitlines()
        for rule in PF_RULES:
            assert rule in lines
        assert not any(line.startswith("iptables") for line in lines)

    def test_the_text_states_that_the_scanner_changes_no_firewall_state(self):
        assert "changes no firewall state" in firewall_rules("linux")
