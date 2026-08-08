"""The typed result of `Processor.process_packet`, FR-typed-api-3 and FR-typed-api-4.

`docs/specs/features/04-typed-api.md` states both requirements. #45 changes the
container the processor returns. It changes no fingerprint value.
"""

import gc
import warnings
import weakref

import pytest
from scapy.all import IP, TCP, UDP, Ether, Raw

from ja4plus import FingerprintResult, Processor

# The order of `Processor._SPEC`. FR-typed-api-3 makes this order part of the interface,
# so the test states it as a literal and reads it from no attribute of the processor.
METHOD_ORDER = [
    "ja4",
    "ja4s",
    "ja4h",
    "ja4t",
    "ja4ts",
    "ja4l",
    "ja4x",
    "ja4ssh",
    "ja4d",
    "ja4d6",
]


def dhcp_discover():
    """Return one DHCP DISCOVER packet, which produces a JA4D fingerprint."""
    bootp = bytearray(236)
    bootp[0] = 1
    payload = bytes(bootp) + b"\x63\x82\x53\x63" + bytes([53, 1, 1, 255])
    return IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(load=payload)


def make_every_method_answer(processor):
    """Make every fingerprinter of the processor return one fixed value.

    A real packet reaches two methods at most, so it proves no order across the ten. A
    processor whose ten methods all answer proves the whole order.

    Args:
        processor: The processor to change.
    """
    for name, fingerprinter in processor.fingerprinters.items():
        fingerprinter.process_packet = lambda packet, name=name: f"{name}-value"


class RaisingFingerprinterError(Exception):
    """The error one fingerprinter raises inside these tests."""


def make_one_method_raise(processor, method):
    """Make one fingerprinter of the processor raise, and return the error it raises.

    Args:
        processor: The processor to change.
        method: The method name of the fingerprinter that raises.

    Returns:
        The exception object the fingerprinter raises.
    """
    error = RaisingFingerprinterError(f"{method} cannot read this packet")

    def raise_it(packet):
        raise error

    processor.fingerprinters[method].process_packet = raise_it
    return error


class TestProcessPacketReturnsTypedResults:
    """FR-typed-api-3 — `Processor.process_packet` returns a list of results."""

    def test_every_element_is_a_fingerprint_result(self):
        results = Processor().process_packet(dhcp_discover())

        assert results, "the DHCP packet produces at least one fingerprint"
        assert [type(result) for result in results] == [FingerprintResult] * len(results)

    def test_the_dhcp_packet_produces_a_ja4d_result(self):
        results = Processor().process_packet(dhcp_discover())

        assert "ja4d" in [result.type for result in results]

    def test_a_result_carries_the_endpoints_of_the_packet(self):
        results = Processor().process_packet(dhcp_discover())

        result = next(result for result in results if result.type == "ja4d")
        assert result.src_ip == "0.0.0.0"
        assert result.dst_ip == "255.255.255.255"
        assert result.src_port == 68
        assert result.dst_port == 67
        assert result.fingerprint

    def test_a_packet_with_no_address_layer_gives_empty_addresses_and_zero_ports(self):
        """`docs/specs/features/04-typed-api.md` states this case in its failure table."""
        processor = Processor()
        make_every_method_answer(processor)

        results = processor.process_packet(Ether())

        assert results, "every method answers, so the list holds ten results"
        for result in results:
            assert result.src_ip == ""
            assert result.dst_ip == ""
            assert result.src_port == 0
            assert result.dst_port == 0

    def test_reading_a_field_by_attribute_emits_no_deprecation_warning(self):
        """A caller who reads the attribute gets no warning. Item access warns."""
        results = Processor().process_packet(dhcp_discover())

        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            assert [result.type for result in results]

    def test_item_access_on_a_result_still_reads_the_same_value(self):
        """FR-typed-api-5 keeps the caller of version 0.6.0 working."""
        results = Processor().process_packet(dhcp_discover())

        with pytest.warns(DeprecationWarning):
            assert results[0]["type"] == results[0].type


class TestProcessPacketKeepsTheMethodOrder:
    """FR-typed-api-3 — the results come back in the fixed method order."""

    def test_the_ten_results_follow_the_order_of_the_spec_list(self):
        processor = Processor()
        make_every_method_answer(processor)

        results = processor.process_packet(dhcp_discover())

        assert [result.type for result in results] == METHOD_ORDER

    def test_a_method_that_produces_no_fingerprint_leaves_the_order_unchanged(self):
        processor = Processor()
        make_every_method_answer(processor)
        processor.fingerprinters["ja4h"].process_packet = lambda packet: None
        processor.fingerprinters["ja4t"].process_packet = lambda packet: None

        results = processor.process_packet(dhcp_discover())

        expected = [name for name in METHOD_ORDER if name not in ("ja4h", "ja4t")]
        assert [result.type for result in results] == expected


class TestProcessPacketWithErrors:
    """FR-typed-api-4 — the processor exposes the parse failures it collected."""

    def test_it_returns_the_exception_one_fingerprinter_raised(self):
        processor = Processor()
        error = make_one_method_raise(processor, "ja4")

        results, errors = processor.process_packet_with_errors(dhcp_discover())

        assert errors == [error]
        assert "ja4" not in [result.type for result in results]

    def test_it_returns_the_same_results_that_process_packet_returns(self):
        packet = dhcp_discover()
        results, errors = Processor().process_packet_with_errors(packet)

        assert errors == []
        assert results == Processor().process_packet(packet)

    def test_it_returns_one_error_for_every_method_that_raises(self):
        processor = Processor()
        first = make_one_method_raise(processor, "ja4")
        second = make_one_method_raise(processor, "ja4ssh")

        results, errors = processor.process_packet_with_errors(dhcp_discover())

        assert errors == [first, second]
        assert results

    def test_process_packet_raises_no_error_when_a_fingerprinter_raises(self):
        """One method that raises poisons no other method."""
        processor = Processor()
        make_one_method_raise(processor, "ja4")

        assert processor.process_packet(dhcp_discover())

    def test_it_returns_an_empty_list_of_results_and_the_error(self):
        """The failure table states this case. The packet reaches one method only."""
        processor = Processor()
        for name in METHOD_ORDER:
            processor.fingerprinters[name].process_packet = lambda packet: None
        error = make_one_method_raise(processor, "ja4t")

        results, errors = processor.process_packet_with_errors(
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=443, flags="S")
        )

        assert results == []
        assert errors == [error]

    def test_a_returned_error_holds_no_reference_to_the_packet(self):
        """`CLAUDE.md` states the rule that this case measures.

        A monitor that keeps the errors of every packet would hold every packet it read.
        An exception reaches the caller with its traceback, and the frames of that
        traceback hold the packet as a local, so the processor clears the traceback.
        """
        processor = Processor()
        make_one_method_raise(processor, "ja4")

        packet = dhcp_discover()
        alive = weakref.ref(packet)
        _, errors = processor.process_packet_with_errors(packet)
        del packet
        gc.collect()

        assert errors, "the case measures the errors the call returned"
        assert alive() is None, "the returned error holds the packet alive"

    def test_a_returned_error_keeps_its_type_and_its_message(self):
        """The traceback goes, and the value the caller reads stays."""
        processor = Processor()
        make_one_method_raise(processor, "ja4h")

        _, errors = processor.process_packet_with_errors(dhcp_discover())

        assert isinstance(errors[0], RaisingFingerprinterError)
        assert str(errors[0]) == "ja4h cannot read this packet"
        assert errors[0].__traceback__ is None

    def test_a_returned_error_clears_the_traceback_of_the_error_it_followed(self):
        """A fingerprinter that raises inside an `except` block chains two errors.

        The second error holds the first under `__context__`, and the traceback of the
        first holds frames of the fingerprinter. Those frames hold the packet.
        """
        processor = Processor()

        def raise_a_chain(packet):
            try:
                raise ValueError("the parser read a length field it cannot trust")
            except ValueError:
                raise RaisingFingerprinterError("ja4 cannot read this packet")

        processor.fingerprinters["ja4"].process_packet = raise_a_chain

        packet = dhcp_discover()
        alive = weakref.ref(packet)
        _, errors = processor.process_packet_with_errors(packet)
        del packet
        gc.collect()

        assert isinstance(errors[0].__context__, ValueError)
        assert errors[0].__context__.__traceback__ is None
        assert alive() is None, "the chained error holds the packet alive"

    def test_it_counts_the_packet_for_the_method_that_raised(self):
        """The packet count of a method rises for a packet it fails to read."""
        processor = Processor()
        make_one_method_raise(processor, "ja4")

        processor.process_packet_with_errors(dhcp_discover())

        assert processor.stats()["ja4"].packets == 1
