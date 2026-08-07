"""The JA4S raw form holds the extensions in the order the ServerHello carries them.

FoxIO publishes one raw key for JA4S, and that key is `JA4S_r`. No expected-output file
carries a `JA4S_ro` key. JA4S sorts no list, so the `raw` key and the
`raw_original_order` key of one JA4S result hold one value. #108 records the reading.

Every expected value comes from a file under `tests/foxio_vectors/`.
`tests/foxio_vectors/NOTICE` records the FoxIO commit each file came from.
"""

import json
import os

VECTOR_DIR = os.path.join(os.path.dirname(__file__), "foxio_vectors")

# The extensions of this vector are not in numeric order, so the sorted form and the wire
# form differ. A vector whose wire order is already numeric order proves nothing here.
ORDER_CAPTURE = os.path.join(VECTOR_DIR, "badcurveball.pcap")
ORDER_EXPECTED = os.path.join(VECTOR_DIR, "badcurveball.pcap.json")


def ja4s_results(capture_path):
    """Return the JA4S result entries of one capture.

    Args:
        capture_path: The path of a capture file.

    Returns:
        The list of entries the JA4S fingerprinter collected.
    """
    from scapy.all import rdpcap

    from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

    fingerprinter = JA4SFingerprinter()
    for packet in rdpcap(capture_path):
        fingerprinter.process_packet(packet)
    return fingerprinter.get_fingerprints()


def test_the_raw_form_holds_the_extensions_in_wire_order():
    """The `raw` key of a JA4S result equals the reference `JA4S_r` value."""
    with open(ORDER_EXPECTED) as handle:
        expected = json.load(handle)[0]

    results = ja4s_results(ORDER_CAPTURE)
    assert len(results) == 1
    # The reference value is `t1205h1_c02b_0000,ff01,000b,0023,0010`. Numeric order puts
    # `ff01` last, so this value proves that the reference holds the wire order.
    assert expected["JA4S_r"] == "t1205h1_c02b_0000,ff01,000b,0023,0010"
    assert results[0]["raw"] == expected["JA4S_r"]


def test_the_two_raw_forms_of_one_ja4s_result_hold_one_value():
    """The `raw` key and the `raw_original_order` key of a JA4S result are equal."""
    results = ja4s_results(ORDER_CAPTURE)
    assert len(results) == 1
    assert results[0]["raw"] == results[0]["raw_original_order"]
    assert results[0]["raw"] is not None


def test_the_last_raw_attribute_holds_the_reference_value():
    """`last_raw` holds the reference `JA4S_r` value of the most recent result."""
    from scapy.all import rdpcap

    from ja4plus.fingerprinters.ja4s import JA4SFingerprinter

    with open(ORDER_EXPECTED) as handle:
        expected = json.load(handle)[0]

    fingerprinter = JA4SFingerprinter()
    for packet in rdpcap(ORDER_CAPTURE):
        fingerprinter.process_packet(packet)
    assert fingerprinter.last_raw == expected["JA4S_r"]
    assert fingerprinter.last_raw == fingerprinter.last_raw_original_order


def test_every_reference_raw_value_appears_in_the_raw_key_of_a_result():
    """Each `JA4S_r` value of each committed vector equals the `raw` key of one result.

    The test compares the set of values and not the count of them. `tls-handshake.pcapng`
    produces five JA4S values the reference does not hold, and the register records that
    difference at `tls-handshake.pcapng/JA4S` under #13.
    """
    checked = 0
    vectors = 0
    for name in sorted(os.listdir(VECTOR_DIR)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(VECTOR_DIR, name)) as handle:
            records = json.load(handle)
        if not isinstance(records, list):
            continue
        expected = {record["JA4S_r"] for record in records if "JA4S_r" in record}
        if not expected:
            continue
        capture_path = os.path.join(VECTOR_DIR, name[: -len(".json")])
        produced = {result["raw"] for result in ja4s_results(capture_path)}
        assert expected <= produced, name
        checked += len(expected)
        vectors += 1
    # Fourteen committed vectors hold a `JA4S_r` key, and they hold 29 distinct values.
    # A drop in either count means a vector left the set, and the test then proves less
    # than it claims.
    assert vectors == 14
    assert checked == 29
