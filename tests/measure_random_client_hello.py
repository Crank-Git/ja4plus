"""Measure what a structurally valid ClientHello with a random body produces.

#343 records the measurement in the `Divergence register` of `docs/specs/spec.md`. This
script reproduces both halves of it. Run it from the repository root:

    python tests/measure_random_client_hello.py

The first half draws random bodies behind a valid TLS record header and a valid
handshake header. The second half reads every committed capture and counts the vector
ClientHellos that a narrow plausibility guard would reject.

The script belongs to no test suite. `tests/fuzz/test_structural_validity.py` holds the
part of the measurement that runs on each suite.
"""

import random
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

from scapy.all import IP, Raw, TCP, rdpcap  # noqa: E402

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter  # noqa: E402
from ja4plus.utils.tls_utils import parse_tls_handshake  # noqa: E402

# The register states these three numbers, so the script pins them here.
SEED = 338
DRAWS = 5000
BODY_SIZE = 256

VECTOR_DIR = Path(__file__).resolve().parent / "foxio_vectors"


def client_hello(body: bytes) -> bytes:
    """Return a structurally valid ClientHello that carries the body.

    The record header, the handshake header and both length fields agree with the byte
    count, so no length field reads past the packet.

    Args:
        body: The bytes that follow the handshake header.

    Returns:
        The payload of one TCP packet.
    """
    return (
        b"\x16\x03\x01"
        + (len(body) + 4).to_bytes(2, "big")
        + b"\x01"
        + len(body).to_bytes(3, "big")
        + body
    )


def read_ja4(load: bytes) -> str | None:
    """Return the JA4 fingerprint of a TCP packet that carries the payload.

    Args:
        load: The payload bytes.

    Returns:
        The fingerprint, or None when the parser reads nothing.
    """
    packet = IP() / TCP(sport=12345, dport=443) / Raw(load=load)
    return JA4Fingerprinter().process_packet(packet)


def measure_random_bodies() -> dict[str, int]:
    """Return the counts that the random draws produce.

    Returns:
        A dictionary of four counts: the draws that produced a fingerprint, the draws
        whose fingerprint carries the version token `00`, and the draws whose
        fingerprint carries neither a cipher suite nor an extension.
    """
    source = random.Random(SEED)
    counts = {"draws": DRAWS, "produced": 0, "version_00": 0, "no_cipher_no_extension": 0}

    for _ in range(DRAWS):
        body = bytes(source.getrandbits(8) for _ in range(BODY_SIZE))
        value = read_ja4(client_hello(body))
        if value is None:
            continue
        counts["produced"] += 1
        if value[1:3] == "00":
            counts["version_00"] += 1
        if value[4:8] == "0000":
            counts["no_cipher_no_extension"] += 1

    return counts


def measure_vector_client_hellos() -> dict[str, int]:
    """Return the counts that the committed captures produce.

    Returns:
        A dictionary of three counts, in the shape `measure_random_bodies` returns,
        minus the draw count.
    """
    counts = {"produced": 0, "version_00": 0, "no_cipher_no_extension": 0}
    captures = sorted(VECTOR_DIR.glob("*.pcap")) + sorted(VECTOR_DIR.glob("*.pcapng"))

    for capture in captures:
        for packet in rdpcap(str(capture)):
            if Raw not in packet:
                continue
            info = parse_tls_handshake(bytes(packet[Raw].load))
            if not info or info.get("type") != "client_hello":
                continue
            value = JA4Fingerprinter().process_packet(packet)
            if value is None:
                continue
            counts["produced"] += 1
            if value[1:3] == "00":
                counts["version_00"] += 1
            if value[4:8] == "0000":
                counts["no_cipher_no_extension"] += 1

    return counts


def main() -> None:
    """Write both measurements to standard output."""
    print(f"random bodies:          {measure_random_bodies()}")
    print(f"vector ClientHellos:    {measure_vector_client_hellos()}")


if __name__ == "__main__":
    main()
