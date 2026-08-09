"""A structurally valid ClientHello produces a fingerprint, whatever its body holds.

**`ja4plus` adds no plausibility guard.** The user decided this on 2026-08-08 and #343
records it. `CLAUDE.md` rule 1 gives the reason. The specification decides intent, and
the vectors decide the exact bytes where intent runs out. No FoxIO material and no
vector rejects such a packet, so a guard here would be a rule this project invented, and
`ja4plus` would answer differently from every FoxIO implementation on the same bytes.

**The cases below read oddly on purpose.** They assert that a random body produces a
fingerprint. A later change that adds a guard therefore fails a case, and its author has
to argue with #343 rather than pass the gate in silence.

`tests/fuzz/test_synthetic_hostile_input.py` holds the other half of the contract, which
#338 built: input that carries no ClientHello produces nothing. The two halves agree,
because the TLS record header, the handshake header and the two length fields separate
the two input sets. This file feeds bytes that carry all three; that file feeds bytes
that carry none of them, or that carry a length field the packet contradicts.

`tests/measure_random_client_hello.py` reproduces the whole measurement, over 5000
draws and over every committed capture.
"""

import pytest
from scapy.all import Raw

import ja4plus.utils.tls_utils as tls_utils
from tests.fuzz.support import spy_on

# The pattern, the draw count, the seeded generator and the reader all come from the
# #338 file. A second copy of the JA4 pattern would drift away from the first one.
from tests.fuzz.test_synthetic_hostile_input import (
    DRAWS,
    JA4_FORM,
    random_payloads,
    read_ja4,
)

# The count of random bytes each body holds. The register states the measurement at this
# size, and a shorter body changes the counts below.
BODY_SIZE = 256

# A TLS record header and a handshake header that bound a body of `BODY_SIZE` bytes. The
# record declares `BODY_SIZE + 4` bytes, because the handshake header holds four. Both
# length fields therefore agree with the byte count, and no read passes the packet.
VALID_HEADERS = (
    b"\x16\x03\x01" + (BODY_SIZE + 4).to_bytes(2, "big") + b"\x01" + BODY_SIZE.to_bytes(3, "big")
)

# The counts that `tests/measure_random_client_hello.py` reports for the first `DRAWS`
# draws of seed 338. The generator carries a fixed seed, so each count is exact.
VERSION_TOKEN_00_DRAWS = 511
NO_CIPHER_NO_EXTENSION_DRAWS = 79


@pytest.fixture
def parser_calls(monkeypatch):
    """Count the calls of `parse_tls_handshake`.

    A case that reaches no parser proves nothing, so every case below reads this
    counter. `tests/fuzz/README.md` states the rule.
    """
    return spy_on(monkeypatch, tls_utils, "parse_tls_handshake")


def random_client_hellos():
    """Return structurally valid ClientHellos whose bodies a fixed seed produces.

    Returns:
        A list of `DRAWS` payloads, each of `BODY_SIZE` random bytes behind valid
        headers.
    """
    return random_payloads(DRAWS, BODY_SIZE, prefix=VALID_HEADERS)


def test_a_structurally_valid_client_hello_with_a_random_body_produces_a_fingerprint(
    parser_calls,
):
    """The reader produces a well formed fingerprint for every random body.

    This case holds the decision of #343. A plausibility guard makes it fail.
    """
    for load in random_client_hellos():
        produced = read_ja4(load)
        assert produced is not None, load[:16].hex()
        assert JA4_FORM.match(produced), produced

    assert parser_calls.calls >= DRAWS


def test_a_random_body_produces_the_version_token_00_on_511_draws_of_512():
    """Almost every random body names a TLS version that no reference knows.

    A guard on the version token therefore rejects almost every draw. It still leaves
    one draw of 512, so it narrows the hole and it closes none of it.
    """
    produced = [read_ja4(load) for load in random_client_hellos()]

    assert sum(1 for value in produced if value[1:3] == "00") == VERSION_TOKEN_00_DRAWS


def test_a_random_body_carries_no_cipher_suite_and_no_extension_on_79_draws_of_512():
    """A guard on the empty cipher list and the empty extension list reaches 79 draws.

    The count is far below the draw count, so this guard narrows the hole less than the
    version guard does.
    """
    produced = [read_ja4(load) for load in random_client_hellos()]

    assert sum(1 for value in produced if value[4:8] == "0000") == NO_CIPHER_NO_EXTENSION_DRAWS


def test_the_vector_client_hello_carries_a_known_version_and_a_cipher_suite(
    client_hello_packet,
):
    """A guard rejects no vector ClientHello, so it buys a divergence and no vector.

    The 168 ClientHellos of `tests/foxio_vectors/` carry neither the version token `00`
    nor an empty cipher list. `tests/measure_random_client_hello.py` counts all 168, and
    this case reads the one packet the fuzz fixtures already hold.
    """
    produced = read_ja4(bytes(client_hello_packet[Raw].load))

    assert produced is not None
    assert produced[1:3] != "00"
    assert produced[4:6] != "00"
