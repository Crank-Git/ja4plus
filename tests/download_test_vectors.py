#!/usr/bin/env python3
"""Refresh the committed FoxIO conformance vectors from a pinned upstream commit.

The vectors are committed to this repository, so the test suite never needs the
network. Run this script by hand to move the vectors to a newer upstream commit.

Usage:
    python tests/download_test_vectors.py
"""

import json
import urllib.request
from pathlib import Path

# The upstream commit that supplies every vector. A vector set that mixes commits
# cannot be reproduced, so the whole set moves together.
FOXIO_COMMIT = "27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8"
FOXIO_REPO = "https://github.com/FoxIO-LLC/ja4"
FOXIO_RAW = f"https://raw.githubusercontent.com/FoxIO-LLC/ja4/{FOXIO_COMMIT}"

PCAP_DIR = "pcap"
EXPECTED_DIR = "python/test/testdata"
WIRESHARK_EXPECTED_DIR = "wireshark/test/testdata"
RUST_EXPECTED_DIR = "rust/ja4/src/snapshots"

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"
WIRESHARK_DIR = VECTORS_DIR / "wireshark_expected"
RUST_DIR = VECTORS_DIR / "rust_expected"

# Every capture in the upstream `pcap/` directory that has an expected-output file.
# `dtls-udp.notest.cap` carries a `notest` marker upstream and has no expected
# output, so it is not a vector.
CAPTURES = [
    "CVE-2018-6794.pcap",
    "badcurveball.pcap",
    "browsers-x509.pcapng",
    "chrome-cloudflare-quic-with-secrets.pcapng",
    "dhcp.pcapng",
    "dhcpv6.pcap",
    "gre-erspan-vxlan.pcap",
    "gre-sample.pcap",
    "http-empty-useragent.pcap",
    "http1-with-cookies.pcapng",
    "http1.pcapng",
    "http2-with-cookies.pcapng",
    "https-connect.pcap",
    "https3-301-get.pcap",
    "ipv6.pcapng",
    "latest.pcapng",
    "macos_tcp_flags.pcap",
    "quic-tls-handshake.pcapng",
    "quic-with-several-tls-frames.pcapng",
    "single-packets.pcap",
    "socks-https-example.pcap",
    "socks4-https.pcap",
    "ssh-r.pcap",
    "ssh-scp-1050.pcap",
    "ssh.pcapng",
    "ssh2-malformed.pcap",
    "ssh2-moloch-crash.pcap",
    "ssh2.pcapng",
    "sshv1.pcap",
    "tcpdump-geneve.pcap",
    "tls-alpn-h2.pcap",
    "tls-handshake.pcapng",
    "tls-non-ascii-alpn.pcapng",
    "tls-sni.pcapng",
    "tls12.pcap",
    "tls3.pcapng",
    "v6.pcap",
]

# The FoxIO Python implementation emits no JA4D and no JA4D6, so the expected-output
# file of each DHCP capture holds an empty array. The Wireshark dissector is the only
# FoxIO implementation that writes a reference value for the two methods.
WIRESHARK_CAPTURES = [
    "dhcp.pcapng",
    "dhcpv6.pcap",
]

# The FoxIO Python implementation reads no QUIC handshake, and it reads no TLS on a port
# it does not know. The FoxIO Rust implementation reads both, so its snapshot holds a
# stream that the expected-output file of the same capture omits. Issue #138 settles
# those streams, and `tests/test_foxio_rust_parity.py` holds the measurement.
RUST_CAPTURES = [
    "chrome-cloudflare-quic-with-secrets.pcapng",
    "https-connect.pcap",
    "quic-tls-handshake.pcapng",
    "quic-with-several-tls-frames.pcapng",
    "ssh2.pcapng",
    "tls-handshake.pcapng",
    "tls-sni.pcapng",
    "tls3.pcapng",
]

# The Rust implementation writes one insta snapshot for each capture, under this name.
RUST_SNAPSHOT_NAME = "ja4__insta@{capture}.snap"

NOTICE_TEMPLATE = """\
FoxIO JA4+ conformance vectors
==============================

Almost every file in this directory is not the work of the ja4plus authors. Those
files are copied without change from the FoxIO JA4+ repository, so that the
conformance suite compares ja4plus against the reference output without network
access. The section `Captures the ja4plus authors built` names the exception.

Upstream repository: {repo}
Upstream commit:     {commit}

Source paths in that repository:

    {pcap_dir}/<capture>                  ->  tests/foxio_vectors/<capture>
    {expected_dir}/<capture>.json  ->  tests/foxio_vectors/<capture>.json

This directory holds {count} captures and {count} expected-output files.

`dtls-udp.notest.cap` is present upstream but is not copied here. It carries a
`notest` marker and has no expected-output file, so it is not a vector.

The subdirectory `wireshark_expected/` holds two more expected-output files:

    {wireshark_dir}/dhcp.pcapng.json  ->  tests/foxio_vectors/wireshark_expected/dhcp.pcapng.json
    {wireshark_dir}/dhcpv6.pcap.json  ->  tests/foxio_vectors/wireshark_expected/dhcpv6.pcap.json

The FoxIO Python implementation emits no JA4D and no JA4D6, so the two files under
`{expected_dir}` hold an empty array. The Wireshark dissector is the only FoxIO
implementation that writes a reference value for the two methods.
`docs/implementation_notes.md` records the reading.

The subdirectory `rust_expected/` holds {rust_count} more expected-output files:

    {rust_dir}/ja4__insta@<capture>.snap
        ->  tests/foxio_vectors/rust_expected/ja4__insta@<capture>.snap

for each of these captures:

{rust_captures}

The FoxIO Python implementation reads no QUIC handshake, and it reads no TLS on a
port it does not know. The FoxIO Rust implementation reads both, so each snapshot
above holds a stream that `{expected_dir}/<capture>.json` omits. Issue #138 settles
those streams, and `tests/test_foxio_rust_parity.py` holds the measurement.

The conformance suite reads only the top level of this directory, so neither
subdirectory adds a case to it.

Captures the ja4plus authors built
----------------------------------

`alpn-condition.pcap` is not FoxIO material. The ja4plus authors built it for #141,
and `tests/build_alpn_condition_capture.py` writes it. The FoxIO vector set holds no
capture that separates the JA4 ALPN rules, so #141 built one.

`alpn-condition.pcap.json` holds a measurement, not a copy. It records what the FoxIO
Python implementation writes for the capture at the commit above. The FoxIO Rust
implementation writes the same two JA4 values. `docs/implementation_notes.md` holds
both commands and their output.

This script does not write these two files, and it does not delete them.

To move to a newer upstream commit, change FOXIO_COMMIT in
tests/download_test_vectors.py and run that script. The script rewrites this
file.

License
-------

The FoxIO repository publishes two licenses, and both apply to this directory.

JA4S, JA4H, JA4L, JA4LS, JA4X, JA4T, JA4TS, JA4TScan, JA4D, JA4D6, JA4SScan,
JA4E and JA4SSH are under the FoxIO License 1.1:

    {repo}/blob/{commit}/LICENSE

JA4 itself, which is TLS client fingerprinting, is under a BSD 3-Clause license:

    {repo}/blob/{commit}/LICENSE-JA4

Copyright (c) 2026 FoxIO. The ja4plus project is not affiliated with FoxIO, LLC
and claims no right in the FoxIO material.
"""


def _fetch(url: str) -> bytes:
    """Return the body of the URL.

    Args:
        url: The address to read.

    Returns:
        The response body.

    Raises:
        urllib.error.URLError: The download failed.
    """
    with urllib.request.urlopen(url) as response:
        return response.read()


def download() -> None:
    """Write every vector and the NOTICE file into tests/foxio_vectors.

    The function overwrites the files that are already present, so that the
    directory always matches FOXIO_COMMIT exactly.

    Raises:
        urllib.error.URLError: A download failed.
        ValueError: An expected-output file is not a JSON array, or holds no value.
    """
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    WIRESHARK_DIR.mkdir(parents=True, exist_ok=True)
    RUST_DIR.mkdir(parents=True, exist_ok=True)

    for capture in CAPTURES:
        print(f"{capture}")
        (VECTORS_DIR / capture).write_bytes(_fetch(f"{FOXIO_RAW}/{PCAP_DIR}/{capture}"))

        expected_name = f"{capture}.json"
        expected = _fetch(f"{FOXIO_RAW}/{EXPECTED_DIR}/{expected_name}")
        # A truncated download still writes a file. Parsing it here fails the
        # refresh instead of leaving a broken vector for the conformance suite.
        if not isinstance(json.loads(expected), list):
            raise ValueError(f"{expected_name} is not a JSON array")
        (VECTORS_DIR / expected_name).write_bytes(expected)

    for capture in WIRESHARK_CAPTURES:
        expected_name = f"{capture}.json"
        print(f"wireshark_expected/{expected_name}")
        expected = _fetch(f"{FOXIO_RAW}/{WIRESHARK_EXPECTED_DIR}/{expected_name}")
        entries = json.loads(expected)
        if not isinstance(entries, list):
            raise ValueError(f"{expected_name} is not a JSON array")
        # An empty file compares no value, and the JA4D reference test would then
        # report a pass on nothing. That is the defect #109 closes.
        if not entries:
            raise ValueError(f"wireshark_expected/{expected_name} is an empty array")
        (WIRESHARK_DIR / expected_name).write_bytes(expected)

    for capture in RUST_CAPTURES:
        snapshot_name = RUST_SNAPSHOT_NAME.format(capture=capture)
        print(f"rust_expected/{snapshot_name}")
        snapshot = _fetch(f"{FOXIO_RAW}/{RUST_EXPECTED_DIR}/{snapshot_name}")
        # A snapshot with no `ja4:` line compares no value, and the QUIC reference test
        # would then report a pass on nothing. That is the defect #115 closes. The test
        # strips each line before it matches, so this check strips too.
        if not any(line.strip().startswith(b"ja4: ") for line in snapshot.splitlines()):
            raise ValueError(f"rust_expected/{snapshot_name} holds no JA4 value")
        (RUST_DIR / snapshot_name).write_bytes(snapshot)

    (VECTORS_DIR / "NOTICE").write_text(
        NOTICE_TEMPLATE.format(
            repo=FOXIO_REPO,
            commit=FOXIO_COMMIT,
            pcap_dir=PCAP_DIR,
            expected_dir=EXPECTED_DIR,
            wireshark_dir=WIRESHARK_EXPECTED_DIR,
            rust_dir=RUST_EXPECTED_DIR,
            count=len(CAPTURES),
            rust_count=len(RUST_CAPTURES),
            rust_captures="\n".join("    {}".format(name) for name in RUST_CAPTURES),
        )
    )
    print(f"{len(CAPTURES)} vectors written to {VECTORS_DIR}")
    print(f"{len(WIRESHARK_CAPTURES)} expected-output files written to {WIRESHARK_DIR}")
    print(f"{len(RUST_CAPTURES)} expected-output files written to {RUST_DIR}")


if __name__ == "__main__":
    download()
