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

VECTORS_DIR = Path(__file__).parent / "foxio_vectors"

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

NOTICE_TEMPLATE = """\
FoxIO JA4+ conformance vectors
==============================

The files in this directory are not the work of the ja4plus authors. They are
copied without change from the FoxIO JA4+ repository, so that the conformance
suite compares ja4plus against the reference output without network access.

Upstream repository: {repo}
Upstream commit:     {commit}

Source paths in that repository:

    {pcap_dir}/<capture>                  ->  tests/foxio_vectors/<capture>
    {expected_dir}/<capture>.json  ->  tests/foxio_vectors/<capture>.json

This directory holds {count} captures and {count} expected-output files.

`dtls-udp.notest.cap` is present upstream but is not copied here. It carries a
`notest` marker and has no expected-output file, so it is not a vector.

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
        ValueError: An expected-output file is not a JSON array.
    """
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)

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

    (VECTORS_DIR / "NOTICE").write_text(
        NOTICE_TEMPLATE.format(
            repo=FOXIO_REPO,
            commit=FOXIO_COMMIT,
            pcap_dir=PCAP_DIR,
            expected_dir=EXPECTED_DIR,
            count=len(CAPTURES),
        )
    )
    print(f"{len(CAPTURES)} vectors written to {VECTORS_DIR}")


if __name__ == "__main__":
    download()
