#!/usr/bin/env python3
"""Download FoxIO JA4+ test vectors for spec validation."""
import os
import urllib.request
import json

FOXIO_RAW = "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main"
TEST_VECTORS_DIR = os.path.join(os.path.dirname(__file__), "foxio_vectors")

# Key PCAPs that exercise JA4+ fingerprint types we support
PCAPS = [
    "tls12.pcap",
    "tls-handshake.pcapng",
    "http1.pcapng",
    "http1-with-cookies.pcapng",
    "ssh.pcapng",
    "ssh2.pcapng",
]

def download():
    os.makedirs(TEST_VECTORS_DIR, exist_ok=True)

    for pcap in PCAPS:
        pcap_path = os.path.join(TEST_VECTORS_DIR, pcap)
        json_path = os.path.join(TEST_VECTORS_DIR, f"{pcap}.json")

        if not os.path.exists(pcap_path):
            print(f"Downloading {pcap}...")
            try:
                urllib.request.urlretrieve(f"{FOXIO_RAW}/pcap/{pcap}", pcap_path)
            except Exception as e:
                print(f"  Warning: Could not download {pcap}: {e}")
                continue

        if not os.path.exists(json_path):
            print(f"Downloading {pcap}.json...")
            try:
                urllib.request.urlretrieve(
                    f"{FOXIO_RAW}/python/test/testdata/{pcap}.json", json_path
                )
            except Exception:
                # Try wireshark testdata as fallback
                try:
                    urllib.request.urlretrieve(
                        f"{FOXIO_RAW}/wireshark/test/testdata/{pcap}.json", json_path
                    )
                except Exception:
                    print(f"  Warning: No expected output found for {pcap}")

if __name__ == "__main__":
    download()
