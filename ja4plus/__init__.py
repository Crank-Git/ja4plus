"""
JA4+ - Network Fingerprinting Library

A Python implementation of the JA4+ network fingerprinting methods
created by FoxIO LLC. Supports TLS, TCP, HTTP, SSH, and X.509
fingerprinting for network security monitoring and traffic analysis.
"""

# Python 3.9 is the floor, and it evaluates no annotation written as `str | None`
# without this import.
from __future__ import annotations

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter
from ja4plus.fingerprinters.ja4d import JA4DFingerprinter
from ja4plus.fingerprinters.ja4d6 import JA4D6Fingerprinter
from ja4plus.processor import Processor
from ja4plus.types import FingerprintResult

# Function-based API
from ja4plus.fingerprinters.ja4 import generate_ja4
from ja4plus.fingerprinters.ja4s import generate_ja4s
from ja4plus.fingerprinters.ja4h import generate_ja4h
from ja4plus.fingerprinters.ja4l import generate_ja4l
from ja4plus.fingerprinters.ja4x import generate_ja4x
from ja4plus.fingerprinters.ja4ssh import generate_ja4ssh
from ja4plus.fingerprinters.ja4t import generate_ja4t
from ja4plus.fingerprinters.ja4ts import generate_ja4ts
from ja4plus.fingerprinters.ja4d import generate_ja4d
from ja4plus.fingerprinters.ja4d6 import generate_ja4d6

from ja4plus.utils.loopback import bind_loopback_ipv6
from ja4plus.utils.tunnels import register_tunnel_dissectors

# scapy binds one loopback address family value, the value of the reading host. Without
# this call a loopback capture that carries IPv6 produces fingerprints on Darwin and
# none on Linux. Issue #94 records the measurement.
bind_loopback_ipv6()

# scapy leaves Geneve, VXLAN and ERSPAN unbound. Without this call a fingerprinter
# reads no TCP layer of a mirrored capture, such as `tcpdump-geneve.pcap`.
register_tunnel_dissectors()


def compute_ja4x_from_der(cert_der_bytes: bytes) -> str | None:
    """Compute the JA4X fingerprint for a DER-encoded X.509 certificate.

    Args:
        cert_der_bytes: bytes containing a DER-encoded certificate.

    Returns:
        JA4X fingerprint string, or None if the certificate could not be parsed.
    """
    fp = JA4XFingerprinter()
    return fp.fingerprint_certificate(cert_der_bytes)


def compute_ja4x_from_pem(cert_pem_bytes: bytes | str) -> str | None:
    """Compute the JA4X fingerprint for a PEM-encoded X.509 certificate.

    Args:
        cert_pem_bytes: bytes containing a PEM-encoded certificate
            (one or more PEM blocks; only the first is used).

    Returns:
        JA4X fingerprint string, or None if the certificate could not be parsed.
    """
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding

    if isinstance(cert_pem_bytes, str):
        cert_pem_bytes = cert_pem_bytes.encode("ascii")

    try:
        cert = x509.load_pem_x509_certificate(cert_pem_bytes, default_backend())
    except Exception:
        return None
    der = cert.public_bytes(Encoding.DER)
    return compute_ja4x_from_der(der)


__version__ = "0.6.0"
__author__ = "ja4plus contributors"
__license__ = "BSD-3-Clause"
