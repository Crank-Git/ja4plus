"""
JA4+ - Network Fingerprinting Library

A Python implementation of the JA4+ network fingerprinting methods
created by FoxIO LLC. Supports TLS, TCP, HTTP, SSH, and X.509
fingerprinting for network security monitoring and traffic analysis.
"""

# This import makes every annotation a string. No annotation therefore evaluates at
# import time, and a forward reference needs no quotation mark.
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
    # The `cryptography` documentation names `ValueError` for data the loader cannot
    # parse. #316 measured `InvalidVersion` from the DER loader, and #319 measured it
    # from the PEM loader. It inherits `Exception` and not `ValueError`, so a list of
    # `ValueError` alone drops it and a real certificate then reaches the caller as an
    # error rather than as nothing.
    except (ValueError, x509.InvalidVersion):
        return None
    der = cert.public_bytes(Encoding.DER)
    return compute_ja4x_from_der(der)


# **`FR-release-1` puts the version number in one place, and this line is that place.**
# `pyproject.toml` reads this attribute through its `[tool.setuptools.dynamic]` table, so
# a release carries the version this line declares. A bump edits this line alone, and it
# needs a matching `## [<version>]` section in `CHANGELOG.md`.
#
# **Keep the plain string assignment.** `setuptools` reads the value from the syntax tree,
# so a computed value would make a build import this module and every dependency it loads.
__version__ = "1.1.0"
__author__ = "ja4plus contributors"
__license__ = "BSD-3-Clause"

# FR-typed-api-12 and FR-typed-api-13 of `docs/specs/features/04-typed-api.md` make this
# list the interface version 1.0.0 promises. A name here stays until version 2.0.0, and a
# name absent from here is not promised. The list therefore names what a caller may
# import from `ja4plus`, and a module states its own public names in its own `__all__`.
#
# `bind_loopback_ipv6` and `register_tunnel_dissectors` stay out. This module calls both
# at import time, so a caller needs neither name.
#
# `__author__` and `__license__` stay out. Both describe the project and not the
# interface, and the distribution metadata carries the license. `__version__` stays in,
# because `ja4plus --version` reads it and a caller reads it to test compatibility.
__all__ = [
    # The typed result and the aggregator that returns it.
    "FingerprintResult",
    "Processor",
    # The ten fingerprinter classes. `JA4LFingerprinter` writes JA4L and JA4LS, so these
    # ten classes carry eleven methods. The Go port exports the same ten fingerprinters,
    # under parity rule 2.
    "JA4Fingerprinter",
    "JA4SFingerprinter",
    "JA4HFingerprinter",
    "JA4LFingerprinter",
    "JA4XFingerprinter",
    "JA4SSHFingerprinter",
    "JA4TFingerprinter",
    "JA4TSFingerprinter",
    "JA4DFingerprinter",
    "JA4D6Fingerprinter",
    # The one-shot form of each method. The port names these `ComputeJA4` and so on.
    "generate_ja4",
    "generate_ja4s",
    "generate_ja4h",
    "generate_ja4l",
    "generate_ja4x",
    "generate_ja4ssh",
    "generate_ja4t",
    "generate_ja4ts",
    "generate_ja4d",
    "generate_ja4d6",
    # The certificate helpers. The port names these `ComputeJA4XFromDER` and
    # `ComputeJA4XFromPEM`.
    "compute_ja4x_from_der",
    "compute_ja4x_from_pem",
    "__version__",
]
