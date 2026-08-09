"""Run every code sample of the README and of `docs/`.

FR-documentation-4 covers the README and FR-documentation-5 covers `docs/`. #63 states
the defect: a sample nobody runs is prose that reads as evidence.

The harness reads `tests/documentation_samples.py`, which classifies every fenced block.
Three groups of cases guard it.

1. The census cases prove the reader sees every block. A second reader counts the blocks
   by another algorithm, and the two counts must agree.
2. The floor cases prove the harness runs a measured count of samples. #302 shipped a
   guard whose floor came from its own broken reader, and it reported green over five
   defects.
3. The execution cases run the samples.
"""

from __future__ import annotations

import io
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import textwrap
from contextlib import redirect_stdout
from typing import Any, Dict, List

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tests.documentation_samples import (  # noqa: E402
    REPOSITORY_ROOT,
    SAMPLE_FILES,
    FencedBlock,
    all_blocks,
    census,
    disposition,
    documentation_files,
)

VECTORS = REPOSITORY_ROOT / "tests" / "foxio_vectors"

# The counts below were measured on 2026-08-09, against the corrected reader in
# `tests/documentation_samples.py`. A count that falls means a sample left the
# documentation or the reader stopped seeing it. Either one is a defect.
#
# Warning: never lower a floor to match what the reader happens to report. Read the
# reader first. #302 set its floor from a reader that skipped every wrapped row, and #345
# replaced a stale count for the same reason.
MINIMUM_BLOCKS = 157
MINIMUM_RUNNABLE_SAMPLES = 45

# The fenced blocks of each file, measured by hand from the file on 2026-08-09.
BLOCKS_PER_SAMPLE_FILE = {
    "README.md": 21,
    "docs/README.md": 0,
    "docs/api_reference.md": 22,
    "docs/implementation_notes.md": 9,
    "docs/mutation_sweep.md": 0,
    "docs/output-schema.md": 4,
    "docs/usage.md": 21,
}

# The capture files the samples name, and the committed vector each one holds. The
# harness writes them into the sample working directory, so a sample runs exactly as the
# reader reads it.
SAMPLE_CAPTURES = {
    "capture.pcap": "https3-301-get.pcap",
    "quic_capture.pcap": "quic-tls-handshake.pcapng",
    "ssh2.pcapng": "ssh2.pcapng",
    "latest.pcapng": "latest.pcapng",
}


def _second_reader_block_count(path: pathlib.Path) -> int:
    """Return the count of fenced blocks of one file, read by an independent algorithm.

    The reader of `tests/documentation_samples.py` matches a regular expression and
    tracks the fence width. This reader uses string operations alone, and it toggles one
    flag on each delimiter line. Two algorithms that disagree prove one is wrong.

    A delimiter line strips to a run of three or more backticks and an info string that
    holds no backtick. `docs/specs/foxio/JA4D.md:137` opens with three backticks and
    closes the span on the same line, so it is an inline code span and no delimiter.

    Args:
        path: The Markdown file to read.

    Returns:
        The count of blocks the toggle reader found.
    """
    count = 0
    inside = False
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("```"):
            continue
        ticks = len(stripped) - len(stripped.lstrip("`"))
        if "`" in stripped[ticks:]:
            continue
        if not inside:
            count += 1
        inside = not inside
    return count


def test_two_readers_count_the_same_fenced_blocks() -> None:
    """The regular-expression reader and the toggle reader agree on every file."""
    disagreements = []
    for path in documentation_files():
        expected = _second_reader_block_count(path)
        found = len(
            [b for b in all_blocks() if b.path == path.relative_to(REPOSITORY_ROOT).as_posix()]
        )
        if expected != found:
            disagreements.append(f"{path.name}: toggle reader {expected}, harness {found}")
    assert not disagreements, "; ".join(disagreements)


def test_the_reader_finds_at_least_the_measured_count_of_blocks() -> None:
    """The reader finds no fewer fenced blocks than the count measured on 2026-08-09."""
    found = len(all_blocks())
    assert found >= MINIMUM_BLOCKS, (
        f"the reader found {found} fenced blocks, and the floor is {MINIMUM_BLOCKS}"
    )


def test_the_harness_runs_at_least_the_measured_count_of_samples() -> None:
    """The harness runs no fewer samples than the count measured on 2026-08-09."""
    counts = census()
    running = counts["run"] + counts["raises"]
    assert running >= MINIMUM_RUNNABLE_SAMPLES, (
        f"the harness runs {running} samples, and the floor is {MINIMUM_RUNNABLE_SAMPLES}. "
        f"The full census is {counts}."
    )


@pytest.mark.parametrize("name", sorted(BLOCKS_PER_SAMPLE_FILE))
def test_each_user_documentation_file_holds_its_measured_count_of_blocks(name: str) -> None:
    """Each user documentation file holds the count of fenced blocks the table records."""
    found = len([b for b in all_blocks() if b.path == name])
    assert found == BLOCKS_PER_SAMPLE_FILE[name], (
        f"{name} holds {found} fenced blocks, and the table records {BLOCKS_PER_SAMPLE_FILE[name]}"
    )


def test_the_table_names_every_markdown_file_outside_the_specification_package() -> None:
    """`BLOCKS_PER_SAMPLE_FILE` names every user documentation file.

    A new page under `docs/` fails this case until somebody records its block count. A
    page nobody classifies is a page whose samples nobody runs.
    """
    found = {
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in documentation_files()
        if not path.relative_to(REPOSITORY_ROOT).as_posix().startswith("docs/specs/")
    }
    assert found == set(SAMPLE_FILES)
    assert found == set(BLOCKS_PER_SAMPLE_FILE)


def test_every_block_carries_one_disposition() -> None:
    """Every fenced block reports an action the harness knows."""
    for block in all_blocks():
        assert disposition(block).action in {"run", "raises", "skip", "output"}


def test_every_skipped_sample_names_its_reason() -> None:
    """A sample the harness does not run carries a reason of at least four words.

    #63 states the rule: a silent skip is the defect this harness exists to remove.
    """
    for block in all_blocks():
        result = disposition(block)
        if result.action == "skip":
            assert len(result.reason.split()) >= 4, f"{block.name}: {result.reason!r}"


# A block with no info string carries output, a schema line or a table. This case proves
# that classification. A block the reader calls output must not import this library and
# must not start with the name of the command.
_LOOKS_LIKE_CODE = re.compile(r"^\s*(?:from|import)\s+ja4plus\b|^\s*ja4plus\s+\w", re.MULTILINE)


def test_no_block_the_reader_calls_output_holds_a_code_sample() -> None:
    """No block the reader classifies as output imports the library or runs the command."""
    offenders = [
        block.name
        for block in all_blocks()
        if disposition(block).action == "output" and _LOOKS_LIKE_CODE.search(block.body)
    ]
    assert not offenders, (
        "these blocks read as code and carry no language, so the harness runs none of "
        f"them: {offenders}"
    )


# --------------------------------------------------------------------------------------
# The sample working directory.
# --------------------------------------------------------------------------------------


def _self_signed_certificate() -> Any:
    """Return one self-signed X.509 certificate for the certificate samples."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ja4plus.example")])
    now = datetime.datetime(2026, 1, 1)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


@pytest.fixture(scope="session")
def sample_workspace(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """Return a directory that holds every file the samples name.

    The samples name `capture.pcap`, `quic_capture.pcap`, `ssh2.pcapng`,
    `latest.pcapng` and `server.der`. The harness writes each one from a committed
    vector, so no sample text changes to name a test file.
    """
    from cryptography.hazmat.primitives.serialization import Encoding
    from scapy.all import rdpcap, wrpcap

    workspace = tmp_path_factory.mktemp("documentation-samples")
    for name, vector in SAMPLE_CAPTURES.items():
        source = VECTORS / vector
        if name.endswith(".pcap") and vector.endswith(".pcapng"):
            wrpcap(str(workspace / name), rdpcap(str(source)))
        else:
            shutil.copyfile(source, workspace / name)
    (workspace / "server.der").write_bytes(_self_signed_certificate().public_bytes(Encoding.DER))
    shutil.copytree(REPOSITORY_ROOT / "examples", workspace / "examples")
    return workspace


@pytest.fixture(scope="session")
def documentation_stock(sample_workspace: pathlib.Path) -> Dict[str, Any]:
    """Return the names the samples read without defining them.

    A sample is a fragment. It writes `fp.process_packet(packet)` and defines no
    `packet`, because a reader supplies their own. The harness supplies one from a
    committed vector, so the sample runs against real traffic.
    """
    from cryptography.hazmat.primitives.serialization import Encoding
    from scapy.all import rdpcap

    from ja4plus import JA4Fingerprinter, Processor
    from ja4plus.utils.packet_utils import get_ip_layer

    packets = rdpcap(str(sample_workspace / "capture.pcap"))
    reader = JA4Fingerprinter()
    client_hello = next((p for p in packets if reader.process_packet(p)), packets[0])
    certificate = _self_signed_certificate()
    processor = Processor()
    for packet in packets:
        processor.process_packet(packet)
    layer = get_ip_layer(client_hello)
    return {
        "packet": client_hello,
        "packets": list(packets),
        "handshake_packets": list(packets[:3]),
        "processor": processor,
        "fingerprints": [
            "t13d1516h2_8daaf6152771_02713d6af862",
            "t99z9999h0_0_0",
        ],
        "fingerprint_string": "t13d1516h2_8daaf6152771_02713d6af862",
        "another_fingerprint": "t99z9999h0_0_0",
        "hassh_value": "b5752e36ba6c5979a575e43178908adf",
        "x509_cert": certificate,
        "der_bytes": certificate.public_bytes(Encoding.DER),
        "cert_der_bytes": certificate.public_bytes(Encoding.DER),
        "pem_bytes": certificate.public_bytes(Encoding.PEM),
        "src_ip": layer.src if layer else "10.0.0.1",
        "dst_ip": layer.dst if layer else "10.0.0.2",
        "src_port": 44444,
        "dst_port": 443,
    }


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse every outbound connection while a sample runs.

    `ja4plus/ja4db.py` reaches `https://ja4db.com` when the caller opts in. #57 made the
    request opt-in, and a sample must reach no third party whatever it asks for.
    """

    def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("a documentation sample tried to reach the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


# --------------------------------------------------------------------------------------
# The execution cases.
# --------------------------------------------------------------------------------------


def _python_samples(name: str) -> List[FencedBlock]:
    """Return the Python blocks of one file that the harness runs, in file order."""
    return [
        block
        for block in all_blocks()
        if block.path == name
        and block.language == "python"
        and disposition(block).action in {"run", "raises"}
    ]


PYTHON_SAMPLE_FILES = sorted(name for name in BLOCKS_PER_SAMPLE_FILE if _python_samples(name))


@pytest.mark.parametrize("name", PYTHON_SAMPLE_FILES)
@pytest.mark.usefixtures("no_network")
def test_every_python_sample_of_the_page_runs(
    name: str,
    sample_workspace: pathlib.Path,
    documentation_stock: Dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each Python sample of the page runs, in the order a reader reads the page.

    The blocks of one page share one namespace, because a reader who copies the second
    block already ran the first one.
    """
    monkeypatch.chdir(sample_workspace)
    namespace: Dict[str, Any] = dict(documentation_stock)
    namespace["__name__"] = "documentation_sample"
    for block in _python_samples(name):
        result = disposition(block)
        source = compile(block.body + "\n", block.name, "exec")
        if result.action == "raises":
            with pytest.raises(Exception) as caught:  # noqa: B017
                with redirect_stdout(io.StringIO()):
                    exec(source, namespace)
            assert type(caught.value).__name__ == result.expected_error, (
                f"{block.name} raised {type(caught.value).__name__}, and the marker names "
                f"{result.expected_error}"
            )
            continue
        try:
            with redirect_stdout(io.StringIO()):
                exec(source, namespace)
        except Exception as error:  # noqa: BLE001
            pytest.fail(
                f"the sample at {block.name} failed: {type(error).__name__}: {error}\n"
                f"{textwrap.indent(block.body, '    ')}"
            )


BASH_SAMPLES = [
    block
    for block in all_blocks()
    if block.language == "bash" and disposition(block).action == "run"
]


@pytest.mark.parametrize("block", BASH_SAMPLES, ids=lambda b: b.name)
def test_every_shell_sample_runs(
    block: FencedBlock, sample_workspace: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each shell sample runs and ends with the status zero."""
    monkeypatch.chdir(sample_workspace)
    # The environment of the run carries `HOME` and the rest, because `scapy` reads the
    # home directory at import time. The search path gains the directory of the
    # interpreter, so a virtual environment supplies the `ja4plus` command.
    environment = dict(os.environ)
    environment["PATH"] = (
        str(pathlib.Path(sys.executable).parent) + os.pathsep + environment.get("PATH", "")
    )
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", block.body],
        cwd=str(sample_workspace),
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, (
        f"the sample at {block.name} ended with the status {completed.returncode}\n"
        f"{textwrap.indent(block.body, '    ')}\n{completed.stdout}\n{completed.stderr}"
    )
