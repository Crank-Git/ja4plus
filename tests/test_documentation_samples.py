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
import signal
import socket
import subprocess
import sys
import textwrap
from contextlib import contextmanager, redirect_stdout
from typing import Any, Dict, Iterator, List

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tests.documentation_samples import (  # noqa: E402
    BLOCKQUOTE_FENCE,
    REPOSITORY_ROOT,
    RUNNABLE_LANGUAGES,
    FencedBlock,
    all_blocks,
    census,
    disposition,
    documentation_files,
    user_documentation_files,
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

# The fenced blocks each page held on 2026-08-09, measured by hand from the page.
#
# **This table is a floor for each page, and never an exact count.** An exact count
# breaks on every page that gains a block, and a floor breaks on the one thing the
# totals above miss: a page that loses a sample while another page gains more.
#
# **The counts stay hand-measured on purpose.** The only tool that could derive them is
# the reader these cases exist to check, and a floor taken from the reader reports
# nothing about the reader. #302 set its floor from the count its own broken parser read.
#
# A page absent from this table carries a floor of zero. It is still read, counted,
# classified and run, because every one of those steps reads the filesystem.
MINIMUM_BLOCKS_PER_PAGE = {
    "README.md": 21,
    "docs/api_reference.md": 22,
    "docs/implementation_notes.md": 9,
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


@pytest.mark.parametrize("name", sorted(MINIMUM_BLOCKS_PER_PAGE))
def test_each_page_holds_at_least_its_measured_count_of_blocks(name: str) -> None:
    """Each page of the floor table holds no fewer blocks than the table records.

    The two totals above miss one regression: a page that loses a sample while another
    page gains more. This floor catches it, and it tolerates a page that grows.
    """
    found = len([b for b in all_blocks() if b.path == name])
    assert found >= MINIMUM_BLOCKS_PER_PAGE[name], (
        f"{name} holds {found} fenced blocks, and the floor is {MINIMUM_BLOCKS_PER_PAGE[name]}"
    )


def test_the_floor_table_names_no_page_the_repository_lacks() -> None:
    """Every page of the floor table still exists.

    A floor entry for a page somebody deleted would report a missing page as a missing
    sample, which names the wrong repair.
    """
    missing = sorted(set(MINIMUM_BLOCKS_PER_PAGE) - set(user_documentation_files()))
    assert not missing, f"the floor table names pages the repository no longer holds: {missing}"


def test_the_execution_cases_reach_every_sample_the_reader_calls_runnable() -> None:
    """Every block the reader calls runnable belongs to a case that runs it.

    The reader and the runner are two lists, and two lists drift apart. #64 proved it:
    a page under `docs/reference/` was read and classified as runnable, and no case ran
    it. This case compares the two, so the drift fails rather than passing in silence.
    """
    reader = {
        block.name for block in all_blocks() if disposition(block).action in {"run", "raises"}
    }
    runner = {block.name for name in PYTHON_SAMPLE_FILES for block in _python_samples(name)}
    runner |= {block.name for block in BASH_SAMPLES}
    assert reader == runner, (
        f"the reader calls these runnable and no case runs them: {sorted(reader - runner)}; "
        f"these cases run a block the reader does not call runnable: {sorted(runner - reader)}"
    )


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


def test_every_marker_sits_on_a_block_the_harness_runs() -> None:
    """Every `sample:` marker sits on a `python` block or on a `bash` block.

    `disposition` reads the language before it reads the marker, so a marker on a JSON
    block or on an output block would state a reason that nothing acts on. This case
    reports the misplaced marker rather than dropping it.
    """
    misplaced = [
        f"{block.name} carries the marker {block.marker!r} on a {block.info!r} block"
        for block in all_blocks()
        if block.marker is not None and block.language not in RUNNABLE_LANGUAGES
    ]
    assert not misplaced, "; ".join(misplaced)


# A fence inside a blockquote reaches neither reader, so the two counts agree on a block
# that neither one found. The census therefore misses it, and the miss is silent.
#
# Two such fences exist today, and both sit in the specification package, which the
# harness excludes whole. They open and close one `.gitignore` fragment, which is data
# rather than a code sample. This list records them so that the miss is counted and not
# silent, and `test_no_new_fence_hides_inside_a_blockquote` fails on a third.
KNOWN_BLOCKQUOTE_FENCES = (
    "docs/specs/features/00-foundation.md:49",
    "docs/specs/features/00-foundation.md:53",
)


def _blockquote_fences() -> List[str]:
    """Return the location of every fence that opens inside a blockquote."""
    return [
        f"{path.relative_to(REPOSITORY_ROOT).as_posix()}:{number}"
        for path in documentation_files()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if BLOCKQUOTE_FENCE.match(line)
    ]


def test_no_new_fence_hides_inside_a_blockquote() -> None:
    """The documentation holds the two recorded blockquote fences and no other."""
    assert _blockquote_fences() == list(KNOWN_BLOCKQUOTE_FENCES)


def test_the_user_documentation_holds_no_fence_inside_a_blockquote() -> None:
    """No user documentation page opens a fence inside a blockquote.

    A blockquote fence reaches neither reader. In the user documentation such a fence
    would hide a runnable sample from the census, so this case bars the shape there.
    """
    offenders = [
        location for location in _blockquote_fences() if not location.startswith("docs/specs/")
    ]
    assert not offenders, (
        f"a fence inside a blockquote reaches neither reader: {offenders}. Move the "
        "block out of the blockquote."
    )


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


# A shell sample runs in a subprocess, which carries its own timeout. A Python sample
# runs in this process, so an unmarked sample that blocks would hang the whole run.
SAMPLE_TIME_LIMIT_SECONDS = 300


@contextmanager
def _time_limit(name: str) -> Iterator[None]:
    """Raise `TimeoutError` when the body runs longer than the sample time limit.

    Args:
        name: The identifier of the block, for the message.

    Yields:
        Nothing. The caller runs the sample inside the body.
    """
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    def expire(*_args: Any) -> None:
        raise TimeoutError(f"{name} ran longer than {SAMPLE_TIME_LIMIT_SECONDS} seconds")

    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, SAMPLE_TIME_LIMIT_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _is_python_sample(block: FencedBlock) -> bool:
    """Return True when the harness runs this block as a Python sample."""
    return block.language == "python" and disposition(block).action in {"run", "raises"}


def _python_samples(name: str) -> List[FencedBlock]:
    """Return the Python blocks of one file that the harness runs, in file order."""
    return [block for block in all_blocks() if block.path == name and _is_python_sample(block)]


# The execution set reads the blocks, so it reaches every page the filesystem holds.
#
# Warning: never drive this list from a table somebody maintains by hand. An earlier form
# read the keys of the block-count table, and a page absent from that table was read,
# counted and classified as runnable, and then never run. #64 added five pages under
# `docs/reference/` and proved it: a page holding a broken sample reported
# `3 passed` from the execution cases.
PYTHON_SAMPLE_FILES = sorted({block.path for block in all_blocks() if _is_python_sample(block)})


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
                with _time_limit(block.name), redirect_stdout(io.StringIO()):
                    exec(source, namespace)
            assert type(caught.value).__name__ == result.expected_error, (
                f"{block.name} raised {type(caught.value).__name__}, and the marker names "
                f"{result.expected_error}"
            )
            continue
        try:
            with _time_limit(block.name), redirect_stdout(io.StringIO()):
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
