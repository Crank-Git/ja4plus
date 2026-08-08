"""Compare the Zeek JA4+ baselines against the fingerprints this project produces.

The Zeek package under `zeek/` in `FoxIO-LLC/ja4` carries seven btest baselines. Each
baseline reads one capture, and this project holds all seven captures under
`tests/foxio_vectors/`. This script reads a baseline, runs `ja4plus` on the same capture,
and prints one line for every fingerprint the two implementations both produce.

The script reads the reference. It never writes to it, and it changes no fingerprinter.

Usage, from the root of a checkout:

    python tests/compare_zeek_baselines.py <path-to-FoxIO-ja4-checkout>

The report is Markdown. `docs/specs/foxio/zeek.md` records the reading it produced.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

VECTORS = Path(__file__).parent / "foxio_vectors"

# Each baseline names its capture in the `@TEST-EXEC` line of the script that produced it.
# `zeek/tests/btest.cfg` sets `TRACES` to the `pcap/` directory of the same checkout.
BASELINES = [
    ("Scripts.ja4-conn", "conn.log", "ipv6.pcapng"),
    ("Scripts.ja4-conn-tls3", "conn.log", "tls3.pcapng"),
    ("Scripts.ja4-conn-quic", "conn.log", "chrome-cloudflare-quic-with-secrets.pcapng"),
    ("Scripts.ja4-dhcp", "ja4d.log", "dhcp.pcapng"),
    ("Scripts.ja4-http1-with-cookies", "http.log", "http1-with-cookies.pcapng"),
    ("Scripts.ja4-ssh2", "ja4ssh.log", "ssh2.pcapng"),
    ("Scripts.ja4-tls-handshake", "ssl.log", "tls-handshake.pcapng"),
]

# The Zeek log column that holds each method. `ja4l_delta` and `ja4ls_delta` have no
# counterpart in this project, so the report states them as absent rather than as a
# difference.
ZEEK_COLUMNS = ["ja4", "ja4s", "ja4h", "ja4l", "ja4ls", "ja4t", "ja4ts", "ja4ssh", "ja4d"]


def read_zeek_log(path: Path) -> list[dict[str, str]]:
    """Return the rows of a Zeek TSV log, one dictionary per row.

    Args:
        path: The path of one baseline.

    Returns:
        One dictionary for each data row, keyed by the column names of the `#fields`
        line.

    Raises:
        ValueError: A data row holds a different column count from the `#fields` line,
            or the file holds a data row before the `#fields` line. Either one makes
            every value of that row reach the wrong column, so the reader stops.
    """
    fields: list[str] = []
    rows: list[dict[str, str]] = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        # A btest baseline opens with a `###` line, and a Zeek log opens with `#` lines.
        if line.startswith("#") or not line:
            continue
        values = line.split("\t")
        if len(values) != len(fields):
            raise ValueError(
                f"{path}:{number} holds {len(values)} values against {len(fields)} fields"
            )
        rows.append(dict(zip(fields, values)))
    return rows


def endpoint(host: str, port: str) -> str:
    """Return one endpoint of a connection as `host:port`."""
    return f"{host}:{port}"


def connection_key(a: str, b: str) -> tuple[str, str]:
    """Return a connection key that does not depend on the direction observed."""
    return tuple(sorted((a, b)))  # type: ignore[return-value]


def split_source(source: str) -> tuple[str, str]:
    """Return the two endpoints of a `ja4plus` `source` field.

    The field has the form `host:port -> host:port`. The function keeps each endpoint
    whole and splits no port from it, because an IPv6 host holds colons and the Zeek key
    joins the host and the port in the same way.

    Args:
        source: The `source` field of one `ja4plus` JSON record.

    Returns:
        The sender endpoint and the receiver endpoint.

    Raises:
        ValueError: The field holds no ` -> ` separator.
    """
    left, right = source.split(" -> ")
    return left, right


def zeek_readings(rows: list[dict[str, str]]) -> dict[tuple[str, str], dict[str, list[str]]]:
    """Return the Zeek fingerprints, keyed by connection and then by method.

    Warning: the key rests on one assumption. Zeek and `ja4plus` must write an address in
    the same form. Both write the compressed form of an IPv6 address on the seven
    captures of `BASELINES`. A capture where the two forms differ produces `(none)` in
    the `ja4plus` column of every method on that connection, and no parse error.
    """
    out: dict[tuple[str, str], dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        key = connection_key(
            endpoint(row["id.orig_h"], row["id.orig_p"]),
            endpoint(row["id.resp_h"], row["id.resp_p"]),
        )
        for column in ZEEK_COLUMNS:
            value = row.get(column, "")
            # `(empty)` is the btest rendering of an empty string, `-` of an unset field.
            if value in ("", "(empty)", "-"):
                continue
            out[key][column].append(value)
    return out


def ja4plus_readings(capture: Path) -> dict[tuple[str, str], dict[str, list[str]]]:
    """Return the `ja4plus` fingerprints for one capture, keyed as `zeek_readings` is.

    Args:
        capture: The path of one capture under `tests/foxio_vectors/`.

    Returns:
        The fingerprints, keyed by connection and then by method.

    Raises:
        subprocess.CalledProcessError: The command-line program failed. `compare` catches
            it, prints the standard error stream, and reads the next baseline.
    """
    result = subprocess.run(
        [sys.executable, "-m", "ja4plus.cli", "--format", "json", "analyze", str(capture)],
        capture_output=True,
        text=True,
        check=True,
    )
    out: dict[tuple[str, str], dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for line in result.stdout.splitlines():
        if not line.startswith("{"):
            continue
        record = json.loads(line)
        left, right = split_source(record["source"])
        method = record["type"]
        value = record["fingerprint"]
        # A JA4L fingerprint carries its side as a prefix. The Zeek log holds two columns
        # instead, so the prefix becomes the method name here.
        if method == "ja4l" and "=" in value:
            side, value = value.split("=", 1)
            method = "ja4l" if side == "JA4L-C" else "ja4ls"
        out[connection_key(left, right)][method].append(value)
    return out


def compare(reference: Path) -> int:
    """Print the comparison and return the count of connections that differ."""
    differences = 0
    for directory, log_name, capture_name in BASELINES:
        log = reference / "zeek" / "tests" / "Traces" / directory / log_name
        capture = VECTORS / capture_name
        print(f"\n## {directory}/{log_name} — capture `{capture_name}`\n")
        if not log.is_file():
            print(f"MISSING baseline: {log}")
            continue
        if not capture.is_file():
            print(f"MISSING capture: {capture}")
            continue
        zeek = zeek_readings(read_zeek_log(log))
        # One capture that fails must not hide the other six, so the loop reports the
        # failure and reads the next baseline.
        try:
            mine = ja4plus_readings(capture)
        except subprocess.CalledProcessError as error:
            print(f"FAILED to read {capture}: exit {error.returncode}")
            print(error.stderr)
            continue
        print("| Connection | Method | Zeek | ja4plus | Same |")
        print("|---|---|---|---|---|")
        for key in sorted(zeek):
            for method in sorted(zeek[key]):
                left = ",".join(zeek[key][method])
                right = ",".join(mine.get(key, {}).get(method, [])) or "(none)"
                same = "yes" if left == right else "NO"
                if same == "NO":
                    differences += 1
                print(f"| {key[0]} / {key[1]} | {method} | `{left}` | `{right}` | {same} |")
    return differences


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    reference = Path(sys.argv[1])
    differences = compare(reference)
    print(f"\nConnection-and-method pairs that differ: {differences}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
