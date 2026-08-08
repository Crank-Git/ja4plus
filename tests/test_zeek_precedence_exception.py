"""Tests that measure the reach of the Zeek precedence exception.

`.claude/rules/external-apis.md` states that `python/test/testdata/` decides where it and
a Zeek baseline both hold a value for one method on one connection. #332 adds one
exception: where `tests/foxio_deviations.json` declines the FoxIO Python value under a
decided entry, that value forfeits its precedence, and a Zeek baseline may hold the
reference value for that method on that connection.

The exception reads three facts from the register and the baseline list, and it reads no
judgment about which value looks right.

1. The key is the value form, so the FoxIO Python file holds a value to decline. The
   occurrence form records a stream the Python file omits, and the Rust snapshot rule
   already decides that case.
2. The entry carries `decided`, so a recorded decision names the issue. An undecided
   entry is an open question, and this exception does not reach it.
3. A Zeek baseline holds a value for the same method on the same connection.

**These cases read fact 3 at capture granularity, where the rule reads it at connection
granularity.** A capture reading counts every connection of the capture, so the reach it
returns is an upper bound and it hides no row. A reader checks each row it returns at
connection granularity, and #332 records that check.

These cases keep `docs/specs/foxio/zeek.md` and the register together. A later decline
that lands on a method a Zeek baseline covers fails `the exception reaches one register
key`, which sends the next reader to the page.

These cases read the register and prose. They import nothing from `ja4plus` and they
produce no fingerprint.
"""

import json
from pathlib import Path

from tests.foxio_deviations import load_register

REPO_ROOT = Path(__file__).resolve().parent.parent

ZEEK_PAGE = REPO_ROOT / "docs" / "specs" / "foxio" / "zeek.md"

# The methods each Zeek baseline holds a value for, keyed by the capture the baseline
# read. `tests/compare_zeek_baselines.py` holds the baseline list, and the run of #332
# read every non-empty method column of the seven baselines at the pinned commit
# 27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8.
ZEEK_METHODS = {
    "ipv6.pcapng": {"JA4L", "JA4LS", "JA4T", "JA4TS"},
    "tls3.pcapng": {"JA4L", "JA4LS", "JA4T", "JA4TS"},
    "chrome-cloudflare-quic-with-secrets.pcapng": {"JA4L", "JA4LS", "JA4T", "JA4TS"},
    "dhcp.pcapng": {"JA4D"},
    "http1-with-cookies.pcapng": {"JA4H"},
    "ssh2.pcapng": {"JA4SSH"},
    "tls-handshake.pcapng": {"JA4", "JA4S"},
}

# The register spells a JA4L value with the direction the value describes, and the Zeek
# baseline writes one `ja4l` column.
REGISTER_METHOD_NAMES = {"JA4L-C": "JA4L", "JA4L-S": "JA4L"}

# `.claude/rules/external-apis.md` reads no JA4L or JA4LS value of a Zeek baseline as a
# reference value, because three rules of the Zeek script diverge from the Python
# reference. That bar stands above the exception, so the exception reaches no such row.
BARRED_METHODS = {"JA4L", "JA4LS"}

# The one row the exception reaches. `docs/specs/foxio/zeek.md` states the rating this
# row carries, and #97 holds the decision that declines the Python value.
REACHED_KEYS = {"ssh2.pcapng/14:57377/JA4SSH.2"}

# The baseline that holds the reference value for the one row the exception reaches.
SSH2_BASELINE = "Scripts.ja4-ssh2/ja4ssh.log"


def _zeek_method(key):
    """Return the Zeek method a value key names, or None.

    Args:
        key: One register key.

    Returns:
        The method name a Zeek baseline writes, or None where the key is the occurrence
        form, or where no Zeek baseline covers the capture and the method.
    """
    parts = key.split("/")
    if len(parts) != 3:
        return None
    capture, _, tail = parts
    method = tail.rsplit(".", 1)[0]
    method = REGISTER_METHOD_NAMES.get(method, method)
    if method not in ZEEK_METHODS.get(capture, set()):
        return None
    return method


def _exception_reach(register):
    """Return every register key the Zeek precedence exception reaches.

    Args:
        register: The register that `load_register` returns.

    Returns:
        The set of keys where the register declines the FoxIO Python value under a
        decided entry, and a Zeek baseline holds a value for the same method.
    """
    reach = set()
    for key, deviation in register.items():
        method = _zeek_method(key)
        if method is None or method in BARRED_METHODS:
            continue
        if not deviation.decided:
            continue
        reach.add(key)
    return reach


class TestTheReachOfTheException:
    """The exception reaches the rows the page names, and no other row."""

    def test_the_exception_reaches_one_register_key(self):
        assert _exception_reach(load_register()) == REACHED_KEYS

    def test_the_zeek_page_names_every_row_the_exception_reaches(self):
        page = ZEEK_PAGE.read_text()
        for key in sorted(_exception_reach(load_register())):
            assert key in page, "{} names no row for {}".format(ZEEK_PAGE, key)

    def test_the_zeek_page_rates_the_baseline_the_exception_reaches(self):
        rows = [line for line in ZEEK_PAGE.read_text().splitlines() if SSH2_BASELINE in line]
        assert rows, "{} holds no rating row for {}".format(ZEEK_PAGE, SSH2_BASELINE)
        for row in rows:
            assert "Undecided" not in row, "{} rates {} as undecided".format(
                ZEEK_PAGE, SSH2_BASELINE
            )

    def test_the_exception_passes_over_an_undecided_entry(self, tmp_path):
        path = tmp_path / "register.json"
        path.write_text(
            json.dumps(
                {
                    "ssh2.pcapng/14:57377/JA4SSH.2": {
                        "issue": 999,
                        "cause": "#999 decides whether ja4plus reads the second window.",
                    }
                }
            )
        )
        assert _exception_reach(load_register(path)) == set()
