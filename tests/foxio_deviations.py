"""The register of known conformance deviations.

A deviation is one conformance case that ja4plus fails today, and that another issue
owns. `tests/foxio_deviations.json` holds one entry for each. The conformance suite
reads the register and marks the matching case `xfail(strict=True)`.

`strict=True` is the point of the register. A registered case that starts passing fails
the suite and names itself, so a fix reports itself the moment it lands. A failing case
that the register does not hold fails normally, which is the regression gate.

## The two key forms

| Form | Example | What it records |
|---|---|---|
| `<vector>/<stream>:<port>/<method>.<occurrence>` | `tls-sni.pcapng/38:57377/JA4.1` | One value differs. |
| `<vector>/<method>` | `ssh2.pcapng/JA4` | The occurrence keys differ. |

The stream part holds the stream index the FoxIO expected-output file gives, then the
source port of the first record on the stream. The port is part of the key because one
index does not name one stream: `chrome-cloudflare-quic-with-secrets.pcapng` gives the
index 0 to two streams. The pair matches the test identifier the suite prints.

## How to add an entry

1. Run the conformance suite and read the failure line. It names the vector, the
   stream, the method and the occurrence.
2. Open the issue that fixes the defect, or find the issue that already owns it. An
   entry with no issue number is not allowed, and the reader rejects it.
3. Add one entry to `tests/foxio_deviations.json`:

```json
"tls-sni.pcapng/38:57377/JA4.1": {"issue": 13, "cause": "JA4 counts one extension too many."}
```

4. Run the conformance suite again. The case now reports as `xfailed`.

## How to remove an entry

A fix that lands makes the case pass, and the strict marker turns that pass into a
failure that names the case. Delete the entry in the same change that lands the fix.
Never delete an entry to make a red suite green.

## How to measure a new baseline

Set `JA4PLUS_IGNORE_DEVIATIONS=1` and run the suite. The lookup returns nothing, so
every deviation fails and the failure list is the measurement.
`tests/generate_foxio_deviations.py` writes a register from that measurement.
"""

import json
import logging
import os
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger(__name__)

REGISTER_PATH = Path(__file__).parent / "foxio_deviations.json"

# The suite reads this variable to measure a new baseline. It disables the lookup, so
# every registered case fails and the failure list names every deviation.
IGNORE_VARIABLE = "JA4PLUS_IGNORE_DEVIATIONS"


class Deviation(NamedTuple):
    """One registered conformance deviation.

    Attributes:
        issue: The number of the issue that fixes the deviation.
        cause: One line that states the cause.
    """

    issue: int
    cause: str

    def reason(self):
        """Return the `xfail` reason that names the issue and the cause."""
        return "issue #{}: {}".format(self.issue, self.cause)


def value_key(vector, stream_index, source_port, method, occurrence):
    """Return the register key of one value comparison.

    Args:
        vector: The capture file name, such as `tls-sni.pcapng`.
        stream_index: The stream index the reference gives.
        source_port: The source port of the first record on the stream.
        method: The method name, such as `JA4`.
        occurrence: The occurrence number, counted from 1.

    Returns:
        The key, in the form `<vector>/<stream>:<port>/<method>.<occurrence>`.
    """
    return "{}/{}:{}/{}.{}".format(vector, stream_index, source_port, method, occurrence)


def occurrence_key(vector, method):
    """Return the register key of one occurrence-key comparison.

    Args:
        vector: The capture file name, such as `ssh2.pcapng`.
        method: The method name, such as `JA4`.

    Returns:
        The key, in the form `<vector>/<method>`.
    """
    return "{}/{}".format(vector, method)


def load_register(path=REGISTER_PATH):
    """Return the deviation register.

    Args:
        path: The path of the register file. Defaults to the committed register.

    Returns:
        A map of key to Deviation. An absent file gives an empty register, because a
        repository with no known deviation holds no register file.

    Raises:
        ValueError: An entry names no issue, or states no cause, or is not a table.
    """
    if not Path(path).exists():
        return {}
    with open(path) as handle:
        entries = json.load(handle)
    register = {}
    for key, entry in entries.items():
        register[key] = _read_entry(key, entry)
    return register


def _read_entry(key, entry):
    """Return one Deviation, or raise ValueError naming the key."""
    if not isinstance(entry, dict):
        raise ValueError("deviation {}: the entry is not a table".format(key))
    issue = entry.get("issue")
    if not isinstance(issue, int) or isinstance(issue, bool) or issue <= 0:
        raise ValueError("deviation {}: the entry names no issue number".format(key))
    cause = entry.get("cause")
    if not isinstance(cause, str) or not cause.strip():
        raise ValueError("deviation {}: the entry states no cause".format(key))
    return Deviation(issue=issue, cause=cause)


def lookup(register, key):
    """Return the Deviation registered against the key, or None.

    Args:
        register: The register that `load_register` returns.
        key: A key that `value_key` or `occurrence_key` builds.

    Returns:
        The Deviation, or None. Returns None for every key when the environment sets
        `JA4PLUS_IGNORE_DEVIATIONS`, which is how a new baseline is measured.
    """
    if os.environ.get(IGNORE_VARIABLE):
        return None
    return register.get(key)
