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

## The marker rule

An entry whose cause cites a decision carries `"decided": true`. An entry that cites no
decision stays unmarked, and that is the correct state for an entry that stays open. An
unmarked entry states that nobody read it, so a marker that is missing hides a decision.

`unmarked_decisions` in `tests/test_foxio_deviations.py` enforces the rule. It reads four
forms of citation as evidence that a person decided an entry:

| Form | Example |
|---|---|
| A Changelog round named by number | `Changelog round 66 settled the marker.` |
| A decision recorded against an issue or a date | `decided on #105`, `decided on 2026-08-07` |
| An issue named as the place the decision was made | `#138 decided to keep the values.` |
| An issue named as the record of the decision | `#162 records the decision.` |

Every form is past tense. An entry that names the issue that will decide it names no
decision, so `#215 decides whether ja4plus reads the raw option bytes` leaves the entry
open. A denied citation is not a citation either, so `no Changelog round settled it`
leaves the entry open.

The guard on a denied citation reads the word before the citation alone. A cause that
denies a citation in other words fails the gate. Reword the cause. A gate that misses a
decision costs more than a gate that asks a question.

The rule runs in one direction. An entry that cites no decision may still carry the
marker, which 38 of the 134 decided entries do. A FoxIO Rust snapshot settled those by
measurement, and no person decided them. The 38 are the 34 entries of #138 and 4 of the 5
entries of #151.

`TestTheMarkerRuleCounts` in `tests/test_foxio_deviations.py` reads the two counts out of
the sentence above and measures them against the register. The denominator went stale
twice, because no case measured it. Correct the sentence whenever the register moves, and
the case names both numbers in its failure.

## The kind of decline

A decided entry records one of two kinds of decline, and `"capability"` states which.

| Field | The kind | What it records |
|---|---|---|
| `"capability": false` | A value decline | A disagreement about the value. An implementation change on either side could close it. |
| `"capability": true` | A capability decline | A capability this project chose not to build. No implementation change closes it, because the difference is the scope this project chose. |

**The default is `false`, and the default is a statement rather than an absence.** An
entry with no field is a value decline. The reader states the default on `Deviation`, and
no caller reads the kind from the prose of a cause.

`unrecorded_kinds` in `tests/test_foxio_deviations.py` requires the field on every
decided entry, so a new decline states its kind at the moment a person decides it. An
undecided entry declines nothing, so it may omit the field.

The kind is load-bearing. The source-neutral precedence exception of
`.claude/rules/external-apis.md` reaches a value decline and passes over a capability
decline, and `tests/test_precedence_exception.py` reads this field for that bar. #334
held the same fact as a set of issue numbers inside that test file, and #341 moved it
here.

43 entries record a capability decline today, and all 43 name #129. `ja4plus` reads no
encrypted request and no encrypted certificate, by a decision Changelog round 26 settled.

## How to remove an entry

A fix that lands makes the case pass, and the strict marker turns that pass into a
failure that names the case. Delete the entry in the same change that lands the fix.
Never delete an entry to make a red suite green.

## How to refresh the owner list

`tests/foxio_deviation_owners.json` records the state of every issue the register names.
`TestTheRegisterOwners` reads it and rejects an owner that no worker can act on: an epic,
or a closed issue that no decision record explains. The register named the epic #13 for
five batches, and no test caught it.

Warning: a refresh turns the suite red whenever an owner closed since the last refresh.
The red suite is the true state. The repair is to point the entry at an open issue. Never
restore the stale state, and never mark the entry `decided`. #255 refreshed the file, and
six undecided entries named the closed #34. The `retrieved` date detects nothing here,
because #34 closed on the day the file records.

The file is checked in, so the unit suite reaches no network. Refresh it with:

```bash
gh issue list --state all --limit 500 --json number,state,labels,title
```

An entry whose owner the file does not hold fails the test. Add the owner, or point the
entry at an issue the file already holds.

Whenever an owner closes, refresh the file. An owner that no register entry names may stay
in the file. #34 stays as the record of the earlier owner of the six JA4L entries.

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

OWNERS_PATH = Path(__file__).parent / "foxio_deviation_owners.json"

# The suite reads this variable to measure a new baseline. It disables the lookup, so
# every registered case fails and the failure list names every deviation.
IGNORE_VARIABLE = "JA4PLUS_IGNORE_DEVIATIONS"


class Deviation(NamedTuple):
    """One registered conformance deviation.

    Attributes:
        issue: The number of the issue that fixes the deviation.
        cause: One line that states the cause.
        decided: True when the issue is a decision record. A decided deviation is
            permanent, so its issue is closed and no fix removes the entry.
        capability: True when the decline records a capability this project chose not to
            build. False records a disagreement about the value. The default is False,
            which states that an entry with no field is a value decline.
    """

    issue: int
    cause: str
    decided: bool = False
    capability: bool = False

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
    decided = entry.get("decided", False)
    if not isinstance(decided, bool):
        raise ValueError("deviation {}: the decided field is not true or false".format(key))
    capability = entry.get("capability", False)
    if not isinstance(capability, bool):
        raise ValueError("deviation {}: the capability field is not true or false".format(key))
    return Deviation(issue=issue, cause=cause, decided=decided, capability=capability)


class Owner(NamedTuple):
    """The recorded state of one issue the register names.

    Attributes:
        number: The issue number.
        state: The issue state, `open` or `closed`.
        epic: True when the issue carries the `type:epic` label.
        title: The issue title, which names the owner for a reader.
    """

    number: int
    state: str
    epic: bool
    title: str


def load_owners(path=OWNERS_PATH):
    """Return the recorded state of every issue the register names.

    The file is checked in, so no test reaches the network. The module docstring holds
    the command that refreshes it.

    Args:
        path: The path of the owner file. Defaults to the committed file.

    Returns:
        A map of issue number to Owner.

    Raises:
        ValueError: An owner names a state the file does not allow.
    """
    with open(path) as handle:
        document = json.load(handle)
    owners = {}
    for number, entry in document["owners"].items():
        state = entry.get("state")
        if state not in ("open", "closed"):
            raise ValueError("owner {}: the state is not open or closed".format(number))
        owners[int(number)] = Owner(
            number=int(number),
            state=state,
            epic=bool(entry.get("epic", False)),
            title=entry.get("title", ""),
        )
    return owners


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
