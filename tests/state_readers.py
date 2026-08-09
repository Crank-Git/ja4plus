"""Readers that report the per-connection state one fingerprinter holds.

A case that calls `cleanup_connection` and asserts nothing passes against a call that
removes the wrong key, against a call that leaves the entry, and against a call that
removes a neighbouring connection. #339 records the twelve cases that read that way.

`BaseFingerprinter.state_tables` already finds every state table of a fingerprinter, so
one reader serves every method. The reader returns key sets, because a key set answers
the three questions above and a value does not.

Warning: read the state through these functions and not through the table itself. A read
of one key holds that entry against both eviction bounds, and a case that holds an entry
measures a table it changed. `BoundedStateTable.keys` holds no entry, and the `streams`
attribute of `TCPStreamReassembler` holds none either.
"""

from typing import Any

from ja4plus.utils.tcp_stream import TCPStreamReassembler

# The address pair of the connection a case removes. Every case builds its target
# connection from these two addresses, and `names_the_target` finds a key that holds
# either one.
TARGET_CLIENT = "10.0.0.1"
TARGET_SERVER = "10.0.0.2"

# The address pair of the connection a case keeps. A call that removes a neighbouring
# connection is one of the three failure modes #339 names, so every case builds a second
# connection that shares no address with the first.
NEIGHBOUR_CLIENT = "192.168.9.1"
NEIGHBOUR_SERVER = "192.168.9.2"

# The prefix both target addresses hold and neither neighbour address holds.
_TARGET_PREFIX = "10.0.0."


def state_keys(fingerprinter: Any) -> dict[str, set[Any]]:
    """Return the key set of every state table the fingerprinter holds.

    Args:
        fingerprinter: Any `BaseFingerprinter`.

    Returns:
        A dict that maps the table name `BaseFingerprinter.state_tables` reports to the
        keys that table holds. The dict is empty for a stateless method.
    """
    keys: dict[str, set[Any]] = {}
    for name, table in fingerprinter.state_tables().items():
        if isinstance(table, TCPStreamReassembler):
            keys[name] = set(table.streams)
        else:
            keys[name] = set(table.keys())
    return keys


def names_the_target(key: Any) -> bool:
    """Report whether one state table key names the target connection.

    A key is a string, or a tuple that holds the endpoints. The text form of both holds
    the address, so one test serves every key shape this project builds.

    Args:
        key: One key of one state table.

    Returns:
        True when the key holds either target address.
    """
    return _TARGET_PREFIX in repr(key)


def target_keys(fingerprinter: Any) -> dict[str, set[Any]]:
    """Return the keys that name the target connection, by table name.

    Args:
        fingerprinter: Any `BaseFingerprinter`.

    Returns:
        A dict that maps the table name to the keys of that table that name the target.
    """
    return {
        name: {key for key in keys if names_the_target(key)}
        for name, keys in state_keys(fingerprinter).items()
    }


def keys_without_the_target(fingerprinter: Any) -> dict[str, set[Any]]:
    """Return the state a correct `cleanup_connection` call leaves behind.

    Args:
        fingerprinter: Any `BaseFingerprinter`.

    Returns:
        A dict that maps the table name to the keys of that table that name no target
        address. A correct call removes every other key and holds these.
    """
    return {
        name: {key for key in keys if not names_the_target(key)}
        for name, keys in state_keys(fingerprinter).items()
    }


def count_keys(keys: dict[str, set[Any]]) -> int:
    """Return the count of keys across every table.

    Args:
        keys: The result of `state_keys`, `target_keys` or `keys_without_the_target`.

    Returns:
        The sum of the key counts.
    """
    return sum(len(table_keys) for table_keys in keys.values())
