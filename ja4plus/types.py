"""The typed result the public interface returns.

`docs/specs/features/04-typed-api.md` defines this module. The `### Result` table of
`docs/specs/spec.md` holds the field list, and `tests/test_types.py` reads that table
back.
"""

# Python 3.9 is the floor, and it evaluates no annotation written as `str | None`
# without this import.
from __future__ import annotations

import dataclasses
import warnings
from dataclasses import dataclass
from datetime import datetime
from typing import Any

__all__ = ["FingerprintResult"]


@dataclass(frozen=True)
class FingerprintResult:
    """One fingerprint, with the addresses and the time of the packet that made it.

    The field names are the snake-case form of the `FingerprintResult` struct of the Go
    port, under parity rule 2. The field that names the method is `type`, because the
    port calls it `Type` and the dictionary of version 0.6.0 already uses that key.

    The result is frozen. It describes something that already happened, so nothing
    changes it after a fingerprinter returns it.

    Attributes:
        type: The method name, lowercase. One of the ten this library implements.
        fingerprint: The fingerprint string. Never empty.
        raw: The raw form, when the method defines one.
        raw_original_order: The original-order raw form, when the method defines one.
        src_ip: The source address. Empty when the packet carries no address.
        src_port: The source port. Zero when the packet carries no port.
        dst_ip: The destination address.
        dst_port: The destination port.
        timestamp: The packet timestamp, or None when the packet carries none.

    Verified against: https://github.com/Crank-Git/ja4plus-go/blob/master/types.go
    (retrieved 2026-08-06).
    """

    type: str
    fingerprint: str
    raw: str | None = None
    raw_original_order: str | None = None
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    timestamp: datetime | None = None

    def __getitem__(self, key: str) -> Any:
        """Return the value of the field the key names.

        Version 0.6.0 returned a dictionary. This method keeps that caller working for
        one major version, and it warns the caller to read the attribute instead.

        Args:
            key: A field name of this dataclass.

        Returns:
            The value the field of that name holds.

        Raises:
            KeyError: This dataclass holds no field of that name. The key `"method"`
                reaches this, because the field is `type`.
        """
        if key not in _FIELD_NAMES:
            raise KeyError(key)
        warnings.warn(
            f"Item access on a FingerprintResult is deprecated. Read result.{key} instead.",
            DeprecationWarning,
            # The caller's line is the useful one, not this method's line.
            stacklevel=2,
        )
        return getattr(self, key)


# The membership test of `__getitem__` reads this set, so item access reaches a field
# and no other attribute.
_FIELD_NAMES = frozenset(field.name for field in dataclasses.fields(FingerprintResult))
