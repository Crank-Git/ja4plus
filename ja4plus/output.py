"""The writers that turn a `FingerprintResult` into an output line.

`docs/specs/features/05-structured-output.md` defines this module. The JSON Lines
format and the CSV format carry a stability promise, so both write the same field set
whatever flags the user passed. The table format is for a person reading a terminal,
and it carries no promise.

A writer reads a `FingerprintResult` and adds the two fields the command-line program
owns: `schema_version` and `identified_as`. `ja4plus/types.py` states why the library
result carries neither.
"""

# This import makes every annotation a string. No annotation therefore evaluates at
# import time, and a forward reference needs no quotation mark.
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from typing import Any, TextIO

from ja4plus.types import FingerprintResult

__all__ = [
    "CSV_COLUMNS",
    "SCHEMA_VERSION",
    "CsvWriter",
    "JsonLinesWriter",
    "OutputWriter",
    "TableWriter",
    "build_writer",
]

# The behaviour rules of `docs/specs/features/05-structured-output.md` state that the
# schema version starts at 1, and the acceptance criteria of #50 state the same value.
# #50 owns the rule that raises it and the document that records it. This module writes
# the value and decides nothing about it.
SCHEMA_VERSION = 1

# FR-structured-output-4 fixes this order, and a new column appends to the end. A
# downstream parser reads a column by position, so an insertion breaks it.
CSV_COLUMNS = (
    "schema_version",
    "timestamp",
    "type",
    "fingerprint",
    "raw",
    "raw_original_order",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "identified_as",
)

# The table format aligns the source column to this width. The value matches the width
# version 0.6.0 used, so a person who reads both releases sees one layout.
_SOURCE_WIDTH = 50
_TYPE_WIDTH = 10
_RULE_WIDTH = 90


def format_timestamp(value: datetime | None) -> str | None:
    """Return the time in RFC 3339 form, or None when there is no time.

    A time that carries no zone reads as UTC, because a packet timestamp counts seconds
    from the epoch and names no zone. The call writes the suffix `Z` rather than
    `+00:00`, because the mockup and the schema example both show `Z`.

    Args:
        value: The packet timestamp, or None when the packet carries none.

    Returns:
        A string such as `2026-08-06T12:34:56.789012Z`, or None.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def display_source(result: FingerprintResult) -> str:
    """Return the endpoints of the result as one string for a person to read.

    Only the table format calls this. FR-structured-output-1 asks every format to carry
    the addresses and the ports as separate fields, and the JSON and CSV writers do.

    Args:
        result: The result to describe.

    Returns:
        `src_ip:src_port -> dst_ip:dst_port` when the result carries ports,
        `src_ip -> dst_ip` when it carries addresses alone, and `unknown` when it
        carries neither. Version 0.6.0 wrote the same three forms.
    """
    if result.src_port or result.dst_port:
        return f"{result.src_ip}:{result.src_port} -> {result.dst_ip}:{result.dst_port}"
    if result.src_ip or result.dst_ip:
        return f"{result.src_ip} -> {result.dst_ip}"
    return "unknown"


class OutputWriter:
    """The interface the three formats share.

    A caller builds one writer, calls `write_header` once, then calls `write` for each
    result. A format with no header leaves `write_header` as the call that does nothing.

    Args:
        stream: The text stream the writer writes to.
    """

    def __init__(self, stream: TextIO) -> None:
        self.stream = stream

    def write_header(self) -> None:
        """Write the header of the format. The base class writes nothing."""

    def write(self, result: FingerprintResult, identified_as: str | None = None) -> None:
        """Write one output line.

        Args:
            result: The fingerprint and the endpoints that produced it.
            identified_as: The application name the lookup returned, or None when the
                user passed no `--lookup` or the lookup found no match.

        Raises:
            NotImplementedError: The base class writes no output line.
        """
        raise NotImplementedError


class JsonLinesWriter(OutputWriter):
    """The writer that puts one JSON object on each line.

    FR-structured-output-2 asks for one object per line, so the output is not one JSON
    array. A reader that streams the output parses each line on its own.
    """

    def write(self, result: FingerprintResult, identified_as: str | None = None) -> None:
        """Write one JSON object and one newline.

        FR-structured-output-5 asks for a field that is present and null rather than
        absent, so the object holds every column of `CSV_COLUMNS`.

        Args:
            result: The fingerprint and the endpoints that produced it.
            identified_as: The application name the lookup returned, or None.
        """
        json_object: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": format_timestamp(result.timestamp),
            "type": result.type,
            "fingerprint": result.fingerprint,
            "raw": result.raw,
            "raw_original_order": result.raw_original_order,
            "src_ip": result.src_ip,
            "src_port": result.src_port,
            "dst_ip": result.dst_ip,
            "dst_port": result.dst_port,
            "identified_as": identified_as or None,
        }
        self.stream.write(json.dumps(json_object) + "\n")


class CsvWriter(OutputWriter):
    """The writer that puts one CSV row on each line.

    FR-structured-output-4 asks for the same columns whatever flags the user passed, so
    the header and every row hold all eleven columns of `CSV_COLUMNS`.
    """

    def __init__(self, stream: TextIO) -> None:
        super().__init__(stream)
        # typeshed publishes no public name for the object `csv.writer` returns. The
        # module quotes a field that holds a comma, which a hand-built row would not.
        self._writer: Any = csv.writer(stream)

    def write_header(self) -> None:
        """Write the header row."""
        self._writer.writerow(list(CSV_COLUMNS))

    def write(self, result: FingerprintResult, identified_as: str | None = None) -> None:
        """Write one data row.

        FR-structured-output-5 asks for a column that is empty rather than absent, so a
        value of None writes an empty column.

        Args:
            result: The fingerprint and the endpoints that produced it.
            identified_as: The application name the lookup returned, or None.
        """
        self._writer.writerow(
            [
                SCHEMA_VERSION,
                format_timestamp(result.timestamp) or "",
                result.type,
                result.fingerprint,
                result.raw or "",
                result.raw_original_order or "",
                result.src_ip,
                result.src_port,
                result.dst_ip,
                result.dst_port,
                identified_as or "",
            ]
        )


class TableWriter(OutputWriter):
    """The writer that aligns the output lines for a person reading a terminal.

    FR-structured-output-7 gives this format no stability promise, so it writes the
    endpoints as one source column. A tool reads the JSON or the CSV format instead.
    """

    def write_header(self) -> None:
        """Write the column names and the rule below them."""
        self.stream.write(f"{'Source':<{_SOURCE_WIDTH}}  {'Type':<{_TYPE_WIDTH}}  Fingerprint\n")
        self.stream.write("-" * _RULE_WIDTH + "\n")

    def write(self, result: FingerprintResult, identified_as: str | None = None) -> None:
        """Write one aligned row.

        Args:
            result: The fingerprint and the endpoints that produced it.
            identified_as: The application name the lookup returned, or None. The row
                holds it in brackets at the end when the lookup found a match.
        """
        source = display_source(result)
        row = f"{source:<{_SOURCE_WIDTH}}  {result.type:<{_TYPE_WIDTH}}  {result.fingerprint}"
        if identified_as:
            row += f"  ({identified_as})"
        self.stream.write(row + "\n")


def build_writer(fmt: str, stream: TextIO) -> OutputWriter:
    """Return the writer that the format name selects.

    Args:
        fmt: One of `table`, `json` and `csv`. FR-structured-output-6 names the three.
        stream: The text stream the writer writes to.

    Returns:
        The writer for that format. An unknown name returns the table writer, because
        `argparse` rejects an unknown name before the program reaches this call.
    """
    if fmt == "json":
        return JsonLinesWriter(stream)
    if fmt == "csv":
        return CsvWriter(stream)
    return TableWriter(stream)
