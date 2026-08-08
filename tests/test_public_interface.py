"""The public interface of the package, and the marker that types it.

`docs/specs/features/04-typed-api.md` states FR-typed-api-9, FR-typed-api-10,
FR-typed-api-12 and FR-typed-api-13. Version 1.0.0 promises that the interface does not
change again before version 2.0.0, so this file reads the promise back.

Verified against: https://peps.python.org/pep-0561/ (retrieved 2026-08-08).
"""

from pathlib import Path

import pytest

import ja4plus
from ja4plus import processor as processor_module

# The interface version 1.0.0 promises. A name here stays until version 2.0.0, so the
# list is the decision this test guards and not a copy of `dir(ja4plus)`.
EXPECTED_PUBLIC_NAMES = [
    "FingerprintResult",
    "Processor",
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
    "compute_ja4x_from_der",
    "compute_ja4x_from_pem",
    "__version__",
]


def test_the_package_declares_its_public_interface():
    """FR-typed-api-12 asks `ja4plus/__init__.py` to list every public name."""
    assert ja4plus.__all__ == EXPECTED_PUBLIC_NAMES


@pytest.mark.parametrize("name", EXPECTED_PUBLIC_NAMES)
def test_every_public_name_is_importable_from_the_package(name):
    """A name in `__all__` that the package does not bind breaks `import *`."""
    assert hasattr(ja4plus, name), name


def test_the_public_interface_holds_no_duplicate_name():
    """A duplicate name hides a merge that added one name twice."""
    assert len(ja4plus.__all__) == len(set(ja4plus.__all__))


def test_the_side_effect_helpers_stay_out_of_the_public_interface():
    """`ja4plus/__init__.py` calls both helpers itself, so neither is a promised name.

    FR-typed-api-13 states that a name absent from `__all__` is not part of the
    interface the project promises.
    """
    assert "bind_loopback_ipv6" not in ja4plus.__all__
    assert "register_tunnel_dissectors" not in ja4plus.__all__


def test_the_processor_module_declares_ProcessorStats_public():
    """`Processor.stats` returns `dict[str, ProcessorStats]`, so the name is public.

    The name is public at `ja4plus.processor.ProcessorStats`, which is the import path
    `docs/api_reference.md` documents. #47 decides that the name is public and moves the
    class nowhere.
    """
    assert processor_module.__all__ == ["Processor", "ProcessorStats"]


def test_the_package_ships_the_py_typed_marker():
    """PEP 561 asks a package that supports type checking for a `py.typed` file."""
    marker = Path(ja4plus.__file__).resolve().parent / "py.typed"
    assert marker.is_file()


def test_the_build_ships_the_marker_as_package_data():
    """A marker that the wheel omits types nothing, and setuptools ships no unlisted file."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    assert '"py.typed"' in text
