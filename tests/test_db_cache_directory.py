"""`db update` writes to the cache directory alone, issue #61.

A package directory may be read-only, several users may share it, and the next
`pip install` replaces it. `db update` therefore writes the mapping file to the platform
cache directory, and it leaves the installed package byte for byte as it was.

The client reads a mapping file that this program did not write, so the cases below prove
both directions of FR-db-enrichment-13. A cached mapping file wins over the bundled one,
and a cache file that holds no entry falls back to the bundled one at `WARNING`.

Every case writes inside its own temporary directory and reaches no network. The
`no_network` fixture of `tests/test_db_offline.py` blocks every outbound socket.
"""

import hashlib
import io
import logging
import os
import sys
import urllib.request
from unittest.mock import patch

import pytest

import ja4plus.ja4db as ja4db
import tests.test_db_offline as db_offline
from ja4plus.ja4db import JA4DBClient

# The `no_network` fixture of #57 blocks every outbound socket. The assignment registers
# it in this module, and an import of the name would shadow every case that requests it.
no_network = db_offline.no_network

# A fingerprint the bundled mapping file holds.
BUNDLED_FINGERPRINT = "t13d1516h2_8daaf6152771_02713d6af862"

# A fingerprint that no bundled mapping file holds. Only a cached mapping file names it,
# so a lookup that answers it proves which file the client read.
CACHE_ONLY_FINGERPRINT = "t13d000000_000000000000_000000000061"

# One mapping file that names the cache-only fingerprint. The header carries the column
# names that `db update` checks for.
CACHE_CSV = (
    "Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes\r\n"
    f"Issue 61 Client,,,,{CACHE_ONLY_FINGERPRINT},,,,,,a cached entry\r\n"
)


def run_cli(*argv):
    """Run the command and return its standard output, standard error and exit status.

    Args:
        *argv: The arguments that follow the program name.

    Returns:
        A tuple of the standard output, the standard error and the exit status. The
        status is zero when `main` returns.
    """
    from ja4plus.cli import main

    captured_out = io.StringIO()
    captured_err = io.StringIO()
    exit_code = 0
    with (
        patch("sys.argv", ["ja4plus"] + list(argv)),
        patch("sys.stdout", captured_out),
        patch("sys.stderr", captured_err),
    ):
        try:
            main()
        except SystemExit as e:
            exit_code = e.code if e.code is not None else 0
    return captured_out.getvalue(), captured_err.getvalue(), exit_code


class StubDownload:
    """A stand-in for the object `urllib.request.urlopen` returns.

    Args:
        body: The text the download reports.
    """

    def __init__(self, body):
        self._body = body

    def read(self):
        """Return the body as bytes."""
        return self._body.encode("utf-8")


def stub_urlopen(body):
    """Return a stand-in for `urlopen` that reaches no network.

    Args:
        body: The text the download reports.

    Returns:
        A callable that accepts the arguments `urlopen` accepts.
    """

    def opener(*args, **kwargs):
        return StubDownload(body)

    return opener


def package_digest():
    """Return one digest over every tracked file of the installed package.

    The digest covers the file names and the file bytes, so a new file changes it as much
    as an edit does. It skips `__pycache__`, because the interpreter writes there.

    Returns:
        The digest as a hexadecimal string.
    """
    root = os.path.dirname(ja4db.__file__)
    digest = hashlib.sha256()
    for directory, subdirectories, names in os.walk(root):
        subdirectories[:] = sorted(n for n in subdirectories if n != "__pycache__")
        for name in sorted(names):
            path = os.path.join(directory, name)
            digest.update(os.path.relpath(path, root).encode("utf-8"))
            with open(path, "rb") as handle:
                digest.update(handle.read())
    return digest.hexdigest()


@pytest.fixture
def cache_home(tmp_path, monkeypatch):
    """Point the cache directory at a temporary directory.

    The convention reads `$XDG_CACHE_HOME` on Linux and the home directory on macOS, so
    the fixture sets both names. No case writes outside the directory it returns.

    Args:
        tmp_path: The pytest fixture that holds one directory for one case.
        monkeypatch: The pytest fixture that restores each name after the case.

    Returns:
        The cache directory of the program, which no case creates in advance.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    # `expanduser` reads a cached home directory on some platforms, and it reads `HOME`
    # again once the case clears that cache.
    monkeypatch.delenv("USERPROFILE", raising=False)
    return os.path.dirname(ja4db.cache_file_path())


class TestTheCacheDirectoryFollowsThePlatformConvention:
    """The cache directory is `$XDG_CACHE_HOME/ja4plus` or `~/.cache/ja4plus` on Linux,
    and `~/Library/Caches/ja4plus` on macOS."""

    def test_the_cache_file_carries_the_name_of_the_mapping_file(self, cache_home):
        assert os.path.basename(ja4db.cache_file_path()) == "ja4plus-mapping.csv"
        assert os.path.basename(cache_home) == "ja4plus"

    @pytest.mark.skipif(sys.platform != "darwin", reason="the macOS convention")
    def test_the_cache_directory_is_under_the_library_on_macos(self, cache_home, tmp_path):
        assert cache_home == str(tmp_path / "home" / "Library" / "Caches" / "ja4plus")

    @pytest.mark.skipif(sys.platform == "darwin", reason="the Linux convention")
    def test_the_cache_directory_reads_xdg_cache_home(self, cache_home, tmp_path):
        assert cache_home == str(tmp_path / "xdg" / "ja4plus")

    @pytest.mark.skipif(sys.platform == "darwin", reason="the Linux convention")
    def test_the_cache_directory_falls_back_to_the_home_directory(
        self, cache_home, tmp_path, monkeypatch
    ):
        """An operator who sets no `XDG_CACHE_HOME` gets `~/.cache/ja4plus`."""
        monkeypatch.delenv("XDG_CACHE_HOME")
        assert os.path.dirname(ja4db.cache_file_path()) == str(
            tmp_path / "home" / ".cache" / "ja4plus"
        )

    def test_the_cache_directory_is_outside_the_installed_package(self, cache_home):
        package = os.path.dirname(ja4db.__file__)
        assert os.path.commonpath([package, ja4db.cache_file_path()]) != package


class TestDbUpdateWritesToTheCacheDirectory:
    """`db update` downloads the mapping file to the cache directory and leaves the
    bundled file unchanged, FR-db-enrichment-12."""

    def test_db_update_writes_the_mapping_file_to_the_cache_directory(
        self, cache_home, no_network, monkeypatch
    ):
        monkeypatch.setattr(urllib.request, "urlopen", stub_urlopen(CACHE_CSV))
        out, err, status = run_cli("db", "update")
        assert status == 0
        cache_file = os.path.join(cache_home, "ja4plus-mapping.csv")
        assert os.path.exists(cache_file)
        with open(cache_file, "rb") as handle:
            assert handle.read() == CACHE_CSV.encode("utf-8")
        assert cache_file in out

    def test_db_update_leaves_the_installed_package_unchanged(
        self, cache_home, no_network, monkeypatch
    ):
        """A package directory may be read-only, and the next `pip install` replaces it."""
        before = package_digest()
        monkeypatch.setattr(urllib.request, "urlopen", stub_urlopen(CACHE_CSV))
        _, _, status = run_cli("db", "update")
        assert status == 0
        assert package_digest() == before

    def test_db_update_leaves_the_bundled_mapping_file_unchanged(
        self, cache_home, no_network, monkeypatch
    ):
        with open(ja4db._BUNDLED_CSV, "rb") as handle:
            before = handle.read()
        monkeypatch.setattr(urllib.request, "urlopen", stub_urlopen(CACHE_CSV))
        _, _, status = run_cli("db", "update")
        assert status == 0
        with open(ja4db._BUNDLED_CSV, "rb") as handle:
            assert handle.read() == before

    def test_db_update_leaves_no_temporary_file_behind(self, cache_home, monkeypatch):
        """The command writes a temporary file and renames it, so no reader ever sees a
        part of the download."""
        monkeypatch.setattr(urllib.request, "urlopen", stub_urlopen(CACHE_CSV))
        run_cli("db", "update")
        assert sorted(os.listdir(cache_home)) == ["ja4plus-mapping.csv"]

    def test_a_download_that_fails_leaves_the_cache_file_unchanged(self, cache_home, monkeypatch):
        os.makedirs(cache_home)
        cache_file = os.path.join(cache_home, "ja4plus-mapping.csv")
        with open(cache_file, "w", encoding="utf-8") as handle:
            handle.write(CACHE_CSV)

        def refuse(*args, **kwargs):
            raise OSError("Name or service not known")

        monkeypatch.setattr(urllib.request, "urlopen", refuse)
        _, err, status = run_cli("db", "update")
        assert status == 1
        with open(cache_file, "rb") as handle:
            assert handle.read() == CACHE_CSV.encode("utf-8")
        assert "could not download" in err

    def test_a_download_that_holds_no_mapping_file_leaves_the_cache_file_unchanged(
        self, cache_home, monkeypatch
    ):
        os.makedirs(cache_home)
        cache_file = os.path.join(cache_home, "ja4plus-mapping.csv")
        with open(cache_file, "w", encoding="utf-8") as handle:
            handle.write(CACHE_CSV)
        monkeypatch.setattr(urllib.request, "urlopen", stub_urlopen("<html>404</html>\n\n"))
        _, err, status = run_cli("db", "update")
        assert status == 1
        with open(cache_file, "rb") as handle:
            assert handle.read() == CACHE_CSV.encode("utf-8")

    def test_a_cache_directory_that_no_operator_can_create_names_the_directory(
        self, cache_home, monkeypatch
    ):
        def refuse(*args, **kwargs):
            raise PermissionError("Permission denied")

        monkeypatch.setattr(os, "makedirs", refuse)
        _, err, status = run_cli("db", "update")
        assert status == 1
        assert cache_home in err


class TestTheClientPrefersTheCachedMappingFile:
    """The client prefers a cached mapping file over the bundled one,
    FR-db-enrichment-13."""

    def write_cache_file(self, cache_home, text):
        """Write one cache file and return its path.

        Args:
            cache_home: The cache directory the case owns.
            text: The bytes or the text the cache file holds.

        Returns:
            The path of the cache file.
        """
        os.makedirs(cache_home, exist_ok=True)
        path = os.path.join(cache_home, "ja4plus-mapping.csv")
        mode = "wb" if isinstance(text, bytes) else "w"
        with open(path, mode) as handle:
            handle.write(text)
        return path

    def test_the_client_reads_the_cached_mapping_file(self, cache_home, no_network):
        self.write_cache_file(cache_home, CACHE_CSV)
        client = JA4DBClient(allow_remote=False)
        result = client.lookup(CACHE_ONLY_FINGERPRINT)
        assert result is not None
        assert result["application"] == "Issue 61 Client"

    def test_the_client_reads_the_bundled_mapping_file_when_no_cache_file_exists(
        self, cache_home, no_network
    ):
        """The other half of the contract. The bundled file answers an operator who ran
        no `db update`."""
        assert not os.path.exists(ja4db.cache_file_path())
        client = JA4DBClient(allow_remote=False)
        assert client.lookup(CACHE_ONLY_FINGERPRINT) is None
        assert client.lookup(BUNDLED_FINGERPRINT) is not None

    def test_an_empty_cache_file_falls_back_to_the_bundled_file(self, cache_home, no_network):
        self.write_cache_file(cache_home, "")
        client = JA4DBClient(allow_remote=False)
        assert client.lookup(BUNDLED_FINGERPRINT) is not None

    def test_a_corrupt_cache_file_falls_back_to_the_bundled_file(self, cache_home, no_network):
        self.write_cache_file(cache_home, b"\x00\x01\x02 not a mapping file \xff\xfe")
        client = JA4DBClient(allow_remote=False)
        assert client.lookup(BUNDLED_FINGERPRINT) is not None

    def test_a_corrupt_cache_file_reports_the_problem_at_warning(
        self, cache_home, no_network, caplog
    ):
        self.write_cache_file(cache_home, b"\x00\x01\x02 not a mapping file \xff\xfe")
        with caplog.at_level(logging.WARNING, logger="ja4plus.ja4db"):
            JA4DBClient(allow_remote=False)
        assert [record for record in caplog.records if record.levelno == logging.WARNING]

    def test_a_cache_file_that_the_client_cannot_read_falls_back_to_the_bundled_file(
        self, cache_home, no_network
    ):
        """A file this program did not write is hostile input. The client reads the
        bundled file instead, and it raises nothing."""
        path = self.write_cache_file(cache_home, CACHE_CSV)
        os.chmod(path, 0o000)
        if os.access(path, os.R_OK):
            pytest.skip("the user reads a file whose mode denies it")
        try:
            client = JA4DBClient(allow_remote=False)
            assert client.lookup(BUNDLED_FINGERPRINT) is not None
        finally:
            os.chmod(path, 0o600)


class TestDbInfoReportsTheSource:
    """`db info` reports the mapping file path, its entry count and its source,
    FR-db-enrichment-11."""

    def test_db_info_reports_the_path_the_entry_count_and_the_source(self, cache_home, no_network):
        out, _, status = run_cli("db", "info")
        assert status == 0
        assert ja4db._BUNDLED_CSV in out
        assert "Source:" in out
        assert "bundled" in out
        assert "Entries:" in out

    def test_db_info_reports_bundled_as_the_source_when_no_cache_file_exists(
        self, cache_home, no_network
    ):
        out, _, _ = run_cli("db", "info")
        assert "Source:   bundled" in out

    def test_db_info_reports_cache_as_the_source_after_db_update(
        self, cache_home, no_network, monkeypatch
    ):
        monkeypatch.setattr(urllib.request, "urlopen", stub_urlopen(CACHE_CSV))
        assert run_cli("db", "update")[2] == 0
        out, _, status = run_cli("db", "info")
        assert status == 0
        assert "Source:   cache" in out
        assert ja4db.cache_file_path() in out
        assert "Entries:  1" in out

    def test_db_info_reports_bundled_as_the_source_for_a_corrupt_cache_file(
        self, cache_home, no_network
    ):
        os.makedirs(cache_home)
        with open(os.path.join(cache_home, "ja4plus-mapping.csv"), "wb") as handle:
            handle.write(b"\x00\x01\x02 not a mapping file \xff\xfe")
        out, _, status = run_cli("db", "info")
        assert status == 0
        assert "Source:   bundled" in out

    def test_db_info_reports_a_cache_file_that_holds_no_entry(self, cache_home, no_network):
        """A hint that names no cache file would contradict the file on disk."""
        os.makedirs(cache_home)
        with open(os.path.join(cache_home, "ja4plus-mapping.csv"), "wb") as handle:
            handle.write(b"\x00\x01\x02 not a mapping file \xff\xfe")
        out, _, _ = run_cli("db", "info")
        assert "No cache file at" not in out
        assert f"The cache file at {ja4db.cache_file_path()} holds no entry." in out

    def test_db_info_names_the_cache_file_the_operator_has_not_downloaded(
        self, cache_home, no_network
    ):
        """The port prints the same hint, at `cmd/ja4plus/main.go:389`."""
        out, _, _ = run_cli("db", "info")
        assert ja4db.cache_file_path() in out
        assert "db update" in out
