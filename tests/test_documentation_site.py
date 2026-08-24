"""Tests that the documentation site is configured and that every internal link resolves.

`FR-documentation-7` asks the site to build from the Markdown files that already exist.
`FR-documentation-9` asks the site to carry an API reference generated from the
docstrings. `FR-documentation-15` asks a broken internal link to fail the build.

**`mkdocs build --strict` is the command that carries the requirement.** These cases
stand in front of it, because the unit suite installs the `dev` extra and not the `docs`
extra, so no case here imports `mkdocs`. They read the site configuration and the pages
as text, and they resolve every internal link the way the build resolves it.

**One case is stricter than the build, and `_publishes` records the measurement.** A link
into the excluded `docs/specs/` returns a 404 on the published site, and the build reports
it at the information level, which strict mode does not fail.

**A case here reads the published page set, which excludes `docs/specs/`.** The
specification package is design material. `mkdocs.yml` excludes it from the site, so a
link inside it reaches no build.

These cases read prose and configuration. They import nothing from `ja4plus` and they
produce no fingerprint.
"""

from pathlib import Path
import json
import re
import unicodedata

import pytest

from tests.dependency_entries import dependency_entries

REPO_ROOT = Path(__file__).resolve().parent.parent

CONFIGURATION = REPO_ROOT / "mkdocs.yml"
DOCS_DIR = REPO_ROOT / "docs"
PYPROJECT = REPO_ROOT / "pyproject.toml"

# The workflow that runs the unit suite on every job of the matrix.
TEST_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "test.yml"

# The allowlist of the skip gate. An entry here records a case that runs on no job.
SKIP_ALLOWLIST = REPO_ROOT / "tests" / "universal_skips.json"

# The slug case, in the form `tests/skip_gate.py` reads from a JUnit report.
SLUG_CASE = "tests.test_documentation_site::test_the_slug_of_a_case_matches_the_slug_of_the_build"

# The install command that puts `pymdownx` on the import path of a job.
DOCS_INSTALL = 'pip install -e ".[docs]"'

# The one job of the matrix that installs the `docs` extra. One run of the slug case is the
# whole requirement, so an install on every job of the matrix buys nothing.
DOCS_EXTRA_CONDITIONS = ("matrix.os == 'ubuntu-latest'", "matrix.python-version == '3.13'")

# One step of a job, as `.github/workflows/test.yml` indents it.
WORKFLOW_STEP = "\n      - name: "

# The job of `.github/workflows/test.yml` that runs the unit suite on the matrix.
MATRIX_JOB = "test"

# The key of one job, at the indentation `.github/workflows/test.yml` gives it. Every job of
# that file indents a step the same way, so a reader of the whole file accepts a step in a
# job that runs no matrix, and `matrix.python-version` resolves to nothing there.
JOB_KEY = re.compile(r"^  [a-z-]+:$", re.MULTILINE)

# The job that installs the `docs` extra into an empty environment and builds the site.
# **The name `docs.yml` belongs to #66**, which publishes the site, so this job takes a
# name of its own and the two never collide.
DOCS_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "docs-build.yml"

# `mkdocs.yml` excludes this directory from the site. A page under it is design material
# and it carries links that the site never resolves.
EXCLUDED_DIRECTORY = "specs"

# An inline Markdown link or image, as `[text](target)` or `![alt](target)`. The target
# stops at the first whitespace, because a link carries an optional title after a space.
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(\s*([^)\s]+)")

# A fenced code block. A sample inside one is text and not a link, so the checker removes
# every block before it reads the links.
FENCED_BLOCK = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)

# An ATX heading, as `## The output schema`. The table of contents of Python-Markdown
# builds one anchor from each heading.
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*$", re.MULTILINE)

# An explicit anchor, as `<a id="name">` or `<a name="name">`. A page writes one where the
# heading slug is not the wanted anchor.
EXPLICIT_ANCHOR = re.compile(r"<a\s[^>]*(?:id|name)=[\"']([^\"']+)[\"']")

# A scheme this checker does not resolve on disk.
EXTERNAL_SCHEMES = ("http://", "https://", "mailto:", "ftp://", "tel:")

# A path that `mkdocs.yml` names, as `  - Usage: usage.md`. Every such path is relative to
# `docs_dir`.
CONFIGURED_PAGE = re.compile(r"^\s*-\s+(?:[^:\n]+:\s*)?([A-Za-z0-9_./-]+\.md)\s*$", re.MULTILINE)

# The identifier that mkdocstrings renders, as `::: ja4plus.processor.Processor`.
MKDOCSTRINGS_IDENTIFIER = re.compile(r"^:::\s+(\S+)\s*$", re.MULTILINE)

# The floor guards the checker itself. A parser that reads no page passes every link case
# on an empty list. The published set held these counts when #64 landed, and both grow.
MINIMUM_PUBLISHED_PAGES = 10
MINIMUM_INTERNAL_LINKS = 20
MINIMUM_PUBLISHED_HEADINGS = 200


def _published_pages() -> list[Path]:
    """Return every Markdown page the site publishes.

    Returns:
        The `*.md` files under `docs/`, without the specification package.
    """
    pages = [
        path
        for path in sorted(DOCS_DIR.rglob("*.md"))
        if EXCLUDED_DIRECTORY not in path.relative_to(DOCS_DIR).parts
    ]
    assert len(pages) >= MINIMUM_PUBLISHED_PAGES, (
        f"the checker read {len(pages)} pages, and the floor is {MINIMUM_PUBLISHED_PAGES}"
    )
    return pages


def _slug(heading: str) -> str:
    """Return the anchor that `mkdocs.yml` builds for one heading.

    `mkdocs.yml` gives the `toc` extension `pymdownx.slugs.slugify(case="lower")`, and
    `_uslugify` of `pymdownx/slugs.py` states these five steps. This function reproduces
    them, because the unit suite installs the `dev` extra and imports no `pymdownx`.

    **Never replace a run of spaces with one hyphen.** The source calls `str.replace`,
    which keeps every space, so `JA4 — TLS client` slugs to `ja4--tls-client` with two
    hyphens. A first form of this function collapsed the run, and it disagreed with the
    build on 84 headings of 268. No link pointed at one of the 84, so the case passed
    while it compared the wrong value.

    Args:
        heading: The heading text, without its `#` characters.

    Returns:
        The anchor, without the leading `#`.
    """
    # Python-Markdown slugs the rendered heading, so the inline Markdown is already gone.
    # `## The `Processor` class` slugs the word and not the backticks, and
    # `## [Usage](usage.md)` slugs the label.
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = text.replace("`", "").replace("*", "")
    slug = re.sub(r"</?[^>]*>", "", unicodedata.normalize("NFC", text)).strip().lower()
    # `\w` holds the underscore, so a name such as `process_packet` keeps it.
    slug = re.sub(r"[^\w\- ]", "", slug, flags=re.UNICODE)
    return slug.replace(" ", "-")


def _anchors(page: Path) -> set[str]:
    """Return every anchor one page defines.

    Args:
        page: The Markdown file.

    Returns:
        The heading slugs and the explicit anchors. A repeated slug gains the `_1` form
        that Python-Markdown appends, so a link to either form resolves.
    """
    text = FENCED_BLOCK.sub("", page.read_text(encoding="utf-8"))
    found: set[str] = set()
    for _, heading in HEADING.findall(text):
        slug = _slug(heading)
        if not slug:
            continue
        if slug in found:
            for suffix in range(1, 12):
                if f"{slug}_{suffix}" not in found:
                    found.add(f"{slug}_{suffix}")
                    break
        else:
            found.add(slug)
    found.update(EXPLICIT_ANCHOR.findall(text))
    return found


def _internal_links() -> list[tuple[Path, int, str]]:
    """Return every internal link of every published page.

    Returns:
        One triple for each link: the page, the line number, and the link target.

    Raises:
        AssertionError: The checker read fewer links than the recorded floor.
    """
    links: list[tuple[Path, int, str]] = []
    for page in _published_pages():
        # Replacing a block with its own newline count keeps every later line number
        # right, so a finding names the line the reader opens.
        text = FENCED_BLOCK.sub(
            lambda match: "\n" * match.group().count("\n"), page.read_text(encoding="utf-8")
        )
        for number, line in enumerate(text.splitlines(), start=1):
            for target in MARKDOWN_LINK.findall(line):
                if target.startswith(EXTERNAL_SCHEMES) or target.startswith("<"):
                    continue
                links.append((page, number, target))
    assert len(links) >= MINIMUM_INTERNAL_LINKS, (
        f"the checker read {len(links)} internal links, and the floor is {MINIMUM_INTERNAL_LINKS}"
    )
    return links


def _publishes(candidate: Path) -> bool:
    """Report whether the site publishes the file one link names.

    **A file that exists is not always a page the site serves.** MkDocs resolves a link
    against `docs_dir` alone, so a target above `docs/` reaches nothing, and
    `exclude_docs` removes `docs/specs/` from the site.

    **This reading is stricter than the build, and the difference is measured.** A link
    to `../specs/spec.md` returns a 404 on the published site, and `mkdocs build
    --strict` still succeeds. It writes `Doc file 'reference/processor.md' contains a
    link to 'specs/spec.md' which is excluded from the built site.` at the information
    level, and strict mode fails on a warning alone. The `validation` tree holds no key
    that raises that message, so this function is the only guard against it.

    Args:
        candidate: The path the link resolves to, before normalization.

    Returns:
        True when the file exists inside `docs_dir` and outside the excluded directory.
    """
    resolved = candidate.resolve()
    if not resolved.exists():
        return False
    try:
        relative = resolved.relative_to(DOCS_DIR.resolve())
    except ValueError:
        return False
    return EXCLUDED_DIRECTORY not in relative.parts


def test_the_slug_of_a_case_matches_the_slug_of_the_build() -> None:
    """`_slug` returns what `pymdownx.slugs.slugify` returns for every published heading.

    **This case reads the anchor checker itself.** `_slug` is a copy of an algorithm the
    site owns, and a copy drifts. A first form of it collapsed a run of spaces and
    disagreed on 84 headings of 268. No link pointed at one of the 84, so the anchor case
    compared the wrong value and still passed.

    **The Python 3.13 job on `ubuntu-latest` installs the `docs` extra, and this case runs
    there.** `.github/workflows/test.yml` holds that step. The five other jobs of the matrix
    install the `dev` extra alone and report a skip. The skip gate reads that skip as
    correct, because one job ran the case. #529 records the repair. #524 measured the state
    before it, where the case ran on no job at all.
    """
    slugs = pytest.importorskip(
        "pymdownx.slugs", reason="the `docs` extra installs pymdownx, and `dev` does not"
    )
    reference = slugs.slugify(case="lower")
    compared = 0
    disagreements = []
    for page in _published_pages():
        text = FENCED_BLOCK.sub("", page.read_text(encoding="utf-8"))
        for _, heading in HEADING.findall(text):
            compared += 1
            if _slug(heading) != reference(heading, "-"):
                disagreements.append(
                    f"{page.relative_to(REPO_ROOT)} {heading!r}: "
                    f"{_slug(heading)!r} against {reference(heading, '-')!r}"
                )
    assert compared >= MINIMUM_PUBLISHED_HEADINGS, (
        f"the case compared {compared} headings, and the floor is {MINIMUM_PUBLISHED_HEADINGS}"
    )
    assert disagreements == [], (
        f"`_slug` disagrees with the build on these headings: {disagreements}"
    )


def _job_block(text: str, job: str) -> str:
    """Return one job of a workflow, from its key to the key of the next job.

    Args:
        text: The whole workflow file.
        job: The name of the job.

    Returns:
        The job block.

    Raises:
        AssertionError: The workflow holds no such job.
    """
    opener = f"\n  {job}:\n"
    assert opener in text, f"{TEST_WORKFLOW.name} holds no job named {job}"
    start = text.index(opener) + 1
    following = [match.start() for match in JOB_KEY.finditer(text) if match.start() > start]
    return text[start : following[0]] if following else text[start:]


def _step_that_runs(text: str, command: str) -> str:
    """Return the one step of one job whose `run` block holds the command.

    Args:
        text: The job block.
        command: The command the step runs.

    Returns:
        The step, from its `- name:` line to the next one.

    Raises:
        AssertionError: No step holds the command, or several steps hold it.
    """
    steps = [step for step in text.split(WORKFLOW_STEP) if command in step]
    assert len(steps) == 1, (
        f"{len(steps)} steps of the {MATRIX_JOB} job run `{command}`, and the reading needs one"
    )
    return steps[0]


def test_one_job_of_the_test_matrix_installs_the_documentation_extra() -> None:
    """One job of the matrix holds `pymdownx`, so the slug case runs on that job.

    **A case that skips on every job of the matrix fails the `skip-gate` job.** The census
    of #524 measured the slug case as such a case, because every job installed the `dev`
    extra alone. #529 removed the finding.

    **The extra reaches one job and not every job.** One report of a run is what the skip
    gate reads, so one job carries the extra. #575 removed the second reason: `griffe`
    2.1.0 requires Python 3.10, which every interpreter of the matrix meets.

    **The reading covers the `test` job alone.** `matrix.python-version` resolves to nothing
    in a job that runs no matrix, so a step of another job would install the extra on every
    run of that job or on none.
    """
    assert TEST_WORKFLOW.is_file(), f"{TEST_WORKFLOW} holds no test workflow"
    block = _job_block(TEST_WORKFLOW.read_text(encoding="utf-8"), MATRIX_JOB)
    step = _step_that_runs(block, DOCS_INSTALL)
    for condition in DOCS_EXTRA_CONDITIONS:
        assert condition in step, (
            f"the step that runs `{DOCS_INSTALL}` names no {condition}, so the reading does "
            "not state which job of the matrix installs the extra"
        )


def test_the_skip_allowlist_holds_no_entry_for_the_slug_case() -> None:
    """The allowlist records no environment limit against the slug case.

    A runner installs either extra, so no limit of the runner ever explained this skip. The
    case now runs on one job, and an allowlist entry beside it would allow a skip that the
    repair removed.

    **The reader reads `case` with `get` and never with an index.** #530 added an entry form
    that names one class of skip under `skip_message_prefix` and names no case at all, and
    an index raises `KeyError` on such an entry. `get` reports None there, and None equals
    no case identifier, so this reading stays exactly as strong as an index.
    """
    entries = json.loads(SKIP_ALLOWLIST.read_text(encoding="utf-8"))["entries"]
    assert SLUG_CASE not in [entry.get("case") for entry in entries], (
        f"{SKIP_ALLOWLIST.name} allows {SLUG_CASE}, and one job of the matrix runs it"
    )


def test_the_slug_reader_accepts_an_entry_that_names_a_class_of_skip() -> None:
    """A prefix entry of #530 names no case, and a reader that indexes `case` raises.

    The sub-merge gate of batch #535 measured that failure on the merge result of #529 and
    #530. Each change set passed on its own branch.
    """
    entries = [
        {"skip_message_prefix": "not applicable:", "reason": "the cell holds no data"},
        {"case": "tests.test_other::test_c", "reason": "a limit of the runner"},
    ]
    assert SLUG_CASE not in [entry.get("case") for entry in entries]


def test_the_slug_reader_still_finds_the_slug_case_in_an_entry() -> None:
    """A reader that found nothing would pass the case above on an empty set."""
    entries = [{"case": SLUG_CASE, "reason": "a limit of the runner"}]
    assert SLUG_CASE in [entry.get("case") for entry in entries]


def test_the_repository_holds_a_site_configuration() -> None:
    """`mkdocs.yml` sits at the repository root, where `mkdocs build` reads it."""
    assert CONFIGURATION.is_file(), "the repository holds no mkdocs.yml"


def test_the_site_configuration_turns_strict_mode_on() -> None:
    """`strict: true` makes `mkdocs build` fail on a warning rather than report it."""
    lines = [line.strip() for line in CONFIGURATION.read_text(encoding="utf-8").splitlines()]
    assert "strict: true" in lines, "mkdocs.yml sets no `strict: true` line"


def test_the_site_configuration_reports_a_broken_link_as_a_warning() -> None:
    """A broken link and a broken anchor each raise a warning, which strict mode fails.

    MkDocs reports a broken anchor as information by default, and strict mode fails on a
    warning alone. Without these settings the site builds while an anchor is dead.
    """
    lines = [line.strip() for line in CONFIGURATION.read_text(encoding="utf-8").splitlines()]
    for setting in ("not_found: warn", "anchors: warn", "unrecognized_links: warn"):
        assert setting in lines, f"mkdocs.yml sets no `{setting}` line"


def test_every_configured_page_names_a_file_that_exists() -> None:
    """Every Markdown path in `mkdocs.yml` resolves under `docs/`."""
    missing = [
        path
        for path in CONFIGURED_PAGE.findall(CONFIGURATION.read_text(encoding="utf-8"))
        if not (DOCS_DIR / path).is_file()
    ]
    assert missing == [], f"mkdocs.yml names these paths and docs/ holds none of them: {missing}"


def test_every_published_page_links_a_file_that_exists() -> None:
    """A relative link of a published page names a file the site publishes.

    `FR-documentation-15`. This case is the unit-suite half of the requirement. The build
    half is `mkdocs build --strict`.
    """
    broken = []
    for page, number, target in _internal_links():
        path = target.split("#", 1)[0]
        if not path:
            continue
        if _publishes(page.parent / path):
            continue
        broken.append(f"{page.relative_to(REPO_ROOT)}:{number} points at {target!r}")
    assert broken == [], f"these links name a page the site does not publish: {broken}"


def test_every_published_page_links_an_anchor_that_exists() -> None:
    """A link that names an anchor names a heading of the page it points at."""
    broken = []
    for page, number, target in _internal_links():
        path, _, anchor = target.partition("#")
        if not anchor:
            continue
        destination = page if not path else (page.parent / path).resolve()
        if not destination.is_file() or destination.suffix != ".md":
            continue
        if anchor in _anchors(destination):
            continue
        broken.append(f"{page.relative_to(REPO_ROOT)}:{number} points at {target!r}")
    assert broken == [], f"these links name an anchor that does not exist: {broken}"


def test_the_site_carries_an_api_reference_page_for_the_processor() -> None:
    """`FR-documentation-9`. A reference page renders the docstrings of `Processor`.

    The page holds no prose copy of the interface. It names the object, and mkdocstrings
    reads the docstring from the source, so the page cannot fall behind the code.
    """
    page = DOCS_DIR / "reference" / "processor.md"
    assert page.is_file(), "docs/reference/processor.md does not exist"
    identifiers = MKDOCSTRINGS_IDENTIFIER.findall(page.read_text(encoding="utf-8"))
    assert "ja4plus.processor.Processor" in identifiers, (
        f"the page renders {identifiers} and none of them is `ja4plus.processor.Processor`"
    )


def _names_a_module(dotted: str) -> bool:
    """Report whether one dotted name reaches a module or a package of the repository.

    Args:
        dotted: A dotted name, as `ja4plus.processor`.

    Returns:
        True when the repository holds the matching `.py` file or directory.
    """
    if not dotted:
        return False
    path = REPO_ROOT / Path(*dotted.split("."))
    return path.with_suffix(".py").is_file() or path.is_dir()


def test_every_reference_identifier_names_a_module_the_package_ships() -> None:
    """A reference page names an importable object, so the build renders every page."""
    unknown = []
    for page in sorted((DOCS_DIR / "reference").glob("*.md")):
        for identifier in MKDOCSTRINGS_IDENTIFIER.findall(page.read_text(encoding="utf-8")):
            parts = identifier.split(".")
            # A trailing part names a class, as in `ja4plus.processor.Processor`. Drop it
            # and read the module when the whole name reaches no file.
            if _names_a_module(identifier) or _names_a_module(".".join(parts[:-1])):
                continue
            unknown.append(f"{page.relative_to(REPO_ROOT)} renders {identifier!r}")
    assert unknown == [], f"these identifiers name no module of the package: {unknown}"


def _dependency_block(text: str, opener: str) -> list[str]:
    """Return the entries of one dependency list of `pyproject.toml`.

    **This function reads `tests/dependency_entries.py` and parses nothing of its own.**
    #452 records the defect of the earlier form. It collected every double-quoted substring
    of the block, so a comment inside the block read as an entry.

    Args:
        text: The whole file.
        opener: The line that opens the block, as `dependencies = [`.

    Returns:
        The entries, without their quotes, in file order.

    Raises:
        AssertionError: The file holds no such block, the block is not closed, or the
            block holds no entry.
    """
    return dependency_entries(text, opener)


# The entries of the `dev` extra, in file order. **Every one of them carries a comment
# above it, and that is the shape no caller of this reader read before #452.** The runtime
# block and the `docs` extra carry no comment inside their brackets. A reader that collects
# a comment therefore stays correct against those two blocks, and it fails here.
DEV_ENTRIES = [
    "pytest==9.1.1",
    "pytest-cov==7.1.0",
    "ruff==0.16.2",
    "mypy>=1.11",
    "build==1.5.0",
    "twine==7.0.0",
]

# The entries of the runtime block, in file order. A user who installs `ja4plus` installs
# these two distributions and no other.
RUNTIME_ENTRIES = [
    "scapy>=2.4.0",
    "cryptography>=42.0.0",
]

# The entries of the `docs` extra, in file order. #391 records the pair of versions that
# the site build needs, so a case names every entry rather than the two it reads.
DOCS_ENTRIES = [
    "mkdocs==1.6.1",
    "mkdocs-material==9.7.7",
    "mkdocstrings==1.0.6",
    "mkdocstrings-python==2.0.7",
    "griffe==2.1.0",
]


def test_the_reader_returns_the_entries_of_the_dev_extra_and_no_comment_fragment() -> None:
    """`_dependency_block` reads the entries of a block that carries a comment.

    The `dev` extra states one comment above every entry, and one of those comments quotes
    the command `pytest tests/ -m "not spec_validation"`. A reader that collects every
    quoted substring returns `not spec_validation` as an entry, and #452 records that
    defect.
    """
    entries = _dependency_block(PYPROJECT.read_text(encoding="utf-8"), "dev = [")
    assert entries == DEV_ENTRIES


def test_the_reader_returns_every_entry_of_the_runtime_block_by_name() -> None:
    """`_dependency_block` returns the runtime dependencies and drops none of them.

    A repair that returns an empty list passes a case that reads the absence of a comment
    fragment. This case therefore names every entry the block holds.
    """
    entries = _dependency_block(PYPROJECT.read_text(encoding="utf-8"), "dependencies = [")
    assert entries == RUNTIME_ENTRIES


def test_the_reader_returns_every_entry_of_the_docs_extra_by_name() -> None:
    """`_dependency_block` returns the documentation dependencies and drops none of them."""
    entries = _dependency_block(PYPROJECT.read_text(encoding="utf-8"), "docs = [")
    assert entries == DOCS_ENTRIES


def test_the_documentation_dependency_stays_out_of_the_runtime_dependencies() -> None:
    """A user who installs `ja4plus` installs no documentation generator.

    Every runtime dependency reaches the release that Epic 9 ships, so the site
    generator belongs in the `docs` extra.
    """
    runtime = _dependency_block(PYPROJECT.read_text(encoding="utf-8"), "dependencies = [")
    offenders = [entry for entry in runtime if "mkdocs" in entry or "griffe" in entry]
    assert offenders == [], f"these runtime dependencies build the site: {offenders}"


def test_the_docs_extra_names_the_site_generator() -> None:
    """The `docs` extra installs the generator and the handler the site needs."""
    docs = _dependency_block(PYPROJECT.read_text(encoding="utf-8"), "docs = [")
    names = {re.split(r"[=<>!~\[]", entry, maxsplit=1)[0].strip() for entry in docs}
    for required in ("mkdocs-material", "mkdocstrings-python"):
        assert required in names, f"the docs extra names {sorted(names)} and not {required}"


def test_every_documentation_dependency_pins_one_version() -> None:
    """A pinned version keeps the site build from changing without a commit.

    #378 records the defect a floating pin causes. A generator that changes between two
    runs moves the build result, and no commit records the move.
    """
    docs = _dependency_block(PYPROJECT.read_text(encoding="utf-8"), "docs = [")
    floating = [entry for entry in docs if "==" not in entry]
    assert floating == [], f"these documentation dependencies float: {floating}"


def _pinned_version(name: str) -> str:
    """Return the exact version the `docs` extra pins for one distribution.

    Args:
        name: The distribution name, as `mkdocstrings`.

    Returns:
        The version after `==`.

    Raises:
        AssertionError: The extra pins no such distribution.
    """
    docs = _dependency_block(PYPROJECT.read_text(encoding="utf-8"), "docs = [")
    for entry in docs:
        if entry.startswith(f"{name}=="):
            return entry.split("==", maxsplit=1)[1].strip()
    raise AssertionError(f"the docs extra pins no {name}: {docs}")


def _version_tuple(version: str) -> tuple[int, ...]:
    """Return one version as the integers a comparison reads.

    Args:
        version: The version, as `1.0.6`.

    Returns:
        The numbers of the version, in order.
    """
    return tuple(int(part) for part in re.findall(r"\d+", version))


def test_the_mkdocstrings_pin_holds_the_handler_module_its_handler_imports() -> None:
    """An exact pin can still be an incompatible pin, and #391 records the instance.

    `mkdocstrings_handlers/python/handler.py` of the 1.x line imports
    `mkdocstrings.handlers.base`. `mkdocstrings` 1.0.0 removed that public module, so the
    pair `mkdocstrings==1.0.6` with `mkdocstrings-python==1.15.0` failed the build with
    `ModuleNotFoundError: No module named 'mkdocstrings.handlers'`. #576 took the handler
    to the 2.x line, which imports from `mkdocstrings` directly, and this case holds the
    lower bound of that line.

    Verified against
    https://github.com/mkdocstrings/mkdocstrings/blob/main/CHANGELOG.md, which lists
    `mkdocstrings.handlers` under the breaking changes of 1.0.0, retrieved 2026-08-09, and
    against https://pypi.org/pypi/mkdocstrings-python/2.0.5/json, which states
    `mkdocstrings>=0.30`, retrieved 2026-08-10.

    This case reads two pins as text. It proves no build. The `build` job of
    `.github/workflows/docs-build.yml` proves the build.
    """
    handler = _version_tuple(_pinned_version("mkdocstrings-python"))
    generator = _version_tuple(_pinned_version("mkdocstrings"))
    # **The bound belongs to the line of `mkdocstrings-python`, so an unmeasured line
    # fails here rather than passing on an `if` that no longer fires.** A guard that a
    # version bump switches off is the shape #391 exists to bar.
    assert handler[0] in (1, 2), (
        f"mkdocstrings-python {handler} is a line this case has not read; read the "
        "changelog of the handler and state the bound it needs"
    )
    if handler[0] == 1:
        assert generator < (1, 0), (
            f"mkdocstrings-python {handler} imports `mkdocstrings.handlers`, and "
            f"mkdocstrings {generator} removed it"
        )
    else:
        # The 2.x handler imports from `mkdocstrings` directly and declares
        # `mkdocstrings>=0.30`. The lower bound replaces the upper one.
        assert generator >= (0, 30), (
            f"mkdocstrings-python {handler} needs mkdocstrings 0.30 or later, and the "
            f"extra pins {generator}"
        )


def test_a_continuous_integration_job_installs_the_documentation_pins_and_builds() -> None:
    """No case in this suite can prove that the committed pins build the site.

    The suite runs inside an environment that another resolution already filled, so a
    case that imports `mkdocs` measures that environment and not `pyproject.toml`. The
    instrument is a job that starts from an empty environment. #391 records the defect
    that reached the integration branch while every case here passed.
    """
    assert DOCS_WORKFLOW.is_file(), f"{DOCS_WORKFLOW} holds no documentation job"
    text = DOCS_WORKFLOW.read_text(encoding="utf-8")
    assert 'pip install -e ".[docs]"' in text, (
        f"{DOCS_WORKFLOW.name} installs some other set than the committed `docs` pins"
    )
    assert "mkdocs build --strict" in text, f"{DOCS_WORKFLOW.name} runs no `mkdocs build --strict`"
    # The `dev` extra brings a second resolution into the environment, and the release
    # installs no such set. A job that installs it measures the wrong artifact.
    assert "[dev" not in text, f"{DOCS_WORKFLOW.name} installs the dev extra beside the docs extra"


def test_the_documentation_job_runs_when_a_pin_or_a_page_changes() -> None:
    """The path filter of the job covers each file that can break the build.

    A job that no change starts reports nothing. The pins live in `pyproject.toml`, the site configuration in `mkdocs.yml`, and the
    pages under `docs/`. A change to any one of the three can break the build.

    **Each trigger carries its own filter, and this case reads each one.** A filter that
    covers `push` alone leaves every pull request unguarded, and the pull request is where
    the batch model reads the result.
    """
    assert DOCS_WORKFLOW.is_file(), f"{DOCS_WORKFLOW} holds no documentation job"
    text = DOCS_WORKFLOW.read_text(encoding="utf-8")
    # A block runs to the next trigger of the same indentation, or to the job list.
    boundaries = ("\n  push:", "\n  pull_request:", "\n  workflow_dispatch:", "\njobs:")
    for trigger in ("push:", "pull_request:"):
        start = text.find(f"\n  {trigger}\n")
        assert start != -1, f"{DOCS_WORKFLOW.name} carries no {trigger} trigger"
        after = [text.find(boundary, start + 1) for boundary in boundaries]
        block = text[start : min(position for position in after if position != -1)]
        for path in ("pyproject.toml", "mkdocs.yml", "docs/**"):
            assert f'"{path}"' in block, (
                f"the {trigger} trigger of {DOCS_WORKFLOW.name} names no filter for {path}"
            )
