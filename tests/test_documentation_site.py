"""Tests that the documentation site is configured and that every internal link resolves.

`FR-documentation-7` asks the site to build from the Markdown files that already exist.
`FR-documentation-9` asks the site to carry an API reference generated from the
docstrings. `FR-documentation-15` asks a broken internal link to fail the build.

**The build itself is the authority, and `mkdocs build --strict` is the command.** These
cases stand in front of it, because the unit suite installs the `dev` extra and not the
`docs` extra, so no case here imports `mkdocs`. They read the site configuration and the
pages as text, and they resolve every internal link the same way the build does.

**A case here reads the published page set, which excludes `docs/specs/`.** The
specification package is design material. `mkdocs.yml` excludes it from the site, so a
link inside it reaches no build.

These cases read prose and configuration. They import nothing from `ja4plus` and they
produce no fingerprint.
"""

from pathlib import Path
import re

REPO_ROOT = Path(__file__).resolve().parent.parent

CONFIGURATION = REPO_ROOT / "mkdocs.yml"
DOCS_DIR = REPO_ROOT / "docs"
PYPROJECT = REPO_ROOT / "pyproject.toml"

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
    """Return the anchor that Python-Markdown builds for one heading.

    The `toc` extension lowercases the text, removes every character that is not a word
    character, a space or a hyphen, and then replaces each space with a hyphen.

    Args:
        heading: The heading text, without its `#` characters.

    Returns:
        The anchor, without the leading `#`.
    """
    # A heading carries inline Markdown. `## The `Processor` class` must slug the word and
    # not the backticks, and `## [Usage](usage.md)` must slug the label.
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = text.replace("`", "").replace("*", "").replace("_", "")
    text = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"\s+", "-", text.strip())


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
        resolved = (page.parent / path).resolve()
        if resolved.exists():
            continue
        broken.append(f"{page.relative_to(REPO_ROOT)}:{number} points at {target!r}")
    assert broken == [], f"these links name a file that does not exist: {broken}"


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

    Args:
        text: The whole file.
        opener: The line that opens the list, as `dependencies = [`.

    Returns:
        The quoted entries, without their quotes.

    Raises:
        AssertionError: The file holds no such list.
    """
    start = text.find(f"\n{opener}\n")
    assert start != -1, f"pyproject.toml holds no {opener!r} list"
    end = text.find("\n]", start)
    assert end != -1, f"the {opener!r} list is not closed"
    return re.findall(r"\"([^\"]+)\"", text[start:end])


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
