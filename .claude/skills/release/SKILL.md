---
name: release
description: Cut a ja4plus release to PyPI. Use when asked to release, publish, cut a version, or ship to PyPI.
allowed-tools: Bash, Read, Edit
---

# Release ja4plus

A publish to PyPI cannot be undone. Every check below runs before the publish, not
after.

## Before you start

Confirm all of the following. Stop and report if any is false.

- The work is merged into `master`.
- `pytest tests/` passes, including the conformance suite.
- `ruff check`, `ruff format --check` and `mypy ja4plus/` report nothing.
- `CHANGELOG.md` has a section for the version you are about to publish.

## Steps

1. Set the version. It lives in `pyproject.toml` only. `ja4plus/__init__.py` reads it
   with `importlib.metadata.version`.

2. Confirm the version and the changelog agree.

   ```bash
   python - <<'PY'
   import re, tomllib, pathlib
   v = tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"]
   changelog = pathlib.Path("CHANGELOG.md").read_text()
   assert re.search(rf"^## \[{re.escape(v)}\]", changelog, re.M), f"no changelog section for {v}"
   print(f"version {v} has a changelog section")
   PY
   ```

3. Build the release and verify it in a clean environment. This one command runs every
   check the publish workflow runs, and `.github/workflows/publish.yml` runs the same
   command.

   ```bash
   rm -rf dist/ build/
   python -m tests.release_verification --dist dist
   ```

   The command runs five checks in this order.

   1. It builds the source distribution and the wheel.
   2. It reads both files with `twine check`.
   3. It installs the wheel into a clean environment.
   4. It runs the console script of that environment.
   5. It runs the conformance suite against the installed package.

   **Warning: never run the conformance suite from the repository root against a clean
   environment.** `python -m` puts the working directory on `sys.path`, and `pytest`
   inserts the parent of the `tests` package there as well. Both paths hold `ja4plus/` in
   the checkout, so the run reads the source tree and it proves nothing about the wheel.
   The command above copies the suite to a directory that holds no package source.

4. Confirm the wheel holds what it must, and nothing it must not.

   ```bash
   python -m pytest tests/ -m installed_wheel -q
   ```

5. Create the GitHub release. The publish workflow triggers on a published release and
   uses trusted publishing, so no token is needed.

   `FR-release-14` puts the changelog section of the version in the release body.
   `tests/release_body.py` builds that body, and the publish workflow runs the same
   module, so the manual step and the workflow cannot disagree.

   **Warning: the provider refuses a body of more than 125000 characters.** The command
   below reports a fault and it writes no file where the section is longer. Read
   `### The release body of version 1.0.0` of `docs/specs/features/09-release.md` before
   you release a version whose section exceeds that limit.

   ```bash
   python -m tests.release_body --output /tmp/ja4plus-release-body.md
   gh release create "v<version>" --title "v<version>" \
     --notes-file /tmp/ja4plus-release-body.md
   ```

   The workflow writes the release body from the same reader after it verifies the
   artifacts, so a release that a maintainer creates in the provider interface carries
   the section too.

6. Confirm the publish.

   ```bash
   gh run list --workflow=publish.yml --limit 1
   pip download --no-deps --dest /tmp/ja4check "ja4plus==<version>"
   ```

## How to run the dry run

`FR-release-13` publishes to TestPyPI first when the maintainer asks for a dry run. The
manual event of `.github/workflows/publish.yml` is that request, and it reaches TestPyPI
alone.

```bash
gh workflow run publish.yml --repo Crank-Git/ja4plus --ref <branch>
gh run list --workflow=publish.yml --limit 1
```

**The manual event takes no input.** The event selects the `dry-run` job, that job names
the `testpypi` environment, and its publish step names the TestPyPI repository URL. Each
value is a literal of the file, so a caller selects no index.

**Warning: a dry run needs a trusted publisher on TestPyPI**, configured against this
repository, `publish.yml` and the environment `testpypi`. The publish step fails and names
the missing configuration where no such publisher exists. It reaches PyPI in no case.

## Rules

- Never publish when any step above failed. A partial publish cannot be undone.
- Never bump a version and publish in one action without a human confirming the
  changelog.
- Version 1.0.0 states that the interface is stable. A breaking change after it needs
  version 2.0.0.
